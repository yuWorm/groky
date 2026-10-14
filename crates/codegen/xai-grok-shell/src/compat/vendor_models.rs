//! Live vendor model lists, cached under `$GROK_HOME/vendor-catalog.json`.
//!
//! Builtin picker rows prefer:
//! 1. Last successful `/models` fetch for that provider
//! 2. Latest generation per family from the models.dev snapshot
//! 3. The small hardcoded fallback on `ProviderSpec`
//!
//! ChatGPT Codex uses its account-scoped product catalog at
//! `/backend-api/codex/models?client_version=...`.
//!
//! Refresh: login, startup when stale, `/sync-models-dev` (also
//! `/refresh-models`), and the provider-picker `r` shortcut. Custom providers
//! merge into `vendor-providers.json` on the same path.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use xai_grok_sampling_types::{ReasoningEffort, ReasoningEffortOption, effort_label};

use super::custom::{RemoteModel, fetch_model_list_with_headers};
use super::probe::VendorLoginError;
use super::reasoning;

const FILE_NAME: &str = "vendor-catalog.json";
const LIVE_LIST_CAP: usize = 40;
const CATALOG_TTL_SECS: u64 = 5 * 60;
const CODEX_CATALOG_BODY_LIMIT: usize = 1024 * 1024;
const CODEX_PROVIDER_ID: &str = "openai-codex";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct CachedModel {
    pub api_model: String,
    pub name: String,
    #[serde(default)]
    pub context_window: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasoning_efforts: Vec<ReasoningEffortOption>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct FileShape {
    #[serde(default)]
    providers: BTreeMap<String, CachedProvider>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedProvider {
    #[serde(default)]
    updated_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    identity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    client_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    etag: Option<String>,
    #[serde(default)]
    models: Vec<CachedModel>,
}

impl CachedProvider {
    fn matches_codex_scope(&self, identity: &str, client_version: &str) -> bool {
        self.identity.as_deref() == Some(identity)
            && self.client_version.as_deref() == Some(client_version)
    }

    fn etag_for_codex_scope(&self, scope: &CodexCacheScope) -> Option<String> {
        self.matches_codex_scope(&scope.identity, &scope.client_version)
            .then(|| self.etag.clone())
            .flatten()
    }

    fn touch_codex_scope(&mut self, scope: &CodexCacheScope, now: u64) -> Option<usize> {
        if !self.matches_codex_scope(&scope.identity, &scope.client_version) {
            return None;
        }
        self.updated_at = now;
        Some(self.models.len())
    }

    fn is_fresh_at(&self, now: u64) -> bool {
        now.saturating_sub(self.updated_at) < CATALOG_TTL_SECS
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CodexCacheScope {
    identity: String,
    client_version: String,
}

struct CodexCatalog {
    models: Vec<CachedModel>,
    etag: Option<String>,
}

enum CodexCatalogResponse {
    Modified(CodexCatalog),
    NotModified,
}

#[derive(Clone, Copy, Debug)]
struct ClaudeId {
    family: ClaudeFamily,
    major: u32,
    minor: u32,
    fast: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum ClaudeFamily {
    Fable,
    Opus,
    Sonnet,
    Haiku,
}

impl ClaudeFamily {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "fable" => Some(Self::Fable),
            "opus" => Some(Self::Opus),
            "sonnet" => Some(Self::Sonnet),
            "haiku" => Some(Self::Haiku),
            _ => None,
        }
    }
}

fn codex_cache_scope() -> Option<CodexCacheScope> {
    let identity = super::auth_store::VendorAuthStore::default_store()
        .ok()?
        .credential(CODEX_PROVIDER_ID)?
        .account_id
        .as_deref()?
        .trim()
        .to_owned();
    if identity.is_empty() {
        return None;
    }
    let identity = blake3::hash(identity.as_bytes()).to_hex().to_string();
    Some(CodexCacheScope {
        identity,
        client_version: codex_client_version(),
    })
}

pub(crate) fn cached_models(provider_id: &str) -> Option<Vec<CachedModel>> {
    #[cfg(test)]
    {
        let _ = provider_id;
        return None;
    }
    #[cfg(not(test))]
    {
        let store = load_store().ok()?;
        let cached = store.data.providers.get(provider_id)?;
        if provider_id == CODEX_PROVIDER_ID {
            let scope = codex_cache_scope()?;
            if !cached.matches_codex_scope(&scope.identity, &scope.client_version) {
                return None;
            }
        }
        (!cached.models.is_empty()).then(|| cached.models.clone())
    }
}

fn cached_codex_etag(scope: &CodexCacheScope) -> Option<String> {
    load_store()
        .ok()?
        .data
        .providers
        .get(CODEX_PROVIDER_ID)?
        .etag_for_codex_scope(scope)
}

fn touch_codex_cache(scope: &CodexCacheScope) -> Result<usize, VendorLoginError> {
    let mut store = load_store()?;
    let Some(count) = store
        .data
        .providers
        .get_mut(CODEX_PROVIDER_ID)
        .and_then(|cached| cached.touch_codex_scope(scope, now_secs()))
    else {
        return Ok(0);
    };
    store.save()?;
    Ok(count)
}

fn refresh_needed(provider_id: &str) -> bool {
    let codex_scope = if provider_id == CODEX_PROVIDER_ID {
        let Some(scope) = codex_cache_scope() else {
            return false;
        };
        Some(scope)
    } else {
        None
    };
    let Ok(store) = load_store() else {
        return true;
    };
    let Some(cached) = store.data.providers.get(provider_id) else {
        return true;
    };
    if let Some(scope) = codex_scope
        && !cached.matches_codex_scope(&scope.identity, &scope.client_version)
    {
        return true;
    }
    !cached.is_fresh_at(now_secs())
}

/// Latest Claude generation per family from models.dev (baked + overlay).
pub(crate) fn models_dev_fallback(provider_id: &str) -> Vec<CachedModel> {
    if !matches!(provider_id, "anthropic" | "anthropic-claude") {
        return Vec::new();
    }
    latest_claude_from_ids(reasoning::catalog_ids())
}

pub async fn refresh(provider_id: &str) -> Result<usize, VendorLoginError> {
    let Some(provider) = super::catalog::provider_by_id(provider_id) else {
        return Ok(0);
    };
    let key = super::live_vendor_key_for_id(provider.id).unwrap_or_default();
    if provider.requires_auth && key.trim().is_empty() {
        return Ok(0);
    }
    let extra = listing_headers(provider.id, provider.anthropic_version);
    if provider.id == CODEX_PROVIDER_ID {
        let Some(scope) = codex_cache_scope() else {
            return Ok(0);
        };
        let cached_etag = cached_codex_etag(&scope);
        let response =
            fetch_codex_model_list(provider.base_url, &key, &extra, cached_etag.as_deref()).await?;
        if codex_cache_scope().as_ref() != Some(&scope) {
            return Ok(0);
        }
        return match response {
            CodexCatalogResponse::NotModified => touch_codex_cache(&scope),
            CodexCatalogResponse::Modified(catalog) => {
                if catalog.models.is_empty() {
                    return Ok(0);
                }
                let n = catalog.models.len();
                save_models(provider.id, catalog.models, Some(&scope), catalog.etag)?;
                Ok(n)
            }
        };
    }

    let listed = fetch_model_list_with_headers(
        provider.base_url,
        &key,
        provider.auth_scheme,
        provider.anthropic_version,
        &extra,
    )
    .await?;
    let filtered = filter_live(provider.id, listed);
    if filtered.is_empty() {
        return Ok(0);
    }
    let n = filtered.len();
    save_models(provider.id, filtered, None, None)?;
    Ok(n)
}

pub async fn refresh_unlocked() -> usize {
    let mut total = 0;
    for provider in super::catalog::builtin_providers() {
        if !super::catalog::provider_is_unlocked(provider.id) {
            continue;
        }
        match refresh(provider.id).await {
            Ok(n) => total += n,
            Err(error) => {
                tracing::warn!(
                    provider = provider.id,
                    error = %error,
                    "vendor model list refresh failed"
                );
            }
        }
    }
    total += super::custom::refresh_unlocked().await;
    total
}

/// Refresh the signed-in ChatGPT Codex catalog when its cache is missing, stale, or scoped to another account.
pub async fn refresh_stale_unlocked() -> usize {
    if !super::catalog::provider_is_unlocked(CODEX_PROVIDER_ID)
        || !refresh_needed(CODEX_PROVIDER_ID)
    {
        return 0;
    }
    match refresh(CODEX_PROVIDER_ID).await {
        Ok(count) => count,
        Err(error) => {
            tracing::warn!(
                provider = CODEX_PROVIDER_ID,
                error = %error,
                "stale vendor model list refresh failed"
            );
            0
        }
    }
}

fn listing_headers(provider_id: &str, anthropic_version: Option<&str>) -> Vec<(String, String)> {
    let mut headers = indexmap::IndexMap::new();
    if let Some(version) = anthropic_version {
        headers.insert("anthropic-version".into(), version.to_owned());
    }
    super::oauth::inject_request_headers(provider_id, &mut headers);
    headers.into_iter().collect()
}

fn whole_client_version(version: &str) -> String {
    semver::Version::parse(version.trim()).map_or_else(
        |_| {
            version
                .trim()
                .split('-')
                .next()
                .unwrap_or(version)
                .to_owned()
        },
        |parsed| format!("{}.{}.{}", parsed.major, parsed.minor, parsed.patch),
    )
}

fn codex_client_version() -> String {
    whole_client_version(xai_grok_version::VERSION)
}

fn codex_models_url(
    base_url: &str,
    client_version: &str,
) -> Result<reqwest::Url, VendorLoginError> {
    let raw = format!("{}/models", base_url.trim_end_matches('/'));
    let mut url = reqwest::Url::parse(&raw)
        .map_err(|error| VendorLoginError::Probe(format!("invalid Codex models URL: {error}")))?;
    url.query_pairs_mut()
        .append_pair("client_version", &whole_client_version(client_version));
    Ok(url)
}

async fn read_limited_body(
    response: reqwest::Response,
    limit: usize,
) -> Result<Vec<u8>, VendorLoginError> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(VendorLoginError::Probe(format!(
            "Codex models response exceeds {limit} bytes"
        )));
    }
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| VendorLoginError::Probe(error.to_string()))?;
        if body.len().saturating_add(chunk.len()) > limit {
            return Err(VendorLoginError::Probe(format!(
                "Codex models response exceeds {limit} bytes"
            )));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

async fn fetch_codex_model_list(
    base_url: &str,
    access_token: &str,
    extra_headers: &[(String, String)],
    etag: Option<&str>,
) -> Result<CodexCatalogResponse, VendorLoginError> {
    let url = codex_models_url(base_url, &codex_client_version())?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .user_agent(format!("groky/{}", xai_grok_version::VERSION))
        .build()
        .map_err(|error| VendorLoginError::Probe(error.to_string()))?;
    let mut request = client.get(url.clone()).bearer_auth(access_token.trim());
    if let Some(etag) = etag.filter(|etag| !etag.trim().is_empty()) {
        request = request.header(reqwest::header::IF_NONE_MATCH, etag);
    }
    for (name, value) in extra_headers {
        if name.eq_ignore_ascii_case("authorization") || name.eq_ignore_ascii_case("x-api-key") {
            continue;
        }
        request = request.header(name.as_str(), value.as_str());
    }
    let response = request
        .send()
        .await
        .map_err(|error| VendorLoginError::Probe(format!("couldn't reach {url}: {error}")))?;
    let status = response.status();
    let response_etag = response
        .headers()
        .get(reqwest::header::ETAG)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    if status == reqwest::StatusCode::NOT_MODIFIED {
        return Ok(CodexCatalogResponse::NotModified);
    }
    let body = read_limited_body(response, CODEX_CATALOG_BODY_LIMIT).await?;
    if !status.is_success() {
        let snippet: String = String::from_utf8_lossy(&body).chars().take(180).collect();
        return Err(VendorLoginError::Probe(format!(
            "{status} from {url}{}",
            if snippet.is_empty() {
                String::new()
            } else {
                format!(": {snippet}")
            }
        )));
    }
    let value: serde_json::Value = serde_json::from_slice(&body).map_err(|error| {
        VendorLoginError::Probe(format!("invalid Codex models response: {error}"))
    })?;
    let models = parse_codex_models_json(&value);
    if models.is_empty() {
        return Err(VendorLoginError::Probe(format!(
            "{url} returned no picker-visible models"
        )));
    }
    Ok(CodexCatalogResponse::Modified(CodexCatalog {
        models,
        etag: response_etag,
    }))
}

fn parse_codex_models_json(value: &serde_json::Value) -> Vec<CachedModel> {
    let Some(items) = value.get("models").and_then(serde_json::Value::as_array) else {
        return Vec::new();
    };
    let mut models = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for (index, item) in items.iter().enumerate() {
        let Some(object) = item.as_object() else {
            continue;
        };
        let visibility = object
            .get("visibility")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("list");
        if visibility != "list" {
            continue;
        }
        let api_model = object
            .get("slug")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .trim();
        if api_model.is_empty() || !seen.insert(api_model.to_owned()) {
            continue;
        }
        let name = object
            .get("display_name")
            .and_then(serde_json::Value::as_str)
            .filter(|name| !name.trim().is_empty())
            .map(str::to_owned)
            .unwrap_or_else(|| humanize_api_model(api_model));
        let description = object
            .get("description")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|description| !description.is_empty())
            .map(str::to_owned);
        let context_window = object
            .get("context_window")
            .and_then(serde_json::Value::as_u64)
            .filter(|window| *window > 0)
            .or_else(|| {
                reasoning::lookup_meta(api_model).and_then(|metadata| metadata.context_window)
            })
            .unwrap_or(400_000);
        let default_effort = object
            .get("default_reasoning_level")
            .and_then(serde_json::Value::as_str)
            .and_then(|effort| effort.parse::<ReasoningEffort>().ok());
        let mut reasoning_efforts = Vec::new();
        if let Some(levels) = object
            .get("supported_reasoning_levels")
            .and_then(serde_json::Value::as_array)
        {
            for level in levels {
                let Some(level) = level.as_object() else {
                    continue;
                };
                let Some(effort) = level
                    .get("effort")
                    .and_then(serde_json::Value::as_str)
                    .and_then(|effort| effort.parse::<ReasoningEffort>().ok())
                else {
                    continue;
                };
                if reasoning_efforts
                    .iter()
                    .any(|option: &ReasoningEffortOption| option.value == effort)
                {
                    continue;
                }
                reasoning_efforts.push(ReasoningEffortOption {
                    id: effort.as_ref().to_owned(),
                    value: effort,
                    label: effort_label(effort),
                    description: level
                        .get("description")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned),
                    default: default_effort == Some(effort),
                });
            }
        }
        if let Some(effort) = default_effort
            && !reasoning_efforts
                .iter()
                .any(|option| option.value == effort)
        {
            reasoning_efforts.push(ReasoningEffortOption {
                id: effort.as_ref().to_owned(),
                value: effort,
                label: effort_label(effort),
                description: None,
                default: true,
            });
        }
        let priority = object
            .get("priority")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(i64::MAX);
        models.push((
            priority,
            index,
            CachedModel {
                api_model: api_model.to_owned(),
                name,
                context_window,
                description,
                reasoning_efforts,
            },
        ));
    }
    models.sort_by_key(|(priority, index, _)| (*priority, *index));
    models.truncate(LIVE_LIST_CAP);
    models.into_iter().map(|(_, _, model)| model).collect()
}

pub(crate) fn filter_live(provider_id: &str, models: Vec<RemoteModel>) -> Vec<CachedModel> {
    let mut out: Vec<CachedModel> = models
        .into_iter()
        .filter(|m| keep_live(provider_id, &m.api_model))
        .map(to_cached)
        .collect();
    dedupe_api_models(&mut out);
    if matches!(provider_id, "anthropic" | "anthropic-claude") && out.len() > LIVE_LIST_CAP {
        out = latest_claude_from_cached(out);
    } else if out.len() > LIVE_LIST_CAP {
        out.truncate(LIVE_LIST_CAP);
    }
    out
}

fn keep_live(provider_id: &str, api_model: &str) -> bool {
    match provider_id {
        "anthropic" | "anthropic-claude" => parse_claude_id(api_model).is_some(),
        "openai" => keep_openai_id(api_model),
        "openrouter" => keep_openrouter_id(api_model),
        "deepseek" | "ollama" => !api_model.trim().is_empty(),
        _ => !api_model.trim().is_empty(),
    }
}

fn to_cached(model: RemoteModel) -> CachedModel {
    let mut context_window = model.context_window;
    if let Some(ctx) = reasoning::lookup_meta(&model.api_model).and_then(|m| m.context_window) {
        context_window = ctx;
    }
    let name = if model.name.trim().is_empty() || model.name == model.api_model {
        humanize_api_model(&model.api_model)
    } else {
        model.name
    };
    CachedModel {
        api_model: model.api_model,
        name,
        context_window,
        description: None,
        reasoning_efforts: Vec::new(),
    }
}

fn keep_openai_id(api_model: &str) -> bool {
    let leaf = leaf_id(api_model);
    if leaf.starts_with("ft:") || leaf.contains("whisper") {
        return false;
    }
    const DROP: &[&str] = &[
        "tts",
        "davinci",
        "babbage",
        "ada-",
        "embedding",
        "dall-e",
        "moderation",
        "transcribe",
        "realtime",
        "image",
        "audio",
        "search",
    ];
    if DROP.iter().any(|token| leaf.contains(token)) {
        return false;
    }
    leaf.starts_with("gpt-")
        || leaf.starts_with("o1")
        || leaf.starts_with("o3")
        || leaf.starts_with("o4")
        || leaf.starts_with("o5")
        || leaf.starts_with("chatgpt-")
}

fn keep_openrouter_id(api_model: &str) -> bool {
    let id = api_model.trim().to_ascii_lowercase();
    if id.contains(":free") || id.contains(":nitro") || id.contains(":extended") {
        return false;
    }
    let Some((author, model)) = id.split_once('/') else {
        return false;
    };
    match author {
        "anthropic" => parse_claude_id(model).is_some(),
        "openai" => keep_openai_id(model),
        "google" => model.starts_with("gemini-") || model.starts_with("gemma-"),
        "x-ai" => model.starts_with("grok-"),
        "deepseek" => model.starts_with("deepseek-"),
        "z-ai" | "zhipuai" => model.starts_with("glm-"),
        "minimax" => model.contains("minimax") || model.starts_with("m"),
        "moonshotai" => model.starts_with("kimi-") || model.starts_with("moonshot-"),
        "qwen" => model.starts_with("qwen"),
        _ => false,
    }
}

fn latest_claude_from_ids(ids: impl IntoIterator<Item = String>) -> Vec<CachedModel> {
    let parsed: Vec<(String, ClaudeId)> = ids
        .into_iter()
        .filter_map(|id| parse_claude_id(&id).map(|parsed| (id, parsed)))
        .collect();
    pick_latest_claude(parsed)
        .into_iter()
        .map(|api_model| {
            let context_window = reasoning::lookup_meta(&api_model)
                .and_then(|m| m.context_window)
                .unwrap_or(200_000);
            let name = humanize_api_model(&api_model);
            CachedModel {
                api_model,
                name,
                context_window,
                description: None,
                reasoning_efforts: Vec::new(),
            }
        })
        .collect()
}

fn latest_claude_from_cached(models: Vec<CachedModel>) -> Vec<CachedModel> {
    let parsed: Vec<(String, ClaudeId)> = models
        .iter()
        .filter_map(|m| parse_claude_id(&m.api_model).map(|parsed| (m.api_model.clone(), parsed)))
        .collect();
    let keep: std::collections::HashSet<String> = pick_latest_claude(parsed).into_iter().collect();
    models
        .into_iter()
        .filter(|m| keep.contains(&m.api_model))
        .collect()
}

fn pick_latest_claude(parsed: Vec<(String, ClaudeId)>) -> Vec<String> {
    let mut best: BTreeMap<(ClaudeFamily, bool), (u32, u32, String)> = BTreeMap::new();
    for (id, spec) in parsed {
        let key = (spec.family, spec.fast);
        let rank = (spec.major, spec.minor);
        match best.get(&key) {
            Some((maj, min, _)) if (*maj, *min) >= rank => {}
            _ => {
                best.insert(key, (spec.major, spec.minor, id));
            }
        }
    }
    best.into_values().map(|(_, _, id)| id).collect()
}

fn parse_claude_id(api_model: &str) -> Option<ClaudeId> {
    let leaf = leaf_id(api_model);
    if leaf.contains('@') || leaf.contains(':') {
        return None;
    }
    if leaf.contains("thinking")
        || leaf.contains("-think")
        || leaf.contains("latest")
        || leaf.contains("mythos")
        || leaf.contains("batch")
        || leaf.contains("free")
    {
        return None;
    }
    let rest = leaf.strip_prefix("claude-")?;
    let mut parts = rest.split('-');
    let family = ClaudeFamily::parse(parts.next()?)?;
    let major: u32 = parts.next()?.parse().ok()?;
    let mut minor = 0u32;
    let mut fast = false;
    for part in parts {
        if part == "fast" {
            fast = true;
            continue;
        }
        if part.chars().all(|c| c.is_ascii_digit()) {
            if part.len() > 2 {
                return None;
            }
            if minor != 0 {
                return None;
            }
            minor = part.parse().ok()?;
            continue;
        }
        return None;
    }
    Some(ClaudeId {
        family,
        major,
        minor,
        fast,
    })
}

pub(crate) fn humanize_api_model(api_model: &str) -> String {
    let leaf = api_model.rsplit('/').next().unwrap_or(api_model).trim();
    if leaf.is_empty() {
        return api_model.to_owned();
    }
    let tokens: Vec<&str> = leaf.split('-').filter(|t| !t.is_empty()).collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        let token = tokens[i];
        if token.chars().all(|c| c.is_ascii_digit()) {
            let mut ver = token.to_string();
            while i + 1 < tokens.len() && tokens[i + 1].chars().all(|c| c.is_ascii_digit()) {
                i += 1;
                ver.push('.');
                ver.push_str(tokens[i]);
            }
            out.push(ver);
        } else if token.eq_ignore_ascii_case("gpt") {
            out.push("GPT".into());
        } else {
            let mut chars = token.chars();
            let pretty = match chars.next() {
                Some(c) => c.to_ascii_uppercase().to_string() + chars.as_str(),
                None => String::new(),
            };
            out.push(pretty);
        }
        i += 1;
    }
    out.join(" ")
}

fn leaf_id(api_model: &str) -> String {
    api_model
        .rsplit('/')
        .next()
        .unwrap_or(api_model)
        .trim()
        .to_ascii_lowercase()
}

fn dedupe_api_models(models: &mut Vec<CachedModel>) {
    let mut seen = std::collections::HashSet::new();
    models.retain(|m| seen.insert(m.api_model.clone()));
}

fn save_models(
    provider_id: &str,
    models: Vec<CachedModel>,
    scope: Option<&CodexCacheScope>,
    etag: Option<String>,
) -> io::Result<()> {
    #[cfg(test)]
    {
        let _ = (provider_id, models, scope, etag);
        return Ok(());
    }
    #[cfg(not(test))]
    {
        let mut store = load_store()?;
        store.data.providers.insert(
            provider_id.to_owned(),
            CachedProvider {
                updated_at: now_secs(),
                identity: scope.map(|scope| scope.identity.clone()),
                client_version: scope.map(|scope| scope.client_version.clone()),
                etag,
                models,
            },
        );
        store.save()
    }
}

fn load_store() -> io::Result<Store> {
    Store::load_from(Store::default_path())
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

struct Store {
    path: PathBuf,
    data: FileShape,
}

impl Store {
    fn default_path() -> PathBuf {
        crate::util::grok_home::grok_home().join(FILE_NAME)
    }

    fn load_from(path: PathBuf) -> io::Result<Self> {
        let data = if path.exists() {
            let raw = fs::read_to_string(&path)?;
            serde_json::from_str(&raw).unwrap_or_default()
        } else {
            FileShape::default()
        };
        Ok(Self { path, data })
    }

    fn save(&self) -> io::Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(&self.data)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let tmp = self.path.with_extension("json.tmp");
        let mut file = fs::File::create(&tmp)?;
        file.write_all(json.as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CachedModel, CachedProvider, ClaudeFamily, CodexCatalogResponse, RemoteModel,
        codex_models_url, fetch_codex_model_list, filter_live, humanize_api_model,
        latest_claude_from_ids, parse_claude_id, parse_codex_models_json,
    };
    use xai_grok_sampling_types::ReasoningEffort;

    fn remote(id: &str, name: &str) -> RemoteModel {
        RemoteModel {
            api_model: id.into(),
            name: name.into(),
            context_window: 200_000,
        }
    }

    #[test]
    fn parse_canonical_claude_ids() {
        let opus5 = parse_claude_id("claude-opus-5").unwrap();
        assert_eq!(opus5.family, ClaudeFamily::Opus);
        assert_eq!((opus5.major, opus5.minor, opus5.fast), (5, 0, false));
        let opus46 = parse_claude_id("claude-opus-4-6").unwrap();
        assert_eq!((opus46.major, opus46.minor), (4, 6));
        let fast = parse_claude_id("claude-opus-5-fast").unwrap();
        assert!(fast.fast);
        assert!(parse_claude_id("claude-opus-4-6@eu").is_none());
        assert!(parse_claude_id("claude-opus-4-6-thinking").is_none());
        assert!(parse_claude_id("claude-haiku-4-5-20251001").is_none());
        assert!(parse_claude_id("claude-mythos-5").is_none());
        assert!(parse_claude_id("claude-fable-latest").is_none());
    }

    #[test]
    fn latest_per_family_drops_old_generations() {
        let ids = latest_claude_from_ids([
            "claude-opus-4-6".into(),
            "claude-opus-5".into(),
            "claude-opus-5-fast".into(),
            "claude-sonnet-4-6".into(),
            "claude-sonnet-5".into(),
            "claude-haiku-4-5".into(),
            "claude-fable-5".into(),
            "claude-opus-4-8".into(),
        ]);
        let set: Vec<&str> = ids.iter().map(|m| m.api_model.as_str()).collect();
        assert!(set.contains(&"claude-fable-5"));
        assert!(set.contains(&"claude-opus-5"));
        assert!(set.contains(&"claude-opus-5-fast"));
        assert!(set.contains(&"claude-sonnet-5"));
        assert!(set.contains(&"claude-haiku-4-5"));
        assert!(!set.contains(&"claude-opus-4-6"));
        assert!(!set.contains(&"claude-opus-4-8"));
        assert!(!set.contains(&"claude-sonnet-4-6"));
    }

    #[test]
    fn live_anthropic_keeps_available_generations() {
        let models = filter_live(
            "anthropic-claude",
            vec![
                remote("claude-fable-5", "Claude Fable 5"),
                remote("claude-opus-5", "Claude Opus 5"),
                remote("claude-opus-4-6", "Claude Opus 4.6"),
                remote("claude-opus-4-6-thinking", "nope"),
                remote("claude-haiku-4-5-20251001", "dated"),
            ],
        );
        let ids: Vec<&str> = models.iter().map(|m| m.api_model.as_str()).collect();
        assert_eq!(ids, ["claude-fable-5", "claude-opus-5", "claude-opus-4-6"]);
    }

    #[test]
    fn live_openai_drops_non_chat() {
        let models = filter_live(
            "openai",
            vec![
                remote("gpt-5.6", "GPT-5.6"),
                remote("gpt-4o", "GPT-4o"),
                remote("whisper-1", "Whisper"),
                remote("dall-e-3", "DALL·E"),
                remote("text-embedding-3-large", "embed"),
            ],
        );
        let ids: Vec<&str> = models.iter().map(|m| m.api_model.as_str()).collect();
        assert_eq!(ids, ["gpt-5.6", "gpt-4o"]);
    }

    #[test]
    fn codex_catalog_uses_slug_visibility_priority_and_reasoning() {
        let payload = serde_json::json!({
            "models": [
                {
                    "slug": "gpt-hidden",
                    "display_name": "Hidden",
                    "visibility": "hide",
                    "priority": 0,
                    "context_window": 128000,
                    "supported_reasoning_levels": []
                },
                {
                    "slug": "gpt-5.6-terra",
                    "display_name": "GPT-5.6 Terra",
                    "description": "Deep work",
                    "visibility": "list",
                    "priority": 20,
                    "context_window": 1050000,
                    "default_reasoning_level": "high",
                    "supported_reasoning_levels": [
                        {"effort": "low", "description": "Fast"},
                        {"effort": "high", "description": "Deep"},
                        {"effort": "ultra", "description": "Future value"}
                    ]
                },
                {
                    "slug": "gpt-5.6-sol",
                    "display_name": "GPT-5.6 Sol",
                    "visibility": "list",
                    "priority": 10,
                    "context_window": 1050000,
                    "default_reasoning_level": "medium",
                    "supported_reasoning_levels": [
                        {"effort": "medium", "description": "Balanced"}
                    ]
                }
            ]
        });

        let models = parse_codex_models_json(&payload);
        let ids: Vec<&str> = models.iter().map(|m| m.api_model.as_str()).collect();
        assert_eq!(ids, ["gpt-5.6-sol", "gpt-5.6-terra"]);
        assert_eq!(models[1].description.as_deref(), Some("Deep work"));
        assert_eq!(models[1].context_window, 1_050_000);
        assert_eq!(models[1].reasoning_efforts.len(), 2);
        assert_eq!(models[1].reasoning_efforts[0].value, ReasoningEffort::Low);
        assert!(models[1].reasoning_efforts[1].default);
    }

    #[test]
    fn codex_models_url_includes_whole_client_version() {
        assert_eq!(
            codex_models_url("https://chatgpt.com/backend-api/codex/", "1.2.3-alpha.4")
                .unwrap()
                .as_str(),
            "https://chatgpt.com/backend-api/codex/models?client_version=1.2.3"
        );
    }

    #[tokio::test]
    async fn codex_fetch_sends_account_headers_and_handles_etag_revalidation() {
        use axum::extract::Query;
        use axum::http::{HeaderMap, StatusCode, header};
        use axum::response::IntoResponse;
        use axum::routing::get;
        use axum::{Json, Router};
        use std::collections::HashMap;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::sync::mpsc;

        let calls = Arc::new(AtomicUsize::new(0));
        let calls_for_route = calls.clone();
        let (request_tx, mut request_rx) = mpsc::unbounded_channel();
        let app = Router::new().route(
            "/models",
            get(
                move |headers: HeaderMap, Query(query): Query<HashMap<String, String>>| {
                    let request_tx = request_tx.clone();
                    let calls = calls_for_route.clone();
                    async move {
                        request_tx.send((headers.clone(), query)).unwrap();
                        if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                            return (
                                [(header::ETAG, "\"catalog-a\"")],
                                Json(serde_json::json!({
                                    "models": [{
                                        "slug": "gpt-live",
                                        "display_name": "GPT Live",
                                        "visibility": "list",
                                        "priority": 1,
                                        "context_window": 400000,
                                        "supported_reasoning_levels": []
                                    }]
                                })),
                            )
                                .into_response();
                        }
                        StatusCode::NOT_MODIFIED.into_response()
                    }
                },
            ),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let base_url = format!("http://{address}");
        let extra_headers = vec![
            ("chatgpt-account-id".into(), "account-a".into()),
            ("originator".into(), "grok-build".into()),
        ];

        let first = fetch_codex_model_list(&base_url, "access-a", &extra_headers, None)
            .await
            .unwrap();
        assert!(matches!(first, CodexCatalogResponse::Modified(_)));
        let (headers, query) = request_rx.recv().await.unwrap();
        assert_eq!(
            headers.get(header::AUTHORIZATION).unwrap(),
            "Bearer access-a"
        );
        assert_eq!(headers.get("chatgpt-account-id").unwrap(), "account-a");
        let expected_version = super::codex_client_version();
        assert_eq!(
            query.get("client_version").map(String::as_str),
            Some(expected_version.as_str())
        );

        let second =
            fetch_codex_model_list(&base_url, "access-a", &extra_headers, Some("\"catalog-a\""))
                .await
                .unwrap();
        assert!(matches!(second, CodexCatalogResponse::NotModified));
        let (headers, _) = request_rx.recv().await.unwrap();
        assert_eq!(headers.get(header::IF_NONE_MATCH).unwrap(), "\"catalog-a\"");
        server.abort();
    }

    #[test]
    fn codex_cache_is_scoped_and_becomes_stale_after_five_minutes() {
        let mut cached = CachedProvider {
            updated_at: 1_000,
            identity: Some("account-a".into()),
            client_version: Some("1.2.3".into()),
            etag: Some("etag-a".into()),
            models: vec![],
        };
        let scope = super::CodexCacheScope {
            identity: "account-a".into(),
            client_version: "1.2.3".into(),
        };
        assert!(cached.matches_codex_scope("account-a", "1.2.3"));
        assert!(!cached.matches_codex_scope("account-b", "1.2.3"));
        assert!(!cached.matches_codex_scope("account-a", "1.2.4"));
        assert_eq!(
            cached.etag_for_codex_scope(&scope).as_deref(),
            Some("etag-a")
        );
        assert!(cached.is_fresh_at(1_299));
        assert!(!cached.is_fresh_at(1_300));
        assert_eq!(cached.touch_codex_scope(&scope, 1_300), Some(0));
        assert!(cached.is_fresh_at(1_300));
    }

    #[test]
    fn humanize_joins_version_digits() {
        assert_eq!(humanize_api_model("claude-opus-4-6"), "Claude Opus 4.6");
        assert_eq!(humanize_api_model("claude-fable-5"), "Claude Fable 5");
        assert_eq!(
            humanize_api_model("claude-opus-5-fast"),
            "Claude Opus 5 Fast"
        );
    }

    #[test]
    fn snapshot_fallback_includes_current_claude_lineup() {
        let ids: Vec<String> = super::models_dev_fallback("anthropic-claude")
            .into_iter()
            .map(|m| m.api_model)
            .collect();
        assert!(
            ids.iter().any(|id| id == "claude-fable-5"),
            "fable missing: {ids:?}"
        );
        assert!(
            ids.iter().any(|id| id == "claude-opus-5"),
            "opus 5 missing: {ids:?}"
        );
        assert!(
            ids.iter().any(|id| id == "claude-sonnet-5"),
            "sonnet 5 missing: {ids:?}"
        );
        assert!(
            ids.iter().any(|id| id == "claude-haiku-4-5"),
            "haiku missing: {ids:?}"
        );
        assert!(
            !ids.iter().any(|id| id == "claude-opus-4-6"),
            "stale opus 4.6 still listed: {ids:?}"
        );
    }

    #[test]
    fn cached_model_roundtrip_json() {
        let model = CachedModel {
            api_model: "claude-fable-5".into(),
            name: "Claude Fable 5".into(),
            context_window: 1_000_000,
            description: None,
            reasoning_efforts: Vec::new(),
        };
        let json = serde_json::to_string(&model).unwrap();
        let back: CachedModel = serde_json::from_str(&json).unwrap();
        assert_eq!(back.api_model, "claude-fable-5");
        assert_eq!(back.context_window, 1_000_000);
    }
}
