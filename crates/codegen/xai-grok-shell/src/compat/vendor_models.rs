//! Live vendor model lists, cached under `$GROK_HOME/vendor-catalog.json`.
//!
//! Builtin picker rows prefer:
//! 1. Last successful `/v1/models` fetch for that provider
//! 2. Latest generation per family from the models.dev snapshot
//! 3. The small hardcoded fallback on `ProviderSpec`
//!
//! ChatGPT Codex has no public listing endpoint; it stays on (3).
//!
//! Refresh: login, `/sync-models-dev` (also `/refresh-models`), and the
//! provider-picker `r` shortcut. Custom providers merge into
//! `vendor-providers.json` on the same path.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use super::custom::{RemoteModel, fetch_model_list_with_headers};
use super::probe::VendorLoginError;
use super::reasoning;

const FILE_NAME: &str = "vendor-catalog.json";
const LIVE_LIST_CAP: usize = 40;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct CachedModel {
    pub api_model: String,
    pub name: String,
    #[serde(default)]
    pub context_window: u64,
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
    #[serde(default)]
    models: Vec<CachedModel>,
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

pub(crate) fn lists_remote_models(provider_id: &str) -> bool {
    !matches!(provider_id, "openai-codex")
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
        let models = store.data.providers.get(provider_id)?.models.clone();
        (!models.is_empty()).then_some(models)
    }
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
    if !lists_remote_models(provider.id) {
        return Ok(0);
    }
    let key = super::live_vendor_key_for_id(provider.id).unwrap_or_default();
    if provider.requires_auth && key.trim().is_empty() {
        return Ok(0);
    }
    let extra = listing_headers(provider.id, provider.anthropic_version);
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
    save_models(provider.id, filtered)?;
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

fn listing_headers(provider_id: &str, anthropic_version: Option<&str>) -> Vec<(String, String)> {
    let mut headers = indexmap::IndexMap::new();
    if let Some(version) = anthropic_version {
        headers.insert("anthropic-version".into(), version.to_owned());
    }
    super::oauth::inject_request_headers(provider_id, &mut headers);
    headers.into_iter().collect()
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

fn save_models(provider_id: &str, models: Vec<CachedModel>) -> io::Result<()> {
    #[cfg(test)]
    {
        let _ = (provider_id, models);
        return Ok(());
    }
    #[cfg(not(test))]
    {
        let mut store = load_store()?;
        store.data.providers.insert(
            provider_id.to_owned(),
            CachedProvider {
                updated_at: now_secs(),
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
        CachedModel, ClaudeFamily, RemoteModel, filter_live, humanize_api_model,
        latest_claude_from_ids, parse_claude_id,
    };

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
        };
        let json = serde_json::to_string(&model).unwrap();
        let back: CachedModel = serde_json::from_str(&json).unwrap();
        assert_eq!(back.api_model, "claude-fable-5");
        assert_eq!(back.context_window, 1_000_000);
    }
}
