//! User-defined providers (`~/.grok/vendor-providers.json`).
//!
//! Specs (name, base URL, protocol, enabled models) live here. Secrets
//! stay in `vendor-auth.json`. Nothing is written to `config.toml`.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use xai_grok_sampler::AuthScheme;
use xai_grok_sampling_types::ApiBackend;

use std::num::NonZeroU64;

use indexmap::IndexMap;

use super::auth_store::VendorAuthStore;
use super::catalog::provider_by_id;
use super::probe::VendorLoginError;
use crate::agent::config::{ModelEntry, ModelInfo};
use crate::util::grok_home::grok_home;

const FILE_NAME: &str = "vendor-providers.json";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct FileShape {
    #[serde(default)]
    providers: BTreeMap<String, CustomProvider>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomProvider {
    pub id: String,
    pub name: String,
    pub base_url: String,
    pub api_backend: String,
    pub auth_scheme: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anthropic_version: Option<String>,
    #[serde(default)]
    pub models: Vec<CustomModel>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomModel {
    pub api_model: String,
    #[serde(default)]
    pub name: String,
    #[serde(default = "default_context_window")]
    pub context_window: u64,
    #[serde(default)]
    pub supports_reasoning_effort: bool,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_context_window() -> u64 {
    128_000
}

fn default_enabled() -> bool {
    true
}

impl CustomProvider {
    pub fn api_backend(&self) -> ApiBackend {
        parse_api_backend(&self.api_backend)
    }

    pub fn auth_scheme(&self) -> AuthScheme {
        parse_auth_scheme(&self.auth_scheme)
    }

    pub fn enabled_models(&self) -> impl Iterator<Item = &CustomModel> {
        self.models.iter().filter(|m| m.enabled)
    }
}

pub fn parse_api_backend(s: &str) -> ApiBackend {
    match s {
        "responses" => ApiBackend::Responses,
        "messages" => ApiBackend::Messages,
        _ => ApiBackend::ChatCompletions,
    }
}

pub fn parse_auth_scheme(s: &str) -> AuthScheme {
    match s {
        "x-api-key" | "x_api_key" => AuthScheme::XApiKey,
        _ => AuthScheme::Bearer,
    }
}

pub fn backend_label(backend: ApiBackend) -> &'static str {
    match backend {
        ApiBackend::ChatCompletions => "chat_completions",
        ApiBackend::Responses => "responses",
        ApiBackend::Messages => "messages",
    }
}

pub fn scheme_for_backend(backend: ApiBackend) -> AuthScheme {
    match backend {
        ApiBackend::Messages => AuthScheme::XApiKey,
        _ => AuthScheme::Bearer,
    }
}

pub fn slugify(name: &str) -> String {
    let mut out = String::new();
    let mut dash = false;
    for c in name.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
            dash = false;
        } else if !dash && !out.is_empty() {
            out.push('-');
            dash = true;
        }
    }
    let slug = out.trim_matches('-').to_owned();
    if slug.is_empty() {
        "custom".into()
    } else {
        slug
    }
}

const RESERVED_IDS: &[&str] = &["custom", "add"];

fn id_taken(id: &str) -> bool {
    RESERVED_IDS.iter().any(|reserved| *reserved == id)
        || provider_by_id(id).is_some()
        || CustomProviderStore::default_store()
            .ok()
            .is_some_and(|s| s.has(id))
}

pub fn unique_id(name: &str) -> String {
    let base = slugify(name);
    if !id_taken(&base) {
        return base;
    }
    for n in 2..100 {
        let candidate = format!("{base}-{n}");
        if !id_taken(&candidate) {
            return candidate;
        }
    }
    format!("{base}-custom")
}

pub fn normalize_base_url(url: &str) -> String {
    url.trim().trim_end_matches('/').to_owned()
}

pub fn display_name(id: &str) -> Option<String> {
    CustomProviderStore::default_store()
        .ok()
        .and_then(|s| s.get(id).map(|p| p.name.clone()))
}

/// Match a sampling `base_url` to a user-defined provider.
pub(crate) fn provider_id_for_base_url(base_url: &str) -> Option<String> {
    #[cfg(test)]
    {
        let _ = base_url;
        return None;
    }
    #[cfg(not(test))]
    {
        let url = normalize_base_url(base_url);
        if url.is_empty() {
            return None;
        }
        let store = CustomProviderStore::default_store().ok()?;
        store.list().find_map(|provider| {
            let base = normalize_base_url(&provider.base_url);
            (url == base || url.starts_with(&format!("{base}/"))).then(|| provider.id.clone())
        })
    }
}

pub struct CustomProviderStore {
    path: PathBuf,
    data: FileShape,
}

impl CustomProviderStore {
    pub fn default_path() -> PathBuf {
        grok_home().join(FILE_NAME)
    }

    pub fn default_store() -> io::Result<Self> {
        Self::load_from(Self::default_path())
    }

    pub fn load_from(path: PathBuf) -> io::Result<Self> {
        let data = if path.exists() {
            let raw = fs::read_to_string(&path)?;
            serde_json::from_str(&raw).unwrap_or_default()
        } else {
            FileShape::default()
        };
        Ok(Self { path, data })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn has(&self, id: &str) -> bool {
        self.data.providers.contains_key(id)
    }

    pub fn get(&self, id: &str) -> Option<&CustomProvider> {
        self.data.providers.get(id)
    }

    pub fn list(&self) -> impl Iterator<Item = &CustomProvider> {
        self.data.providers.values()
    }

    pub fn upsert(&mut self, provider: CustomProvider) -> io::Result<()> {
        self.data.providers.insert(provider.id.clone(), provider);
        self.save()
    }

    pub fn remove(&mut self, id: &str) -> io::Result<bool> {
        let existed = self.data.providers.remove(id).is_some();
        if existed {
            self.save()?;
        }
        Ok(existed)
    }

    fn save(&self) -> io::Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(&self.data)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let mut file = fs::File::create(&self.path)?;
        file.write_all(json.as_bytes())?;
        file.sync_all()?;
        Ok(())
    }
}

/// OpenAI/Anthropic-style `/models` listing.
#[derive(Debug, Clone)]
pub struct RemoteModel {
    pub api_model: String,
    pub name: String,
    pub context_window: u64,
}

fn models_endpoint_candidates(base_url: &str) -> Vec<String> {
    let base = normalize_base_url(base_url);
    if base.is_empty() {
        return Vec::new();
    }
    if base.ends_with("/models") {
        return vec![base];
    }
    let mut urls = vec![format!("{base}/models")];
    let lower = base.to_ascii_lowercase();
    if !lower.ends_with("/v1") && !lower.ends_with("/v1beta") && !lower.contains("/v1/") {
        urls.push(format!("{base}/v1/models"));
    }
    urls
}

pub async fn fetch_model_list(
    base_url: &str,
    api_key: &str,
    auth_scheme: AuthScheme,
    anthropic_version: Option<&str>,
) -> Result<Vec<RemoteModel>, VendorLoginError> {
    fetch_model_list_with_headers(base_url, api_key, auth_scheme, anthropic_version, &[]).await
}

pub async fn fetch_model_list_with_headers(
    base_url: &str,
    api_key: &str,
    auth_scheme: AuthScheme,
    anthropic_version: Option<&str>,
    extra_headers: &[(String, String)],
) -> Result<Vec<RemoteModel>, VendorLoginError> {
    let urls = models_endpoint_candidates(base_url);
    if urls.is_empty() {
        return Err(VendorLoginError::Probe("base URL is required".into()));
    }
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .map_err(|e| VendorLoginError::Probe(e.to_string()))?;
    let mut last_error = String::from("couldn't list models");
    for url in urls {
        let mut req = client.get(&url);
        if !api_key.trim().is_empty() {
            match auth_scheme {
                AuthScheme::XApiKey => {
                    req = req.header("x-api-key", api_key.trim());
                }
                AuthScheme::Bearer => {
                    req = req.bearer_auth(api_key.trim());
                }
            }
        }
        if let Some(version) = anthropic_version {
            req = req.header("anthropic-version", version);
        }
        for (name, value) in extra_headers {
            if name.eq_ignore_ascii_case("authorization") || name.eq_ignore_ascii_case("x-api-key")
            {
                continue;
            }
            req = req.header(name.as_str(), value.as_str());
        }
        let resp = match req.send().await {
            Ok(resp) => resp,
            Err(e) => {
                last_error = format!("couldn't reach {url}: {e}");
                continue;
            }
        };
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            let snippet: String = body.chars().take(180).collect();
            last_error = format!(
                "{status} from {url}{}",
                if snippet.is_empty() {
                    String::new()
                } else {
                    format!(": {snippet}")
                }
            );
            continue;
        }
        let value: serde_json::Value =
            serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
        let models = parse_models_json(&value);
        if models.is_empty() {
            last_error = format!("{url} returned no models");
            continue;
        }
        return Ok(apply_overlay_limits(models));
    }
    Err(VendorLoginError::Probe(last_error))
}

pub async fn probe_existing(provider_id: &str, api_key: &str) -> Result<(), VendorLoginError> {
    let provider = CustomProviderStore::default_store()?
        .get(provider_id)
        .cloned()
        .ok_or_else(|| VendorLoginError::UnknownProvider(provider_id.to_owned()))?;
    fetch_model_list(
        &provider.base_url,
        api_key,
        provider.auth_scheme(),
        provider.anthropic_version.as_deref(),
    )
    .await
    .map(|_| ())
}

pub async fn login_existing(provider_id: &str, api_key: &str) -> Result<(), VendorLoginError> {
    probe_existing(provider_id, api_key).await?;
    let mut store = VendorAuthStore::default_store()?;
    if api_key.trim().is_empty() {
        store.mark_connected(provider_id)?;
    } else {
        store.set_api_key(provider_id, api_key.trim().to_owned())?;
    }
    Ok(())
}

pub fn parse_models_json(value: &serde_json::Value) -> Vec<RemoteModel> {
    let arr = value
        .get("data")
        .and_then(|d| d.as_array())
        .or_else(|| value.get("models").and_then(|d| d.as_array()))
        .or_else(|| value.as_array());
    let Some(arr) = arr else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for item in arr {
        if let Some(s) = item.as_str() {
            let api_model = s.trim();
            if api_model.is_empty() {
                continue;
            }
            out.push(RemoteModel {
                api_model: api_model.to_owned(),
                name: api_model.to_owned(),
                context_window: 128_000,
            });
            if out.len() >= 2000 {
                break;
            }
            continue;
        }
        let obj = match item.as_object() {
            Some(o) => o,
            None => continue,
        };
        let api_model = obj
            .get("id")
            .or_else(|| obj.get("model"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim();
        if api_model.is_empty() {
            continue;
        }
        let name = obj
            .get("display_name")
            .or_else(|| obj.get("name"))
            .and_then(|v| v.as_str())
            .unwrap_or(api_model)
            .to_owned();
        let context_window = obj
            .get("context_window")
            .or_else(|| obj.get("context_length"))
            .or_else(|| obj.get("max_context_length"))
            .and_then(|v| v.as_u64())
            .unwrap_or(128_000);
        out.push(RemoteModel {
            api_model: api_model.to_owned(),
            name,
            context_window,
        });
        if out.len() >= 2000 {
            break;
        }
    }
    out
}

fn apply_overlay_limits(mut models: Vec<RemoteModel>) -> Vec<RemoteModel> {
    for model in &mut models {
        if let Some(ctx) = crate::compat::reasoning::lookup_meta(&model.api_model)
            .and_then(|meta| meta.context_window)
        {
            model.context_window = ctx;
        }
    }
    models
}

/// Picker label: provider name plus model name, unless the model already
/// mentions the provider (`GPT-4o (OpenRouter)`).
pub fn vendor_model_display_name(provider_name: &str, model_label: &str) -> String {
    let provider = provider_name.trim();
    let label = model_label.trim();
    if provider.is_empty() {
        return label.to_owned();
    }
    if label.is_empty() {
        return provider.to_owned();
    }
    let lower = label.to_ascii_lowercase();
    let p = provider.to_ascii_lowercase();
    if lower == p || lower.contains(&p) {
        return label.to_owned();
    }
    format!("{provider} · {label}")
}

pub fn get_provider(id: &str) -> Option<CustomProvider> {
    CustomProviderStore::default_store()
        .ok()
        .and_then(|s| s.get(id).cloned())
}

pub fn stored_secret(id: &str) -> Option<String> {
    VendorAuthStore::default_store()
        .ok()
        .and_then(|s| s.api_key(id))
}

pub fn save_custom_provider(spec: CustomProvider, api_key: &str) -> Result<(), VendorLoginError> {
    let mut spec = spec;
    spec.base_url = normalize_base_url(&spec.base_url);
    if spec.api_backend == "messages" && spec.anthropic_version.is_none() {
        spec.anthropic_version = Some("2023-06-01".into());
    }
    let mut catalog = CustomProviderStore::default_store()?;
    let id = spec.id.clone();
    catalog.upsert(spec)?;
    let mut store = VendorAuthStore::default_store()?;
    if !api_key.trim().is_empty() {
        store.set_api_key(&id, api_key.trim().to_owned())?;
    } else if !store.has_provider(&id) {
        store.mark_connected(&id)?;
    }
    Ok(())
}

pub fn is_custom_provider(id: &str) -> bool {
    #[cfg(test)]
    {
        let _ = id;
        return false;
    }
    #[cfg(not(test))]
    CustomProviderStore::default_store()
        .ok()
        .is_some_and(|s| s.has(id))
}

pub fn extend_arg_items(items: &mut Vec<(String, String, String)>) {
    #[cfg(test)]
    {
        let _ = items;
        return;
    }
    #[cfg(not(test))]
    if let Ok(store) = CustomProviderStore::default_store() {
        for p in store.list() {
            let status = if VendorAuthStore::default_store()
                .ok()
                .is_some_and(|s| s.has_provider(&p.id))
            {
                "edit models"
            } else {
                "sign in"
            };
            items.push((
                p.id.clone(),
                p.name.clone(),
                format!("{} · {status}", p.base_url),
            ));
        }
    }
}

/// Merge enabled custom-provider models. Existing keys win.
pub fn merge_into(resolved: &mut IndexMap<String, ModelEntry>) {
    #[cfg(test)]
    {
        let _ = resolved;
        return;
    }
    #[cfg(not(test))]
    {
        let Ok(store) = CustomProviderStore::default_store() else {
            return;
        };
        let auth = VendorAuthStore::default_store().ok();
        for provider in store.list() {
            let unlocked = auth.as_ref().is_some_and(|s| s.has_provider(&provider.id));
            if !unlocked {
                continue;
            }
            merge_one(resolved, provider);
        }
    }
}

pub fn merge_one(resolved: &mut IndexMap<String, ModelEntry>, provider: &CustomProvider) {
    for spec in provider.enabled_models() {
        let key = format!("{}/{}", provider.id, spec.api_model);
        if resolved.contains_key(&key) {
            continue;
        }
        let mut info = ModelInfo::fallback(&spec.api_model);
        info.id = Some(key.clone());
        info.model = spec.api_model.clone();
        info.model_family = Some(provider.id.clone());
        info.base_url = provider.base_url.clone();
        let label = if spec.name.is_empty() {
            spec.api_model.as_str()
        } else {
            spec.name.as_str()
        };
        info.name = Some(vendor_model_display_name(&provider.name, label));
        info.api_backend = provider.api_backend();
        info.auth_scheme = provider.auth_scheme();
        if matches!(provider.api_backend(), ApiBackend::Messages) {
            let version = provider
                .anthropic_version
                .clone()
                .unwrap_or_else(|| "2023-06-01".into());
            info.extra_headers
                .insert("anthropic-version".into(), version);
        }
        info.context_window = NonZeroU64::new(spec.context_window).unwrap_or(info.context_window);
        info.supported_in_api = true;
        info.user_selectable = true;
        crate::compat::reasoning::apply_custom_model_meta(
            &mut info,
            &spec.api_model,
            spec.supports_reasoning_effort,
        );
        resolved.insert(
            key,
            ModelEntry {
                info,
                mtls_cert_dir: None,
                api_key: None,
                env_key: None,
                auth_provider: None,
                api_base_url: None,
            },
        );
    }
}

/// Merge a live `/models` listing into a stored custom-provider list.
///
/// Existing rows keep `enabled` and `supports_reasoning_effort`. New live
/// rows are enabled. Manual rows that the endpoint does not return are kept.
pub fn merge_live_models(stored: &[CustomModel], live: Vec<RemoteModel>) -> Vec<CustomModel> {
    let stored_by_id: std::collections::HashMap<&str, &CustomModel> =
        stored.iter().map(|m| (m.api_model.as_str(), m)).collect();
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for model in live {
        let api_model = model.api_model.trim();
        if api_model.is_empty() || !seen.insert(api_model.to_owned()) {
            continue;
        }
        let prev = stored_by_id.get(api_model).copied();
        let name = if model.name.trim().is_empty() || model.name == model.api_model {
            prev.filter(|m| !m.name.is_empty())
                .map(|m| m.name.clone())
                .unwrap_or_else(|| model.api_model.clone())
        } else {
            model.name
        };
        out.push(CustomModel {
            api_model: api_model.to_owned(),
            name,
            context_window: model.context_window,
            supports_reasoning_effort: prev
                .map(|m| m.supports_reasoning_effort)
                .unwrap_or_else(|| crate::compat::reasoning::model_supports(api_model)),
            enabled: prev.map(|m| m.enabled).unwrap_or(true),
        });
    }
    for model in stored {
        if seen.contains(model.api_model.as_str()) {
            continue;
        }
        out.push(model.clone());
    }
    out
}

/// Signed-in custom provider ids (empty in unit tests).
pub fn unlocked_ids() -> Vec<String> {
    #[cfg(test)]
    {
        Vec::new()
    }
    #[cfg(not(test))]
    {
        let Ok(store) = CustomProviderStore::default_store() else {
            return Vec::new();
        };
        let auth = VendorAuthStore::default_store().ok();
        store
            .list()
            .filter(|p| auth.as_ref().is_some_and(|s| s.has_provider(&p.id)))
            .map(|p| p.id.clone())
            .collect()
    }
}

/// Re-fetch `/models` for a saved custom provider and merge into
/// `vendor-providers.json`. GROK_COMPAT_HOOK.
pub async fn refresh(provider_id: &str) -> Result<usize, VendorLoginError> {
    #[cfg(test)]
    {
        let _ = provider_id;
        return Ok(0);
    }
    #[cfg(not(test))]
    {
        let mut catalog = CustomProviderStore::default_store()?;
        let Some(mut provider) = catalog.get(provider_id).cloned() else {
            return Ok(0);
        };
        let key = stored_secret(provider_id).unwrap_or_default();
        let listed = fetch_model_list(
            &provider.base_url,
            &key,
            provider.auth_scheme(),
            provider.anthropic_version.as_deref(),
        )
        .await?;
        if listed.is_empty() {
            return Ok(0);
        }
        let n = listed.len();
        provider.models = merge_live_models(&provider.models, listed);
        catalog.upsert(provider)?;
        Ok(n)
    }
}

/// Refresh every signed-in custom provider's live model list.
pub async fn refresh_unlocked() -> usize {
    #[cfg(test)]
    {
        0
    }
    #[cfg(not(test))]
    {
        let mut total = 0;
        for id in unlocked_ids() {
            match refresh(&id).await {
                Ok(n) => total += n,
                Err(error) => {
                    tracing::warn!(
                        provider = %id,
                        error = %error,
                        "custom provider model list refresh failed"
                    );
                }
            }
        }
        total
    }
}

pub fn acp_models_for_custom(
    provider_id: &str,
) -> IndexMap<agent_client_protocol::ModelId, agent_client_protocol::ModelInfo> {
    let mut resolved = IndexMap::new();
    if let Ok(store) = CustomProviderStore::default_store()
        && let Some(provider) = store.get(provider_id)
    {
        merge_one(&mut resolved, provider);
    }
    crate::agent::config::to_acp_model_info(&resolved)
}

#[cfg(test)]
mod tests {
    use super::{
        CustomModel, CustomProvider, CustomProviderStore, RemoteModel, merge_live_models,
        merge_one, models_endpoint_candidates, parse_models_json, slugify,
        vendor_model_display_name,
    };
    use indexmap::IndexMap;
    use xai_grok_sampling_types::ApiBackend;

    #[test]
    fn slugify_name() {
        assert_eq!(slugify("My Corp API"), "my-corp-api");
        assert_eq!(slugify("  "), "custom");
        assert_eq!(slugify("GPT/OpenAI"), "gpt-openai");
    }

    #[test]
    fn models_urls_prefer_v1_when_missing() {
        assert_eq!(
            models_endpoint_candidates("https://api.example.com"),
            vec![
                "https://api.example.com/models".to_owned(),
                "https://api.example.com/v1/models".to_owned()
            ]
        );
        assert_eq!(
            models_endpoint_candidates("https://api.example.com/v1/"),
            vec!["https://api.example.com/v1/models".to_owned()]
        );
    }

    #[test]
    fn parse_openai_models_payload() {
        let v = serde_json::json!({
            "data": [
                {"id": "gpt-4o", "object": "model"},
                {"id": "claude-sonnet-4-6", "display_name": "Claude Sonnet 4.6", "context_window": 200000}
            ]
        });
        let models = parse_models_json(&v);
        assert_eq!(models.len(), 2);
        assert_eq!(models[0].api_model, "gpt-4o");
        assert_eq!(models[1].name, "Claude Sonnet 4.6");
        assert_eq!(models[1].context_window, 200_000);
    }

    #[test]
    fn parse_models_array_and_strings() {
        let v = serde_json::json!({ "models": ["alpha", {"id": "beta", "name": "Beta"}] });
        let models = parse_models_json(&v);
        assert_eq!(models.len(), 2);
        assert_eq!(models[0].api_model, "alpha");
        assert_eq!(models[1].name, "Beta");
    }

    fn stored(id: &str, name: &str, enabled: bool, reasoning: bool) -> CustomModel {
        CustomModel {
            api_model: id.into(),
            name: name.into(),
            context_window: 32_000,
            supports_reasoning_effort: reasoning,
            enabled,
        }
    }

    fn live(id: &str, name: &str, ctx: u64) -> RemoteModel {
        RemoteModel {
            api_model: id.into(),
            name: name.into(),
            context_window: ctx,
        }
    }

    #[test]
    fn merge_live_keeps_flags_adds_new_and_retains_manual() {
        let stored = vec![
            stored("keep", "Keep", true, true),
            stored("off", "Off", false, false),
            stored("manual", "Manual", true, false),
        ];
        let merged = merge_live_models(
            &stored,
            vec![
                live("keep", "Keep v2", 64_000),
                live("off", "Off", 32_000),
                live("new", "New", 128_000),
            ],
        );
        assert_eq!(merged.len(), 4);
        assert_eq!(merged[0].api_model, "keep");
        assert_eq!(merged[0].name, "Keep v2");
        assert_eq!(merged[0].context_window, 64_000);
        assert!(merged[0].enabled);
        assert!(merged[0].supports_reasoning_effort);
        assert!(!merged[1].enabled);
        assert_eq!(merged[2].api_model, "new");
        assert!(merged[2].enabled);
        assert_eq!(merged[3].api_model, "manual");
        assert!(merged[3].enabled);
    }

    #[test]
    fn store_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vendor-providers.json");
        let mut store = CustomProviderStore::load_from(path.clone()).unwrap();
        store
            .upsert(CustomProvider {
                id: "acme".into(),
                name: "Acme".into(),
                base_url: "https://acme.example/v1".into(),
                api_backend: "responses".into(),
                auth_scheme: "bearer".into(),
                anthropic_version: None,
                models: vec![CustomModel {
                    api_model: "acme-large".into(),
                    name: "Acme Large".into(),
                    context_window: 64_000,
                    supports_reasoning_effort: false,
                    enabled: true,
                }],
            })
            .unwrap();
        drop(store);
        let store = CustomProviderStore::load_from(path).unwrap();
        let provider = store.get("acme").unwrap();
        assert_eq!(provider.name, "Acme");
        assert_eq!(provider.api_backend(), ApiBackend::Responses);
        assert_eq!(provider.models[0].api_model, "acme-large");
    }

    #[test]
    fn display_name_prefixes_provider_unless_already_present() {
        assert_eq!(vendor_model_display_name("Acme", "gpt-4o"), "Acme · gpt-4o");
        assert_eq!(
            vendor_model_display_name("OpenRouter", "GPT-4o (OpenRouter)"),
            "GPT-4o (OpenRouter)"
        );
        assert_eq!(vendor_model_display_name("Acme", ""), "Acme");
    }

    #[test]
    fn merge_one_skips_disabled_and_existing() {
        let provider = CustomProvider {
            id: "acme".into(),
            name: "Acme".into(),
            base_url: "https://acme.example/v1".into(),
            api_backend: "chat_completions".into(),
            auth_scheme: "bearer".into(),
            anthropic_version: None,
            models: vec![
                CustomModel {
                    api_model: "keep".into(),
                    name: "Keep".into(),
                    context_window: 32_000,
                    supports_reasoning_effort: false,
                    enabled: true,
                },
                CustomModel {
                    api_model: "skip".into(),
                    name: "Skip".into(),
                    context_window: 32_000,
                    supports_reasoning_effort: false,
                    enabled: false,
                },
            ],
        };
        let mut resolved = IndexMap::new();
        merge_one(&mut resolved, &provider);
        assert!(resolved.contains_key("acme/keep"));
        assert!(!resolved.contains_key("acme/skip"));
        assert_eq!(
            resolved.get("acme/keep").unwrap().info.name.as_deref(),
            Some("Acme · Keep")
        );
        resolved.get_mut("acme/keep").unwrap().info.name = Some("user override".into());
        merge_one(&mut resolved, &provider);
        assert_eq!(
            resolved.get("acme/keep").unwrap().info.name.as_deref(),
            Some("user override")
        );
    }

    #[test]
    fn merge_one_applies_models_dev_reasoning_menu() {
        let provider = CustomProvider {
            id: "openai".into(),
            name: "OpenAI".into(),
            base_url: "https://api.openai.com/v1".into(),
            api_backend: "chat_completions".into(),
            auth_scheme: "bearer".into(),
            anthropic_version: None,
            models: vec![CustomModel {
                api_model: "gpt-5.6-sol".into(),
                name: "GPT-5.6 Sol".into(),
                context_window: 400_000,
                supports_reasoning_effort: true,
                enabled: true,
            }],
        };
        let mut resolved = IndexMap::new();
        merge_one(&mut resolved, &provider);
        let info = &resolved.get("openai/gpt-5.6-sol").unwrap().info;
        assert!(info.supports_reasoning_effort);
        assert!(!info.reasoning_efforts.is_empty());
        assert_eq!(info.context_window.get(), 1_050_000);
        assert_eq!(info.max_completion_tokens, Some(128_000));
    }

    #[test]
    fn merge_one_user_off_strips_models_dev_reasoning() {
        let provider = CustomProvider {
            id: "openai".into(),
            name: "OpenAI".into(),
            base_url: "https://api.openai.com/v1".into(),
            api_backend: "chat_completions".into(),
            auth_scheme: "bearer".into(),
            anthropic_version: None,
            models: vec![CustomModel {
                api_model: "gpt-5.6-sol".into(),
                name: "GPT-5.6 Sol".into(),
                context_window: 400_000,
                supports_reasoning_effort: false,
                enabled: true,
            }],
        };
        let mut resolved = IndexMap::new();
        merge_one(&mut resolved, &provider);
        let info = &resolved.get("openai/gpt-5.6-sol").unwrap().info;
        assert!(!info.supports_reasoning_effort);
        assert!(info.reasoning_efforts.is_empty());
        assert_eq!(info.context_window.get(), 1_050_000);
    }

    #[test]
    fn merge_one_unknown_model_keeps_manual_reasoning_menu() {
        let provider = CustomProvider {
            id: "acme".into(),
            name: "Acme".into(),
            base_url: "https://acme.example/v1".into(),
            api_backend: "chat_completions".into(),
            auth_scheme: "bearer".into(),
            anthropic_version: None,
            models: vec![CustomModel {
                api_model: "proxy-mystery-v1".into(),
                name: "Mystery".into(),
                context_window: 64_000,
                supports_reasoning_effort: true,
                enabled: true,
            }],
        };
        let mut resolved = IndexMap::new();
        merge_one(&mut resolved, &provider);
        let info = &resolved.get("acme/proxy-mystery-v1").unwrap().info;
        assert!(info.supports_reasoning_effort);
        assert_eq!(info.reasoning_efforts.len(), 3);
        assert_eq!(info.context_window.get(), 64_000);
    }
}
