//! Built-in third-party providers and models (Pi-style catalog).

use std::num::NonZeroU64;

use indexmap::IndexMap;

use crate::agent::config::{EnvKeys, ModelEntry, ModelInfo};
#[cfg(not(test))]
use crate::compat::auth_store::VendorAuthStore;
use xai_grok_sampler::AuthScheme;
use xai_grok_sampling_types::ApiBackend;

#[derive(Clone, Debug)]
pub struct ProviderSpec {
    pub id: &'static str,
    pub name: &'static str,
    pub base_url: &'static str,
    pub env_key: Option<&'static str>,
    pub api_backend: ApiBackend,
    pub auth_scheme: AuthScheme,
    pub anthropic_version: Option<&'static str>,
    /// When false, `/provider-login` may persist a connected marker with no key.
    pub requires_auth: bool,
    /// When true, a cached loopback TCP probe can unlock the catalog (Ollama).
    pub local_probe: bool,
    pub models: &'static [VendorModelSpec],
}

#[derive(Clone, Copy, Debug)]
pub struct VendorModelSpec {
    pub api_model: &'static str,
    pub name: &'static str,
    pub context_window: u64,
    pub supports_reasoning_effort: bool,
}

const OPENAI_MODELS: &[VendorModelSpec] = &[
    VendorModelSpec {
        api_model: "gpt-4o",
        name: "GPT-4o",
        context_window: 128_000,
        supports_reasoning_effort: false,
    },
    VendorModelSpec {
        api_model: "gpt-4.1",
        name: "GPT-4.1",
        context_window: 1_047_576,
        supports_reasoning_effort: false,
    },
    VendorModelSpec {
        api_model: "gpt-5",
        name: "GPT-5",
        context_window: 400_000,
        supports_reasoning_effort: true,
    },
    VendorModelSpec {
        api_model: "gpt-5.6",
        name: "GPT-5.6",
        context_window: 400_000,
        supports_reasoning_effort: true,
    },
];

/// Last-resort Claude rows when live `/v1/models` and models.dev both miss.
const ANTHROPIC_MODELS: &[VendorModelSpec] = &[
    VendorModelSpec {
        api_model: "claude-opus-4-6",
        name: "Claude Opus 4.6",
        context_window: 200_000,
        supports_reasoning_effort: true,
    },
    VendorModelSpec {
        api_model: "claude-sonnet-4-6",
        name: "Claude Sonnet 4.6",
        context_window: 200_000,
        supports_reasoning_effort: true,
    },
    VendorModelSpec {
        api_model: "claude-haiku-4-5",
        name: "Claude Haiku 4.5",
        context_window: 200_000,
        supports_reasoning_effort: false,
    },
];

const OPENROUTER_MODELS: &[VendorModelSpec] = &[
    VendorModelSpec {
        api_model: "openai/gpt-4o",
        name: "GPT-4o (OpenRouter)",
        context_window: 128_000,
        supports_reasoning_effort: false,
    },
    VendorModelSpec {
        api_model: "anthropic/claude-sonnet-4.6",
        name: "Claude Sonnet 4.6 (OpenRouter)",
        context_window: 200_000,
        supports_reasoning_effort: true,
    },
];

const DEEPSEEK_MODELS: &[VendorModelSpec] = &[
    VendorModelSpec {
        api_model: "deepseek-chat",
        name: "DeepSeek Chat",
        context_window: 128_000,
        supports_reasoning_effort: false,
    },
    VendorModelSpec {
        api_model: "deepseek-reasoner",
        name: "DeepSeek Reasoner",
        context_window: 128_000,
        supports_reasoning_effort: true,
    },
];

const OPENAI_CODEX_MODELS: &[VendorModelSpec] = &[
    VendorModelSpec {
        api_model: "gpt-5.6-sol",
        name: "GPT-5.6 Sol",
        context_window: 1_050_000,
        supports_reasoning_effort: true,
    },
    VendorModelSpec {
        api_model: "gpt-5.6-terra",
        name: "GPT-5.6 Terra",
        context_window: 1_050_000,
        supports_reasoning_effort: true,
    },
    VendorModelSpec {
        api_model: "gpt-5.6-luna",
        name: "GPT-5.6 Luna",
        context_window: 1_050_000,
        supports_reasoning_effort: true,
    },
    VendorModelSpec {
        api_model: "gpt-5.5",
        name: "GPT-5.5",
        context_window: 1_050_000,
        supports_reasoning_effort: true,
    },
    VendorModelSpec {
        api_model: "gpt-5.4",
        name: "GPT-5.4",
        context_window: 1_050_000,
        supports_reasoning_effort: true,
    },
    VendorModelSpec {
        api_model: "gpt-5.4-mini",
        name: "GPT-5.4 Mini",
        context_window: 400_000,
        supports_reasoning_effort: true,
    },
    VendorModelSpec {
        api_model: "gpt-5",
        name: "GPT-5",
        context_window: 400_000,
        supports_reasoning_effort: true,
    },
];

const OLLAMA_MODELS: &[VendorModelSpec] = &[
    VendorModelSpec {
        api_model: "llama3.1",
        name: "Llama 3.1 (Ollama)",
        context_window: 128_000,
        supports_reasoning_effort: false,
    },
    VendorModelSpec {
        api_model: "qwen2.5-coder",
        name: "Qwen 2.5 Coder (Ollama)",
        context_window: 32_768,
        supports_reasoning_effort: false,
    },
];

const PROVIDERS: &[ProviderSpec] = &[
    ProviderSpec {
        id: "openai",
        name: "OpenAI",
        base_url: "https://api.openai.com/v1",
        env_key: Some("OPENAI_API_KEY"),
        api_backend: ApiBackend::ChatCompletions,
        auth_scheme: AuthScheme::Bearer,
        anthropic_version: None,
        requires_auth: true,
        local_probe: false,
        models: OPENAI_MODELS,
    },
    ProviderSpec {
        id: "openai-codex",
        name: "OpenAI Codex (ChatGPT)",
        // Sampler appends `/responses`; Pi resolves this to
        // `https://chatgpt.com/backend-api/codex/responses`.
        base_url: "https://chatgpt.com/backend-api/codex",
        env_key: None,
        api_backend: ApiBackend::Responses,
        auth_scheme: AuthScheme::Bearer,
        anthropic_version: None,
        requires_auth: true,
        local_probe: false,
        models: OPENAI_CODEX_MODELS,
    },
    ProviderSpec {
        id: "anthropic",
        name: "Anthropic",
        base_url: "https://api.anthropic.com/v1",
        env_key: Some("ANTHROPIC_API_KEY"),
        api_backend: ApiBackend::Messages,
        auth_scheme: AuthScheme::XApiKey,
        anthropic_version: Some("2023-06-01"),
        requires_auth: true,
        local_probe: false,
        models: ANTHROPIC_MODELS,
    },
    ProviderSpec {
        id: "anthropic-claude",
        name: "Claude Pro/Max",
        base_url: "https://api.anthropic.com/v1",
        env_key: None,
        api_backend: ApiBackend::Messages,
        auth_scheme: AuthScheme::Bearer,
        anthropic_version: Some("2023-06-01"),
        requires_auth: true,
        local_probe: false,
        models: ANTHROPIC_MODELS,
    },
    ProviderSpec {
        id: "openrouter",
        name: "OpenRouter",
        base_url: "https://openrouter.ai/api/v1",
        env_key: Some("OPENROUTER_API_KEY"),
        api_backend: ApiBackend::ChatCompletions,
        auth_scheme: AuthScheme::Bearer,
        anthropic_version: None,
        requires_auth: true,
        local_probe: false,
        models: OPENROUTER_MODELS,
    },
    ProviderSpec {
        id: "deepseek",
        name: "DeepSeek",
        base_url: "https://api.deepseek.com/v1",
        env_key: Some("DEEPSEEK_API_KEY"),
        api_backend: ApiBackend::ChatCompletions,
        auth_scheme: AuthScheme::Bearer,
        anthropic_version: None,
        requires_auth: true,
        local_probe: false,
        models: DEEPSEEK_MODELS,
    },
    ProviderSpec {
        id: "ollama",
        name: "Ollama",
        base_url: "http://localhost:11434/v1",
        env_key: None,
        api_backend: ApiBackend::ChatCompletions,
        auth_scheme: AuthScheme::Bearer,
        anthropic_version: None,
        requires_auth: false,
        local_probe: true,
        models: OLLAMA_MODELS,
    },
];

pub fn builtin_providers() -> &'static [ProviderSpec] {
    PROVIDERS
}

pub fn provider_by_id(id: &str) -> Option<&'static ProviderSpec> {
    PROVIDERS.iter().find(|p| p.id == id)
}

fn url_matches_provider(base_url: &str, provider: &ProviderSpec) -> bool {
    let url = base_url.trim().trim_end_matches('/');
    if url.is_empty() {
        return false;
    }
    let base = provider.base_url.trim_end_matches('/');
    url == base || url.starts_with(&format!("{base}/"))
}

/// All builtin vendors that own this sampling URL (Claude Pro shares Anthropic's host).
pub(crate) fn provider_ids_for_base_url(base_url: &str) -> Vec<&'static str> {
    PROVIDERS
        .iter()
        .filter(|provider| url_matches_provider(base_url, provider))
        .map(|provider| provider.id)
        .collect()
}

/// Match a sampling `base_url` to a builtin vendor (prefix, slash-insensitive).
/// When several providers share a host, prefer one that currently has credentials.
pub(crate) fn provider_id_for_base_url(base_url: &str) -> Option<&'static str> {
    let ids = provider_ids_for_base_url(base_url);
    ids.iter()
        .copied()
        .find(|id| store_has_provider(id))
        .or_else(|| ids.first().copied())
}

pub fn provider_display_name(id: &str) -> String {
    if let Some(provider) = provider_by_id(id) {
        return provider.name.to_owned();
    }
    crate::compat::custom::display_name(id).unwrap_or_else(|| id.to_owned())
}

pub(crate) fn catalog_key(provider_id: &str, api_model: &str) -> String {
    format!("{provider_id}/{api_model}")
}

#[cfg(not(test))]
fn env_key_set(name: &str) -> bool {
    std::env::var(name).is_ok_and(|v| !v.trim().is_empty())
}

fn env_key_present(name: &str) -> bool {
    #[cfg(test)]
    {
        if let Some(forced) = unlock_override::env_keys() {
            return forced.iter().any(|k| k == name);
        }
        return false;
    }
    #[cfg(not(test))]
    env_key_set(name)
}

fn store_has_provider(provider_id: &str) -> bool {
    #[cfg(test)]
    {
        if let Some(ids) = unlock_override::store_ids() {
            return ids.iter().any(|id| id == provider_id);
        }
        return false;
    }
    #[cfg(not(test))]
    VendorAuthStore::default_store()
        .ok()
        .is_some_and(|store| store.has_provider(provider_id))
}

fn provider_unlocked(provider: &ProviderSpec) -> bool {
    if provider.env_key.is_some_and(env_key_present) {
        return true;
    }
    if store_has_provider(provider.id) {
        return true;
    }
    provider.local_probe && local_endpoint_reachable(provider.base_url)
}

#[cfg(not(test))]
const LOCAL_PROBE_TTL: std::time::Duration = std::time::Duration::from_secs(5);
#[cfg(not(test))]
const LOCAL_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(150);

fn local_endpoint_reachable(base_url: &str) -> bool {
    #[cfg(test)]
    {
        let _ = base_url;
        if let Some(forced) = unlock_override::local_reachable() {
            return forced;
        }
        return false;
    }
    #[cfg(not(test))]
    cached_loopback_probe(base_url)
}

#[cfg(not(test))]
fn cached_loopback_probe(base_url: &str) -> bool {
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::time::Instant;

    static CACHE: Mutex<Option<HashMap<String, (Instant, bool)>>> = Mutex::new(None);

    let now = Instant::now();
    if let Ok(cache) = CACHE.lock()
        && let Some(map) = cache.as_ref()
        && let Some((at, ok)) = map.get(base_url)
        && now.saturating_duration_since(*at) < LOCAL_PROBE_TTL
    {
        return *ok;
    }

    let ok = loopback_tcp_probe(base_url);
    if let Ok(mut cache) = CACHE.lock() {
        cache
            .get_or_insert_with(HashMap::new)
            .insert(base_url.to_owned(), (now, ok));
    }
    ok
}

#[cfg(not(test))]
fn loopback_tcp_probe(base_url: &str) -> bool {
    use std::net::{TcpStream, ToSocketAddrs};

    let Ok(parsed) = url::Url::parse(base_url) else {
        return false;
    };
    let Some(host) = parsed.host_str() else {
        return false;
    };
    if !matches!(host, "localhost" | "127.0.0.1" | "::1") {
        return false;
    }
    let Some(port) = parsed.port_or_known_default() else {
        return false;
    };
    let Ok(addrs) = (host, port).to_socket_addrs() else {
        return false;
    };
    addrs
        .take(2)
        .any(|addr| TcpStream::connect_timeout(&addr, LOCAL_PROBE_TIMEOUT).is_ok())
}

fn extra_headers(provider: &ProviderSpec) -> indexmap::IndexMap<String, String> {
    let mut headers = indexmap::IndexMap::new();
    if let Some(version) = provider.anthropic_version {
        headers.insert("anthropic-version".into(), version.into());
    }
    if provider.id == "openai-codex" {
        headers.insert("OpenAI-Beta".into(), "responses=experimental".into());
        headers.insert("originator".into(), "grok-build".into());
    }
    headers
}

struct ResolvedModel {
    api_model: String,
    name: String,
    context_window: u64,
    supports_reasoning_effort: bool,
}

fn static_models(provider: &ProviderSpec) -> Vec<ResolvedModel> {
    provider
        .models
        .iter()
        .map(|spec| ResolvedModel {
            api_model: spec.api_model.to_owned(),
            name: spec.name.to_owned(),
            context_window: spec.context_window,
            supports_reasoning_effort: spec.supports_reasoning_effort,
        })
        .collect()
}

#[cfg(not(test))]
fn from_cached(models: Vec<crate::compat::vendor_models::CachedModel>) -> Vec<ResolvedModel> {
    models
        .into_iter()
        .map(|model| {
            let supports_reasoning_effort =
                crate::compat::reasoning::model_supports(&model.api_model);
            ResolvedModel {
                api_model: model.api_model,
                name: model.name,
                context_window: model.context_window,
                supports_reasoning_effort,
            }
        })
        .collect()
}

/// Live cache, then models.dev current generation, then the hardcoded slice.
fn resolved_models(provider: &ProviderSpec) -> Vec<ResolvedModel> {
    #[cfg(test)]
    {
        return static_models(provider);
    }
    #[cfg(not(test))]
    {
        if let Some(cached) = crate::compat::vendor_models::cached_models(provider.id) {
            return from_cached(cached);
        }
        let fallback = crate::compat::vendor_models::models_dev_fallback(provider.id);
        if !fallback.is_empty() {
            return from_cached(fallback);
        }
        static_models(provider)
    }
}

fn model_entry(provider: &ProviderSpec, spec: &ResolvedModel) -> (String, ModelEntry) {
    let key = catalog_key(provider.id, &spec.api_model);
    let mut info = ModelInfo::fallback(&spec.api_model);
    info.id = Some(key.clone());
    info.model = spec.api_model.clone();
    info.model_family = Some(provider.id.to_owned());
    info.base_url = provider.base_url.to_owned();
    info.name = Some(crate::compat::custom::vendor_model_display_name(
        provider.name,
        &spec.name,
    ));
    info.api_backend = provider.api_backend.clone();
    info.auth_scheme = provider.auth_scheme;
    info.extra_headers = extra_headers(provider);
    info.context_window = NonZeroU64::new(spec.context_window).unwrap_or(info.context_window);
    info.supported_in_api = true;
    info.supports_reasoning_effort = spec.supports_reasoning_effort;
    info.user_selectable = true;
    crate::compat::reasoning::apply_to_model_info(&mut info, &spec.api_model);
    let entry = ModelEntry {
        info,
        mtls_cert_dir: None,
        api_key: None,
        env_key: provider.env_key.map(EnvKeys::single),
        auth_provider: None,
        api_base_url: None,
    };
    (key, entry)
}

/// Insert unlocked vendor models. Existing keys (defaults, remote, user
/// config) win.
pub fn merge_vendor_catalog(resolved: &mut IndexMap<String, ModelEntry>) {
    for provider in PROVIDERS {
        if !provider_unlocked(provider) {
            continue;
        }
        for spec in resolved_models(provider) {
            let (key, entry) = model_entry(provider, &spec);
            if !resolved.contains_key(&key) {
                resolved.insert(key, entry);
            }
        }
    }
    crate::compat::custom::merge_into(resolved);
}

/// ACP model infos for a provider's catalog (used by the pager after login).
pub fn acp_models_for_provider(
    provider_id: &str,
) -> IndexMap<agent_client_protocol::ModelId, agent_client_protocol::ModelInfo> {
    let Some(provider) = provider_by_id(provider_id) else {
        return crate::compat::custom::acp_models_for_custom(provider_id);
    };
    let mut entries = IndexMap::new();
    for spec in resolved_models(provider) {
        let (key, entry) = model_entry(provider, &spec);
        entries.insert(key, entry);
    }
    crate::agent::config::to_acp_model_info(&entries)
}

pub(crate) fn provider_is_unlocked(id: &str) -> bool {
    provider_by_id(id).is_some_and(provider_unlocked)
}

pub fn unlocked_provider_ids() -> Vec<String> {
    let mut ids: Vec<String> = PROVIDERS
        .iter()
        .filter(|provider| provider_unlocked(provider))
        .map(|provider| provider.id.to_owned())
        .collect();
    ids.extend(crate::compat::custom::unlocked_ids());
    ids
}

#[cfg(test)]
mod unlock_override {
    use std::cell::RefCell;

    #[derive(Clone, Default)]
    pub(super) struct Unlock {
        pub env: Vec<String>,
        pub store: Vec<String>,
        pub local: bool,
    }

    thread_local! {
        static CURRENT: RefCell<Option<Unlock>> = const { RefCell::new(None) };
    }

    struct ClearOnDrop;
    impl Drop for ClearOnDrop {
        fn drop(&mut self) {
            CURRENT.with(|c| *c.borrow_mut() = None);
        }
    }

    pub(super) fn with(unlock: Unlock, f: impl FnOnce()) {
        CURRENT.with(|c| *c.borrow_mut() = Some(unlock));
        let _guard = ClearOnDrop;
        f();
    }

    pub(super) fn env_keys() -> Option<Vec<String>> {
        CURRENT.with(|c| c.borrow().as_ref().map(|u| u.env.clone()))
    }

    pub(super) fn store_ids() -> Option<Vec<String>> {
        CURRENT.with(|c| c.borrow().as_ref().map(|u| u.store.clone()))
    }

    pub(super) fn local_reachable() -> Option<bool> {
        CURRENT.with(|c| c.borrow().as_ref().map(|u| u.local))
    }
}

#[cfg(test)]
mod tests {
    use super::merge_vendor_catalog;
    use super::provider_id_for_base_url;
    use super::unlock_override::{Unlock, with};
    use indexmap::IndexMap;
    use xai_grok_sampling_types::ApiBackend;

    #[test]
    fn provider_id_for_base_url_matches_codex_and_openai() {
        assert_eq!(
            provider_id_for_base_url("https://chatgpt.com/backend-api/codex"),
            Some("openai-codex")
        );
        assert_eq!(
            provider_id_for_base_url("https://chatgpt.com/backend-api/codex/"),
            Some("openai-codex")
        );
        assert_eq!(
            provider_id_for_base_url("https://chatgpt.com/backend-api/codex/responses"),
            Some("openai-codex")
        );
        assert_eq!(
            provider_id_for_base_url("https://api.openai.com/v1"),
            Some("openai")
        );
        assert_eq!(provider_id_for_base_url("https://api.x.ai/v1"), None);
        assert_eq!(provider_id_for_base_url("http://localhost"), None);
    }

    #[test]
    fn empty_unlock_matches_official_list() {
        with(Unlock::default(), || {
            let mut resolved = IndexMap::new();
            merge_vendor_catalog(&mut resolved);
            assert!(
                resolved.is_empty(),
                "no vendor rows without env, store, or local probe, keys={:?}",
                resolved.keys().collect::<Vec<_>>()
            );
        });
    }

    #[test]
    fn ollama_stays_hidden_without_login_or_probe() {
        with(Unlock::default(), || {
            let mut resolved = IndexMap::new();
            merge_vendor_catalog(&mut resolved);
            assert!(!resolved.contains_key("ollama/llama3.1"));
            assert!(!resolved.contains_key("openai/gpt-4o"));
        });
    }

    #[test]
    fn ollama_listed_after_explicit_connect() {
        with(
            Unlock {
                store: vec!["ollama".into()],
                ..Unlock::default()
            },
            || {
                let mut resolved = IndexMap::new();
                merge_vendor_catalog(&mut resolved);
                assert!(
                    resolved.contains_key("ollama/llama3.1"),
                    "keys={:?}",
                    resolved.keys().collect::<Vec<_>>()
                );
                assert!(!resolved.contains_key("openai/gpt-4o"));
            },
        );
    }

    #[test]
    fn ollama_listed_when_loopback_is_up() {
        with(
            Unlock {
                local: true,
                ..Unlock::default()
            },
            || {
                let mut resolved = IndexMap::new();
                merge_vendor_catalog(&mut resolved);
                assert!(resolved.contains_key("ollama/llama3.1"));
                assert!(resolved.contains_key("ollama/qwen2.5-coder"));
            },
        );
    }

    #[test]
    fn openai_listed_when_env_or_store_present() {
        with(
            Unlock {
                env: vec!["OPENAI_API_KEY".into()],
                ..Unlock::default()
            },
            || {
                let mut resolved = IndexMap::new();
                merge_vendor_catalog(&mut resolved);
                assert!(resolved.contains_key("openai/gpt-5.6"));
                assert!(!resolved.contains_key("anthropic/claude-sonnet-4-6"));
            },
        );
        with(
            Unlock {
                store: vec!["anthropic".into()],
                ..Unlock::default()
            },
            || {
                let mut resolved = IndexMap::new();
                merge_vendor_catalog(&mut resolved);
                assert!(resolved.contains_key("anthropic/claude-opus-4-6"));
                assert!(!resolved.contains_key("openai/gpt-4o"));
            },
        );
    }

    #[test]
    fn existing_keys_win_over_catalog() {
        with(
            Unlock {
                store: vec!["openai".into()],
                ..Unlock::default()
            },
            || {
                let mut resolved = IndexMap::new();
                let mut info = crate::agent::config::ModelInfo::fallback("gpt-4o");
                info.name = Some("user override".into());
                resolved.insert(
                    "openai/gpt-4o".into(),
                    crate::agent::config::ModelEntry {
                        info,
                        mtls_cert_dir: None,
                        api_key: None,
                        env_key: None,
                        auth_provider: None,
                        api_base_url: None,
                    },
                );
                merge_vendor_catalog(&mut resolved);
                assert_eq!(
                    resolved.get("openai/gpt-4o").unwrap().info.name.as_deref(),
                    Some("user override")
                );
            },
        );
    }

    #[test]
    fn openai_api_key_does_not_unlock_codex() {
        with(
            Unlock {
                env: vec!["OPENAI_API_KEY".into()],
                ..Unlock::default()
            },
            || {
                let mut resolved = IndexMap::new();
                merge_vendor_catalog(&mut resolved);
                assert!(resolved.contains_key("openai/gpt-5.6"));
                assert!(!resolved.contains_key("openai-codex/gpt-5.6-sol"));
            },
        );
    }

    #[test]
    fn openai_codex_listed_when_store_present() {
        with(
            Unlock {
                store: vec!["openai-codex".into()],
                ..Unlock::default()
            },
            || {
                let mut resolved = IndexMap::new();
                merge_vendor_catalog(&mut resolved);
                assert!(
                    resolved.contains_key("openai-codex/gpt-5.6-sol"),
                    "keys={:?}",
                    resolved.keys().collect::<Vec<_>>()
                );
                let info = &resolved.get("openai-codex/gpt-5.6-sol").unwrap().info;
                assert_eq!(info.api_backend, ApiBackend::Responses);
                assert_eq!(info.base_url, "https://chatgpt.com/backend-api/codex");
                assert_eq!(
                    info.extra_headers.get("OpenAI-Beta").map(String::as_str),
                    Some("responses=experimental")
                );
                assert!(!resolved.contains_key("openai/gpt-4o"));
            },
        );
    }
}

pub fn arg_items() -> Vec<(String, String, String)> {
    let mut items: Vec<(String, String, String)> = PROVIDERS
        .iter()
        .map(|p| {
            let status = if provider_unlocked(p) {
                "connected"
            } else {
                "sign in"
            };
            (
                p.id.to_owned(),
                p.name.to_owned(),
                format!("{} · {status}", p.base_url),
            )
        })
        .collect();
    crate::compat::custom::extend_arg_items(&mut items);
    items
}
