use super::*;
use crate::managed_config::LaunchProfile;
use crate::remote::{ModelSource, active_model_source};

// ── Fetch ───────────────────────────────────────────────────────────────────

pub(crate) fn build_prefetched_map(
    models: Vec<config::ModelEntryConfig>,
    api_base_url_override: Option<String>,
) -> IndexMap<String, ModelEntry> {
    let mut map: IndexMap<String, ModelEntry> = IndexMap::with_capacity(models.len());
    for m in models {
        let key = m.id.clone().unwrap_or_else(|| m.model.clone());
        let info = config::ModelInfo::from_config(&m);
        let entry = ModelEntry {
            info,
            mtls_cert_dir: None,
            api_key: None,
            env_key: None,
            auth_provider: None,
            api_base_url: m.api_base_url.clone().or(api_base_url_override.clone()),
        };
        map.insert(key, entry);
    }
    map
}

/// Fetch remote models. Checks disk cache first; persists after fetch.
pub(crate) fn prefetch_models_blocking(
    endpoints: &config::EndpointsConfig,
    auth: Option<&GrokAuth>,
    fetch_auth: ModelFetchAuth,
) -> Option<IndexMap<String, ModelEntry>> {
    prefetch_models_blocking_gated(
        endpoints,
        auth,
        fetch_auth,
        crate::util::config::resolve_remote_fetch_enabled(),
    )
}

/// Whether the startup settings fetch ran and what it produced. Separates a
/// skipped fetch (no session auth) from a real failure so a no-auth boot is not
/// misclassified as a degraded start.
pub(in crate::agent::models) enum SettingsPrefetch {
    /// Boxed because `RemoteSettings` is large and the other variants are unit-sized.
    Fetched(Box<crate::util::config::RemoteSettings>),
    /// A fetch ran but yielded no settings (rejected/transient/exhausted).
    Failed,
    /// No fetch ran (no session auth or remote fetch disabled): not degraded.
    Skipped,
}

/// Fetch models + settings without touching disk; the cache write is returned
/// for the caller to commit.
fn prefetch_uncommitted(
    endpoints: &config::EndpointsConfig,
    auth: Option<&GrokAuth>,
    fetch_auth: ModelFetchAuth,
) -> (ModelsPrefetch, SettingsPrefetch, Option<SettingsCacheWrite>) {
    // Resolved once so both fetches see the same policy.
    let remote_fetch_enabled = crate::util::config::resolve_remote_fetch_enabled();
    let models = {
        let _timer = crate::instrumentation_timer!("startup.early_models_fetch");
        fetch_models_uncommitted(endpoints, auth, fetch_auth, remote_fetch_enabled)
    };
    let (settings, settings_write) = match auth {
        Some(auth) if remote_fetch_enabled => {
            let origin = endpoints.proxy_url();
            let alpha_test_key = endpoints.alpha_test_key.as_deref();
            let (settings, settings_write) =
                SettingsCacheManager::new().load_or_fetch(auth, &origin, alpha_test_key, || {
                    let _timer = crate::instrumentation_timer!("startup.early_settings_fetch");
                    crate::remote::fetch_settings_blocking(&origin, auth, alpha_test_key)
                        .into_option()
                });
            // A real attempt yielding nothing is a failure, not a skip.
            let settings = match settings {
                Some(settings) => SettingsPrefetch::Fetched(Box::new(settings)),
                None => SettingsPrefetch::Failed,
            };
            (settings, settings_write)
        }
        _ => (SettingsPrefetch::Skipped, None),
    };
    (models, settings, settings_write)
}

fn prefetch_models_blocking_gated(
    endpoints: &config::EndpointsConfig,
    auth: Option<&GrokAuth>,
    fetch_auth: ModelFetchAuth,
    remote_fetch_enabled: bool,
) -> Option<IndexMap<String, ModelEntry>> {
    fetch_models_uncommitted(endpoints, auth, fetch_auth, remote_fetch_enabled).commit()
}

/// A models fetch not yet written to the disk cache; the commit point decides
/// whether any state lands.
pub(in crate::agent::models) enum ModelsPrefetch {
    Cached(IndexMap<String, ModelEntry>),
    Fetched(ModelsCacheWrite),
    Unavailable,
}

impl ModelsPrefetch {
    fn commit(self) -> Option<IndexMap<String, ModelEntry>> {
        match self {
            Self::Cached(models) => Some(models),
            Self::Fetched(write) => Some(write.commit()),
            Self::Unavailable => None,
        }
    }

    pub(in crate::agent::models) fn into_deferred_write(self) -> Option<ModelsCacheWrite> {
        match self {
            Self::Fetched(write) => Some(write),
            Self::Cached(_) | Self::Unavailable => None,
        }
    }
}

pub(in crate::agent::models) struct ModelsCacheWrite {
    models: IndexMap<String, ModelEntry>,
    etag: Option<String>,
    auth_method: CacheAuthMethod,
    origin: String,
}

impl ModelsCacheWrite {
    pub(in crate::agent::models) fn commit(self) -> IndexMap<String, ModelEntry> {
        ModelsCacheManager::new().persist(
            &self.models,
            self.etag.as_deref(),
            self.auth_method,
            &self.origin,
        );
        self.models
    }
}

fn fetch_models_uncommitted(
    endpoints: &config::EndpointsConfig,
    auth: Option<&GrokAuth>,
    fetch_auth: ModelFetchAuth,
    remote_fetch_enabled: bool,
) -> ModelsPrefetch {
    let cache_auth = fetch_auth.cache_auth_method();
    let source = active_model_source(endpoints, fetch_auth);
    let cache_origin = source.cache_origin();

    let cache = ModelsCacheManager::new();
    if let Some(cached) = cache.load_fresh(&cache_auth, &cache_origin) {
        return ModelsPrefetch::Cached(cached.models);
    }

    if !remote_fetch_enabled {
        tracing::info!("models fetch skipped: remote_fetch disabled");
        return ModelsPrefetch::Unavailable;
    }

    let _timer = crate::instrumentation_timer!("startup.fetch_models_blocking");
    match source.fetch(auth) {
        Ok(FetchModelsResult { models, etag }) if !models.is_empty() => {
            let api_base_url_override = match fetch_auth {
                ModelFetchAuth::ApiKey => Some(endpoints.xai_api_base_url.clone()),
                _ => None,
            };
            let map = build_prefetched_map(models, api_base_url_override);

            tracing::info!(count = map.len(), etag = ?etag, "Prefetched models");
            ModelsPrefetch::Fetched(ModelsCacheWrite {
                models: map,
                etag,
                auth_method: cache_auth,
                origin: cache_origin,
            })
        }
        Ok(FetchModelsResult { .. }) => {
            tracing::warn!("Models endpoint returned empty list");
            ModelsPrefetch::Unavailable
        }
        Err(e) => {
            tracing::warn!("Failed to fetch models: {:?}", e);
            ModelsPrefetch::Unavailable
        }
    }
}

pub(crate) struct PrefetchEnv {
    pub(crate) auth: Option<GrokAuth>,
    pub(crate) endpoints: config::EndpointsConfig,
    pub(crate) model_fetch_auth: ModelFetchAuth,
}

/// Resolves startup endpoints from the effective config rather than env vars alone, so the prefetch cannot leak the bearer to api.x.ai.
pub(in crate::agent::models) fn resolve_startup_endpoints() -> config::EndpointsConfig {
    let mut endpoints = config::EndpointsConfig::from_effective_config();
    if endpoints.deployment_key.is_none() {
        endpoints.deployment_key = crate::managed_config::resolve_deployment_key();
    }
    endpoints
}

/// Decides whether the startup prefetch runs; takes auth and endpoints as parameters so tests skip the config loading.
pub(crate) fn resolve_prefetch_env_from_parts(
    auth: Option<GrokAuth>,
    endpoints: config::EndpointsConfig,
    remote_fetch_enabled: bool,
) -> Option<PrefetchEnv> {
    if !remote_fetch_enabled {
        tracing::info!("startup model/settings prefetch skipped: remote_fetch disabled");
        return None;
    }

    let model_fetch_auth = ModelFetchAuth::resolve(&endpoints, auth.is_some());

    if auth.is_none()
        && !endpoints.has_custom_endpoint()
        && model_fetch_auth == ModelFetchAuth::Session
    {
        return None;
    }

    Some(PrefetchEnv {
        auth,
        endpoints,
        model_fetch_auth,
    })
}

/// Never touches managed config: the refresh supervisor owns syncing, so a
/// live server cannot heal a tampered policy ahead of the fail-closed gate.
pub(in crate::agent::models) fn prefetch_env(auth: Option<GrokAuth>) -> Option<PrefetchEnv> {
    let _timer = crate::instrumentation_timer!("startup.early_prefetch_launch");
    resolve_prefetch_env_from_parts(
        auth,
        resolve_startup_endpoints(),
        crate::util::config::resolve_remote_fetch_enabled(),
    )
}

pub(in crate::agent::models) fn resolve_disk_auth(
    grok_com_config: Option<GrokComConfig>,
) -> Option<GrokAuth> {
    let grok_home = crate::util::grok_home::grok_home();
    AuthManager::new_with_proxy_base_url(
        &grok_home,
        grok_com_config.unwrap_or_default(),
        crate::agent::config::EndpointsConfig::from_effective_config().proxy_url(),
    )
    .current()
}

pub(in crate::agent::models) fn run_prefetch(
    env: PrefetchEnv,
) -> (ModelsPrefetch, SettingsPrefetch, Option<SettingsCacheWrite>) {
    let mut timer = crate::instrumentation_timer!("startup.early_prefetch");
    let proxy_endpoint = env.endpoints.proxy_url();
    timer.with_field("endpoint", proxy_endpoint.as_str());
    prefetch_uncommitted(&env.endpoints, env.auth.as_ref(), env.model_fetch_auth)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, strum::AsRefStr, strum::IntoStaticStr)]
pub(crate) enum DegradedStartCause {
    #[strum(serialize = "settings fetch failed")]
    FetchFailed,
    #[strum(serialize = "deadline missed")]
    DeadlineMissed,
    #[strum(serialize = "prefetch thread died")]
    ThreadDied,
}

pub(crate) fn record_degraded_start(
    cause: DegradedStartCause,
    profile: LaunchProfile,
    deadline: std::time::Duration,
    wait: std::time::Duration,
) {
    xai_grok_telemetry::unified_log::emit(
        degraded_log_level(profile),
        "startup proceeding without remote settings",
        None,
        Some(serde_json::json!({
            "cause": cause.as_ref(),
            "deadline_ms": deadline.as_millis() as u64,
            "wait_ms": wait.as_millis() as u64,
            "outcome": "settings unavailable at gate time",
        })),
    );
}

pub(crate) fn degraded_log_level(
    profile: LaunchProfile,
) -> xai_grok_telemetry::unified_log::LogLevel {
    use xai_grok_telemetry::unified_log::LogLevel;
    match profile {
        LaunchProfile::Managed => LogLevel::Warn,
        LaunchProfile::Personal => LogLevel::Debug,
    }
}
