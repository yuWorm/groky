//! Agent bootstrap and lifecycle hooks.
//!
//! [`bootstrap`] runs the full init sequence (config resolution, process
//! singletons, model catalog) and returns a resolved config + `ModelsManager`.
//! [`update_telemetry_config`] re-initializes telemetry after auth changes.
use crate::agent::config::{self, Config as AgentConfig, ModelEntry};
use crate::agent::models::{ModelsManager, startup_prefetch};
use crate::config::StorageMode;
use crate::managed_config::LaunchProfile;
use indexmap::IndexMap;
use std::sync::{Arc, Mutex, TryLockError};
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use xai_grok_login::AuthManager;
/// The policy refusal stays typed; stringify only at the process boundary.
#[derive(Debug, thiserror::Error)]
pub enum BootstrapError {
    #[error("{0}")]
    PolicyRefusal(crate::managed_config::ManagedPolicyRefusal),
    #[error("{0}")]
    Config(String),
    #[error("bootstrap cancelled")]
    Cancelled,
}
impl From<crate::managed_config::ManagedPolicyRefusal> for BootstrapError {
    fn from(refusal: crate::managed_config::ManagedPolicyRefusal) -> Self {
        Self::PolicyRefusal(refusal)
    }
}
impl From<String> for BootstrapError {
    fn from(message: String) -> Self {
        Self::Config(message)
    }
}
/// One bootstrap at a time. A connect-timeout drop does not abort
/// `spawn_blocking`, so the fallback connect would otherwise overlap
/// `start_refresh_supervisor` / `init_process`.
static BOOTSTRAP_GATE: Mutex<()> = Mutex::new(());
struct BootstrapPermit<'a>(#[allow(dead_code)] std::sync::MutexGuard<'a, ()>);
fn ensure_bootstrap_not_cancelled(cancel: &CancellationToken) -> Result<(), BootstrapError> {
    if cancel.is_cancelled() {
        Err(BootstrapError::Cancelled)
    } else {
        Ok(())
    }
}
/// Spin on [`BOOTSTRAP_GATE`] so a cancelled waiter can bail instead of
/// blocking forever behind a worker that is itself winding down.
fn acquire_bootstrap_gate(
    cancel: &CancellationToken,
) -> Result<BootstrapPermit<'_>, BootstrapError> {
    loop {
        match BOOTSTRAP_GATE.try_lock() {
            Ok(guard) => return Ok(BootstrapPermit(guard)),
            Err(TryLockError::Poisoned(poisoned)) => {
                return Ok(BootstrapPermit(poisoned.into_inner()));
            }
            Err(TryLockError::WouldBlock) => {
                ensure_bootstrap_not_cancelled(cancel)?;
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}
#[cfg(test)]
pub(crate) fn hold_bootstrap_gate_for_tests() -> std::sync::MutexGuard<'static, ()> {
    loop {
        match BOOTSTRAP_GATE.try_lock() {
            Ok(guard) => return guard,
            Err(TryLockError::Poisoned(poisoned)) => return poisoned.into_inner(),
            Err(TryLockError::WouldBlock) => std::thread::sleep(Duration::from_millis(10)),
        }
    }
}
/// Resolve config, init process singletons, build the model catalog.
/// The `ModelsManager` is `Clone + Send`, so callers that need a handle for the config watcher can clone it before passing it to `MvpAgent::with_models`.
pub fn bootstrap(
    cfg: &AgentConfig,
    auth_manager: &Arc<AuthManager>,
    prefetched: Option<IndexMap<String, ModelEntry>>,
) -> Result<(AgentConfig, ModelsManager), BootstrapError> {
    bootstrap_with_cancel(cfg, auth_manager, prefetched, &CancellationToken::new())
}
/// [`bootstrap`] that stops at phase boundaries when `cancel` fires.
/// Connect timeout drops the pager's `spawn_blocking` join; that does not abort the worker. The token is the stop signal, and [`BOOTSTRAP_GATE`] keeps a fallback connect from running `start_refresh_supervisor` / `init_process` beside the one that is still winding down.
pub fn bootstrap_with_cancel(
    cfg: &AgentConfig,
    auth_manager: &Arc<AuthManager>,
    prefetched: Option<IndexMap<String, ModelEntry>>,
    cancel: &CancellationToken,
) -> Result<(AgentConfig, ModelsManager), BootstrapError> {
    let _permit = acquire_bootstrap_gate(cancel)?;
    ensure_bootstrap_not_cancelled(cancel)?;
    xai_grok_telemetry::id::prefetch_agent_id();
    xai_grok_telemetry::startup::enter(xai_grok_telemetry::startup::StartupPhase::Bootstrap);
    let mut cfg = cfg.clone();
    let profile = crate::managed_config::startup_profile();
    let pre_gate_prefetch = {
        let mut timer = crate::instrumentation_timer!("startup.bootstrap.remote_settings");
        timer.with_subphase(xai_grok_telemetry::startup::Subphase::RemoteSettings);
        ensure_remote_settings_side_effects(&mut cfg, profile)
    };
    ensure_bootstrap_not_cancelled(cancel)?;
    {
        let _timer = crate::instrumentation_timer!("startup.bootstrap.policy_gate");
        crate::managed_config::managed_policy_gate()?;
    }
    ensure_bootstrap_not_cancelled(cancel)?;
    if !cfg!(test) {
        crate::managed_config::start_refresh_supervisor(auth_manager);
    }
    let cfg = {
        let mut timer = crate::instrumentation_timer!("startup.bootstrap.resolve_config");
        timer.with_subphase(xai_grok_telemetry::startup::Subphase::ResolveConfig);
        let cfg = resolve_config(&cfg, auth_manager, pre_gate_prefetch, profile);
        cfg.validate_model_filters()?;
        cfg
    };
    ensure_bootstrap_not_cancelled(cancel)?;
    {
        let mut timer = crate::instrumentation_timer!("startup.bootstrap.init_process");
        timer.with_subphase(xai_grok_telemetry::startup::Subphase::InitProcess);
        init_process(&cfg, auth_manager);
    }
    xai_grok_telemetry::startup::enter(xai_grok_telemetry::startup::StartupPhase::ModelCatalog);
    let models_manager = {
        let mut timer = crate::instrumentation_timer!("startup.model_catalog.models_manager");
        timer.with_subphase(xai_grok_telemetry::startup::Subphase::ModelsManager);
        ModelsManager::from_config(&cfg, prefetched, auth_manager.clone())?
    };
    models_manager.start_auth_refresh_watcher(auth_manager.refresh_notifier());
    Ok((cfg, models_manager))
}
/// Prints the error to the user's real stderr (undoing any TUI redirect) and exits.
pub(crate) fn exit_on_config_error<T>(e: BootstrapError) -> T {
    xai_tty_utils::restore_native_stderr();
    eprintln!("\nConfiguration error:\n\n    {e}\n");
    std::process::exit(1);
}
#[must_use]
enum StartupPrefetch {
    Ran,
    ClientSupplied,
}
#[cfg(test)]
thread_local! {
    static PREFETCH_RUNS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}
/// Fill `remote_settings` if absent and apply process-global remote side effects.
/// The boot spends at most one settings retry budget (#278686).
fn ensure_remote_settings_side_effects(
    cfg: &mut AgentConfig,
    profile: LaunchProfile,
) -> StartupPrefetch {
    let ran_prefetch = cfg.remote_settings.is_none();
    if ran_prefetch {
        #[cfg(test)]
        PREFETCH_RUNS.with(|c| c.set(c.get() + 1));
        let deadline = startup_settings_deadline(profile);
        let started = std::time::Instant::now();
        let (settings, source, degraded) = match startup_prefetch::accept_within(deadline) {
            (startup_prefetch::Accept::Consumed(settings), degraded) => {
                (settings.map(|s| *s), "prefetch", degraded)
            }
            (startup_prefetch::Accept::Miss, _) => {
                let (settings, degraded) =
                    startup_prefetch::fetch_now_before_policy_gate(cfg, deadline);
                (settings, "fallback", degraded)
            }
        };
        if let Some(cause) = degraded {
            crate::agent::models::record_degraded_start(
                cause,
                profile,
                deadline,
                started.elapsed(),
            );
        }
        if settings.is_some() {
            cfg.remote_settings = settings;
            crate::util::config::set_remote_campaigns_from_settings(cfg.remote_settings.as_ref());
            tracing::info!(source, "remote_settings resolved at startup");
        }
    } else {
        let _ = startup_prefetch::accept_within(startup_settings_deadline(profile));
    }
    crate::agent::config::apply_remote_settings_side_effects(cfg.remote_settings.as_ref());
    if ran_prefetch {
        StartupPrefetch::Ran
    } else {
        StartupPrefetch::ClientSupplied
    }
}
fn startup_settings_deadline(profile: LaunchProfile) -> std::time::Duration {
    match profile {
        LaunchProfile::Managed => crate::http::MANAGED_STARTUP_SETTINGS_WAIT_DEADLINE,
        LaunchProfile::Personal => crate::http::STARTUP_SETTINGS_WAIT_DEADLINE,
    }
}
/// Reuse the pre-gate result: one boot never spends a second settings fetch, and any
/// managed sync is the supervisor's.
fn apply_post_gate_settings(
    cfg: &mut AgentConfig,
    pre_gate: StartupPrefetch,
    profile: LaunchProfile,
) {
    match (cfg.remote_settings.is_some(), pre_gate) {
        (true, _) => {}
        (false, StartupPrefetch::ClientSupplied) => {
            let _ = ensure_remote_settings_side_effects(cfg, profile);
        }
        (false, StartupPrefetch::Ran) => {}
    }
}
fn resolve_config(
    cfg: &AgentConfig,
    auth_manager: &AuthManager,
    pre_gate_prefetch: StartupPrefetch,
    profile: LaunchProfile,
) -> AgentConfig {
    let mut cfg = cfg.clone();
    if let Ok(layers) = crate::config::ConfigLayers::load()
        && layers.has_managed()
    {
        let origins = crate::config::config_origins(&layers);
        let managed_keys: Vec<&str> = origins
            .iter()
            .filter(|(_, s)| matches!(s, config::ConfigSource::ManagedConfig))
            .map(|(k, _)| k.as_str())
            .collect();
        if !managed_keys.is_empty() {
            tracing::info!(keys = ?managed_keys, "managed_config.toml fields");
        }
    }
    crate::config::apply_policy(&mut cfg);
    apply_post_gate_settings(&mut cfg, pre_gate_prefetch, profile);
    crate::util::config::sync_campaign_fields(&mut cfg);
    let has_xai_auth = auth_manager.current().is_some_and(|a| a.is_xai_auth());
    if cfg.storage_mode == StorageMode::Local
        && cfg.mode != crate::agent::config::AgentMode::Generic
    {
        cfg.storage_mode =
            StorageMode::from_remote_gated(cfg.remote_settings.as_ref(), has_xai_auth);
    }
    if cfg.storage_mode == StorageMode::Writeback && !has_xai_auth {
        tracing::info!("Writeback is disabled: requires auth with grok.com");
        cfg.storage_mode = StorageMode::Local;
    }
    if let Some(rs) = cfg.remote_settings.as_ref()
        && let Some(v) = rs.path_not_found_hints
    {
        cfg.path_not_found_hints = v;
    }
    cfg
}
/// Initialize process-level singletons (deployment sync, built-in metadata,
/// telemetry). `Once`-guarded: only the first call takes effect.
/// Telemetry user ID is updated separately via [`update_telemetry_config`].
fn init_process(cfg: &AgentConfig, auth_manager: &AuthManager) {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        xai_grok_telemetry::unified_log::set_version(xai_grok_version::VERSION);
        let limits = crate::util::limits::ProcessLimits::read();
        limits.log();
        let grok_home = crate::util::grok_home::grok_home();
        crate::builtin::extract_builtin_files(&grok_home);
        if !cfg!(test) {
            crate::builtin::purge_stale_extracted_skills(&grok_home);
        }
        crate::extensions::marketplace::purge_default_skills_installs(&grok_home);
        if cfg.resolve_official_marketplace_auto_register().value {
            crate::extensions::marketplace::ensure_official_marketplace_source(&grok_home);
        }
        let telemetry_mode = cfg.resolve_telemetry_mode();
        let trace_upload = cfg.resolve_trace_upload();
        let feedback = cfg.feature(config::Feature::Feedback);
        let feedback_url = cfg.endpoints.resolve_feedback_base_url();
        let trace_upload_url = cfg.endpoints.resolve_trace_upload_url();
        tracing::info!(
            telemetry = %telemetry_mode,
            trace_upload = %trace_upload,
            feedback = %feedback,
            feedback_url = %feedback_url,
            feedback_url_custom = cfg.endpoints.feedback_base_url.is_some(),
            trace_upload_url = %trace_upload_url,
            trace_upload_url_custom = cfg.endpoints.trace_upload_url.is_some(),
            trace_upload_bucket = cfg.endpoints.trace_upload_bucket.as_deref().unwrap_or("none"),
            trace_upload_region = cfg.endpoints.trace_upload_region.as_deref().unwrap_or("none"),
            "data capture config resolved",
        );
        if telemetry_mode.value.is_disabled() && trace_upload.value {
            tracing::info!(
                "Telemetry disabled but trace uploads enabled: \
                 session artifacts will be uploaded, analytics events will not"
            );
        }
        update_telemetry_config(cfg, auth_manager);
        xai_grok_telemetry::session_ctx::log_event(limits.into_event());
    });
}
/// Apply current telemetry config + auth identity. Tears down the client
/// when telemetry is disabled, so it's safe to call repeatedly.
pub fn update_telemetry_config(config: &AgentConfig, auth_manager: &AuthManager) {
    let user_agent = crate::http::process_user_agent_string();
    if reqwest::header::HeaderValue::from_str(&user_agent).is_err() {
        tracing::warn!("telemetry init skipped: GROK_CLIENT_NAME yields an invalid user agent");
        return;
    }
    let grok_auth = auth_manager.current().filter(|a| a.is_xai_auth());
    let user_id = grok_auth.as_ref().map(|a| a.user_id.clone());
    let team_id = grok_auth.as_ref().and_then(|a| a.team_id.clone());
    let subscription_tier = super::mvp_agent::resolve_subscription_tier_for_telemetry(
        config
            .remote_settings
            .as_ref()
            .and_then(|rs| rs.subscription_tier_display.clone()),
        auth_manager.current_or_expired().as_ref(),
    );
    xai_grok_telemetry::client::init(
        config.telemetry.clone(),
        config.resolve_telemetry_mode().value,
        user_id,
        team_id,
        config.endpoints.deployment_key.clone(),
        crate::http::origin_client_info_from_env(),
        xai_grok_version::VERSION.to_owned(),
        subscription_tier,
        crate::http::shared_client(),
    );
}
/// Assemble the default OTel layer config both `xai-grok-pager` and `xai-grok-tui` need at tracing init time.
///
/// Owns the endpoint and exporter assembly here in shell; the bootstrap credential provider comes from auth.
pub fn build_default_otel_layer_config() -> xai_grok_telemetry::otel_layer::OtelLayerConfig {
    let endpoints = crate::agent::config::EndpointsConfig::default();
    let (credentials, token_header_value) =
        crate::credential_factory::build_bootstrap_otel_credentials();
    let exporter = xai_grok_telemetry::otel_layer::OtelExporterConfig {
        traces_url: endpoints.resolve_otlp_traces_endpoint(),
        extra_headers: endpoints.resolve_otlp_headers(),
        export_interval: endpoints.resolve_otlp_export_interval(),
        timeout: endpoints.resolve_otlp_timeout(),
        enabled: endpoints.resolve_traces_export_enabled()
            && !crate::agent::config::is_telemetry_explicitly_disabled_sync(),
    };
    xai_grok_telemetry::otel_layer::OtelLayerConfig {
        credentials,
        token_header_value,
        alpha_test_key: None,
        exporter,
    }
}
/// Sync this principal's config now rather than waiting for the background tick.
/// Stay quiet about absence or failure during login; confirm only when config was actually applied.
/// Driven by the login callers here so auth does not reach into managed config.
pub async fn apply_post_login_config(
    authenticated: xai_grok_login::GrokAuth,
) -> anyhow::Result<()> {
    let outcome = crate::managed_config::post_login_sync(Some(authenticated)).await;
    match outcome {
        crate::managed_config::ManagedConfigSync::Updated { is_team: true } => {
            eprintln!("Applied your team's managed configuration.");
        }
        crate::managed_config::ManagedConfigSync::Updated { is_team: false } => {
            eprintln!("Applied your deployment's managed configuration.");
        }
        crate::managed_config::ManagedConfigSync::Staged => {
            eprintln!(
                "Managed configuration update verified; it takes effect the next time Grok starts."
            );
        }
        _ => {}
    }
    Ok(())
}
/// `grok logout` CLI subcommand: clear the cached session and, when one was cleared, drop any orphaned synced files.
/// The orphan cleanup runs here in shell so auth stays out of managed config.
pub fn run_cli_logout(grok_com_config: &xai_grok_login::GrokComConfig) -> anyhow::Result<()> {
    let grok_home = xai_grok_shell_base::util::grok_home::grok_home();
    let auth_manager = xai_grok_login::AuthManager::new_with_proxy_base_url(
        &grok_home,
        grok_com_config.clone(),
        crate::agent::config::EndpointsConfig::from_effective_config().proxy_url(),
    );
    let result =
        xai_grok_login::perform_logout(&auth_manager, None, crate::managed_config::clear_orphan)
            .map_err(|e| anyhow::anyhow!("Failed to clear auth: {e}"))?;
    if !result.was_logged_in {
        eprintln!("No cached session to log out of.");
        if result.api_key_still_set {
            eprintln!("You are authenticated via XAI_API_KEY (environment variable).");
        }
        return Ok(());
    }
    if let Some(email) = result.email {
        eprintln!("Logged out (was signed in as {email})");
    } else {
        eprintln!("Logged out");
    }
    if result.api_key_still_set {
        eprintln!("XAI_API_KEY is still set and will be used for authentication.");
    }
    Ok(())
}
#[cfg(test)]
#[path = "init_tests.rs"]
mod tests;
