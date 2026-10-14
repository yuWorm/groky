//! Multi-provider catalog, API-key store, and credential merge.
//!
//! GROK_COMPAT: first-party xAI auth (`AuthManager` / `auth.json`) is
//! untouched. Vendor keys live in `$GROK_HOME/vendor-auth.json`
//! (default `~/.groky/vendor-auth.json`).

mod auth_store;
mod catalog;
pub mod changelog;
pub mod custom;
pub mod oauth;
mod probe;
pub mod reasoning;
mod self_update;
mod vendor_models;

pub use auth_store::{VendorAuthStore, VendorCredential};
pub use catalog::{
    ProviderSpec, acp_models_for_provider, arg_items, builtin_providers, merge_vendor_catalog,
    provider_by_id, provider_display_name, unlocked_provider_ids,
};
pub use probe::{VendorLoginError, login_with_api_key, logout_provider, probe_api_key};
pub use self_update::{
    BackgroundCheck as GrokyBackgroundCheck, UpdateStatus as GrokyUpdateStatus, check_background,
    check_status, ensure_latest_on_disk, install as install_groky_update, install_hint,
    is_managed_install as is_groky_managed_install, is_release_build, product_version,
    set_product_version, updates_allowed as groky_updates_allowed,
};
pub use vendor_models::{
    refresh as refresh_vendor_models, refresh_stale_unlocked as refresh_stale_vendor_models,
    refresh_unlocked as refresh_unlocked_vendor_models,
};

use crate::agent::config::ModelEntry;

/// Credential owner of a catalog model, unless explicit model credentials take precedence.
pub fn vendor_id_for_model(model: &ModelEntry) -> Option<&str> {
    if model.own_credential().is_some() || model.auth_provider.is_some() {
        return None;
    }
    model
        .info
        .model_family
        .as_deref()
        .filter(|id| is_known_vendor(id))
}

/// Resolve a catalog namespace even after logout hides its rows from the picker.
/// Never infer an owner from an endpoint or an unqualified wire model.
pub(crate) fn vendor_auth_for_catalog_id(
    model_id: &str,
) -> Option<(&str, xai_grok_sampler::AuthScheme)> {
    let (id, model) = model_id.split_once('/')?;
    if model.is_empty() {
        return None;
    }
    if let Some(provider) = provider_by_id(id) {
        return Some((id, provider.auth_scheme));
    }
    #[cfg(not(test))]
    if let Ok(store) = custom::CustomProviderStore::default_store()
        && let Some(provider) = store.get(id)
    {
        return Some((id, provider.auth_scheme()));
    }
    None
}

/// Look up the selected model's vendor credential, never another provider on the same URL.
pub fn vendor_key_for_model(model: &ModelEntry) -> Option<String> {
    live_vendor_key_for_id(vendor_id_for_model(model)?)
}

pub fn is_known_vendor(id: &str) -> bool {
    provider_by_id(id).is_some() || custom::is_custom_provider(id)
}

pub fn is_vendor_catalog_model(model: &ModelEntry) -> bool {
    model
        .info
        .model_family
        .as_deref()
        .is_some_and(is_known_vendor)
}

pub fn live_vendor_key_for_id(id: &str) -> Option<String> {
    oauth::ensure_fresh(id);
    VendorAuthStore::default_store()
        .ok()?
        .api_key(id)
        .filter(|k| !k.trim().is_empty())
}

pub fn vendor_auth_user_message(provider_id: &str) -> String {
    let name = provider_display_name(provider_id);
    format!(
        "Authentication required: {name} rejected this session. Run /provider-login {provider_id}, then resend your message."
    )
}

/// groky does not auto-open grok.com on first launch. Welcome stays usable;
/// `/login` and `groky login` still work. `--force-login` keeps upstream
/// auto-open.
pub fn skip_xai_startup_auto_login(force_login: bool) -> bool {
    !force_login
}

/// Official x.ai/cli auto-update stays off. Groky uses GitHub Releases.
pub fn skip_official_auto_update() -> bool {
    true
}

/// Product CLI name for user-facing commands and window titles.
pub const PRODUCT_CLI: &str = "groky";

/// Extra-header key that carries session Fast mode into the sampler.
/// SamplingClient strips it and never sends it on the wire.
pub const GROKY_SERVICE_TIER_HEADER: &str = "x-groky-service-tier";
/// Wire value for `/fast` (OpenAI `service_tier`; Codex accepts `priority`, not `fast`).
pub const OPENAI_FAST_SERVICE_TIER: &str = "priority";

const OPENAI_FAST_PROVIDERS: &[&str] = &["openai", "openai-codex"];

fn catalog_id_is_provider(model_id: &str, provider: &str) -> bool {
    model_id == provider || model_id.starts_with(&format!("{provider}/"))
}

fn is_gpt_wire_id(model_id: &str) -> bool {
    let wire = model_id.rsplit('/').next().unwrap_or(model_id);
    let lower = wire.to_ascii_lowercase();
    lower == "gpt" || lower.starts_with("gpt-")
}

/// Official `openai/…` and `openai-codex/…`, plus any GPT wire id (`gpt-4o`,
/// `acme/gpt-5`, `openrouter/openai/gpt-4o`). Custom OpenAI-compatible GPT
/// models use this.
pub fn model_supports_openai_fast(model_id: &str) -> bool {
    OPENAI_FAST_PROVIDERS
        .iter()
        .any(|provider| catalog_id_is_provider(model_id, provider))
        || is_gpt_wire_id(model_id)
}

/// Official OpenAI and ChatGPT Codex hosts. Custom GPT Fast uses the model
/// gate instead; this stays host-only so a Claude row on the same relay URL
/// does not inherit `service_tier`.
pub fn url_supports_openai_fast(base_url: &str) -> bool {
    OPENAI_FAST_PROVIDERS
        .iter()
        .filter_map(|id| provider_by_id(id))
        .any(|provider| catalog::url_matches_provider(base_url, provider))
}

/// ACP method id for "a vendor credential is configured" (not grok.com).
pub const VENDOR_AUTH_METHOD_ID: &str = "vendor";

/// True when `vendor-auth.json` has at least one usable provider.
pub fn has_any_configured_provider() -> bool {
    VendorAuthStore::default_store()
        .ok()
        .is_some_and(|store| store.has_any_configured_provider())
}

/// Advertise a no-browser ACP method when a vendor is already configured so
/// session create is not blocked on grok.com `authenticate`.
pub fn apply_vendor_auth_method(built: &mut crate::agent::auth_method::BuiltAuthMethods) {
    if !has_any_configured_provider() {
        return;
    }
    let already = built
        .methods
        .iter()
        .any(|m| m.id().0.as_ref() == VENDOR_AUTH_METHOD_ID);
    if !already {
        let method = vendor_auth_method();
        let api_key_first = built.methods.first().is_some_and(|m| {
            crate::agent::auth_method::AuthMethodKind::from_id(m.id()).is_api_key()
        });
        if api_key_first || built.default_auth_method_id.is_some() {
            built.methods.push(method);
        } else {
            built.methods.insert(0, method);
        }
    }
    if built.default_auth_method_id.is_none() {
        built.default_auth_method_id = Some(agent_client_protocol::AuthMethodId::new(
            VENDOR_AUTH_METHOD_ID,
        ));
    }
}

fn vendor_auth_method() -> agent_client_protocol::AuthMethod {
    agent_client_protocol::AuthMethod::Agent(
        agent_client_protocol::AuthMethodAgent::new(
            agent_client_protocol::AuthMethodId::new(VENDOR_AUTH_METHOD_ID),
            "Configured provider".to_string(),
        )
        .description(Some(
            "Use a credential from ~/.groky/vendor-auth.json".into(),
        )),
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn skip_xai_startup_auto_login_unless_force_login() {
        assert!(super::skip_xai_startup_auto_login(false));
        assert!(!super::skip_xai_startup_auto_login(true));
    }

    #[test]
    fn official_openai_and_codex_models_support_fast() {
        assert!(super::model_supports_openai_fast("openai/gpt-4o"));
        assert!(super::model_supports_openai_fast(
            "openai-codex/gpt-5.6-sol"
        ));
        assert!(super::model_supports_openai_fast("openai"));
        assert!(super::model_supports_openai_fast("gpt-4o"));
        assert!(super::model_supports_openai_fast("acme/gpt-5"));
        assert!(super::model_supports_openai_fast(
            "openrouter/openai/gpt-4o"
        ));
        assert!(!super::model_supports_openai_fast(
            "openai-foo/claude-opus-4"
        ));
        assert!(!super::model_supports_openai_fast("grok-4.5"));
        assert!(!super::model_supports_openai_fast(
            "anthropic/claude-opus-5"
        ));
        assert!(!super::model_supports_openai_fast("acme/claude-sonnet-4"));
    }

    #[test]
    fn official_openai_urls_support_fast() {
        assert!(super::url_supports_openai_fast("https://api.openai.com/v1"));
        assert!(super::url_supports_openai_fast(
            "https://chatgpt.com/backend-api/codex"
        ));
        assert!(!super::url_supports_openai_fast("https://api.x.ai/v1"));
        assert!(!super::url_supports_openai_fast(
            "https://openrouter.ai/api/v1"
        ));
        assert!(!super::url_supports_openai_fast(
            "http://localhost:11434/v1"
        ));
    }

    #[test]
    fn official_auto_update_is_disabled() {
        assert!(super::skip_official_auto_update());
    }
}
