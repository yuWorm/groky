//! Session-local vendor account bindings.
//!
//! A binding is deliberately separate from the provider default.  The provider
//! default is only a seed for a new session; requests always use this mapping.

use crate::agent::config::ModelEntry;
use indexmap::IndexMap;
use std::sync::Arc;

pub(crate) const CODEX_PROVIDER_ID: &str = "openai-codex";

/// Provider id to stable account-slot id, shared by a session actor and its handle.
pub(crate) type VendorAccountBindings = Arc<parking_lot::RwLock<IndexMap<String, String>>>;

pub(crate) fn shared_vendor_accounts(accounts: IndexMap<String, String>) -> VendorAccountBindings {
    Arc::new(parking_lot::RwLock::new(accounts))
}

/// Snapshot the Codex subscription account selected at root-session creation.
/// Other vendor providers retain their legacy singleton credential behavior.
pub(crate) fn snapshot_default_vendor_accounts() -> IndexMap<String, String> {
    let Ok(store) = crate::compat::VendorAuthStore::default_store() else {
        return IndexMap::new();
    };
    store
        .default_account_id(CODEX_PROVIDER_ID)
        .map(|account_id| IndexMap::from([(CODEX_PROVIDER_ID.to_owned(), account_id.to_owned())]))
        .unwrap_or_default()
}

/// Resolve a request credential exactly once. Codex uses the selected slot;
/// all other providers retain their legacy singleton/default resolution.
pub(crate) fn request_session_vendor_credential(
    vendor_accounts: &IndexMap<String, String>,
    provider_id: &str,
) -> Option<crate::compat::VendorCredential> {
    let account_id = if provider_id == CODEX_PROVIDER_ID {
        Some(vendor_accounts.get(provider_id)?.as_str())
    } else {
        None
    };
    match crate::compat::oauth::request_credential(provider_id, account_id) {
        Ok(credential) => credential,
        Err(error) => {
            tracing::warn!(
                provider_id,
                account_id,
                %error,
                "selected vendor account could not provide a credential"
            );
            None
        }
    }
}

/// Replace global Codex rows with the selected account's rows without
/// overwriting a user's explicit credential or routing overrides.
pub(crate) fn models_for_vendor_accounts(
    models: IndexMap<String, ModelEntry>,
    vendor_accounts: &IndexMap<String, String>,
) -> IndexMap<String, ModelEntry> {
    let selected = vendor_accounts
        .get(CODEX_PROVIDER_ID)
        .map(|account_id| crate::compat::models_for_provider_account(CODEX_PROVIDER_ID, account_id))
        .unwrap_or_default();
    overlay_codex_account_models(models, selected)
}

fn overlay_codex_account_models(
    mut models: IndexMap<String, ModelEntry>,
    mut selected: IndexMap<String, ModelEntry>,
) -> IndexMap<String, ModelEntry> {
    models.retain(|model_id, entry| {
        let is_codex = model_id
            .split_once('/')
            .is_some_and(|(provider_id, _)| provider_id == CODEX_PROVIDER_ID)
            || entry.info.model_family.as_deref() == Some(CODEX_PROVIDER_ID);
        if !is_codex {
            return true;
        }
        if entry.own_credential().is_some() || entry.auth_provider.is_some() {
            return true;
        }
        let Some(selected_entry) = selected.shift_remove(model_id) else {
            return false;
        };
        merge_codex_account_capabilities(entry, selected_entry);
        true
    });
    for (model_id, selected_entry) in selected {
        models.entry(model_id).or_insert(selected_entry);
    }
    models
}
fn merge_codex_account_capabilities(merged: &mut ModelEntry, selected: ModelEntry) {
    // Keep local routing and all local override fields; these fields come from
    // the account-specific catalog and therefore must update with the selected
    // account's catalog rather than the manager's default-account catalog.
    merged.info.model_family = selected.info.model_family;
    merged.info.max_completion_tokens = selected.info.max_completion_tokens;
    merged.info.context_window = selected.info.context_window;
    merged.info.context_windows = selected.info.context_windows;
    merged.info.supports_reasoning_effort = selected.info.supports_reasoning_effort;
    merged.info.reasoning_effort = selected.info.reasoning_effort;
    merged.info.reasoning_efforts = selected.info.reasoning_efforts;
    merged.info.reasoning_effort_server_default = selected.info.reasoning_effort_server_default;
    merged.info.variants = selected.info.variants;
}

impl crate::session::acp_session::SessionActor {
    /// Queue a selection while the complete tool turn is active. The latest
    /// selection wins per provider; a later request must never see a half-turn
    /// account change.
    pub(crate) async fn set_vendor_account_at_turn_boundary(
        &self,
        provider_id: String,
        account_id: String,
    ) {
        let mut state = self.state.lock().await;
        if crate::session::acp_session::state_is_busy(&state) {
            state
                .pending_vendor_account_changes
                .insert(provider_id, account_id);
            return;
        }
        drop(state);
        self.apply_vendor_account_change(provider_id, account_id)
            .await;
    }

    /// Consume selections queued by ACP while a turn ran. Call only after the
    /// completion handler has released the running-turn/finalization state.
    pub(crate) async fn apply_pending_vendor_account_changes(&self) {
        let pending = {
            let mut state = self.state.lock().await;
            if crate::session::acp_session::state_is_busy(&state) {
                return;
            }
            std::mem::take(&mut state.pending_vendor_account_changes)
        };
        for (provider_id, account_id) in pending {
            self.apply_vendor_account_change(provider_id, account_id)
                .await;
        }
    }
    /// Resolve a coherent credential snapshot for this session. Codex uses the
    /// selected slot; legacy providers retain singleton credential resolution.
    pub(crate) fn pinned_vendor_credential(
        &self,
        provider_id: &str,
    ) -> Option<crate::compat::VendorCredential> {
        request_session_vendor_credential(&self.vendor_accounts.read(), provider_id)
    }

    async fn apply_vendor_account_change(&self, provider_id: String, account_id: String) {
        // Keep an explicit missing/deleted id instead of retaining the prior
        // account. The request path then fails closed rather than silently
        // falling back to either the previous or provider-default account.
        self.vendor_accounts
            .write()
            .insert(provider_id.clone(), account_id.clone());
        self.invalidate_model_auth_memo();
        if provider_id == CODEX_PROVIDER_ID {
            let models = models_for_vendor_accounts(
                self.models_manager.models(),
                &self.vendor_accounts.read(),
            );
            let current_model_id = self.catalog_model_id.borrow().clone();
            if let Some(entry) =
                crate::agent::config::find_model_by_id(&models, current_model_id.0.as_ref()).filter(
                    |entry| crate::compat::vendor_id_for_model(entry) == Some(CODEX_PROVIDER_ID),
                )
                && let Some(mut config) = self.chat_state_handle.get_sampling_config().await
            {
                config.context_window = self
                    .compaction
                    .context_window_override
                    .unwrap_or(entry.info.context_window);
                if !entry
                    .info
                    .reasoning_efforts
                    .iter()
                    .any(|option| Some(option.value) == config.reasoning_effort)
                {
                    config.reasoning_effort = entry.info.reasoning_effort;
                }
                config.max_completion_tokens = entry.info.max_completion_tokens;
                self.chat_state_handle.update_sampling_config(config);
            }
        }
        let _ = self.notifications.persistence_tx.send(
            crate::session::persistence::PersistenceMsg::VendorAccounts(
                self.vendor_accounts.read().clone(),
            ),
        );
        self.send_xai_notification_transient(
            crate::extensions::notification::SessionUpdate::VendorAccountChanged {
                models: crate::compat::acp_models_for_provider_account(&provider_id, &account_id)
                    .into_values()
                    .collect(),
                provider_id,
                account_id,
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{CODEX_PROVIDER_ID, IndexMap, ModelEntry, overlay_codex_account_models};

    fn codex_entry(model: &str, base_url: &str, api_key: Option<&str>) -> ModelEntry {
        let mut entry = ModelEntry::fallback(model, &Default::default());
        entry.info.model_family = Some(CODEX_PROVIDER_ID.to_owned());
        entry.info.base_url = base_url.to_owned();
        entry.api_key = api_key.map(str::to_owned);
        entry
    }

    #[test]
    fn account_catalog_keeps_local_routing_and_updates_capabilities() {
        let mut local = codex_entry("local-wire", "https://local.example/v1", None);
        // A configured model can shadow the catalog key without repeating its
        // provider family; the canonical key still identifies it as Codex.
        local.info.model_family = None;
        local.info.context_window = std::num::NonZeroU64::new(128).expect("non-zero");
        let mut selected = codex_entry("account-wire", "https://account.example/v1", None);
        selected.info.context_window = std::num::NonZeroU64::new(256).expect("non-zero");
        selected.info.supports_reasoning_effort = true;

        let models = overlay_codex_account_models(
            IndexMap::from([("openai-codex/test".to_owned(), local)]),
            IndexMap::from([("openai-codex/test".to_owned(), selected)]),
        );
        let resolved = models
            .get("openai-codex/test")
            .expect("selected account model is present");

        assert_eq!(resolved.info.model, "local-wire");
        assert_eq!(resolved.info.base_url, "https://local.example/v1");
        assert_eq!(resolved.info.context_window.get(), 256);
        assert_eq!(
            resolved.info.model_family.as_deref(),
            Some(CODEX_PROVIDER_ID)
        );
        assert!(resolved.info.supports_reasoning_effort);
    }

    #[test]
    fn explicit_model_credential_wins_over_selected_account_catalog() {
        let local = codex_entry("local-wire", "https://local.example/v1", Some("local-key"));
        let selected = codex_entry("account-wire", "https://account.example/v1", None);

        let models = overlay_codex_account_models(
            IndexMap::from([("openai-codex/test".to_owned(), local)]),
            IndexMap::from([("openai-codex/test".to_owned(), selected)]),
        );
        let resolved = models
            .get("openai-codex/test")
            .expect("explicit model remains present");

        assert_eq!(resolved.api_key.as_deref(), Some("local-key"));
        assert_eq!(resolved.info.model, "local-wire");
        assert_eq!(resolved.info.base_url, "https://local.example/v1");
    }

    #[test]
    fn absent_selected_account_catalog_removes_global_codex_models() {
        let models = overlay_codex_account_models(
            IndexMap::from([(
                "openai-codex/test".to_owned(),
                codex_entry("default-wire", "https://default.example/v1", None),
            )]),
            IndexMap::new(),
        );

        assert!(!models.contains_key("openai-codex/test"));
    }

    #[test]
    fn non_codex_vendor_catalogs_keep_legacy_models() {
        let mut api_provider = ModelEntry::fallback("api-wire", &Default::default());
        api_provider.info.model_family = Some("openai".to_owned());

        let models = overlay_codex_account_models(
            IndexMap::from([("openai/api-model".to_owned(), api_provider)]),
            IndexMap::new(),
        );

        assert!(models.contains_key("openai/api-model"));
    }
}
