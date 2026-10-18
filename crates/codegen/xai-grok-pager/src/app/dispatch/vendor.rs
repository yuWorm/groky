//! Third-party provider login / logout (GROK_COMPAT). Does not use xAI `/login`.

use super::ctx::{active_agent_session_id, get_active_agent_mut};
use crate::acp::model_state::ModelState;
use crate::app::actions::{Action, Effect};
use crate::app::app_view::{AppView, InputOutcome};
use crate::views::vendor_login_modal::{VendorLoginOutcome, VendorLoginState};
use agent_client_protocol as acp;
use xai_grok_shell::compat::custom::{CustomModel, CustomPlatform};
use xai_grok_shell::sampling::types::{
    REASONING_EFFORT_META_KEY, REASONING_EFFORTS_META_KEY, SUPPORTS_REASONING_EFFORT_META_KEY,
    parse_reasoning_effort_meta, reasoning_effort_meta_value, reasoning_efforts_meta_value,
};

fn vendor_login_mut(app: &mut AppView) -> Option<&mut VendorLoginState> {
    let on_agent = get_active_agent_mut(app).is_some_and(|agent| agent.vendor_login.is_some());
    if on_agent {
        return get_active_agent_mut(app).and_then(|agent| agent.vendor_login.as_mut());
    }
    app.welcome_vendor_login.as_mut()
}

fn map_vendor_login_outcome(outcome: VendorLoginOutcome) -> InputOutcome {
    match outcome {
        VendorLoginOutcome::Unchanged => InputOutcome::Unchanged,
        VendorLoginOutcome::Changed => InputOutcome::Changed,
        VendorLoginOutcome::Close => InputOutcome::Action(Action::CloseVendorLogin),
        VendorLoginOutcome::Submit { provider_id, key } => {
            InputOutcome::Action(Action::SubmitVendorKey { provider_id, key })
        }
        VendorLoginOutcome::StartOAuth { provider_id } => {
            InputOutcome::Action(Action::StartVendorOAuth { provider_id })
        }
        VendorLoginOutcome::SubmitOAuthCode { provider_id, code } => {
            InputOutcome::Action(Action::SubmitVendorOAuthCode { provider_id, code })
        }
        VendorLoginOutcome::SelectAccount {
            provider_id,
            account_id,
        } => InputOutcome::Action(Action::SelectVendorAccount {
            provider_id,
            account_id,
        }),
        VendorLoginOutcome::RenameAccount {
            provider_id,
            account_id,
            label,
        } => InputOutcome::Action(Action::RenameVendorAccount {
            provider_id,
            account_id,
            label,
        }),
        VendorLoginOutcome::RemoveAccount {
            provider_id,
            account_id,
        } => InputOutcome::Action(Action::RemoveVendorAccount {
            provider_id,
            account_id,
        }),
        VendorLoginOutcome::RemoveCustom { provider_id } => {
            InputOutcome::Action(Action::RemoveVendorCustom { provider_id })
        }
        VendorLoginOutcome::SyncCustom {
            name,
            base_url,
            api_backend,
            auth_scheme,
            key,
        } => InputOutcome::Action(Action::SyncVendorCustom {
            name,
            base_url,
            api_backend,
            auth_scheme,
            key,
        }),
        VendorLoginOutcome::SaveCustom {
            provider_id,
            name,
            base_url,
            api_backend,
            auth_scheme,
            platform,
            usage_base_url,
            key,
            models,
        } => InputOutcome::Action(Action::SaveVendorCustom {
            provider_id,
            name,
            base_url,
            api_backend,
            auth_scheme,
            platform,
            usage_base_url,
            key,
            models,
        }),
        VendorLoginOutcome::RefreshCatalog => InputOutcome::Action(Action::SyncModelsDev),
    }
}

pub(crate) fn handle_welcome_vendor_login_input(
    app: &mut AppView,
    ev: &crossterm::event::Event,
) -> InputOutcome {
    let Some(state) = app.welcome_vendor_login.as_mut() else {
        return InputOutcome::Unchanged;
    };
    match ev {
        crossterm::event::Event::Key(key) => map_vendor_login_outcome(
            crate::views::vendor_login_modal::handle_vendor_login_key(state, key),
        ),
        crossterm::event::Event::Mouse(mouse) => {
            map_vendor_login_outcome(crate::views::vendor_login_modal::handle_vendor_login_mouse(
                state,
                mouse.kind,
                mouse.column,
                mouse.row,
            ))
        }
        crossterm::event::Event::Paste(text) => {
            match crate::views::vendor_login_modal::handle_vendor_login_paste(state, text) {
                VendorLoginOutcome::Changed => InputOutcome::Changed,
                other => map_vendor_login_outcome(other),
            }
        }
        _ => InputOutcome::Unchanged,
    }
}

pub(super) fn dispatch_open_vendor_login(
    app: &mut AppView,
    provider_id: Option<String>,
) -> Vec<Effect> {
    let mut state = match provider_id {
        Some(id) if id == "custom" || id == "add" => VendorLoginState::custom_form(),
        Some(id) => {
            if let Some(spec) = xai_grok_shell::compat::provider_by_id(&id) {
                VendorLoginState::for_provider(spec.id.to_owned(), spec.name.to_owned())
            } else if xai_grok_shell::compat::custom::get_provider(&id).is_some() {
                VendorLoginState::edit_custom(id)
            } else if xai_grok_shell::compat::is_known_vendor(&id) {
                VendorLoginState::for_provider(id.clone(), id)
            } else {
                app.show_toast(&format!("Unknown provider '{id}'"));
                return vec![];
            }
        }
        None => VendorLoginState::picker(),
    };
    if let Some(agent) = get_active_agent_mut(app) {
        state.current_codex_account = agent.session.models.available.iter().find_map(|(id, model)| {
            id.0.starts_with("openai-codex/").then_some(model)
                .and_then(|model| model.meta.as_ref()?.get("grokyAccountId")?.as_str())
                .map(str::to_owned)
        });
        agent.vendor_login = Some(state);
    } else {
        app.welcome_vendor_login = Some(state);
    }
    vec![]
}

pub(super) fn dispatch_close_vendor_login(app: &mut AppView) -> Vec<Effect> {
    if let Some(id) = vendor_login_mut(app).and_then(|s| s.oauth_provider_id().map(str::to_owned)) {
        xai_grok_shell::compat::oauth::cancel(&id);
    }
    if let Some(agent) = get_active_agent_mut(app) {
        agent.vendor_login = None;
    }
    app.welcome_vendor_login = None;
    vec![]
}

pub(super) fn dispatch_start_vendor_oauth(app: &mut AppView, provider_id: String) -> Vec<Effect> {
    if let Some(state) = vendor_login_mut(app) {
        state.probing = true;
        state.error = None;
    }
    vec![Effect::VendorOAuthStart { provider_id }]
}

pub(super) fn dispatch_submit_vendor_oauth_code(
    app: &mut AppView,
    provider_id: String,
    code: String,
) -> Vec<Effect> {
    if let Err(error) = xai_grok_shell::compat::oauth::submit_manual(&provider_id, &code) {
        if let Some(state) = vendor_login_mut(app) {
            state.probing = false;
            state.error = Some(error.to_string());
        } else {
            app.show_toast(&error.to_string());
        }
        return vec![];
    }
    if let Some(state) = vendor_login_mut(app) {
        state.probing = true;
        state.error = None;
    }
    vec![]
}

pub(super) fn dispatch_sync_vendor_custom(
    app: &mut AppView,
    base_url: String,
    api_backend: String,
    auth_scheme: String,
    key: String,
) -> Vec<Effect> {
    if let Some(state) = vendor_login_mut(app) {
        state.probing = true;
        state.error = None;
    }
    vec![Effect::VendorCustomSync {
        base_url,
        api_backend,
        auth_scheme,
        key,
    }]
}

pub(super) fn dispatch_save_vendor_custom(
    app: &mut AppView,
    provider_id: Option<String>,
    name: String,
    base_url: String,
    api_backend: String,
    auth_scheme: String,
    platform: CustomPlatform,
    usage_base_url: Option<String>,
    key: String,
    models: Vec<CustomModel>,
) -> Vec<Effect> {
    if let Some(state) = vendor_login_mut(app) {
        state.probing = true;
        state.error = None;
    }
    vec![Effect::VendorCustomSave {
        provider_id,
        name,
        base_url,
        api_backend,
        auth_scheme,
        platform,
        usage_base_url,
        key,
        models,
    }]
}

pub(super) fn handle_vendor_custom_synced(
    app: &mut AppView,
    models: Vec<(String, String, u64)>,
    error: Option<String>,
) -> Vec<Effect> {
    if let Some(state) = vendor_login_mut(app) {
        state.apply_custom_models(models, error);
    } else if let Some(err) = error {
        app.show_toast(&err);
    }
    vec![]
}

pub(super) fn handle_vendor_oauth_pending(
    app: &mut AppView,
    provider_id: String,
    authorize_url: String,
    instructions: String,
) -> Vec<Effect> {
    if let Some(state) = vendor_login_mut(app) {
        state.enter_oauth_wait(authorize_url, instructions);
        return vec![Effect::VendorOAuthWait { provider_id }];
    }
    xai_grok_shell::compat::oauth::cancel(&provider_id);
    vec![]
}

pub(super) fn dispatch_submit_vendor_key(
    _app: &mut AppView,
    provider_id: String,
    key: String,
) -> Vec<Effect> {
    vec![Effect::VendorProbe { provider_id, key }]
}
pub(super) fn dispatch_select_vendor_account(
    app: &mut AppView,
    provider_id: String,
    account_id: String,
) -> Vec<Effect> {
    let session_id = active_agent_session_id(app);
    let update_session_catalog = session_id.as_ref().is_some_and(|session_id| {
        app.agents.values().any(|agent| {
            agent.session.session_id.as_ref() == Some(session_id)
                && !agent.session.state.is_turn_running()
        })
    });
    vec![Effect::SelectVendorAccount {
        provider_id,
        account_id,
        session_id,
        update_session_catalog,
    }]
}

pub(super) fn dispatch_rename_vendor_account(
    _app: &mut AppView,
    provider_id: String,
    account_id: String,
    label: String,
) -> Vec<Effect> {
    vec![Effect::RenameVendorAccount {
        provider_id,
        account_id,
        label,
    }]
}

pub(super) fn dispatch_remove_vendor_account(
    _app: &mut AppView,
    provider_id: String,
    account_id: String,
) -> Vec<Effect> {
    vec![Effect::RemoveVendorAccount {
        provider_id,
        account_id,
    }]
}

pub(super) fn dispatch_vendor_logout(app: &mut AppView, provider_id: String) -> Vec<Effect> {
    let _ = app;
    vec![Effect::VendorLogoutPersist { provider_id }]
}

pub(super) fn dispatch_remove_vendor_custom(_app: &mut AppView, provider_id: String) -> Vec<Effect> {
    vec![Effect::VendorCustomRemove { provider_id }]
}

pub(super) fn dispatch_sync_models_dev(app: &mut AppView) -> Vec<Effect> {
    app.show_toast("Syncing model catalog…");
    vec![Effect::SyncModelsDev]
}

pub(super) fn handle_models_dev_synced(
    app: &mut AppView,
    count: usize,
    vendor_count: usize,
    error: Option<String>,
) -> Vec<Effect> {
    for provider_id in xai_grok_shell::compat::unlocked_provider_ids() {
        inject_provider_models(app, &provider_id);
    }
    patch_model_state_reasoning(&mut app.models);
    for agent in app.agents.values_mut() {
        patch_model_state_reasoning(&mut agent.session.models);
    }
    let toast = match (error.as_deref(), vendor_count) {
        (Some(err), 0) => format!("Model list refresh failed: {err}"),
        (Some(err), _) => {
            format!("Refreshed vendor model lists; models.dev failed: {err}")
        }
        (None, _) => format!("Refreshed model lists ({count} from models.dev)"),
    };
    app.show_toast(&toast);
    vec![]
}

pub(super) fn handle_stale_vendor_models_refreshed(app: &mut AppView, count: usize) -> Vec<Effect> {
    if count == 0 {
        return vec![];
    }
    for provider_id in xai_grok_shell::compat::unlocked_provider_ids() {
        inject_provider_models(app, &provider_id);
    }
    patch_model_state_reasoning(&mut app.models);
    for agent in app.agents.values_mut() {
        patch_model_state_reasoning(&mut agent.session.models);
    }
    vec![]
}

fn inject_provider_models(app: &mut AppView, provider_id: &str) {
    let extras = xai_grok_shell::compat::acp_models_for_provider(provider_id);
    let prefix = format!("{provider_id}/");
    app.models
        .available
        .retain(|id, _| !id.0.starts_with(&prefix));
    app.models.available.extend(extras.clone());
    // Codex catalogs are account-scoped. A default refresh must never replace
    // another session's pinned account catalog.
    if provider_id == "openai-codex" {
        return;
    }
    for agent in app.agents.values_mut() {
        agent
            .session
            .models
            .available
            .retain(|id, _| !id.0.starts_with(&prefix));
        agent.session.models.available.extend(extras.clone());
    }
}

fn inject_provider_models_for_account(
    app: &mut AppView,
    provider_id: &str,
    account_id: &str,
    update_default_catalog: bool,
    session_id: Option<&acp::SessionId>,
    update_session_catalog: bool,
) {
    if !update_default_catalog && !update_session_catalog {
        return;
    }
    let extras = xai_grok_shell::compat::acp_models_for_provider_account(provider_id, account_id);
    let prefix = format!("{provider_id}/");
    let session_agent_id = if update_session_catalog {
        session_id.and_then(|session_id| {
            app.agents
                .iter()
                .find(|(_, agent)| agent.session.session_id.as_ref() == Some(session_id))
                .map(|(agent_id, _)| agent_id.clone())
        })
    } else {
        None
    };

    match (update_default_catalog, session_agent_id) {
        (true, Some(agent_id)) => {
            app.models
                .available
                .retain(|id, _| !id.0.starts_with(&prefix));
            app.models.available.extend(extras.clone());
            patch_model_state_reasoning(&mut app.models);

            let agent = app
                .agents
                .get_mut(&agent_id)
                .expect("session agent remains registered while updating account models");
            agent
                .session
                .models
                .available
                .retain(|id, _| !id.0.starts_with(&prefix));
            agent.session.models.available.extend(extras);
            patch_model_state_reasoning(&mut agent.session.models);
        }
        (true, None) => {
            app.models
                .available
                .retain(|id, _| !id.0.starts_with(&prefix));
            app.models.available.extend(extras);
            patch_model_state_reasoning(&mut app.models);
        }
        (false, Some(agent_id)) => {
            let agent = app
                .agents
                .get_mut(&agent_id)
                .expect("session agent remains registered while updating account models");
            agent
                .session
                .models
                .available
                .retain(|id, _| !id.0.starts_with(&prefix));
            agent.session.models.available.extend(extras);
            patch_model_state_reasoning(&mut agent.session.models);
        }
        (false, None) => {}
    }
}

fn patch_model_state_reasoning(models: &mut ModelState) {
    for (id, info) in models.available.iter_mut() {
        let key = id.0.as_ref();
        if !key.contains('/') {
            continue;
        }
        let Some(meta) = xai_grok_shell::compat::reasoning::lookup_meta(key) else {
            continue;
        };
        let mut map = info.meta.clone().unwrap_or_default();
        if let Some(menu) = meta.reasoning {
            map.insert(
                SUPPORTS_REASONING_EFFORT_META_KEY.to_string(),
                serde_json::Value::Bool(true),
            );
            map.insert(
                REASONING_EFFORTS_META_KEY.to_string(),
                reasoning_efforts_meta_value(&menu.options),
            );
            if parse_reasoning_effort_meta(Some(&map)).is_none() {
                map.insert(
                    REASONING_EFFORT_META_KEY.to_string(),
                    reasoning_effort_meta_value(menu.default),
                );
            }
        }
        if let Some(ctx) = meta.context_window {
            map.insert(
                "totalContextTokens".to_string(),
                serde_json::Value::Number(ctx.into()),
            );
        }
        info.meta = Some(map);
    }
}
fn authenticate_vendor_if_needed(app: &mut AppView) -> Vec<Effect> {
    if matches!(app.auth_state, crate::app::app_view::AuthState::Done) {
        return vec![];
    }
    app.auth_state = crate::app::app_view::AuthState::Done;
    app.welcome_prompt_focused = true;
    let request_seq = app.next_auth_request_seq;
    app.next_auth_request_seq += 1;
    vec![Effect::Authenticate {
        request_seq,
        method_id: acp::AuthMethodId::new(xai_grok_shell::compat::VENDOR_AUTH_METHOD_ID),
        use_oauth: false,
        force_interactive: false,
    }]
}


pub(super) fn handle_vendor_login_complete(
    app: &mut AppView,
    provider_id: String,
    error: Option<String>,
) -> Vec<Effect> {
    if let Some(err) = error {
        let cancelled = err.to_lowercase().contains("cancel");
        if let Some(state) = vendor_login_mut(app) {
            state.probing = false;
            if cancelled {
                state.back_from_oauth();
            } else {
                state.error = Some(err);
            }
        } else if !cancelled {
            app.show_toast(&format!("Sign-in failed: {err}"));
        }
        return vec![];
    }

    if provider_id == "openai-codex" {
        let account_ids = vendor_login_mut(app)
            .map(VendorLoginState::complete_codex_oauth)
            .unwrap_or_else(|| {
                xai_grok_shell::compat::VendorAuthStore::default_store()
                    .map(|store| {
                        store
                            .accounts("openai-codex")
                            .into_iter()
                            .map(|account| account.id)
                            .collect()
                    })
                    .unwrap_or_default()
            });
        let default_account_id = xai_grok_shell::compat::VendorAuthStore::default_store()
            .ok()
            .and_then(|store| {
                store
                    .default_account_id("openai-codex")
                    .map(str::to_owned)
            });
        if let Some(account_id) = default_account_id.as_deref() {
            inject_provider_models_for_account(
                app,
                "openai-codex",
                account_id,
                true,
                None,
                false,
            );
        }
        app.show_toast(
            "Signed in to ChatGPT Codex. Select an account to use in this session.",
        );
        let mut effects: Vec<Effect> = account_ids
            .into_iter()
            .map(|account_id| Effect::RefreshVendorAccountCatalog {
                provider_id: "openai-codex".into(),
                account_id,
                session_id: None,
                update_session_catalog: false,
            })
            .collect();
        effects.extend(authenticate_vendor_if_needed(app));
        return effects;
    }

    inject_provider_models(app, &provider_id);
    for agent in app.agents.values_mut() {
        agent.vendor_login = None;
    }
    app.welcome_vendor_login = None;
    let name = xai_grok_shell::compat::provider_display_name(&provider_id);
    app.show_toast(&format!("Signed in to {name}. Use /model to switch."));
    authenticate_vendor_if_needed(app)
}
pub(super) fn handle_vendor_account_selected(
    app: &mut AppView,
    provider_id: String,
    account_id: String,
    session_id: Option<acp::SessionId>,
    update_session_catalog: bool,
    error: Option<String>,
) -> Vec<Effect> {
    if let Some(state) = vendor_login_mut(app) {
        state.complete_account_selection(&account_id, error.clone());
    }
    if let Some(error) = error {
        if vendor_login_mut(app).is_none() {
            app.show_toast(&format!("Could not select account: {error}"));
        }
        return vec![];
    }

    inject_provider_models_for_account(
        app,
        &provider_id,
        &account_id,
        true,
        session_id.as_ref(),
        update_session_catalog,
    );
    let mut effects = vec![Effect::RefreshVendorAccountCatalog {
        provider_id: provider_id.clone(),
        account_id: account_id.clone(),
        session_id: session_id.clone(),
        update_session_catalog,
    }];
    if let Some(session_id) = session_id {
        effects.push(Effect::NotifyVendorAccountChanged {
            session_id,
            provider_id,
            account_id,
        });
        if update_session_catalog {
            app.show_toast("Codex account selected for this session.");
        } else {
            app.show_toast(
                "Codex account selected as default; this session will switch after the current turn.",
            );
        }
    } else {
        app.show_toast("Codex account selected as the provider default.");
    }
    effects
}

pub(super) fn handle_vendor_account_renamed(
    app: &mut AppView,
    account_id: String,
    error: Option<String>,
) -> Vec<Effect> {
    if let Some(state) = vendor_login_mut(app) {
        state.complete_account_rename(&account_id, error.clone());
    }
    if let Some(error) = error {
        if vendor_login_mut(app).is_none() {
            app.show_toast(&format!("Could not label account: {error}"));
        }
    } else {
        app.show_toast("Codex account label saved.");
    }
    vec![]
}

pub(super) fn handle_vendor_account_removed(
    app: &mut AppView,
    provider_id: String,
    error: Option<String>,
    removed: bool,
    was_default: bool,
) -> Vec<Effect> {
    if let Some(state) = vendor_login_mut(app) {
        state.complete_account_remove(error.clone());
    }
    if let Some(error) = error {
        if vendor_login_mut(app).is_none() {
            app.show_toast(&format!("Could not remove account: {error}"));
        }
        return vec![];
    }
    if !removed {
        app.show_toast("The selected Codex account no longer exists.");
        return vec![];
    }
    if was_default {
        let prefix = format!("{provider_id}/");
        app.models
            .available
            .retain(|id, _| !id.0.starts_with(&prefix));
        app.show_toast(
            "Codex account removed. No default account is selected; choose one explicitly.",
        );
    } else {
        app.show_toast("Codex account removed.");
    }
    vec![]
}

pub(super) fn handle_vendor_account_catalog_refreshed(
    app: &mut AppView,
    provider_id: String,
    account_id: String,
    session_id: Option<acp::SessionId>,
    update_session_catalog: bool,
    _count: usize,
    error: Option<String>,
) -> Vec<Effect> {
    if let Some(error) = error {
        if let Some(state) = vendor_login_mut(app) {
            state.error = Some(format!("Could not refresh account models: {error}"));
        } else {
            app.show_toast(&format!("Could not refresh account models: {error}"));
        }
        return vec![];
    }
    let (account_exists, is_default) = xai_grok_shell::compat::VendorAuthStore::default_store()
        .ok()
        .map(|store| {
            let account_exists = store.account_credential(&provider_id, &account_id).is_some();
            let is_default = store
                .default_account_id(&provider_id)
                .is_some_and(|id| id == account_id.as_str());
            (account_exists, is_default)
        })
        .unwrap_or((false, false));
    if !account_exists {
        return vec![];
    }
    let update_session_catalog = update_session_catalog
        && session_id.as_ref().is_some_and(|session_id| {
            app.agents.values().any(|agent| {
                agent.session.session_id.as_ref() == Some(session_id)
                    && agent.session.models.available.values().any(|model| {
                        model.meta.as_ref()
                            .and_then(|meta| meta.get("grokyAccountId"))
                            .and_then(serde_json::Value::as_str) == Some(account_id.as_str())
                    })
            })
        });
    inject_provider_models_for_account(
        app,
        &provider_id,
        &account_id,
        is_default,
        session_id.as_ref(),
        update_session_catalog,
    );
    vec![]
}


pub(super) fn handle_vendor_custom_removed(
    app: &mut AppView,
    provider_id: String,
    error: Option<String>,
) -> Vec<Effect> {
    if let Some(state) = vendor_login_mut(app) {
        state.complete_custom_remove(&provider_id, error.clone());
    }
    if let Some(error) = error {
        app.show_toast(&format!("Could not remove provider: {error}"));
        return vec![];
    }
    remove_provider_models(app, &provider_id);
    app.show_toast(&format!("Removed custom provider {provider_id}"));
    vec![]
}

fn remove_provider_models(app: &mut AppView, provider_id: &str) {
    let prefix = format!("{provider_id}/");
    app.models
        .available
        .retain(|id, _| !id.0.starts_with(&prefix));
    for agent in app.agents.values_mut() {
        agent
            .session
            .models
            .available
            .retain(|id, _| !id.0.starts_with(&prefix));
    }
}

pub(super) fn handle_vendor_logout_complete(
    app: &mut AppView,
    provider_id: String,
    removed: bool,
    error: Option<String>,
) -> Vec<Effect> {
    if let Some(err) = error {
        app.show_toast(&format!("Logout failed: {err}"));
        return vec![];
    }
    remove_provider_models(app, &provider_id);
    let name = xai_grok_shell::compat::provider_display_name(&provider_id);
    if removed {
        if provider_id == "openai-codex" {
            app.show_toast("Signed out of every stored ChatGPT Codex account.");
        } else {
            app.show_toast(&format!("Signed out of {name}"));
        }
    } else {
        app.show_toast(&format!("No stored key for {name}"));
    }
    vec![]
}
