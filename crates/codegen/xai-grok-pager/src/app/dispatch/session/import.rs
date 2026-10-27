use super::load::dispatch_load_session;
use crate::app::actions::Effect;
use crate::app::agent::AgentId;
use crate::app::app_view::{ActiveView, AppView, SessionPickerEntry};
use crate::views::modal::ActiveModal;
use crate::views::session_picker::ImportSessionPreview;
use crate::views::session_title::sanitize_display_text;
use xai_grok_foreign_sessions::import::ImportCandidate;

const MAX_IMPORT_WARNING_COUNT: usize = 16;
const MAX_IMPORT_DISPLAY_CHARS: usize = 240;

fn safe_display(value: &str) -> String {
    sanitize_display_text(value)
        .trim()
        .chars()
        .take(MAX_IMPORT_DISPLAY_CHARS)
        .collect()
}

fn safe_warnings(warnings: Vec<String>) -> Vec<String> {
    let total = warnings.len();
    let mut safe: Vec<String> = warnings
        .into_iter()
        .take(MAX_IMPORT_WARNING_COUNT)
        .map(|warning| safe_display(&warning))
        .filter(|warning| !warning.is_empty())
        .collect();
    if total > MAX_IMPORT_WARNING_COUNT {
        safe.push(format!(
            "{remaining} additional warnings omitted from this preview",
            remaining = total - MAX_IMPORT_WARNING_COUNT
        ));
    }
    safe
}

fn candidate_entry(candidate: &ImportCandidate) -> SessionPickerEntry {
    let updated_at = chrono::DateTime::<chrono::Utc>::from(candidate.modified);
    let cwd = safe_display(&candidate.cwd.to_string_lossy());
    SessionPickerEntry {
        id: safe_display(&candidate.id),
        summary: safe_display(&candidate.title),
        updated_at,
        created_at: updated_at,
        cwd: cwd.clone(),
        hostname: None,
        source: candidate.source.as_str().to_owned(),
        model_id: None,
        num_messages: 0,
        last_active_at: Some(updated_at),
        branch: None,
        repo_name: crate::views::session_picker::repo_name_from_cwd(&cwd),
        worktree_label: None,
        last_turn_summary: None,
        last_recap: None,
        session_kind: None,
        card_detail: None,
    }
}

fn current_import_picker_matches(
    app: &AppView,
    agent_id: AgentId,
    generation: u64,
    target_cwd: &std::path::Path,
    owner_session_id: Option<&str>,
) -> bool {
    matches!(app.active_view, ActiveView::Agent(id) if id == agent_id)
        && app.cwd.as_path() == target_cwd
        && app.agents.get(&agent_id).is_some_and(|agent| {
            owner_session_id.is_none_or(|owner| {
                agent
                    .session
                    .session_id
                    .as_ref()
                    .map(|session_id| session_id.0.as_ref())
                    == Some(owner)
            }) && matches!(
                agent.active_modal.as_ref(),
                Some(ActiveModal::SessionPicker {
                    generation: current_generation,
                    import: Some(_),
                    ..
                }) if *current_generation == generation
            )
        })
}

fn configured_model_id(app: &AppView, agent_id: AgentId) -> Option<String> {
    app.models
        .current_model_id_str()
        .map(str::to_owned)
        .or_else(|| app.persisted_default_model.clone())
        .or_else(|| {
            app.agents.get(&agent_id).and_then(|agent| {
                agent
                    .session
                    .models
                    .current_model_id_str()
                    .map(str::to_owned)
            })
        })
}
fn owner_session_id(app: &AppView, agent_id: AgentId) -> Option<String> {
    app.agents
        .get(&agent_id)
        .and_then(|agent| agent.session.session_id.as_ref())
        .map(|session_id| session_id.0.to_string())
}

fn discovery_effect(
    agent_id: AgentId,
    generation: u64,
    target_cwd: std::path::PathBuf,
    owner_session_id: Option<String>,
    all_projects: bool,
) -> Effect {
    Effect::DiscoverImportSessions {
        agent_id,
        cwd: (!all_projects).then_some(target_cwd.clone()),
        target_cwd,
        owner_session_id,
        generation,
    }
}

/// Opens the ordinary session picker in import mode, then starts metadata-only discovery.
pub(in crate::app::dispatch) fn dispatch_show_import_session_picker(
    app: &mut AppView,
) -> Vec<Effect> {
    let mut effects = Vec::new();
    if matches!(app.active_view, ActiveView::Welcome) {
        super::lifecycle::reveal_home_session(app);
    }
    if !matches!(app.active_view, ActiveView::Agent(_)) && app.session_startup_allowed() {
        effects.extend(super::lifecycle::dispatch_new_session_inner(app, None));
    }
    let ActiveView::Agent(agent_id) = app.active_view else {
        app.show_toast("Open a chat to import a session, or use groky sessions import.");
        return effects;
    };
    let owner_session_id = owner_session_id(app, agent_id);
    let generation = app.alloc_picker_generation();
    let target_cwd = app.cwd.clone();
    let Some(agent) = app.agents.get_mut(&agent_id) else {
        return effects;
    };
    let mut modal = crate::views::modal::import_session_picker_modal();
    if let ActiveModal::SessionPicker {
        generation: modal_generation,
        ..
    } = &mut modal
    {
        *modal_generation = generation;
    }
    agent.active_modal = Some(modal);
    effects.push(discovery_effect(
        agent_id,
        generation,
        target_cwd,
        owner_session_id,
        false,
    ));
    effects
}

/// Toggles the import picker between the launch directory and every project.
pub(in crate::app::dispatch) fn dispatch_toggle_import_session_scope(
    app: &mut AppView,
    generation: u64,
) -> Vec<Effect> {
    let ActiveView::Agent(agent_id) = app.active_view else {
        return vec![];
    };
    let target_cwd = app.cwd.clone();
    let owner_session_id = owner_session_id(app, agent_id);
    if !current_import_picker_matches(
        app,
        agent_id,
        generation,
        &target_cwd,
        owner_session_id.as_deref(),
    ) {
        return vec![];
    }
    let next_generation = app.alloc_picker_generation();
    let Some(agent) = app.agents.get_mut(&agent_id) else {
        return vec![];
    };
    let Some(ActiveModal::SessionPicker {
        generation: modal_generation,
        state,
        entries,
        loading,
        import: Some(import),
        ..
    }) = agent.active_modal.as_mut()
    else {
        return vec![];
    };
    *modal_generation = next_generation;
    import.all_projects = !import.all_projects;
    import.candidates.clear();
    import.discovery_warnings.clear();
    import.preview = None;
    import.inspecting = None;
    import.importing = None;
    *entries = Some(Vec::new());
    *loading = true;
    state.selected = 0;
    state.scroll_offset = None;
    state.expanded.clear();
    vec![discovery_effect(
        agent_id,
        next_generation,
        target_cwd,
        owner_session_id,
        import.all_projects,
    )]
}

/// Reads a selected transcript on the blocking pool before a native session can be created.
pub(in crate::app::dispatch) fn dispatch_preview_import_session(
    app: &mut AppView,
    generation: u64,
    candidate_index: usize,
) -> Vec<Effect> {
    let ActiveView::Agent(agent_id) = app.active_view else {
        return vec![];
    };
    let target_cwd = app.cwd.clone();
    let owner_session_id = owner_session_id(app, agent_id);
    if !current_import_picker_matches(
        app,
        agent_id,
        generation,
        &target_cwd,
        owner_session_id.as_deref(),
    ) {
        return vec![];
    }
    let Some(agent) = app.agents.get_mut(&agent_id) else {
        return vec![];
    };
    let Some(ActiveModal::SessionPicker {
        state,
        import: Some(import),
        ..
    }) = agent.active_modal.as_mut()
    else {
        return vec![];
    };
    if import.inspecting.is_some() || import.importing.is_some() {
        return vec![];
    }
    let Some(candidate) = import.candidates.get(candidate_index).cloned() else {
        return vec![];
    };
    import.preview = None;
    import.inspecting = Some(candidate_index);
    state.expanded.insert(candidate_index);
    vec![Effect::PreviewImportSession {
        agent_id,
        generation,
        candidate_index,
        candidate,
        target_cwd,
        owner_session_id,
    }]
}

/// Cancels an inspected import without invalidating the underlying candidate list.
pub(in crate::app::dispatch) fn dispatch_cancel_import_session_preview(
    app: &mut AppView,
    generation: u64,
) -> Vec<Effect> {
    let ActiveView::Agent(agent_id) = app.active_view else {
        return vec![];
    };
    let next_generation = app.alloc_picker_generation();
    let Some(agent) = app.agents.get_mut(&agent_id) else {
        return vec![];
    };
    let Some(ActiveModal::SessionPicker {
        generation: modal_generation,
        import: Some(import),
        ..
    }) = agent.active_modal.as_mut()
    else {
        return vec![];
    };
    if *modal_generation != generation {
        return vec![];
    }
    *modal_generation = next_generation;
    import.preview = None;
    import.inspecting = None;
    vec![]
}

/// Starts a confirmed native import using the live Groky cwd and model, never source metadata.
pub(in crate::app::dispatch) fn dispatch_confirm_import_session(
    app: &mut AppView,
    generation: u64,
    candidate_index: usize,
) -> Vec<Effect> {
    let ActiveView::Agent(agent_id) = app.active_view else {
        return vec![];
    };
    let target_cwd = app.cwd.clone();
    let owner_session_id = owner_session_id(app, agent_id);
    if !current_import_picker_matches(
        app,
        agent_id,
        generation,
        &target_cwd,
        owner_session_id.as_deref(),
    ) {
        return vec![];
    }
    let Some(model_id) = configured_model_id(app, agent_id) else {
        if let Some(agent) = app.agents.get_mut(&agent_id) {
            agent.show_toast("Choose a Groky model before importing a session.");
        }
        return vec![];
    };
    let Some(agent) = app.agents.get_mut(&agent_id) else {
        return vec![];
    };
    let Some(ActiveModal::SessionPicker {
        import: Some(import),
        ..
    }) = agent.active_modal.as_mut()
    else {
        return vec![];
    };
    if import.inspecting.is_some()
        || import.importing.is_some()
        || !import
            .preview
            .as_ref()
            .is_some_and(|preview| preview.candidate_index == candidate_index)
    {
        return vec![];
    }
    let Some(candidate) = import.candidates.get(candidate_index).cloned() else {
        return vec![];
    };
    import.preview = None;
    import.importing = Some(candidate_index);
    vec![Effect::ImportSession {
        agent_id,
        generation,
        candidate_index,
        candidate,
        target_cwd,
        owner_session_id,
        model_id,
    }]
}

pub(in crate::app::dispatch) fn handle_import_sessions_discovered(
    app: &mut AppView,
    agent_id: AgentId,
    generation: u64,
    target_cwd: std::path::PathBuf,
    owner_session_id: Option<String>,
    candidates: Vec<ImportCandidate>,
    warnings: Vec<String>,
) -> Vec<Effect> {
    if !current_import_picker_matches(
        app,
        agent_id,
        generation,
        &target_cwd,
        owner_session_id.as_deref(),
    ) {
        return vec![];
    }
    let entries: Vec<SessionPickerEntry> = candidates.iter().map(candidate_entry).collect();
    let Some(agent) = app.agents.get_mut(&agent_id) else {
        return vec![];
    };
    let Some(ActiveModal::SessionPicker {
        entries: picker_entries,
        loading,
        state,
        import: Some(import),
        ..
    }) = agent.active_modal.as_mut()
    else {
        return vec![];
    };
    import.candidates = candidates;
    import.discovery_warnings = safe_warnings(warnings);
    import.preview = None;
    import.inspecting = None;
    import.importing = None;
    *picker_entries = Some(entries);
    *loading = false;
    state.selected = 0;
    state.scroll_offset = None;
    state.expanded.clear();
    vec![]
}

pub(in crate::app::dispatch) fn handle_import_session_previewed(
    app: &mut AppView,
    agent_id: AgentId,
    generation: u64,
    candidate_index: usize,
    target_cwd: std::path::PathBuf,
    owner_session_id: Option<String>,
    context_count: usize,
    warnings: Vec<String>,
    error: Option<String>,
) -> Vec<Effect> {
    if !current_import_picker_matches(
        app,
        agent_id,
        generation,
        &target_cwd,
        owner_session_id.as_deref(),
    ) {
        return vec![];
    }
    let Some(agent) = app.agents.get_mut(&agent_id) else {
        return vec![];
    };
    let Some(ActiveModal::SessionPicker {
        import: Some(import),
        ..
    }) = agent.active_modal.as_mut()
    else {
        return vec![];
    };
    if import.inspecting != Some(candidate_index) {
        return vec![];
    }
    import.inspecting = None;
    if let Some(error) = error {
        agent.show_toast(&safe_display(&error));
        return vec![];
    }
    import.preview = Some(ImportSessionPreview {
        candidate_index,
        context_count,
        warnings: safe_warnings(warnings),
    });
    vec![]
}

pub(in crate::app::dispatch) fn handle_import_session_completed(
    app: &mut AppView,
    agent_id: AgentId,
    generation: u64,
    candidate_index: usize,
    target_cwd: std::path::PathBuf,
    owner_session_id: Option<String>,
    session_id: Option<String>,
    message_count: usize,
    warnings: Vec<String>,
    error: Option<String>,
) -> Vec<Effect> {
    if !current_import_picker_matches(
        app,
        agent_id,
        generation,
        &target_cwd,
        owner_session_id.as_deref(),
    ) {
        return vec![];
    }
    let Some(agent) = app.agents.get_mut(&agent_id) else {
        return vec![];
    };
    let Some(ActiveModal::SessionPicker {
        import: Some(import),
        ..
    }) = agent.active_modal.as_mut()
    else {
        return vec![];
    };
    if import.importing != Some(candidate_index) {
        return vec![];
    }
    import.importing = None;
    if let Some(error) = error {
        agent.show_toast(&safe_display(&error));
        return vec![];
    }
    let Some(session_id) = session_id else {
        agent.show_toast("Session import did not return a native session ID.");
        return vec![];
    };
    agent.active_modal = None;
    let warning_count = safe_warnings(warnings).len();
    let notice = if warning_count == 0 {
        format!("Imported {message_count} messages into native session {session_id}.")
    } else {
        format!(
            "Imported {message_count} messages with {warning_count} warnings into native session {session_id}."
        )
    };
    let effects = dispatch_load_session(app, session_id, Some(target_cwd), false);
    app.show_toast(&notice);
    effects
}
