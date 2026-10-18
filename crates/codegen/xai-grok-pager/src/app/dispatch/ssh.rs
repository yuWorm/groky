//! Local-only SSH manager dispatch and Welcome-screen input routing.

use super::ctx::{active_agent_session_id, get_active_agent_mut};
use crate::app::actions::{Action, Effect};
use crate::app::app_view::{AppView, InputOutcome};
use crate::views::ssh_modal::SshModalOutcome;

fn map_ssh_modal_outcome(outcome: SshModalOutcome) -> InputOutcome {
    match outcome {
        SshModalOutcome::Close => InputOutcome::Unchanged,
        SshModalOutcome::Changed => InputOutcome::Changed,
        SshModalOutcome::Unchanged => InputOutcome::Unchanged,
        SshModalOutcome::Refresh => InputOutcome::Action(Action::RefreshSshTargets),
        SshModalOutcome::AddTarget(draft) => InputOutcome::Action(Action::AddSshTarget(draft)),
        SshModalOutcome::Connect { target_id } => {
            InputOutcome::Action(Action::ConnectSshTarget { target_id })
        }
        SshModalOutcome::Disconnect { target_id } => {
            InputOutcome::Action(Action::DisconnectSshTarget { target_id })
        }
        SshModalOutcome::RequestGrant {
            target_id,
            root,
            capabilities,
            lifetime,
            set_default,
        } => InputOutcome::Action(Action::RequestSshGrant {
            target_id,
            root,
            capabilities,
            lifetime,
            set_default,
        }),
        SshModalOutcome::ApproveGrant {
            request_id,
            approved,
            target_id,
            root,
            capabilities,
            lifetime,
            set_default,
        } => InputOutcome::Action(Action::ApproveSshGrant {
            request_id,
            approved,
            target_id,
            root,
            capabilities,
            lifetime,
            set_default,
        }),
        SshModalOutcome::InspectGrantTarget {
            request_id,
            target_id,
        } => InputOutcome::Action(Action::InspectSshGrantTarget {
            request_id,
            target_id,
        }),
        SshModalOutcome::UseBinding { binding_id } => {
            InputOutcome::Action(Action::UseSshBinding { binding_id })
        }
        SshModalOutcome::RevokeBinding { binding_id } => {
            InputOutcome::Action(Action::RevokeSshBinding { binding_id })
        }
        SshModalOutcome::OpenProject {
            target_id,
            root,
            binding_id,
            capabilities,
        } => InputOutcome::Action(Action::OpenSshProject {
            target_id,
            root,
            binding_id,
            capabilities,
        }),
        SshModalOutcome::ApproveOperation {
            approval_id,
            approved,
        } => InputOutcome::Action(Action::ApproveSshOperation {
            approval_id,
            approved,
        }),
        SshModalOutcome::AnswerAuthentication {
            challenge_id,
            connection_generation,
            target_id,
            accept_host_key,
            remember,
            secret,
            answers,
        } => InputOutcome::Action(Action::SubmitSshAuthentication {
            challenge_id,
            connection_generation,
            target_id,
            accept_host_key,
            remember,
            secret,
            answers,
        }),
    }
}

fn active_session_id(app: &AppView) -> Option<String> {
    active_agent_session_id(app).map(|session_id| session_id.to_string())
}

pub(super) fn ssh_manager_mut(
    app: &mut AppView,
) -> Option<&mut crate::views::ssh_modal::SshManagerState> {
    let on_agent = get_active_agent_mut(app).is_some_and(|agent| agent.ssh_manager.is_some());
    if on_agent {
        return get_active_agent_mut(app).and_then(|agent| agent.ssh_manager.as_mut());
    }
    app.welcome_ssh_manager.as_mut()
}

/// Events are session-scoped, not modal-scoped. When a normal project receives a local SSH
/// authentication or operation approval while its manager is closed, create the local-only
/// manager state on that project so the required consent surface is still reachable.
pub(super) fn ssh_manager_for_session_mut<'a>(
    app: &'a mut AppView,
    session_id: Option<&str>,
) -> Option<&'a mut crate::views::ssh_modal::SshManagerState> {
    let Some(session_id) = session_id else {
        if app.welcome_ssh_manager.is_none() {
            app.welcome_ssh_manager = Some(crate::views::ssh_modal::SshManagerState::new(None));
        }
        return app.welcome_ssh_manager.as_mut();
    };
    if app
        .pending_ssh_project_open
        .as_ref()
        .is_some_and(|project| project.project_session_id == session_id)
    {
        return app.welcome_ssh_manager.as_mut();
    }
    // A remote worktree's child is pre-minted before ACP binds it to the optimistic
    // agent. Once its grant resolves, retain that exact child ID until WorktreeForked so
    // subsequent checkout approval and completion stay on the visible child.
    let pending_child_agent_id = match app.active_view {
        crate::app::app_view::ActiveView::Agent(agent_id)
            if app.agents.get(&agent_id).is_some_and(|agent| {
                active_worktree_child_matches_pre_minted_session(agent, session_id)
                    && agent
                        .ssh_manager
                        .as_ref()
                        .is_none_or(|manager| manager.session_id.as_deref() == Some(session_id))
            }) =>
        {
            Some(agent_id)
        }
        _ => None,
    };
    if let Some(agent_id) = pending_child_agent_id {
        let agent = app.agents.get_mut(&agent_id)?;
        if agent.ssh_manager.is_none() {
            agent.ssh_manager = Some(crate::views::ssh_modal::SshManagerState::new(Some(
                session_id.to_owned(),
            )));
        }
        return agent.ssh_manager.as_mut();
    }
    let source_agent_id = app.agents.iter().find_map(|(agent_id, agent)| {
        agent
            .session
            .session_id
            .as_ref()
            .is_some_and(|candidate| candidate.0.as_ref() == session_id)
            .then_some(*agent_id)
    })?;
    // A worktree fork is optimistic: the active child has no session yet, but the remote
    // worktree RPC is authorized by its source session. Surface that source-owned approval on
    // the child which initiated the request; its manager still submits against `session_id`.
    let manager_agent_id = match app.active_view {
        crate::app::app_view::ActiveView::Agent(active_agent_id)
            if active_agent_id != source_agent_id
                && app.agents.get(&active_agent_id).is_some_and(|agent| {
                    active_worktree_child_matches_source(agent, session_id)
                        && agent.pending_worktree_child_session_id.is_none()
                        && agent
                            .ssh_manager
                            .as_ref()
                            .is_none_or(|manager| manager.session_id.as_deref() == Some(session_id))
                }) =>
        {
            active_agent_id
        }
        _ => source_agent_id,
    };
    let agent = app.agents.get_mut(&manager_agent_id)?;
    if agent.ssh_manager.is_none() {
        agent.ssh_manager = Some(crate::views::ssh_modal::SshManagerState::new(Some(
            session_id.to_owned(),
        )));
    }
    agent.ssh_manager.as_mut()
}
/// Find an already-visible manager for this exact session without creating an overlay.
fn existing_ssh_manager_for_session<'a>(
    app: &'a AppView,
    session_id: Option<&str>,
) -> Option<&'a crate::views::ssh_modal::SshManagerState> {
    if app
        .welcome_ssh_manager
        .as_ref()
        .is_some_and(|manager| manager.session_id.as_deref() == session_id)
    {
        return app.welcome_ssh_manager.as_ref();
    }
    let session_id = session_id?;
    let active_child_id = match app.active_view {
        crate::app::app_view::ActiveView::Agent(agent_id)
            if app.agents.get(&agent_id).is_some_and(|agent| {
                active_worktree_child_matches_session(agent, session_id)
            }) =>
        {
            Some(agent_id)
        }
        _ => None,
    };
    if let Some(agent_id) = active_child_id
        && let Some(manager) = app
            .agents
            .get(&agent_id)
            .and_then(|agent| agent.ssh_manager.as_ref())
            .filter(|manager| manager.session_id.as_deref() == Some(session_id))
    {
        return Some(manager);
    }
    app.agents
        .values()
        .find(|agent| {
            agent
                .session
                .session_id
                .as_ref()
                .is_some_and(|candidate| candidate.0.as_ref() == session_id)
        })
        .and_then(|agent| agent.ssh_manager.as_ref())
}

/// Find an already-visible manager for this exact session without creating an overlay.
pub(super) fn existing_ssh_manager_for_session_mut<'a>(
    app: &'a mut AppView,
    session_id: Option<&str>,
) -> Option<&'a mut crate::views::ssh_modal::SshManagerState> {
    if app
        .welcome_ssh_manager
        .as_ref()
        .is_some_and(|manager| manager.session_id.as_deref() == session_id)
    {
        return app.welcome_ssh_manager.as_mut();
    }
    let session_id = session_id?;
    let active_child_id = match app.active_view {
        crate::app::app_view::ActiveView::Agent(agent_id)
            if app.agents.get(&agent_id).is_some_and(|agent| {
                active_worktree_child_matches_session(agent, session_id)
                    && agent
                        .ssh_manager
                        .as_ref()
                        .is_some_and(|manager| manager.session_id.as_deref() == Some(session_id))
            }) =>
        {
            Some(agent_id)
        }
        _ => None,
    };
    let owner_agent_id = active_child_id.or_else(|| {
        app.agents.iter().find_map(|(agent_id, agent)| {
            agent
                .session
                .session_id
                .as_ref()
                .is_some_and(|candidate| candidate.0.as_ref() == session_id)
                .then_some(*agent_id)
        })
    })?;
    app.agents
        .get_mut(&owner_agent_id)
        .and_then(|agent| agent.ssh_manager.as_mut())
}

/// Find the manager awaiting target data for a session. A cold remote worktree's child session
/// is pre-minted before its optimistic agent is bound, so normal session lookup cannot find it;
/// its displayed grant retains the exact child ID until the user decides it.
pub(super) fn ssh_manager_for_target_list_session_mut<'a>(
    app: &'a mut AppView,
    session_id: Option<&str>,
) -> Option<&'a mut crate::views::ssh_modal::SshManagerState> {
    if let Some(session_id) = session_id {
        if app
            .welcome_ssh_manager
            .as_ref()
            .is_some_and(|manager| manager.owns_pending_grant_session(session_id))
        {
            return app.welcome_ssh_manager.as_mut();
        }
        let owner_agent_id = app.agents.iter().find_map(|(agent_id, agent)| {
            agent
                .ssh_manager
                .as_ref()
                .is_some_and(|manager| manager.owns_pending_grant_session(session_id))
                .then_some(*agent_id)
        });
        if let Some(agent_id) = owner_agent_id {
            return app
                .agents
                .get_mut(&agent_id)
                .and_then(|agent| agent.ssh_manager.as_mut());
        }
    }
    ssh_manager_for_session_mut(app, session_id)
}

/// Remove only the exact transient manager that interrupted a session. An explicit manager or a
/// newer approval never shares this path.
pub(super) fn close_transient_ssh_manager_for_session(
    app: &mut AppView,
    session_id: Option<&str>,
) {
    if app
        .welcome_ssh_manager
        .as_ref()
        .is_some_and(|manager| manager.session_id.as_deref() == session_id)
    {
        app.welcome_ssh_manager = None;
        return;
    }
    let Some(session_id) = session_id else {
        return;
    };
    let active_child_id = match app.active_view {
        crate::app::app_view::ActiveView::Agent(agent_id)
            if app.agents.get(&agent_id).is_some_and(|agent| {
                active_worktree_child_matches_session(agent, session_id)
                    && agent
                        .ssh_manager
                        .as_ref()
                        .is_some_and(|manager| manager.session_id.as_deref() == Some(session_id))
            }) =>
        {
            Some(agent_id)
        }
        _ => None,
    };
    if let Some(agent_id) = active_child_id {
        if let Some(agent) = app.agents.get_mut(&agent_id) {
            agent.ssh_manager = None;
        }
        return;
    }
    if let Some(agent) = app.agents.values_mut().find(|agent| {
        agent
            .session
            .session_id
            .as_ref()
            .is_some_and(|candidate| candidate.0.as_ref() == session_id)
    }) {
        agent.ssh_manager = None;
    }
}

fn session_or_show_error(app: &mut AppView) -> Option<String> {
    let session_id = active_session_id(app);
    if session_id.is_none()
        && let Some(manager) = ssh_manager_mut(app)
    {
        manager.show_error("Open or create a session before granting SSH access.");
    }
    session_id
}

pub(super) fn dispatch_open_ssh_manager(app: &mut AppView) -> Vec<Effect> {
    let session_id = active_session_id(app);
    if let Some(agent) = get_active_agent_mut(app) {
        agent.ssh_manager = Some(crate::views::ssh_modal::SshManagerState::new(
            session_id.clone(),
        ));
    } else {
        app.welcome_ssh_manager = Some(crate::views::ssh_modal::SshManagerState::new(
            session_id.clone(),
        ));
    }
    let mut effects = Vec::with_capacity(2);
    // One receiver owns this pager client's event stream for all sessions. It is deliberately
    // independent of overlay visibility and re-arms itself after every event.
    if !app.ssh_event_consumer_active {
        app.ssh_event_consumer_active = true;
        effects.push(Effect::SshAwaitEvent {
            client_id: app.ssh_client_id,
            session_id: session_id.clone(),
        });
    }
    effects.push(Effect::SshListTargets {
        session_id,
        client_id: app.ssh_client_id,
    });
    effects
}

/// Start the `groky ssh open` consent flow. The session id is pre-minted before a grant is
/// requested, so an approved binding already belongs to the exact session passed to `session/new`.
pub(super) fn dispatch_begin_ssh_project_open(
    app: &mut AppView,
    project: crate::app::cli::SshProjectOpen,
) -> Vec<Effect> {
    app.welcome_ssh_manager = Some(crate::views::ssh_modal::SshManagerState::new(Some(
        project.project_session_id.clone(),
    )));
    app.pending_ssh_project_open = Some(project.clone());
    let mut effects = Vec::with_capacity(3);
    if !app.ssh_event_consumer_active {
        app.ssh_event_consumer_active = true;
        effects.push(Effect::SshAwaitEvent {
            client_id: app.ssh_client_id,
            session_id: Some(project.project_session_id.clone()),
        });
    }
    effects.push(Effect::SshListTargets {
        session_id: Some(project.project_session_id.clone()),
        client_id: app.ssh_client_id,
    });
    effects.push(Effect::SshBeginProjectGrant {
        project,
        client_id: app.ssh_client_id,
    });
    effects
}

pub(super) fn dispatch_refresh_ssh_targets(app: &mut AppView) -> Vec<Effect> {
    vec![Effect::SshListTargets {
        session_id: active_session_id(app),
        client_id: app.ssh_client_id,
    }]
}

pub(super) fn dispatch_add_ssh_target(
    app: &mut AppView,
    draft: crate::views::ssh_modal::SshManualTargetDraft,
) -> Vec<Effect> {
    vec![Effect::SshAddTarget {
        session_id: active_session_id(app),
        client_id: app.ssh_client_id,
        draft,
    }]
}

pub(super) fn dispatch_connect_ssh_target(app: &mut AppView, target_id: String) -> Vec<Effect> {
    if let Some(manager) = ssh_manager_mut(app) {
        manager.show_info("Connecting through the local SSH service…");
    }
    vec![Effect::SshConnect {
        target_id,
        client_id: app.ssh_client_id,
    }]
}

pub(super) fn dispatch_disconnect_ssh_target(app: &mut AppView, target_id: String) -> Vec<Effect> {
    if let Some(manager) = ssh_manager_mut(app) {
        manager.show_info("Releasing the retained SSH connection…");
    }
    vec![Effect::SshDisconnect {
        target_id,
        client_id: app.ssh_client_id,
    }]
}

pub(super) fn dispatch_request_ssh_grant(
    app: &mut AppView,
    target_id: String,
    root: String,
    capabilities: crate::views::ssh_modal::SshCapabilitiesView,
    lifetime: crate::views::ssh_modal::SshGrantLifetime,
    set_default: bool,
) -> Vec<Effect> {
    let Some(session_id) = session_or_show_error(app) else {
        return vec![];
    };
    if let Some(manager) = ssh_manager_mut(app) {
        manager.remember_local_grant_options(
            target_id.clone(),
            root.clone(),
            capabilities,
            lifetime,
            set_default,
        );
    }
    vec![Effect::SshRequestGrant {
        session_id,
        client_id: app.ssh_client_id,
        target_id,
        root,
        capabilities,
        lifetime,
        set_default,
    }]
}

pub(super) fn dispatch_inspect_ssh_grant_target(
    app: &mut AppView,
    request_id: String,
    target_id: String,
) -> Vec<Effect> {
    if let Some(manager) = ssh_manager_mut(app) {
        manager.show_info("Authenticating the selected SSH target before access review…");
    }
    let session_id = ssh_manager_mut(app)
        .and_then(|manager| manager.grant_session_id_for(&request_id))
        .or_else(|| active_session_id(app))
        .or_else(|| {
            app.welcome_ssh_manager
                .as_ref()
                .and_then(|manager| manager.session_id.clone())
        });
    vec![Effect::SshInspectGrantTarget {
        session_id,
        request_id,
        target_id,
        client_id: app.ssh_client_id,
    }]
}

pub(super) fn dispatch_approve_ssh_grant(
    app: &mut AppView,
    request_id: String,
    approved: bool,
    target_id: Option<String>,
    root: Option<String>,
    capabilities: Option<crate::views::ssh_modal::SshCapabilitiesView>,
    lifetime: crate::views::ssh_modal::SshGrantLifetime,
    set_default: bool,
) -> Vec<Effect> {
    // `groky ssh open` and remote worktree resumes have intentionally not created their
    // pre-minted child ACP session yet. The displayed consent request, not the active source
    // project, is authoritative for the grant decision's session id.
    let session_id = ssh_manager_mut(app)
        .and_then(|manager| {
            let session_id = manager.grant_session_id_for(&request_id);
            if approved && session_id.is_some() {
                let _ = manager.record_grant_approval(
                    &request_id,
                    target_id.as_deref(),
                    root.as_deref(),
                );
            }
            session_id
        })
        .or_else(|| active_session_id(app))
        .or_else(|| {
            app.welcome_ssh_manager
                .as_ref()
                .and_then(|manager| manager.session_id.clone())
        });
    let Some(session_id) = session_id else {
        if let Some(manager) = ssh_manager_mut(app) {
            manager.show_error("Open or create a session before granting SSH access.");
        }
        return vec![];
    };
    vec![Effect::SshApproveGrant {
        session_id,
        request_id,
        client_id: app.ssh_client_id,
        approved,
        target_id,
        root,
        capabilities,
        lifetime,
        set_default,
    }]
}

pub(super) fn dispatch_use_ssh_binding(app: &mut AppView, binding_id: String) -> Vec<Effect> {
    let Some(session_id) = session_or_show_error(app) else {
        return vec![];
    };
    vec![Effect::SshUseBinding {
        session_id,
        binding_id,
        client_id: app.ssh_client_id,
    }]
}

pub(super) fn dispatch_revoke_ssh_binding(app: &mut AppView, binding_id: String) -> Vec<Effect> {
    let Some(session_id) = session_or_show_error(app) else {
        return vec![];
    };
    vec![Effect::SshRevokeBinding {
        session_id,
        binding_id,
        client_id: app.ssh_client_id,
    }]
}

pub(super) fn dispatch_open_ssh_project(
    app: &mut AppView,
    target_id: String,
    root: String,
    binding_id: String,
    capabilities: crate::views::ssh_modal::SshCapabilitiesView,
) -> Vec<Effect> {
    let Some(source_session_id) = session_or_show_error(app) else {
        return vec![];
    };
    let project_session_id = uuid::Uuid::now_v7().to_string();
    if let Some(manager) = ssh_manager_mut(app) {
        manager.show_info("Preparing an inherited SSH binding for the new local project…");
    }
    vec![Effect::SshInheritBinding {
        source_session_id,
        source_binding_id: binding_id,
        project_session_id,
        target_id,
        root,
        capabilities,
        client_id: app.ssh_client_id,
    }]
}

/// Create the actual local pager session only after the leader has minted a binding owned by
/// `project_session_id`. Reusing the source binding would be rejected by session setup.
pub(super) fn dispatch_inherited_ssh_project(
    app: &mut AppView,
    target_id: String,
    root: String,
    project_session_id: String,
    binding_id: String,
) -> Vec<Effect> {
    let ssh_project_location = crate::app::agent_view::SshProjectLocation {
        target_id: target_id.clone(),
        root: root.clone(),
    };
    let start = match xai_grok_shell::project::SshProjectStart::new(
        target_id,
        root,
        Some(binding_id),
        Some(project_session_id),
    ) {
        Ok(start) => start,
        Err(error) => {
            if let Some(manager) = ssh_manager_mut(app) {
                manager.show_error(error.to_string());
            }
            return vec![];
        }
    };
    let ssh_client_id = app.ssh_client_id;
    let (agent_id, mut effects) =
        super::session::lifecycle::dispatch_new_session_inner_with_id(app, None, false);
    let mut start = Some(start);
    if let Some(agent) = app.agents.get_mut(&agent_id) {
        agent.ssh_project_location = Some(ssh_project_location);
    }
    for effect in &mut effects {
        if let Effect::CreateSession {
            agent_id: candidate,
            cwd,
            ..
        } = effect
            && *candidate == agent_id
        {
            *effect = Effect::OpenSshProject {
                agent_id,
                local_launch_cwd: cwd.clone(),
                start: start
                    .take()
                    .expect("the SSH start is consumed only by its session effect"),
                ssh_client_id,
            };
            return effects;
        }
    }
    unreachable!("new SSH project placeholder must emit CreateSession")
}

pub(super) fn dispatch_submit_ssh_authentication(
    app: &mut AppView,
    challenge_id: String,
    connection_generation: u64,
    _target_id: String,
    accept_host_key: Option<bool>,
    remember: bool,
    secret: Option<crate::views::ssh_modal::SshSecret>,
    answers: Vec<crate::views::ssh_modal::SshSecret>,
) -> Vec<Effect> {
    vec![Effect::SshSubmitAuthentication {
        client_id: app.ssh_client_id,
        challenge_id,
        connection_generation,
        accept_host_key,
        remember,
        secret,
        answers,
    }]
}

pub(super) fn dispatch_approve_ssh_operation(
    app: &mut AppView,
    approval_id: String,
    approved: bool,
) -> Vec<Effect> {
    let client_id = app.ssh_client_id;
    let Some(manager) = ssh_manager_mut(app) else {
        return vec![];
    };
    if !manager.submit_operation_approval(&approval_id, approved) {
        return vec![];
    }
    vec![Effect::SshApproveOperation {
        session_id: manager.session_id.clone(),
        client_id,
        approval_id,
        approved,
    }]
}

/// Locate the visible manager that owns an in-flight grant. A remote worktree can request a
/// pre-minted child session before that child has an `AgentView`, so its consent remains on the
/// source project manager until the child binding is accepted.
fn manager_session_for_grant(app: &AppView, request_id: &str) -> Option<Option<String>> {
    if app
        .welcome_ssh_manager
        .as_ref()
        .is_some_and(|manager| manager.grant_session_id_for(request_id).is_some())
    {
        return Some(None);
    }
    app.agents.values().find_map(|agent| {
        agent
            .ssh_manager
            .as_ref()
            .filter(|manager| manager.grant_session_id_for(request_id).is_some())
            .map(|manager| manager.session_id.clone())
    })
}
/// True only for the visible optimistic worktree child that was created from this exact source
/// session. This is the correlation boundary for source-owned worktree RPC approvals: no reason,
/// root, or unknown session can select a child.
fn active_worktree_child_matches_source(
    agent: &crate::app::agent_view::AgentView,
    source_session_id: &str,
) -> bool {
    agent.pending_fork_banner.as_ref().is_some_and(|fork| {
        fork.worktree && fork.parent_sid == source_session_id
    }) || (agent.pending_worktree_source_session_id.as_deref() == Some(source_session_id)
        && agent.session.session_id.is_none()
        && matches!(
            agent.session.state.command_in_flight(),
            Some(crate::app::agent::AgentCommand::RestoreWorktree)
        ))
}

/// The exact pre-minted child remains authoritative only while its worktree creation command
/// is in flight. This correlation is installed after an accepted child grant and retired by
/// WorktreeForked/WorktreeSessionFailed; it never derives from request prose or a root path.
fn active_worktree_child_matches_pre_minted_session(
    agent: &crate::app::agent_view::AgentView,
    child_session_id: &str,
) -> bool {
    agent.pending_worktree_child_session_id.as_deref() == Some(child_session_id)
        && agent.session.session_id.is_none()
        && matches!(
            agent.session.state.command_in_flight(),
            Some(
                crate::app::agent::AgentCommand::CreateWorktree
                    | crate::app::agent::AgentCommand::RestoreWorktree
            )
        )
}

/// Match either side of an optimistic remote-worktree handoff: the source while creating the
/// child, or the exact child after its grant resolves but before ACP binds it.
fn active_worktree_child_matches_session(
    agent: &crate::app::agent_view::AgentView,
    session_id: &str,
) -> bool {
    active_worktree_child_matches_source(agent, session_id)
        || active_worktree_child_matches_pre_minted_session(agent, session_id)
}

/// Promote an approved worktree child's exact server-minted session to the visible optimistic
/// child. Its manager must submit subsequent checkout approvals against the child binding, not
/// the source binding that authorized worktree creation.
fn promote_worktree_child_session(
    app: &mut AppView,
    source_session_id: &str,
    child_session_id: &str,
) {
    let crate::app::app_view::ActiveView::Agent(active_agent_id) = app.active_view else {
        return;
    };
    let Some(agent) = app.agents.get_mut(&active_agent_id) else {
        return;
    };
    if !active_worktree_child_matches_source(agent, source_session_id) {
        return;
    }
    if agent
        .ssh_manager
        .as_ref()
        .is_none_or(|manager| manager.session_id.as_deref() != Some(source_session_id))
    {
        return;
    }
    agent.pending_worktree_child_session_id = Some(child_session_id.to_owned());
    agent.ssh_manager.as_mut().unwrap().session_id = Some(child_session_id.to_owned());
}

/// Correlate a new-root worktree grant to the active optimistic child without accepting an
/// arbitrary unknown session. Only the shell's dedicated worktree-grant path can attach the
/// typed source session, and both that source and target must still belong to the active fork.
fn worktree_source_session_for_grant(
    app: &AppView,
    request: &xai_grok_shell::ssh::SshGrantRequest,
    client_id: u64,
) -> Option<String> {
    if request.client_id != Some(client_id) {
        return None;
    }
    let source_session_id = request.originating_session_id.as_deref()?;
    let crate::app::app_view::ActiveView::Agent(active_agent_id) = app.active_view else {
        return None;
    };
    let active_agent = app.agents.get(&active_agent_id)?;
    if !active_worktree_child_matches_source(active_agent, source_session_id) {
        return None;
    }
    let source_agent = app.agents.values().find(|agent| {
        agent
            .session
            .session_id
            .as_ref()
            .is_some_and(|session_id| session_id.0.as_ref() == source_session_id)
    })?;
    source_agent
        .ssh_project_location
        .as_ref()
        .filter(|location| request.target_id.as_deref() == Some(location.target_id.as_str()))?;
    Some(source_session_id.to_owned())
}


fn operation_approval_target(
    detail: &serde_json::Value,
    binding_id: &str,
    manager: &crate::views::ssh_modal::SshManagerState,
) -> (String, Option<String>) {
    let binding = detail.get("binding").and_then(serde_json::Value::as_object);
    let target_label = binding
        .and_then(|binding| binding.get("target_id"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .or_else(|| manager.target_label_for_binding(binding_id))
        .unwrap_or_else(|| "Unresolved SSH target".into());
    let identity = binding.and_then(|binding| {
        let identity = binding.get("identity")?.as_object()?;
        let username = identity.get("username")?.as_str()?;
        let hostname = identity.get("hostname")?.as_str()?;
        let port = identity.get("port")?.as_u64()?;
        let mut rendered = format!("{username}@{hostname}:{port}");
        if let Some(fingerprint) = identity.get("fingerprint").and_then(serde_json::Value::as_str)
        {
            rendered.push_str(&format!(" ({fingerprint})"));
        }
        Some(rendered)
    });
    (target_label, identity)
}

/// Apply one client-targeted control event locally, never through ACP or scrollback.
pub(super) fn apply_ssh_control_event(
    app: &mut AppView,
    session_id: Option<String>,
    event: xai_grok_shell::ssh::SshEvent,
) -> Vec<Effect> {
    let client_id = app.ssh_client_id;
    let event_session_id = match &event {
        xai_grok_shell::ssh::SshEvent::GrantRequested(request) => Some(request.session_id.clone()),
        xai_grok_shell::ssh::SshEvent::BindingRevoked { session_id, .. } => {
            Some(session_id.clone())
        }
        xai_grok_shell::ssh::SshEvent::OperationApproval(approval) => {
            Some(approval.session_id.clone())
        }
        xai_grok_shell::ssh::SshEvent::Authentication(_)
        | xai_grok_shell::ssh::SshEvent::TargetStatus(_) => {
            active_session_id(app).or_else(|| session_id.clone())
        }
        xai_grok_shell::ssh::SshEvent::GrantResolved { .. } => session_id.clone(),
        // Worker progress is delivered to the session's ACP subscriber. Keep the manager
        // control stream alive without creating a local SSH manager overlay.
        xai_grok_shell::ssh::SshEvent::Worker(_) => {
            return vec![Effect::SshAwaitEvent {
                client_id,
                session_id,
            }];
        }
    };
    let manager_session_id = match &event {
        xai_grok_shell::ssh::SshEvent::GrantRequested(request) => {
            worktree_source_session_for_grant(app, request, client_id)
                .or_else(|| event_session_id.clone())
        }
        xai_grok_shell::ssh::SshEvent::GrantResolved { request_id, .. } => {
            manager_session_for_grant(app, request_id).unwrap_or_else(|| event_session_id.clone())
        }
        _ => event_session_id.clone(),
    };
    let operation_approval_origin = match &event {
        xai_grok_shell::ssh::SshEvent::OperationApproval(_) => {
            match existing_ssh_manager_for_session(app, manager_session_id.as_deref()) {
                Some(manager) => manager
                    .operation_approval_origin()
                    .unwrap_or(crate::views::ssh_modal::SshOperationApprovalOrigin::ExplicitManager),
                None => crate::views::ssh_modal::SshOperationApprovalOrigin::TransientEvent,
            }
        }
        _ => crate::views::ssh_modal::SshOperationApprovalOrigin::ExplicitManager,
    };
    let pending_project = app.pending_ssh_project_open.clone();
    let mut grant_resolution = None;
    if let Some(manager) = ssh_manager_for_session_mut(app, manager_session_id.as_deref()) {
        match event {
            xai_grok_shell::ssh::SshEvent::GrantRequested(request) => {
                if request.client_id == Some(client_id) {
                    let identity = request.verified_identity.map(|identity| {
                        format!(
                            "{}@{}:{} ({})",
                            identity.username,
                            identity.hostname,
                            identity.port,
                            identity.fingerprint
                        )
                    });
                    manager.show_incoming_grant(
                        request.session_id.clone(),
                        crate::views::ssh_modal::SshIncomingGrant {
                            request_id: request.id,
                            target_id: request.target_id,
                            root: request.root,
                            capabilities: crate::views::ssh_modal::SshCapabilitiesView {
                                read: request.capabilities.read,
                                write: request.capabilities.write,
                                execute: request.capabilities.execute,
                            },
                            verified_identity: identity,
                            reason: request.reason,
                        },
                    );
                }
            }
            xai_grok_shell::ssh::SshEvent::GrantResolved {
                request_id,
                approved,
                binding,
            } => {
                // The request id is immutable and was retained only when this card was
                // displayed. A worktree's child session is minted by the shell after the
                // pager subscribes, so the receiver's source-session tag is not its owner.
                let owns_resolution = manager.grant_session_id_for(&request_id).is_some();
                let submitted_project_root = pending_project.as_ref().and_then(|project| {
                    manager
                        .submitted_project_grant_root(
                            &request_id,
                            &project.project_session_id,
                            &project.target_id,
                            &project.root,
                        )
                        .map(ToOwned::to_owned)
                });
                let resolution_matches_pending_project =
                    pending_project.as_ref().is_none_or(|project| {
                        let receiver_matches =
                            event_session_id.as_deref().is_none_or(|session_id| {
                                session_id == project.project_session_id
                            });
                        if !approved {
                            return receiver_matches;
                        }
                        receiver_matches
                            && submitted_project_root.is_some()
                            && binding.as_ref().is_some_and(|binding| {
                                binding.session_id == project.project_session_id
                                    && binding.target_id == project.target_id
                            })
                    });
                if owns_resolution && resolution_matches_pending_project {
                    manager.settle_grant(approved);
                    grant_resolution = Some((approved, binding, submitted_project_root));
                } else if owns_resolution {
                    manager.show_error(
                        "Ignoring an SSH grant resolution that does not match the active project request.",
                    );
                }
            }
            xai_grok_shell::ssh::SshEvent::BindingRevoked {
                session_id: event_session_id,
                binding_id,
                status,
            } => {
                if manager.session_id.as_deref() == Some(event_session_id.as_str()) {
                    manager.mark_binding_revoked(
                        &binding_id,
                        matches!(status, xai_grok_shell::ssh::RevokeStatus::Confirmed),
                    );
                }
            }
            xai_grok_shell::ssh::SshEvent::Authentication(prompt) => {
                if prompt.client_id == client_id {
                    let challenge_id = prompt.challenge_id;
                    let connection_generation = prompt.connection_generation;
                    let target_id = prompt.target_id;
                    let kind = match (prompt.kind, prompt.detail) {
                        (
                            xai_grok_shell::ssh::SshAuthPromptKind::HostKey,
                            xai_grok_shell::ssh::SshAuthPromptDetail::HostKey {
                                hostname,
                                port,
                                algorithm,
                                fingerprint,
                                status,
                            },
                        ) => Some(crate::views::ssh_modal::SshAuthKind::HostKey {
                            hostname,
                            port,
                            algorithm,
                            fingerprint,
                            status,
                        }),
                        (
                            xai_grok_shell::ssh::SshAuthPromptKind::Password,
                            xai_grok_shell::ssh::SshAuthPromptDetail::Secret {
                                username,
                                message,
                                allow_remember,
                            },
                        ) => Some(crate::views::ssh_modal::SshAuthKind::Password {
                            username,
                            message,
                            allow_remember,
                        }),
                        (
                            xai_grok_shell::ssh::SshAuthPromptKind::PrivateKeyPassphrase,
                            xai_grok_shell::ssh::SshAuthPromptDetail::Secret {
                                username,
                                message,
                                allow_remember,
                            },
                        ) => Some(crate::views::ssh_modal::SshAuthKind::PrivateKeyPassphrase {
                            username,
                            message,
                            allow_remember,
                        }),
                        (
                            xai_grok_shell::ssh::SshAuthPromptKind::KeyboardInteractive,
                            xai_grok_shell::ssh::SshAuthPromptDetail::KeyboardInteractive {
                                name,
                                instruction,
                                questions,
                            },
                        ) => Some(crate::views::ssh_modal::SshAuthKind::KeyboardInteractive {
                            name,
                            instruction,
                            prompts: questions
                                .into_iter()
                                .map(|question| question.prompt)
                                .collect(),
                        }),
                        _ => None,
                    };
                    if let Some(kind) = kind {
                        manager.show_authentication(crate::views::ssh_modal::SshAuthCard::new(
                            challenge_id,
                            connection_generation,
                            target_id,
                            kind,
                        ));
                    } else {
                        manager.show_error(
                            "SSH authentication prompt kind did not match its local details.",
                        );
                    }
                }
            }
            xai_grok_shell::ssh::SshEvent::OperationApproval(approval) => {
                if approval.client_id == client_id
                    && manager.session_id.as_deref() == Some(approval.session_id.as_str())
                {
                    let (target_label, target_identity) =
                        operation_approval_target(&approval.detail, &approval.binding_id, manager);
                    let detail = serde_json::to_string_pretty(&approval.detail)
                        .unwrap_or_else(|_| "Remote operation details are unavailable.".into());
                    manager.show_operation_approval(
                        crate::views::ssh_modal::SshOperationApprovalCard::new(
                            approval.approval_id,
                            approval.binding_id,
                            target_label,
                            target_identity,
                            approval.title,
                            detail,
                        ),
                        operation_approval_origin,
                    );
                }
            }
            xai_grok_shell::ssh::SshEvent::TargetStatus(status) => {
                manager.apply_target_status(
                    &status.target_id,
                    matches!(
                        status.connection,
                        xai_grok_shell::ssh::SshConnectionState::Connected
                    ),
                    status.detail,
                );
            }
            xai_grok_shell::ssh::SshEvent::Worker(_) => {
                return vec![Effect::SshAwaitEvent {
                    client_id,
                    session_id,
                }];
            }
        }
    }
    if pending_project.is_none()
        && let Some((true, Some(binding), _)) = grant_resolution.as_ref()
        && let Some(source_session_id) = manager_session_id.as_deref()
    {
        promote_worktree_child_session(app, source_session_id, &binding.session_id);
    }
    if let Some((approved, binding, submitted_project_root)) = grant_resolution {
        let pending_matches_session =
            app.pending_ssh_project_open
                .as_ref()
                .is_some_and(|project| {
                    event_session_id.as_deref().is_none_or(|session_id| {
                        session_id == project.project_session_id
                    })
                });
        if !approved {
            if pending_matches_session {
                app.pending_ssh_project_open = None;
            }
        } else if let (Some(binding), Some(submitted_project_root)) =
            (binding, submitted_project_root)
        {
            let project = pending_project.as_ref().filter(|project| {
                binding.session_id == project.project_session_id
                    && binding.target_id == project.target_id
            });
            if let Some(project) = project {
                let target_id = project.target_id.clone();
                let project_session_id = project.project_session_id.clone();
                app.pending_ssh_project_open = None;
                // The binding root is authoritative: the worker may have canonicalized the
                // user-approved raw path. The retained request id/session/target and submitted
                // raw root above prove this resolution belongs to the pending CLI open.
                let root = binding.root.clone();
                tracing::debug!(
                    target_id,
                    requested_root = %project.root,
                    submitted_root = %submitted_project_root,
                    canonical_binding_root = %root,
                    "opening SSH project from resolved worker binding"
                );
                // The Welcome-only consent card no longer owns any operation after its exact
                // binding has been accepted; dropping it avoids a stale overlay over the project.
                app.welcome_ssh_manager = None;
                return dispatch_inherited_ssh_project(
                    app,
                    target_id,
                    root,
                    project_session_id,
                    binding.id,
                );
            }
        }
    }
    vec![
        Effect::SshAwaitEvent {
            client_id,
            session_id,
        },
        Effect::SshListTargets {
            session_id: event_session_id,
            client_id,
        },
    ]
}

/// Route input to the local SSH modal while it is displayed on Welcome.
pub(crate) fn handle_welcome_ssh_input(
    app: &mut AppView,
    event: &crossterm::event::Event,
) -> InputOutcome {
    let outcome = {
        let Some(state) = app.welcome_ssh_manager.as_mut() else {
            return InputOutcome::Unchanged;
        };
        match event {
            crossterm::event::Event::Key(key) => {
                crate::views::ssh_modal::handle_ssh_key(state, key)
            }
            crossterm::event::Event::Mouse(mouse) => {
                crate::views::ssh_modal::handle_ssh_mouse(state, mouse)
            }
            crossterm::event::Event::Paste(text) => {
                crate::views::ssh_modal::handle_ssh_paste(state, text)
            }
            _ => return InputOutcome::Unchanged,
        }
    };
    if matches!(outcome, SshModalOutcome::Close) {
        app.welcome_ssh_manager = None;
        InputOutcome::Changed
    } else {
        map_ssh_modal_outcome(outcome)
    }
}
