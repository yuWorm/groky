//! Local-only SSH manager dispatch and Welcome-screen input routing.

use super::ctx::{
    SwitchCause, active_agent_session_id, get_active_agent_mut, show_welcome, switch_to_agent,
};
use crate::app::actions::{Action, Effect, SshGrantReplyKind, SshManagerOwner};
use crate::app::app_view::{AppView, InputOutcome};
use crate::views::ssh_modal::SshModalOutcome;

fn map_ssh_modal_outcome(outcome: SshModalOutcome) -> InputOutcome {
    match outcome {
        SshModalOutcome::Close => InputOutcome::Unchanged,
        SshModalOutcome::Changed => InputOutcome::Changed,
        SshModalOutcome::Unchanged => InputOutcome::Unchanged,
        SshModalOutcome::Refresh => InputOutcome::Action(Action::RefreshSshTargets),
        SshModalOutcome::AddTarget {
            draft,
            submission_id,
        } => InputOutcome::Action(Action::AddSshTarget {
            draft,
            submission_id,
        }),
        SshModalOutcome::UpdateTarget {
            expected,
            replacement,
            submission_id,
        } => InputOutcome::Action(Action::UpdateSshTarget {
            expected,
            replacement,
            submission_id,
        }),
        SshModalOutcome::RemoveTarget {
            expected,
            submission_id,
        } => InputOutcome::Action(Action::RemoveSshTarget {
            expected,
            submission_id,
        }),
        SshModalOutcome::SelectPromptTarget { target_id } => {
            InputOutcome::Action(Action::ChooseSshPromptTarget { target_id })
        }
        SshModalOutcome::Connect { target_id } => {
            InputOutcome::Action(Action::ConnectSshTarget { target_id })
        }
        SshModalOutcome::Disconnect { target_id } => {
            InputOutcome::Action(Action::DisconnectSshTarget { target_id })
        }
        SshModalOutcome::BrowseProjectDirectory { request_id, target_id, path } =>
            InputOutcome::Action(Action::BrowseSshProjectDirectory { request_id, target_id, path }),
        SshModalOutcome::ChooseProjectDirectory { request_id, target_id, root, identity } =>
            InputOutcome::Action(Action::ChooseSshProjectDirectory { request_id, target_id, root, identity }),
        SshModalOutcome::CancelProjectOpen { request_id } =>
            InputOutcome::Action(Action::CancelSshProjectOpen { request_id }),
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
        SshModalOutcome::CancelGrant { request_id } => {
            InputOutcome::Action(Action::CancelSshGrant { request_id })
        }
        SshModalOutcome::InspectGrantTarget {
            request_id,
            target_id,
            selected_root,
            expected_identity,
        } => InputOutcome::Action(Action::InspectSshGrantTarget {
            request_id,
            target_id,
            selected_root,
            expected_identity,
        }),
        SshModalOutcome::UseBinding { binding_id } => {
            InputOutcome::Action(Action::UseSshBinding { binding_id })
        }
        SshModalOutcome::RevokeBinding { binding_id } => {
            InputOutcome::Action(Action::RevokeSshBinding { binding_id })
        }
        SshModalOutcome::ApproveOperation {
            approval_id,
            approved,
            scope,
        } => InputOutcome::Action(Action::ApproveSshOperation {
            approval_id,
            approved,
            scope,
        }),
        SshModalOutcome::ResetOperationApprovals { binding_id } =>
            InputOutcome::Action(Action::ResetSshOperationApprovals { binding_id }),
        SshModalOutcome::ApproveWorkerInstall {
            request_id,
            session_id,
            binding_id,
            approved,
        } => InputOutcome::Action(Action::ApproveSshWorkerInstall {
            request_id,
            session_id,
            binding_id,
            approved,
        }),
        SshModalOutcome::AnswerAuthentication {
            challenge_id,
            connection_generation,
            target_id,
            host_key_decision,
            remember,
            secret,
            answers,
        } => InputOutcome::Action(Action::SubmitSshAuthentication {
            challenge_id,
            connection_generation,
            target_id,
            host_key_decision,
            remember,
            secret,
            answers,
        }),
    }
}

fn active_session_id(app: &AppView) -> Option<String> {
    active_agent_session_id(app).map(|session_id| session_id.to_string())
}

/// Capture the currently visible SSH manager's stable identity for an asynchronous request.
///
/// A completion must use this exact owner rather than the active view when it returns: the user
/// may switch sessions, dismiss the overlay, or open a replacement manager before then.
pub(super) fn ssh_manager_owner(app: &AppView) -> Option<SshManagerOwner> {
    if let crate::app::app_view::ActiveView::Agent(agent_id) = app.active_view
        && let Some(manager) = app
            .agents
            .get(&agent_id)
            .and_then(|agent| agent.ssh_manager.as_ref())
    {
        return Some(SshManagerOwner {
            agent_id: Some(agent_id),
            instance_id: manager.instance_id(),
        });
    }
    app.welcome_ssh_manager
        .as_ref()
        .map(|manager| SshManagerOwner {
            agent_id: None,
            instance_id: manager.instance_id(),
        })
}

/// Find the exact visible manager that initiated an asynchronous request. This deliberately
/// never constructs an overlay: a late completion cannot reopen a manager the user dismissed.
pub(super) fn ssh_manager_for_owner_mut(
    app: &mut AppView,
    owner: SshManagerOwner,
) -> Option<&mut crate::views::ssh_modal::SshManagerState> {
    let manager = match owner.agent_id {
        Some(agent_id) => app
            .agents
            .get_mut(&agent_id)
            .and_then(|agent| agent.ssh_manager.as_mut()),
        None => app.welcome_ssh_manager.as_mut(),
    }?;
    (manager.instance_id() == owner.instance_id).then_some(manager)
}

/// Capture an exact owner for an already-present manager associated with `session_id`.
///
/// This is only used after an unsolicited global control event has deliberately materialized an
/// approval surface. Ordinary async completions carry their initiating owner directly.
pub(super) fn ssh_manager_owner_for_session(
    app: &AppView,
    session_id: Option<&str>,
) -> Option<SshManagerOwner> {
    if app
        .welcome_ssh_manager
        .as_ref()
        .is_some_and(|manager| manager.session_id.as_deref() == session_id)
    {
        return app
            .welcome_ssh_manager
            .as_ref()
            .map(|manager| SshManagerOwner {
                agent_id: None,
                instance_id: manager.instance_id(),
            });
    }
    app.agents.iter().find_map(|(agent_id, agent)| {
        agent
            .ssh_manager
            .as_ref()
            .filter(|manager| manager.session_id.as_deref() == session_id)
            .map(|manager| SshManagerOwner {
                agent_id: Some(*agent_id),
                instance_id: manager.instance_id(),
            })
    })
}

fn ssh_manager_owner_for_authentication(app: &AppView, target_id: &str) -> Option<SshManagerOwner> {
    if let Some(manager) = app.welcome_ssh_manager.as_ref()
        && manager.pending_authentication_target_id() == Some(target_id)
    {
        return Some(SshManagerOwner { agent_id: None, instance_id: manager.instance_id() });
    }
    app.agents.iter().find_map(|(agent_id, agent)| {
        agent.ssh_manager.as_ref().filter(|manager| {
            manager.pending_authentication_target_id() == Some(target_id)
        }).map(|manager| SshManagerOwner {
            agent_id: Some(*agent_id), instance_id: manager.instance_id(),
        })
    })
}

/// Find the exact manager entitled to answer a managed-worker fallback without creating an
/// overlay. A child bootstrap may be active while its initiating manager belongs to a hidden
/// source session; ordinary session prompts remain on their own manager.
fn worker_install_owner_for_request(
    app: &AppView,
    session_id: &str,
    binding_id: &str,
    target_id: &str,
) -> Option<SshManagerOwner> {
    if let Some(owner) = app.agents.values().find_map(|agent| {
        (agent.ssh_project_open_session_id.as_deref() == Some(session_id)
            && agent.ssh_project_binding_id.as_deref() == Some(binding_id)
            && agent
                .ssh_project_location
                .as_ref()
                .is_some_and(|location| location.target_id.as_str() == target_id))
        .then_some(agent.ssh_project_open_owner)
        .flatten()
    }) {
        return Some(owner);
    }
    app.agents.iter().find_map(|(agent_id, agent)| {
        let manager = agent.ssh_manager.as_ref()?;
        (agent
            .session
            .session_id
            .as_ref()
            .is_some_and(|candidate| candidate.0.as_ref() == session_id)
            && agent.ssh_project_binding_id.as_deref() == Some(binding_id)
            && agent
                .ssh_project_location
                .as_ref()
                .is_some_and(|location| location.target_id.as_str() == target_id)
            && manager.session_id.as_deref() == Some(session_id))
        .then_some(SshManagerOwner {
            agent_id: Some(*agent_id),
            instance_id: manager.instance_id(),
        })
    })
}

/// Surface a bootstrap fallback on its existing source only when the still-active child is the
/// one that originated it. A user who has moved to any other session keeps that selection.
fn focus_worker_install_source_from_active_child(
    app: &mut AppView,
    owner: SshManagerOwner,
    session_id: &str,
    binding_id: &str,
    target_id: &str,
) {
    let crate::app::app_view::ActiveView::Agent(child_id) = app.active_view else {
        return;
    };
    let child_matches = app.agents.get(&child_id).is_some_and(|agent| {
        agent.ssh_project_open_owner == Some(owner)
            && agent.ssh_project_open_session_id.as_deref() == Some(session_id)
            && agent.ssh_project_binding_id.as_deref() == Some(binding_id)
            && agent
                .ssh_project_location
                .as_ref()
                .is_some_and(|location| location.target_id.as_str() == target_id)
    });
    if !child_matches {
        return;
    }
    match owner.agent_id {
        Some(source_id)
            if app.agents.get(&source_id).is_some_and(|agent| {
                agent
                    .ssh_manager
                    .as_ref()
                    .is_some_and(|manager| manager.instance_id() == owner.instance_id)
            }) =>
        {
            switch_to_agent(app, source_id, SwitchCause::Picker);
        }
        None if app
            .welcome_ssh_manager
            .as_ref()
            .is_some_and(|manager| manager.instance_id() == owner.instance_id) =>
        {
            show_welcome(app);
        }
        Some(_) | None => {}
    }
}

enum ResumeWorkerInstallRoute {
    NotPending,
    Displayed(SshManagerOwner),
    ClosedOrReplaced,
}

fn resume_install_matches_request(
    install: &crate::app::agent_view::SshProjectResumeInstall,
    request: &xai_grok_shell::ssh::SshWorkerInstallRequest,
) -> bool {
    install.client_id == request.client_id
        && install.request_id == request.request_id
        && install.session_id == request.session_id
        && install.binding_id == request.binding_id
        && install.target_id == request.target_id
}

/// The load placeholder has not received remote location metadata yet, so this is the sole
/// narrow exception that may materialize a manager from a worker event. Its explicit-load marker,
/// session id, and replay placeholder make the event trustworthy; subsequent/late events reuse
/// only the exact transient owner and can never recreate a dismissed replacement.
fn show_resumed_worker_install_fallback(
    app: &mut AppView,
    request: &xai_grok_shell::ssh::SshWorkerInstallRequest,
) -> ResumeWorkerInstallRoute {
    let Some(agent_id) = app.agents.iter().find_map(|(agent_id, agent)| {
        (agent.ssh_project_resume_pending_session_id.as_deref() == Some(request.session_id.as_str())
            && agent.session.loading_replay
            && agent.loading_placeholder_id.is_some()
            && agent
                .session
                .session_id
                .as_ref()
                .is_some_and(|session_id| session_id.0.as_ref() == request.session_id.as_str()))
        .then_some(*agent_id)
    }) else {
        return if app.agents.values().any(|agent| {
            agent
                .ssh_project_resume_install
                .as_ref()
                .is_some_and(|install| resume_install_matches_request(install, request))
        }) {
            ResumeWorkerInstallRoute::ClosedOrReplaced
        } else {
            ResumeWorkerInstallRoute::NotPending
        };
    };

    if let Some(existing) = app
        .agents
        .get(&agent_id)
        .and_then(|agent| agent.ssh_project_resume_install.as_ref())
    {
        let owner = existing.owner;
        let request_matches = resume_install_matches_request(existing, request);
        let owner_is_current = app.agents.get(&agent_id).is_some_and(|agent| {
            agent
                .ssh_manager
                .as_ref()
                .is_some_and(|manager| manager.instance_id() == owner.instance_id)
        });
        return if request_matches && owner_is_current {
            ResumeWorkerInstallRoute::Displayed(owner)
        } else {
            ResumeWorkerInstallRoute::ClosedOrReplaced
        };
    }

    let Some(agent) = app.agents.get_mut(&agent_id) else {
        return ResumeWorkerInstallRoute::ClosedOrReplaced;
    };
    if agent.ssh_manager.is_none() {
        agent.ssh_manager = Some(crate::views::ssh_modal::SshManagerState::new(Some(
            request.session_id.clone(),
        )));
    }
    let Some(manager) = agent.ssh_manager.as_mut() else {
        return ResumeWorkerInstallRoute::ClosedOrReplaced;
    };
    if manager.session_id.as_deref() != Some(request.session_id.as_str()) {
        return ResumeWorkerInstallRoute::ClosedOrReplaced;
    }
    manager.show_worker_install_fallback(request.clone());
    let owner = SshManagerOwner {
        agent_id: Some(agent_id),
        instance_id: manager.instance_id(),
    };
    agent.ssh_project_resume_install =
        Some(crate::app::agent_view::SshProjectResumeInstall {
            client_id: request.client_id,
            request_id: request.request_id.clone(),
            session_id: request.session_id.clone(),
            binding_id: request.binding_id.clone(),
            target_id: request.target_id.clone(),
            owner,
        });
    ResumeWorkerInstallRoute::Displayed(owner)
}

fn resumed_worker_install_owner(
    app: &AppView,
    client_id: u64,
    request_id: &str,
    session_id: &str,
    binding_id: &str,
    target_id: &str,
) -> Option<SshManagerOwner> {
    app.agents.values().find_map(|agent| {
        let install = agent.ssh_project_resume_install.as_ref()?;
        (install.client_id == client_id
            && install.request_id == request_id
            && install.session_id == session_id
            && install.binding_id == binding_id
            && install.target_id == target_id
            && agent
                .ssh_manager
                .as_ref()
                .is_some_and(|manager| manager.instance_id() == install.owner.instance_id))
        .then_some(install.owner)
    })
}

fn has_recorded_resumed_worker_install(
    app: &AppView,
    client_id: u64,
    request_id: &str,
    session_id: &str,
    binding_id: &str,
    target_id: &str,
) -> bool {
    app.agents.values().any(|agent| {
        agent.ssh_project_resume_install.as_ref().is_some_and(|install| {
            install.client_id == client_id
                && install.request_id == request_id
                && install.session_id == session_id
                && install.binding_id == binding_id
                && install.target_id == target_id
        })
    })
}

/// Dismiss precisely the manager instance that produced a transient approval.
///
/// Unlike session lookup, this cannot close a manager reopened while the decision was in flight.
/// A retained root authorization keeps only its exact sudo correlation when the visible surface
/// is dismissed, so a later password prompt cannot be lost.
pub(super) fn close_ssh_manager_for_owner(app: &mut AppView, owner: SshManagerOwner) {
    match owner.agent_id {
        Some(agent_id) => {
            let Some(agent) = app.agents.get_mut(&agent_id) else {
                return;
            };
            if !agent
                .ssh_manager
                .as_ref()
                .is_some_and(|manager| manager.instance_id() == owner.instance_id)
            {
                return;
            }
            if agent
                .ssh_manager
                .as_mut()
                .is_some_and(|manager| manager.hide_if_waiting_for_sudo())
            {
                return;
            }
            agent.ssh_manager = None;
        }
        None => {
            if !app
                .welcome_ssh_manager
                .as_ref()
                .is_some_and(|manager| manager.instance_id() == owner.instance_id)
            {
                return;
            }
            if app
                .welcome_ssh_manager
                .as_mut()
                .is_some_and(|manager| manager.hide_if_waiting_for_sudo())
            {
                return;
            }
            app.welcome_ssh_manager = None;
        }
    }
}

const DIRECT_SSH_GRANT_REPLY_CAP: usize = 32;

fn remember_direct_ssh_grant_reply(app: &mut AppView, request_id: &str, kind: SshGrantReplyKind) {
    if app
        .direct_ssh_grant_replies
        .iter()
        .any(|(seen, phase)| seen == request_id && *phase == kind)
    {
        return;
    }
    app.direct_ssh_grant_replies
        .push_back((request_id.to_owned(), kind));
    while app.direct_ssh_grant_replies.len() > DIRECT_SSH_GRANT_REPLY_CAP {
        app.direct_ssh_grant_replies.pop_front();
    }
}

fn is_direct_ssh_grant_reply(app: &AppView, request_id: &str, kind: SshGrantReplyKind) -> bool {
    app.direct_ssh_grant_replies
        .iter()
        .any(|(seen, phase)| seen == request_id && *phase == kind)
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
            if app
                .agents
                .get(&agent_id)
                .is_some_and(|agent| active_worktree_child_matches_session(agent, session_id)) =>
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

pub(super) fn dispatch_open_ssh_manager(app: &mut AppView) -> Vec<Effect> {
    open_ssh_surface(app, false)
}

pub(super) fn dispatch_open_ssh_target_picker(app: &mut AppView) -> Vec<Effect> {
    open_ssh_surface(app, true)
}

fn new_ssh_surface_state(
    for_prompt: bool,
    session_id: Option<String>,
) -> crate::views::ssh_modal::SshManagerState {
    if for_prompt {
        crate::views::ssh_modal::SshManagerState::for_prompt(session_id)
    } else {
        crate::views::ssh_modal::SshManagerState::new(session_id)
    }
}

fn open_ssh_surface(app: &mut AppView, for_prompt: bool) -> Vec<Effect> {
    let session_id = active_session_id(app);
    if let Some(agent) = get_active_agent_mut(app) {
        if let Some(manager) = agent.ssh_manager.as_mut().filter(|manager| !manager.is_visible()) {
            manager.reopen(for_prompt);
        } else {
            agent.ssh_manager = Some(new_ssh_surface_state(for_prompt, session_id.clone()));
        }
    } else if let Some(manager) = app
        .welcome_ssh_manager
        .as_mut()
        .filter(|manager| !manager.is_visible())
    {
        manager.reopen(for_prompt);
    } else {
        app.welcome_ssh_manager = Some(new_ssh_surface_state(for_prompt, session_id.clone()));
    }
    let owner = ssh_manager_owner(app).expect("the SSH manager was just installed");
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
        owner,
    });
    effects
}

pub(super) fn dispatch_select_ssh_target(app: &mut AppView, reference: String) -> Vec<Effect> {
    let effects = dispatch_open_ssh_target_picker(app);
    if let Some(owner) = ssh_manager_owner(app)
        && let Some(manager) = ssh_manager_for_owner_mut(app, owner)
    {
        manager.queue_target_reference(reference);
    }
    effects
}

pub(super) fn dispatch_choose_ssh_prompt_target(
    app: &mut AppView,
    target_id: String,
) -> Vec<Effect> {
    if let Some(owner) = ssh_manager_owner(app) {
        choose_ssh_prompt_target_for_owner(app, owner, &target_id);
    }
    vec![]
}

/// Selecting a target changes only the exact originating draft. It never grants access,
/// queues a prompt, switches sessions, or resurrects a closed picker.
pub(super) fn choose_ssh_prompt_target_for_owner(
    app: &mut AppView,
    owner: SshManagerOwner,
    target_id: &str,
) {
    let Some(manager) = ssh_manager_for_owner_mut(app, owner) else {
        return;
    };
    if !manager.is_prompt_picker() {
        return;
    }
    let Some(target) = manager.targets.iter().find(|target| {
        target.target_id == target_id && target.connected
    }) else {
        return;
    };
    let label = target.label.clone();
    let address = target.effective_address.clone();
    let session_id = manager.session_id.clone();
    match owner.agent_id {
        Some(agent_id) => {
            let Some(agent) = app.agents.get_mut(&agent_id) else { return };
            if agent.session.session_id.as_ref().map(|id| id.0.as_ref())
                != session_id.as_deref()
            {
                return;
            }
            agent.prompt.set_ssh_target_context(target_id, &label, &address);
        }
        None => {
            let Some(dashboard) = app.dashboard.as_mut() else { return };
            dashboard.dispatch.set_ssh_target_context(target_id, &label, &address);
        }
    }
    close_ssh_manager_for_owner(app, owner);
}

/// CLI and interactive entry share the same correlated project preparation and consent.
pub(super) fn dispatch_begin_ssh_project_open(
    app: &mut AppView,
    project: crate::app::cli::SshProjectOpen,
) -> Vec<Effect> {
    let mut effects = dispatch_open_ssh_manager(app);
    let Some(owner) = ssh_manager_owner(app) else { return effects };
    let Some(manager) = ssh_manager_for_owner_mut(app, owner) else { return effects };
    let SshModalOutcome::BrowseProjectDirectory { request_id, .. } =
        manager.begin_project_browser(project.target_id.clone(), Some(project.root.clone()))
    else { return effects };
    let source_session_id = manager.session_id.clone();
    if manager.begin_project_preparation(
        request_id, project.project_session_id.clone(), project.target_id.clone(), project.root.clone(),
    ) {
        effects.push(Effect::SshPrepareProjectOpen {
            request_id,
            project_session_id: project.project_session_id,
            source_session_id,
            target_id: project.target_id,
            root: project.root,
            expected_identity: project.expected_identity,
            client_id: app.ssh_client_id,
            owner,
        });
    }
    effects
}

pub(super) fn dispatch_browse_ssh_project_directory(
    app: &mut AppView, request_id: u64, target_id: String, path: Option<String>,
) -> Vec<Effect> {
    let Some(owner) = ssh_manager_owner(app) else { return vec![] };
    if !ssh_manager_for_owner_mut(app, owner)
        .is_some_and(|manager| manager.project_directory_request_matches(request_id, &target_id))
    { return vec![]; }
    vec![Effect::SshBrowseProjectDirectory {
        request_id, target_id, path, client_id: app.ssh_client_id, owner,
    }]
}

pub(super) fn dispatch_choose_ssh_project_directory(
    app: &mut AppView, request_id: u64, target_id: String, root: String,
    identity: xai_grok_shell::ssh::SshHostIdentity,
) -> Vec<Effect> {
    let Some(owner) = ssh_manager_owner(app) else { return vec![] };
    let Some(manager) = ssh_manager_for_owner_mut(app, owner) else { return vec![] };
    let project_session_id = uuid::Uuid::new_v4().to_string();
    let source_session_id = manager.session_id.clone();
    if !manager.project_directory_request_matches(request_id, &target_id)
        || !manager.begin_project_preparation(
            request_id, project_session_id.clone(), target_id.clone(), root.clone(),
        )
    { return vec![]; }
    vec![Effect::SshPrepareProjectOpen {
        request_id, project_session_id, source_session_id, target_id, root,
        expected_identity: Some(identity), client_id: app.ssh_client_id, owner,
    }]
}

pub(super) fn dispatch_cancel_ssh_project_open(app: &mut AppView, request_id: u64) -> Vec<Effect> {
    if let Some(owner) = ssh_manager_owner(app)
        && let Some(manager) = ssh_manager_for_owner_mut(app, owner)
    {
        manager.finish_project_preparation(request_id, None);
    }
    vec![]
}

pub(super) fn apply_ssh_project_prepared(
    app: &mut AppView, owner: SshManagerOwner, request_id: u64,
    target_id: String, project_session_id: String,
    result: Result<xai_grok_shell::ssh::SshProjectPreparation, String>,
) -> Vec<Effect> {
    use xai_grok_shell::ssh::SshProjectPreparation;
    if app.agents.values().any(|agent| {
        agent.ssh_project_open_owner == Some(owner)
            && agent.ssh_project_open_session_id.as_deref() == Some(project_session_id.as_str())
    }) {
        return vec![];
    }
    let matches = ssh_manager_for_owner_mut(app, owner).is_some_and(|manager| {
        manager.pending_project_request_id() == Some(request_id)
            && manager.pending_project_open_tuple().is_some_and(|(session, target, _)| {
                session == project_session_id && target == target_id
            })
    });
    if !matches {
        return match result {
            Ok(SshProjectPreparation::NeedsApproval(request)) => vec![Effect::SshRejectProjectGrant {
                request_id: request.id, client_id: app.ssh_client_id,
            }],
            _ => vec![],
        };
    }
    match result {
        Ok(SshProjectPreparation::Ready(binding))
            if binding.session_id == project_session_id && binding.target_id == target_id =>
        {
            dispatch_inherited_ssh_project(
                app, target_id, binding.root, project_session_id, binding.id, Some(owner),
            )
        }
        Ok(SshProjectPreparation::NeedsApproval(request))
            if request.session_id == project_session_id
                && request.target_id.as_deref() == Some(target_id.as_str())
                && request.client_id == Some(app.ssh_client_id) =>
        {
            remember_direct_ssh_grant_reply(app, &request.id, SshGrantReplyKind::Requested);
            let grant_request_id = request.id.clone();
            let shown = ssh_manager_for_owner_mut(app, owner).is_some_and(|manager| {
                manager.show_project_consent(request_id, incoming_grant(request), project_session_id)
            });
            if shown {
                vec![]
            } else {
                if let Some(manager) = ssh_manager_for_owner_mut(app, owner) {
                    manager.finish_project_preparation(request_id, Some(
                        "SSH project consent no longer matches the active folder selection.".into(),
                    ));
                }
                vec![Effect::SshRejectProjectGrant {
                    request_id: grant_request_id, client_id: app.ssh_client_id,
                }]
            }
        }
        other => {
            let error = match other {
                Err(error) => error,
                _ => "SSH service returned a project belonging to a different request.".into(),
            };
            if let Some(manager) = ssh_manager_for_owner_mut(app, owner) {
                manager.finish_project_preparation(request_id, Some(error));
            }
            vec![]
        }
    }
}

fn incoming_grant(request: xai_grok_shell::ssh::SshGrantRequest)
    -> crate::views::ssh_modal::SshIncomingGrant
{
    crate::views::ssh_modal::SshIncomingGrant {
        request_id: request.id,
        target_id: request.target_id,
        root: request.root,
        capabilities: crate::views::ssh_modal::SshCapabilitiesView {
            read: request.capabilities.read,
            write: request.capabilities.write,
            execute: request.capabilities.execute,
        },
        verified_identity: request.verified_identity.map(|identity| format!(
            "{}@{}:{} ({})", identity.username, identity.hostname, identity.port, identity.fingerprint,
        )),
        reason: request.reason,
        awaiting_tool: request.awaiting_tool,
    }
}

pub(super) fn dispatch_refresh_ssh_targets(app: &mut AppView) -> Vec<Effect> {
    let client_id = app.ssh_client_id;
    let Some(owner) = ssh_manager_owner(app) else {
        return vec![];
    };
    let Some(manager) = ssh_manager_for_owner_mut(app, owner) else {
        return vec![];
    };
    vec![Effect::SshListTargets {
        session_id: manager.session_id.clone(),
        client_id,
        owner,
    }]
}

pub(super) fn dispatch_add_ssh_target(
    app: &mut AppView,
    draft: crate::views::ssh_modal::SshManualTargetDraft,
    submission_id: u64,
) -> Vec<Effect> {
    let client_id = app.ssh_client_id;
    let Some(owner) = ssh_manager_owner(app) else {
        return vec![];
    };
    let Some(manager) = ssh_manager_for_owner_mut(app, owner) else {
        return vec![];
    };
    vec![Effect::SshAddTarget {
        session_id: manager.session_id.clone(),
        client_id,
        submission_id,
        owner,
        draft,
    }]
}

pub(super) fn dispatch_update_ssh_target(
    app: &mut AppView,
    expected: xai_grok_ssh::SshTarget,
    replacement: xai_grok_ssh::SshTarget,
    submission_id: u64,
) -> Vec<Effect> {
    let client_id = app.ssh_client_id;
    let Some(owner) = ssh_manager_owner(app) else {
        return vec![];
    };
    let Some(manager) = ssh_manager_for_owner_mut(app, owner) else {
        return vec![];
    };
    if manager.target_update_submission_id() != Some(submission_id) {
        return vec![];
    }
    vec![Effect::SshUpdateTarget {
        session_id: manager.session_id.clone(),
        client_id,
        submission_id,
        owner,
        expected,
        replacement,
    }]
}

pub(super) fn dispatch_remove_ssh_target(
    app: &mut AppView,
    expected: xai_grok_ssh::SshTarget,
    submission_id: u64,
) -> Vec<Effect> {
    let client_id = app.ssh_client_id;
    let Some(owner) = ssh_manager_owner(app) else {
        return vec![];
    };
    let Some(manager) = ssh_manager_for_owner_mut(app, owner) else {
        return vec![];
    };
    if manager.target_remove_submission_id() != Some(submission_id) {
        return vec![];
    }
    vec![Effect::SshRemoveTarget {
        session_id: manager.session_id.clone(),
        client_id,
        submission_id,
        owner,
        expected,
    }]
}

pub(super) fn dispatch_connect_ssh_target(app: &mut AppView, target_id: String) -> Vec<Effect> {
    let client_id = app.ssh_client_id;
    let Some(owner) = ssh_manager_owner(app) else {
        return vec![];
    };
    let Some(manager) = ssh_manager_for_owner_mut(app, owner) else {
        return vec![];
    };
    manager.begin_connection_action(&target_id, true);
    vec![Effect::SshConnect {
        session_id: manager.session_id.clone(),
        target_id,
        client_id,
        owner,
    }]
}

pub(super) fn dispatch_disconnect_ssh_target(app: &mut AppView, target_id: String) -> Vec<Effect> {
    let client_id = app.ssh_client_id;
    let Some(owner) = ssh_manager_owner(app) else {
        return vec![];
    };
    let Some(manager) = ssh_manager_for_owner_mut(app, owner) else {
        return vec![];
    };
    manager.begin_connection_action(&target_id, false);
    vec![Effect::SshDisconnect {
        session_id: manager.session_id.clone(),
        target_id,
        client_id,
        owner,
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
    let client_id = app.ssh_client_id;
    let Some(owner) = ssh_manager_owner(app) else {
        return vec![];
    };
    let Some(manager) = ssh_manager_for_owner_mut(app, owner) else {
        return vec![];
    };
    let Some(session_id) = manager.session_id.clone() else {
        manager.show_error("Open or create a session before granting SSH access.");
        return vec![];
    };
    manager.remember_local_grant_options(
        target_id.clone(),
        root.clone(),
        capabilities,
        lifetime,
        set_default,
    );
    vec![Effect::SshRequestGrant {
        session_id,
        client_id,
        owner,
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
    selected_root: Option<String>,
    expected_identity: Option<xai_grok_shell::ssh::SshHostIdentity>,
) -> Vec<Effect> {
    let client_id = app.ssh_client_id;
    let Some(owner) = ssh_manager_owner(app) else {
        return vec![];
    };
    let Some(manager) = ssh_manager_for_owner_mut(app, owner) else {
        return vec![];
    };
    manager.show_info("Authenticating the selected SSH target before access review…");
    let session_id = manager
        .grant_session_id_for(&request_id)
        .or_else(|| manager.session_id.clone());
    vec![Effect::SshInspectGrantTarget {
        session_id,
        request_id,
        target_id,
        selected_root,
        expected_identity,
        client_id,
        owner,
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
    let client_id = app.ssh_client_id;
    // `groky ssh open` and remote worktree resumes have intentionally not created their
    // pre-minted child ACP session yet. The displayed consent request, not the active source
    // project, is authoritative for the grant decision's session id.
    let Some(owner) = ssh_manager_owner(app) else {
        return vec![];
    };
    let Some(manager) = ssh_manager_for_owner_mut(app, owner) else {
        return vec![];
    };
    let session_id = manager
        .grant_session_id_for(&request_id)
        .or_else(|| manager.session_id.clone());
    let Some(session_id) = session_id else {
        manager.show_error("Open or create a session before granting SSH access.");
        return vec![];
    };
    if approved {
        let _ = manager.record_grant_approval(&request_id, target_id.as_deref(), root.as_deref());
    }
    vec![Effect::SshApproveGrant {
        session_id,
        request_id,
        client_id,
        owner,
        approved,
        target_id,
        root,
        capabilities,
        lifetime,
        set_default,
    }]
}

pub(super) fn dispatch_cancel_ssh_grant(
    app: &mut AppView,
    request_id: String,
) -> Vec<Effect> {
    let client_id = app.ssh_client_id;
    let Some(owner) = ssh_manager_owner(app) else {
        return vec![];
    };
    let Some(manager) = ssh_manager_for_owner_mut(app, owner) else {
        return vec![];
    };
    let Some(session_id) = manager.grant_session_id_for(&request_id) else {
        return vec![];
    };
    vec![Effect::SshCancelGrant {
        session_id,
        request_id,
        client_id,
        owner,
    }]
}

pub(super) fn dispatch_use_ssh_binding(app: &mut AppView, binding_id: String) -> Vec<Effect> {
    let client_id = app.ssh_client_id;
    let Some(owner) = ssh_manager_owner(app) else {
        return vec![];
    };
    let Some(manager) = ssh_manager_for_owner_mut(app, owner) else {
        return vec![];
    };
    let Some(session_id) = manager.session_id.clone() else {
        manager.show_error("Open or create a session before selecting an SSH default.");
        return vec![];
    };
    vec![Effect::SshUseBinding {
        session_id,
        binding_id,
        client_id,
        owner,
    }]
}

pub(super) fn dispatch_revoke_ssh_binding(app: &mut AppView, binding_id: String) -> Vec<Effect> {
    let client_id = app.ssh_client_id;
    let Some(owner) = ssh_manager_owner(app) else {
        return vec![];
    };
    let Some(manager) = ssh_manager_for_owner_mut(app, owner) else {
        return vec![];
    };
    let Some(session_id) = manager.session_id.clone() else {
        manager.show_error("Open or create a session before revoking SSH access.");
        return vec![];
    };
    vec![Effect::SshRevokeBinding {
        session_id,
        binding_id,
        client_id,
        owner,
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
    source_owner: Option<SshManagerOwner>,
) -> Vec<Effect> {
    let ssh_project_location = crate::app::agent_view::SshProjectLocation {
        target_id: target_id.clone(),
        root: root.clone(),
    };
    let start = match xai_grok_shell::project::SshProjectStart::new(
        target_id,
        root,
        Some(binding_id.clone()),
        Some(project_session_id.clone()),
    ) {
        Ok(start) => start,
        Err(error) => {
            if let Some(owner) = source_owner
                && let Some(manager) = ssh_manager_for_owner_mut(app, owner)
            {
                manager.settle_project_open();
                manager.show_error(error.to_string());
            }
            return vec![];
        }
    };
    let ssh_client_id = app.ssh_client_id;
    // Keep the initiating source visible through the install/consent phase. Besides making the
    // fallback actionable, this preserves the source in minimal mode.
    let (agent_id, mut effects) =
        super::session::lifecycle::dispatch_new_session_inner_with_id(app, None, true);
    let mut start = Some(start);
    if let Some(agent) = app.agents.get_mut(&agent_id) {
        agent.ssh_project_location = Some(ssh_project_location);
        agent.ssh_project_open_owner = source_owner;
        agent.ssh_project_open_session_id = Some(project_session_id);
        agent.ssh_project_binding_id = Some(binding_id);
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
    host_key_decision: Option<xai_grok_shell::ssh::SshHostKeyDecision>,
    remember: bool,
    secret: Option<crate::views::ssh_modal::SshSecret>,
    answers: Vec<crate::views::ssh_modal::SshSecret>,
) -> Vec<Effect> {
    let Some(owner) = ssh_manager_owner(app) else {
        return vec![];
    };
    vec![Effect::SshSubmitAuthentication {
        client_id: app.ssh_client_id,
        owner,
        challenge_id,
        connection_generation,
        host_key_decision,
        remember,
        secret,
        answers,
    }]
}

pub(super) fn dispatch_approve_ssh_operation(
    app: &mut AppView,
    approval_id: String,
    approved: bool,
    scope: xai_grok_shell::ssh::SshOperationApprovalScope,
) -> Vec<Effect> {
    let Some(owner) = ssh_manager_owner(app) else {
        return vec![];
    };
    let client_id = app.ssh_client_id;
    let Some(manager) = ssh_manager_for_owner_mut(app, owner) else {
        return vec![];
    };
    if !manager.submit_operation_approval(&approval_id, approved) {
        return vec![];
    }
    vec![Effect::SshApproveOperation {
        session_id: manager.session_id.clone(),
        client_id,
        owner,
        approval_id,
        approved,
        scope,
    }]
}

pub(super) fn dispatch_reset_ssh_operation_approvals(
    app: &mut AppView, binding_id: String,
) -> Vec<Effect> {
    let Some(owner) = ssh_manager_owner(app) else { return vec![] };
    let client_id = app.ssh_client_id;
    let Some(manager) = ssh_manager_for_owner_mut(app, owner) else { return vec![] };
    let Some(session_id) = manager.session_id.clone() else { return vec![] };
    vec![Effect::SshResetOperationApprovals { session_id, binding_id, client_id, owner }]
}

pub(super) fn dispatch_approve_ssh_worker_install(
    app: &mut AppView,
    request_id: String,
    session_id: String,
    binding_id: String,
    approved: bool,
) -> Vec<Effect> {
    let Some(owner) = ssh_manager_owner(app) else {
        return vec![];
    };
    let client_id = app.ssh_client_id;
    let Some(manager) = ssh_manager_for_owner_mut(app, owner) else {
        return vec![];
    };
    if !manager.submit_worker_install(client_id, &request_id, &session_id, &binding_id, approved) {
        return vec![];
    }
    vec![Effect::SshApproveWorkerInstall {
        client_id,
        owner,
        request_id,
        session_id,
        binding_id,
        approved,
    }]
}

/// Locate the visible manager that owns an in-flight grant. A remote worktree can request a
/// pre-minted child session before that child has an `AgentView`, so its consent remains on the
/// source project manager until the child binding is accepted.
fn manager_session_for_grant(app: &AppView, request_id: &str) -> Option<Option<String>> {
    if let Some(manager) = app
        .welcome_ssh_manager
        .as_ref()
        .filter(|manager| manager.grant_session_id_for(request_id).is_some())
    {
        return Some(manager.session_id.clone());
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
    agent
        .pending_fork_banner
        .as_ref()
        .is_some_and(|fork| fork.worktree && fork.parent_sid == source_session_id)
        || (agent.pending_worktree_source_session_id.as_deref() == Some(source_session_id)
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
        if let Some(fingerprint) = identity
            .get("fingerprint")
            .and_then(serde_json::Value::as_str)
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
    owner: Option<SshManagerOwner>,
    event: xai_grok_shell::ssh::SshEvent,
) -> Vec<Effect> {
    let client_id = app.ssh_client_id;
    let event_targets_this_client = match &event {
        xai_grok_shell::ssh::SshEvent::GrantRequested(request) => {
            request.client_id == Some(client_id)
        }
        xai_grok_shell::ssh::SshEvent::GrantCancelled {
            client_id: event_client_id,
            ..
        }
        | xai_grok_shell::ssh::SshEvent::GrantFailed {
            client_id: event_client_id,
            ..
        }
        | xai_grok_shell::ssh::SshEvent::OperationApprovalExpired {
            client_id: event_client_id,
            ..
        }
        | xai_grok_shell::ssh::SshEvent::SudoAuthenticationResolved {
            client_id: event_client_id,
            ..
        } => *event_client_id == client_id,
        xai_grok_shell::ssh::SshEvent::SudoAuthentication { prompt, .. } => {
            prompt.client_id == client_id
        }
        _ => true,
    };
    if !event_targets_this_client {
        return vec![Effect::SshAwaitEvent { client_id, session_id }];
    }
    let owner = match &event {
        xai_grok_shell::ssh::SshEvent::SudoAuthentication { session_id, .. }
        | xai_grok_shell::ssh::SshEvent::SudoAuthenticationResolved { session_id, .. } => {
            ssh_manager_owner_for_session(app, Some(session_id))
        }
        xai_grok_shell::ssh::SshEvent::Authentication(prompt) => owner
            .or_else(|| ssh_manager_owner_for_authentication(app, &prompt.target_id)),
        _ => owner,
    };
    match &event {
        xai_grok_shell::ssh::SshEvent::WorkerInstallRequested(request) => {
            let mut effects = vec![Effect::SshAwaitEvent {
                client_id,
                session_id,
            }];
            if request.client_id != client_id {
                return effects;
            }
            let displayed_owner = match show_resumed_worker_install_fallback(app, request) {
                ResumeWorkerInstallRoute::Displayed(owner) => Some(owner),
                ResumeWorkerInstallRoute::ClosedOrReplaced => None,
                ResumeWorkerInstallRoute::NotPending => {
                    worker_install_owner_for_request(
                        app,
                        &request.session_id,
                        &request.binding_id,
                        &request.target_id,
                    )
                    .and_then(|owner| {
                        ssh_manager_for_owner_mut(app, owner).map(|manager| {
                            manager.show_worker_install_fallback(request.clone());
                            owner
                        })
                    })
                }
            };
            if let Some(owner) = displayed_owner {
                focus_worker_install_source_from_active_child(
                    app,
                    owner,
                    &request.session_id,
                    &request.binding_id,
                    &request.target_id,
                );
            } else {
                effects.push(Effect::SshRejectWorkerInstall {
                    client_id,
                    request_id: request.request_id.clone(),
                    session_id: request.session_id.clone(),
                    binding_id: request.binding_id.clone(),
                });
            }
            return effects;
        }
        xai_grok_shell::ssh::SshEvent::WorkerInstallProgress(progress) => {
            if progress.client_id == client_id
                && let Some(owner) = resumed_worker_install_owner(
                    app,
                    progress.client_id,
                    &progress.request_id,
                    &progress.session_id,
                    &progress.binding_id,
                    &progress.target_id,
                )
                .or_else(|| {
                    (!has_recorded_resumed_worker_install(
                        app,
                        progress.client_id,
                        &progress.request_id,
                        &progress.session_id,
                        &progress.binding_id,
                        &progress.target_id,
                    ))
                    .then(|| {
                        worker_install_owner_for_request(
                            app,
                            &progress.session_id,
                            &progress.binding_id,
                            &progress.target_id,
                        )
                    })
                    .flatten()
                })
                && let Some(manager) = ssh_manager_for_owner_mut(app, owner)
            {
                manager.apply_worker_install_progress(
                    progress.client_id,
                    &progress.request_id,
                    &progress.session_id,
                    &progress.binding_id,
                    &progress.target_id,
                    progress.message.clone(),
                );
            }
            return vec![Effect::SshAwaitEvent {
                client_id,
                session_id,
            }];
        }
        _ => {}
    }
    let direct_grant_reply = match &event {
        xai_grok_shell::ssh::SshEvent::GrantRequested(request) =>
            Some((request.id.as_str(), SshGrantReplyKind::Requested)),
        xai_grok_shell::ssh::SshEvent::GrantResolved { request_id, .. } =>
            Some((request_id.as_str(), SshGrantReplyKind::Resolved)),
        xai_grok_shell::ssh::SshEvent::GrantCancelled { request_id, .. } =>
            Some((request_id.as_str(), SshGrantReplyKind::Cancelled)),
        xai_grok_shell::ssh::SshEvent::GrantFailed { request_id, .. } =>
            Some((request_id.as_str(), SshGrantReplyKind::Failed)),
        _ => None,
    };
    if let Some((request_id, kind)) = direct_grant_reply {
        if owner.is_some() {
            remember_direct_ssh_grant_reply(app, request_id, kind);
        } else if is_direct_ssh_grant_reply(app, request_id, kind) {
            return vec![Effect::SshAwaitEvent {
                client_id,
                session_id,
            }];
        }
    }
    let event_session_id = match &event {
        xai_grok_shell::ssh::SshEvent::GrantRequested(request) => Some(request.session_id.clone()),
        xai_grok_shell::ssh::SshEvent::GrantCancelled { session_id, .. }
        | xai_grok_shell::ssh::SshEvent::GrantFailed { session_id, .. }
        | xai_grok_shell::ssh::SshEvent::BindingRevoked { session_id, .. }
        | xai_grok_shell::ssh::SshEvent::OperationApprovalExpired { session_id, .. }
        | xai_grok_shell::ssh::SshEvent::SudoAuthentication { session_id, .. }
        | xai_grok_shell::ssh::SshEvent::SudoAuthenticationResolved { session_id, .. } => {
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
        xai_grok_shell::ssh::SshEvent::WorkerInstallRequested(request) => {
            Some(request.session_id.clone())
        }
        xai_grok_shell::ssh::SshEvent::WorkerInstallProgress(progress) => {
            Some(progress.session_id.clone())
        }
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
        xai_grok_shell::ssh::SshEvent::GrantResolved { request_id, .. }
        | xai_grok_shell::ssh::SshEvent::GrantCancelled { request_id, .. }
        | xai_grok_shell::ssh::SshEvent::GrantFailed { request_id, .. } => {
            manager_session_for_grant(app, request_id).unwrap_or_else(|| event_session_id.clone())
        }
        _ => event_session_id.clone(),
    };
    let resolution_owner = owner
        .or_else(|| ssh_manager_owner_for_session(app, manager_session_id.as_deref()));
    let mut grant_resolution = None;
    let mut dismiss_approved_grant_manager = false;
    let mut terminal_grant_failed = false;
    let mut project_resolution = None;
    let mut grant_follow_up = None;
    let mut grant_continuation = SshModalOutcome::Unchanged;
    let mut selected_prompt_target = None;
    let manager = match owner {
        Some(owner) => ssh_manager_for_owner_mut(app, owner),
        None => match &event {
            xai_grok_shell::ssh::SshEvent::TargetStatus(_)
            | xai_grok_shell::ssh::SshEvent::BindingRevoked { .. }
            | xai_grok_shell::ssh::SshEvent::GrantResolved { .. }
            | xai_grok_shell::ssh::SshEvent::GrantCancelled { .. }
            | xai_grok_shell::ssh::SshEvent::GrantFailed { .. }
            | xai_grok_shell::ssh::SshEvent::OperationApprovalExpired { .. }
            | xai_grok_shell::ssh::SshEvent::SudoAuthentication { .. }
            | xai_grok_shell::ssh::SshEvent::SudoAuthenticationResolved { .. } => {
                existing_ssh_manager_for_session_mut(app, manager_session_id.as_deref())
            }
            xai_grok_shell::ssh::SshEvent::GrantRequested(_)
            | xai_grok_shell::ssh::SshEvent::Authentication(_)
            | xai_grok_shell::ssh::SshEvent::OperationApproval(_) => {
                ssh_manager_for_session_mut(app, manager_session_id.as_deref())
            }
            xai_grok_shell::ssh::SshEvent::WorkerInstallRequested(_)
            | xai_grok_shell::ssh::SshEvent::WorkerInstallProgress(_)
            | xai_grok_shell::ssh::SshEvent::Worker(_) => None,
        },
    };
    if let Some(manager) = manager {
        match event {
            xai_grok_shell::ssh::SshEvent::GrantRequested(request) => {
                if request.client_id == Some(client_id) {
                    if owner.is_some() {
                        manager.bind_local_grant_request(
                            &request.id, request.target_id.as_deref(), request.root.as_deref(),
                        );
                    }
                    grant_continuation = manager.show_incoming_grant(
                        request.session_id.clone(), incoming_grant(request),
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
                let pending_project = manager.pending_project_open_tuple()
                    .map(|(session, target, root)| (session.to_owned(), target.to_owned(), root.to_owned()));
                let submitted_project_root = pending_project.as_ref().and_then(|(session, target, root)| {
                    manager.submitted_project_grant_root(&request_id, session, target, root)
                        .map(ToOwned::to_owned)
                });
                let matches_project = pending_project.as_ref().is_none_or(|(session, target, _)| {
                    event_session_id.as_deref().is_none_or(|receiver| receiver == session)
                        && (!approved || (submitted_project_root.is_some()
                            && binding.as_ref().is_some_and(|binding| {
                                &binding.session_id == session && &binding.target_id == target
                            })))
                });
                if owns_resolution && matches_project {
                    grant_follow_up = manager.take_grant_follow_up(&request_id);
                    if pending_project.is_some() {
                        project_resolution = manager.pending_project_request_id();
                    }
                    dismiss_approved_grant_manager = approved
                        && binding.is_some()
                        && pending_project.is_none()
                        && manager.current_grant_surface_matches(&request_id);
                    manager.settle_grant(approved);
                    if !approved
                        && let Some(request_id) = project_resolution
                    {
                        manager.finish_project_preparation(request_id, None);
                    }
                    grant_resolution = Some((approved, binding));
                } else if owns_resolution {
                    manager.show_error(
                        "Ignoring an SSH grant resolution that does not match the active project request.",
                    );
                }
            }
            xai_grok_shell::ssh::SshEvent::GrantCancelled {
                request_id,
                session_id: grant_session_id,
                client_id: grant_client_id,
            } => {
                if grant_client_id == client_id
                    && manager.grant_session_id_for(&request_id).as_deref()
                        == Some(grant_session_id.as_str())
                {
                    manager.settle_grant_cancellation(&request_id);
                }
            }
            xai_grok_shell::ssh::SshEvent::GrantFailed {
                request_id,
                session_id: grant_session_id,
                client_id: grant_client_id,
                error,
            } => {
                if grant_client_id == client_id
                    && manager.grant_session_id_for(&request_id).as_deref()
                        == Some(grant_session_id.as_str())
                    && manager.settle_grant_failure(&request_id, error)
                {
                    terminal_grant_failed = true;
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
                if prompt.client_id == client_id
                    && !matches!(
                        &prompt.kind,
                        xai_grok_shell::ssh::SshAuthPromptKind::SudoPassword
                    )
                {
                    match crate::app::ssh_control::authentication_card(prompt) {
                        Ok(card) => manager.show_authentication(card),
                        Err(error) => manager.show_error(error),
                    }
                }
            }
            xai_grok_shell::ssh::SshEvent::SudoAuthentication {
                session_id: sudo_session_id,
                operation_id,
                prompt,
            } => {
                if prompt.client_id == client_id
                    && manager.session_id.as_deref() == Some(sudo_session_id.as_str())
                    && let Ok(card) = crate::app::ssh_control::authentication_card(prompt)
                {
                    manager.show_sudo_authentication(
                        client_id,
                        &sudo_session_id,
                        &operation_id,
                        card,
                    );
                }
            }
            xai_grok_shell::ssh::SshEvent::SudoAuthenticationResolved {
                client_id: event_client_id,
                session_id: sudo_session_id,
                challenge_id,
                error,
            } => {
                if event_client_id == client_id {
                    manager.resolve_sudo_authentication(
                        event_client_id,
                        &sudo_session_id,
                        &challenge_id,
                        error,
                    );
                }
            }
            xai_grok_shell::ssh::SshEvent::OperationApproval(approval) => {
                if approval.client_id == client_id
                    && manager.session_id.as_deref() == Some(approval.session_id.as_str())
                {
                    let (target_label, target_identity) =
                        operation_approval_target(&approval.detail, &approval.binding_id, manager);
                    manager.show_operation_approval(
                        crate::views::ssh_modal::SshOperationApprovalCard::new(
                            approval.approval_id,
                            approval.binding_id,
                            target_label,
                            target_identity,
                            approval.title,
                            approval.detail,
                            approval.operation,
                        )
                        .with_allow_session(approval.allow_session)
                        .with_operation_id(approval.operation_id),
                    );
                }
            }
            xai_grok_shell::ssh::SshEvent::OperationApprovalExpired {
                client_id: event_client_id,
                session_id: expired_session_id,
                approval_id,
            } => {
                if event_client_id == client_id
                    && manager.session_id.as_deref() == Some(expired_session_id.as_str())
                {
                    manager.expire_operation_approval(&approval_id);
                }
            }
            xai_grok_shell::ssh::SshEvent::TargetStatus(status) => {
                manager.apply_target_status(&status.target_id, status.connection, status.detail);
                if owner.is_some()
                    && status.connection == xai_grok_shell::ssh::SshConnectionState::Connected
                {
                    selected_prompt_target =
                        manager.take_connected_prompt_target(&status.target_id);
                }
            }
            xai_grok_shell::ssh::SshEvent::WorkerInstallRequested(_)
            | xai_grok_shell::ssh::SshEvent::WorkerInstallProgress(_) => {
                unreachable!("worker install events were handled before manager routing")
            }
            xai_grok_shell::ssh::SshEvent::Worker(_) => {
                return vec![Effect::SshAwaitEvent {
                    client_id,
                    session_id,
                }];
            }
        }
    }
    if let (Some(owner), Some(target_id)) = (owner, selected_prompt_target) {
        choose_ssh_prompt_target_for_owner(app, owner, &target_id);
        return vec![Effect::SshAwaitEvent { client_id, session_id }];
    }
    if terminal_grant_failed {
        return vec![Effect::SshAwaitEvent { client_id, session_id }];
    }
    if let Some((true, Some(binding))) = grant_resolution {
        if project_resolution.is_some() {
            return dispatch_inherited_ssh_project(
                app, binding.target_id, binding.root, binding.session_id, binding.id, resolution_owner,
            );
        }
        if let Some(source_session_id) = manager_session_id.as_deref() {
            promote_worktree_child_session(app, source_session_id, &binding.session_id);
        }
        if matches!(grant_follow_up, Some(crate::views::ssh_modal::SshGrantFollowUp::UseBinding))
            && let Some(owner) = resolution_owner
        {
            let effects = vec![Effect::SshUseBinding {
                session_id: binding.session_id, binding_id: binding.id, client_id, owner,
            }];
            if dismiss_approved_grant_manager {
                close_ssh_manager_for_owner(app, owner);
            }
            return effects;
        }
    }
    if dismiss_approved_grant_manager
        && let Some(owner) = resolution_owner
    {
        close_ssh_manager_for_owner(app, owner);
        return vec![Effect::SshAwaitEvent { client_id, session_id }];
    }
    let refresh = owner
        .or_else(|| ssh_manager_owner_for_session(app, manager_session_id.as_deref()))
        .and_then(|owner| {
            ssh_manager_for_owner_mut(app, owner).map(|manager| (owner, manager.session_id.clone()))
        });
    let mut effects = vec![Effect::SshAwaitEvent {
        client_id,
        session_id,
    }];
    if let Some((owner, session_id)) = refresh {
        effects.push(Effect::SshListTargets {
            session_id,
            client_id,
            owner,
        });
        match grant_continuation {
            SshModalOutcome::BrowseProjectDirectory { request_id, target_id, path } => {
                effects.push(Effect::SshBrowseProjectDirectory {
                    request_id, target_id, path, client_id, owner,
                });
            }
            SshModalOutcome::InspectGrantTarget {
                request_id, target_id, selected_root, expected_identity,
            } => {
                effects.push(Effect::SshInspectGrantTarget {
                    session_id: event_session_id, request_id, target_id,
                    selected_root, expected_identity, client_id, owner,
                });
            }
            SshModalOutcome::ApproveGrant {
                request_id, approved: false, target_id, root, capabilities, lifetime, set_default,
            } => {
                if let Some(session_id) = event_session_id {
                    effects.push(Effect::SshApproveGrant {
                        session_id, request_id, approved: false, target_id, root,
                        capabilities, lifetime, set_default, client_id, owner,
                    });
                }
            }
            _ => {}
        }
    }
    effects
}

/// Route input to the local SSH modal while it is displayed on Welcome.
pub(crate) fn handle_welcome_ssh_input(
    app: &mut AppView,
    event: &crossterm::event::Event,
) -> InputOutcome {
    let outcome = {
        let Some(state) = app
            .welcome_ssh_manager
            .as_mut()
            .filter(|state| state.is_visible())
        else {
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
        if !app
            .welcome_ssh_manager
            .as_mut()
            .is_some_and(|manager| manager.hide_if_waiting_for_sudo())
        {
            app.welcome_ssh_manager = None;
        }
        InputOutcome::Changed
    } else {
        map_ssh_modal_outcome(outcome)
    }
}
