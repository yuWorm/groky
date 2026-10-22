//! Deterministic routing tests for the SSH project-grant correlation boundary.

use super::*;
use crate::app::app_view::InputOutcome;
use crate::app::cli::SshProjectOpen;
use crate::app::dispatch::session::lifecycle::handle_session_created;
use crate::app::dispatch::session::load::{
    dispatch_load_session, handle_session_load_failed, handle_session_loaded,
};
use crate::app::dispatch::ssh::{
    apply_ssh_control_event, close_ssh_manager_for_owner, dispatch_approve_ssh_grant,
    dispatch_begin_ssh_project_open, dispatch_inherited_ssh_project,
    existing_ssh_manager_for_session_mut, ssh_manager_for_session_mut, ssh_manager_owner,
};
use crate::views::ssh_modal::{SshGrantLifetime, SshModalOutcome, handle_ssh_key};
use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};
use xai_grok_shell::ssh::{
    SshBinding, SshCapabilities, SshEvent, SshGrantRequest, SshHostIdentity,
    SshWorkerInstallProgress, SshWorkerInstallRequest,
};

const SESSION_ID: &str = "project-session";
const TARGET_ID: &str = "fixture-worker";
const RAW_ROOT: &str = "/var/fixture/project";
const CANONICAL_ROOT: &str = "/private/var/fixture/project";

fn pending_project() -> SshProjectOpen {
    SshProjectOpen {
        target_id: TARGET_ID.into(),
        root: RAW_ROOT.into(),
        project_session_id: SESSION_ID.into(),
        expected_identity: None,
    }
}

fn grant_request(request_id: &str, target_id: &str, root: &str, client_id: u64) -> SshGrantRequest {
    SshGrantRequest {
        id: request_id.into(),
        session_id: SESSION_ID.into(),
        target_id: Some(target_id.into()),
        root: Some(root.into()),
        capabilities: SshCapabilities::all(),
        reason: "User requested a new local SSH project.".into(),
        verified_identity: Some(SshHostIdentity {
            hostname: "fixture-host".into(),
            port: 22,
            username: "fixture-user".into(),
            fingerprint: "SHA256:fixture".into(),
        }),
        client_id: Some(client_id),
        originating_session_id: None,
        awaiting_tool: false,
    }
}

fn binding(target_id: &str, root: &str) -> SshBinding {
    SshBinding {
        id: "binding-id".into(),
        session_id: SESSION_ID.into(),
        target_id: target_id.into(),
        identity: SshHostIdentity {
            hostname: "fixture-host".into(),
            port: 22,
            username: "fixture-user".into(),
            fingerprint: "SHA256:fixture".into(),
        },
        root: root.into(),
        cwd: root.into(),
        capabilities: SshCapabilities::all(),
        epoch: 1,
        revoked: false,
    }
}

fn begin_grant(app: &mut AppView, request_id: &str, target_id: &str, root: &str) {
    let effects = dispatch_begin_ssh_project_open(app, pending_project());
    let (flow_id, owner) = effects.iter().find_map(|effect| match effect {
        Effect::SshPrepareProjectOpen { request_id, owner, .. } => Some((*request_id, *owner)),
        _ => None,
    }).expect("CLI starts the same project preparation as the folder picker");
    let client_id = app.ssh_client_id;
    let _ = crate::app::dispatch::ssh::apply_ssh_project_prepared(
        app, owner, flow_id, TARGET_ID.into(), SESSION_ID.into(),
        Ok(xai_grok_shell::ssh::SshProjectPreparation::NeedsApproval(
            grant_request(request_id, target_id, root, client_id),
        )),
    );
}

fn approve(app: &mut AppView, request_id: &str, target_id: Option<&str>, root: Option<&str>) {
    let _ = dispatch_approve_ssh_grant(
        app,
        request_id.into(),
        true,
        target_id.map(str::to_owned),
        root.map(str::to_owned),
        None,
        SshGrantLifetime::CurrentSession,
        false,
    );
}

fn opened_project_root(effects: &[Effect]) -> Option<String> {
    effects.iter().find_map(|effect| match effect {
        Effect::OpenSshProject { start, .. } => Some(start.root().to_owned()),
        _ => None,
    })
}
#[test]
fn worktree_fork_routes_source_session_approval_to_active_child() {
    let mut app = test_app();
    let source_id = AgentId(0);
    let child_id = AgentId(1);
    let source = AgentView::new(
        make_test_agent_session(&app, source_id, SESSION_ID),
        ScrollbackState::new(),
    );
    let mut child = AgentView::new(
        make_test_agent_session(&app, child_id, "optimistic-worktree"),
        ScrollbackState::new(),
    );
    child.session.session_id = None;
    child.pending_fork_banner = Some(crate::app::agent_view::PendingForkBanner {
        parent_sid: SESSION_ID.into(),
        worktree: true,
    });
    app.agents.insert(source_id, source);
    app.agents.insert(child_id, child);
    app.active_view = ActiveView::Agent(child_id);

    let manager = ssh_manager_for_session_mut(&mut app, Some(SESSION_ID))
        .expect("the active optimistic worktree child must own the approval surface");
    assert_eq!(manager.session_id.as_deref(), Some(SESSION_ID));
    assert!(
        app.agents
            .get(&child_id)
            .and_then(|agent| agent.ssh_manager.as_ref())
            .is_some(),
        "the approval must render where the user initiated the worktree fork"
    );
    assert!(
        app.agents
            .get(&source_id)
            .and_then(|agent| agent.ssh_manager.as_ref())
            .is_none(),
        "the hidden source session must not swallow the child worktree approval"
    );
}

#[test]
fn cold_worktree_routes_only_recorded_source_approval_to_active_child() {
    let mut app = test_app();
    let source_id = AgentId(0);
    let child_id = AgentId(1);
    let source = AgentView::new(
        make_test_agent_session(&app, source_id, SESSION_ID),
        ScrollbackState::new(),
    );
    let mut child = AgentView::new(
        make_test_agent_session(&app, child_id, "optimistic-worktree"),
        ScrollbackState::new(),
    );
    child.session.session_id = None;
    child.pending_worktree_source_session_id = Some(SESSION_ID.into());
    child
        .session
        .start_command(crate::app::agent::AgentCommand::RestoreWorktree);
    app.agents.insert(source_id, source);
    app.agents.insert(child_id, child);
    app.active_view = ActiveView::Agent(child_id);

    let manager = ssh_manager_for_session_mut(&mut app, Some(SESSION_ID))
        .expect("the exact cold source must surface its approval on the visible child");
    assert_eq!(manager.session_id.as_deref(), Some(SESSION_ID));
    assert!(
        app.agents
            .get(&child_id)
            .and_then(|agent| agent.ssh_manager.as_ref())
            .is_some()
    );
    assert_eq!(
        existing_ssh_manager_for_session_mut(&mut app, Some(SESSION_ID))
            .map(|manager| manager.session_id.as_deref()),
        Some(Some(SESSION_ID)),
        "completion must find the child-held source manager"
    );
    let owner = ssh_manager_owner(&app).expect("the visible child owns its manager");
    close_ssh_manager_for_owner(&mut app, owner);
    assert!(
        app.agents
            .get(&child_id)
            .and_then(|agent| agent.ssh_manager.as_ref())
            .is_none(),
        "completion must remove the transient approval card from the visible child"
    );

    app.agents.get_mut(&child_id).unwrap().ssh_manager = None;
    app.agents
        .get_mut(&child_id)
        .unwrap()
        .pending_worktree_source_session_id = Some("different-source".into());
    let manager = ssh_manager_for_session_mut(&mut app, Some(SESSION_ID))
        .expect("the source session remains a valid manager owner");
    assert_eq!(
        manager.session_id.as_deref(),
        Some(SESSION_ID),
        "a mismatched pending source must not be redirected to the child"
    );
    assert!(
        app.agents
            .get(&child_id)
            .and_then(|agent| agent.ssh_manager.as_ref())
            .is_none(),
        "only the recorded source may route an approval onto a cold child"
    );
}
#[test]
fn cold_worktree_new_root_grant_routes_only_recorded_source_to_child() {
    let mut app = test_app();
    let source_id = AgentId(0);
    let child_id = AgentId(1);
    let mut source = AgentView::new(
        make_test_agent_session(&app, source_id, SESSION_ID),
        ScrollbackState::new(),
    );
    source.ssh_project_location = Some(crate::app::agent_view::SshProjectLocation {
        target_id: TARGET_ID.into(),
        root: CANONICAL_ROOT.into(),
    });
    let mut child = AgentView::new(
        make_test_agent_session(&app, child_id, "optimistic-worktree"),
        ScrollbackState::new(),
    );
    child.session.session_id = None;
    child.pending_worktree_source_session_id = Some(SESSION_ID.into());
    child
        .session
        .start_command(crate::app::agent::AgentCommand::RestoreWorktree);
    app.agents.insert(source_id, source);
    app.agents.insert(child_id, child);
    app.active_view = ActiveView::Agent(child_id);
    let client_id = app.ssh_client_id;

    let _ = apply_ssh_control_event(
        &mut app,
        Some(SESSION_ID.into()),
        None,
        SshEvent::GrantRequested(SshGrantRequest {
            id: "worktree-child-request".into(),
            session_id: "minted-child-session".into(),
            target_id: Some(TARGET_ID.into()),
            root: Some("/private/var/fixture/worktree".into()),
            capabilities: SshCapabilities::all(),
            reason: "A dedicated remote worktree creation requires a new root grant.".into(),
            verified_identity: None,
            client_id: Some(client_id),
            originating_session_id: Some(SESSION_ID.into()),
            awaiting_tool: false,
        }),
    );
    let _ = apply_ssh_control_event(
        &mut app,
        Some(SESSION_ID.into()),
        None,
        SshEvent::GrantRequested(SshGrantRequest {
            id: "untrusted-model-request".into(),
            session_id: "untrusted-session".into(),
            target_id: Some(TARGET_ID.into()),
            root: Some("/private/var/fixture/other-worktree".into()),
            capabilities: SshCapabilities::all(),
            reason: format!(
                "Resume SSH session {SESSION_ID} in remote worktree /private/var/fixture/other-worktree"
            ),
            verified_identity: None,
            client_id: Some(client_id),
            originating_session_id: None,
            awaiting_tool: true,
        }),
    );

    assert_eq!(
        app.agents
            .get(&child_id)
            .and_then(|agent| agent.ssh_manager.as_ref())
            .and_then(|manager| manager.grant_session_id_for("worktree-child-request")),
        Some("minted-child-session".into()),
        "the card must retain the shell-minted child session for the grant decision"
    );
    assert!(
        app.agents
            .get(&child_id)
            .and_then(|agent| agent.ssh_manager.as_ref())
            .and_then(|manager| manager.grant_session_id_for("untrusted-model-request"))
            .is_none(),
        "model-controlled request text must not route an unknown grant to the optimistic child"
    );
    assert!(
        app.agents
            .get(&source_id)
            .and_then(|agent| agent.ssh_manager.as_ref())
            .is_none(),
        "only the active matching worktree child may surface a new-root grant"
    );
    let owner = ssh_manager_owner(&app).expect("the visible child owns its manager");
    let client_id = app.ssh_client_id;
    for (session_id, expected_loading) in [("untrusted-session", true), (SESSION_ID, false)] {
        dispatch(
            Action::TaskComplete(TaskResult::SshTargetsLoaded {
                session_id: Some(session_id.into()),
                client_id,
                owner,
                targets: vec![],
                error: None,
            }),
            &mut app,
        );
        let manager = app
            .agents
            .get(&child_id)
            .unwrap()
            .ssh_manager
            .as_ref()
            .unwrap();
        assert_eq!(manager.loading, expected_loading);
        assert_eq!(
            manager
                .grant_session_id_for("worktree-child-request")
                .as_deref(),
            Some("minted-child-session"),
            "target loading must preserve the child's pending consent",
        );
    }
    let mut child_binding = binding(TARGET_ID, "/private/var/fixture/worktree");
    child_binding.session_id = "minted-child-session".into();
    let _ = apply_ssh_control_event(
        &mut app,
        None,
        None,
        SshEvent::GrantResolved {
            request_id: "worktree-child-request".into(),
            approved: true,
            binding: Some(child_binding),
        },
    );
    assert_eq!(
        app.agents
            .get(&child_id)
            .and_then(|agent| agent.pending_worktree_child_session_id.as_deref()),
        Some("minted-child-session"),
        "the accepted child binding must survive consent until WorktreeForked"
    );
    assert_eq!(
        ssh_manager_for_session_mut(&mut app, Some("minted-child-session"))
            .map(|manager| manager.session_id.as_deref()),
        Some(Some("minted-child-session")),
        "the child checkout approval must submit against the child binding"
    );
    assert!(
        ssh_manager_for_session_mut(&mut app, Some("forged-child-session")).is_none(),
        "an unknown child session must not surface an approval on the optimistic child"
    );
    app.agents.get_mut(&child_id).unwrap().ssh_manager = None;
    assert_eq!(
        ssh_manager_for_session_mut(&mut app, Some("minted-child-session"))
            .map(|manager| manager.session_id.as_deref()),
        Some(Some("minted-child-session")),
        "a checkout approval after the grant manager closes must recreate the child-owned card"
    );
    let owner = ssh_manager_owner(&app).expect("the visible child owns its manager");
    close_ssh_manager_for_owner(&mut app, owner);
    assert!(
        app.agents
            .get(&child_id)
            .and_then(|agent| agent.ssh_manager.as_ref())
            .is_none(),
        "child operation completion must return to chat by closing only its transient card"
    );
    assert_eq!(
        ssh_manager_for_session_mut(&mut app, Some(SESSION_ID))
            .map(|manager| manager.session_id.as_deref()),
        Some(Some(SESSION_ID)),
        "a later source event must not retarget the child manager after handoff"
    );
}

#[test]
fn matching_project_grant_uses_worker_canonical_root_after_user_changes_consent_root() {
    let mut app = test_app();
    begin_grant(&mut app, "request-1", TARGET_ID, RAW_ROOT);
    let submitted_raw_root = "/var/fixture/project/selected";
    approve(
        &mut app,
        "request-1",
        Some(TARGET_ID),
        Some(submitted_raw_root),
    );

    let owner = ssh_manager_owner(&app);
    let effects = apply_ssh_control_event(
        &mut app,
        None,
        owner,
        SshEvent::GrantResolved {
            request_id: "request-1".into(),
            approved: true,
            binding: Some(binding(TARGET_ID, "/private/var/fixture/project/selected")),
        },
    );

    assert_eq!(
        opened_project_root(&effects).as_deref(),
        Some("/private/var/fixture/project/selected"),
        "the remote worker's canonical binding root, not either local raw path, starts the project"
    );
    assert!(app.agents.values().any(|agent| {
        agent.ssh_project_open_session_id.as_deref() == Some(SESSION_ID)
    }), "approval automatically starts the child without another keypress");
}
#[test]
fn matching_project_grant_denial_from_global_receiver_clears_pending_open() {
    let mut app = test_app();
    begin_grant(&mut app, "request-1", TARGET_ID, RAW_ROOT);
    let owner = ssh_manager_owner(&app);

    let effects = apply_ssh_control_event(
        &mut app,
        None,
        owner,
        SshEvent::GrantResolved {
            request_id: "request-1".into(),
            approved: false,
            binding: None,
        },
    );

    assert!(
        opened_project_root(&effects).is_none(),
        "a denied grant must never open the project"
    );
    assert!(
        app.welcome_ssh_manager.as_ref().unwrap().pending_project_session_id().is_none(),
        "the exact denied project grant must clear its one-shot pending open"
    );
    assert!(
        app.welcome_ssh_manager
            .as_ref()
            .and_then(|manager| manager.grant_session_id_for("request-1"))
            .is_none(),
        "the denied request must no longer leave a consent card behind"
    );
}

#[test]
fn unrelated_grant_resolution_does_not_clear_displayed_project_consent() {
    let mut app = test_app();
    begin_grant(&mut app, "request-1", TARGET_ID, RAW_ROOT);
    approve(&mut app, "request-1", Some(TARGET_ID), Some(RAW_ROOT));

    let effects = apply_ssh_control_event(
        &mut app,
        Some(SESSION_ID.into()),
        None,
        SshEvent::GrantResolved {
            request_id: "unrelated-request".into(),
            approved: true,
            binding: Some(binding(TARGET_ID, CANONICAL_ROOT)),
        },
    );

    assert!(opened_project_root(&effects).is_none());
    assert_eq!(
        app.welcome_ssh_manager.as_ref().unwrap().pending_project_session_id(),
        Some(SESSION_ID),
        "an unrelated request must leave the matching consent available"
    );
    assert_eq!(
        app.welcome_ssh_manager
            .as_ref()
            .and_then(|manager| manager.grant_session_id_for("request-1"))
            .as_deref(),
        Some(SESSION_ID),
        "an unrelated resolution must not dismiss the displayed matching consent"
    );
}

#[test]
fn wrong_resolution_session_or_target_cannot_consume_project_open() {
    let cases = [
        ("wrong-session", "other-session", TARGET_ID),
        ("wrong-target", SESSION_ID, "other-target"),
    ];

    for (request_id, resolution_session, binding_target) in cases {
        let mut app = test_app();
        begin_grant(&mut app, request_id, TARGET_ID, RAW_ROOT);
        approve(&mut app, request_id, Some(TARGET_ID), Some(RAW_ROOT));
        let owner = ssh_manager_owner(&app);
        let effects = apply_ssh_control_event(
            &mut app,
            Some(resolution_session.into()),
            owner,
            SshEvent::GrantResolved {
                request_id: request_id.into(),
                approved: true,
                binding: Some(binding(binding_target, CANONICAL_ROOT)),
            },
        );

        assert!(
            opened_project_root(&effects).is_none(),
            "{request_id} resolution must not open a different project"
        );
        assert!(
            app.welcome_ssh_manager.as_ref().unwrap().pending_project_session_id().is_some(),
            "{request_id} resolution must not consume the pending project"
        );
    }
}

#[test]
fn mismatched_user_approval_tuple_cannot_consume_project_open() {
    let mut app = test_app();
    begin_grant(&mut app, "request-1", TARGET_ID, RAW_ROOT);
    approve(
        &mut app,
        "request-1",
        Some("different-target"),
        Some(RAW_ROOT),
    );

    let owner = ssh_manager_owner(&app);
    let effects = apply_ssh_control_event(
        &mut app,
        Some(SESSION_ID.into()),
        owner,
        SshEvent::GrantResolved {
            request_id: "request-1".into(),
            approved: true,
            binding: Some(binding(TARGET_ID, CANONICAL_ROOT)),
        },
    );

    assert!(opened_project_root(&effects).is_none());
    assert!(
        app.welcome_ssh_manager.as_ref().unwrap().pending_project_session_id().is_some(),
        "a decision whose target differs from the displayed request cannot consume the project"
    );
}

fn ssh_target_list_request(
    effects: &[Effect],
) -> (Option<String>, crate::app::actions::SshManagerOwner) {
    effects
        .iter()
        .find_map(|effect| match effect {
            Effect::SshListTargets {
                session_id, owner, ..
            } => Some((session_id.clone(), *owner)),
            _ => None,
        })
        .expect("SSH manager open must request its target list")
}

#[test]
fn pre_session_manager_binds_and_refreshes_without_routing_old_list_to_welcome() {
    let mut app = test_app_with_agent();
    let agent_id = AgentId(0);
    app.agents.get_mut(&agent_id).unwrap().session.session_id = None;
    app.active_view = ActiveView::Agent(agent_id);

    let initial = dispatch(Action::OpenSshManager, &mut app);
    let (initial_session_id, initial_owner) = ssh_target_list_request(&initial);
    assert_eq!(initial_session_id, None);

    let created = dispatch(
        Action::TaskComplete(TaskResult::SessionCreated {
            agent_id,
            session_id: acp::SessionId::new("bound-session"),
            models: None,
            modes: None,
        }),
        &mut app,
    );
    let (bound_session_id, bound_owner) = ssh_target_list_request(&created);
    assert_eq!(bound_session_id.as_deref(), Some("bound-session"));
    assert_eq!(bound_owner.agent_id, Some(agent_id));
    assert_eq!(
        app.agents
            .get(&agent_id)
            .and_then(|agent| agent.ssh_manager.as_ref())
            .and_then(|manager| manager.session_id.as_deref()),
        Some("bound-session")
    );

    dispatch(
        Action::TaskComplete(TaskResult::SshTargetsLoaded {
            session_id: initial_session_id,
            client_id: app.ssh_client_id,
            owner: initial_owner,
            targets: vec![],
            error: None,
        }),
        &mut app,
    );
    assert!(
        app.welcome_ssh_manager.is_none(),
        "the pre-bind response must not be rerouted to a Welcome manager"
    );
    assert!(
        app.agents
            .get(&agent_id)
            .and_then(|agent| agent.ssh_manager.as_ref())
            .is_some_and(|manager| manager.loading),
        "the old pre-bind list must wait for the bound-session refresh"
    );

    dispatch(
        Action::TaskComplete(TaskResult::SshTargetsLoaded {
            session_id: bound_session_id,
            client_id: app.ssh_client_id,
            owner: bound_owner,
            targets: vec![],
            error: None,
        }),
        &mut app,
    );
    assert!(
        app.agents
            .get(&agent_id)
            .and_then(|agent| agent.ssh_manager.as_ref())
            .is_some_and(|manager| !manager.loading),
        "the bound-session list must resolve the cold manager"
    );
}

#[test]
fn target_list_completion_cannot_cross_sessions_or_reopen_a_replaced_manager() {
    let mut app = test_app_with_agent();
    let first_id = AgentId(0);
    app.active_view = ActiveView::Agent(first_id);
    let first_open = dispatch(Action::OpenSshManager, &mut app);
    let (first_session_id, first_owner) = ssh_target_list_request(&first_open);

    let second_id = AgentId(1);
    app.agents.insert(
        second_id,
        AgentView::new(
            make_test_agent_session(&app, second_id, "second-session"),
            ScrollbackState::new(),
        ),
    );
    app.active_view = ActiveView::Agent(second_id);
    let second_open = dispatch(Action::OpenSshManager, &mut app);
    let (_, second_owner) = ssh_target_list_request(&second_open);
    dispatch(
        Action::TaskComplete(TaskResult::SshTargetsLoaded {
            session_id: first_session_id.clone(),
            client_id: app.ssh_client_id,
            owner: first_owner,
            targets: vec![],
            error: None,
        }),
        &mut app,
    );
    assert!(
        app.agents
            .get(&second_id)
            .and_then(|agent| agent.ssh_manager.as_ref())
            .is_some_and(|manager| manager.loading),
        "a source-session completion must not consume the other session's manager"
    );
    assert_eq!(
        app.agents
            .get(&first_id)
            .and_then(|agent| agent.ssh_manager.as_ref())
            .map(|manager| manager.instance_id()),
        Some(first_owner.instance_id)
    );
    assert_ne!(first_owner, second_owner);

    app.agents.get_mut(&first_id).unwrap().ssh_manager = None;
    app.active_view = ActiveView::Agent(first_id);
    let reopened = dispatch(Action::OpenSshManager, &mut app);
    let (_, reopened_owner) = ssh_target_list_request(&reopened);
    assert_ne!(reopened_owner, first_owner);
    dispatch(
        Action::TaskComplete(TaskResult::SshTargetsLoaded {
            session_id: first_session_id,
            client_id: app.ssh_client_id,
            owner: first_owner,
            targets: vec![],
            error: None,
        }),
        &mut app,
    );
    assert!(
        app.agents
            .get(&first_id)
            .and_then(|agent| agent.ssh_manager.as_ref())
            .is_some_and(|manager| manager.loading),
        "a late completion from the closed manager must not mutate its replacement"
    );
}

#[test]
fn target_add_completion_returns_only_to_its_originating_form() {
    let mut app = test_app_with_agent();
    let source_id = AgentId(0);
    app.active_view = ActiveView::Agent(source_id);
    let opened = dispatch(Action::OpenSshManager, &mut app);
    let (session_id, owner) = ssh_target_list_request(&opened);
    let (draft, submission_id) = {
        let manager = app
            .agents
            .get_mut(&source_id)
            .and_then(|agent| agent.ssh_manager.as_mut())
            .expect("source manager must be open");
        assert!(matches!(
            handle_ssh_key(
                manager,
                &KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE)
            ),
            SshModalOutcome::Changed
        ));
        for character in "saved.example.test".chars() {
            let _ = handle_ssh_key(
                manager,
                &KeyEvent::new(KeyCode::Char(character), KeyModifiers::NONE),
            );
        }
        match handle_ssh_key(manager, &KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)) {
            SshModalOutcome::AddTarget {
                draft,
                submission_id,
            } => (draft, submission_id),
            _ => panic!("expected target-add submission"),
        }
    };
    let submitted = dispatch(
        Action::AddSshTarget {
            draft,
            submission_id,
        },
        &mut app,
    );
    assert!(matches!(
        submitted.as_slice(),
        [Effect::SshAddTarget {
            session_id: effect_session_id,
            owner: effect_owner,
            submission_id: effect_submission_id,
            ..
        }] if effect_session_id == &session_id
            && *effect_owner == owner
            && *effect_submission_id == submission_id
    ));

    let other_id = AgentId(1);
    app.agents.insert(
        other_id,
        AgentView::new(
            make_test_agent_session(&app, other_id, "other-session"),
            ScrollbackState::new(),
        ),
    );
    app.active_view = ActiveView::Agent(other_id);
    assert!(
        dispatch(
            Action::TaskComplete(TaskResult::SshTargetAdded {
                session_id: session_id.clone(),
                client_id: app.ssh_client_id,
                owner,
                submission_id,
                result: Err("target already exists".into()),
            }),
            &mut app,
        )
        .is_empty()
    );
    assert!(
        !app.agents
            .get(&source_id)
            .and_then(|agent| agent.ssh_manager.as_ref())
            .is_some_and(|manager| manager.target_add_is_submitting()),
        "the failed submission must settle on its hidden source form"
    );

    app.active_view = ActiveView::Agent(source_id);
    let (retry_draft, retry_submission_id) = {
        let manager = app
            .agents
            .get_mut(&source_id)
            .and_then(|agent| agent.ssh_manager.as_mut())
            .expect("source form must remain visible after failure");
        handle_ssh_key(manager, &KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        match handle_ssh_key(manager, &KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)) {
            SshModalOutcome::AddTarget {
                draft,
                submission_id,
            } => (draft, submission_id),
            _ => panic!("expected retry target-add submission"),
        }
    };
    let retry = dispatch(
        Action::AddSshTarget {
            draft: retry_draft,
            submission_id: retry_submission_id,
        },
        &mut app,
    );
    assert!(matches!(
        retry.as_slice(),
        [Effect::SshAddTarget {
            owner: effect_owner,
            submission_id: effect_submission_id,
            ..
        }] if *effect_owner == owner && *effect_submission_id == retry_submission_id
    ));
    app.active_view = ActiveView::Agent(other_id);
    let refresh = dispatch(
        Action::TaskComplete(TaskResult::SshTargetAdded {
            session_id: session_id.clone(),
            client_id: app.ssh_client_id,
            owner,
            submission_id: retry_submission_id,
            result: Ok("saved-target".into()),
        }),
        &mut app,
    );
    assert!(
        !app.agents
            .get(&source_id)
            .and_then(|agent| agent.ssh_manager.as_ref())
            .is_some_and(|manager| manager.target_add_is_submitting()),
        "the success completion must close the original form even while another session is active"
    );
    assert!(matches!(
        refresh.as_slice(),
        [Effect::SshListTargets {
            session_id: refresh_session_id,
            owner: refresh_owner,
            ..
        }] if refresh_session_id == &session_id && *refresh_owner == owner
    ));
}

#[test]
fn ssh_manager_wheel_scroll_reaches_modal_instead_of_background_transcript() {
    let mut app = test_app_with_agent();
    let id = AgentId(0);
    dispatch(Action::OpenSshManager, &mut app);
    let manager = app
        .agents
        .get_mut(&id)
        .unwrap()
        .ssh_manager
        .as_mut()
        .unwrap();
    manager.set_targets(
        (0..20)
            .map(|index| {
                let mut target = xai_grok_ssh::SshTarget::new(format!("target-{index}"));
                target.id = format!("target-{index}");
                target.label = format!("Host {index}");
                crate::views::ssh_modal::SshTargetView::from_target(
                    target,
                    "user@example.test:22".into(),
                    false,
                    "Not connected.".into(),
                    crate::views::ssh_modal::SshGrantView::NotGranted,
                )
            })
            .collect(),
    );
    let area = ratatui::layout::Rect::new(0, 0, 100, 24);
    let mut buffer = ratatui::buffer::Buffer::empty(area);
    crate::views::ssh_modal::render_ssh_modal(
        &mut buffer,
        area,
        manager,
        false,
        &crate::theme::Theme::current(),
    );
    app.handle_input(&crossterm::event::Event::Mouse(
        crossterm::event::MouseEvent {
            kind: crossterm::event::MouseEventKind::ScrollDown,
            column: 20,
            row: 10,
            modifiers: KeyModifiers::NONE,
        },
    ));
    let manager = app.agents.get(&id).unwrap().ssh_manager.as_ref().unwrap();
    assert_eq!(manager.targets[manager.selected].target_id, "target-3");
    assert!(
        app.last_scroll_pos.is_none(),
        "the background transcript must not receive the wheel event"
    );
}

#[test]
fn folder_selection_is_single_flight_and_preparation_failure_can_retry() {
    let mut app = test_app_with_agent();
    let source_id = AgentId(0);
    app.active_view = ActiveView::Agent(source_id);
    dispatch(Action::OpenSshManager, &mut app);
    let owner = ssh_manager_owner(&app).unwrap();
    let manager = app.agents.get_mut(&source_id).unwrap().ssh_manager.as_mut().unwrap();
    let SshModalOutcome::BrowseProjectDirectory { request_id, .. } =
        manager.begin_project_browser(TARGET_ID.into(), None)
    else { panic!("folder browser must request remote directories") };
    manager.settle_project_directory(request_id, TARGET_ID, Ok(xai_grok_shell::ssh::SshDirectoryListing {
        target_id: TARGET_ID.into(), identity: binding(TARGET_ID, RAW_ROOT).identity,
        path: RAW_ROOT.into(), parent: Some("/var/fixture".into()),
        directories: vec![], truncated: false,
    }));
    let outcome = app.handle_input(&Event::Key(KeyEvent::new(KeyCode::Char('o'), KeyModifiers::NONE)));
    let InputOutcome::Action(action) = outcome else { panic!("selected folder must open") };
    let effects = dispatch(action, &mut app);
    let (request_id, project_session_id) = effects.iter().find_map(|effect| match effect {
        Effect::SshPrepareProjectOpen { request_id, project_session_id, owner: actual_owner, .. }
            if *actual_owner == owner => Some((*request_id, project_session_id.clone())),
        _ => None,
    }).expect("folder selection prepares a child owned by its source manager");
    assert!(dispatch(Action::ChooseSshProjectDirectory {
        request_id, target_id: TARGET_ID.into(), root: RAW_ROOT.into(),
        identity: binding(TARGET_ID, RAW_ROOT).identity,
    }, &mut app).is_empty(), "double click must not mint another child");
    dispatch(Action::TaskComplete(TaskResult::SshProjectPrepared {
        request_id, target_id: TARGET_ID.into(), project_session_id,
        client_id: app.ssh_client_id, owner,
        result: Err("remote folder permission denied".into()),
    }), &mut app);
    let manager = app.agents.get(&source_id).unwrap().ssh_manager.as_ref().unwrap();
    assert!(manager.pending_project_session_id().is_none());
    app.handle_input(&Event::Key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)));
    let outcome = app.handle_input(&Event::Key(KeyEvent::new(KeyCode::Char('o'), KeyModifiers::NONE)));
    let InputOutcome::Action(action) = outcome else { panic!("failed folder open must remain retryable") };
    assert!(dispatch(action, &mut app).iter().any(|effect| matches!(effect, Effect::SshPrepareProjectOpen { .. })));
}

#[test]
fn ssh_project_session_failure_returns_full_error_to_its_source_diagnostic() {
    let mut app = test_app_with_agent();
    let source_id = AgentId(0);
    app.active_view = ActiveView::Agent(source_id);
    let opened = dispatch_begin_ssh_project_open(&mut app, pending_project());
    let (_, owner) = ssh_target_list_request(&opened);

    let child_id = AgentId(1);
    let mut child = AgentView::new(
        make_test_agent_session(&app, child_id, "unbound-ssh-project"),
        ScrollbackState::new(),
    );
    child.session.session_id = None;
    child.ssh_project_open_owner = Some(owner);
    child.ssh_project_open_session_id = Some(SESSION_ID.into());
    app.agents.insert(child_id, child);
    app.active_view = ActiveView::Agent(child_id);

    dispatch(
        Action::TaskComplete(TaskResult::SessionFailed {
            agent_id: child_id,
            error: "missing remote worker executable".into(),
            timed_out: false,
        }),
        &mut app,
    );
    assert!(!app.agents.contains_key(&child_id));
    assert!(matches!(app.active_view, ActiveView::Agent(id) if id == source_id));
    let area = ratatui::layout::Rect::new(0, 0, 120, 30);
    let mut buffer = ratatui::buffer::Buffer::empty(area);
    crate::views::ssh_modal::render_ssh_modal(
        &mut buffer, area, app.agents.get_mut(&source_id).unwrap().ssh_manager.as_mut().unwrap(),
        false, &crate::theme::Theme::default(),
    );
    let visible: String = buffer.content.iter().map(|cell| cell.symbol()).collect();
    assert!(visible.contains("missing remote worker executable"));
    assert!(
        app.agents
            .get(&source_id)
            .and_then(|agent| agent.toast.as_ref())
            .is_none(),
        "the source manager diagnostic must replace the hidden child toast"
    );
}

#[test]
fn broadcast_duplicate_of_a_direct_grant_reply_cannot_reopen_a_dismissed_manager() {
    let mut app = test_app_with_agent();
    let source_id = AgentId(0);
    app.active_view = ActiveView::Agent(source_id);
    let opened = dispatch(Action::OpenSshManager, &mut app);
    let (_, owner) = ssh_target_list_request(&opened);
    let request = grant_request("direct-grant-reply", TARGET_ID, RAW_ROOT, app.ssh_client_id);

    let _ = apply_ssh_control_event(
        &mut app,
        Some("test-session".into()),
        Some(owner),
        SshEvent::GrantRequested(request.clone()),
    );
    app.agents.get_mut(&source_id).unwrap().ssh_manager = None;

    let effects = apply_ssh_control_event(
        &mut app,
        Some("test-session".into()),
        None,
        SshEvent::GrantRequested(request),
    );
    assert!(
        app.agents
            .get(&source_id)
            .and_then(|agent| agent.ssh_manager.as_ref())
            .is_none(),
        "the global duplicate must not recreate a manager dismissed after its direct reply"
    );
    assert!(
        app.welcome_ssh_manager.is_none(),
        "the duplicate must not be routed through Welcome"
    );
    assert!(
        effects
            .iter()
            .all(|effect| matches!(effect, Effect::SshAwaitEvent { .. })),
        "the duplicate only re-arms the global control receiver"
    );
}

fn worker_install_request(
    request_id: &str,
    session_id: &str,
    binding_id: &str,
    client_id: u64,
) -> SshWorkerInstallRequest {
    SshWorkerInstallRequest {
        client_id,
        request_id: request_id.into(),
        session_id: session_id.into(),
        binding_id: binding_id.into(),
        target_id: TARGET_ID.into(),
        version: "1.2.3".into(),
        platform: "linux-aarch64".into(),
        remote_error: "direct remote download failed".into(),
    }
}

#[test]
fn worker_fallback_keeps_its_source_actionable_through_inherited_child_bootstrap() {
    let mut app = test_app_with_agent();
    app.screen_mode = crate::app::ScreenMode::Minimal;
    let source_id = AgentId(0);
    app.active_view = ActiveView::Agent(source_id);
    let opened = dispatch_begin_ssh_project_open(&mut app, pending_project());
    let (_, owner) = ssh_target_list_request(&opened);

    let inherited = dispatch_inherited_ssh_project(
        &mut app,
        TARGET_ID.into(),
        RAW_ROOT.into(),
        SESSION_ID.into(),
        "project-binding".into(),
        Some(owner),
    );
    let child_id = inherited
        .iter()
        .find_map(|effect| match effect {
            Effect::OpenSshProject { agent_id, .. } => Some(*agent_id),
            _ => None,
        })
        .expect("inherited project bootstrap opens its child session");
    assert!(
        app.agents.contains_key(&source_id),
        "minimal mode must retain the source while worker consent is possible"
    );
    assert_eq!(
        app.active_view,
        ActiveView::Agent(source_id),
        "the source manager remains actionable through child bootstrap"
    );
    assert_eq!(
        app.agents
            .get(&child_id)
            .and_then(|agent| agent.ssh_project_open_owner),
        Some(owner)
    );

    let client_id = app.ssh_client_id;
    let effects = apply_ssh_control_event(
        &mut app,
        None,
        None,
        SshEvent::WorkerInstallRequested(worker_install_request(
            "install-1",
            SESSION_ID,
            "project-binding",
            client_id,
        )),
    );
    assert!(matches!(effects.as_slice(), [Effect::SshAwaitEvent { .. }]));
    let action = match app.handle_input(&Event::Key(KeyEvent::new(
        KeyCode::Char('y'),
        KeyModifiers::NONE,
    ))) {
        InputOutcome::Action(action) => action,
        _ => panic!("fallback approval must travel through the visible source manager"),
    };
    let effects = dispatch(action, &mut app);
    assert!(matches!(
        effects.as_slice(),
        [Effect::SshApproveWorkerInstall {
            client_id,
            owner: effect_owner,
            request_id,
            session_id,
            binding_id,
            approved: true,
        }]
            if *client_id == app.ssh_client_id
                && *effect_owner == owner
                && request_id == "install-1"
                && session_id == SESSION_ID
                && binding_id == "project-binding"
    ));
    let _ = handle_session_created(
        &mut app,
        child_id,
        acp::SessionId::new(SESSION_ID),
        None,
        None,
    );
    assert_eq!(
        app.active_view,
        ActiveView::Agent(child_id),
        "a completed fallback returns to its child only while the source flow is still active"
    );
}

#[test]
fn inherited_project_success_does_not_steal_focus_after_user_leaves_source_flow() {
    let mut app = test_app_with_agent();
    let source_id = AgentId(0);
    app.active_view = ActiveView::Agent(source_id);
    let opened = dispatch_begin_ssh_project_open(&mut app, pending_project());
    let (_, owner) = ssh_target_list_request(&opened);
    let inherited = dispatch_inherited_ssh_project(
        &mut app,
        TARGET_ID.into(),
        RAW_ROOT.into(),
        SESSION_ID.into(),
        "project-binding".into(),
        Some(owner),
    );
    let child_id = inherited
        .iter()
        .find_map(|effect| match effect {
            Effect::OpenSshProject { agent_id, .. } => Some(*agent_id),
            _ => None,
        })
        .expect("inherited project bootstrap opens its child session");

    let other_id = AgentId(2);
    let other = AgentView::new(
        make_test_agent_session(&app, other_id, "user-selected-session"),
        ScrollbackState::new(),
    );
    app.agents.insert(other_id, other);
    app.active_view = ActiveView::Agent(other_id);
    let _ = handle_session_created(
        &mut app,
        child_id,
        acp::SessionId::new(SESSION_ID),
        None,
        None,
    );
    assert_eq!(
        app.active_view,
        ActiveView::Agent(other_id),
        "session readiness must not pull the user away from an unrelated active session"
    );
}

#[test]
fn worker_fallback_for_closed_source_is_rejected_without_touching_replacement_manager() {
    let mut app = test_app_with_agent();
    let source_id = AgentId(0);
    app.active_view = ActiveView::Agent(source_id);
    let opened = dispatch(Action::OpenSshManager, &mut app);
    let (_, original_owner) = ssh_target_list_request(&opened);
    app.agents.get_mut(&source_id).unwrap().ssh_manager = None;
    let reopened = dispatch(Action::OpenSshManager, &mut app);
    let (_, replacement_owner) = ssh_target_list_request(&reopened);
    assert_ne!(original_owner, replacement_owner);

    let child_id = AgentId(1);
    let mut child = AgentView::new(
        make_test_agent_session(&app, child_id, "unbound-ssh-project"),
        ScrollbackState::new(),
    );
    child.session.session_id = None;
    child.ssh_project_location = Some(crate::app::agent_view::SshProjectLocation {
        target_id: TARGET_ID.into(),
        root: RAW_ROOT.into(),
    });
    child.ssh_project_open_owner = Some(original_owner);
    child.ssh_project_open_session_id = Some(SESSION_ID.into());
    child.ssh_project_binding_id = Some("project-binding".into());
    app.agents.insert(child_id, child);
    app.active_view = ActiveView::Agent(child_id);
    let client_id = app.ssh_client_id;

    let effects = apply_ssh_control_event(
        &mut app,
        None,
        None,
        SshEvent::WorkerInstallRequested(worker_install_request(
            "install-closed",
            SESSION_ID,
            "project-binding",
            client_id,
        )),
    );
    assert!(matches!(
        effects.as_slice(),
        [
            Effect::SshAwaitEvent { .. },
            Effect::SshRejectWorkerInstall {
                request_id,
                session_id,
                binding_id,
                ..
            }
        ] if request_id == "install-closed"
            && session_id == SESSION_ID
            && binding_id == "project-binding"
    ));
    assert_eq!(
        app.agents
            .get(&source_id)
            .and_then(|agent| agent.ssh_manager.as_ref())
            .map(|manager| manager.instance_id()),
        Some(replacement_owner.instance_id),
        "a late fallback must not replace or mutate a reopened manager"
    );
}

#[test]
fn worker_fallback_decline_flows_from_agent_input_to_exact_rejection_effect() {
    let mut app = test_app_with_agent();
    let source_id = AgentId(0);
    app.active_view = ActiveView::Agent(source_id);
    let opened = dispatch(Action::OpenSshManager, &mut app);
    let (_, owner) = ssh_target_list_request(&opened);
    let client_id = app.ssh_client_id;
    let agent = app.agents.get_mut(&source_id).unwrap();
    agent.ssh_project_location = Some(crate::app::agent_view::SshProjectLocation {
        target_id: TARGET_ID.into(),
        root: RAW_ROOT.into(),
    });
    agent.ssh_project_binding_id = Some("project-binding".into());

    let _ = apply_ssh_control_event(
        &mut app,
        None,
        None,
        SshEvent::WorkerInstallRequested(worker_install_request(
            "install-decline",
            "test-session",
            "project-binding",
            client_id,
        )),
    );
    let action =
        match app.handle_input(&Event::Key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE))) {
            InputOutcome::Action(action) => action,
            _ => panic!("fallback decline must travel through normal agent input"),
        };
    let effects = dispatch(action, &mut app);
    assert!(matches!(
        effects.as_slice(),
        [Effect::SshApproveWorkerInstall {
            client_id: effect_client_id,
            owner: effect_owner,
            request_id,
            session_id,
            binding_id,
            approved: false,
        }]
            if *effect_client_id == client_id
                && *effect_owner == owner
                && request_id == "install-decline"
                && session_id == "test-session"
                && binding_id == "project-binding"
    ));
}

#[test]
fn resumed_ssh_project_fallback_uses_loading_placeholder_input_and_clears_on_success() {
    let mut app = test_app();
    let resumed_session = "resume-ssh-project";
    let load = dispatch_load_session(&mut app, resumed_session.into(), None, false);
    let agent_id = load
        .iter()
        .find_map(|effect| match effect {
            Effect::LoadSession { agent_id, .. } => Some(*agent_id),
            _ => None,
        })
        .expect("explicit resume creates a loading placeholder");
    let client_id = app.ssh_client_id;
    let request = worker_install_request(
        "resume-install",
        resumed_session,
        "resume-binding",
        client_id,
    );

    let effects = apply_ssh_control_event(
        &mut app,
        None,
        None,
        SshEvent::WorkerInstallRequested(request.clone()),
    );
    assert!(matches!(
        effects.as_slice(),
        [Effect::SshAwaitEvent { .. }]
    ));
    let owner = app
        .agents
        .get(&agent_id)
        .and_then(|agent| agent.ssh_project_resume_install.as_ref())
        .map(|install| {
            assert_eq!(install.request_id, "resume-install");
            assert_eq!(install.binding_id, "resume-binding");
            install.owner
        })
        .expect("the exact request is retained with its transient owner");

    let action = match app.handle_input(&Event::Key(KeyEvent::new(
        KeyCode::Char('y'),
        KeyModifiers::NONE,
    ))) {
        InputOutcome::Action(action) => action,
        _ => panic!("resume fallback approval must use the loading placeholder input"),
    };
    let effects = dispatch(action, &mut app);
    assert!(matches!(
        effects.as_slice(),
        [Effect::SshApproveWorkerInstall {
            owner: effect_owner,
            request_id,
            session_id,
            binding_id,
            approved: true,
            ..
        }] if *effect_owner == owner
            && request_id == "resume-install"
            && session_id == resumed_session
            && binding_id == "resume-binding"
    ));

    let _ = handle_session_loaded(
        &mut app,
        agent_id,
        acp::SessionId::new(resumed_session),
        None,
        None,
        false,
        None,
        None,
        None,
    );
    let resumed = app.agents.get(&agent_id).unwrap();
    assert!(resumed.ssh_manager.is_none());
    assert!(
        resumed
            .ssh_project_resume_install
            .as_ref()
            .is_some_and(|install| install.owner == owner)
    );
    assert!(resumed.ssh_project_resume_pending_session_id.is_none());

    let effects = apply_ssh_control_event(
        &mut app,
        None,
        None,
        SshEvent::WorkerInstallRequested(request),
    );
    assert!(
        matches!(
            effects.as_slice(),
            [
                Effect::SshAwaitEvent { .. },
                Effect::SshRejectWorkerInstall { .. }
            ]
        ),
        "late resume event must not recreate a closed transient confirmation"
    );
}

#[test]
fn resumed_worker_fallback_never_reopens_a_replaced_manager_or_steals_focus() {
    let mut app = test_app_with_agent();
    let source_id = AgentId(0);
    let resumed_session = "resume-ssh-project";
    let load = dispatch_load_session(&mut app, resumed_session.into(), None, false);
    let resumed_id = load
        .iter()
        .find_map(|effect| match effect {
            Effect::LoadSession { agent_id, .. } => Some(*agent_id),
            _ => None,
        })
        .expect("explicit resume creates a loading placeholder");
    app.active_view = ActiveView::Agent(source_id);
    let client_id = app.ssh_client_id;
    let request = worker_install_request(
        "resume-replaced",
        resumed_session,
        "resume-binding",
        client_id,
    );
    let _ = apply_ssh_control_event(
        &mut app,
        None,
        None,
        SshEvent::WorkerInstallRequested(request.clone()),
    );
    assert_eq!(
        app.active_view,
        ActiveView::Agent(source_id),
        "a pending resume must not pull focus from an unrelated user-selected session"
    );
    let original_owner = app
        .agents
        .get(&resumed_id)
        .and_then(|agent| agent.ssh_project_resume_install.as_ref())
        .map(|install| install.owner)
        .expect("trusted loading placeholder receives one transient owner");
    close_ssh_manager_for_owner(&mut app, original_owner);
    app.active_view = ActiveView::Agent(resumed_id);
    let opened = dispatch(Action::OpenSshManager, &mut app);
    let (_, replacement_owner) = ssh_target_list_request(&opened);
    assert_ne!(original_owner, replacement_owner);

    let effects = apply_ssh_control_event(
        &mut app,
        None,
        None,
        SshEvent::WorkerInstallRequested(request),
    );
    assert!(matches!(
        effects.as_slice(),
        [
            Effect::SshAwaitEvent { .. },
            Effect::SshRejectWorkerInstall { .. }
        ]
    ));
    assert_eq!(
        app.agents
            .get(&resumed_id)
            .and_then(|agent| agent.ssh_manager.as_ref())
            .map(|manager| manager.instance_id()),
        Some(replacement_owner.instance_id)
    );

    let _ = handle_session_load_failed(
        &mut app,
        resumed_id,
        acp::SessionId::new(resumed_session),
        "resume failed".into(),
    );
    let effects = apply_ssh_control_event(
        &mut app,
        None,
        None,
        SshEvent::WorkerInstallProgress(SshWorkerInstallProgress {
            client_id,
            request_id: "resume-replaced".into(),
            session_id: resumed_session.into(),
            binding_id: "resume-binding".into(),
            target_id: TARGET_ID.into(),
            message: Some("late upload progress".into()),
        }),
    );
    assert!(
        matches!(effects.as_slice(), [Effect::SshAwaitEvent { .. }]),
        "late resume progress must not be applied to the replacement manager"
    );
    let resumed = app.agents.get(&resumed_id).unwrap();
    assert!(
        resumed
            .ssh_project_resume_install
            .as_ref()
            .is_some_and(|install| install.owner == original_owner)
    );
    assert!(resumed.ssh_project_resume_pending_session_id.is_none());
    assert_eq!(
        resumed.ssh_manager.as_ref().map(|manager| manager.instance_id()),
        Some(replacement_owner.instance_id),
        "terminal cleanup must not close a user-created replacement"
    );
}

#[test]
fn project_preparation_cancellation_rejects_late_consent_without_reopening() {
    let mut app = test_app();
    let effects = dispatch_begin_ssh_project_open(&mut app, pending_project());
    let (request_id, owner) = effects.iter().find_map(|effect| match effect {
        Effect::SshPrepareProjectOpen { request_id, owner, .. } => Some((*request_id, *owner)),
        _ => None,
    }).unwrap();
    dispatch(Action::CancelSshProjectOpen { request_id }, &mut app);
    let effects = dispatch(Action::TaskComplete(TaskResult::SshProjectPrepared {
        request_id, target_id: TARGET_ID.into(), project_session_id: SESSION_ID.into(),
        client_id: app.ssh_client_id, owner,
        result: Ok(xai_grok_shell::ssh::SshProjectPreparation::NeedsApproval(
            grant_request("late-grant", TARGET_ID, RAW_ROOT, app.ssh_client_id),
        )),
    }), &mut app);
    assert!(effects.iter().any(|effect| matches!(effect,
        Effect::SshRejectProjectGrant { request_id, .. } if request_id == "late-grant"
    )));
    assert!(app.agents.is_empty());
    assert!(app.welcome_ssh_manager.as_ref().unwrap().grant_session_id_for("late-grant").is_none());
}

#[test]
fn remembered_project_opens_once_and_never_on_a_replacement_manager() {
    let mut app = test_app();
    let effects = dispatch_begin_ssh_project_open(&mut app, pending_project());
    let (request_id, owner) = effects.iter().find_map(|effect| match effect {
        Effect::SshPrepareProjectOpen { request_id, owner, .. } => Some((*request_id, *owner)),
        _ => None,
    }).unwrap();
    let ready = || Ok(xai_grok_shell::ssh::SshProjectPreparation::Ready(binding(TARGET_ID, CANONICAL_ROOT)));
    let effects = crate::app::dispatch::ssh::apply_ssh_project_prepared(
        &mut app, owner, request_id, TARGET_ID.into(), SESSION_ID.into(), ready(),
    );
    assert_eq!(opened_project_root(&effects).as_deref(), Some(CANONICAL_ROOT));
    let duplicate = crate::app::dispatch::ssh::apply_ssh_project_prepared(
        &mut app, owner, request_id, TARGET_ID.into(), SESSION_ID.into(), ready(),
    );
    assert!(opened_project_root(&duplicate).is_none());
    close_ssh_manager_for_owner(&mut app, owner);
    dispatch(Action::OpenSshManager, &mut app);
    let replacement = ssh_manager_owner(&app).unwrap();
    assert_ne!(owner, replacement);
    let late = crate::app::dispatch::ssh::apply_ssh_project_prepared(
        &mut app, owner, request_id, TARGET_ID.into(), SESSION_ID.into(), ready(),
    );
    assert!(opened_project_root(&late).is_none());
    assert_eq!(ssh_manager_owner(&app), Some(replacement));
}

#[test]
fn project_grant_broadcast_cannot_steal_the_source_manager_before_correlated_reply() {
    let mut app = test_app();
    dispatch_begin_ssh_project_open(&mut app, pending_project());
    let owner = ssh_manager_owner(&app);
    let client_id = app.ssh_client_id;
    apply_ssh_control_event(&mut app, None, None,
        SshEvent::GrantRequested(grant_request("broadcast", TARGET_ID, RAW_ROOT, client_id)));
    assert_eq!(ssh_manager_owner(&app), owner);
    assert!(app.welcome_ssh_manager.as_ref().unwrap().grant_session_id_for("broadcast").is_none());
    assert_eq!(app.welcome_ssh_manager.as_ref().unwrap().pending_project_session_id(), Some(SESSION_ID));
}

#[test]
fn cancelled_project_start_cannot_replace_a_new_folder_flow_on_completion() {
    let mut app = test_app();
    let effects = dispatch_begin_ssh_project_open(&mut app, pending_project());
    let (request_id, owner) = effects.iter().find_map(|effect| match effect {
        Effect::SshPrepareProjectOpen { request_id, owner, .. } => Some((*request_id, *owner)),
        _ => None,
    }).unwrap();
    let effects = crate::app::dispatch::ssh::apply_ssh_project_prepared(
        &mut app, owner, request_id, TARGET_ID.into(), SESSION_ID.into(),
        Ok(xai_grok_shell::ssh::SshProjectPreparation::Ready(binding(TARGET_ID, RAW_ROOT))),
    );
    let child = effects.iter().find_map(|effect| match effect {
        Effect::OpenSshProject { agent_id, .. } => Some(*agent_id), _ => None,
    }).unwrap();
    dispatch(Action::CancelSshProjectOpen { request_id }, &mut app);
    app.welcome_ssh_manager.as_mut().unwrap().begin_project_browser(TARGET_ID.into(), None);
    let effects = handle_session_created(&mut app, child, acp::SessionId::new(SESSION_ID), None, None);
    assert!(!app.agents.contains_key(&child));
    assert!(matches!(app.active_view, ActiveView::Welcome));
    assert_eq!(ssh_manager_owner(&app), Some(owner));
    assert!(effects.iter().any(|effect| matches!(effect, Effect::UnregisterActiveSession { session_id } if session_id.0.as_ref() == SESSION_ID)));
}

#[test]
fn direct_ssh_selection_cannot_resume_in_a_replacement_manager() {
    let mut app = test_app_with_agent();
    app.active_view = ActiveView::Agent(AgentId(0));
    let initial = dispatch(Action::SelectSshTarget { reference: "Fixture".into() }, &mut app);
    let (session_id, owner) = ssh_target_list_request(&initial);
    let mut target = xai_grok_ssh::SshTarget::new(TARGET_ID);
    target.id = TARGET_ID.into();
    target.label = "Fixture".into();
    let targets = vec![crate::views::ssh_modal::SshTargetView::from_target(
        target, "user@host:22".into(), false, String::new(),
        crate::views::ssh_modal::SshGrantView::NotGranted,
    )];
    let client_id = app.ssh_client_id;
    let effects = dispatch(Action::TaskComplete(TaskResult::SshTargetsLoaded {
        session_id: session_id.clone(), client_id, owner, targets: targets.clone(), error: None,
    }), &mut app);
    assert!(matches!(effects.as_slice(), [Effect::SshBrowseProjectDirectory {
        target_id, owner: actual_owner, ..
    }] if target_id == TARGET_ID && actual_owner == &owner));
    dispatch(Action::OpenSshManager, &mut app);
    let late = dispatch(Action::TaskComplete(TaskResult::SshTargetsLoaded {
        session_id, client_id, owner, targets, error: None,
    }), &mut app);
    assert!(late.is_empty());
    assert_ne!(ssh_manager_owner(&app), Some(owner));
}

#[test]
fn enter_defaults_the_selected_existing_binding_without_requesting_access() {
    let mut app = test_app_with_agent();
    let source = AgentId(0);
    app.active_view = ActiveView::Agent(source);
    dispatch(Action::OpenSshManager, &mut app);
    let owner = ssh_manager_owner(&app).unwrap();
    let session_id = app.agents.get(&source).unwrap().session.session_id.as_ref().unwrap().to_string();
    let mut target = xai_grok_ssh::SshTarget::new(TARGET_ID);
    target.id = TARGET_ID.into();
    target.label = "Fixture".into();
    app.agents.get_mut(&source).unwrap().ssh_manager.as_mut().unwrap().set_targets(vec![
        crate::views::ssh_modal::SshTargetView::from_target(
            target,
            "fixture-user@fixture-host:22".into(),
            false,
            String::new(),
            crate::views::ssh_modal::SshGrantView::Granted {
                binding_id: "existing-binding".into(),
                root: CANONICAL_ROOT.into(),
                capabilities: crate::views::ssh_modal::SshCapabilitiesView::default(),
                is_default: false,
            },
        ),
    ]);
    let InputOutcome::Action(action) =
        app.handle_input(&Event::Key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)))
    else { panic!("a granted selected candidate must become the default directly") };
    assert!(matches!(action, Action::UseSshBinding { ref binding_id } if binding_id == "existing-binding"));
    let effects = dispatch(action, &mut app);
    assert!(effects.iter().any(|effect| matches!(
        effect,
        Effect::SshUseBinding {
            session_id: actual,
            binding_id,
            owner: actual_owner,
            ..
        } if actual == &session_id && binding_id == "existing-binding" && actual_owner == &owner
    )));
    assert!(effects.iter().all(|effect| !matches!(
        effect,
        Effect::SshRequestGrant { .. }
            | Effect::SshInspectGrantTarget { .. }
            | Effect::SshBrowseProjectDirectory { .. }
    )));
}

#[test]
fn enter_authorizes_a_manual_selection_then_defaults_its_approved_binding() {
    let mut app = test_app_with_agent();
    let source = AgentId(0);
    app.active_view = ActiveView::Agent(source);
    dispatch(Action::OpenSshManager, &mut app);
    let owner = ssh_manager_owner(&app).unwrap();
    let manager = app.agents.get_mut(&source).unwrap().ssh_manager.as_mut().unwrap();
    let mut target = xai_grok_ssh::SshTarget::new(TARGET_ID);
    target.id = TARGET_ID.into();
    target.label = "Fixture".into();
    manager.set_targets(vec![crate::views::ssh_modal::SshTargetView::from_target(
        target,
        "fixture-user@fixture-host:22".into(),
        false,
        String::new(),
        crate::views::ssh_modal::SshGrantView::NotGranted,
    )]);
    let InputOutcome::Action(action) =
        app.handle_input(&Event::Key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)))
    else { panic!("a manual selection must choose a folder before requesting access") };
    let effects = dispatch(action, &mut app);
    let request_id = effects.iter().find_map(|effect| match effect {
        Effect::SshBrowseProjectDirectory { request_id, .. } => Some(*request_id), _ => None,
    }).unwrap();
    app.agents.get_mut(&source).unwrap().ssh_manager.as_mut().unwrap()
        .settle_project_directory(request_id, TARGET_ID, Ok(xai_grok_shell::ssh::SshDirectoryListing {
            target_id: TARGET_ID.into(),
            identity: binding(TARGET_ID, CANONICAL_ROOT).identity,
            path: CANONICAL_ROOT.into(), parent: Some("/private/var/fixture".into()),
            directories: vec![], truncated: false,
        }));
    let InputOutcome::Action(action) =
        app.handle_input(&Event::Key(KeyEvent::new(KeyCode::Char('o'), KeyModifiers::NONE)))
    else { panic!("selected folder must request access, not create a project session") };
    let effects = dispatch(action, &mut app);
    let session_id = effects.iter().find_map(|effect| match effect {
        Effect::SshRequestGrant { session_id, .. } => Some(session_id.clone()), _ => None,
    }).unwrap();
    let mut request = grant_request("advanced", TARGET_ID, CANONICAL_ROOT, app.ssh_client_id);
    request.session_id = session_id.clone();
    request.verified_identity = None;
    let effects = apply_ssh_control_event(&mut app, Some(session_id.clone()), Some(owner),
        SshEvent::GrantRequested(request.clone()));
    assert!(effects.iter().any(|effect| matches!(effect,
        Effect::SshInspectGrantTarget { request_id, .. } if request_id == "advanced")));
    request.root = Some(CANONICAL_ROOT.into());
    request.verified_identity = Some(binding(TARGET_ID, CANONICAL_ROOT).identity);
    apply_ssh_control_event(&mut app, Some(session_id.clone()), Some(owner),
        SshEvent::GrantRequested(request));
    approve(&mut app, "advanced", Some(TARGET_ID), Some(CANONICAL_ROOT));
    let mut approved = binding(TARGET_ID, CANONICAL_ROOT);
    approved.session_id = session_id.clone();
    approved.capabilities = SshCapabilities::read_only();
    let effects = apply_ssh_control_event(&mut app, Some(session_id.clone()), Some(owner),
        SshEvent::GrantResolved { request_id: "advanced".into(), approved: true, binding: Some(approved) });
    assert!(effects.iter().any(|effect| matches!(effect,
        Effect::SshUseBinding { session_id: actual, binding_id, .. }
            if actual == &session_id && binding_id == "binding-id")));
}

#[test]
fn rootless_request_browses_in_its_owner_and_cancellation_does_not_revive_it() {
    let mut app = test_app_with_agent();
    let source = AgentId(0);
    app.active_view = ActiveView::Agent(source);
    dispatch(Action::OpenSshManager, &mut app);
    let owner = ssh_manager_owner(&app).unwrap();
    let session_id = app.agents.get(&source).unwrap().ssh_manager.as_ref().unwrap()
        .session_id.clone().unwrap();
    let mut request = grant_request("rootless", TARGET_ID, "", app.ssh_client_id);
    request.session_id = session_id.clone();
    request.root = None;
    request.capabilities = SshCapabilities::read_only();
    request.verified_identity = None;
    let effects = apply_ssh_control_event(&mut app, Some(session_id.clone()), None,
        SshEvent::GrantRequested(request.clone()));
    let browse_id = effects.iter().find_map(|effect| match effect {
        Effect::SshBrowseProjectDirectory { request_id, owner: actual, .. }
            if actual == &owner => Some(*request_id),
        _ => None,
    }).expect("original request must immediately open its own folder picker");
    let InputOutcome::Action(action) =
        app.handle_input(&Event::Key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)))
    else { panic!("cancelling directory selection must cancel the original waiting request") };
    let effects = dispatch(action, &mut app);
    assert!(effects.iter().any(|effect| matches!(effect,
        Effect::SshCancelGrant { request_id, session_id: actual, .. }
            if request_id == "rootless" && actual == &session_id)));
    let client_id = app.ssh_client_id;
    apply_ssh_control_event(&mut app, Some(session_id.clone()), Some(owner),
        SshEvent::GrantCancelled {
            request_id: "rootless".into(),
            session_id: session_id.clone(),
            client_id,
        });
    let manager = app.agents.get_mut(&source).unwrap().ssh_manager.as_mut().unwrap();
    assert!(!manager.settle_project_directory(browse_id, TARGET_ID,
        Ok(xai_grok_shell::ssh::SshDirectoryListing {
            target_id: TARGET_ID.into(), identity: binding(TARGET_ID, CANONICAL_ROOT).identity,
            path: CANONICAL_ROOT.into(), parent: None, directories: vec![], truncated: false,
        })));
    request.root = Some(CANONICAL_ROOT.into());
    request.verified_identity = Some(binding(TARGET_ID, CANONICAL_ROOT).identity);
    let effects = apply_ssh_control_event(&mut app, Some(session_id.clone()), Some(owner),
        SshEvent::GrantRequested(request));
    assert!(!effects.iter().any(|effect| matches!(effect,
        Effect::SshBrowseProjectDirectory { .. } | Effect::SshInspectGrantTarget { .. })));
    assert!(app.agents.get(&source).unwrap().ssh_manager.as_ref().unwrap()
        .grant_session_id_for("rootless").is_none());
    dispatch(Action::TaskComplete(TaskResult::SshGrantInspected {
        session_id: Some(session_id), request_id: "rootless".into(),
        client_id: app.ssh_client_id, owner, result: Err("late connection failure".into()),
    }), &mut app);
    app.handle_input(&Event::Key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)));
    assert!(app.agents.get(&source).unwrap().ssh_manager.is_none(),
        "late failure must not insert a diagnostic over the cancelled manager");
}

#[test]
fn owned_grant_failure_reports_the_original_tool_and_rejects_stale_reopen() {
    let mut app = test_app_with_agent();
    let source = AgentId(0);
    app.active_view = ActiveView::Agent(source);
    dispatch(Action::OpenSshManager, &mut app);
    let owner = ssh_manager_owner(&app).unwrap();
    let session_id = app.agents.get(&source).unwrap().ssh_manager.as_ref().unwrap()
        .session_id.clone().unwrap();
    let mut request = grant_request("inspection-failed", TARGET_ID, CANONICAL_ROOT, app.ssh_client_id);
    request.session_id = session_id.clone();
    request.verified_identity = None;
    let effects = apply_ssh_control_event(
        &mut app,
        Some(session_id.clone()),
        None,
        SshEvent::GrantRequested(request.clone()),
    );
    assert!(effects.iter().any(|effect| matches!(
        effect,
        Effect::SshInspectGrantTarget { request_id, .. } if request_id == "inspection-failed"
    )));
    let effects = dispatch(
        Action::TaskComplete(TaskResult::SshGrantInspected {
            session_id: Some(session_id.clone()),
            request_id: "inspection-failed".into(),
            client_id: app.ssh_client_id,
            owner,
            result: Err("remote configuration rejected the selected target".into()),
        }),
        &mut app,
    );
    assert!(effects.iter().any(|effect| matches!(
        effect,
        Effect::SshFailGrant {
            session_id: actual,
            request_id,
            error,
            owner: actual_owner,
            ..
        } if actual == &session_id
            && request_id == "inspection-failed"
            && error == "remote configuration rejected the selected target"
            && actual_owner == &owner
    )));
    let client_id = app.ssh_client_id;
    apply_ssh_control_event(
        &mut app,
        None,
        None,
        SshEvent::GrantFailed {
            request_id: "inspection-failed".into(),
            session_id: session_id.clone(),
            client_id,
            error: "remote configuration rejected the selected target".into(),
        },
    );
    assert!(app.agents.get(&source).unwrap().ssh_manager.as_ref().unwrap()
        .grant_session_id_for("inspection-failed").is_none());
    let effects = apply_ssh_control_event(
        &mut app,
        Some(session_id),
        None,
        SshEvent::GrantRequested(request),
    );
    assert!(!effects.iter().any(|effect| matches!(
        effect,
        Effect::SshBrowseProjectDirectory { .. } | Effect::SshInspectGrantTarget { .. }
    )));
}

#[test]
fn ssh_tool_grant_resolution_closes_its_transient_prompt_after_direct_inspection() {
    for approved in [false, true] {
        let mut app = test_app_with_agent();
        let source = AgentId(0);
        app.active_view = ActiveView::Agent(source);
        let session_id = app.agents.get(&source).unwrap().session.session_id.as_ref().unwrap().to_string();
        let mut request = grant_request("waiting-tool", TARGET_ID, CANONICAL_ROOT, app.ssh_client_id);
        request.session_id = session_id.clone();
        request.awaiting_tool = true;
        request.verified_identity = None;
        apply_ssh_control_event(&mut app, Some(session_id.clone()), None,
            SshEvent::GrantRequested(request.clone()));
        let owner = ssh_manager_owner(&app).expect("tool request must automatically open consent");
        request.verified_identity = Some(binding(TARGET_ID, CANONICAL_ROOT).identity);
        apply_ssh_control_event(&mut app, Some(session_id.clone()), Some(owner),
            SshEvent::GrantRequested(request));
        let resolved_binding = if approved {
            approve(&mut app, "waiting-tool", Some(TARGET_ID), Some(CANONICAL_ROOT));
            let mut granted = binding(TARGET_ID, CANONICAL_ROOT);
            granted.session_id = session_id.clone();
            Some(granted)
        } else { None };
        apply_ssh_control_event(&mut app, Some(session_id.clone()), None,
            SshEvent::GrantResolved {
                request_id: "waiting-tool".into(), approved, binding: resolved_binding,
            });
        assert!(app.agents.get(&source).unwrap().ssh_manager.is_none(),
            "both approval and cancellation must return to the originating conversation");
        dispatch(Action::TaskComplete(TaskResult::SshGrantInspected {
            session_id: Some(session_id), request_id: "waiting-tool".into(),
            client_id: app.ssh_client_id, owner, result: Err("late inspection failure".into()),
        }), &mut app);
        assert!(app.agents.get(&source).unwrap().ssh_manager.is_none(),
            "a late inspection must not resurrect the resolved prompt");
    }
}

#[test]
fn ssh_tool_grant_resolution_preserves_an_explicit_manager() {
    let mut app = test_app_with_agent();
    let source = AgentId(0);
    app.active_view = ActiveView::Agent(source);
    dispatch(Action::OpenSshManager, &mut app);
    let owner = ssh_manager_owner(&app).unwrap();
    let session_id = app.agents.get(&source).unwrap().session.session_id.as_ref().unwrap().to_string();
    let mut request = grant_request("existing-manager", TARGET_ID, CANONICAL_ROOT, app.ssh_client_id);
    request.session_id = session_id.clone();
    request.awaiting_tool = true;
    apply_ssh_control_event(&mut app, Some(session_id.clone()), None, SshEvent::GrantRequested(request));
    apply_ssh_control_event(&mut app, Some(session_id), None,
        SshEvent::GrantResolved { request_id: "existing-manager".into(), approved: false, binding: None });
    assert_eq!(ssh_manager_owner(&app), Some(owner));
    assert!(app.agents.get(&source).unwrap().ssh_manager.as_ref().unwrap()
        .grant_session_id_for("existing-manager").is_none());
}

#[test]
fn ssh_tool_grant_authentication_stays_with_its_hidden_originating_session() {
    let mut app = test_app_with_agent();
    let source = AgentId(0);
    app.active_view = ActiveView::Agent(source);
    let session_id = app.agents.get(&source).unwrap().session.session_id.as_ref().unwrap().to_string();
    let mut request = grant_request("auth-waiting-tool", TARGET_ID, CANONICAL_ROOT, app.ssh_client_id);
    request.session_id = session_id.clone();
    request.awaiting_tool = true;
    request.verified_identity = None;
    apply_ssh_control_event(&mut app, Some(session_id.clone()), None,
        SshEvent::GrantRequested(request));
    app.active_view = ActiveView::Welcome;
    let client_id = app.ssh_client_id;
    apply_ssh_control_event(&mut app, None, None,
        SshEvent::Authentication(xai_grok_shell::ssh::SshAuthPrompt {
            client_id,
            connection_generation: 3,
            challenge_id: "grant-password".into(),
            target_id: TARGET_ID.into(),
            kind: xai_grok_shell::ssh::SshAuthPromptKind::Password,
            detail: xai_grok_shell::ssh::SshAuthPromptDetail::Secret {
                username: "fixture-user".into(),
                message: "Password required".into(),
                allow_remember: false,
            },
        }));
    assert!(app.welcome_ssh_manager.is_none(),
        "a grant's password prompt must not appear on the unrelated active Welcome view");
    let manager = app.agents.get_mut(&source).unwrap().ssh_manager.as_mut().unwrap();
    assert!(matches!(
        handle_ssh_key(manager, &KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)),
        SshModalOutcome::AnswerAuthentication { challenge_id, connection_generation: 3, .. }
            if challenge_id == "grant-password"
    ));
}
