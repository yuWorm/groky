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
    let _ = dispatch_begin_ssh_project_open(app, pending_project());
    let client_id = app.ssh_client_id;
    let _ = apply_ssh_control_event(
        app,
        Some(SESSION_ID.into()),
        None,
        SshEvent::GrantRequested(grant_request(request_id, target_id, root, client_id)),
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

    let effects = apply_ssh_control_event(
        &mut app,
        None,
        None,
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
    assert!(
        app.pending_ssh_project_open.is_none(),
        "only the matching resolution consumes the pending CLI project open"
    );
}
#[test]
fn matching_project_grant_denial_from_global_receiver_clears_pending_open() {
    let mut app = test_app();
    begin_grant(&mut app, "request-1", TARGET_ID, RAW_ROOT);

    let effects = apply_ssh_control_event(
        &mut app,
        None,
        None,
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
        app.pending_ssh_project_open.is_none(),
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
        app.pending_ssh_project_open
            .as_ref()
            .map(|project| project.project_session_id.as_str()),
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
fn wrong_resolution_session_target_or_original_root_cannot_consume_project_open() {
    let cases = [
        (
            "wrong-session",
            TARGET_ID,
            RAW_ROOT,
            "other-session",
            TARGET_ID,
            CANONICAL_ROOT,
        ),
        (
            "wrong-target",
            "other-target",
            RAW_ROOT,
            SESSION_ID,
            "other-target",
            CANONICAL_ROOT,
        ),
        (
            "wrong-root",
            TARGET_ID,
            "/var/other/project",
            SESSION_ID,
            TARGET_ID,
            "/private/var/other/project",
        ),
    ];

    for (
        request_id,
        requested_target,
        requested_root,
        resolution_session,
        binding_target,
        binding_root,
    ) in cases
    {
        let mut app = test_app();
        begin_grant(&mut app, request_id, requested_target, requested_root);
        approve(
            &mut app,
            request_id,
            Some(requested_target),
            Some(requested_root),
        );

        let effects = apply_ssh_control_event(
            &mut app,
            Some(resolution_session.into()),
            None,
            SshEvent::GrantResolved {
                request_id: request_id.into(),
                approved: true,
                binding: Some(binding(binding_target, binding_root)),
            },
        );

        assert!(
            opened_project_root(&effects).is_none(),
            "{request_id} resolution must not open a different project"
        );
        assert!(
            app.pending_ssh_project_open.is_some(),
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

    let effects = apply_ssh_control_event(
        &mut app,
        Some(SESSION_ID.into()),
        None,
        SshEvent::GrantResolved {
            request_id: "request-1".into(),
            approved: true,
            binding: Some(binding(TARGET_ID, CANONICAL_ROOT)),
        },
    );

    assert!(opened_project_root(&effects).is_none());
    assert!(
        app.pending_ssh_project_open.is_some(),
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
            .map(|index| crate::views::ssh_modal::SshTargetView {
                target_id: format!("target-{index}"),
                label: format!("Host {index}"),
                source: "Groky config".into(),
                effective_address: "user@example.test:22".into(),
                connected: false,
                connection_detail: "Not connected.".into(),
                grant: crate::views::ssh_modal::SshGrantView::NotGranted,
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
fn inherited_project_open_is_single_flight_and_reports_setup_failure_to_source_manager() {
    let mut app = test_app_with_agent();
    let source_id = AgentId(0);
    app.active_view = ActiveView::Agent(source_id);
    let opened = dispatch(Action::OpenSshManager, &mut app);
    let (_, owner) = ssh_target_list_request(&opened);
    app.agents
        .get_mut(&source_id)
        .unwrap()
        .ssh_manager
        .as_mut()
        .unwrap()
        .set_targets(vec![crate::views::ssh_modal::SshTargetView {
            target_id: TARGET_ID.into(),
            label: "Build host".into(),
            source: "Groky config".into(),
            effective_address: "user@example.test:22".into(),
            connected: true,
            connection_detail: "Connected.".into(),
            grant: crate::views::ssh_modal::SshGrantView::Granted {
                binding_id: "source-binding".into(),
                root: RAW_ROOT.into(),
                capabilities: crate::views::ssh_modal::SshCapabilitiesView::default(),
                is_default: true,
            },
        }]);
    let outcome = app.handle_input(&crossterm::event::Event::Key(KeyEvent::new(
        KeyCode::Char('o'),
        KeyModifiers::NONE,
    )));
    let crate::app::app_view::InputOutcome::Action(action) = outcome else {
        panic!("opening the selected grant must dispatch an action: {outcome:?}");
    };
    let first = dispatch(action, &mut app);
    assert!(
        first
            .iter()
            .any(|effect| matches!(effect, Effect::SshInheritBinding { owner: effect_owner, .. } if *effect_owner == owner))
    );
    assert!(
        dispatch(
            Action::OpenSshProject {
                target_id: TARGET_ID.into(),
                root: RAW_ROOT.into(),
                binding_id: "source-binding".into(),
                capabilities: crate::views::ssh_modal::SshCapabilitiesView::default(),
            },
            &mut app,
        )
        .is_empty(),
        "an in-flight inherited binding must reject repeated project opens"
    );

    dispatch(
        Action::TaskComplete(TaskResult::SshProjectBindingInheritFailed {
            source_session_id: SESSION_ID.into(),
            client_id: app.ssh_client_id,
            owner,
            error: "missing remote worker executable".into(),
        }),
        &mut app,
    );
    assert_eq!(
        app.agents
            .get(&source_id)
            .and_then(|agent| agent.ssh_manager.as_ref())
            .and_then(|manager| manager.message.as_ref())
            .map(|(message, is_error)| (message.as_str(), *is_error)),
        Some(("missing remote worker executable", true))
    );
    assert!(
        !dispatch(
            Action::OpenSshProject {
                target_id: TARGET_ID.into(),
                root: RAW_ROOT.into(),
                binding_id: "source-binding".into(),
                capabilities: crate::views::ssh_modal::SshCapabilitiesView::default(),
            },
            &mut app,
        )
        .is_empty(),
        "a terminal failure must clear the pending project-open guard"
    );
}

#[test]
fn ssh_project_session_failure_returns_full_error_to_its_source_diagnostic() {
    let mut app = test_app_with_agent();
    let source_id = AgentId(0);
    app.active_view = ActiveView::Agent(source_id);
    let opened = dispatch(Action::OpenSshManager, &mut app);
    let (_, owner) = ssh_target_list_request(&opened);
    let _ = dispatch(
        Action::OpenSshProject {
            target_id: TARGET_ID.into(),
            root: RAW_ROOT.into(),
            binding_id: "source-binding".into(),
            capabilities: crate::views::ssh_modal::SshCapabilitiesView::default(),
        },
        &mut app,
    );

    let child_id = AgentId(1);
    let mut child = AgentView::new(
        make_test_agent_session(&app, child_id, "unbound-ssh-project"),
        ScrollbackState::new(),
    );
    child.session.session_id = None;
    child.ssh_project_open_owner = Some(owner);
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
    assert_eq!(
        app.agents
            .get(&source_id)
            .and_then(|agent| agent.ssh_manager.as_ref())
            .and_then(|manager| manager.message.as_ref())
            .map(|(message, is_error)| (message.as_str(), *is_error)),
        Some((
            "Could not open SSH project: missing remote worker executable",
            true
        ))
    );
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
    let opened = dispatch(Action::OpenSshManager, &mut app);
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
    let opened = dispatch(Action::OpenSshManager, &mut app);
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
