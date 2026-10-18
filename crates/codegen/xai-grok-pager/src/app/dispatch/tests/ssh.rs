//! Deterministic routing tests for the SSH project-grant correlation boundary.

use super::*;
use crate::app::cli::SshProjectOpen;
use crate::app::dispatch::ssh::{
    apply_ssh_control_event, close_transient_ssh_manager_for_session,
    dispatch_approve_ssh_grant, dispatch_begin_ssh_project_open,
    existing_ssh_manager_for_session_mut, ssh_manager_for_session_mut,
    ssh_manager_for_target_list_session_mut,
};
use crate::views::ssh_modal::SshGrantLifetime;
use xai_grok_shell::ssh::{
    SshBinding, SshCapabilities, SshEvent, SshGrantRequest, SshHostIdentity,
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
        SshEvent::GrantRequested(grant_request(request_id, target_id, root, client_id)),
    );
}

fn approve(
    app: &mut AppView,
    request_id: &str,
    target_id: Option<&str>,
    root: Option<&str>,
) {
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
    close_transient_ssh_manager_for_session(&mut app, Some(SESSION_ID));
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
    assert_eq!(
        ssh_manager_for_target_list_session_mut(&mut app, Some("minted-child-session"))
            .map(|manager| manager.session_id.as_deref()),
        Some(Some(SESSION_ID)),
        "the target-list completion must find the cold child's source-owned manager"
    );
    assert!(
        ssh_manager_for_target_list_session_mut(&mut app, Some("untrusted-session")).is_none(),
        "an unrelated child session must not consume the displayed grant's target result"
    );
    let mut child_binding = binding(TARGET_ID, "/private/var/fixture/worktree");
    child_binding.session_id = "minted-child-session".into();
    let _ = apply_ssh_control_event(
        &mut app,
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
    close_transient_ssh_manager_for_session(&mut app, Some("minted-child-session"));
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
        ("wrong-session", TARGET_ID, RAW_ROOT, "other-session", TARGET_ID, CANONICAL_ROOT),
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

    for (request_id, requested_target, requested_root, resolution_session, binding_target, binding_root) in
        cases
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
