use super::*;
use crate::notifications::{NotificationCondition, NotificationConfig, NotificationEventKind, NotificationMethod, NotificationService};
use crate::render::draw::{EscapeWriter, WriterPayload, WriterSync};
use std::sync::mpsc::{Receiver, channel};

fn capture_notifications(app: &mut AppView, condition: NotificationCondition) -> Receiver<WriterPayload> {
    let (tx, rx) = channel();
    app.notification_service = NotificationService::new(
        NotificationConfig {
            method: NotificationMethod::Bel,
            condition,
            idle_threshold_secs: 0,
            sleep_prevention: false,
            events: vec![NotificationEventKind::ApprovalRequired],
            ..Default::default()
        },
        EscapeWriter::new(tx, WriterSync::new()),
    );
    rx
}

fn deliver(app: &mut AppView, event: SshEvent) {
    dispatch(Action::TaskComplete(TaskResult::SshControlEvent {
        session_id: None, client_id: app.ssh_client_id, owner: None, event,
    }), app);
}

fn assert_alert(rx: &Receiver<WriterPayload>) {
    assert_eq!(rx.try_recv().expect("SSH wait must alert the terminal").data(), b"\x07");
    assert!(rx.try_recv().is_err(), "one challenge must emit one alert");
}

fn refresh_title(app: &mut AppView) -> Option<String> {
    app.pending_notification_escapes = None;
    app.update_notifications();
    app.pending_notification_escapes.take()
}

#[test]
fn root_approval_and_password_alert_once_each_and_submission_releases_attention() {
    let mut app = test_app_with_agent();
    app.active_view = ActiveView::Agent(AgentId(0));
    let rx = capture_notifications(&mut app, NotificationCondition::Always);
    let client_id = app.ssh_client_id;
    let approval = root_operation_approval("root-attention", "test-session", client_id);
    deliver(&mut app, SshEvent::OperationApproval(approval.clone()));
    assert_alert(&rx);
    deliver(&mut app, SshEvent::OperationApproval(approval));
    assert!(rx.try_recv().is_err(), "replayed approval must not alert twice");
    assert!(refresh_title(&mut app).unwrap().contains("Action Required"));
    let owner = ssh_manager_owner(&app).unwrap();
    dispatch(Action::ApproveSshOperation {
        approval_id: "root-attention".into(), approved: true,
        scope: xai_grok_shell::ssh::SshOperationApprovalScope::Once,
    }, &mut app);
    assert!(!refresh_title(&mut app).unwrap().contains("Action Required"));
    dispatch(Action::TaskComplete(TaskResult::SshOperationApprovalComplete {
        session_id: Some("test-session".into()), client_id, owner,
        approval_id: "root-attention".into(), expired: false, error: None,
    }), &mut app);
    let password = SshEvent::SudoAuthentication {
        session_id: "test-session".into(), operation_id: "operation-root-attention".into(),
        prompt: SshAuthPrompt {
            client_id, connection_generation: 1, challenge_id: "password-attention".into(),
            target_id: TARGET_ID.into(), session_id: None, kind: SshAuthPromptKind::SudoPassword,
            detail: SshAuthPromptDetail::Secret {
                username: "fixture".into(), message: "Root password required".into(), allow_remember: false,
            },
        },
    };
    deliver(&mut app, password.clone());
    assert_alert(&rx);
    deliver(&mut app, password);
    assert!(rx.try_recv().is_err());
    assert!(refresh_title(&mut app).unwrap().contains("Action Required"));
    let agent = app.agents.get_mut(&AgentId(0)).unwrap();
    agent.handle_input(&Event::Paste("fixture-secret".into()), &crate::actions::ActionRegistry::defaults());
    let outcome = agent.handle_input(
        &Event::Key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)),
        &crate::actions::ActionRegistry::defaults(),
    );
    let InputOutcome::Action(action) = outcome else { panic!("password Enter must submit its exact challenge") };
    dispatch(action, &mut app);
    assert!(!refresh_title(&mut app).unwrap().contains("Action Required"));
    deliver(&mut app, SshEvent::SudoAuthenticationResolved {
        client_id, session_id: "test-session".into(), challenge_id: "password-attention".into(), error: None,
    });
    assert!(!app.agents.get(&AgentId(0)).unwrap().ssh_manager.as_ref().is_some_and(|manager| manager.is_visible()));
    assert!(rx.try_recv().is_err(), "completion is not another approval request");
}

#[test]
fn submitted_grant_decisions_clear_attention_and_failed_cancel_restores_it_on_escape() {
    let mut app = test_app_with_agent();
    app.active_view = ActiveView::Agent(AgentId(0));
    let rx = capture_notifications(&mut app, NotificationCondition::Always);
    let client_id = app.ssh_client_id;
    let session_id = app
        .agents
        .get(&AgentId(0))
        .unwrap()
        .session
        .session_id
        .as_ref()
        .unwrap()
        .to_string();
    let mut request = grant_request("attention-grant", TARGET_ID, CANONICAL_ROOT, client_id);
    request.session_id = session_id.clone();
    request.awaiting_tool = true;
    deliver(&mut app, SshEvent::GrantRequested(request));
    assert_alert(&rx);
    assert!(refresh_title(&mut app).unwrap().contains("Action Required"));
    let owner = ssh_manager_owner(&app).expect("the visible grant owns its cancellation");
    let InputOutcome::Action(action) =
        app.handle_input(&Event::Key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)))
    else {
        panic!("Escape must submit the grant cancellation");
    };
    assert!(matches!(
        action,
        Action::CancelSshGrant { ref request_id } if request_id == "attention-grant"
    ));
    dispatch(action, &mut app);
    assert!(
        !refresh_title(&mut app).unwrap().contains("Action Required"),
        "a submitted cancellation must stop claiming that the request is actionable",
    );
    dispatch(
        Action::TaskComplete(TaskResult::SshGrantCancellationAcknowledged {
            session_id: session_id.clone(),
            request_id: "attention-grant".into(),
            client_id,
            owner,
            error: Some("fixture cancellation send failed".into()),
        }),
        &mut app,
    );
    assert!(
        !app.needs_user_action(),
        "the diagnostic itself is not a grant decision surface",
    );
    assert!(matches!(
        app.handle_input(&Event::Key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE))),
        InputOutcome::Changed
    ));
    assert!(
        refresh_title(&mut app).unwrap().contains("Action Required"),
        "closing a failed-cancel diagnostic must refresh the restored grant attention immediately",
    );
    assert!(
        rx.try_recv().is_err(),
        "restoring the same request must not duplicate its notification",
    );
    let InputOutcome::Action(action) =
        app.handle_input(&Event::Key(KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE)))
    else {
        panic!("n must submit an explicit grant denial");
    };
    assert!(matches!(
        action,
        Action::ApproveSshGrant {
            approved: false,
            ref request_id,
            ..
        } if request_id == "attention-grant"
    ));
    dispatch(action, &mut app);
    assert!(
        !refresh_title(&mut app).unwrap().contains("Action Required"),
        "an explicit denial in flight must not keep the grant actionable",
    );
    dispatch(
        Action::TaskComplete(TaskResult::SshActionComplete {
            session_id: Some(session_id),
            client_id,
            owner: Some(owner),
            target_id: None,
            message: None,
            error: Some("fixture denial send failed".into()),
        }),
        &mut app,
    );
    assert!(
        !app.needs_user_action(),
        "only a send failure may restore a submitted decision, first through its diagnostic",
    );
    assert!(matches!(
        app.handle_input(&Event::Key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE))),
        InputOutcome::Changed
    ));
    assert!(
        refresh_title(&mut app).unwrap().contains("Action Required"),
        "the failed explicit denial must become actionable again after its diagnostic closes",
    );
    assert!(rx.try_recv().is_err());
}

#[test]
fn background_ssh_wait_alerts_its_terminal_and_snapshot_recovery_deduplicates() {
    let mut app = test_app_with_agent();
    app.active_view = ActiveView::Welcome;
    let rx = capture_notifications(&mut app, NotificationCondition::Always);
    let approval = operation_approval("background-attention", "test-session", app.ssh_client_id);
    deliver(&mut app, SshEvent::OperationApproval(approval.clone()));
    assert_alert(&rx);
    assert_eq!(app.active_view, ActiveView::Welcome);
    assert!(refresh_title(&mut app).unwrap().contains("Action Required"));
    for generation in [1, 2] {
        dispatch(Action::TaskComplete(TaskResult::SshEventStreamRecovered {
            pump_generation: app.ssh_event_pump_generation, control_generation: generation,
            client_id: app.ssh_client_id,
            snapshot: xai_grok_shell::ssh::PendingSshInteractions {
                client_id: app.ssh_client_id, sequence: generation,
                operation_approvals: vec![approval.clone()], ..Default::default()
            },
        }), &mut app);
        assert!(rx.try_recv().is_err(), "known live requests must survive recovery without another alert");
    }
    dispatch(Action::TaskComplete(TaskResult::SshEventStreamRecovered {
        pump_generation: app.ssh_event_pump_generation, control_generation: 3,
        client_id: app.ssh_client_id,
        snapshot: xai_grok_shell::ssh::PendingSshInteractions {
            client_id: app.ssh_client_id, sequence: 3, ..Default::default()
        },
    }), &mut app);
    assert!(!refresh_title(&mut app).unwrap().contains("Action Required"));
}

#[test]
fn recovered_password_challenge_alerts_without_an_approval_replay() {
    let mut app = test_app_with_agent();
    let rx = capture_notifications(&mut app, NotificationCondition::Always);
    let snapshot = xai_grok_shell::ssh::PendingSshInteractions {
        client_id: app.ssh_client_id, sequence: 9,
        active_operation_ids: vec!["recovered-operation".into()],
        sudo_authentication: vec![xai_grok_shell::ssh::SshPendingSudoAuthentication {
            session_id: "test-session".into(), operation_id: "recovered-operation".into(),
            prompt: SshAuthPrompt {
                client_id: app.ssh_client_id, connection_generation: 4,
                challenge_id: "recovered-password".into(), target_id: TARGET_ID.into(),
                session_id: None, kind: SshAuthPromptKind::SudoPassword,
                detail: SshAuthPromptDetail::Secret {
                    username: "fixture".into(), message: "Root password required".into(), allow_remember: false,
                },
            },
        }], ..Default::default()
    };
    for generation in [1, 2] {
        dispatch(Action::TaskComplete(TaskResult::SshEventStreamRecovered {
            pump_generation: app.ssh_event_pump_generation, control_generation: generation,
            client_id: app.ssh_client_id, snapshot: snapshot.clone(),
        }), &mut app);
        if generation == 1 { assert_alert(&rx); } else { assert!(rx.try_recv().is_err()); }
    }
}

#[test]
fn ssh_alert_respects_focus_policy_and_manual_manager_is_not_attention() {
    let mut app = test_app_with_agent();
    app.active_view = ActiveView::Agent(AgentId(0));
    let rx = capture_notifications(&mut app, NotificationCondition::Unfocused);
    dispatch(Action::OpenSshManager, &mut app);
    assert!(rx.try_recv().is_err());
    assert!(!refresh_title(&mut app).unwrap().contains("Action Required"));
    let approval = operation_approval("focused-wait", "test-session", app.ssh_client_id);
    deliver(&mut app, SshEvent::OperationApproval(approval));
    assert!(rx.try_recv().is_err(), "focused terminals preserve the configured no-popup policy");
    app.notification_service.focus_tracker.on_focus_lost();
    let other = operation_approval("unfocused-wait", "test-session", app.ssh_client_id);
    deliver(&mut app, SshEvent::OperationApproval(other));
    assert_alert(&rx);
}
