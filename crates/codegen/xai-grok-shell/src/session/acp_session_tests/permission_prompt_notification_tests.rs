use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use xai_acp_lib::AcpAgentGatewaySender;

use super::support::*;
use super::*;

fn install_notification_client_hook(actor: &SessionActor) {
    let mut client_hooks = crate::extensions::hooks::ClientHooks::new();
    client_hooks.insert(
        xai_grok_hooks::event::HookEventName::Notification,
        vec![crate::extensions::hooks::ClientHookGroup {
            matcher: None,
            callback_ids: vec!["cb_permission".to_string()],
            timeout: None,
        }],
    );
    *actor.client_hooks.borrow_mut() = client_hooks;
}

async fn setup_ssh_attention_actor(
    session_id: &str,
) -> (Arc<SessionActor>, Arc<Mutex<Vec<serde_json::Value>>>) {
    let (gateway_tx, mut gateway_rx) =
        tokio::sync::mpsc::unbounded_channel::<xai_acp_lib::AcpClientMessage>();
    let (persistence_tx, _persistence_rx) =
        tokio::sync::mpsc::unbounded_channel::<PersistenceMsg>();
    let mut actor = create_test_actor(0, 256_000, 85, gateway_tx, persistence_tx).await;
    actor.session_info.id = acp::SessionId::new(session_id);
    actor.hook_resolved_workspace_root = actor.session_info.cwd.clone();
    install_notification_client_hook(&actor);
    let actor = Arc::new(actor);
    let captured = Arc::new(Mutex::new(Vec::new()));
    let captured_hooks = captured.clone();
    tokio::task::spawn_local(async move {
        while let Some(message) = gateway_rx.recv().await {
            if let xai_acp_lib::AcpClientMessage::ExtNotification(args) = message
                && args.request.method.as_ref() == "x.ai/hooks/event"
            {
                let params: serde_json::Value =
                    serde_json::from_str(args.request.params.get()).unwrap();
                if params.get("notificationType")
                    == Some(&serde_json::json!("permission_prompt"))
                {
                    captured_hooks.lock().unwrap().push(params);
                }
            }
        }
    });
    (actor, captured)
}

async fn wait_for_hook_count(captured: &Arc<Mutex<Vec<serde_json::Value>>>, count: usize) {
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        while captured.lock().unwrap().len() < count {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("permission_prompt hook must arrive");
}

async fn setup_actor(
    yolo: bool,
    park_until_hook: bool,
) -> (Arc<SessionActor>, Arc<AtomicUsize>, tokio::task::LocalSet) {
    setup_actor_with_pre_tool_use_hook(yolo, park_until_hook, None).await
}

async fn setup_actor_with_pre_tool_use_hook(
    yolo: bool,
    park_until_hook: bool,
    pre_tool_use_script: Option<&str>,
) -> (Arc<SessionActor>, Arc<AtomicUsize>, tokio::task::LocalSet) {
    let local = tokio::task::LocalSet::new();
    let (actor, hooks) = local
        .run_until(async {
            let (gateway_tx, gateway_rx) =
                tokio::sync::mpsc::unbounded_channel::<xai_acp_lib::AcpClientMessage>();
            let hook_gateway = AcpAgentGatewaySender::new(gateway_tx.clone());
            let (persistence_tx, _persistence_rx) =
                tokio::sync::mpsc::unbounded_channel::<PersistenceMsg>();
            let mut actor = create_test_actor(0, 256_000, 85, gateway_tx, persistence_tx).await;
            *actor.agent.borrow_mut() = test_agent_with_tools(read_and_edit_toolset()).await;
            install_permission_manager(&mut actor, yolo, hook_gateway);
            install_notification_client_hook(&actor);
            if let Some(script) = pre_tool_use_script {
                install_pre_tool_use_hooks(
                    &mut actor,
                    vec![pre_tool_use_spec("test/ask", None, script)],
                );
            }
            let actor = Arc::new(actor);
            actor.wire_permission_prompt_notification();
            let hooks = Arc::new(AtomicUsize::new(0));
            spawn_gateway_loop_counting_prompt_hooks(gateway_rx, hooks.clone(), park_until_hook);
            (actor, hooks)
        })
        .await;
    (actor, hooks, local)
}

#[tokio::test(flavor = "current_thread")]
async fn ssh_tool_grant_hook_uses_only_its_originating_session_once_and_excludes_reason() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (source, source_hooks) = setup_ssh_attention_actor("source-session").await;
            let (other, other_hooks) = setup_ssh_attention_actor("other-session").await;
            let source_session_id = source.session_id_string();
            let other_session_id = other.session_id_string();
            assert_ne!(source_session_id, other_session_id);

            let home = tempfile::tempdir().unwrap();
            let marker = home.path().join("permission-prompt.json");
            let mut spec = pre_tool_use_spec(
                "test/ssh-wait",
                Some("permission_prompt"),
                "cat > \"$SSH_NOTIFICATION_MARKER\"",
            );
            spec.event = xai_grok_hooks::event::HookEventName::Notification;
            spec.extra_env.insert(
                "SSH_NOTIFICATION_MARKER".into(),
                marker.to_string_lossy().into_owned(),
            );
            let (mut registry, _) = xai_grok_hooks::discovery::load_hooks(None, None);
            registry.append_specs(vec![spec]);
            *source.hook_registry.borrow_mut() = Some(Arc::new(registry));
            let service = Arc::new(crate::ssh::SessionSsh::new(home.path().to_owned()));
            source.wire_ssh_attention_notifications(&service);
            other.wire_ssh_attention_notifications(&service);
            let mut events = service.subscribe_events();
            let request_service = service.clone();
            let request_session_id = source_session_id.clone();
            let request = tokio::task::spawn_local(async move {
                request_service
                    .request_tool_grant(
                        request_session_id,
                        None,
                        None,
                        crate::ssh::SshCapabilities::all(),
                        "SSH_RAW_SECRET_MARKER".into(),
                        Some(7),
                        None,
                    )
                    .await
            });

            let request_id = match events.recv().await.unwrap() {
                crate::ssh::SshEvent::GrantRequested(request) => request.id,
                event => panic!("expected tool grant request, got {event:?}"),
            };
            wait_for_hook_count(&source_hooks, 1).await;
            let hooks = source_hooks.lock().unwrap().clone();
            assert_eq!(hooks.len(), 1);
            assert_eq!(hooks[0]["sessionId"], source_session_id);
            assert_eq!(hooks[0]["notificationType"], "permission_prompt");
            assert_eq!(hooks[0]["message"], "SSH access approval requested");
            assert!(
                !serde_json::to_string(&hooks).unwrap().contains("SSH_RAW_SECRET_MARKER"),
                "the hook event must not include the model's access reason"
            );
            assert!(
                other_hooks.lock().unwrap().is_empty(),
                "a shared SSH service must not broadcast the hook to another session"
            );
            let command_event: serde_json::Value =
                tokio::time::timeout(std::time::Duration::from_secs(5), async {
                    loop {
                        if let Ok(bytes) = tokio::fs::read(&marker).await
                            && let Ok(event) = serde_json::from_slice(&bytes)
                        {
                            break event;
                        }
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .expect("the configured permission_prompt command must execute");
            assert_eq!(command_event["sessionId"], source_session_id);
            assert_eq!(command_event["notificationType"], "permission_prompt");
            assert_eq!(command_event["message"], "SSH access approval requested");
            assert!(!command_event.to_string().contains("SSH_RAW_SECRET_MARKER"));

            service
                .cancel_grant(&source_session_id, &request_id, 7)
                .await
                .unwrap();
            assert!(matches!(
                request.await.unwrap(),
                Err(crate::ssh::SshServiceError::GrantCancelled)
            ));
            tokio::task::yield_now().await;
            assert_eq!(
                source_hooks.lock().unwrap().len(),
                1,
                "terminal grant events must not replay the permission_prompt hook"
            );
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn auto_allowed_tool_does_not_fire_permission_prompt_notification() {
    let (actor, hooks, local) = setup_actor(/*yolo=*/ false, /*park_until_hook=*/ false).await;
    local
        .run_until(async {
            let result = prepare_call(&actor, read_file_call("call_safe")).await;
            assert!(
                result.is_ok(),
                "read must auto-allow; got {:?}",
                result.err()
            );
            drain_gateway_turns().await;
            assert_eq!(
                hooks.load(Ordering::SeqCst),
                0,
                "auto-allowed tool permission must not fire permission_prompt"
            );
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn real_user_prompt_fires_permission_prompt_notification() {
    let (actor, hooks, local) = setup_actor(/*yolo=*/ false, /*park_until_hook=*/ true).await;
    local
        .run_until(async {
            let result = prepare_call(&actor, search_replace_call("call_unsafe")).await;
            assert!(
                result.is_ok(),
                "prompted allow-once must prepare; got {:?}",
                result.err()
            );
            assert_eq!(
                hooks.load(Ordering::SeqCst),
                1,
                "a real user permission prompt must fire permission_prompt once"
            );
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn inherited_handle_second_wire_does_not_steal_parent_hook() {
    let (parent, hooks, local) = setup_actor(/*yolo=*/ false, /*park_until_hook=*/ true).await;
    local
        .run_until(async {
            let (child_gateway_tx, child_gateway_rx) =
                tokio::sync::mpsc::unbounded_channel::<xai_acp_lib::AcpClientMessage>();
            let (persistence_tx, _persistence_rx) =
                tokio::sync::mpsc::unbounded_channel::<PersistenceMsg>();
            let mut child =
                create_test_actor(0, 256_000, 85, child_gateway_tx, persistence_tx).await;
            child.startup_hints.is_subagent = true;
            child.permissions = parent.permissions.clone();
            install_notification_client_hook(&child);
            let child = Arc::new(child);
            child.wire_permission_prompt_notification();
            let (steal_tx, _steal_rx) = tokio::sync::mpsc::unbounded_channel();
            child.permissions.set_user_prompt_notify(steal_tx);
            drop(child_gateway_rx);

            let result = prepare_call(&parent, search_replace_call("call_shared")).await;
            assert!(
                result.is_ok(),
                "prompted allow-once must prepare; got {:?}",
                result.err()
            );
            assert_eq!(
                hooks.load(Ordering::SeqCst),
                1,
                "parent hook must still fire once after a cloned handle tries to re-wire"
            );
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn yolo_tool_does_not_fire_permission_prompt_notification() {
    let (actor, hooks, local) = setup_actor(/*yolo=*/ true, /*park_until_hook=*/ false).await;
    local
        .run_until(async {
            let result = prepare_call(&actor, search_replace_call("call_yolo")).await;
            assert!(
                result.is_ok(),
                "yolo must auto-allow; got {:?}",
                result.err()
            );
            drain_gateway_turns().await;
            assert_eq!(
                hooks.load(Ordering::SeqCst),
                0,
                "yolo auto-approve must not fire permission_prompt"
            );
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn hook_ask_under_yolo_fires_permission_prompt_notification() {
    let (actor, hooks, local) = setup_actor_with_pre_tool_use_hook(
        /*yolo=*/ true,
        /*park_until_hook=*/ true,
        Some(r#"echo '{"hookSpecificOutput":{"permissionDecision":"ask"}}'"#),
    )
    .await;
    local
        .run_until(async {
            let result = prepare_call(&actor, search_replace_call("call_hook_ask")).await;
            assert!(
                result.is_ok(),
                "the forced prompt was approved, so the call must run; got {:?}",
                result.err()
            );
            assert_eq!(
                hooks.load(Ordering::SeqCst),
                1,
                "a hook ask forces a real prompt, so permission_prompt must fire once"
            );
        })
        .await;
}
