use super::*;
use crate::session::commands::{NotificationSource, SessionCommand};
use crate::tools::notification_bridge::{spawn_notification_bridge, tests::make_test_config_full};
use tokio::sync::mpsc;
use xai_grok_agent::{Agent, AgentDefinition};
use xai_grok_tools::notification::{MonitorEvent, ToolNotification};
use xai_grok_tools::types::output::ToolOutput;
use xai_tool_types::KillTaskOutput;

struct MonitorCallbacks(WorkerCallbacks);

#[async_trait]
impl SshClientCallbacks for MonitorCallbacks {
    async fn on_event(&self, event: SshWorkerEvent) {
        self.0.on_event(event).await;
    }
    async fn approve(&self, _: SshApprovalRequest) -> SshApprovalDecision {
        SshApprovalDecision::Approve
    }
}

struct MonitorFixture {
    _home: tempfile::TempDir,
    remote: tempfile::TempDir,
    service: SessionSsh,
    binding: SshBinding,
    workspace: xai_grok_workspace::WorkspaceOps,
    spec: Arc<crate::session::agent_rebuild::AgentRebuildSpec>,
    callbacks: Arc<MonitorCallbacks>,
    commands: mpsc::UnboundedReceiver<SessionCommand>,
    gateway: mpsc::UnboundedReceiver<xai_acp_lib::AcpClientMessage>,
    _persistence: mpsc::UnboundedReceiver<crate::session::persistence::PersistenceMsg>,
    _server: tokio_util::task::AbortOnDropHandle<anyhow::Result<()>>,
}

impl MonitorFixture {
    async fn new() -> Self {
        let home = tempfile::tempdir().unwrap();
        let remote = tempfile::tempdir().unwrap();
        let root = dunce::canonicalize(remote.path())
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let session = uuid::Uuid::now_v7().to_string();
        let binding = SshBinding {
            id: uuid::Uuid::now_v7().to_string(),
            session_id: session.clone(),
            target_id: "monitor-fixture".into(),
            identity: SshHostIdentity {
                hostname: "fixture".into(),
                port: 22,
                username: "fixture".into(),
                fingerprint: "fixture".into(),
            },
            root: root.clone(),
            cwd: root,
            capabilities: SshCapabilities::all(),
            epoch: 1,
            revoked: false,
        };
        let service = SessionSsh::new(home.path().to_owned());
        service
            .restore_session(
                &session,
                PersistedSshState {
                    grants: vec![PersistedSshGrant {
                        binding: binding.clone(),
                        parent_binding_id: None,
                        requires_revalidation: false,
                        scope: SshGrantScope::CurrentSession,
                        revoke_status: None,
                        worker_bound: false,
                        worker_commands: Vec::new(),
                    }],
                    default_binding_id: Some(binding.id.clone()),
                    pending_requests: Vec::new(),
                },
            )
            .await;
        let callbacks = Arc::new(MonitorCallbacks(WorkerCallbacks {
            service: Arc::downgrade(&service.inner),
            client_id: None,
            binding: binding.clone(),
            target_epoch: service.target_config_epoch(),
            allow_session: false,
        }));
        let (stream, peer) = tokio::io::duplex(64 * 1024);
        let server = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(
            xai_grok_workspace::ssh_worker::serve_stream(
                xai_grok_workspace::ssh_worker::SshWorkerService::for_test(),
                peer,
            ),
        ));
        let client =
            SshWorkspaceClient::connect(Box::pin(stream), binding.clone(), callbacks.clone())
                .await
                .unwrap();
        let workspace = xai_grok_workspace::WorkspaceOps::ssh(client);
        let (mut config, gateway, persistence, commands) = make_test_config_full();
        config.session_id = agent_client_protocol::SessionId::new(session.clone());
        config.auto_wake_enabled = false;
        config
            .emit_local_background_tasks
            .store(false, Ordering::Release);
        let handle = spawn_notification_bridge(config);
        let mut spec = crate::session::agent_rebuild::test_rebuild_spec_default();
        let fields = Arc::get_mut(&mut spec).unwrap();
        fields.working_directory = home.path().to_owned();
        fields.bridge_state_path = home.path().join("tools.json");
        fields.ssh_workspace = Some(workspace.clone());
        fields.session_id_str = session;
        fields.tools_notification_handle = handle;
        Self {
            _home: home,
            remote,
            service,
            binding,
            workspace,
            spec,
            callbacks,
            commands,
            gateway,
            _persistence: persistence,
            _server: server,
        }
    }

    async fn build(&self, previous: Option<&Agent>) -> Agent {
        let agent = self
            .spec
            .build_agent(
                AgentDefinition::default_grok_build(),
                xai_grok_agent::DEFAULT_SYSTEM_PROMPT_LABEL,
            )
            .await
            .unwrap();
        if let Some(previous) = previous {
            let relay = previous
                .tool_bridge()
                .read_resource::<crate::ssh::RemoteNotifications>()
                .await
                .unwrap();
            agent.tool_bridge().update_resource(relay).await;
        } else {
            self.service
                .attach_project_notifications(agent.tool_bridge(), &self.workspace)
                .await
                .unwrap();
        }
        self.workspace
            .register_remote_tools(agent.tool_bridge())
            .await
            .unwrap();
        agent
    }

    async fn monitor(&self, agent: &Agent) -> String {
        let result = agent.tool_bridge().call("monitor", serde_json::json!({
            "command": "while [ ! -f release ]; do sleep 0.02; done; cat marker.txt; while [ ! -f finish ]; do sleep 0.02; done",
            "description": "remote fixture monitor", "timeout_ms": 10000,
        }), &uuid::Uuid::now_v7().to_string()).await.unwrap();
        let ToolOutput::Monitor(monitor) = result.output else {
            panic!("{result:?}")
        };
        monitor.task_id
    }

    async fn wake(&mut self) -> SessionCommand {
        tokio::time::timeout(Duration::from_secs(5), self.commands.recv())
            .await
            .unwrap()
            .unwrap()
    }

    async fn gateway_event(&mut self, method: &str) -> serde_json::Value {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match self.gateway.recv().await.unwrap() {
                    xai_acp_lib::AcpClientMessage::ExtNotification(message)
                        if message.request.method.as_ref() == method =>
                    {
                        break serde_json::from_str(message.request.params.get()).unwrap();
                    }
                    xai_acp_lib::AcpClientMessage::SessionNotification(message) => {
                        let _ = message.response_tx.send(Ok(()));
                    }
                    _ => {}
                }
            }
        })
        .await
        .unwrap()
    }
}

#[tokio::test(flavor = "current_thread")]
async fn ssh_monitor_events_wake_after_return_and_rebuild_then_complete_once() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut fixture = MonitorFixture::new().await;
            std::fs::write(
                fixture.remote.path().join("marker.txt"),
                "REMOTE_MONITOR_MARKER\n",
            )
            .unwrap();
            std::fs::write(
                fixture._home.path().join("marker.txt"),
                "LOCAL_MUST_NOT_BE_MONITORED\n",
            )
            .unwrap();
            let first = fixture.build(None).await;
            let id = fixture.monitor(&first).await;
            fixture.gateway_event("x.ai/task_backgrounded").await;
            let replacement = fixture.build(Some(&first)).await;
            drop(first);
            std::fs::write(fixture.remote.path().join("release"), "go").unwrap();
            match fixture.wake().await {
                SessionCommand::InjectNotification {
                    source: NotificationSource::MonitorEvent { task_id },
                    prompt_blocks,
                    ..
                } => {
                    assert_eq!(task_id, id);
                    let text = serde_json::to_string(&prompt_blocks).unwrap();
                    assert!(text.contains("REMOTE_MONITOR_MARKER"), "{text}");
                    assert!(!text.contains("LOCAL_MUST_NOT_BE_MONITORED"));
                }
                _ => panic!("expected monitor wake"),
            }
            fixture.gateway_event("x.ai/monitor_event").await;
            assert!(
                fixture.commands.try_recv().is_err(),
                "bridge replacement must not duplicate the event"
            );
            std::fs::write(fixture.remote.path().join("finish"), "done").unwrap();
            match fixture.wake().await {
                SessionCommand::InjectNotification {
                    source: NotificationSource::MonitorCompleted { task_id },
                    ..
                } => assert_eq!(task_id, id),
                _ => panic!("expected natural monitor completion"),
            }
            fixture.gateway_event("x.ai/task_completed").await;
            assert!(matches!(
                fixture.commands.try_recv().unwrap(),
                SessionCommand::DispatchNotificationHook { .. }
            ));
            assert!(fixture.commands.try_recv().is_err());
            drop(replacement);
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn ssh_monitor_explicit_kill_completes_without_another_wake() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut fixture = MonitorFixture::new().await;
            let agent = fixture.build(None).await;
            let id = fixture.monitor(&agent).await;
            fixture.gateway_event("x.ai/task_backgrounded").await;
            let result = agent
                .tool_bridge()
                .call(
                    "kill_command_or_subagent",
                    serde_json::json!({"task_id": id}),
                    &uuid::Uuid::now_v7().to_string(),
                )
                .await
                .unwrap();
            assert!(
                matches!(&result.output, ToolOutput::KillTask(KillTaskOutput::Result(killed))
                    if killed.outcome == "killed"),
                "{result:?}"
            );
            let completed = fixture.gateway_event("x.ai/task_completed").await;
            let snapshot = &completed["update"]["task_snapshot"];
            assert_eq!(snapshot["task_id"], id);
            assert_eq!(snapshot["explicitly_killed"], true);
            assert_eq!(snapshot["kill_result_delivered"], true);
            assert!(matches!(
                fixture.commands.try_recv().unwrap(),
                SessionCommand::DispatchNotificationHook { .. }
            ));
            assert!(
                fixture.commands.try_recv().is_err(),
                "a delivered kill must not wake the model"
            );
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn ssh_monitor_rejects_foreign_owner_binding_revocation_and_released_bridge() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut fixture = MonitorFixture::new().await;
            let agent = fixture.build(None).await;
            let payload = |owner: &str| {
                serde_json::to_value(ToolNotification::MonitorEvent(MonitorEvent {
                    task_id: "same-task-id".into(),
                    description: "isolated".into(),
                    event_text: "owned event".into(),
                    raw_text: "owned event".into(),
                    owner_session_id: Some(owner.into()),
                }))
                .unwrap()
            };
            let event = |notification| SshWorkerEvent::ToolNotification {
                operation_id: "same-operation-id".into(),
                notification,
            };
            fixture
                .callbacks
                .on_event(event(payload("foreign-session")))
                .await;
            let other = WorkerCallbacks {
                service: Arc::downgrade(&fixture.service.inner),
                client_id: None,
                binding: SshBinding {
                    id: "foreign-binding".into(),
                    ..fixture.binding.clone()
                },
                target_epoch: 0,
                allow_session: false,
            };
            other
                .on_event(event(payload(&fixture.binding.session_id)))
                .await;
            fixture
                .callbacks
                .on_event(event(serde_json::json!({"type":"MonitorEvent"})))
                .await;
            assert!(fixture.commands.try_recv().is_err());
            fixture
                .callbacks
                .on_event(event(payload(&fixture.binding.session_id)))
                .await;
            assert!(matches!(
                fixture.wake().await,
                SessionCommand::InjectNotification {
                    source: NotificationSource::MonitorEvent { .. },
                    ..
                }
            ));
            fixture.gateway_event("x.ai/monitor_event").await;
            fixture
                .service
                .inner
                .sessions
                .write()
                .await
                .get_mut(&fixture.binding.session_id)
                .unwrap()
                .grants
                .get_mut(&fixture.binding.id)
                .unwrap()
                .persisted
                .binding
                .revoked = true;
            fixture
                .callbacks
                .on_event(event(payload(&fixture.binding.session_id)))
                .await;
            assert!(fixture.commands.try_recv().is_err());
            fixture
                .service
                .inner
                .sessions
                .write()
                .await
                .get_mut(&fixture.binding.session_id)
                .unwrap()
                .grants
                .get_mut(&fixture.binding.id)
                .unwrap()
                .persisted
                .binding
                .revoked = false;
            drop(agent);
            fixture
                .callbacks
                .on_event(event(payload(&fixture.binding.session_id)))
                .await;
            assert!(
                fixture.commands.try_recv().is_err(),
                "SSH service must not retain a closed session sink"
            );
        })
        .await;
}
