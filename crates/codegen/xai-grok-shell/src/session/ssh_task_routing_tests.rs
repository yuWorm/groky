use super::*;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use xai_grok_tools::bridge::ToolBridge;
use xai_grok_tools::implementations::grok_build::task::coordinator::StartedChild;
use xai_grok_tools::types::output::{ToolOutput, ToolRunResult};
use xai_grok_workspace_types::ssh::SshOperation;
use xai_grok_workspace_types::ssh_wire::{SshOperationRecord, SshOperationState, SshWorkerEvent};
use xai_tool_types::{KillTaskOutput, TaskOutputOutput, TaskOutputResult};

struct RoutingControl(CancellationToken);
impl ChildControl for RoutingControl {
    type ProgressFuture = std::future::Ready<SubagentProgress>;
    fn progress(&self) -> Self::ProgressFuture {
        std::future::ready(Default::default())
    }
    fn cancel(&self) {
        self.0.cancel();
    }
}

struct RoutingRunner(mpsc::UnboundedSender<(String, oneshot::Sender<()>)>);
impl ChildRunner for RoutingRunner {
    type Control = RoutingControl;
    type RootControl =
        xai_grok_tools::implementations::grok_build::task::root_control::NoRootControl;
    type CompletionData = ();
    type RunFuture = SendBoxFuture<ChildRunOutput<()>>;
    type ValidateFuture = std::future::Ready<SubagentValidateTypeOutcome>;
    type DescribeFuture = std::future::Ready<SubagentDescribeOutcome>;

    fn run(&self, run: ChildRunRequest<Self::Control>) -> Self::RunFuture {
        let started = self.0.clone();
        Box::pin(async move {
            let id = run.request.id.clone();
            assert!(
                run.reporter
                    .started(StartedChild {
                        child_session_id: id.clone(),
                        persona: None,
                        resumed_from: None,
                        child_cwd: String::new(),
                        worktree_path: None,
                        effective_model_id: "routing-test".into(),
                        definition_background: true,
                        control: RoutingControl(run.cancellation.clone()),
                    })
                    .await
            );
            let (finish, done) = oneshot::channel();
            started.send((id.clone(), finish)).unwrap();
            let cancelled = tokio::select! {
                _ = run.cancellation.cancelled() => true,
                result = done => { result.expect("release child"); false },
            };
            ChildRunOutput {
                result: SubagentResult {
                    success: !cancelled,
                    cancelled,
                    output: Arc::from("LOCAL_SUBAGENT_RESULT"),
                    subagent_id: id.clone(),
                    child_session_id: id,
                    subagent_type: run.request.subagent_type,
                    ..Default::default()
                },
                completion_data: (),
                snapshot_ref: None,
            }
        })
    }
    fn validate_type(&self, _: String, _: String) -> Self::ValidateFuture {
        std::future::ready(SubagentValidateTypeOutcome::Ok)
    }
    fn describe_type(&self, _: String, _: Option<String>, _: String) -> Self::DescribeFuture {
        std::future::ready(SubagentDescribeOutcome::Unavailable)
    }
    fn supports_wake(&self) -> bool {
        false
    }
    fn on_completed(&self, _: ChildCompletion<()>, publish: Box<dyn FnOnce() + Send>) {
        publish();
    }
}

struct ObserveOperations(mpsc::UnboundedSender<SshOperationRecord>);
#[async_trait::async_trait]
impl SshClientCallbacks for ObserveOperations {
    async fn approve(&self, _: SshApprovalRequest) -> SshApprovalDecision {
        SshApprovalDecision::Approve
    }
    async fn on_event(&self, event: SshWorkerEvent) {
        if let SshWorkerEvent::Operation(operation) = event {
            let _ = self.0.send(operation);
        }
    }
}

struct RoutingFixture {
    ssh: SshBridgeFixture,
    spec: Arc<AgentRebuildSpec>,
    started: mpsc::UnboundedReceiver<(String, oneshot::Sender<()>)>,
    operations: mpsc::UnboundedReceiver<SshOperationRecord>,
    actor: tokio::task::JoinHandle<()>,
}
impl Drop for RoutingFixture {
    fn drop(&mut self) {
        self.actor.abort();
    }
}
impl RoutingFixture {
    async fn new() -> Self {
        let (events, operations) = mpsc::unbounded_channel();
        let ssh = ssh_bridge_fixture_with_callbacks(Arc::new(ObserveOperations(events))).await;
        let (sender, receiver) = SubagentCoordinator::<RoutingRunner>::channel();
        let (started_tx, started) = mpsc::unbounded_channel();
        let actor = tokio::task::spawn_local(
            SubagentCoordinator::from_channel(
                receiver,
                RoutingRunner(started_tx),
                Default::default(),
            )
            .run(),
        );
        let mut spec = ssh_rebuild_spec(&ssh, Some(sender.event_sender().0));
        Arc::get_mut(&mut spec).unwrap().subagent_coordinator_sender = Some(sender);
        Self {
            ssh,
            spec,
            started,
            operations,
            actor,
        }
    }
    async fn build(&self, definition: AgentDefinition) -> Agent {
        build_delegated_ssh_agent(&self.spec, &self.ssh, definition).await
    }
    async fn child(&mut self, bridge: &ToolBridge) -> (String, oneshot::Sender<()>) {
        let result = call(
            bridge,
            "spawn_subagent",
            serde_json::json!({
                "prompt": "Wait for the test release then report the local marker.",
                "description": "controlled local child", "background": true,
            }),
        )
        .await;
        let (id, finish) = self.started.recv().await.unwrap();
        assert!(result.prompt_text.contains(&id), "spawn must return the coordinator-owned task ID");
        (id, finish)
    }
    async fn command(&self, bridge: &ToolBridge, gate: &str) -> String {
        let command =
            format!("while [ ! -f '{gate}' ]; do sleep 0.02; done; printf REMOTE_COMMAND_RESULT");
        let result = call(bridge, "run_terminal_command", serde_json::json!({
            "command": command, "description": "controlled remote command", "block_until_ms": 1, "timeout": 30,
        })).await;
        let ToolOutput::BackgroundTaskStarted(task) = result.output else {
            panic!("not background: {result:?}")
        };
        task.task_id
    }
    fn release_command(&self, gate: &str) {
        std::fs::write(self.ssh._remote_root.path().join(gate), "release").unwrap();
    }
    async fn waiting_remote_read(&mut self) -> String {
        // Mixed routing first snapshots the remote subset, then starts a wait.
        // Ignore bootstrap/read operations already in the queue by draining it
        // before spawning the call under test (see clear_operations).
        let mut completed_snapshot = false;
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let operation = self.operations.recv().await.unwrap();
                if operation.operation != SshOperation::Read {
                    continue;
                }
                if operation.state.is_terminal() {
                    completed_snapshot = true;
                }
                if completed_snapshot && operation.state == SshOperationState::Running {
                    break operation.operation_id;
                }
            }
        })
        .await
        .expect("remote blocking read started")
    }
    fn clear_operations(&mut self) {
        while self.operations.try_recv().is_ok() {}
    }
    async fn terminal_operation(&mut self, id: &str) -> SshOperationRecord {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let operation = self.operations.recv().await.unwrap();
                if operation.operation_id == id && operation.state.is_terminal() {
                    break operation;
                }
            }
        })
        .await
        .expect("abandoned remote wait terminated")
    }
}

async fn call(bridge: &ToolBridge, name: &str, args: serde_json::Value) -> ToolRunResult {
    bridge
        .call(name, args, &uuid::Uuid::now_v7().to_string())
        .await
        .unwrap()
}
fn rows(result: ToolRunResult) -> Vec<TaskOutputResult> {
    match result.output {
        ToolOutput::TaskOutput(TaskOutputOutput::Result(row)) => vec![row],
        ToolOutput::TaskOutput(TaskOutputOutput::MultiResult(result)) => result.results,
        other => panic!("expected task results: {other:?}"),
    }
}
fn row<'a>(rows: &'a [TaskOutputResult], id: &str) -> &'a TaskOutputResult {
    rows.iter().find(|row| row.task_id == id).unwrap()
}
async fn kill(bridge: &ToolBridge, id: &str) {
    let output = call(
        bridge,
        "kill_command_or_subagent",
        serde_json::json!({"task_id":id}),
    )
    .await
    .output;
    assert!(
        matches!(&output, ToolOutput::KillTask(KillTaskOutput::Result(result)) if result.outcome == "killed" || result.outcome == "already_exited"),
        "{output:?}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn ssh_task_wait_any_local_completion_cancels_only_remote_wait() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut fixture = RoutingFixture::new().await;
            let agent = fixture.build(AgentDefinition::default_grok_build()).await;
            let bridge = agent.tool_bridge();
            let (local, finish) = fixture.child(bridge).await;
            let remote = fixture.command(bridge, "any-local").await;
            fixture.clear_operations();
            let waiting = {
                let bridge = bridge.clone();
                let ids = vec![remote.clone(), local.clone()];
                tokio::task::spawn_local(async move {
                    call(
                        &bridge,
                        "wait_commands_or_subagents",
                        serde_json::json!({"task_ids":ids,"mode":"wait_any","timeout_ms":10000}),
                    )
                    .await
                })
            };
            let operation = fixture.waiting_remote_read().await;
            finish.send(()).unwrap();
            let result = rows(
                tokio::time::timeout(Duration::from_secs(5), waiting)
                    .await
                    .unwrap()
                    .unwrap(),
            );
            assert_eq!(
                result
                    .iter()
                    .map(|r| r.task_id.as_str())
                    .collect::<Vec<_>>(),
                vec![remote.as_str(), local.as_str()]
            );
            assert_eq!(row(&result, &local).status, "completed");
            assert!(
                row(&result, &local)
                    .output
                    .contains("LOCAL_SUBAGENT_RESULT")
            );
            assert_eq!(row(&result, &remote).status, "running");
            let cancelled = fixture.terminal_operation(&operation).await;
            assert_ne!(
                cancelled.state,
                SshOperationState::Completed,
                "the losing waiter must be cancelled"
            );
            fixture.release_command("any-local");
            let done = rows(
                call(
                    bridge,
                    "get_command_or_subagent_output",
                    serde_json::json!({"task_ids":[remote],"timeout_ms":5000}),
                )
                .await,
            );
            assert_eq!(row(&done, &remote).status, "completed");
            assert!(row(&done, &remote).output.contains("REMOTE_COMMAND_RESULT"));
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn ssh_task_wait_any_remote_completion_and_completed_input_return_early() {
    tokio::task::LocalSet::new().run_until(async {
        let mut fixture = RoutingFixture::new().await;
        let agent = fixture.build(AgentDefinition::default_grok_build()).await;
        let bridge = agent.tool_bridge();
        let (local, _finish) = fixture.child(bridge).await;
        let remote = fixture.command(bridge, "any-remote").await;
        fixture.clear_operations();
        let waiting = {
            let bridge = bridge.clone(); let ids = vec![local.clone(), remote.clone()];
            tokio::task::spawn_local(async move { call(&bridge, "wait_commands_or_subagents", serde_json::json!({"task_ids":ids,"mode":"wait_any","timeout_ms":10000})).await })
        };
        fixture.waiting_remote_read().await;
        fixture.release_command("any-remote");
        let result = rows(tokio::time::timeout(Duration::from_secs(5), waiting).await.unwrap().unwrap());
        assert_eq!(row(&result, &remote).status, "completed");
        assert_eq!(row(&result, &local).status, "running");
        let again = tokio::time::timeout(Duration::from_secs(2), call(bridge, "wait_commands_or_subagents", serde_json::json!({"task_ids":[local,remote],"mode":"wait_any","timeout_ms":10000}))).await.expect("already-completed input satisfies any");
        assert_eq!(row(&rows(again), &local).status, "running");
        kill(bridge, &local).await;
    }).await;
}

#[tokio::test(flavor = "current_thread")]
async fn ssh_task_wait_all_and_timeout_preserve_both_tasks() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut fixture = RoutingFixture::new().await;
            let agent = fixture.build(AgentDefinition::default_grok_build()).await;
            let bridge = agent.tool_bridge();
            let (local, finish) = fixture.child(bridge).await;
            let remote = fixture.command(bridge, "all").await;
            let timed = rows(
                call(
                    bridge,
                    "get_command_or_subagent_output",
                    serde_json::json!({"task_ids":[local,remote],"timeout_ms":30}),
                )
                .await,
            );
            assert_eq!(row(&timed, &local).status, "running");
            assert_eq!(row(&timed, &remote).status, "running");
            fixture.clear_operations();
            let mut waiting = {
                let bridge = bridge.clone();
                let ids = vec![local.clone(), remote.clone()];
                tokio::task::spawn_local(async move {
                    call(
                        &bridge,
                        "wait_commands_or_subagents",
                        serde_json::json!({"task_ids":ids,"mode":"wait_all","timeout_ms":10000}),
                    )
                    .await
                })
            };
            fixture.waiting_remote_read().await;
            fixture.release_command("all");
            let remote_done = rows(
                call(
                    bridge,
                    "get_command_or_subagent_output",
                    serde_json::json!({"task_ids":[remote],"timeout_ms":5000}),
                )
                .await,
            );
            assert_eq!(row(&remote_done, &remote).status, "completed");
            assert!(
                tokio::time::timeout(Duration::from_millis(30), &mut waiting)
                    .await
                    .is_err(),
                "wait_all must still await the local child"
            );
            finish.send(()).unwrap();
            let result = rows(
                tokio::time::timeout(Duration::from_secs(5), waiting)
                    .await
                    .unwrap()
                    .unwrap(),
            );
            assert_eq!(row(&result, &local).status, "completed");
            assert_eq!(row(&result, &remote).status, "completed");
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn ssh_task_dropped_wait_releases_remote_waiter_without_cancelling_tasks() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut fixture = RoutingFixture::new().await;
            let agent = fixture.build(AgentDefinition::default_grok_build()).await;
            let bridge = agent.tool_bridge();
            let (local, _finish) = fixture.child(bridge).await;
            let remote = fixture.command(bridge, "dropped").await;
            fixture.clear_operations();
            let waiting = {
                let bridge = bridge.clone();
                let ids = vec![local.clone(), remote.clone()];
                tokio::task::spawn_local(async move {
                    call(
                        &bridge,
                        "wait_commands_or_subagents",
                        serde_json::json!({"task_ids":ids,"mode":"wait_all","timeout_ms":10000}),
                    )
                    .await
                })
            };
            let operation = fixture.waiting_remote_read().await;
            waiting.abort();
            assert!(waiting.await.unwrap_err().is_cancelled());
            fixture.terminal_operation(&operation).await;
            let result = rows(
                call(
                    bridge,
                    "get_command_or_subagent_output",
                    serde_json::json!({"task_ids":[local,remote]}),
                )
                .await,
            );
            assert_eq!(row(&result, &local).status, "running");
            assert_eq!(row(&result, &remote).status, "running");
            kill(bridge, &remote).await;
            kill(bridge, &local).await;
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn ssh_task_controls_preserve_renames_rebuild_and_subagent_only_toolsets() {
    tokio::task::LocalSet::new().run_until(async {
        let mut fixture = RoutingFixture::new().await;
        let mut definition = AgentDefinition::default_grok_build();
        for tool in &mut definition.tool_config.tools {
            if tool.kind == Some(ToolKind::BackgroundTaskAction) { *tool = tool.clone().with_name("inspect_jobs").with_param_rename("task_ids", "jobs").with_param_rename("timeout_ms", "budget"); }
            if tool.kind == Some(ToolKind::WaitTasksAction) { *tool = tool.clone().with_name("join_jobs").with_param_rename("task_ids", "jobs").with_param_rename("mode", "until"); }
            if tool.kind == Some(ToolKind::KillTaskAction) { *tool = tool.clone().with_name("stop_job").with_param_rename("task_id", "job"); }
        }
        let agent = fixture.build(definition.clone()).await;
        let (local, _finish) = fixture.child(agent.tool_bridge()).await;
        let remote = fixture.command(agent.tool_bridge(), "rename").await;
        let rebuilt = fixture.build(definition.clone()).await;
        let bridge = rebuilt.tool_bridge();
        let result = rows(call(bridge, "inspect_jobs", serde_json::json!({"jobs":[remote,local],"budget":0})).await);
        assert_eq!(row(&result, &local).status, "running");
        assert_eq!(row(&result, &remote).status, "running");
        let result = rows(call(bridge, "join_jobs", serde_json::json!({"jobs":[remote,local],"until":"wait_any","timeout_ms":0})).await);
        assert_eq!(row(&result, &remote).status, "running");
        for id in [&remote, &local] {
            let output = call(bridge, "stop_job", serde_json::json!({"job":id})).await.output;
            assert!(matches!(&output, ToolOutput::KillTask(KillTaskOutput::Result(result)) if result.outcome == "killed"), "{output:?}");
        }
        definition.tool_config.tools.retain(|tool| matches!(tool.kind, Some(ToolKind::Read | ToolKind::Task | ToolKind::BackgroundTaskAction | ToolKind::WaitTasksAction | ToolKind::KillTaskAction)));
        let restricted = fixture.build(definition).await;
        let bridge = restricted.tool_bridge();
        let (new_local, finish) = fixture.child(bridge).await;
        finish.send(()).unwrap();
        let done = rows(call(bridge, "inspect_jobs", serde_json::json!({"jobs":[new_local],"budget":5000})).await);
        assert_eq!(row(&done, &new_local).status, "completed");
        assert!(fixture.ssh.workspace.remote_tool_definitions().await.unwrap().iter().all(|definition| !["inspect_jobs","join_jobs","stop_job"].contains(&definition.function.name.as_str())));
        assert!(bridge.call("inspect_jobs", serde_json::json!({"jobs":[remote]}), "no-remote-provider").await.is_err());
    }).await;
}

#[tokio::test(flavor = "current_thread")]
async fn ssh_task_controls_never_consult_client_terminal_and_propagate_disconnect() {
    tokio::task::LocalSet::new().run_until(async {
        let mut fixture = RoutingFixture::new().await;
        // Launch a real local task before delegating this bridge.
        let agent = fixture.spec.build_agent(AgentDefinition::default_grok_build(), xai_grok_agent::DEFAULT_SYSTEM_PROMPT_LABEL).await.unwrap();
        let bridge = agent.tool_bridge();
        let local_command = call(bridge, "run_terminal_command", serde_json::json!({"command":"sleep 30", "description":"local task must remain untouched", "block_until_ms":1,"timeout":30})).await;
        let ToolOutput::BackgroundTaskStarted(local_command) = local_command.output else { panic!("local task was not backgrounded") };
        let terminal = bridge.shared_resources().await.lock().await
            .require::<xai_grok_tools::types::resources::Terminal>().unwrap().0.clone();
        fixture.ssh.workspace.register_remote_tools(bridge).await.unwrap();
        let unknown = call(bridge, "get_command_or_subagent_output", serde_json::json!({"task_ids":[local_command.task_id]})).await.output;
        assert!(matches!(unknown, ToolOutput::TaskOutput(TaskOutputOutput::TaskNotFound(_))), "{unknown:?}");
        let unknown = call(bridge, "kill_command_or_subagent", serde_json::json!({"task_id":local_command.task_id})).await.output;
        assert!(matches!(unknown, ToolOutput::KillTask(KillTaskOutput::TaskNotFound(_))), "{unknown:?}");
        assert!(!terminal.get_task(&local_command.task_id).await.unwrap().completed);
        terminal.kill_task(&local_command.task_id).await;
        let (local, finish) = fixture.child(bridge).await;
        fixture.ssh.server.abort();
        assert!(bridge.call("get_command_or_subagent_output", serde_json::json!({"task_ids":["unknown-remote",local]}), "disconnected-mixed").await.is_err());
        finish.send(()).unwrap();
        let done = rows(call(bridge, "get_command_or_subagent_output", serde_json::json!({"task_ids":[local],"timeout_ms":5000})).await);
        assert_eq!(row(&done, &local).status, "completed");
    }).await;
}
