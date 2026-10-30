use super::*;

#[cfg(unix)]
#[path = "ssh_task_routing_tests.rs"]
mod ssh_task_routing_tests;

use xai_grok_tools::implementations::grok_build::task::backend::SubagentBackend;
use xai_grok_tools::implementations::grok_build::task::coordinator::{
    ChildCompletion, ChildControl, ChildRunOutput, ChildRunRequest, ChildRunner, SendBoxFuture,
    SubagentCoordinator, SubagentProgress,
};
use xai_grok_tools::implementations::grok_build::task::types::{
    AgentMessageSenderResource, SubagentDescribeOutcome, SubagentOwner, SubagentRequest,
    SubagentValidateTypeOutcome,
};
#[cfg(unix)]
use std::collections::BTreeSet;
#[cfg(unix)]
use xai_grok_tools::implementations::grok_build::task::types::{SubagentEvent, SubagentResult};
#[cfg(unix)]
use xai_grok_tools::registry::types::ToolConfig;
#[cfg(unix)]
use xai_grok_workspace::ssh_worker::{SshWorkerService, serve_stream};
#[cfg(unix)]
use xai_grok_workspace_client::ssh::{SshClientCallbacks, SshWorkspaceClient};
#[cfg(unix)]
use xai_grok_workspace_types::ssh::{SshBinding, SshCapabilities, SshHostIdentity};
#[cfg(unix)]
use xai_grok_workspace_types::ssh_wire::{SshApprovalDecision, SshApprovalRequest};
use xai_grok_tools::types::tool::ToolKind;

struct SenderProbeRunner(tokio::sync::mpsc::UnboundedSender<Option<AgentMessageSender>>);
struct SenderProbeControl;

impl ChildControl for SenderProbeControl {
    type ProgressFuture = std::future::Ready<SubagentProgress>;
    fn progress(&self) -> Self::ProgressFuture {
        std::future::ready(Default::default())
    }
    fn cancel(&self) {}
}

impl ChildRunner for SenderProbeRunner {
    type Control = SenderProbeControl;
    type RootControl =
        xai_grok_tools::implementations::grok_build::task::root_control::NoRootControl;
    type CompletionData = ();
    type RunFuture = SendBoxFuture<ChildRunOutput<()>>;
    type ValidateFuture = SendBoxFuture<SubagentValidateTypeOutcome>;
    type DescribeFuture = SendBoxFuture<SubagentDescribeOutcome>;

    fn run(&self, run: ChildRunRequest<Self::Control>) -> Self::RunFuture {
        let sender = self.0.clone();
        Box::pin(async move {
            sender.send(run.agent_message_sender).unwrap();
            std::future::pending().await
        })
    }
    fn validate_type(&self, _: String, _: String) -> Self::ValidateFuture {
        Box::pin(std::future::pending())
    }
    fn describe_type(&self, _: String, _: Option<String>, _: String) -> Self::DescribeFuture {
        Box::pin(std::future::pending())
    }
    fn supports_wake(&self) -> bool {
        true
    }
    fn supports_agent_message_sender(&self) -> bool {
        true
    }
    fn on_completed(&self, _: ChildCompletion<()>, terminal_published: Box<dyn FnOnce() + Send>) {
        terminal_published();
    }
}

async fn mint_test_sender(owner: SubagentOwner) -> Option<AgentMessageSender> {
    let (coordinator_sender, receiver) = SubagentCoordinator::<SenderProbeRunner>::channel();
    let (sender_tx, mut sender_rx) = tokio::sync::mpsc::unbounded_channel();
    let actor = tokio::spawn(
        SubagentCoordinator::from_channel(
            receiver,
            SenderProbeRunner(sender_tx),
            Default::default(),
        )
        .run(),
    );
    let backend = xai_grok_tools::implementations::grok_build::task::backend::ChannelBackend::from_coordinator(coordinator_sender);
    let id = uuid::Uuid::now_v7().to_string();
    let spawn = tokio::spawn(async move {
        backend
            .spawn(
                SubagentRequest {
                    id,
                    prompt: "work".to_owned(),
                    description: "child".to_owned(),
                    subagent_type: "general-purpose".to_owned(),
                    parent_session_id: "root".to_owned(),
                    parent_prompt_id: None,
                    resume_from: None,
                    cwd: None,
                    runtime_overrides: Default::default(),
                    run_in_background: true,
                    surface_completion: false,
                    await_to_completion: false,
                    fork_context: false,
                    owner,
                    cancel_token: tokio_util::sync::CancellationToken::new(),
                    spawn_root: Default::default(),
                    tool_call_id: None,
                },
                None,
            )
            .await
    });
    let sender = sender_rx.recv().await.unwrap();
    actor.abort();
    spawn.abort();
    sender
}

#[tokio::test(flavor = "current_thread")]
async fn child_rebuild_rejects_coordinator_authority() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let (coordinator_sender, _receiver) =
                SubagentCoordinator::<SenderProbeRunner>::channel();
            let mut spec = test_rebuild_spec_default();
            let spec_fields = Arc::get_mut(&mut spec).unwrap();
            spec_fields.prompt_audience = PromptAudience::Subagent;
            spec_fields.subagent_coordinator_sender = Some(coordinator_sender);

            let result = spec
                .build_agent(
                    AgentDefinition::default_grok_build(),
                    xai_grok_agent::DEFAULT_SYSTEM_PROMPT_LABEL,
                )
                .await;
            assert!(matches!(result, Err(AgentBuildError::InvalidConfig(_))));
        })
        .await;
}

async fn child_agent(
    definition: AgentDefinition,
    sender: Option<AgentMessageSender>,
    active_agent_messages_enabled: bool,
) -> Agent {
    let (event_tx, _event_rx) = tokio::sync::mpsc::unbounded_channel();
    let mut spec = test_rebuild_spec_default();
    let fields = Arc::get_mut(&mut spec).unwrap();
    fields.prompt_audience = PromptAudience::Subagent;
    fields.subagent_depth = 1;
    fields.subagent_event_tx = Some(event_tx);
    fields.agent_message_sender = sender;
    fields.active_agent_messages_enabled = active_agent_messages_enabled;
    spec.build_agent(definition, xai_grok_agent::DEFAULT_SYSTEM_PROMPT_LABEL)
        .await
        .unwrap()
}

async fn assert_no_child_messaging(agent: &Agent) {
    let bridge = agent.tool_bridge();
    assert!(
        bridge
            .read_resource::<AgentMessageSenderResource>()
            .await
            .is_none()
    );
    assert!(
        bridge
            .tool_for_kind(ToolKind::ActiveAgentMessage)
            .await
            .is_none()
    );
}

#[tokio::test(flavor = "current_thread")]
async fn child_rebuild_message_authority_respects_grant_workflow_and_capability_ceiling() {
    use xai_tool_types::SubagentCapabilityMode;

    tokio::task::LocalSet::new()
        .run_until(async {
            let sender = mint_test_sender(SubagentOwner::Task)
                .await
                .expect("non-workflow child sender");
            let mut definition = AgentDefinition::default_grok_build();
            definition.capability_mode = Some(SubagentCapabilityMode::All);
            let agent = child_agent(definition.clone(), Some(sender.clone()), true).await;
            let bridge = agent.tool_bridge();
            assert!(bridge.read_resource::<AgentMessageSenderResource>().await.is_some());
            let backend = bridge
                .read_resource::<
                    xai_grok_tools::implementations::grok_build::task::backend::SubagentBackendResource,
                >()
                .await
                .unwrap();
            assert_eq!(
                backend
                    .backend()
                    .send_active_message(
                        xai_grok_tools::implementations::grok_build::task::types::ActiveAgentMessageRequest::try_new(
                            "child",
                            "follow up",
                        )
                        .unwrap(),
                    )
                    .await,
                xai_grok_tools::implementations::grok_build::task::types::ActiveAgentMessageOutcome::Unsupported,
            );
            assert!(bridge.tool_for_kind(ToolKind::ActiveAgentMessage).await.is_some());

            let ungranted = child_agent(definition.clone(), Some(sender.clone()), false).await;
            assert_no_child_messaging(&ungranted).await;
            let workflow_sender = mint_test_sender(SubagentOwner::workflow("workflow-run")).await;
            assert!(workflow_sender.is_none());
            assert_no_child_messaging(&child_agent(definition.clone(), workflow_sender, true).await)
                .await;
            // The production spawn policy filters the definition; the rebuild must not add messaging back.
            definition.capability_mode = Some(SubagentCapabilityMode::ReadOnly);
            xai_grok_subagent_resolution::apply_child_tool_policy(
                &mut definition,
                Some(SubagentCapabilityMode::ReadOnly),
                true,
            );
            assert_no_child_messaging(&child_agent(definition, Some(sender), true).await).await;
        })
        .await;
}

#[cfg(unix)]
struct ApproveSshRequests;

#[cfg(unix)]
#[async_trait::async_trait]
impl SshClientCallbacks for ApproveSshRequests {
    async fn approve(&self, _: SshApprovalRequest) -> SshApprovalDecision {
        SshApprovalDecision::Approve
    }
}

#[cfg(unix)]
struct SshBridgeFixture {
    local_root: tempfile::TempDir,
    _remote_root: tempfile::TempDir,
    remote_cwd: String,
    workspace: xai_grok_workspace::WorkspaceOps,
    server: tokio::task::JoinHandle<anyhow::Result<()>>,
}

#[cfg(unix)]
impl Drop for SshBridgeFixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}

#[cfg(unix)]
async fn ssh_bridge_fixture() -> SshBridgeFixture {
    ssh_bridge_fixture_with_callbacks(Arc::new(ApproveSshRequests)).await
}

#[cfg(unix)]
async fn ssh_bridge_fixture_with_callbacks(callbacks: Arc<dyn SshClientCallbacks>) -> SshBridgeFixture {
    let local_root = tempfile::tempdir().expect("local workspace");
    let remote_root = tempfile::tempdir().expect("remote workspace");
    std::fs::write(local_root.path().join("fixture.txt"), "local fixture\n")
        .expect("write local fixture");
    std::fs::write(remote_root.path().join("fixture.txt"), "remote fixture\n")
        .expect("write remote fixture");
    let remote_cwd = dunce::canonicalize(remote_root.path())
        .expect("canonical remote root")
        .to_string_lossy()
        .into_owned();
    let binding = SshBinding {
        id: "ssh-rebuild-test-binding".into(),
        session_id: format!("ssh-rebuild-{}", uuid::Uuid::now_v7()),
        target_id: "ssh-rebuild-test-target".into(),
        identity: SshHostIdentity {
            hostname: "test-host".into(),
            port: 22,
            username: "test-user".into(),
            fingerprint: "test-fingerprint".into(),
        },
        root: remote_cwd.clone(),
        cwd: remote_cwd.clone(),
        capabilities: SshCapabilities::all(),
        epoch: 1,
        revoked: false,
    };
    let (client_stream, worker_stream) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(serve_stream(SshWorkerService::for_test(), worker_stream));
    let client = SshWorkspaceClient::connect(
        Box::pin(client_stream),
        binding,
        callbacks,
    )
    .await
    .expect("connect SSH worker");
    SshBridgeFixture {
        local_root,
        _remote_root: remote_root,
        remote_cwd,
        workspace: xai_grok_workspace::WorkspaceOps::ssh(client),
        server,
    }
}

#[cfg(unix)]
fn ssh_rebuild_spec(
    fixture: &SshBridgeFixture,
    subagent_event_tx: Option<tokio::sync::mpsc::UnboundedSender<SubagentEvent>>,
) -> Arc<AgentRebuildSpec> {
    let mut spec = test_rebuild_spec_default();
    let fields = Arc::get_mut(&mut spec).expect("new rebuild spec has one owner");
    fields.working_directory = fixture.local_root.path().to_path_buf();
    fields.bridge_state_path = fixture.local_root.path().join("tool-state.json");
    fields.ssh_workspace = Some(fixture.workspace.clone());
    fields.subagents_enabled = subagent_event_tx.is_some();
    fields.subagent_event_tx = subagent_event_tx;
    spec
}

#[cfg(unix)]
async fn build_delegated_ssh_agent(
    spec: &Arc<AgentRebuildSpec>,
    fixture: &SshBridgeFixture,
    definition: AgentDefinition,
) -> Agent {
    let agent = spec
        .build_agent(
            definition,
            xai_grok_agent::DEFAULT_SYSTEM_PROMPT_LABEL,
        )
        .await
        .expect("build SSH project agent");
    fixture
        .workspace
        .register_remote_tools(agent.tool_bridge())
        .await
        .expect("delegate remote SSH tools");
    agent
}

#[cfg(unix)]
async fn respond_to_local_subagent_events(
    mut events: tokio::sync::mpsc::UnboundedReceiver<SubagentEvent>,
) {
    while let Some(event) = events.recv().await {
        match event {
            SubagentEvent::ValidateType(request) => {
                let _ = request.respond_to.send(SubagentValidateTypeOutcome::Ok);
            }
            SubagentEvent::Spawn(request) => {
                let _ = request.respond_with(|request| SubagentResult {
                    success: true,
                    output: Arc::from("local subagent completed"),
                    subagent_id: request.id.clone(),
                    child_session_id: request.id.clone(),
                    subagent_type: request.subagent_type.clone(),
                    ..Default::default()
                });
            }
            _ => {}
        }
    }
}

#[cfg(unix)]
async fn assert_local_spawn_subagent(agent: &Agent, call_id: &str) {
    let bridge = agent.tool_bridge();
    for id in ["GrokBuild:ssh_read", "GrokBuild:ssh_edit", "GrokBuild:ssh_run"] {
        assert!(
            bridge.tool_for_registry_id(id).is_some(),
            "explicit SSH tools must retain their local SessionSsh implementation: {id}"
        );
    }
    assert!(
        bridge
            .read_resource::<
                xai_grok_tools::implementations::grok_build::task::backend::SubagentBackendResource,
            >()
            .await
            .is_some(),
        "the local Task tool must retain its real subagent backend resource"
    );
    let task_name = bridge
        .tool_for_kind(ToolKind::Task)
        .await
        .expect("spawn_subagent remains a local tool");
    let result = bridge
        .call(
            &task_name,
            serde_json::json!({
                "description": "verify local Task ownership",
                "prompt": "Reply with the fixture marker.",
                "subagent_type": "explore",
                "background": false,
            }),
            call_id,
        )
        .await
        .expect("local spawn_subagent call");
    match result.output {
        xai_grok_tools::types::output::ToolOutput::SubagentCompleted(result) => {
            assert_eq!(result.output, "local subagent completed");
        }
        other => panic!("expected local subagent completion, got {other:?}"),
    }
}

#[cfg(unix)]
fn definition_with_renamed_read() -> AgentDefinition {
    let mut definition = AgentDefinition::default_grok_build();
    let read = definition
        .tool_config
        .tools
        .iter_mut()
        .find(|tool| tool.kind == Some(ToolKind::Read))
        .expect("default agent has a read tool");
    *read = read
        .clone()
        .with_name("remote_read_file")
        .with_param_rename("target_file", "remote_path");
    definition
}

#[cfg(unix)]
async fn assert_remote_dispatch(agent: &Agent, fixture: &SshBridgeFixture, call_suffix: &str) {
    let bridge = agent.tool_bridge();
    let read = bridge
        .call(
            "remote_read_file",
            serde_json::json!({"remote_path": "fixture.txt"}),
            &format!("ssh-read-{call_suffix}"),
        )
        .await
        .expect("renamed read dispatches to SSH worker");
    assert!(
        read.prompt_text.contains("remote fixture"),
        "expected remote file content, got:\n{}",
        read.prompt_text
    );
    assert!(
        !read.prompt_text.contains("local fixture"),
        "read must not fall back to the local filesystem: {}",
        read.prompt_text
    );
    let command = bridge
        .call(
            "run_terminal_command",
            serde_json::json!({"command": "pwd", "description": "Verify remote working directory"}),
            &format!("ssh-command-{call_suffix}"),
        )
        .await
        .expect("run_terminal_command dispatches to SSH worker");
    assert!(
        command.prompt_text.contains(&fixture.remote_cwd),
        "expected worker cwd {}, got:\n{}",
        fixture.remote_cwd,
        command.prompt_text
    );
    assert!(
        !command
            .prompt_text
            .contains(&fixture.local_root.path().display().to_string()),
        "command must not execute in local cwd: {}",
        command.prompt_text
    );
}

#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn ssh_project_rebuild_preserves_local_subagent_and_remote_dispatch() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let fixture = ssh_bridge_fixture().await;
            let (subagent_event_tx, subagent_events) = tokio::sync::mpsc::unbounded_channel();
            let responder =
                tokio::task::spawn_local(respond_to_local_subagent_events(subagent_events));
            let spec = ssh_rebuild_spec(&fixture, Some(subagent_event_tx));
            let definition = definition_with_renamed_read();

            let first =
                build_delegated_ssh_agent(&spec, &fixture, definition.clone()).await;
            assert_local_spawn_subagent(&first, "ssh-local-subagent-first").await;
            assert_remote_dispatch(&first, &fixture, "first").await;

            let rebuilt = build_delegated_ssh_agent(&spec, &fixture, definition).await;
            assert_local_spawn_subagent(&rebuilt, "ssh-local-subagent-rebuilt").await;
            assert_remote_dispatch(&rebuilt, &fixture, "rebuilt").await;
            responder.abort();
        })
        .await;
}

#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn ssh_project_unserved_remote_tool_is_removed_without_local_fallback() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let fixture = ssh_bridge_fixture().await;
            let spec = ssh_rebuild_spec(&fixture, None);
            let mut definition = AgentDefinition::default_grok_build();
            // No dependent tools: isolate worker rejection from finalization.
            definition.tool_config.tools = vec![
                ToolConfig::for_tool::<
                    xai_grok_tools::implementations::grok_build_concise::ReadFileConciseTool,
                >()
                .with_name("unsupported_remote_read"),
            ];
            let agent = build_delegated_ssh_agent(&spec, &fixture, definition).await;
            let bridge = agent.tool_bridge();
            assert!(
                bridge
                    .tool_definitions()
                    .await
                    .iter()
                    .all(|definition| definition.function.name != "unsupported_remote_read"),
                "worker-rejected remote tool must not survive as a local fallback"
            );
            assert!(
                bridge
                    .call(
                        "unsupported_remote_read",
                        serde_json::json!({"target_file": "fixture.txt"}),
                        "ssh-unserved-read",
                    )
                    .await
                    .is_err(),
                "worker-rejected remote tool must be absent from the bridge"
            );
        })
        .await;
}

#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn ssh_explore_child_configures_only_read_only_worker_tools() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let fixture = ssh_bridge_fixture().await;
            // Use the production built-in without discovering user-home overrides.
            let mut definition = AgentDefinition::explore();
            xai_grok_subagent_resolution::apply_harness_toolset(
                "explore",
                &xai_grok_subagent_resolution::HarnessToolsetContext {
                    harness_override: None,
                    parent_agent_name: None,
                    parent_model_agent_type: None,
                    file_tool_overrides: None,
                },
                &mut definition,
            );
            xai_grok_subagent_resolution::apply_child_tool_policy(&mut definition, None, false);

            let mut spec = ssh_rebuild_spec(&fixture, None);
            Arc::get_mut(&mut spec)
                .expect("unique child spec")
                .prompt_audience = PromptAudience::Subagent;
            let _agent = build_delegated_ssh_agent(&spec, &fixture, definition).await;
            let remote_names = fixture
                .workspace
                .remote_tool_definitions()
                .await
                .expect("inspect configured SSH worker toolset")
                .into_iter()
                .map(|definition| definition.function.name)
                .collect::<BTreeSet<_>>();
            assert_eq!(
                remote_names,
                BTreeSet::from([
                    "grep".to_string(),
                    "list_dir".to_string(),
                    "read_file".to_string(),
                ]),
                "the actual explore child worker toolset must exclude write and execute tools"
            );
        })
        .await;
}
