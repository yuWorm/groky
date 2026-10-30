use super::*;
use crate::session::acp_session::support::{create_test_actor, prepare_call};
use xai_grok_tools::implementations::grok_build::task::types::{
    SubagentEvent, SubagentResult, SubagentValidateTypeOutcome,
};
use xai_grok_tools::types::tool::ToolKind;
use xai_grok_workspace::WorkspaceOps;
use xai_grok_workspace_client::ssh::{SshClientCallbacks, SshWorkspaceClient};
use xai_grok_workspace_types::ssh::{SshBinding, SshCapabilities, SshHostIdentity};
use xai_grok_workspace_types::ssh_wire::{SshApprovalDecision, SshApprovalRequest};

struct ApproveFixture;

#[async_trait::async_trait]
impl SshClientCallbacks for ApproveFixture {
    async fn approve(&self, _: SshApprovalRequest) -> SshApprovalDecision {
        SshApprovalDecision::Approve
    }
}

async fn prepared(actor: &SessionActor, name: &str, args: serde_json::Value) -> PreparedToolCall {
    prepare_call(
        actor,
        crate::sampling::types::ToolCallResponse {
            id: uuid::Uuid::now_v7().to_string(),
            kind: "function".into(),
            function: crate::sampling::types::ToolCallFunction::new(name, args.to_string()),
        },
    )
    .await
    .unwrap_or_else(|_| panic!("prepare {name}"))
}

#[tokio::test(flavor = "current_thread")]
async fn ssh_actor_dispatch_preserves_local_tools_remote_names_and_rebuild() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let local = tempfile::tempdir().unwrap();
            let remote = tempfile::tempdir().unwrap();
            std::fs::write(local.path().join("marker.txt"), "LOCAL_NOT_REMOTE").unwrap();
            std::fs::write(remote.path().join("marker.txt"), "REMOTE_ACTOR_MARKER").unwrap();
            let (gateway, _gateway_rx) = tokio::sync::mpsc::unbounded_channel();
            let (persist, _persist_rx) = tokio::sync::mpsc::unbounded_channel();
            let mut actor = create_test_actor(0, 100_000, 80, gateway, persist).await;
            let session_id = actor.session_id_string();
            let cwd = dunce::canonicalize(remote.path())
                .unwrap()
                .to_string_lossy()
                .into_owned();
            let binding = SshBinding {
                id: uuid::Uuid::now_v7().to_string(),
                session_id: session_id.clone(),
                target_id: "dispatch-fixture".into(),
                identity: SshHostIdentity {
                    hostname: "fixture".into(),
                    port: 22,
                    username: "fixture".into(),
                    fingerprint: "fixture".into(),
                },
                root: cwd.clone(),
                cwd,
                capabilities: SshCapabilities::all(),
                epoch: 1,
                revoked: false,
            };
            let (client_stream, worker_stream) = tokio::io::duplex(64 * 1024);
            let server = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(
                xai_grok_workspace::ssh_worker::serve_stream(
                    xai_grok_workspace::ssh_worker::SshWorkerService::for_test(),
                    worker_stream,
                ),
            ));
            let client = SshWorkspaceClient::connect(
                Box::pin(client_stream),
                binding,
                Arc::new(ApproveFixture),
            )
            .await
            .unwrap();
            actor.workspace_ops = WorkspaceOps::ssh(client);
            let (subagent_tx, mut subagent_rx) = tokio::sync::mpsc::unbounded_channel();
            let _children =
                tokio_util::task::AbortOnDropHandle::new(tokio::task::spawn_local(async move {
                    while let Some(event) = subagent_rx.recv().await {
                        match event {
                            SubagentEvent::ValidateType(request) => {
                                let _ = request.respond_to.send(SubagentValidateTypeOutcome::Ok);
                            }
                            SubagentEvent::Spawn(request) => {
                                let _ = request.respond_with(|request| SubagentResult {
                                    success: true,
                                    output: Arc::from("LOCAL_ACTOR_CHILD"),
                                    subagent_id: request.id.clone(),
                                    child_session_id: request.id.clone(),
                                    subagent_type: request.subagent_type.clone(),
                                    ..Default::default()
                                });
                            }
                            _ => {}
                        }
                    }
                }));
            let mut spec = crate::session::agent_rebuild::test_rebuild_spec_default();
            let fields = Arc::get_mut(&mut spec).unwrap();
            fields.working_directory = local.path().to_owned();
            fields.bridge_state_path = local.path().join("tool-state.json");
            fields.ssh_workspace = Some(actor.workspace_ops.clone());
            fields.session_id_str = session_id.clone();
            fields.subagents_enabled = true;
            fields.subagent_event_tx = Some(subagent_tx);
            let mut definition = xai_grok_agent::AgentDefinition::default_grok_build();
            let read = definition
                .tool_config
                .tools
                .iter_mut()
                .find(|tool| tool.kind == Some(ToolKind::Read))
                .unwrap();
            *read = read
                .clone()
                .with_name("remote_read_marker")
                .with_param_rename("target_file", "remote_path");
            for _ in 0..2 {
                let agent = spec
                    .build_agent(
                        definition.clone(),
                        xai_grok_agent::DEFAULT_SYSTEM_PROMPT_LABEL,
                    )
                    .await
                    .unwrap();
                actor
                    .workspace_ops
                    .register_remote_tools(agent.tool_bridge())
                    .await
                    .unwrap();
                *actor.agent.borrow_mut() = agent;
                let spawn = prepared(
                    &actor,
                    "spawn_subagent",
                    serde_json::json!({
                        "prompt": "Return the child marker", "description": "dispatch ownership",
                        "subagent_type": "explore", "background": false,
                    }),
                )
                .await;
                let result = actor.dispatch_tool(&spawn).await.unwrap();
                assert!(
                    result.prompt_text.contains("LOCAL_ACTOR_CHILD"),
                    "{}",
                    result.prompt_text
                );
                let read = prepared(
                    &actor,
                    "remote_read_marker",
                    serde_json::json!({"remote_path":"marker.txt"}),
                )
                .await;
                let result = actor.dispatch_tool(&read).await.unwrap();
                assert!(
                    result.prompt_text.contains("REMOTE_ACTOR_MARKER"),
                    "{}",
                    result.prompt_text
                );
                assert!(!result.prompt_text.contains("LOCAL_NOT_REMOTE"));
            }
            drop(server);
        })
        .await;
}
