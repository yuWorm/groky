//! Session terminal for SSH projects.
//!
//! An SSH project's cwd exists only on the remote host, so the session
//! terminal (user bash mode) runs through the bound worker's
//! `run_terminal_cmd` instead of spawning a local process.

use crate::terminal::{AsyncTerminalRunner, TerminalError, TerminalRunRequest, TerminalRunResult};
use xai_grok_tools::types::output::ToolOutput;

/// Worker registry id of the terminal tool; the SSH wire accepts registry ids.
const REMOTE_TERMINAL_TOOL: &str = "GrokBuild:run_terminal_cmd";
/// Foreground ceiling enforced by the remote terminal tool.
const REMOTE_TERMINAL_MAX_TIMEOUT_MS: u64 = 300_000;

pub(crate) struct SshTerminalRunner {
    workspace: xai_grok_workspace::WorkspaceOps,
}

impl SshTerminalRunner {
    pub(crate) fn new(workspace: xai_grok_workspace::WorkspaceOps) -> Self {
        Self { workspace }
    }
}

#[async_trait::async_trait]
impl AsyncTerminalRunner for SshTerminalRunner {
    /// `request.cwd` and `request.env` describe the local machine and are not
    /// forwarded: the worker runs in its admitted remote cwd and environment.
    async fn run(&self, request: TerminalRunRequest) -> Result<TerminalRunResult, TerminalError> {
        let timeout_ms = u64::try_from(request.timeout.as_millis())
            .unwrap_or(u64::MAX)
            .clamp(1, REMOTE_TERMINAL_MAX_TIMEOUT_MS);
        let result = self
            .workspace
            .call_tool(
                REMOTE_TERMINAL_TOOL,
                serde_json::json!({
                    "command": request.command,
                    "description": request.command,
                    "timeout": timeout_ms,
                }),
                &request.tool_call_id.0,
                None,
            )
            .await
            .map_err(|error| TerminalError::Other(format!("remote command failed: {error}")))?;
        terminal_result(result.output)
    }
}

fn terminal_result(output: ToolOutput) -> Result<TerminalRunResult, TerminalError> {
    match output {
        ToolOutput::Bash(output) => Ok(TerminalRunResult {
            combined_output: String::from_utf8_lossy(&output.output).into_owned(),
            exit_code: Some(output.exit_code),
            truncated: output.truncated,
            signal: output.signal,
            timed_out: output.timed_out,
        }),
        // The remote tool moves a foreground command that outlives its timeout
        // into a remote background task; the interactive wait has timed out.
        ToolOutput::BackgroundTaskStarted(task) => Ok(TerminalRunResult {
            combined_output: format!(
                "Command is still running on the remote host as background task {}.",
                task.task_id
            ),
            exit_code: None,
            truncated: false,
            signal: None,
            timed_out: true,
        }),
        _ => Err(TerminalError::Other(
            "remote command did not return terminal output".into(),
        )),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::sync::Arc;
    use xai_grok_workspace::ssh_worker::{SshWorkerService, serve_stream};
    use xai_grok_workspace_client::ssh::{SshClientCallbacks, SshWorkspaceClient};
    use xai_grok_workspace_types::ssh::{SshBinding, SshCapabilities, SshHostIdentity};
    use xai_grok_workspace_types::ssh_wire::{SshApprovalDecision, SshApprovalRequest};

    struct Approve;
    #[async_trait::async_trait]
    impl SshClientCallbacks for Approve {
        async fn approve(&self, _: SshApprovalRequest) -> SshApprovalDecision {
            SshApprovalDecision::Approve
        }
    }

    #[tokio::test]
    async fn runs_in_the_remote_root_not_the_local_cwd() {
        let remote = tempfile::tempdir().expect("remote workspace");
        let root = dunce::canonicalize(remote.path())
            .expect("canonical remote root")
            .to_string_lossy()
            .into_owned();
        let binding = SshBinding {
            id: "binding".into(),
            session_id: "session".into(),
            target_id: "target".into(),
            identity: SshHostIdentity {
                hostname: "host".into(),
                port: 22,
                username: "user".into(),
                fingerprint: "fingerprint".into(),
            },
            root: root.clone(),
            cwd: root.clone(),
            capabilities: SshCapabilities::all(),
            epoch: 1,
            revoked: false,
        };
        let (client_stream, worker_stream) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(serve_stream(SshWorkerService::new(), worker_stream));
        let client =
            SshWorkspaceClient::connect(Box::pin(client_stream), binding, Arc::new(Approve))
                .await
                .expect("connect worker");
        let runner = SshTerminalRunner::new(xai_grok_workspace::WorkspaceOps::ssh(client));

        let result = runner
            .run(TerminalRunRequest {
                tool_call_id: agent_client_protocol::ToolCallId::from("bash-mode-1".to_owned()),
                command: "pwd".into(),
                // The local launch directory does not exist on the remote host.
                cwd: xai_grok_paths::AbsPathBuf::new(std::path::PathBuf::from(
                    "/nonexistent-local-launch-dir",
                ))
                .expect("absolute"),
                env: std::collections::HashMap::new(),
                timeout: std::time::Duration::from_secs(60 * 60),
                output_byte_limit: 1 << 20,
                stream: true,
                output_file: None,
            })
            .await
            .expect("remote command");

        assert_eq!(result.exit_code, Some(0), "{}", result.combined_output);
        assert_eq!(result.combined_output.trim(), root);
        server.abort();
    }
}
