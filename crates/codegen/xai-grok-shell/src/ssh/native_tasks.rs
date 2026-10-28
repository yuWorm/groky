//! Local accounting for generation-bound SSH commands. No remote daemon, replay,
//! or promise that a disconnected remote process has stopped.
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::{Mutex, mpsc, oneshot};
use uuid::Uuid;
use xai_grok_ssh::{SshCommand, SshCommandEvent};
use xai_grok_tools::implementations::grok_build::bash::BashToolInput;
use xai_grok_workspace_client::ssh::SshClientCallbacks;
use xai_grok_workspace_types::ssh::{ResolvedSshInvocation, SshBinding};
use xai_grok_workspace_types::ssh_wire::{
    SshCancellation, SshOperationRecord, SshOperationState, SshTaskRecord, SshToolProgress,
    SshWireError, SshWorkerEvent,
};

use super::{SshDispatchRequest, SshDispatchResult};

const MAX_OPERATIONS: usize = 1024;
const MAX_STREAM_BYTES: usize = 64 * 1024;

#[derive(Default)]
pub(super) struct NativeOperations {
    entries: Mutex<HashMap<String, Arc<NativeOperation>>>,
}

pub(super) struct NativeOperation {
    pub id: String,
    client_id: Option<u64>,
    invocation: ResolvedSshInvocation,
    command: Option<String>,
    state: Mutex<OperationState>,
}
struct OperationState {
    record: SshOperationRecord,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    truncated: bool,
    exit_code: Option<u32>,
    cancel: Option<mpsc::Sender<()>>,
    result: Option<SshDispatchResult>,
}

impl NativeOperations {
    pub(super) async fn reserve(
        &self,
        request: &SshDispatchRequest,
        client_id: Option<u64>,
    ) -> Result<Arc<NativeOperation>, String> {
        let mut entries = self.entries.lock().await;
        for entry in entries.values() {
            if entry.invocation.session_id == request.invocation.session_id
                && entry.invocation.binding_id == request.invocation.binding_id
                && entry.invocation.call_id == request.invocation.call_id
            {
                return Err(format!(
                    "Operation already submitted as {}; query it rather than replaying",
                    entry.id
                ));
            }
        }
        if entries.len() >= MAX_OPERATIONS {
            return Err("SSH operation history is full for this local service; start a new service before submitting more operations".into());
        }
        let id = format!("ssh-native-{}", Uuid::now_v7());
        let entry = Arc::new(NativeOperation {
            id: id.clone(),
            client_id,
            invocation: request.invocation.clone(),
            command: if request.tool_name == "GrokBuild:run_terminal_cmd" {
                Some(
                    request
                        .args
                        .get("command")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_owned(),
                )
            } else {
                None
            },
            state: Mutex::new(OperationState {
                record: SshOperationRecord {
                    operation_id: id.clone(),
                    mutation_id: request.mutation_id.clone(),
                    binding_id: request.invocation.binding_id.clone(),
                    session_id: request.invocation.session_id.clone(),
                    operation: request.invocation.operation,
                    state: SshOperationState::Pending,
                    result: None,
                    post_hook: None,
                    error: None,
                },
                stdout: Vec::new(),
                stderr: Vec::new(),
                truncated: false,
                exit_code: None,
                cancel: None,
                result: None,
            }),
        });
        entries.insert(id, entry.clone());
        Ok(entry)
    }

    /// Nonterminal operations owned by one interactive local client. The
    /// caller must validate each invocation against its current session
    /// binding before treating an ID as live.
    pub(super) async fn active_operations_for_client(
        &self,
        client_id: u64,
    ) -> Vec<(String, ResolvedSshInvocation)> {
        let entries = self
            .entries
            .lock()
            .await
            .values()
            .filter(|entry| entry.client_id == Some(client_id))
            .cloned()
            .collect::<Vec<_>>();
        let mut operations = Vec::new();
        for entry in entries {
            if !entry.state.lock().await.record.state.is_terminal() {
                operations.push((entry.id.clone(), entry.invocation.clone()));
            }
        }
        operations.sort_by(|left, right| left.0.cmp(&right.0));
        operations
    }

    pub(super) async fn active_ids_for_client(&self, client_id: u64) -> Vec<String> {
        self.active_operations_for_client(client_id)
            .await
            .into_iter()
            .map(|(id, _)| id)
            .collect()
    }

    async fn owned(
        &self,
        binding: &SshBinding,
        id: &str,
        cancelling: bool,
    ) -> Option<Arc<NativeOperation>> {
        self.entries
            .lock()
            .await
            .get(id)
            .filter(|entry| {
                entry.invocation.binding_id == binding.id
                    && entry.invocation.session_id == binding.session_id
                    && (entry.invocation.epoch == binding.epoch
                        || (cancelling
                            && binding.revoked
                            && entry.invocation.epoch.checked_add(1) == Some(binding.epoch)))
            })
            .cloned()
    }

    pub(super) async fn query(&self, binding: &SshBinding, id: &str) -> Option<SshDispatchResult> {
        Some(self.owned(binding, id, false).await?.snapshot().await)
    }

    pub(super) async fn list(&self, binding: &SshBinding) -> Vec<SshTaskRecord> {
        let entries: Vec<_> = self
            .entries
            .lock()
            .await
            .values()
            .filter(|entry| {
                entry.command.is_some()
                    && entry.invocation.binding_id == binding.id
                    && entry.invocation.session_id == binding.session_id
                    && entry.invocation.epoch == binding.epoch
            })
            .cloned()
            .collect();
        let mut tasks = Vec::with_capacity(entries.len());
        for entry in entries {
            let state = entry.state.lock().await;
            tasks.push(SshTaskRecord {
                task_id: entry.id.clone(),
                binding_id: binding.id.clone(),
                session_id: binding.session_id.clone(),
                command: entry.command.clone().unwrap_or_default(),
                completed: matches!(
                    state.record.state,
                    SshOperationState::Completed
                        | SshOperationState::Failed
                        | SshOperationState::Cancelled
                ),
            });
        }
        tasks.sort_by(|a, b| a.task_id.cmp(&b.task_id));
        tasks
    }

    pub(super) async fn cancel(
        &self,
        binding: &SshBinding,
        id: &str,
    ) -> Result<SshCancellation, String> {
        let entry = self
            .owned(binding, id, true)
            .await
            .ok_or("SSH task not found for this binding/session")?;
        let sender = {
            let state = entry.state.lock().await;
            if state.record.state.is_terminal() {
                return Ok(SshCancellation::OperationPending(state.record.clone()));
            }
            state
                .cancel
                .clone()
                .ok_or("This SSH operation is not a cancellable command")?
        };
        sender.send(()).await.map_err(
            |_| "SSH command channel is no longer available; remote termination is unknown",
        )?;
        let mut state = entry.state.lock().await;
        if !state.record.state.is_terminal() {
            state.record.state = SshOperationState::CancellationRequested;
        }
        Ok(SshCancellation::OperationPending(state.record.clone()))
    }
}

pub(super) struct CompletionGuard {
    operation: Option<Arc<NativeOperation>>,
    callbacks: Arc<dyn SshClientCallbacks>,
}

impl CompletionGuard {
    pub(super) fn disarm(&mut self) {
        self.operation = None;
    }
}

impl Drop for CompletionGuard {
    fn drop(&mut self) {
        if let Some(operation) = self.operation.take() {
            let callbacks = self.callbacks.clone();
            tokio::spawn(async move {
                let sender = operation.state.lock().await.cancel.clone();
                if let Some(sender) = sender {
                    if sender.send(()).await.is_ok() {
                        let mut state = operation.state.lock().await;
                        if !state.record.state.is_terminal() {
                            state.record.state = SshOperationState::CancellationRequested;
                        }
                        return;
                    }
                }
                operation
                    .finish(
                        Err(
                            "Local call interrupted; remote outcome is unknown. Do not replay it."
                                .into(),
                        ),
                        true,
                        callbacks.as_ref(),
                    )
                    .await;
            });
        }
    }
}

impl NativeOperation {
    pub(super) fn guard(
        self: &Arc<Self>,
        callbacks: Arc<dyn SshClientCallbacks>,
    ) -> CompletionGuard {
        CompletionGuard {
            operation: Some(self.clone()),
            callbacks,
        }
    }

    pub(super) async fn finish(
        &self,
        result: Result<SshDispatchResult, String>,
        uncertain: bool,
        callbacks: &dyn SshClientCallbacks,
    ) {
        let record = {
            let mut state = self.state.lock().await;
            if state.record.state.is_terminal() {
                return;
            }
            match result {
                Ok(result) => {
                    state.record.state = SshOperationState::Completed;
                    state.record.result = Some(result.output.clone());
                    state.result = Some(result);
                }
                Err(message) => {
                    // A failed SFTP write may have reached the server. Never invite a retry.
                    state.record.state = if uncertain {
                        SshOperationState::Unknown
                    } else {
                        SshOperationState::Failed
                    };
                    state.record.error = Some(SshWireError::new("native_operation", message));
                }
            }
            state.record.clone()
        };
        callbacks.on_event(SshWorkerEvent::Operation(record)).await;
    }

    pub(super) async fn snapshot(&self) -> SshDispatchResult {
        let state = self.state.lock().await;
        let stdout = String::from_utf8_lossy(&state.stdout);
        let stderr = String::from_utf8_lossy(&state.stderr);
        let mut output = json!({
            "operation_id": self.id, "task_id": self.command.as_ref().map(|_| &self.id),
            "state": state.record.state, "exit_code": state.exit_code,
            "stdout": stdout, "stderr": stderr, "truncated": state.truncated,
            "error": state.record.error, "result": state.result.as_ref().map(|r| &r.output),
            "_ssh": super::service::remote_scope(&self.invocation, &self.id),
        });
        let mut prompt_text = format!("SSH operation {}: {:?}", self.id, state.record.state);
        if let Some(code) = state.exit_code {
            prompt_text.push_str(&format!(" (exit {code})"));
        }
        if state.record.state == SshOperationState::Unknown {
            prompt_text.push_str("\nRemote outcome is unknown. The command may still be running. It was not replayed.");
        }
        if let Some(error) = &state.record.error {
            prompt_text.push_str(&format!("\n{}", error.message));
        }
        if !stdout.is_empty() {
            prompt_text.push_str(&format!("\nstdout:\n{stdout}"));
        }
        if !stderr.is_empty() {
            prompt_text.push_str(&format!("\nstderr:\n{stderr}"));
        }
        if state.truncated {
            prompt_text.push_str("\nOutput truncated to 64 KiB per stream.");
        }
        if let Some(result) = &state.result {
            prompt_text.push('\n');
            prompt_text.push_str(&result.prompt_text);
        }
        if self.command.is_some() {
            let target =
                serde_json::to_string(&self.invocation.binding_id).expect("binding ID serializes");
            let task = serde_json::to_string(&self.id).expect("task ID serializes");
            prompt_text.push_str(&format!(
                "\nQuery with ssh_task_query({{\"target\":{target},\"task_id\":{task}}}); \
                 cancel with ssh_task_cancel({{\"target\":{target},\"task_id\":{task}}}). \
                 Use this binding even if the default target changes. Native task history is held by this local service, not a remote daemon."
            ));
        }
        prompt_text = super::service::render_ssh_dispatch_prompt(
            prompt_text,
            None,
            &self.invocation,
            &self.id,
        );
        if self.command.is_none() {
            output.as_object_mut().unwrap().remove("task_id");
        }
        SshDispatchResult {
            output,
            prompt_text,
        }
    }

    pub(super) async fn run(
        self: Arc<Self>,
        mut command: SshCommand,
        args: BashToolInput,
        callbacks: Arc<dyn SshClientCallbacks>,
    ) -> SshDispatchResult {
        let (cancel_tx, mut cancel_rx) = mpsc::channel(1);
        let running = {
            let mut state = self.state.lock().await;
            state.record.state = SshOperationState::Running;
            state.cancel = Some(cancel_tx);
            state.record.clone()
        };
        let (done_tx, done_rx) = oneshot::channel();
        let entry = self.clone();
        // block_until_ms only limits waiting, never execution. Legacy timeout is
        // an execution deadline for foreground commands, as advertised by its schema.
        let background = args.is_background || args.timeout == Some(0);
        let execution_timeout = if args.block_until_ms.is_some() || background {
            None
        } else {
            Some(Duration::from_millis(
                args.timeout.unwrap_or(120_000).min(300_000),
            ))
        };
        let wait = args
            .block_until_ms
            .map(Duration::from_millis)
            .unwrap_or_else(|| {
                if background {
                    Duration::ZERO
                } else {
                    Duration::from_secs(310)
                }
            });
        tokio::spawn(async move {
            callbacks.on_event(SshWorkerEvent::Operation(running)).await;
            let mut deadline =
                execution_timeout.map(|duration| tokio::time::Instant::now() + duration);
            let mut cancellation_requested = false;
            let mut terminal = None;
            let mut failure = None;
            loop {
                let deadline_wait = async {
                    match deadline {
                        Some(instant) => tokio::time::sleep_until(instant).await,
                        None => std::future::pending::<()>().await,
                    }
                };
                tokio::select! {
                    _ = deadline_wait => {
                        if cancellation_requested {
                            let _ = command.close().await;
                            failure = Some("Cancellation was sent, but no exit was confirmed; remote outcome is unknown".to_owned());
                            break;
                        }
                        cancellation_requested = true;
                        if let Err(error) = command.signal("KILL").await {
                            failure = Some(format!("Unable to cancel timed-out SSH command: {error}"));
                            break;
                        }
                        deadline = Some(tokio::time::Instant::now() + Duration::from_secs(5));
                        entry.state.lock().await.record.state = SshOperationState::CancellationRequested;
                    }
                    Some(()) = cancel_rx.recv(), if !cancellation_requested => {
                        cancellation_requested = true;
                        if let Err(error) = command.signal("KILL").await {
                            failure = Some(format!("SSH cancellation could not be sent: {error}"));
                            break;
                        }
                        deadline = Some(tokio::time::Instant::now() + Duration::from_secs(5));
                        entry.state.lock().await.record.state = SshOperationState::CancellationRequested;
                    }
                    event = command.next_event() => match event {
                        Ok(Some(SshCommandEvent::Stdout(bytes))) | Ok(Some(SshCommandEvent::Stderr(bytes))) if bytes.is_empty() => {},
                        Ok(Some(SshCommandEvent::Stdout(bytes))) => entry.output(false, &bytes, callbacks.as_ref()).await,
                        Ok(Some(SshCommandEvent::Stderr(bytes))) => entry.output(true, &bytes, callbacks.as_ref()).await,
                        Ok(Some(SshCommandEvent::ExitStatus(code))) => {
                            entry.state.lock().await.exit_code = Some(code);
                            terminal = Some(if code == 0 { SshOperationState::Completed } else { SshOperationState::Failed });
                        }
                        Ok(Some(SshCommandEvent::ExitSignal(signal))) => {
                            terminal = Some(if cancellation_requested { SshOperationState::Cancelled } else { SshOperationState::Failed });
                            failure = Some(format!("Remote command exited on signal {signal}"));
                        }
                        Ok(None) => break,
                        Err(error) => { failure = Some(error.to_string()); break; }
                    }
                }
            }
            let record = {
                let mut state = entry.state.lock().await;
                state.record.state = terminal.unwrap_or(SshOperationState::Unknown);
                state.record.error =
                    failure.map(|message| SshWireError::new("native_command", message));
                state.cancel = None;
                state.record.clone()
            };
            callbacks.on_event(SshWorkerEvent::Operation(record)).await;
            let _ = done_tx.send(());
        });
        if !wait.is_zero() {
            let _ = tokio::time::timeout(wait, done_rx).await;
        }
        self.snapshot().await
    }

    async fn output(&self, stderr: bool, bytes: &[u8], callbacks: &dyn SshClientCallbacks) {
        {
            let mut state = self.state.lock().await;
            let output = if stderr {
                &mut state.stderr
            } else {
                &mut state.stdout
            };
            let available = MAX_STREAM_BYTES.saturating_sub(output.len());
            output.extend(bytes.iter().take(available));
            state.truncated |= bytes.len() > available;
        }
        callbacks
            .on_event(SshWorkerEvent::ToolProgress {
                operation_id: self.id.clone(),
                progress: SshToolProgress {
                    kind: "ssh_output".into(),
                    body: json!({
                        "stream": if stderr { "stderr" } else { "stdout" },
                        "text": String::from_utf8_lossy(bytes),
                        "command": self.command,
                        "cwd": self.invocation.cwd,
                    }),
                },
            })
            .await;
    }
}

pub(super) fn shell_quote(value: &str) -> Result<String, String> {
    if value.contains('\0') {
        return Err("SSH shell argument contains NUL".into());
    }
    Ok(format!("'{}'", value.replace('\'', "'\\''")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use xai_grok_workspace_types::ssh::{SshCapabilities, SshHostIdentity, SshOperation};

    fn binding() -> SshBinding {
        SshBinding {
            id: "binding-a".into(),
            session_id: "session-a".into(),
            target_id: "host-a".into(),
            identity: SshHostIdentity {
                hostname: "host-a".into(),
                port: 22,
                username: "user".into(),
                fingerprint: "SHA256:test".into(),
            },
            root: "/repo".into(),
            cwd: "/repo".into(),
            capabilities: SshCapabilities::all(),
            epoch: 1,
            revoked: false,
        }
    }

    fn request(binding: &SshBinding) -> SshDispatchRequest {
        SshDispatchRequest {
            invocation: ResolvedSshInvocation {
                binding_id: binding.id.clone(),
                target_id: binding.target_id.clone(),
                session_id: binding.session_id.clone(),
                epoch: binding.epoch,
                cwd: binding.cwd.clone(),
                operation: SshOperation::Execute,
                call_id: "call-a".into(),
            },
            tool_name: "GrokBuild:run_terminal_cmd".into(),
            args: json!({"command":"echo once"}),
            mutation_id: Some("call-a".into()),
        }
    }

    #[tokio::test]
    async fn native_ssh_tasks_never_replay_pending_or_completed_calls() {
        let operations = NativeOperations::default();
        let binding = binding();
        let request = request(&binding);
        let operation = operations.reserve(&request, Some(7)).await.unwrap();
        assert!(operations.reserve(&request, Some(7)).await.is_err());
        operation.state.lock().await.record.state = SshOperationState::Completed;
        assert!(operations.reserve(&request, Some(7)).await.is_err());
        assert_eq!(
            operations
                .query(&binding, &operation.id)
                .await
                .unwrap()
                .output["state"],
            "completed"
        );
    }

    #[tokio::test]
    async fn active_operation_ids_are_scoped_to_client_and_drop_at_terminal_state() {
        let operations = NativeOperations::default();
        let binding = binding();
        let operation = operations.reserve(&request(&binding), Some(7)).await.unwrap();

        assert_eq!(
            operations.active_ids_for_client(7).await,
            vec![operation.id.clone()]
        );
        assert!(operations.active_ids_for_client(8).await.is_empty());

        operation.state.lock().await.record.state = SshOperationState::Completed;
        assert!(operations.active_ids_for_client(7).await.is_empty());
    }

    #[tokio::test]
    async fn native_ssh_task_lookup_isolated_by_binding_session_and_epoch() {
        let operations = NativeOperations::default();
        let binding = binding();
        let operation = operations.reserve(&request(&binding), Some(7)).await.unwrap();
        let mut other_binding = binding.clone();
        other_binding.id = "binding-b".into();
        let mut other_session = binding.clone();
        other_session.session_id = "session-b".into();
        let mut other_epoch = binding.clone();
        other_epoch.epoch += 1;
        for foreign in [&other_binding, &other_session, &other_epoch] {
            assert!(operations.query(foreign, &operation.id).await.is_none());
            assert!(operations.list(foreign).await.is_empty());
            assert!(operations.cancel(foreign, &operation.id).await.is_err());
        }
        assert_eq!(operations.list(&binding).await[0].task_id, operation.id);
    }

    struct NoCallbacks;

    #[async_trait::async_trait]
    impl SshClientCallbacks for NoCallbacks {
        async fn on_event(&self, _: SshWorkerEvent) {}
        async fn approve(
            &self,
            _: xai_grok_workspace_types::ssh_wire::SshApprovalRequest,
        ) -> xai_grok_workspace_types::ssh_wire::SshApprovalDecision {
            xai_grok_workspace_types::ssh_wire::SshApprovalDecision::Deny
        }
    }

    #[tokio::test]
    async fn native_ssh_late_interruption_cannot_overwrite_confirmed_result() {
        let operations = NativeOperations::default();
        let binding = binding();
        let operation = operations.reserve(&request(&binding), Some(7)).await.unwrap();
        operation
            .finish(
                Ok(SshDispatchResult {
                    output: json!({"exit_code": 0}),
                    prompt_text: "confirmed command exit".into(),
                }),
                false,
                &NoCallbacks,
            )
            .await;
        operation
            .finish(
                Err("interrupted after completion".into()),
                true,
                &NoCallbacks,
            )
            .await;
        let result = operations.query(&binding, &operation.id).await.unwrap();
        assert_eq!(result.output["state"], "completed");
        assert!(result.output["error"].is_null());
        assert_eq!(result.output["result"]["exit_code"], 0);
    }
}
