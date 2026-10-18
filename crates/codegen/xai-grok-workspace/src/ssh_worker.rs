//! Non-Hub SSH workspace worker.
//!
//! The worker owns normal [`WorkspaceHandle`]s and routes every RPC through the
//! existing [`WorkspaceRpcHandler`]. It is deliberately independent of the
//! native SSH crate: callers hand it an authenticated duplex stream. A private
//! local daemon can keep those handles, terminal tasks, and operation records
//! alive after an SSH stdio bridge disconnects.

use crate::capability::CapabilityMode;
use crate::config::{DEFAULT_EVENT_BUFFER_CAPACITY, HookSourceConfig, WorkspaceConfig};
use crate::handle::WorkspaceHandle;
use crate::host_kind::WorkspaceHostKind;
use crate::hub_server::{WorkspaceRpcHandler, workspace_rpc_operation};
use crate::permission::ToolApprovalGate;
use crate::session::tool_config::WorkspaceSessionContextFactory;
use crate::workspace_ops::ssh_operation_for_tool_kind;
use anyhow::{Context, anyhow, bail};
use std::collections::{HashMap, HashSet};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{Mutex, RwLock, oneshot};
use tokio_util::sync::CancellationToken;
use xai_grok_tools::computer::types::KillSource;
use xai_grok_tools::notification::{PerCallNotificationSink, ToolNotificationHandle};
use xai_grok_tools::types::output::ToolRunResult;
use xai_grok_tools::types::resources::Terminal;
use xai_grok_workspace_client::ssh::{SshClientError, read_frame, write_frame};
use xai_grok_workspace_types::ssh::{ResolvedSshInvocation, SshBinding, SshOperation};
use xai_grok_workspace_types::ssh_wire::{
    SSH_WIRE_PROTOCOL_VERSION, SshApprovalDecision, SshApprovalRequest, SshCancellation,
    SshMutationId, SshOperationId, SshOperationRecord, SshOperationState, SshPathSemantics,
    SshPostToolHookNote, SshPostToolHookOutcome, SshPostToolReplacement, SshProjectBootstrap,
    SshResumeToken, SshTaskRecord, SshToolProgress, SshWireError, SshWireFrame,
    SshWorkerCapabilities, SshWorkerEvent, SshWorkerHello, SshWorkerReply, SshWorkerRequest,
    SshWorkerResponse,
};
use xai_tool_runtime::{Cancellation, ToolCallContext, ToolProgress, ToolStreamItem};

use xai_grok_hooks::event::{HookEventEnvelope, HookEventName, HookPayload};
use xai_grok_hooks::runner::RunContext as HookRunContext;

const APPROVAL_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// A long-lived worker service. It has no Hub configuration, no model token,
/// and no public listener; the hosting SSH/local transport authenticates peers.
pub struct SshWorkerService {
    worker_id: String,
    // A no-execute binding gets a separate handle with no command-producing
    // extension sources. Sharing only by root would let a read-only session
    // enter project hooks/MCP initialized for an execute-capable session.
    workspaces: Mutex<HashMap<(PathBuf, bool), Arc<WorkerWorkspace>>>,
    bindings: Mutex<HashMap<String, BindingState>>,
    // Tombstones deliberately carry no WorkspaceHandle. A revocation reconnect
    // must never revive the old session or start project extensions.
    tombstones: Mutex<HashMap<String, SshBinding>>,
    operations: Mutex<HashMap<SshOperationId, OperationEntry>>,
    mutations: Mutex<HashMap<(String, String, SshMutationId), SshOperationId>>,
    next_id: AtomicU64,
}

struct WorkerWorkspace {
    root: PathBuf,
    handle: WorkspaceHandle,
    rpc: Arc<WorkspaceRpcHandler>,
    mcp_servers: Vec<agent_client_protocol::McpServer>,
    project_trusted: bool,
}

struct BindingState {
    binding: SshBinding,
    workspace: Arc<WorkerWorkspace>,
    resume_token: SshResumeToken,
    revoked: bool,
}

struct OperationEntry {
    record: SshOperationRecord,
    cancellation: CancellationToken,
}

struct AuthorizedInvocation {
    binding: SshBinding,
    workspace: Arc<WorkerWorkspace>,
    cwd: PathBuf,
}

enum BeginOperation {
    Existing(SshOperationRecord),
    Started {
        operation_id: SshOperationId,
        cancellation: CancellationToken,
    },
}

impl SshWorkerService {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            worker_id: format!("ssh-worker-{}", uuid::Uuid::now_v7()),
            workspaces: Mutex::new(HashMap::new()),
            bindings: Mutex::new(HashMap::new()),
            tombstones: Mutex::new(HashMap::new()),
            operations: Mutex::new(HashMap::new()),
            mutations: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
        })
    }

    async fn bind(
        &self,
        binding: SshBinding,
    ) -> Result<(SshBinding, SshResumeToken), SshWireError> {
        if binding.revoked {
            return Err(wire_error(
                "binding_revoked",
                "refusing an already-revoked binding",
            ));
        }
        if binding.id.is_empty() || binding.session_id.is_empty() || binding.target_id.is_empty() {
            return Err(wire_error(
                "invalid_binding",
                "binding id, session id, and target id are required",
            ));
        }
        if self.tombstones.lock().await.contains_key(&binding.id) {
            return Err(wire_error(
                "authorization_revoked",
                "a revoked binding cannot be rebound",
            ));
        }
        let root = canonical_directory(Path::new(&binding.root), None)
            .map_err(|e| wire_error("invalid_root", e.to_string()))?;
        let cwd = canonical_directory(Path::new(&binding.cwd), Some(&root))
            .map_err(|e| wire_error("invalid_cwd", e.to_string()))?;
        let mut binding = binding;
        binding.root = root.to_string_lossy().into_owned();
        binding.cwd = cwd.to_string_lossy().into_owned();

        let workspace = self
            .workspace_for_root(root, binding.capabilities.permits(SshOperation::Execute))
            .await?;
        {
            let bindings = self.bindings.lock().await;
            if let Some(existing) = bindings.get(&binding.id) {
                ensure_bindable(existing, &binding)?;
            }
        }

        let created = if workspace.handle.session(&binding.session_id).is_none() {
            workspace
                .handle
                .create_session_with_config(
                    binding.session_id.clone(),
                    Some(cwd),
                    None,
                    CapabilityMode::All,
                    None,
                    false,
                )
                .map_err(|e| wire_error("session_setup_failed", e.to_string()))?;
            true
        } else {
            false
        };
        if created && !workspace.mcp_servers.is_empty() {
            workspace
                .handle
                .start_session_mcp_servers(&binding.session_id, workspace.mcp_servers.clone())
                .await
                .map_err(|e| wire_error("mcp_setup_failed", e.to_string()))?;
        }
        let token = self.new_token();

        {
            // Session creation can take long enough for a concurrent revocation
            // to land. Revalidate while committing so a bind never resurrects it.
            let tombstones = self.tombstones.lock().await;
            if tombstones.contains_key(&binding.id) {
                return Err(wire_error(
                    "authorization_revoked",
                    "a revoked binding cannot be rebound",
                ));
            }
            let mut bindings = self.bindings.lock().await;
            if let Some(existing) = bindings.get(&binding.id) {
                ensure_bindable(existing, &binding)?;
            }
            bindings.insert(
                binding.id.clone(),
                BindingState {
                    binding: binding.clone(),
                    workspace: Arc::clone(&workspace),
                    resume_token: token.clone(),
                    revoked: false,
                },
            );
        }
        if created {
            self.ensure_live_hook_binding(&binding).await?;
            dispatch_worker_observe_hook(
                &workspace,
                &binding,
                HookEventName::SessionStart,
                HookPayload::SessionStart {
                    source: "new".to_owned(),
                    model_id: None,
                    agent_type: None,
                },
            )
            .await;
        }
        Ok((binding, token))
    }

    async fn admit_revocation_tombstone(
        &self,
        mut binding: SshBinding,
    ) -> Result<(SshBinding, SshResumeToken), SshWireError> {
        if !binding.revoked {
            return Err(wire_error(
                "invalid_tombstone",
                "revocation-only admission requires a revoked binding",
            ));
        }
        if binding.id.is_empty() || binding.session_id.is_empty() || binding.target_id.is_empty() {
            return Err(wire_error(
                "invalid_binding",
                "binding id, session id, and target id are required",
            ));
        }
        let mut tombstones = self.tombstones.lock().await;
        if let Some(existing) = tombstones.get(&binding.id) {
            if !same_binding_scope(existing, &binding) {
                return Err(wire_error(
                    "binding_scope_changed",
                    "a tombstone cannot change the original binding scope",
                ));
            }
            if binding.epoch < existing.epoch {
                return Err(wire_error(
                    "stale_authorization_epoch",
                    "cannot acknowledge an older revocation epoch",
                ));
            }
        }
        let mut bindings = self.bindings.lock().await;
        if let Some(existing) = bindings.get_mut(&binding.id) {
            if !same_binding_scope(&existing.binding, &binding) {
                return Err(wire_error(
                    "binding_scope_changed",
                    "a tombstone cannot change the original binding scope",
                ));
            }
            if binding.epoch < existing.binding.epoch {
                return Err(wire_error(
                    "stale_authorization_epoch",
                    "cannot acknowledge an older revocation epoch",
                ));
            }
            existing.binding.epoch = binding.epoch;
            existing.binding.revoked = true;
            existing.revoked = true;
        }
        binding.revoked = true;
        tombstones.insert(binding.id.clone(), binding.clone());
        Ok((binding, self.new_token()))
    }

    async fn resume(
        &self,
        binding: SshBinding,
        resume_token: SshResumeToken,
    ) -> Result<(SshBinding, SshResumeToken), SshWireError> {
        let prior = {
            let bindings = self.bindings.lock().await;
            let Some(prior) = bindings.get(&binding.id) else {
                return Err(wire_error(
                    "resume_not_found",
                    "worker has no matching binding",
                ));
            };
            if prior.revoked || prior.resume_token != resume_token || prior.binding != binding {
                return Err(wire_error(
                    "resume_rejected",
                    "binding or resume token is no longer valid",
                ));
            }
            prior.binding.clone()
        };
        self.bind(prior).await
    }

    async fn revoke(&self, binding_id: &str, epoch: u64) -> Result<(), SshWireError> {
        let mut tombstones = self.tombstones.lock().await;
        let mut bindings = self.bindings.lock().await;
        if let Some(binding) = bindings.get_mut(binding_id) {
            if epoch < binding.binding.epoch {
                return Err(wire_error(
                    "stale_authorization_epoch",
                    "cannot revoke an older epoch",
                ));
            }
            binding.binding.epoch = epoch;
            binding.binding.revoked = true;
            binding.revoked = true;
            tombstones.insert(binding_id.to_owned(), binding.binding.clone());
            return Ok(());
        }
        let Some(tombstone) = tombstones.get_mut(binding_id) else {
            return Err(wire_error(
                "binding_not_found",
                "worker has no matching binding",
            ));
        };
        if epoch < tombstone.epoch {
            return Err(wire_error(
                "stale_authorization_epoch",
                "cannot revoke an older epoch",
            ));
        }
        tombstone.epoch = epoch;
        tombstone.revoked = true;
        Ok(())
    }

    async fn workspace_for_root(
        &self,
        root: PathBuf,
        extensions_enabled: bool,
    ) -> Result<Arc<WorkerWorkspace>, SshWireError> {
        let cache_key = (root.clone(), extensions_enabled);
        let mut workspaces = self.workspaces.lock().await;
        if let Some(workspace) = workspaces.get(&cache_key) {
            return Ok(Arc::clone(workspace));
        }
        let project_trusted = crate::folder_trust::folder_trust_inert()
            || crate::folder_trust::is_trusted_this_process(&crate::trust::workspace_key(&root));
        let factory = WorkspaceSessionContextFactory::hub_only()
            .with_tool_state_home(crate::handle::resolve_workspace_home().join("ssh-worker"));
        let config = WorkspaceConfig {
            root_cwd: root.clone(),
            default_tool_config: crate::workspace_ops::ssh_worker_toolset(),
            respect_gitignore: true,
            memory_config: None,
            event_buffer_capacity: DEFAULT_EVENT_BUFFER_CAPACITY,
            session_factory: Arc::new(factory),
            hook_global_sources: extensions_enabled
                .then(worker_global_hook_sources)
                .unwrap_or_default(),
            hook_project_sources: (extensions_enabled && project_trusted)
                .then(|| worker_project_hook_sources(&root))
                .unwrap_or_default(),
            skills_config: Default::default(),
            plugin_discovery_config: Default::default(),
            hub_config: None,
            auth_provider: None,
            server_metadata: None,
            status_config: Default::default(),
            project_lsp_trusted: extensions_enabled && project_trusted,
            require_explicit_toolset: false,
            confine_fs_to_workspace_root: true,
            bind_mcp: None,
            // SSH uses the protocol approval gate below. The Hub gate cannot
            // prompt without a Hub transport and would otherwise be silently off.
            tool_approval: ToolApprovalGate::Off,
            host_kind: WorkspaceHostKind::Daemon,
            sandbox: None,
        };
        let mcp_servers = worker_mcp_servers(&root, extensions_enabled && project_trusted);
        let handle = WorkspaceHandle::new(config)
            .map_err(|e| wire_error("workspace_setup_failed", e.to_string()))?;
        let workspace = Arc::new(WorkerWorkspace {
            root: root.clone(),
            rpc: Arc::new(WorkspaceRpcHandler::new(handle.clone())),
            handle,
            mcp_servers,
            project_trusted,
        });

        workspaces.insert(cache_key, Arc::clone(&workspace));
        Ok(workspace)
    }

    /// A hook command is a fresh remote side effect, not part of the prior
    /// bind. Recheck the live epoch immediately before dispatching one.
    async fn ensure_live_hook_binding(&self, binding: &SshBinding) -> Result<(), SshWireError> {
        let bindings = self.bindings.lock().await;
        let Some(state) = bindings.get(&binding.id) else {
            return Err(wire_error(
                "authorization_revoked",
                "hook binding is no longer active",
            ));
        };
        if state.revoked || state.binding.revoked || state.binding != *binding {
            return Err(wire_error(
                "authorization_revoked",
                "hook binding was revoked or changed before dispatch",
            ));
        }
        Ok(())
    }

    async fn authorize(
        &self,
        accepted_bindings: &RwLock<HashSet<String>>,
        invocation: &ResolvedSshInvocation,
        expected: SshOperation,
    ) -> Result<AuthorizedInvocation, SshWireError> {
        if invocation.operation != expected {
            return Err(wire_error(
                "operation_mismatch",
                "invocation operation does not match the worker-classified operation",
            ));
        }
        if !accepted_bindings
            .read()
            .await
            .contains(&invocation.binding_id)
        {
            return Err(wire_error(
                "binding_not_active",
                "binding was not admitted on this bridge",
            ));
        }
        let bindings = self.bindings.lock().await;
        let Some(state) = bindings.get(&invocation.binding_id) else {
            return Err(wire_error(
                "binding_not_found",
                "worker has no matching binding",
            ));
        };
        if state.revoked
            || state.binding.revoked
            || state.binding.epoch != invocation.epoch
            || state.binding.target_id != invocation.target_id
            || state.binding.session_id != invocation.session_id
        {
            return Err(wire_error(
                "authorization_revoked",
                "binding authorization is no longer valid",
            ));
        }
        if !state.binding.capabilities.permits(expected) {
            return Err(wire_error(
                "capability_denied",
                "binding capability does not permit this operation",
            ));
        }
        let cwd = canonical_directory(Path::new(&invocation.cwd), Some(&state.workspace.root))
            .map_err(|e| wire_error("invalid_cwd", e.to_string()))?;
        Ok(AuthorizedInvocation {
            binding: state.binding.clone(),
            workspace: Arc::clone(&state.workspace),
            cwd,
        })
    }

    async fn begin_operation(
        &self,
        binding: &SshBinding,
        operation: SshOperation,
        mutation_id: Option<SshMutationId>,
    ) -> Result<BeginOperation, SshWireError> {
        let mutation_key = mutation_id.as_ref().map(|mutation_id| {
            (
                binding.id.clone(),
                binding.session_id.clone(),
                mutation_id.clone(),
            )
        });
        // A mutation claim and its operation must appear together. Keeping the
        // mutation lock until after the operation is installed makes concurrent
        // duplicate IDs deterministically select one execution.
        let mut mutations = self.mutations.lock().await;
        if let Some(key) = &mutation_key
            && let Some(existing_id) = mutations.get(key).cloned()
        {
            let operations = self.operations.lock().await;
            let Some(existing) = operations.get(&existing_id) else {
                return Err(wire_error(
                    "operation_lost",
                    "mutation index points to no operation",
                ));
            };
            if existing.record.state == SshOperationState::Completed {
                return Ok(BeginOperation::Existing(existing.record.clone()));
            }
            return Err(wire_error(
                "mutation_not_replayable",
                "a mutation with this id is pending, failed, cancelled, or unknown; query it instead of replaying",
            ));
        }
        let operation_id = format!("ssh-op-{}", self.next_id.fetch_add(1, Ordering::Relaxed));
        let cancellation = CancellationToken::new();
        let record = SshOperationRecord {
            operation_id: operation_id.clone(),
            mutation_id,
            binding_id: binding.id.clone(),
            session_id: binding.session_id.clone(),
            operation,
            state: SshOperationState::Pending,
            result: None,
            post_hook: None,
            error: None,
        };
        self.operations.lock().await.insert(
            operation_id.clone(),
            OperationEntry {
                record,
                cancellation: cancellation.clone(),
            },
        );
        if let Some(key) = mutation_key {
            mutations.insert(key, operation_id.clone());
        }
        Ok(BeginOperation::Started {
            operation_id,
            cancellation,
        })
    }

    async fn mark_running(&self, operation_id: &str) -> Result<SshOperationRecord, SshWireError> {
        let mut operations = self.operations.lock().await;
        let Some(operation) = operations.get_mut(operation_id) else {
            return Err(wire_error(
                "operation_not_found",
                "worker operation disappeared",
            ));
        };
        if operation.record.state != SshOperationState::CancellationRequested {
            operation.record.state = SshOperationState::Running;
        }
        Ok(operation.record.clone())
    }

    async fn complete(
        &self,
        operation_id: &str,
        result: Result<serde_json::Value, SshWireError>,
    ) -> Result<SshOperationRecord, SshWireError> {
        let mut operations = self.operations.lock().await;
        let Some(operation) = operations.get_mut(operation_id) else {
            return Err(wire_error(
                "operation_not_found",
                "worker operation disappeared",
            ));
        };
        if operation.record.state == SshOperationState::Cancelled {
            return Ok(operation.record.clone());
        }
        match result {
            Ok(value) => {
                operation.record.state = SshOperationState::Completed;
                operation.record.result = Some(value);
                operation.record.error = None;
            }
            Err(error) => {
                operation.record.state = SshOperationState::Failed;
                operation.record.error = Some(error);
                operation.record.result = None;
            }
        }
        Ok(operation.record.clone())
    }

    async fn complete_tool(
        &self,
        operation_id: &str,
        result: Result<serde_json::Value, SshWireError>,
        post_hook: Option<SshPostToolHookOutcome>,
    ) -> Result<SshOperationRecord, SshWireError> {
        let mut operations = self.operations.lock().await;
        let Some(operation) = operations.get_mut(operation_id) else {
            return Err(wire_error(
                "operation_not_found",
                "worker operation disappeared",
            ));
        };
        if operation.record.state == SshOperationState::Cancelled {
            return Ok(operation.record.clone());
        }
        match result {
            Ok(value) => {
                operation.record.state = SshOperationState::Completed;
                operation.record.result = Some(value);
                operation.record.post_hook = post_hook;
                operation.record.error = None;
            }
            Err(mut error) => {
                // The operation retains terminal hook effects in its dedicated
                // field. The immediate wire error retains them separately, but
                // a queried operation must not serialize the same outcome twice.
                error.post_hook = None;
                operation.record.state = SshOperationState::Failed;
                operation.record.error = Some(error);
                operation.record.result = None;
                operation.record.post_hook = post_hook;
            }
        }
        Ok(operation.record.clone())
    }

    async fn confirm_cancelled(
        &self,
        operation_id: &str,
        message: &'static str,
    ) -> Result<SshOperationRecord, SshWireError> {
        let mut operations = self.operations.lock().await;
        let Some(operation) = operations.get_mut(operation_id) else {
            return Err(wire_error(
                "operation_not_found",
                "worker operation disappeared",
            ));
        };
        operation.record.state = SshOperationState::Cancelled;
        operation.record.result = None;
        operation.record.error = Some(wire_error("cancelled", message));
        Ok(operation.record.clone())
    }

    async fn operation_for(
        &self,
        binding_id: &str,
        session_id: &str,
        operation_id: &str,
    ) -> Result<Option<SshOperationRecord>, SshWireError> {
        let operations = self.operations.lock().await;
        let Some(operation) = operations.get(operation_id) else {
            return Ok(None);
        };
        if operation.record.binding_id != binding_id || operation.record.session_id != session_id {
            return Err(wire_error(
                "operation_not_owned",
                "operation belongs to another binding or session",
            ));
        }
        Ok(Some(operation.record.clone()))
    }

    async fn mutation_for(
        &self,
        binding_id: &str,
        session_id: &str,
        mutation_id: &str,
    ) -> Result<Option<SshOperationRecord>, SshWireError> {
        let key = (
            binding_id.to_owned(),
            session_id.to_owned(),
            mutation_id.to_owned(),
        );
        let Some(operation_id) = self.mutations.lock().await.get(&key).cloned() else {
            return Ok(None);
        };
        self.operation_for(binding_id, session_id, &operation_id)
            .await
    }

    async fn cancel(
        &self,
        authorized: &AuthorizedInvocation,
        reference: &str,
    ) -> Result<SshCancellation, SshWireError> {
        let operation = {
            let mut operations = self.operations.lock().await;
            match operations.get_mut(reference) {
                Some(operation) => {
                    if operation.record.binding_id != authorized.binding.id
                        || operation.record.session_id != authorized.binding.session_id
                    {
                        return Err(wire_error(
                            "operation_not_owned",
                            "operation belongs to another binding or session",
                        ));
                    }
                    if operation.record.state.is_terminal() {
                        return Err(wire_error(
                            "operation_terminal",
                            "operation is already terminal and cannot be cancelled",
                        ));
                    }
                    operation.cancellation.cancel();
                    operation.record.state = SshOperationState::CancellationRequested;
                    operation.record.error = Some(wire_error(
                        "cancellation_requested",
                        "cancellation was requested; query the operation for its confirmed terminal state",
                    ));
                    Some(operation.record.clone())
                }
                None => None,
            }
        };
        if let Some(operation) = operation {
            return Ok(SshCancellation::OperationPending(operation));
        }

        let session = authorized
            .workspace
            .handle
            .session(&authorized.binding.session_id)
            .ok_or_else(|| wire_error("session_not_found", "worker session not found"))?;
        let toolset = session.toolset();
        let terminal = {
            let resources = toolset.resources.lock().await;
            resources
                .get::<Terminal>()
                .map(|terminal| terminal.0.clone())
        }
        .ok_or_else(|| wire_error("task_unsupported", "session has no terminal task manager"))?;
        let before = terminal
            .get_task(reference)
            .await
            .ok_or_else(|| wire_error("task_not_found", "worker has no matching owned task"))?;
        let outcome = terminal
            .kill_task_with_source(reference, KillSource::ClientUi)
            .await;
        if matches!(
            outcome,
            xai_grok_tools::computer::types::KillOutcome::NotFound
        ) {
            return Err(wire_error(
                "task_not_found",
                "task disappeared before the task manager confirmed cancellation",
            ));
        }
        let after = terminal.get_task(reference).await.unwrap_or(before);
        Ok(SshCancellation::Task(SshTaskRecord {
            task_id: after.task_id,
            binding_id: authorized.binding.id.clone(),
            session_id: authorized.binding.session_id.clone(),
            command: after.display_command.unwrap_or(after.command),
            // `Killed`/`AlreadyExited` are terminal-backend acknowledgements;
            // some backends retain a stale snapshot briefly after that ack.
            completed: true,
        }))
    }
    fn new_token(&self) -> SshResumeToken {
        format!("ssh-resume-{}", uuid::Uuid::now_v7())
    }
}

impl WorkerWorkspace {
    async fn instruction_files(&self) -> Vec<serde_json::Value> {
        let mut files =
            crate::discovery::discover_agents_md(&self.root, self.project_trusted).await;
        retain_discovery_within_root(&mut files, "file_path", &self.root);
        files
    }

    async fn skills(&self) -> Vec<serde_json::Value> {
        let mut skills = crate::discovery::discover_skills(
            &self.root,
            self.handle.shared.skills_config(),
            self.project_trusted,
        )
        .await;
        retain_discovery_within_root(&mut skills, "path", &self.root);
        skills
    }
    async fn prepare_skill_discovery(
        &self,
        toolset: &xai_grok_tools::registry::types::FinalizedToolset,
    ) -> Result<(), SshWireError> {
        use xai_grok_tools::types::{
            resources::AvailableSkills, skill_discovery_tracker::SkillManager,
        };
        if toolset.resources.lock().await.get::<SkillManager>()
            .is_some_and(|manager| manager.discovery_root.is_some())
        {
            return Ok(());
        }
        let skills = self.skills().await.into_iter()
            .map(serde_json::from_value)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| wire_error("skill_decode_failed", error.to_string()))?;
        let mut resources = toolset.resources.lock().await;
        let manager = resources.get_or_default::<SkillManager>();
        if manager.discovery_root.is_none() {
            manager.discovery_root = Some(self.root.clone());
            // The client announces the same authorized startup snapshot.
            // Seed the worker catalog as well so Skill executes remotely.
            manager.restore_announced_names(
                skills.iter().map(|skill: &xai_grok_tools::implementations::skills::types::SkillInfo| {
                    skill.dedup_key()
                }).collect(),
            );
            manager.seed(
                Some(self.root.clone()), Some(self.root.clone()),
                skills.clone(), None, None, None,
            );
            resources.insert(AvailableSkills(skills));
        }
        Ok(())
    }

    fn project_config(&self) -> Result<serde_json::Value, SshWireError> {
        ensure_path_within_root(
            &self.root.join(".grok/config.toml").to_string_lossy(),
            &self.root,
            &self.root,
        )
        .map_err(|error| wire_error("path_denied", error.to_string()))?;
        Ok(crate::discovery::load_project_config(&self.root))
    }

    async fn project_bootstrap(
        &self,
        session_id: &str,
    ) -> Result<SshProjectBootstrap, SshWireError> {
        let instructions = self
            .instruction_files()
            .await
            .into_iter()
            .map(serde_json::from_value)
            .collect::<Result<_, _>>()
            .map_err(|error| wire_error("bootstrap_decode_failed", error.to_string()))?;
        let skills = self
            .skills()
            .await
            .into_iter()
            .map(serde_json::from_value)
            .collect::<Result<_, _>>()
            .map_err(|error| wire_error("bootstrap_decode_failed", error.to_string()))?;
        let hook_registry = self
            .rpc
            .dispatch(
                "workspace.hook_registry",
                serde_json::json!({}),
                Some(session_id),
            )
            .await
            .map_err(|error| wire_error("workspace_rpc_failed", error.to_string()))
            .and_then(|value| {
                serde_json::from_value(value)
                    .map_err(|error| wire_error("bootstrap_decode_failed", error.to_string()))
            })?;
        let tool_definitions = self
            .rpc
            .dispatch(
                "workspace.tool_definitions",
                serde_json::json!({"session_id": session_id}),
                Some(session_id),
            )
            .await
            .map_err(|error| wire_error("workspace_rpc_failed", error.to_string()))?;
        let project_config = self.project_config()?;
        let agent_definition = self
            .project_trusted
            .then(|| selected_project_agent_definition(&self.root, &project_config))
            .flatten()
            .map(serde_json::to_value)
            .transpose()
            .map_err(|error| wire_error("bootstrap_encode_failed", error.to_string()))?;
        let mcp_servers = serde_json::to_value(&self.mcp_servers)
            .map_err(|error| wire_error("bootstrap_encode_failed", error.to_string()))?;
        Ok(SshProjectBootstrap {
            instructions,
            hook_registry,
            skills,
            tool_definitions,
            project_config,
            agent_definition,
            mcp_servers,
        })
    }
}

/// Discovery normally includes ancestors and user homes. An SSH file grant
/// does not authorize those contents, including through an in-root symlink.
fn retain_discovery_within_root(
    values: &mut Vec<serde_json::Value>,
    path_key: &str,
    root: &Path,
) {
    values.retain(|value| {
        value
            .get(path_key)
            .and_then(serde_json::Value::as_str)
            .and_then(|path| dunce::canonicalize(path).ok())
            .is_some_and(|path| path.starts_with(root))
    });
}

/// Resolve the project-selected primary agent on the remote host. This mirrors
/// the config precedence relevant to a project snapshot: an explicit
/// definition path wins over a discovered agent name. Untrusted project config
/// is never allowed to select an executable agent definition.
fn selected_project_agent_definition(
    root: &Path,
    project_config: &serde_json::Value,
) -> Option<xai_grok_agent::AgentDefinition> {
    let root = dunce::canonicalize(root).ok()?;
    let agent = project_config.get("agent")?.as_object()?;
    if let Some(definition) = agent.get("definition").and_then(serde_json::Value::as_str) {
        let path = Path::new(definition);
        let path = if path.is_absolute() {
            path.to_path_buf()
        } else {
            root.join(path)
        };
        let path = dunce::canonicalize(path).ok()?;
        return path
            .starts_with(&root)
            .then(|| xai_grok_agent::AgentDefinition::from_file(path).ok())
            .flatten();
    }
    let definition = agent
        .get("name")
        .and_then(serde_json::Value::as_str)
        .and_then(|name| xai_grok_agent::discovery::by_name_in_cwd(name, &root))?;
    let is_within_root = match definition.source_path.as_ref() {
        Some(path) => path.starts_with(&root),
        None => true,
    };
    is_within_root.then_some(definition)
}

struct PendingApproval {
    binding_id: String,
    session_id: String,
    sender: oneshot::Sender<SshApprovalDecision>,
}

struct WorkerConnection<W> {
    service: Arc<SshWorkerService>,
    writer: Arc<Mutex<W>>,
    accepted_bindings: Arc<RwLock<HashSet<String>>>,
    approvals: Arc<Mutex<HashMap<String, PendingApproval>>>,
    revocation_only: bool,
}

impl<W> Clone for WorkerConnection<W> {
    fn clone(&self) -> Self {
        Self {
            service: Arc::clone(&self.service),
            writer: Arc::clone(&self.writer),
            accepted_bindings: Arc::clone(&self.accepted_bindings),
            approvals: Arc::clone(&self.approvals),
            revocation_only: self.revocation_only,
        }
    }
}

impl<W: AsyncWrite + Unpin + Send + 'static> WorkerConnection<W> {
    async fn reply(
        &self,
        request_id: String,
        result: Result<SshWorkerResponse, SshWireError>,
    ) -> Result<(), SshClientError> {
        let mut writer = self.writer.lock().await;
        write_frame(
            &mut *writer,
            &SshWireFrame::Reply(SshWorkerReply { request_id, result }),
        )
        .await
    }

    async fn event(&self, event: SshWorkerEvent) -> Result<(), SshClientError> {
        let mut writer = self.writer.lock().await;
        write_frame(&mut *writer, &SshWireFrame::Event(event)).await
    }

    async fn approve(
        &self,
        approval_id: &str,
        binding_id: &str,
        session_id: &str,
        decision: SshApprovalDecision,
    ) -> Result<(), SshWireError> {
        if !self.accepted_bindings.read().await.contains(binding_id) {
            return Err(wire_error(
                "approval_not_owned",
                "binding was not admitted on this bridge",
            ));
        }
        let pending = {
            let mut approvals = self.approvals.lock().await;
            let Some(pending) = approvals.get(approval_id) else {
                return Err(wire_error(
                    "approval_not_found",
                    "approval is no longer pending on this bridge",
                ));
            };
            if pending.binding_id != binding_id || pending.session_id != session_id {
                return Err(wire_error(
                    "approval_not_owned",
                    "approval belongs to a different SSH binding or session",
                ));
            }
            approvals
                .remove(approval_id)
                .expect("pending approval was just checked")
        };
        pending
            .sender
            .send(decision)
            .map_err(|_| wire_error("approval_expired", "approval waiter has already closed"))
    }

    async fn request_approval(
        &self,
        operation_id: &str,
        binding: &SshBinding,
        operation: SshOperation,
        title: String,
        detail: serde_json::Value,
        cancellation: &CancellationToken,
    ) -> Result<(), SshWireError> {
        let approval_id = format!(
            "ssh-approval-{}-{}-{}",
            binding.id,
            operation_id,
            uuid::Uuid::now_v7()
        );
        let (sender, receiver) = oneshot::channel();
        self.approvals.lock().await.insert(
            approval_id.clone(),
            PendingApproval {
                binding_id: binding.id.clone(),
                session_id: binding.session_id.clone(),
                sender,
            },
        );
        let request = SshApprovalRequest {
            approval_id: approval_id.clone(),
            operation_id: operation_id.to_owned(),
            binding_id: binding.id.clone(),
            session_id: binding.session_id.clone(),
            operation,
            title,
            detail,
        };
        if self
            .event(SshWorkerEvent::ApprovalRequired(request))
            .await
            .is_err()
        {
            self.approvals.lock().await.remove(&approval_id);
            return Err(wire_error(
                "approval_delivery_failed",
                "approval UI bridge disconnected",
            ));
        }
        let decision = tokio::select! {
            decision = tokio::time::timeout(APPROVAL_TIMEOUT, receiver) => {
                match decision {
                    Ok(Ok(decision)) => Ok(decision),
                    Ok(Err(_)) => Err(wire_error("approval_disconnected", "approval UI disconnected")),
                    Err(_) => Err(wire_error("approval_timed_out", "approval was not answered")),
                }
            }
            _ = cancellation.cancelled() => Err(wire_error("cancelled", "operation cancelled while awaiting approval")),
        };
        self.approvals.lock().await.remove(&approval_id);
        let decision = decision?;
        if decision == SshApprovalDecision::Approve {
            Ok(())
        } else {
            Err(wire_error(
                "approval_denied",
                "user denied remote operation",
            ))
        }
    }
}

async fn emit_operation_update<W: AsyncWrite + Unpin + Send + 'static>(
    connection: &WorkerConnection<W>,
    operation: SshOperationRecord,
) {
    let _ = connection
        .event(SshWorkerEvent::Operation(operation.clone()))
        .await;
    let _ = connection
        .event(SshWorkerEvent::ToolNotification {
            operation_id: operation.operation_id.clone(),
            notification: serde_json::json!({
                "kind": "operation_state",
                "state": operation.state,
            }),
        })
        .await;
}

/// Serve one already-authenticated stream. The service deliberately outlives a
/// disconnected bridge when it is shared by a private daemon.
pub async fn serve_stream<S>(service: Arc<SshWorkerService>, stream: S) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut reader, mut writer) = tokio::io::split(stream);
    let hello = match read_frame(&mut reader)
        .await
        .context("reading worker hello")?
    {
        Some(SshWireFrame::ClientHello(hello)) => hello,
        Some(_) => bail!("SSH worker expected client hello as first frame"),
        None => return Ok(()),
    };
    if hello.protocol_version != SSH_WIRE_PROTOCOL_VERSION {
        let error = wire_error(
            "protocol_mismatch",
            format!(
                "client protocol {} is incompatible with worker protocol {}",
                hello.protocol_version, SSH_WIRE_PROTOCOL_VERSION
            ),
        );
        write_frame(&mut writer, &SshWireFrame::HandshakeError(error))
            .await
            .context("writing worker protocol mismatch")?;
        return Ok(());
    }
    let xai_grok_workspace_types::ssh_wire::SshClientHello {
        binding,
        resume_token,
        revocation_only,
        ..
    } = hello;
    let admission = if revocation_only {
        if resume_token.is_some() {
            Err(wire_error(
                "invalid_tombstone",
                "revocation-only SSH worker admission cannot resume an active binding",
            ))
        } else {
            service.admit_revocation_tombstone(binding).await
        }
    } else {
        match resume_token {
            Some(token) => service.resume(binding, token).await,
            None => service.bind(binding).await,
        }
    };
    let (binding, resume_token) = match admission {
        Ok(admission) => admission,
        Err(error) => {
            write_frame(&mut writer, &SshWireFrame::HandshakeError(error))
                .await
                .context("writing worker admission rejection")?;
            return Ok(());
        }
    };
    let root = binding.root.clone();
    write_frame(
        &mut writer,
        &SshWireFrame::WorkerHello(SshWorkerHello {
            protocol_version: SSH_WIRE_PROTOCOL_VERSION,
            worker_id: service.worker_id.clone(),
            os: std::env::consts::OS.to_owned(),
            path_semantics: if cfg!(windows) {
                SshPathSemantics::Windows
            } else {
                SshPathSemantics::Posix
            },
            capabilities: SshWorkerCapabilities::complete(),
            root,
            binding: binding.clone(),
            resume_token,
        }),
    )
    .await
    .context("writing worker hello")?;

    let connection = WorkerConnection {
        service,
        writer: Arc::new(Mutex::new(writer)),
        accepted_bindings: Arc::new(RwLock::new(HashSet::from([binding.id]))),
        approvals: Arc::new(Mutex::new(HashMap::new())),
        revocation_only,
    };
    while let Some(frame) = read_frame(&mut reader)
        .await
        .context("reading worker frame")?
    {
        let SshWireFrame::Request(request) = frame else {
            bail!("SSH worker received non-request after handshake");
        };
        let connection = connection.clone();
        tokio::spawn(async move {
            let request_id = request_id(&request).to_owned();
            let result = dispatch_request(&connection, request).await;
            let _ = connection.reply(request_id, result).await;
        });
    }
    Ok(())
}

async fn dispatch_request<W: AsyncWrite + Unpin + Send + 'static>(
    connection: &WorkerConnection<W>,
    request: SshWorkerRequest,
) -> Result<SshWorkerResponse, SshWireError> {
    if connection.revocation_only && !matches!(request, SshWorkerRequest::Revoke { .. }) {
        return Err(wire_error(
            "revocation_only",
            "a revocation tombstone bridge accepts only its revoke acknowledgement",
        ));
    }
    match request {
        SshWorkerRequest::Bind { binding, .. } => {
            let (binding, resume_token) = connection.service.bind(binding).await?;
            connection
                .accepted_bindings
                .write()
                .await
                .insert(binding.id.clone());
            Ok(SshWorkerResponse::Bound {
                binding,
                resume_token,
            })
        }
        SshWorkerRequest::Resume {
            binding,
            resume_token,
            ..
        } => {
            let (binding, resume_token) = connection.service.resume(binding, resume_token).await?;
            connection
                .accepted_bindings
                .write()
                .await
                .insert(binding.id.clone());
            Ok(SshWorkerResponse::Bound {
                binding,
                resume_token,
            })
        }
        SshWorkerRequest::Revoke {
            binding_id, epoch, ..
        } => {
            if !connection
                .accepted_bindings
                .read()
                .await
                .contains(&binding_id)
            {
                return Err(wire_error(
                    "binding_not_active",
                    "binding was not admitted on this bridge",
                ));
            }
            connection.service.revoke(&binding_id, epoch).await?;
            Ok(SshWorkerResponse::Revoked { binding_id, epoch })
        }
        SshWorkerRequest::Canonicalize {
            binding_id, path, ..
        } => {
            if !connection
                .accepted_bindings
                .read()
                .await
                .contains(&binding_id)
            {
                return Err(wire_error(
                    "binding_not_active",
                    "binding was not admitted on this bridge",
                ));
            }
            let bindings = connection.service.bindings.lock().await;
            let binding = bindings
                .get(&binding_id)
                .ok_or_else(|| wire_error("binding_not_found", "worker has no matching binding"))?;
            if binding.revoked || binding.binding.revoked {
                return Err(wire_error(
                    "authorization_revoked",
                    "binding authorization is no longer valid",
                ));
            }
            if !binding.binding.capabilities.permits(SshOperation::Read) {
                return Err(wire_error(
                    "capability_denied",
                    "binding capability does not permit path inspection",
                ));
            }
            let canonical = canonical_directory(Path::new(&path), Some(&binding.workspace.root))
                .map_err(|e| wire_error("invalid_path", e.to_string()))?;
            Ok(SshWorkerResponse::CanonicalPath(
                canonical.to_string_lossy().into_owned(),
            ))
        }
        SshWorkerRequest::Rpc {
            invocation,
            method,
            params,
            mutation_id,
            ..
        } => run_rpc(connection, invocation, method, params, mutation_id).await,
        SshWorkerRequest::ToolCall {
            invocation,
            tool_name,
            args,
            mutation_id,
            ..
        } => run_tool(connection, invocation, tool_name, args, mutation_id).await,
        SshWorkerRequest::Cancel {
            invocation,
            operation_id,
            ..
        } => {
            let authorized = connection
                .service
                .authorize(
                    &connection.accepted_bindings,
                    &invocation,
                    SshOperation::Read,
                )
                .await?;
            let cancellation = connection
                .service
                .cancel(&authorized, &operation_id)
                .await?;
            if let SshCancellation::OperationPending(operation) = &cancellation {
                emit_operation_update(connection, operation.clone()).await;
            }
            Ok(SshWorkerResponse::CancellationRequested(cancellation))
        }
        SshWorkerRequest::Operation {
            binding_id,
            session_id,
            operation_id,
            ..
        } => {
            ensure_query_owner(connection, &binding_id, &session_id).await?;
            let operation = connection
                .service
                .operation_for(&binding_id, &session_id, &operation_id)
                .await?;
            Ok(SshWorkerResponse::Operation(operation))
        }
        SshWorkerRequest::Mutation {
            binding_id,
            session_id,
            mutation_id,
            ..
        } => {
            ensure_query_owner(connection, &binding_id, &session_id).await?;
            let operation = connection
                .service
                .mutation_for(&binding_id, &session_id, &mutation_id)
                .await?;
            Ok(SshWorkerResponse::Operation(operation))
        }
        SshWorkerRequest::Tasks {
            binding_id,
            session_id,
            ..
        } => {
            let binding = ensure_query_owner(connection, &binding_id, &session_id).await?;
            let session = binding
                .workspace
                .handle
                .session(&session_id)
                .ok_or_else(|| wire_error("session_not_found", "worker session not found"))?;
            let tasks = session_tasks(&session.toolset(), &binding_id, &session_id).await;
            Ok(SshWorkerResponse::Tasks(tasks))
        }
        SshWorkerRequest::Approval {
            approval_id,
            binding_id,
            session_id,
            decision,
            ..
        } => {
            connection
                .approve(&approval_id, &binding_id, &session_id, decision)
                .await?;
            Ok(SshWorkerResponse::ApprovalRecorded)
        }
        SshWorkerRequest::Ping { .. } => Ok(SshWorkerResponse::Pong),
    }
}

async fn run_rpc<W: AsyncWrite + Unpin + Send + 'static>(
    connection: &WorkerConnection<W>,
    invocation: ResolvedSshInvocation,
    method: String,
    params: serde_json::Value,
    mutation_id: Option<SshMutationId>,
) -> Result<SshWorkerResponse, SshWireError> {
    let expected = workspace_rpc_operation(&method);
    let authorized = connection
        .service
        .authorize(&connection.accepted_bindings, &invocation, expected)
        .await?;
    ensure_json_paths_within_root(&params, &authorized.workspace.root, &authorized.cwd)
        .map_err(|e| wire_error("path_denied", e.to_string()))?;
    ensure_json_session_owner(&params, &authorized.binding.session_id)
        .map_err(|e| wire_error("session_denied", e.to_string()))?;
    let begin = connection
        .service
        .begin_operation(&authorized.binding, expected, mutation_id)
        .await?;
    let (operation_id, cancellation) = match begin {
        BeginOperation::Existing(operation) => {
            let value = operation.result.clone().ok_or_else(|| {
                wire_error(
                    "mutation_not_replayable",
                    "completed mutation has no stored result",
                )
            })?;
            return Ok(SshWorkerResponse::Rpc { operation, value });
        }
        BeginOperation::Started {
            operation_id,
            cancellation,
        } => (operation_id, cancellation),
    };
    let running = connection.service.mark_running(&operation_id).await?;
    emit_operation_update(connection, running).await;
    if expected != SshOperation::Read {
        if let Err(error) = connection
            .request_approval(
                &operation_id,
                &authorized.binding,
                expected,
                format!("Remote workspace RPC: {method}"),
                approval_detail(
                    &authorized.binding,
                    &authorized.cwd,
                    serde_json::json!({"method": method, "params": params.clone()}),
                ),
                &cancellation,
            )
            .await
        {
            let operation = if cancellation.is_cancelled() {
                connection
                    .service
                    .confirm_cancelled(&operation_id, "operation cancelled while awaiting approval")
                    .await?
            } else {
                connection
                    .service
                    .complete(&operation_id, Err(error.clone()))
                    .await?
            };
            emit_operation_update(connection, operation).await;
            return Err(error);
        }
    }
    if cancellation.is_cancelled() {
        let operation = connection
            .service
            .confirm_cancelled(&operation_id, "operation cancelled before RPC dispatch")
            .await?;
        emit_operation_update(connection, operation).await;
        return Err(wire_error(
            "cancelled",
            "operation cancelled before dispatch",
        ));
    }
    let authorized = match connection
        .service
        .authorize(&connection.accepted_bindings, &invocation, expected)
        .await
    {
        Ok(authorized) => authorized,
        Err(error) => {
            let operation = connection
                .service
                .complete(&operation_id, Err(error.clone()))
                .await?;
            emit_operation_update(connection, operation).await;
            return Err(error);
        }
    };
    if let Err(error) =
        ensure_json_paths_within_root(&params, &authorized.workspace.root, &authorized.cwd)
            .map_err(|e| wire_error("path_denied", e.to_string()))
    {
        let operation = connection
            .service
            .complete(&operation_id, Err(error.clone()))
            .await?;
        emit_operation_update(connection, operation).await;
        return Err(error);
    }
    if let Err(error) = ensure_json_session_owner(&params, &authorized.binding.session_id)
        .map_err(|e| wire_error("session_denied", e.to_string()))
    {
        let operation = connection
            .service
            .complete(&operation_id, Err(error.clone()))
            .await?;
        emit_operation_update(connection, operation).await;
        return Err(error);
    }
    let result = if method == "workspace.project_bootstrap" {
        authorized
            .workspace
            .project_bootstrap(&authorized.binding.session_id)
            .await
            .and_then(|bootstrap| {
                serde_json::to_value(bootstrap)
                    .map_err(|error| wire_error("bootstrap_encode_failed", error.to_string()))
            })
    } else if method == "workspace.discover_agents_md" {
        Ok(serde_json::Value::Array(
            authorized.workspace.instruction_files().await,
        ))
    } else if method == "workspace.discover_skills" {
        Ok(serde_json::Value::Array(authorized.workspace.skills().await))
    } else if method == "workspace.skill_content" {
        match params.get("path").and_then(serde_json::Value::as_str) {
            Some(path) => {
                let skill = xai_grok_tools::implementations::skills::types::SkillInfo {
                    path: path.to_owned(),
                    ..Default::default()
                };
                xai_grok_tools::implementations::skills::skill::load_skill_content(&skill)
                    .await
                    .map(|mut content| {
                        xai_grok_tools::implementations::skills::skill::cap_skill_body(&mut content);
                        serde_json::Value::String(content)
                    })
                    .map_err(|error| wire_error("skill_read_failed", error))
            }
            None => Err(wire_error("invalid_skill", "skill content requires a path")),
        }
    } else if method == "workspace.discover_plugins" {
        let workspace = &authorized.workspace;
        let mut plugins = crate::discovery::discover_plugins(
            &workspace.root,
            workspace.handle.shared.plugin_discovery_config(),
            &crate::discovery::PluginTrustStore::load(),
            workspace.project_trusted,
        );
        retain_discovery_within_root(&mut plugins, "root", &workspace.root);
        Ok(serde_json::Value::Array(plugins))
    } else if method == "workspace.load_project_config" {
        authorized.workspace.project_config()
    } else if method == "workspace.dispatch_hook" {
        let envelope = serde_json::from_value(
            params
                .get("envelope")
                .cloned()
                .ok_or_else(|| wire_error("invalid_hook", "missing hook envelope"))?,
        )
        .map_err(|error| wire_error("invalid_hook", error.to_string()))?;
        dispatch_worker_remote_observe_hook(&authorized.workspace, &authorized.binding, envelope)
            .await
            .map(|_| serde_json::Value::Null)
    } else if method == "workspace.dispatch_prompt_hook" {
        let envelope = serde_json::from_value(
            params
                .get("envelope")
                .cloned()
                .ok_or_else(|| wire_error("invalid_hook", "missing hook envelope"))?,
        )
        .map_err(|error| wire_error("invalid_hook", error.to_string()))?;
        dispatch_worker_remote_prompt_hook(&authorized.workspace, &authorized.binding, envelope)
            .await
    } else if method == "workspace.dispatch_stop_hook" {
        let envelope = serde_json::from_value(
            params
                .get("envelope")
                .cloned()
                .ok_or_else(|| wire_error("invalid_hook", "missing hook envelope"))?,
        )
        .map_err(|error| wire_error("invalid_hook", error.to_string()))?;
        dispatch_worker_remote_stop_hook(&authorized.workspace, &authorized.binding, envelope).await
    } else {
        authorized
            .workspace
            .rpc
            .dispatch(&method, params, Some(&authorized.binding.session_id))
            .await
            .map_err(|error| wire_error("workspace_rpc_failed", error.to_string()))
    };
    // RPC dispatch has no cancellation token. Once it has started, retain the
    // actual terminal result instead of falsely reporting cancellation.
    let operation = connection
        .service
        .complete(&operation_id, result.clone())
        .await?;
    emit_operation_update(connection, operation.clone()).await;
    let value = result?;
    Ok(SshWorkerResponse::Rpc { operation, value })
}

async fn run_tool<W: AsyncWrite + Unpin + Send + 'static>(
    connection: &WorkerConnection<W>,
    invocation: ResolvedSshInvocation,
    tool_name: String,
    args: serde_json::Value,
    mutation_id: Option<SshMutationId>,
) -> Result<SshWorkerResponse, SshWireError> {
    let binding_id = invocation.binding_id.clone();
    let session_id = invocation.session_id.clone();
    let (resolved_tool_name, expected, toolset) = {
        let bindings = connection.service.bindings.lock().await;
        let state = bindings
            .get(&binding_id)
            .ok_or_else(|| wire_error("binding_not_found", "worker has no matching binding"))?;
        let session = state
            .workspace
            .handle
            .session(&session_id)
            .ok_or_else(|| wire_error("session_not_found", "worker session not found"))?;
        let toolset = session.toolset();
        let resolved = toolset
            .tool_name_for_registry_id(&tool_name)
            .unwrap_or_else(|| tool_name.clone());
        let operation = classify_tool_operation(&toolset, &resolved);
        (resolved, operation, toolset)
    };
    let authorized = connection
        .service
        .authorize(&connection.accepted_bindings, &invocation, expected)
        .await?;
    ensure_json_paths_within_root(&args, &authorized.workspace.root, &authorized.cwd)
        .map_err(|e| wire_error("path_denied", e.to_string()))?;
    ensure_json_session_owner(&args, &authorized.binding.session_id)
        .map_err(|e| wire_error("session_denied", e.to_string()))?;
    authorized.workspace.prepare_skill_discovery(&toolset).await?;
    let begin = connection
        .service
        .begin_operation(&authorized.binding, expected, mutation_id)
        .await?;
    let (operation_id, cancellation) = match begin {
        BeginOperation::Existing(operation) => {
            let value = operation.result.clone().ok_or_else(|| {
                wire_error(
                    "mutation_not_replayable",
                    "completed mutation has no stored result",
                )
            })?;
            return Ok(SshWorkerResponse::Tool { operation, value });
        }
        BeginOperation::Started {
            operation_id,
            cancellation,
        } => (operation_id, cancellation),
    };
    let running = connection.service.mark_running(&operation_id).await?;
    emit_operation_update(connection, running).await;
    let hook_authorized = match connection
        .service
        .authorize(&connection.accepted_bindings, &invocation, expected)
        .await
    {
        Ok(authorized) => authorized,
        Err(error) => {
            let operation = connection
                .service
                .complete(&operation_id, Err(error.clone()))
                .await?;
            emit_operation_update(connection, operation).await;
            return Err(error);
        }
    };
    let pre_hook = match dispatch_worker_pre_tool_hook(
        &hook_authorized.workspace,
        &hook_authorized.binding,
        &resolved_tool_name,
        &invocation.call_id,
        args,
    )
    .await
    {
        Ok(result) => result,
        Err(error) => {
            let operation = connection
                .service
                .complete(&operation_id, Err(error.clone()))
                .await?;
            emit_operation_update(connection, operation).await;
            return Err(error);
        }
    };
    let (args, hook_ask, pre_tool_context) = match pre_hook {
        WorkerPreToolHook::Continue {
            args,
            additional_context,
        } => (args, None, additional_context),
        WorkerPreToolHook::Ask {
            args,
            hook_name,
            reason,
            additional_context,
        } => (args, Some((hook_name, reason)), additional_context),
    };
    if let Some((hook_name, reason)) = hook_ask {
        if let Err(error) = connection
            .request_approval(
                &operation_id,
                &authorized.binding,
                SshOperation::Execute,
                format!("Remote project hook: {hook_name}"),
                approval_detail(
                    &authorized.binding,
                    &authorized.cwd,
                    serde_json::json!({
                        "hook_name": hook_name,
                        "reason": reason,
                        "tool_name": tool_name,
                        "args": args,
                    }),
                ),
                &cancellation,
            )
            .await
        {
            let operation = if cancellation.is_cancelled() {
                connection
                    .service
                    .confirm_cancelled(
                        &operation_id,
                        "operation cancelled while awaiting hook approval",
                    )
                    .await?
            } else {
                connection
                    .service
                    .complete(&operation_id, Err(error.clone()))
                    .await?
            };
            emit_operation_update(connection, operation).await;
            return Err(error);
        }
    }
    if expected != SshOperation::Read {
        if let Err(error) = connection
            .request_approval(
                &operation_id,
                &authorized.binding,
                expected,
                format!("Remote tool: {tool_name}"),
                approval_detail(
                    &authorized.binding,
                    &authorized.cwd,
                    serde_json::json!({"tool_name": tool_name, "args": args.clone()}),
                ),
                &cancellation,
            )
            .await
        {
            let operation = if cancellation.is_cancelled() {
                connection
                    .service
                    .confirm_cancelled(&operation_id, "operation cancelled while awaiting approval")
                    .await?
            } else {
                connection
                    .service
                    .complete(&operation_id, Err(error.clone()))
                    .await?
            };
            emit_operation_update(connection, operation).await;
            return Err(error);
        }
    }
    if cancellation.is_cancelled() {
        let operation = connection
            .service
            .confirm_cancelled(&operation_id, "operation cancelled before tool dispatch")
            .await?;
        emit_operation_update(connection, operation).await;
        return Err(wire_error(
            "cancelled",
            "operation cancelled before dispatch",
        ));
    }
    let authorized = match connection
        .service
        .authorize(&connection.accepted_bindings, &invocation, expected)
        .await
    {
        Ok(authorized) => authorized,
        Err(error) => {
            let operation = connection
                .service
                .complete(&operation_id, Err(error.clone()))
                .await?;
            emit_operation_update(connection, operation).await;
            return Err(error);
        }
    };
    if let Err(error) =
        ensure_json_paths_within_root(&args, &authorized.workspace.root, &authorized.cwd)
            .map_err(|e| wire_error("path_denied", e.to_string()))
    {
        let operation = connection
            .service
            .complete(&operation_id, Err(error.clone()))
            .await?;
        emit_operation_update(connection, operation).await;
        return Err(error);
    }
    if let Err(error) = ensure_json_session_owner(&args, &authorized.binding.session_id)
        .map_err(|e| wire_error("session_denied", e.to_string()))
    {
        let operation = connection
            .service
            .complete(&operation_id, Err(error.clone()))
            .await?;
        emit_operation_update(connection, operation).await;
        return Err(error);
    }
    let call_id = xai_tool_protocol::ToolCallId::new(invocation.call_id.as_str())
        .unwrap_or_else(|_| xai_tool_protocol::ToolCallId::new_v7());
    let (notification_handle, mut notifications) = ToolNotificationHandle::channel();
    let notification_connection = connection.clone();
    let notification_operation_id = operation_id.clone();
    tokio::spawn(async move {
        while let Some(notification) = notifications.recv().await {
            if let Ok(payload) = serde_json::to_value(notification) {
                let _ = notification_connection
                    .event(SshWorkerEvent::ToolNotification {
                        operation_id: notification_operation_id.clone(),
                        notification: payload,
                    })
                    .await;
            }
        }
    });
    let mut context = ToolCallContext::new(call_id);
    context.insert(xai_tool_runtime::Cwd(authorized.cwd));
    context.insert(Cancellation(cancellation.clone()));
    // Bash and other streaming tools honor this per-call sink without changing
    // the session-wide resource. The forwarder remains alive for a background
    // task after its initial tool response completes.
    context.insert(PerCallNotificationSink(notification_handle));
    let tool_started_at = std::time::Instant::now();
    let mut stream =
        toolset.call_streaming_with_context(&resolved_tool_name, args.clone(), context);
    let mut result = loop {
        let item = std::future::poll_fn(|cx| stream.as_mut().poll_next(cx)).await;
        match item {
            Some(ToolStreamItem::Progress(progress)) => {
                let _ = connection
                    .event(SshWorkerEvent::ToolProgress {
                        operation_id: operation_id.clone(),
                        progress: progress_to_wire(progress),
                    })
                    .await;
            }
            Some(ToolStreamItem::Terminal(Ok(output))) => {
                break serde_json::to_value(output).map_err(|error| {
                    wire_error("tool_result_serialize_failed", error.to_string())
                });
            }
            Some(ToolStreamItem::Terminal(Err(error))) => {
                break Err(wire_error("tool_failed", error.to_string()));
            }
            None => {
                break Err(wire_error(
                    "tool_stream_ended",
                    "tool stream ended without a terminal result",
                ));
            }
        }
    };
    let mut post_hook = if let Ok(hook_authorized) = connection
        .service
        .authorize(&connection.accepted_bindings, &invocation, expected)
        .await
    {
        dispatch_worker_post_tool_hook(
            &hook_authorized.workspace,
            &hook_authorized.binding,
            &resolved_tool_name,
            &invocation.call_id,
            &args,
            &result,
            u64::try_from(tool_started_at.elapsed().as_millis()).unwrap_or(u64::MAX),
        )
        .await
    } else {
        None
    };
    if !pre_tool_context.is_empty() {
        post_hook
            .get_or_insert_with(SshPostToolHookOutcome::default)
            .pre_tool_context = pre_tool_context;
    }
    if let (Err(error), Some(post_hook)) = (&mut result, post_hook.clone()) {
        error.post_hook = Some(post_hook);
    }
    // A tool receives the cancellation token, but only its terminal stream can
    // prove whether side effects stopped. Preserve that actual terminal result.
    let operation = connection
        .service
        .complete_tool(&operation_id, result.clone(), post_hook)
        .await?;
    emit_operation_update(connection, operation.clone()).await;
    let value = result?;
    Ok(SshWorkerResponse::Tool { operation, value })
}

/// Execute an observe-only hook on the worker that owns the granted remote root.
///
/// The shell may display a worker hook registry, but it must never execute that
/// registry locally. Project hook commands are eligible only for an executable,
/// trusted SSH binding and always receive the canonical remote workspace root.
async fn dispatch_worker_observe_hook(
    workspace: &WorkerWorkspace,
    binding: &SshBinding,
    event: HookEventName,
    payload: HookPayload,
) -> Option<SshPostToolHookOutcome> {
    if !binding.capabilities.permits(SshOperation::Execute) || !workspace.project_trusted {
        return None;
    }
    let registry = workspace.handle.hook_registry();
    if registry.is_empty() {
        return None;
    }
    let workspace_root = workspace.root.to_string_lossy().into_owned();
    let envelope = HookEventEnvelope {
        hook_event_name: event.canonical(),
        session_id: binding.session_id.clone(),
        cwd: binding.cwd.clone(),
        workspace_root: workspace_root.clone(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        transcript_path: None,
        client_identifier: None,
        prompt_id: None,
        permission_mode: None,
        payload,
    };
    let disabled = Arc::new(crate::permission::resolution::disabled_hooks_snapshot(
        crate::permission::resolution::managed_settings(),
        xai_grok_config::user_grok_home().as_deref(),
    ));
    let context = HookRunContext {
        session_id: &binding.session_id,
        workspace_root: &workspace_root,
        process_scope: None,
        disabled,
    };
    if event == HookEventName::PostToolUse {
        let result =
            xai_grok_hooks::dispatcher::dispatch_post_tool_use(&registry, &envelope, &context)
                .await;
        Some(post_hook_outcome_to_wire(result))
    } else {
        let _ = xai_grok_hooks::dispatcher::dispatch_non_blocking(
            &registry, event, &envelope, &context,
        )
        .await;
        None
    }
}

fn post_hook_outcome_to_wire(
    result: xai_grok_hooks::dispatcher::PostToolUseResult,
) -> SshPostToolHookOutcome {
    let replacement =
        |selected: xai_grok_hooks::dispatcher::SelectedReplacement| SshPostToolReplacement {
            value: selected.replacement.value,
            run_index: selected.run_index,
        };
    SshPostToolHookOutcome {
        post_tool_failure: false,
        pre_tool_context: Vec::new(),
        builtin_replacement: result.builtin_replacement.map(replacement),
        mcp_replacement: result.mcp_replacement.map(replacement),
        additional_context: result
            .additional_context
            .into_iter()
            .map(|note| SshPostToolHookNote {
                hook_name: note.hook_name,
                text: note.text,
            })
            .collect(),
        blocks: result
            .blocks
            .into_iter()
            .map(|note| SshPostToolHookNote {
                hook_name: note.hook_name,
                text: note.reason,
            })
            .collect(),
    }
}

/// Run a passive lifecycle event received from the session actor. Remote
/// identity fields are always reconstructed from the authorized binding rather
/// than trusted from the client-provided envelope.
async fn dispatch_worker_remote_observe_hook(
    workspace: &WorkerWorkspace,
    binding: &SshBinding,
    mut envelope: HookEventEnvelope,
) -> Result<(), SshWireError> {
    if envelope.hook_event_name.traits().gate != xai_grok_hooks::event::GateKind::Observe {
        return Err(wire_error(
            "invalid_hook",
            "only passive lifecycle hooks may use workspace.dispatch_hook",
        ));
    }
    if !binding.capabilities.permits(SshOperation::Execute) || !workspace.project_trusted {
        return Ok(());
    }
    let registry = workspace.handle.hook_registry();
    if registry.is_empty() {
        return Ok(());
    }
    let workspace_root = workspace.root.to_string_lossy().into_owned();
    envelope.hook_event_name = envelope.hook_event_name.canonical();
    envelope.session_id = binding.session_id.clone();
    envelope.cwd = binding.cwd.clone();
    envelope.workspace_root = workspace_root.clone();
    envelope.timestamp = chrono::Utc::now().to_rfc3339();
    let disabled = Arc::new(crate::permission::resolution::disabled_hooks_snapshot(
        crate::permission::resolution::managed_settings(),
        xai_grok_config::user_grok_home().as_deref(),
    ));
    let context = HookRunContext {
        session_id: &binding.session_id,
        workspace_root: &workspace_root,
        process_scope: None,
        disabled,
    };
    let _ = xai_grok_hooks::dispatcher::dispatch_non_blocking(
        &registry,
        envelope.hook_event_name,
        &envelope,
        &context,
    )
    .await;
    Ok(())
}

/// Run a user-prompt gate on the remote worker and return only its verdict to
/// the local session actor. Command execution remains wholly remote.
async fn dispatch_worker_remote_prompt_hook(
    workspace: &WorkerWorkspace,
    binding: &SshBinding,
    mut envelope: HookEventEnvelope,
) -> Result<serde_json::Value, SshWireError> {
    if envelope.hook_event_name != HookEventName::UserPromptSubmit {
        return Err(wire_error(
            "invalid_hook",
            "workspace.dispatch_prompt_hook requires UserPromptSubmit",
        ));
    }
    if !binding.capabilities.permits(SshOperation::Execute) || !workspace.project_trusted {
        return Ok(serde_json::json!({"decision": "allow"}));
    }
    let registry = workspace.handle.hook_registry();
    if registry.is_empty() {
        return Ok(serde_json::json!({"decision": "allow"}));
    }
    let workspace_root = workspace.root.to_string_lossy().into_owned();
    envelope.session_id = binding.session_id.clone();
    envelope.cwd = binding.cwd.clone();
    envelope.workspace_root = workspace_root.clone();
    envelope.timestamp = chrono::Utc::now().to_rfc3339();
    let disabled = Arc::new(crate::permission::resolution::disabled_hooks_snapshot(
        crate::permission::resolution::managed_settings(),
        xai_grok_config::user_grok_home().as_deref(),
    ));
    let context = HookRunContext {
        session_id: &binding.session_id,
        workspace_root: &workspace_root,
        process_scope: None,
        disabled,
    };
    let result =
        xai_grok_hooks::dispatcher::dispatch_prompt_gate(&registry, &envelope, &context).await;
    Ok(match result.decision {
        xai_grok_hooks::result::PromptDecision::Allow => serde_json::json!({"decision": "allow"}),
        xai_grok_hooks::result::PromptDecision::Block { reason, hook_name } => {
            serde_json::json!({"decision": "block", "reason": reason, "hookName": hook_name})
        }
    })
}

/// Run the remote Stop gate and return the only decision the local turn loop
/// needs: continue with feedback, or allow the turn to end.
async fn dispatch_worker_remote_stop_hook(
    workspace: &WorkerWorkspace,
    binding: &SshBinding,
    mut envelope: HookEventEnvelope,
) -> Result<serde_json::Value, SshWireError> {
    if !matches!(
        envelope.hook_event_name,
        HookEventName::Stop | HookEventName::SubagentStop
    ) {
        return Err(wire_error(
            "invalid_hook",
            "workspace.dispatch_stop_hook requires Stop or SubagentStop",
        ));
    }
    if !binding.capabilities.permits(SshOperation::Execute) || !workspace.project_trusted {
        return Ok(serde_json::json!({"continue": false}));
    }
    let registry = workspace.handle.hook_registry();
    if registry.is_empty() {
        return Ok(serde_json::json!({"continue": false}));
    }
    let workspace_root = workspace.root.to_string_lossy().into_owned();
    envelope.hook_event_name = envelope.hook_event_name.canonical();
    envelope.session_id = binding.session_id.clone();
    envelope.cwd = binding.cwd.clone();
    envelope.workspace_root = workspace_root.clone();
    envelope.timestamp = chrono::Utc::now().to_rfc3339();
    let disabled = Arc::new(crate::permission::resolution::disabled_hooks_snapshot(
        crate::permission::resolution::managed_settings(),
        xai_grok_config::user_grok_home().as_deref(),
    ));
    let context = HookRunContext {
        session_id: &binding.session_id,
        workspace_root: &workspace_root,
        process_scope: None,
        disabled,
    };
    let result = xai_grok_hooks::dispatcher::dispatch_stop(
        &registry,
        envelope.hook_event_name,
        &envelope,
        &context,
    )
    .await;
    Ok(serde_json::json!({
        "continue": result.wants_continuation(),
        "feedback": result.feedback(),
    }))
}

enum WorkerPreToolHook {
    Continue {
        args: serde_json::Value,
        additional_context: Vec<SshPostToolHookNote>,
    },
    Ask {
        args: serde_json::Value,
        hook_name: String,
        reason: Option<String>,
        additional_context: Vec<SshPostToolHookNote>,
    },
}

/// Run a project `PreToolUse` gate in the worker before its target tool starts.
///
/// A denial prevents execution, a rewrite is re-authorized against the remote
/// root, and an ask uses the normal SSH approval channel instead of a local
/// prompt.
async fn dispatch_worker_pre_tool_hook(
    workspace: &WorkerWorkspace,
    binding: &SshBinding,
    tool_name: &str,
    tool_use_id: &str,
    args: serde_json::Value,
) -> Result<WorkerPreToolHook, SshWireError> {
    if !binding.capabilities.permits(SshOperation::Execute) || !workspace.project_trusted {
        return Ok(WorkerPreToolHook::Continue {
            args,
            additional_context: Vec::new(),
        });
    }
    let registry = workspace.handle.hook_registry();
    if registry.is_empty() {
        return Ok(WorkerPreToolHook::Continue {
            args,
            additional_context: Vec::new(),
        });
    }
    let (tool_input, tool_input_truncated) = xai_grok_hooks::event::truncate_payload(args.clone());
    let workspace_root = workspace.root.to_string_lossy().into_owned();
    let envelope = HookEventEnvelope {
        hook_event_name: HookEventName::PreToolUse,
        session_id: binding.session_id.clone(),
        cwd: binding.cwd.clone(),
        workspace_root: workspace_root.clone(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        transcript_path: None,
        client_identifier: None,
        prompt_id: None,
        permission_mode: None,
        payload: HookPayload::PreToolUse {
            tool_name: tool_name.to_owned(),
            tool_use_id: tool_use_id.to_owned(),
            tool_input,
            tool_input_truncated,
            subagent_type: None,
        },
    };
    let disabled = Arc::new(crate::permission::resolution::disabled_hooks_snapshot(
        crate::permission::resolution::managed_settings(),
        xai_grok_config::user_grok_home().as_deref(),
    ));
    let context = HookRunContext {
        session_id: &binding.session_id,
        workspace_root: &workspace_root,
        process_scope: None,
        disabled,
    };
    let result =
        xai_grok_hooks::dispatcher::dispatch_pre_tool_use(&registry, &envelope, &context).await;
    let additional_context = result
        .additional_context
        .into_iter()
        .map(|note| SshPostToolHookNote {
            hook_name: note.hook_name,
            text: note.text,
        })
        .collect();
    let args = result
        .updated_input
        .map(|rewrite| serde_json::Value::Object(rewrite.input))
        .unwrap_or(args);
    match result.decision {
        xai_grok_hooks::result::HookDecision::Allow
        | xai_grok_hooks::result::HookDecision::Defer { .. } => Ok(WorkerPreToolHook::Continue {
            args,
            additional_context,
        }),
        xai_grok_hooks::result::HookDecision::Ask { hook_name, reason } => {
            Ok(WorkerPreToolHook::Ask {
                args,
                hook_name,
                reason,
                additional_context,
            })
        }
        xai_grok_hooks::result::HookDecision::Deny { hook_name, reason } => Err(wire_error(
            "hook_denied",
            format!("project hook {hook_name} denied remote tool: {reason}"),
        )),
    }
}

/// Run a remote post-tool hook only after the worker observes a terminal tool
/// result. Replayed mutations intentionally bypass this path.
async fn dispatch_worker_post_tool_hook(
    workspace: &WorkerWorkspace,
    binding: &SshBinding,
    tool_name: &str,
    tool_use_id: &str,
    args: &serde_json::Value,
    result: &Result<serde_json::Value, SshWireError>,
    duration_ms: u64,
) -> Option<SshPostToolHookOutcome> {
    let (tool_input, tool_input_truncated) = xai_grok_hooks::event::truncate_payload(args.clone());
    match result {
        Ok(output) => {
            if let Ok(tool_result) = serde_json::from_value::<ToolRunResult>(output.clone())
                && matches!(
                    &tool_result.output,
                    xai_grok_tools::types::output::ToolOutput::MCP(_)
                )
                && tool_result.output.is_error()
            {
                return dispatch_worker_post_tool_failure_hook(
                    workspace,
                    binding,
                    tool_name,
                    tool_use_id,
                    tool_input,
                    tool_input_truncated,
                    tool_result.output.to_prompt_format(),
                    duration_ms,
                )
                .await;
            }
            let (tool_result, tool_result_truncated) =
                xai_grok_hooks::event::truncate_payload(output.clone());
            dispatch_worker_observe_hook(
                workspace,
                binding,
                HookEventName::PostToolUse,
                HookPayload::PostToolUse {
                    tool_name: tool_name.to_owned(),
                    tool_use_id: tool_use_id.to_owned(),
                    tool_input,
                    tool_result,
                    tool_input_truncated,
                    tool_result_truncated,
                    duration_ms: Some(duration_ms),
                    is_backgrounded: false,
                    subagent_type: None,
                },
            )
            .await
        }
        Err(error) => {
            dispatch_worker_post_tool_failure_hook(
                workspace,
                binding,
                tool_name,
                tool_use_id,
                tool_input,
                tool_input_truncated,
                format!("{}: {}", error.code, error.message),
                duration_ms,
            )
            .await
        }
    }
}

async fn dispatch_worker_post_tool_failure_hook(
    workspace: &WorkerWorkspace,
    binding: &SshBinding,
    tool_name: &str,
    tool_use_id: &str,
    tool_input: serde_json::Value,
    tool_input_truncated: bool,
    error: String,
    duration_ms: u64,
) -> Option<SshPostToolHookOutcome> {
    if !binding.capabilities.permits(SshOperation::Execute) || !workspace.project_trusted {
        return None;
    }
    let registry = workspace.handle.hook_registry();
    if registry.is_empty() {
        return None;
    }
    let workspace_root = workspace.root.to_string_lossy().into_owned();
    let envelope = HookEventEnvelope {
        hook_event_name: HookEventName::PostToolUseFailure,
        session_id: binding.session_id.clone(),
        cwd: binding.cwd.clone(),
        workspace_root: workspace_root.clone(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        transcript_path: None,
        client_identifier: None,
        prompt_id: None,
        permission_mode: None,
        payload: HookPayload::PostToolUseFailure {
            tool_name: tool_name.to_owned(),
            tool_use_id: tool_use_id.to_owned(),
            tool_input,
            tool_input_truncated,
            error,
            duration_ms: Some(duration_ms),
            is_interrupt: false,
            subagent_type: None,
        },
    };
    let disabled = Arc::new(crate::permission::resolution::disabled_hooks_snapshot(
        crate::permission::resolution::managed_settings(),
        xai_grok_config::user_grok_home().as_deref(),
    ));
    let context = HookRunContext {
        session_id: &binding.session_id,
        workspace_root: &workspace_root,
        process_scope: None,
        disabled,
    };
    let result =
        xai_grok_hooks::dispatcher::dispatch_post_tool_use_failure(&registry, &envelope, &context)
            .await;
    Some(SshPostToolHookOutcome {
        post_tool_failure: true,
        additional_context: result
            .additional_context
            .into_iter()
            .map(|note| SshPostToolHookNote {
                hook_name: note.hook_name,
                text: note.text,
            })
            .collect(),
        ..SshPostToolHookOutcome::default()
    })
}

async fn ensure_query_owner<W: AsyncWrite + Unpin + Send + 'static>(
    connection: &WorkerConnection<W>,
    binding_id: &str,
    session_id: &str,
) -> Result<BindingStateView, SshWireError> {
    if !connection
        .accepted_bindings
        .read()
        .await
        .contains(binding_id)
    {
        return Err(wire_error(
            "binding_not_active",
            "binding was not admitted on this bridge",
        ));
    }
    let bindings = connection.service.bindings.lock().await;
    let state = bindings
        .get(binding_id)
        .ok_or_else(|| wire_error("binding_not_found", "worker has no matching binding"))?;
    if state.revoked || state.binding.revoked || state.binding.session_id != session_id {
        return Err(wire_error(
            "operation_not_owned",
            "binding/session does not own this request",
        ));
    }
    if !state.binding.capabilities.permits(SshOperation::Read) {
        return Err(wire_error(
            "capability_denied",
            "binding capability does not permit operation inspection",
        ));
    }
    Ok(BindingStateView {
        workspace: Arc::clone(&state.workspace),
    })
}

struct BindingStateView {
    workspace: Arc<WorkerWorkspace>,
}

async fn session_tasks(
    toolset: &xai_grok_tools::registry::types::FinalizedToolset,
    binding_id: &str,
    session_id: &str,
) -> Vec<SshTaskRecord> {
    let terminal = {
        let resources = toolset.resources.lock().await;
        resources
            .get::<Terminal>()
            .map(|terminal| terminal.0.clone())
    };
    let Some(terminal) = terminal else {
        return Vec::new();
    };
    terminal
        .list_tasks()
        .await
        .into_iter()
        .map(|task| SshTaskRecord {
            task_id: task.task_id,
            binding_id: binding_id.to_owned(),
            session_id: session_id.to_owned(),
            command: task.display_command.unwrap_or(task.command),
            completed: task.completed,
        })
        .collect()
}

fn classify_tool_operation(
    toolset: &xai_grok_tools::registry::types::FinalizedToolset,
    tool_name: &str,
) -> SshOperation {
    toolset
        .get_tool_metadata(tool_name)
        .map(|metadata| ssh_operation_for_tool_kind(metadata.kind()))
        // Unknown/custom tools are never treated as read-only.
        .unwrap_or(SshOperation::Execute)
}

fn progress_to_wire(progress: ToolProgress) -> SshToolProgress {
    match progress {
        ToolProgress::Text { text } => SshToolProgress {
            kind: "text".into(),
            body: serde_json::json!({"text": text}),
        },
        ToolProgress::Content { blocks } => SshToolProgress {
            kind: "content".into(),
            body: serde_json::to_value(blocks).unwrap_or(serde_json::Value::Null),
        },
        ToolProgress::Custom { subkind, payload } => SshToolProgress {
            kind: subkind,
            body: payload,
        },
    }
}

fn canonical_directory(path: &Path, root: Option<&Path>) -> anyhow::Result<PathBuf> {
    let candidate = match root {
        Some(root) if path.is_relative() => root.join(path),
        _ => path.to_path_buf(),
    };
    let canonical = dunce::canonicalize(&candidate).with_context(|| {
        format!(
            "path does not exist or cannot be resolved: {}",
            candidate.display()
        )
    })?;
    if !canonical.is_dir() {
        bail!("path is not a directory: {}", canonical.display());
    }
    if let Some(root) = root
        && !canonical.starts_with(root)
    {
        bail!("path escapes authorized root");
    }
    Ok(canonical)
}

fn ensure_json_paths_within_root(
    value: &serde_json::Value,
    root: &Path,
    cwd: &Path,
) -> anyhow::Result<()> {
    match value {
        serde_json::Value::Object(fields) => {
            for (name, value) in fields {
                if is_id_or_path_field(name) {
                    ensure_json_path_value_within_root(value, root, cwd, false)?;
                } else if is_path_field(name) {
                    ensure_json_path_value_within_root(value, root, cwd, true)?;
                }
                ensure_json_paths_within_root(value, root, cwd)?;
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                ensure_json_paths_within_root(value, root, cwd)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn ensure_json_session_owner(value: &serde_json::Value, session_id: &str) -> anyhow::Result<()> {
    match value {
        serde_json::Value::Object(fields) => {
            for (name, value) in fields {
                let normalized = name.to_ascii_lowercase();
                if (normalized == "session_id" || normalized.ends_with("_session_id"))
                    && let Some(requested_session) = value.as_str()
                    && requested_session != session_id
                {
                    bail!("request references a session outside the authenticated SSH binding");
                }
                ensure_json_session_owner(value, session_id)?;
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                ensure_json_session_owner(value, session_id)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn is_id_or_path_field(name: &str) -> bool {
    matches!(name, "id_or_path" | "idOrPath")
}

fn is_path_field(name: &str) -> bool {
    matches!(
        name,
        "path"
            | "paths"
            | "file"
            | "files"
            | "file_path"
            | "target_file"
            | "filePath"
            | "target_notebook"
            | "cwd"
            | "workdir"
            | "directory"
            | "project_dir"
            | "git_root"
            | "gitRoot"
            | "root"
            | "out"
    ) || name.ends_with("_path")
        || name.ends_with("_file")
        || name.ends_with("_dir")
        || name.ends_with("_root")
        || name.ends_with("_cwd")
        || name.ends_with("Path")
        || name.ends_with("File")
        || name.ends_with("Dir")
        || name.ends_with("Root")
        || name.ends_with("Cwd")
}

fn ensure_json_path_value_within_root(
    value: &serde_json::Value,
    root: &Path,
    cwd: &Path,
    required_path: bool,
) -> anyhow::Result<()> {
    let validate = |path: &str| {
        if required_path || looks_like_path(path) {
            ensure_path_within_root(path, root, cwd)?;
        }
        Ok(())
    };
    match value {
        serde_json::Value::String(path) => validate(path),
        serde_json::Value::Array(paths) => {
            for path in paths {
                if let Some(path) = path.as_str() {
                    validate(path)?;
                }
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn looks_like_path(value: &str) -> bool {
    Path::new(value).is_absolute()
        || matches!(value, "." | "..")
        || value.starts_with("./")
        || value.starts_with("../")
        || value.contains('/')
        || value.contains('\\')
}

fn ensure_path_within_root(path: &str, root: &Path, cwd: &Path) -> anyhow::Result<()> {
    if path.is_empty() {
        return Ok(());
    }
    let candidate = if Path::new(path).is_absolute() {
        PathBuf::from(path)
    } else {
        cwd.join(path)
    };
    let canonical = canonicalize_path_with_existing_ancestor(&candidate)?;
    if canonical.starts_with(root) {
        Ok(())
    } else {
        bail!("path escapes authorized root")
    }
}

/// Canonicalize the existing part of a not-yet-created path, preserving its
/// remaining normal components. This catches symlink escapes while permitting
/// tools to create arbitrarily deep paths below the authorized root.
fn canonicalize_path_with_existing_ancestor(candidate: &Path) -> anyhow::Result<PathBuf> {
    let mut existing = candidate;
    while !existing.exists() {
        existing = existing
            .parent()
            .ok_or_else(|| anyhow!("path has no existing ancestor"))?;
    }
    let suffix = candidate
        .strip_prefix(existing)
        .map_err(|_| anyhow!("path cannot be resolved from its existing ancestor"))?;
    let mut canonical = dunce::canonicalize(existing)?;
    for component in suffix.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(component) => canonical.push(component),
            Component::ParentDir => {
                if !canonical.pop() {
                    bail!("path escapes filesystem root");
                }
            }
            Component::RootDir | Component::Prefix(_) => {
                bail!("path has an invalid unresolved component")
            }
        }
    }
    Ok(canonical)
}

fn same_binding_scope(left: &SshBinding, right: &SshBinding) -> bool {
    left.id == right.id
        && left.session_id == right.session_id
        && left.target_id == right.target_id
        && left.identity == right.identity
        && left.root == right.root
        && left.cwd == right.cwd
        && left.capabilities == right.capabilities
}

fn ensure_bindable(existing: &BindingState, binding: &SshBinding) -> Result<(), SshWireError> {
    if !same_binding_scope(&existing.binding, binding) {
        return Err(wire_error(
            "binding_scope_changed",
            "a binding id cannot be rebound to a different identity, target, root, or capability ceiling",
        ));
    }
    if existing.revoked || existing.binding.revoked {
        return Err(wire_error(
            "authorization_revoked",
            "a revoked binding cannot be rebound",
        ));
    }
    if binding.epoch < existing.binding.epoch {
        return Err(wire_error(
            "stale_authorization_epoch",
            "binding authorization epoch is stale",
        ));
    }
    Ok(())
}

fn approval_detail(
    binding: &SshBinding,
    cwd: &Path,
    request: serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "binding": {
            "id": binding.id,
            "target_id": binding.target_id,
            "identity": binding.identity,
            "root": binding.root,
            "cwd": cwd.to_string_lossy(),
            "capabilities": binding.capabilities,
            "epoch": binding.epoch,
        },
        "request": request,
    })
}

fn worker_global_hook_sources() -> Vec<HookSourceConfig> {
    let home = xai_grok_config::user_grok_home();
    let mut sources = xai_grok_config::resolve_global_hook_sources(home.as_deref(), false)
        .map(|sources| {
            sources
                .discovery_sources()
                .map(|source| {
                    if source.is_dir() {
                        HookSourceConfig::Directory(source.path.clone())
                    } else {
                        HookSourceConfig::SettingsFile(source.path.clone())
                    }
                })
                .collect()
        })
        .unwrap_or_else(|error| {
            tracing::warn!(%error, "SSH worker could not resolve global hook sources");
            Vec::new()
        });
    if let Some(home) = xai_dirs::home_dir() {
        sources.extend([
            HookSourceConfig::SettingsFile(home.join(".claude").join("settings.json")),
            HookSourceConfig::SettingsFile(home.join(".claude").join("settings.local.json")),
        ]);
    }
    sources
}

fn worker_project_hook_sources(root: &Path) -> Vec<HookSourceConfig> {
    vec![
        HookSourceConfig::Directory(root.join(".grok").join("hooks")),
        HookSourceConfig::SettingsFile(root.join(".claude").join("settings.json")),
        HookSourceConfig::SettingsFile(root.join(".claude").join("settings.local.json")),
    ]
}

fn worker_mcp_servers(
    root: &Path,
    extensions_enabled: bool,
) -> Vec<agent_client_protocol::McpServer> {
    if !extensions_enabled {
        // Even user-private MCP configurations are command-producing. A
        // read-only SSH binding may inspect project metadata but cannot launch
        // any extension process until it has execute authority.
        return Vec::new();
    }

    let sources = xai_grok_config::mcp_servers::McpServerSources {
        cwd: root.to_path_buf(),
        project_configs: crate::project_config::find_project_configs(root),
        mcp_json_files: crate::project_config::find_mcp_json_files(root),
        compat: xai_grok_tools::types::compat::CompatConfig::default(),
        claude_import: xai_grok_config::ClaudeImport::from_marker(
            xai_grok_config::is_claude_import_marked(&xai_grok_config::grok_home()),
        ),
    };
    xai_grok_config::mcp_servers::load_mcp_servers(&sources)
}

fn wire_error(code: impl Into<String>, message: impl Into<String>) -> SshWireError {
    SshWireError::new(code, message)
}

fn request_id(request: &SshWorkerRequest) -> &str {
    match request {
        SshWorkerRequest::Bind { request_id, .. }
        | SshWorkerRequest::Resume { request_id, .. }
        | SshWorkerRequest::Revoke { request_id, .. }
        | SshWorkerRequest::Rpc { request_id, .. }
        | SshWorkerRequest::ToolCall { request_id, .. }
        | SshWorkerRequest::Cancel { request_id, .. }
        | SshWorkerRequest::Operation { request_id, .. }
        | SshWorkerRequest::Mutation { request_id, .. }
        | SshWorkerRequest::Tasks { request_id, .. }
        | SshWorkerRequest::Approval { request_id, .. }
        | SshWorkerRequest::Canonicalize { request_id, .. }
        | SshWorkerRequest::Ping { request_id } => request_id,
    }
}

/// The private daemon endpoint path in a dedicated user-only state namespace.
pub fn default_private_socket_path() -> PathBuf {
    #[cfg(windows)]
    {
        let user = std::env::var("USERNAME").unwrap_or_else(|_| "user".to_owned());
        return PathBuf::from(format!(r"\\.\pipe\groky-ssh-worker-{user}"));
    }
    #[cfg(not(windows))]
    {
        crate::handle::resolve_workspace_home()
            .join("ssh-worker")
            .join("worker.sock")
    }
}

/// Start or use a private per-user worker daemon, then bridge this process's
/// stdin/stdout to it. Protocol bytes are the only stdout output.
#[cfg(unix)]
pub async fn run_stdio() -> anyhow::Result<()> {
    use std::process::Stdio;
    use tokio::net::UnixStream;

    let socket = default_private_socket_path();
    let stream = match UnixStream::connect(&socket).await {
        Ok(stream) => stream,
        Err(_) => {
            let executable = std::env::current_exe().context("resolving worker executable")?;
            let mut child = tokio::process::Command::new(executable);
            // The worker must retain task/session state after this SSH stdio
            // bridge exits. A separate session prevents the bridge's process
            // group teardown from taking the daemon with it.
            {
                use std::os::unix::process::CommandExt;
                unsafe {
                    child.pre_exec(|| {
                        if libc::setsid() == -1 {
                            Err(std::io::Error::last_os_error())
                        } else {
                            Ok(())
                        }
                    });
                }
            }
            child
                .arg("worker")
                .arg("--daemon")
                .arg("--socket")
                .arg(&socket)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .kill_on_drop(false)
                .spawn()
                .context("starting private SSH worker daemon")?;
            let mut connected = None;
            for _ in 0..50 {
                match UnixStream::connect(&socket).await {
                    Ok(stream) => {
                        connected = Some(stream);
                        break;
                    }
                    Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
                }
            }
            connected.ok_or_else(|| anyhow!("private SSH worker daemon did not become ready"))?
        }
    };
    let (mut reader, mut writer) = stream.into_split();
    let to_worker = tokio::spawn(async move {
        let mut stdin = tokio::io::stdin();
        tokio::io::copy(&mut stdin, &mut writer).await
    });
    let mut stdout = tokio::io::stdout();
    tokio::select! {
        result = to_worker => {
            result
                .context("joining private SSH worker input bridge")?
                .context("bridging private SSH worker input")?;
        }
        result = tokio::io::copy(&mut reader, &mut stdout) => {
            result.context("bridging private SSH worker output")?;
        }
    }
    Ok(())
}

/// Run the private user-only Unix-domain worker daemon. This never opens a TCP
/// listener and refuses to replace an existing non-socket path.
#[cfg(unix)]
pub async fn run_private_daemon(socket: PathBuf) -> anyhow::Result<()> {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    use tokio::net::UnixListener;

    let parent = socket
        .parent()
        .ok_or_else(|| anyhow!("private worker socket must have a parent"))?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("creating private worker directory {}", parent.display()))?;
    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("protecting private worker directory {}", parent.display()))?;
    if let Ok(metadata) = std::fs::symlink_metadata(&socket) {
        if !metadata.file_type().is_socket() {
            bail!(
                "refusing to replace non-socket private worker path {}",
                socket.display()
            );
        }
        match tokio::net::UnixStream::connect(&socket).await {
            Ok(_) => bail!("private SSH worker daemon is already running"),
            Err(_) => std::fs::remove_file(&socket)
                .with_context(|| format!("removing stale private socket {}", socket.display()))?,
        }
    }
    let listener = UnixListener::bind(&socket)
        .with_context(|| format!("binding private worker socket {}", socket.display()))?;
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("protecting private worker socket {}", socket.display()))?;
    let service = SshWorkerService::new();
    loop {
        let (stream, _) = listener
            .accept()
            .await
            .context("accepting private worker bridge")?;
        let service = Arc::clone(&service);
        tokio::spawn(async move {
            let _ = serve_stream(service, stream).await;
        });
    }
}

/// Start or use the current user's local named-pipe worker daemon, then bridge
/// stdin/stdout. The pipe rejects remote clients and its default DACL is taken
/// from the current user's process token.
#[cfg(windows)]
pub async fn run_stdio() -> anyhow::Result<()> {
    use std::process::Stdio;
    use tokio::net::windows::named_pipe::ClientOptions;

    let pipe = default_private_socket_path().to_string_lossy().into_owned();
    let stream = match ClientOptions::new().open(&pipe) {
        Ok(stream) => stream,
        Err(_) => {
            let executable = std::env::current_exe().context("resolving worker executable")?;
            let mut child = tokio::process::Command::new(executable);
            // Do not tie the private daemon to the bridge process lifetime.
            {
                use std::os::windows::process::CommandExt;
                const DETACHED_PROCESS: u32 = 0x0000_0008;
                const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
                child.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
            }
            child
                .arg("worker")
                .arg("--daemon")
                .arg("--socket")
                .arg(&pipe)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .kill_on_drop(false)
                .spawn()
                .context("starting private SSH worker daemon")?;
            let mut connected = None;
            for _ in 0..50 {
                match ClientOptions::new().open(&pipe) {
                    Ok(stream) => {
                        connected = Some(stream);
                        break;
                    }
                    Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
                }
            }
            connected.ok_or_else(|| anyhow!("private SSH worker daemon did not become ready"))?
        }
    };
    let (mut reader, mut writer) = tokio::io::split(stream);
    let to_worker = tokio::spawn(async move {
        let mut stdin = tokio::io::stdin();
        tokio::io::copy(&mut stdin, &mut writer).await
    });
    let mut stdout = tokio::io::stdout();
    tokio::select! {
        result = to_worker => {
            result
                .context("joining private SSH worker input bridge")?
                .context("bridging private SSH worker input")?;
        }
        result = tokio::io::copy(&mut reader, &mut stdout) => {
            result.context("bridging private SSH worker output")?;
        }
    }
    Ok(())
}

/// Run the current user's private named-pipe worker daemon. The pipe is local
/// only (`reject_remote_clients`) and never opens a network listener.
#[cfg(windows)]
pub async fn run_private_daemon(socket: PathBuf) -> anyhow::Result<()> {
    use tokio::net::windows::named_pipe::ServerOptions;

    let pipe = socket.to_string_lossy().into_owned();
    let service = SshWorkerService::new();
    let mut first_instance = true;
    loop {
        let server = ServerOptions::new()
            .first_pipe_instance(first_instance)
            .reject_remote_clients(true)
            .create(&pipe)
            .with_context(|| format!("binding private worker pipe {pipe}"))?;
        first_instance = false;
        server
            .connect()
            .await
            .with_context(|| format!("accepting private worker pipe {pipe}"))?;
        let service = Arc::clone(&service);
        tokio::spawn(async move {
            let _ = serve_stream(service, server).await;
        });
    }
}

#[cfg(all(not(unix), not(windows)))]
pub async fn run_stdio() -> anyhow::Result<()> {
    bail!("the SSH worker private bridge requires a platform private IPC transport")
}

#[cfg(all(not(unix), not(windows)))]
pub async fn run_private_daemon(_socket: PathBuf) -> anyhow::Result<()> {
    bail!("the SSH worker private daemon requires a platform private IPC transport")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_guard_rejects_escape_through_parent() {
        let root = dunce::canonicalize(std::env::temp_dir()).expect("temp directory exists");
        let outside = root.parent().expect("temp has parent").join("escape");
        assert!(ensure_path_within_root(&outside.to_string_lossy(), &root, &root).is_err());
    }

    #[test]
    fn path_guard_allows_missing_nested_path() {
        let temp = tempfile::tempdir().expect("create workspace root");
        let root = dunce::canonicalize(temp.path()).expect("canonical workspace root");
        let nested = root.join("new").join("nested").join("file.txt");
        assert!(ensure_path_within_root(&nested.to_string_lossy(), &root, &root).is_ok());
    }

    #[test]
    fn json_path_guard_covers_camel_case_worktree_paths() {
        let root = tempfile::tempdir().expect("create workspace root");
        let canonical_root = dunce::canonicalize(root.path()).expect("canonical workspace root");
        let outside = canonical_root
            .parent()
            .expect("workspace root has parent")
            .join("outside-worktree");

        for field in ["worktreePath", "sourceGitRoot", "mountPath"] {
            let mut params = serde_json::Map::new();
            params.insert(
                field.to_owned(),
                serde_json::Value::String(outside.to_string_lossy().into_owned()),
            );
            assert!(
                ensure_json_paths_within_root(
                    &serde_json::Value::Object(params),
                    &canonical_root,
                    &canonical_root,
                )
                .is_err(),
                "{field} must not escape the authorized root"
            );
        }
    }

    #[test]
    fn json_path_guard_preserves_opaque_id_or_path_values() {
        let root = tempfile::tempdir().expect("create workspace root");
        let canonical_root = dunce::canonicalize(root.path()).expect("canonical workspace root");
        assert!(
            ensure_json_paths_within_root(
                &serde_json::json!({"idOrPath": "worktree-opaque-id"}),
                &canonical_root,
                &canonical_root,
            )
            .is_ok()
        );
        assert!(
            ensure_json_paths_within_root(
                &serde_json::json!({"id_or_path": "../outside"}),
                &canonical_root,
                &canonical_root,
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn approval_cannot_be_answered_by_another_binding() {
        let (writer, _reader) = tokio::io::duplex(64);
        let (sender, receiver) = oneshot::channel();
        let connection = WorkerConnection {
            service: SshWorkerService::new(),
            writer: Arc::new(Mutex::new(writer)),
            accepted_bindings: Arc::new(RwLock::new(HashSet::from([
                "binding-a".to_owned(),
                "binding-b".to_owned(),
            ]))),
            approvals: Arc::new(Mutex::new(HashMap::from([(
                "approval".to_owned(),
                PendingApproval {
                    binding_id: "binding-a".into(),
                    session_id: "session-a".into(),
                    sender,
                },
            )]))),
            revocation_only: false,
        };

        let error = connection
            .approve(
                "approval",
                "binding-b",
                "session-a",
                SshApprovalDecision::Approve,
            )
            .await
            .expect_err("foreign binding cannot answer approval");
        assert_eq!(error.code, "approval_not_owned");
        assert!(connection.approvals.lock().await.contains_key("approval"));

        connection
            .approve(
                "approval",
                "binding-a",
                "session-a",
                SshApprovalDecision::Approve,
            )
            .await
            .expect("owner answers approval");
        assert_eq!(
            receiver.await.expect("approval delivered"),
            SshApprovalDecision::Approve
        );
    }

    #[tokio::test]
    async fn revocation_tombstone_cannot_initialize_or_use_a_workspace() {
        let service = SshWorkerService::new();
        let mut binding = test_binding();
        binding.revoked = true;
        binding.epoch = 2;
        let (admitted, _) = service
            .admit_revocation_tombstone(binding.clone())
            .await
            .expect("admit revoked tombstone");
        assert_eq!(admitted, binding);
        assert!(
            service.workspaces.lock().await.is_empty(),
            "tombstone admission must not create a WorkspaceHandle"
        );
        let mut replay = binding.clone();
        replay.revoked = false;
        let rejected_rebind = service
            .bind(replay)
            .await
            .expect_err("tombstone must permanently reject normal rebind");
        assert_eq!(rejected_rebind.code, "authorization_revoked");
        assert!(
            service.workspaces.lock().await.is_empty(),
            "rejected rebind must not initialize the old workspace"
        );

        let (writer, _reader) = tokio::io::duplex(64);
        let connection = WorkerConnection {
            service: Arc::clone(&service),
            writer: Arc::new(Mutex::new(writer)),
            accepted_bindings: Arc::new(RwLock::new(HashSet::from([binding.id.clone()]))),
            approvals: Arc::new(Mutex::new(HashMap::new())),
            revocation_only: true,
        };
        let denied = dispatch_request(
            &connection,
            SshWorkerRequest::Ping {
                request_id: "not-allowed".into(),
            },
        )
        .await
        .expect_err("tombstone bridge cannot issue ordinary requests");
        assert_eq!(denied.code, "revocation_only");

        let acknowledged = dispatch_request(
            &connection,
            SshWorkerRequest::Revoke {
                request_id: "ack".into(),
                binding_id: binding.id.clone(),
                epoch: binding.epoch,
            },
        )
        .await
        .expect("tombstone revoke acknowledgement");
        assert!(matches!(
            acknowledged,
            SshWorkerResponse::Revoked { binding_id, epoch }
                if binding_id == binding.id && epoch == binding.epoch
        ));
    }

    #[tokio::test]
    async fn read_binding_creates_provider_free_workspace_session() {
        use xai_grok_workspace_client::ssh::{BoxSshStream, DenySshApprovals, SshWorkspaceClient};

        let temp = tempfile::tempdir().expect("create workspace root");
        let fixture = temp.path().join("fixture.txt");
        std::fs::write(&fixture, "read through the provider-free SSH worker")
            .expect("write fixture");
        let root = dunce::canonicalize(temp.path()).expect("canonical workspace root");
        let mut binding = test_binding();
        binding.root = root.to_string_lossy().into_owned();
        binding.cwd = binding.root.clone();
        binding.capabilities = xai_grok_workspace_types::ssh::SshCapabilities::read_only();

        let service = SshWorkerService::new();
        let (client_stream, worker_stream) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(serve_stream(Arc::clone(&service), worker_stream));
        let client_stream: BoxSshStream = Box::pin(client_stream);
        let client =
            SshWorkspaceClient::connect(client_stream, binding.clone(), Arc::new(DenySshApprovals))
                .await
                .expect("a read-only SSH binding initializes local tools without Hub credentials");

        let invocation = ResolvedSshInvocation {
            binding_id: binding.id.clone(),
            target_id: binding.target_id.clone(),
            session_id: binding.session_id.clone(),
            epoch: binding.epoch,
            cwd: binding.cwd.clone(),
            operation: SshOperation::Read,
            call_id: "provider-free-read".into(),
        };
        let result = client
            .call_tool(
                invocation,
                "GrokBuild:read_file",
                serde_json::json!({"target_file": fixture}),
                None,
            )
            .await
            .expect("a fully-qualified registry id resolves to the finalized read tool");
        assert!(
            result
                .value
                .to_string()
                .contains("read through the provider-free SSH worker"),
            "worker must return real filesystem content: {}",
            result.value
        );

        let workspace = service
            .workspace_for_root(root, false)
            .await
            .expect("read-only worker workspace remains available");
        assert!(
            workspace.handle.session(&binding.session_id).is_some(),
            "the admitted binding must own a usable local WorkspaceHandle session"
        );
        drop(client);
        server.abort();
    }

    #[tokio::test]
    async fn read_only_workspace_never_reuses_extension_enabled_runtime() {
        let temp = tempfile::tempdir().expect("create workspace root");
        let root = dunce::canonicalize(temp.path()).expect("canonical workspace root");
        let service = SshWorkerService::new();
        let read_only = service
            .workspace_for_root(root.clone(), false)
            .await
            .expect("build read-only worker workspace");
        let execute_capable = service
            .workspace_for_root(root, true)
            .await
            .expect("build execute-capable worker workspace");

        assert!(
            !Arc::ptr_eq(&read_only, &execute_capable),
            "a read-only binding must not share project hook/MCP/LSP runtime with an execute binding"
        );
        assert!(
            read_only.mcp_servers.is_empty(),
            "a read-only worker workspace must not load MCP command definitions"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn ssh_discovery_excludes_parent_and_symlink_contents() {
        let temp = tempfile::tempdir().expect("workspace fixture");
        let parent = dunce::canonicalize(temp.path()).expect("canonical fixture");
        git2::Repository::init(&parent).expect("parent repository");
        let root = parent.join("granted");
        std::fs::create_dir(&root).expect("granted root");
        std::fs::write(parent.join("AGENTS.md"), "OUTSIDE_PARENT_INSTRUCTIONS")
            .expect("parent instructions");
        std::fs::write(root.join("AGENTS.md"), "INSIDE_GRANTED_INSTRUCTIONS")
            .expect("granted instructions");
        let secret = parent.join("outside-rules.md");
        std::fs::write(&secret, "OUTSIDE_SYMLINK_INSTRUCTIONS").expect("outside rule");
        let rules = root.join(".grok/rules");
        std::fs::create_dir_all(&rules).expect("rules directory");
        std::os::unix::fs::symlink(&secret, rules.join("escaped.md")).expect("rule symlink");
        let own_skill = root.join(".grok/skills/inside/SKILL.md");
        std::fs::create_dir_all(own_skill.parent().unwrap()).expect("skill directory");
        std::fs::write(
            &own_skill,
            "---\nname: inside\ndescription: INSIDE_GRANTED_SKILL\n---\ninside",
        )
        .expect("granted skill");
        let outside_skill = parent.join("outside-skill.md");
        std::fs::write(
            &outside_skill,
            "---\nname: outside\ndescription: OUTSIDE_SYMLINK_SKILL\n---\noutside",
        )
        .expect("outside skill");
        let escaped_skill = root.join(".grok/skills/outside/SKILL.md");
        std::fs::create_dir_all(escaped_skill.parent().unwrap()).expect("escaped skill directory");
        std::os::unix::fs::symlink(&outside_skill, &escaped_skill).expect("skill symlink");

        let service = SshWorkerService::new();
        let base = service
            .workspace_for_root(root.clone(), false)
            .await
            .expect("provider-free workspace");
        let workspace = WorkerWorkspace {
            root,
            handle: base.handle.clone(),
            rpc: Arc::clone(&base.rpc),
            mcp_servers: Default::default(),
            project_trusted: true,
        };
        let instructions = serde_json::to_string(&workspace.instruction_files().await).unwrap();
        assert!(instructions.contains("INSIDE_GRANTED_INSTRUCTIONS"));
        assert!(!instructions.contains("OUTSIDE_PARENT_INSTRUCTIONS"));
        assert!(!instructions.contains("OUTSIDE_SYMLINK_INSTRUCTIONS"));
        let skills = serde_json::to_string(&workspace.skills().await).unwrap();
        assert!(skills.contains("INSIDE_GRANTED_SKILL"));
        assert!(!skills.contains("OUTSIDE_SYMLINK_SKILL"));
        let toolset = xai_grok_tools::registry::types::FinalizedToolset::empty_for_test();
        workspace.prepare_skill_discovery(&toolset).await.unwrap();
        let mut resources = toolset.resources.lock().await;
        let catalog = resources.get::<xai_grok_tools::types::resources::AvailableSkills>().unwrap();
        assert!(catalog.0.iter().any(|skill| skill.name == "inside"));
        let escaped = xai_grok_tools::implementations::skills::discovery::parse_skill_files(vec![(
            escaped_skill,
            xai_grok_tools::implementations::skills::types::SkillScope::Local,
        )]);
        let manager = resources
            .get_mut::<xai_grok_tools::types::skill_discovery_tracker::SkillManager>().unwrap();
        assert!(!manager.add_discovered(escaped));
        assert!(!manager.slash_skills().iter().any(|skill| skill.name == "outside"));
        drop(resources);

        std::os::unix::fs::symlink(&secret, workspace.root.join(".grok/config.toml"))
            .expect("config symlink");
        assert_eq!(workspace.project_config().unwrap_err().code, "path_denied");
    }

    #[tokio::test]
    async fn ssh_session_checkout_restores_head_and_preserves_dirty_files() {
        let temp = tempfile::tempdir().expect("checkout fixture");
        let root = dunce::canonicalize(temp.path()).expect("canonical fixture");
        let repo = git2::Repository::init(&root).expect("repository");
        let mut config = repo.config().unwrap();
        config.set_str("user.name", "SSH restore test").unwrap();
        config.set_str("user.email", "ssh@example.invalid").unwrap();
        let signature = git2::Signature::now("SSH restore test", "ssh@example.invalid").unwrap();
        let mut commits = Vec::new();
        for content in ["saved head\n", "newer head\n"] {
            std::fs::write(root.join("tracked.txt"), content).unwrap();
            let mut index = repo.index().unwrap();
            index.add_path(Path::new("tracked.txt")).unwrap();
            index.write().unwrap();
            let tree = repo.find_tree(index.write_tree().unwrap()).unwrap();
            let parent = commits.last().map(|oid| repo.find_commit(*oid).unwrap());
            let parents = parent.iter().collect::<Vec<_>>();
            commits.push(repo.commit(
                Some("HEAD"), &signature, &signature, content, &tree, &parents,
            ).unwrap());
        }
        std::fs::write(root.join("tracked.txt"), "uncommitted tracked\n").unwrap();
        std::fs::write(root.join("untracked.txt"), "uncommitted untracked\n").unwrap();
        let service = SshWorkerService::new();
        let workspace = service.workspace_for_root(root.clone(), false).await.unwrap();
        let outcome: crate::session::git::CheckoutSessionOutcome = serde_json::from_value(
            workspace.rpc.dispatch(
                "workspace.checkout_session_commit",
                serde_json::json!({"target_sha": commits[0].to_string(), "session_id": "restore-session"}),
                Some("restore-session"),
            ).await.unwrap(),
        ).unwrap();
        assert!(outcome.checked_out);
        assert_eq!(repo.head().unwrap().target(), Some(commits[0]));
        assert_eq!(std::fs::read_to_string(root.join("tracked.txt")).unwrap(), "saved head\n");
        assert!(!root.join("untracked.txt").exists());
        let stash = repo.find_commit(
            git2::Oid::from_str(outcome.stash_ref.as_deref().expect("dirty state stashed")).unwrap(),
        ).unwrap();
        let tracked = stash.tree().unwrap().get_path(Path::new("tracked.txt")).unwrap().id();
        assert_eq!(repo.find_blob(tracked).unwrap().content(), b"uncommitted tracked\n");
        let untracked = stash.parent(2).unwrap().tree().unwrap()
            .get_path(Path::new("untracked.txt")).unwrap().id();
        assert_eq!(repo.find_blob(untracked).unwrap().content(), b"uncommitted untracked\n");
        let invalid = workspace.rpc.dispatch(
            "workspace.checkout_session_commit",
            serde_json::json!({"target_sha": "--force", "session_id": "restore-session"}),
            Some("restore-session"),
        ).await;
        assert!(invalid.is_err());
        assert_eq!(repo.head().unwrap().target(), Some(commits[0]));
    }

    #[test]
    fn session_guard_rejects_foreign_session() {
        assert!(
            ensure_json_session_owner(
                &serde_json::json!({"nested": {"session_id": "other-session"}}),
                "bound-session",
            )
            .is_err()
        );
        assert!(
            ensure_json_session_owner(
                &serde_json::json!({"caller_session_id": "bound-session"}),
                "bound-session",
            )
            .is_ok()
        );
    }

    #[test]
    fn unknown_tool_is_never_read_only() {
        let toolset = xai_grok_tools::registry::types::FinalizedToolset::empty_for_test();
        assert_eq!(
            classify_tool_operation(&toolset, "unregistered"),
            SshOperation::Execute
        );
    }

    #[test]
    fn project_config_selected_agent_resolves_on_worker_host() {
        let temp = tempfile::tempdir().expect("create workspace root");
        let grok = temp.path().join(".grok");
        let agents = grok.join("agents");
        std::fs::create_dir_all(&agents).expect("create agent directory");
        std::fs::write(
            grok.join("config.toml"),
            "[agent]\nname = \"remote-reviewer\"\n",
        )
        .expect("write project config");
        std::fs::write(
            agents.join("remote-reviewer.md"),
            "---\nname: remote-reviewer\ndescription: worker-selected profile\n---\n",
        )
        .expect("write project agent");

        let config = crate::discovery::load_project_config(temp.path());
        let definition = selected_project_agent_definition(temp.path(), &config)
            .expect("project config selects the remote definition");
        assert_eq!(definition.name, "remote-reviewer");
    }

    #[test]
    fn project_selected_agent_definition_cannot_escape_remote_root() {
        let root = tempfile::tempdir().expect("create workspace root");
        let outside = tempfile::NamedTempFile::new().expect("create outside profile");
        let config = serde_json::json!({
            "agent": {"definition": outside.path().to_string_lossy()}
        });

        assert!(
            selected_project_agent_definition(root.path(), &config).is_none(),
            "a remote project config may not read an agent profile outside its authorized root"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn project_session_start_hook_runs_only_for_execute_binding() {
        let temp = tempfile::tempdir().expect("create remote workspace");
        let root = dunce::canonicalize(temp.path()).expect("canonical remote workspace");
        let hooks = root.join(".grok").join("hooks");
        std::fs::create_dir_all(&hooks).expect("create project hook directory");
        let marker = root.join(".grok").join("session-start.marker");
        let cwd_marker = root.join(".grok").join("session-start.cwd");
        std::fs::write(
            hooks.join("session-start.json"),
            serde_json::json!({
                "hooks": {
                    "SessionStart": [{
                        "hooks": [{
                            "type": "command",
                            "command": format!(
                                "pwd > .grok/session-start.cwd; printf 'REMOTE_SESSION_START\\ncwd=%s\\n' \"$PWD\" >> {}",
                                marker.display()
                            ),
                        }],
                    }],
                },
            })
            .to_string(),
        )
        .expect("write project hook");

        let service = SshWorkerService::new();
        let mut read_only = test_binding();
        read_only.id = "read-only-binding".into();
        read_only.session_id = "read-only-session".into();
        read_only.root = root.to_string_lossy().into_owned();
        read_only.cwd = read_only.root.clone();
        read_only.capabilities = xai_grok_workspace_types::ssh::SshCapabilities::read_only();
        service
            .bind(read_only)
            .await
            .expect("read-only binding initializes without project hook execution");
        assert!(
            !marker.exists(),
            "read-only binding must not execute remote project hook commands"
        );

        let mut execute = test_binding();
        execute.id = "execute-binding".into();
        execute.session_id = "execute-session".into();
        execute.root = root.to_string_lossy().into_owned();
        execute.cwd = execute.root.clone();
        service
            .bind(execute.clone())
            .await
            .expect("execute binding starts remote project hook");
        let observed = std::fs::read_to_string(&marker).expect("remote hook marker");
        let physical_cwd = std::fs::read_to_string(&cwd_marker).expect("hook physical cwd marker");
        assert!(observed.contains("REMOTE_SESSION_START"));
        assert!(
            observed.contains(root.to_string_lossy().as_ref()),
            "hook PWD must remain a runtime remote workspace reference: {observed}"
        );
        assert_eq!(
            physical_cwd.trim(),
            root.to_string_lossy().as_ref(),
            "hook process must spawn in its canonical remote workspace root"
        );
        service
            .bind(execute)
            .await
            .expect("rebinding must not replay SessionStart");
        assert_eq!(
            std::fs::read_to_string(&marker)
                .expect("remote hook marker")
                .matches("REMOTE_SESSION_START")
                .count(),
            1,
            "a resumed bridge must not duplicate the worker-owned SessionStart hook"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn actor_hooks_execute_remotely_after_local_transcript_exists() {
        use xai_grok_workspace_client::ssh::{SshClientCallbacks, SshWorkspaceClient};

        struct Approve;
        #[async_trait::async_trait]
        impl SshClientCallbacks for Approve {
            async fn approve(&self, _: SshApprovalRequest) -> SshApprovalDecision {
                SshApprovalDecision::Approve
            }
        }

        let temp = tempfile::tempdir().expect("remote workspace");
        let local = tempfile::tempdir().expect("local session storage");
        let root = dunce::canonicalize(temp.path()).expect("canonical remote root");
        let hooks = root.join(".grok/hooks");
        std::fs::create_dir_all(&hooks).expect("hook directory");
        std::fs::write(
            hooks.join("lifecycle.json"),
            serde_json::json!({"hooks": {
                "UserPromptSubmit": [{"hooks": [{
                    "type": "command",
                    "command": "cat > .grok/prompt-envelope.json; pwd > .grok/prompt.cwd"
                }]}],
                "Stop": [{"hooks": [{
                    "type": "command",
                    "command": "cat > .grok/stop-envelope.json; pwd > .grok/stop.cwd"
                }]}]
            }}).to_string(),
        ).expect("write lifecycle hooks");
        let mut binding = test_binding();
        binding.root = root.to_string_lossy().into_owned();
        binding.cwd = binding.root.clone();
        let service = SshWorkerService::new();
        let (client_stream, worker_stream) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(serve_stream(service, worker_stream));
        let client = SshWorkspaceClient::connect(
            Box::pin(client_stream), binding.clone(), Arc::new(Approve),
        ).await.expect("connect worker");
        let ops = crate::WorkspaceOps::ssh(client);
        let mut envelope = HookEventEnvelope {
            hook_event_name: HookEventName::UserPromptSubmit,
            session_id: binding.session_id.clone(),
            cwd: local.path().to_string_lossy().into_owned(),
            workspace_root: "ssh-v1-local-storage-identity".into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            transcript_path: Some(local.path().join("transcript.jsonl").to_string_lossy().into_owned()),
            client_identifier: None,
            prompt_id: Some("prompt".into()),
            permission_mode: Some("default".into()),
            payload: xai_grok_hooks::event::HookPayload::UserPromptSubmit {
                prompt: Some("remote lifecycle".into()),
                subagent_type: None,
            },
        };
        ops.dispatch_remote_prompt_hook(&envelope).await.expect("prompt hook after transcript creation");
        envelope.hook_event_name = HookEventName::Stop;
        envelope.payload = xai_grok_hooks::event::HookPayload::Stop {
            reason: "end_turn".into(),
            stop_hook_active: false,
            last_assistant_message: Some("remote answer".into()),
            background_tasks: None,
            session_crons: None,
        };
        assert!(ops.dispatch_remote_stop_hook(&envelope).await.expect("stop hook").is_none());
        for event in ["prompt", "stop"] {
            let observed: serde_json::Value = serde_json::from_slice(
                &std::fs::read(root.join(format!(".grok/{event}-envelope.json"))).expect("hook stdin"),
            ).expect("hook envelope");
            assert_eq!(observed["cwd"], binding.cwd);
            assert_eq!(observed["workspaceRoot"], binding.root);
            assert!(observed.get("transcriptPath").is_none());
            assert!(observed.get("transcript_path").is_none());
            assert_eq!(
                std::fs::read_to_string(root.join(format!(".grok/{event}.cwd"))).expect("hook cwd").trim(),
                binding.root,
            );
        }
        assert!(envelope.transcript_path.is_some(), "client hooks keep their local transcript");
        drop(ops);
        server.abort();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn execute_binding_runs_pre_and_post_tool_hooks_without_closing_bridge() {
        use xai_grok_workspace_client::ssh::{BoxSshStream, DenySshApprovals, SshWorkspaceClient};

        let temp = tempfile::tempdir().expect("create remote workspace");
        let root = dunce::canonicalize(temp.path()).expect("canonical remote workspace");
        let hooks = root.join(".grok").join("hooks");
        std::fs::create_dir_all(&hooks).expect("create project hook directory");
        let fixture = root.join("fixture.txt");
        std::fs::write(&fixture, "remote hook fixture").expect("write fixture");
        let pre = root.join(".grok").join("pre.marker");
        let post = root.join(".grok").join("post.marker");
        std::fs::write(
            hooks.join("tool.json"),
            serde_json::json!({
                "hooks": {
                    "PreToolUse": [{
                        "matcher": "read_file",
                        "hooks": [{
                            "type": "command",
                            "command": format!(
                                "printf pre > {}; printf '%s' '{{\"hookSpecificOutput\":{{\"permissionDecision\":\"allow\",\"additionalContext\":\"REMOTE_PRE_CONTEXT\"}}}}'",
                                pre.display()
                            ),
                        }],
                    }],
                    "PostToolUse": [{
                        "matcher": "read_file",
                        "hooks": [{
                            "type": "command",
                            "command": format!(
                                "printf post > {}; printf '%s' '{{\"hookSpecificOutput\":{{\"additionalContext\":\"REMOTE_POST_CONTEXT\"}}}}'",
                                post.display()
                            ),
                        }],
                    }],
                },
            })
            .to_string(),
        )
        .expect("write tool hook");

        let mut binding = test_binding();
        binding.id = "pre-post-binding".into();
        binding.session_id = "pre-post-session".into();
        binding.root = root.to_string_lossy().into_owned();
        binding.cwd = binding.root.clone();
        let service = SshWorkerService::new();
        let (client_stream, worker_stream) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(serve_stream(Arc::clone(&service), worker_stream));
        let client_stream: BoxSshStream = Box::pin(client_stream);
        let client =
            SshWorkspaceClient::connect(client_stream, binding.clone(), Arc::new(DenySshApprovals))
                .await
                .expect("connect execute-capable worker");

        let result = client
            .call_tool(
                ResolvedSshInvocation {
                    binding_id: binding.id.clone(),
                    target_id: binding.target_id.clone(),
                    session_id: binding.session_id.clone(),
                    epoch: binding.epoch,
                    cwd: binding.cwd.clone(),
                    operation: SshOperation::Read,
                    call_id: "pre-post-read".into(),
                },
                "GrokBuild:read_file",
                serde_json::json!({"target_file": fixture}),
                None,
            )
            .await
            .expect("post hook must not close the worker bridge");
        assert!(result.value.to_string().contains("remote hook fixture"));
        let post_hook = result
            .operation
            .post_hook
            .as_ref()
            .expect("terminal operation retains remote post-hook outcome");
        assert_eq!(
            post_hook.additional_context[0].text, "REMOTE_POST_CONTEXT",
            "remote hook context must survive the worker response boundary"
        );
        assert_eq!(
            post_hook.pre_tool_context[0].text, "REMOTE_PRE_CONTEXT",
            "remote pre-hook context must share the terminal operation boundary"
        );
        assert_eq!(std::fs::read_to_string(pre).expect("pre marker"), "pre");
        assert_eq!(std::fs::read_to_string(post).expect("post marker"), "post");
        drop(client);
        server.abort();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn failed_tool_post_hook_context_survives_worker_outcome() {
        let temp = tempfile::tempdir().expect("create remote workspace");
        let root = dunce::canonicalize(temp.path()).expect("canonical remote workspace");
        let hooks = root.join(".grok").join("hooks");
        std::fs::create_dir_all(&hooks).expect("create project hook directory");
        std::fs::write(
            hooks.join("failure.json"),
            serde_json::json!({
                "hooks": {
                    "PostToolUseFailure": [{
                        "matcher": "read_file",
                        "hooks": [{
                            "type": "command",
                            "command": "printf '%s' '{\"hookSpecificOutput\":{\"additionalContext\":\"REMOTE_FAILURE_CONTEXT\"}}'",
                        }],
                    }],
                },
            })
            .to_string(),
        )
        .expect("write failure hook");

        let service = SshWorkerService::new();
        let workspace = service
            .workspace_for_root(root.clone(), true)
            .await
            .expect("create execute-capable worker workspace");
        let mut binding = test_binding();
        binding.root = root.to_string_lossy().into_owned();
        binding.cwd = binding.root.clone();
        let failure: Result<serde_json::Value, SshWireError> =
            Err(wire_error("tool_failed", "fixture failure"));
        let outcome = dispatch_worker_post_tool_hook(
            &workspace,
            &binding,
            "read_file",
            "failed-read",
            &serde_json::json!({"target_file": "missing.txt"}),
            &failure,
            1,
        )
        .await
        .expect("failure hook outcome");
        assert!(
            outcome.post_tool_failure,
            "failure hooks must retain their event kind across the wire"
        );

        assert_eq!(
            outcome.additional_context[0].text, "REMOTE_FAILURE_CONTEXT",
            "failed remote calls retain model-visible failure context for the actor"
        );
    }

    fn test_binding() -> SshBinding {
        SshBinding {
            id: "binding".into(),
            session_id: "session".into(),
            target_id: "target".into(),
            identity: xai_grok_workspace_types::ssh::SshHostIdentity {
                hostname: "host".into(),
                port: 22,
                username: "user".into(),
                fingerprint: "fingerprint".into(),
            },
            root: "/workspace".into(),
            cwd: "/workspace".into(),
            capabilities: xai_grok_workspace_types::ssh::SshCapabilities::all(),
            epoch: 1,
            revoked: false,
        }
    }

    #[tokio::test]
    async fn operation_lookup_rejects_known_cross_binding_operation() {
        let service = SshWorkerService::new();
        let owner = test_binding();
        let mut other = test_binding();
        other.id = "other-binding".into();
        other.session_id = "other-session".into();
        let BeginOperation::Started { operation_id, .. } = service
            .begin_operation(&owner, SshOperation::Read, None)
            .await
            .expect("start operation")
        else {
            panic!("new operation must start");
        };

        let error = service
            .operation_for(&other.id, &other.session_id, &operation_id)
            .await
            .expect_err("known foreign operation must not appear as not found");
        assert_eq!(error.code, "operation_not_owned");
        assert!(
            service
                .operation_for(&owner.id, &owner.session_id, &operation_id)
                .await
                .expect("owner lookup succeeds")
                .is_some()
        );
    }

    #[tokio::test]
    async fn concurrent_mutation_claim_starts_once() {
        let service = SshWorkerService::new();
        let binding = test_binding();
        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let first_service = Arc::clone(&service);
        let first_binding = binding.clone();
        let first_barrier = Arc::clone(&barrier);
        let first = async move {
            first_barrier.wait().await;
            first_service
                .begin_operation(&first_binding, SshOperation::Write, Some("mutation".into()))
                .await
        };
        let second_service = Arc::clone(&service);
        let second_barrier = Arc::clone(&barrier);
        let second = async move {
            second_barrier.wait().await;
            second_service
                .begin_operation(&binding, SshOperation::Write, Some("mutation".into()))
                .await
        };
        let (first, second) = tokio::join!(first, second);
        assert_eq!(
            matches!(&first, Ok(BeginOperation::Started { .. })) as usize
                + matches!(&second, Ok(BeginOperation::Started { .. })) as usize,
            1,
        );
        assert!(
            matches!(&first, Err(error) if error.code == "mutation_not_replayable")
                || matches!(&second, Err(error) if error.code == "mutation_not_replayable")
        );
    }
}
