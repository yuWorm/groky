//! Versioned, credential-free frames for the authenticated SSH workspace worker.
//!
//! The SSH transport authenticates the byte stream.  These frames carry the
//! session-scoped authority that the worker verifies before every operation;
//! they never contain passwords, private keys, or agent material.

use crate::ssh::{ResolvedSshInvocation, SshBinding, SshOperation};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The only compatible protocol version for this wire family.
pub const SSH_WIRE_PROTOCOL_VERSION: u32 = 1;
/// Frames larger than this are rejected before JSON decoding.
pub const SSH_WIRE_MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;
/// Build identity reported by `groky worker --info` before opening an SSH worker bridge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshWorkerBuildInfo {
    /// Exact product release. `None` identifies a development build.
    pub product_version: Option<String>,
    pub protocol_version: u32,
    pub os: String,
    pub arch: String,
}

/// Product release identity without allocating the platform metadata.
pub fn local_worker_product_version() -> Option<&'static str> {
    option_env!("GROKY_VERSION").filter(|version| !version.is_empty())
}

/// Return the build identity of the local SSH worker executable.
pub fn local_worker_build_info() -> SshWorkerBuildInfo {
    let product_version = local_worker_product_version().map(str::to_owned);
    SshWorkerBuildInfo {
        product_version,
        protocol_version: SSH_WIRE_PROTOCOL_VERSION,
        os: std::env::consts::OS.to_owned(),
        arch: std::env::consts::ARCH.to_owned(),
    }
}

/// A client-generated request identifier. It is unique only within a bridge.
pub type SshRequestId = String;
/// An operation identifier retained for the lifetime of the worker daemon.
pub type SshOperationId = String;
/// A client-generated id used to discover an interrupted mutation. It is never replayed by the worker.
pub type SshMutationId = String;
/// Opaque worker-issued binding-resume token.
pub type SshResumeToken = String;

/// OS path rules reported during the initial handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SshPathSemantics {
    Posix,
    Windows,
}

/// Client hello sent as the first frame on every authenticated bridge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshClientHello {
    pub protocol_version: u32,
    /// Exact worker release expected for normal bridges. Omitted for a development build and
    /// revocation-only tombstones so those tombstones remain compatible with protocol-1 workers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_product_version: Option<String>,
    /// Local bridge identity for diagnostics and ownership; it is not authority.
    pub client_id: String,
    /// The binding was granted locally and is revalidated by the worker.
    pub binding: SshBinding,
    /// Reconnects use the token issued in an earlier worker hello.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resume_token: Option<SshResumeToken>,
    /// Admit only a locally persisted revocation tombstone. This handshake cannot create
    /// a workspace/session or authorize normal worker requests.
    #[serde(default)]
    pub revocation_only: bool,
}

/// Worker facilities negotiated at handshake. A missing facility is never
/// emulated by the client, especially for mutations and cancellation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SshWorkerCapabilities {
    pub workspace_rpc: bool,
    pub tool_calls: bool,
    pub streaming_progress: bool,
    pub approvals: bool,
    pub cancellation: bool,
    pub operation_query: bool,
}

impl SshWorkerCapabilities {
    pub const fn complete() -> Self {
        Self {
            workspace_rpc: true,
            tool_calls: true,
            streaming_progress: true,
            approvals: true,
            cancellation: true,
            operation_query: true,
        }
    }
}

/// Worker hello returned after a compatible client hello.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshWorkerHello {
    pub protocol_version: u32,
    /// Exact release of this worker. `None` identifies a development build.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product_version: Option<String>,
    pub worker_id: String,
    pub os: String,
    pub path_semantics: SshPathSemantics,
    pub capabilities: SshWorkerCapabilities,
    /// Canonical root actually admitted by the worker.
    pub root: String,
    pub binding: SshBinding,
    pub resume_token: SshResumeToken,
}

/// Remote-worker discovery snapshot consumed before constructing a local shell
/// actor. All paths and contents originate on the authenticated worker host.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshProjectBootstrap {
    pub instructions: Vec<crate::rpc::agents_md::AgentConfigFile>,
    pub hook_registry: crate::rpc::hooks::HookRegistryWire,
    pub skills: Vec<crate::rpc::skills::SkillInfo>,
    pub tool_definitions: Value,
    pub project_config: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_definition: Option<Value>,
    pub mcp_servers: Value,
}

/// Terminal state of an operation stored by a worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SshOperationState {
    Pending,
    Running,
    /// Cancellation was requested, but the worker has not yet observed a
    /// terminal stop. This is deliberately non-terminal.
    CancellationRequested,
    Completed,
    Failed,
    Cancelled,
    /// The bridge disconnected around a mutation and its result cannot be claimed.
    Unknown,
}

impl SshOperationState {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Failed | Self::Cancelled | Self::Unknown
        )
    }
}

/// Queryable operation record. `result` is present only for a completed call.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshOperationRecord {
    pub operation_id: SshOperationId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mutation_id: Option<SshMutationId>,
    pub binding_id: String,
    pub session_id: String,
    pub operation: SshOperation,
    pub state: SshOperationState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// Terminal post-tool effects are retained with a completed operation so a
    /// reconnect can return the same model-visible result without re-running hooks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post_hook: Option<SshPostToolHookOutcome>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<SshWireError>,
}

/// A worker-owned background task, always scoped to its binding and owner session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshTaskRecord {
    pub task_id: String,
    pub binding_id: String,
    pub session_id: String,
    pub command: String,
    pub completed: bool,
}

/// Outcome of a cancellation request. A generic operation remains pending
/// until its runtime actually stops; a terminal task is returned only after its
/// task manager acknowledges termination.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum SshCancellation {
    OperationPending(SshOperationRecord),
    Task(SshTaskRecord),
}

/// A callback-sensitive approval request. The client must explicitly answer it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshApprovalRequest {
    pub approval_id: String,
    pub operation_id: SshOperationId,
    pub binding_id: String,
    pub session_id: String,
    pub operation: SshOperation,
    pub title: String,
    pub detail: Value,
}

/// Explicit user decision for one approval request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SshApprovalDecision {
    Approve,
    Deny,
}

/// A streamed progress item, preserving the runtime's custom subtype/body form.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshToolProgress {
    pub kind: String,
    pub body: Value,
}

/// Asynchronous worker-to-client events. Events never authorize an operation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum SshWorkerEvent {
    ToolProgress {
        operation_id: SshOperationId,
        progress: SshToolProgress,
    },
    ToolNotification {
        operation_id: SshOperationId,
        notification: Value,
    },
    ApprovalRequired(SshApprovalRequest),
    Operation(SshOperationRecord),
}

/// Request frames sent after the hello exchange.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum SshWorkerRequest {
    Bind {
        request_id: SshRequestId,
        binding: SshBinding,
    },
    Resume {
        request_id: SshRequestId,
        binding: SshBinding,
        resume_token: SshResumeToken,
    },
    /// Increments the remote authorization epoch and acknowledges only after it is stored.
    Revoke {
        request_id: SshRequestId,
        binding_id: String,
        epoch: u64,
    },
    Rpc {
        request_id: SshRequestId,
        invocation: ResolvedSshInvocation,
        method: String,
        params: Value,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mutation_id: Option<SshMutationId>,
    },
    ToolCall {
        request_id: SshRequestId,
        invocation: ResolvedSshInvocation,
        tool_name: String,
        args: Value,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mutation_id: Option<SshMutationId>,
    },
    Cancel {
        request_id: SshRequestId,
        invocation: ResolvedSshInvocation,
        operation_id: SshOperationId,
    },
    Operation {
        request_id: SshRequestId,
        binding_id: String,
        session_id: String,
        operation_id: SshOperationId,
    },
    Mutation {
        request_id: SshRequestId,
        binding_id: String,
        session_id: String,
        mutation_id: SshMutationId,
    },
    Tasks {
        request_id: SshRequestId,
        binding_id: String,
        session_id: String,
    },
    Approval {
        request_id: SshRequestId,
        approval_id: String,
        binding_id: String,
        session_id: String,
        decision: SshApprovalDecision,
    },
    /// Canonicalize a path below one already-admitted binding's root.
    Canonicalize {
        request_id: SshRequestId,
        binding_id: String,
        path: String,
    },
    Ping {
        request_id: SshRequestId,
    },
}

/// Model-visible context or feedback produced by a remote post-tool hook.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshPostToolHookNote {
    pub hook_name: String,
    pub text: String,
}

/// A post-tool replacement retained separately for each output family. The
/// consumer selects the compatible/latest entry after decoding the tool result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshPostToolReplacement {
    pub value: Value,
    pub run_index: usize,
}

/// Credential-free post-tool effects computed on the authorized worker and
/// delivered to the local actor alongside its normal tool result.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SshPostToolHookOutcome {
    /// The worker dispatched `PostToolUseFailure` rather than `PostToolUse`.
    /// Consumers retain this distinction when a tool's terminal result arrives
    /// as a protocol error.
    #[serde(default)]
    pub post_tool_failure: bool,
    /// Model-visible `PreToolUse` context accumulated before the terminal
    /// result. It shares the terminal record so reconnect cannot lose or
    /// duplicate it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pre_tool_context: Vec<SshPostToolHookNote>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub builtin_replacement: Option<SshPostToolReplacement>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp_replacement: Option<SshPostToolReplacement>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub additional_context: Vec<SshPostToolHookNote>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blocks: Vec<SshPostToolHookNote>,
}
/// Response payload for a correlated request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum SshWorkerResponse {
    Bound {
        binding: SshBinding,
        resume_token: SshResumeToken,
    },
    Revoked {
        binding_id: String,
        epoch: u64,
    },
    Rpc {
        operation: SshOperationRecord,
        value: Value,
    },
    Tool {
        operation: SshOperationRecord,
        value: Value,
    },
    Operation(Option<SshOperationRecord>),
    Tasks(Vec<SshTaskRecord>),
    CanonicalPath(String),
    CancellationRequested(SshCancellation),
    ApprovalRecorded,
    Pong,
}

/// A structured, display-safe protocol error.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshWireError {
    pub code: String,
    pub message: String,
    /// Post-tool effects from a failed tool are retained so reconnect and the
    /// local actor observe the same model-visible context without re-running
    /// the remote hook.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post_hook: Option<SshPostToolHookOutcome>,
}

impl SshWireError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            post_hook: None,
        }
    }
}

/// Every post-hello reply keeps the request id so clients can multiplex calls.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshWorkerReply {
    pub request_id: SshRequestId,
    pub result: Result<SshWorkerResponse, SshWireError>,
}

/// One bounded JSON record in the SSH worker stream.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum SshWireFrame {
    ClientHello(SshClientHello),
    WorkerHello(SshWorkerHello),
    /// A display-safe admission failure sent instead of silently closing the
    /// authenticated bridge before a worker hello can be produced.
    HandshakeError(SshWireError),
    Request(SshWorkerRequest),
    Reply(SshWorkerReply),
    Event(SshWorkerEvent),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancellation_requested_remains_nonterminal() {
        assert!(SshOperationState::Unknown.is_terminal());
        assert!(SshOperationState::Cancelled.is_terminal());
        assert!(!SshOperationState::Running.is_terminal());
        assert!(!SshOperationState::CancellationRequested.is_terminal());
    }

    #[test]
    fn frame_uses_adjacent_tagging() {
        let value = serde_json::to_value(SshWireFrame::Request(SshWorkerRequest::Ping {
            request_id: "r-1".into(),
        }))
        .expect("serializes");
        assert_eq!(value["type"], "request");
        assert_eq!(value["data"]["type"], "ping");
    }
}
