use zeroize::Zeroize;

use serde::{Deserialize, Serialize};
use xai_grok_workspace_types::ssh::{
    ResolvedSshInvocation, SshBinding, SshCapabilities, SshHostIdentity, SshOperation,
};
use xai_grok_workspace_types::ssh_wire::SshWorkerEvent;

/// A human-reviewable request for session-scoped remote authority. It deliberately
/// contains neither an SSH secret nor a resolved endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshGrantRequest {
    pub id: String,
    pub session_id: String,
    /// Set only by the trusted worktree workflow to route new-session consent.
    /// Model-provided reasons cannot establish a parent session relationship.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub originating_session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<String>,
    pub capabilities: SshCapabilities,
    pub reason: String,
    /// The identity captured from a real native SSH lease after the local user
    /// chooses to inspect this target. It is never model-provided.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_identity: Option<SshHostIdentity>,
    /// The local client that must receive the approval and authentication UI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<u64>,
}

/// A directory a local SSH project picker can navigate to. The path is a
/// server-provided spelling and may be a symlink; project opening canonicalizes
/// it before any authority is reused or granted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshDirectoryEntry {
    pub name: String,
    pub path: String,
}

/// A bounded, native-SFTP-only directory listing for a local project picker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshDirectoryListing {
    pub target_id: String,
    pub identity: SshHostIdentity,
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    pub directories: Vec<SshDirectoryEntry>,
    pub truncated: bool,
}

/// The result of preparing an SSH project session. It contains either the
/// child-owned binding that is ready for project setup or the exact, already
/// verified consent request that must be resolved first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum SshProjectPreparation {
    Ready(SshBinding),
    NeedsApproval(SshGrantRequest),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SshGrantScope {
    #[default]
    CurrentSession,
    ProjectRule,
}

/// A local user's decision. The optional target/root complete requests where the
/// model deliberately did not know the user's configured targets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshGrantDecision {
    pub request_id: String,
    pub approved: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<SshCapabilities>,
    #[serde(default)]
    pub scope: SshGrantScope,
    #[serde(default)]
    pub make_default: bool,
    pub client_id: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SshGrantStatus {
    Pending,
    Denied,
    Granted,
    RevokedLocalPending,
    RevokedConfirmed,
}

/// The only durable representation of a grant. Authentication material is held
/// by the native transport and is intentionally absent from this type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedSshGrant {
    pub binding: SshBinding,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_binding_id: Option<String>,
    #[serde(default)]
    pub requires_revalidation: bool,
    #[serde(default)]
    pub scope: SshGrantScope,
    #[serde(default)]
    pub revoke_status: Option<SshGrantStatus>,
    /// Whether this authority has been sent to a project worker. Old saved
    /// grants were always worker-backed and must still revoke remotely.
    #[serde(default = "legacy_worker_bound")]
    pub worker_bound: bool,
    /// Managed worker executables that received this grant, retained for cross-version revocation.
    /// Custom argv may contain secrets and remains only in the local target configuration.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub worker_commands: Vec<Vec<String>>,
}

fn legacy_worker_bound() -> bool {
    true
}

/// Per-session SSH state supplied to normal session persistence. It is safe to
/// serialize into an ordinary session record because it never contains secrets.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PersistedSshState {
    pub grants: Vec<PersistedSshGrant>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_binding_id: Option<String>,
    #[serde(default)]
    pub pending_requests: Vec<SshGrantRequest>,
}

/// Granted target data that can safely be shown to the model. Configured but
/// ungranted targets are deliberately not represented here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshTargetAccess {
    pub binding_id: String,
    pub target_id: String,
    pub root: String,
    pub cwd: String,
    pub capabilities: SshCapabilities,
    pub identity: SshHostIdentity,
    pub epoch: u64,
    pub is_default: bool,
    pub connection: SshConnectionState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SshConnectionState {
    Disconnected,
    Connecting,
    Connected,
    AuthenticationRequired,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshTargetStatus {
    pub target_id: String,
    pub connection: SshConnectionState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevokeStatus {
    LocalPending,
    Confirmed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectSshBinding {
    pub binding: SshBinding,
}

/// A resolved operation is captured before it can enter a remote queue. A
/// default change after this point cannot retarget the operation.
#[derive(Debug, Clone)]
pub struct SshDispatchRequest {
    pub invocation: ResolvedSshInvocation,
    pub tool_name: String,
    pub args: serde_json::Value,
    pub mutation_id: Option<String>,
}

impl SshDispatchRequest {
    pub fn operation(&self) -> SshOperation {
        self.invocation.operation
    }
}

/// Clean remote output and the separately rendered model prompt for one
/// explicit `ssh_*` call. The raw output remains available to UI consumers;
/// project hook replacements and feedback are carried only by `prompt_text`.
#[derive(Debug, Clone)]
pub struct SshDispatchResult {
    pub output: serde_json::Value,
    pub prompt_text: String,
}
/// Worker-originated progress, notification, approval, or operation updates
/// scoped to one granted session binding. This is delivered to session/project
/// consumers independently of the SSH manager modal.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SshSessionWorkerEvent {
    pub session_id: String,
    pub binding_id: String,
    pub event: SshWorkerEvent,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SshEvent {
    GrantRequested(SshGrantRequest),
    GrantResolved {
        request_id: String,
        approved: bool,
        binding: Option<SshBinding>,
    },
    BindingRevoked {
        session_id: String,
        binding_id: String,
        status: RevokeStatus,
    },
    Authentication(SshAuthPrompt),
    Worker(SshSessionWorkerEvent),
    OperationApproval(SshOperationApproval),
    WorkerInstallRequested(SshWorkerInstallRequest),
    WorkerInstallProgress(SshWorkerInstallProgress),
    TargetStatus(SshTargetStatus),
}

/// A current remote-worker approval request. It is sent only to the client
/// that originated the call and is not replayed in conversation history.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SshOperationApproval {
    pub client_id: u64,
    pub approval_id: String,
    pub operation_id: String,
    pub binding_id: String,
    pub session_id: String,
    pub operation: SshOperation,
    pub title: String,
    pub detail: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshOperationApprovalDecision {
    pub client_id: u64,
    pub approval_id: String,
    pub approved: bool,
}

/// Local-only consent to download an exact worker build locally and upload it over SSH.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshWorkerInstallRequest {
    pub client_id: u64,
    pub request_id: String,
    pub session_id: String,
    pub binding_id: String,
    pub target_id: String,
    pub version: String,
    pub platform: String,
    pub remote_error: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshWorkerInstallDecision {
    pub client_id: u64,
    pub request_id: String,
    pub session_id: String,
    pub binding_id: String,
    pub approved: bool,
}

/// Installation progress belongs only to the client and binding that opened the project.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshWorkerInstallProgress {
    pub client_id: u64,
    pub request_id: String,
    pub session_id: String,
    pub binding_id: String,
    pub target_id: String,
    /// None clears this request's progress without touching newer messages.
    pub message: Option<String>,
}

/// A native SSH interaction translated into a local-client-only event. The
/// secret itself is provided only by [`SshAuthResponse`] and never appears here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshAuthPrompt {
    pub client_id: u64,
    pub connection_generation: u64,
    pub challenge_id: String,
    pub target_id: String,
    pub kind: SshAuthPromptKind,
    pub detail: SshAuthPromptDetail,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SshAuthPromptDetail {
    HostKey {
        hostname: String,
        port: u16,
        algorithm: String,
        fingerprint: String,
        status: String,
        previous_keys: Vec<String>,
        can_replace: bool,
    },
    Secret {
        username: String,
        message: String,
        #[serde(default)]
        allow_remember: bool,
    },
    KeyboardInteractive {
        name: String,
        instruction: String,
        questions: Vec<SshKeyboardInteractiveQuestion>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshKeyboardInteractiveQuestion {
    pub prompt: String,
    pub echo: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SshAuthPromptKind {
    HostKey,
    Password,
    PrivateKeyPassphrase,
    KeyboardInteractive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SshHostKeyDecision {
    Reject,
    TrustOnce,
    TrustAndStore,
    ReplaceAndStore,
}

/// Secret responses are intentionally not serializable or Debug. They stay on
/// the authenticated local control channel and are converted to the native
pub struct SshAuthResponse {
    pub client_id: u64,
    pub connection_generation: u64,
    pub challenge_id: String,
    pub accepted: Option<bool>,
    pub host_key_decision: Option<SshHostKeyDecision>,
    pub remember: bool,
    pub secret: Option<Vec<u8>>,
    pub answers: Vec<Vec<u8>>,
}

impl Drop for SshAuthResponse {
    fn drop(&mut self) {
        if let Some(secret) = &mut self.secret {
            secret.zeroize();
        }
        for answer in &mut self.answers {
            answer.zeroize();
        }
    }
}

impl std::fmt::Debug for SshAuthResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SshAuthResponse")
            .field("client_id", &self.client_id)
            .field("connection_generation", &self.connection_generation)
            .field("challenge_id", &self.challenge_id)
            .field("accepted", &self.accepted)
            .field("host_key_decision", &self.host_key_decision)
            .field("remember", &self.remember)
            .field(
                "secret",
                &self
                    .secret
                    .as_ref()
                    .map(|secret| format!("<{} bytes>", secret.len())),
            )
            .field("answers", &format!("<{} answers>", self.answers.len()))
            .finish()
    }
}
