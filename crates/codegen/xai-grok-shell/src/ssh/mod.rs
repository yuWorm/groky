//! Session-scoped SSH authority, explicit remote tool pack, and local-only
//! control/authentication bridges. SSH credentials are owned by the native
//! transport and never enter this module's persisted session state.

mod control;
mod control_client;
mod model;
mod native_files;
mod native_tasks;
mod service;
mod tools;

pub use control::{SshAuthControlResponse, SshControlCommand, SshControlReply};
pub use control_client::{SshControlClient, SshControlClientError};
pub use model::{
    PersistedSshGrant, PersistedSshState, ProjectSshBinding, RevokeStatus, SshAuthPrompt,
    SshAuthPromptDetail, SshAuthPromptKind, SshAuthResponse, SshConnectionState,
    SshDispatchRequest, SshDispatchResult, SshEvent, SshGrantDecision, SshGrantRequest,
    SshGrantScope, SshGrantStatus, SshHostKeyDecision, SshKeyboardInteractiveQuestion,
    SshOperationApproval, SshOperationApprovalDecision, SshSessionWorkerEvent, SshTargetAccess,
    SshTargetStatus,
};
pub use service::{SessionSsh, SessionSshResource, SshServiceError};
pub(crate) use tools::configure_default_tools;
pub use tools::register_tool_pack;
pub use xai_grok_workspace_types::ssh::{
    ProjectLocation, ResolvedSshInvocation, SshBinding, SshCapabilities, SshHostIdentity,
    SshOperation,
};
