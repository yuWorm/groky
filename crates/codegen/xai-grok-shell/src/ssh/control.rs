use zeroize::Zeroize;

use serde::{Deserialize, Serialize};
use xai_grok_workspace_types::ssh::SshCapabilities;

use super::model::{
    RevokeStatus, SshAuthResponse, SshOperationApprovalDecision, SshTargetAccess, SshTargetStatus,
};
use super::{SshGrantDecision, SshGrantRequest};

/// Leader IPC commands available without provider or model authentication. Every
/// command runs against the leader-held `SessionSsh`, which is why CLI connect
/// leases survive after the short-lived CLI process exits.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum SshControlCommand {
    ListConfiguredTargets,
    ListSessionTargets {
        session_id: String,
    },
    RequestGrant {
        session_id: String,
        #[serde(default)]
        target_id: Option<String>,
        #[serde(default)]
        root: Option<String>,
        capabilities: SshCapabilities,
        reason: String,
    },
    InspectGrantTarget {
        request_id: String,
        target_id: String,
    },
    ApproveGrant(SshGrantDecision),
    /// Explicitly mint a child/session-local grant from a parent grant. The
    /// requested capability ceiling may only narrow the parent binding.
    InheritSession {
        source_session_id: String,
        binding_id: String,
        target_session_id: String,
        capabilities: SshCapabilities,
    },
    /// Registers the originating local or SSH project that owns explicitly
    /// saved rules. Registration alone never grants remote authority.
    RegisterProjectLocation {
        session_id: String,
        location: xai_grok_workspace_types::ssh::ProjectLocation,
    },
    /// Restore only explicitly saved rules for this project, then verify its
    /// exact remote root before returning a project-opening binding.
    RestoreProjectGrant {
        session_id: String,
        location: xai_grok_workspace_types::ssh::ProjectLocation,
    },
    UseBinding {
        session_id: String,
        binding_id: String,
    },
    RevokeBinding {
        session_id: String,
        binding_id: String,
    },
    Connect {
        target_id: String,
        interactive: bool,
    },
    Disconnect {
        target_id: String,
    },
    ConnectionStatus {
        target_id: String,
    },
    SubmitAuthentication(SshAuthControlResponse),
    SubmitOperationApproval(SshOperationApprovalDecision),
}

/// IPC-only secret input. Its Debug implementation is redacted and it is never
/// placed in session persistence, events, tool output, logs, or model replay.
pub struct SshAuthControlResponse {
    pub client_id: u64,
    pub connection_generation: u64,
    pub challenge_id: String,
    pub accepted: Option<bool>,
    pub host_key_decision: Option<super::SshHostKeyDecision>,
    pub remember: bool,
    pub secret: Option<Vec<u8>>,
    pub answers: Vec<Vec<u8>>,
}

impl std::fmt::Debug for SshAuthControlResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SshAuthControlResponse")
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

impl Drop for SshAuthControlResponse {
    fn drop(&mut self) {
        if let Some(secret) = &mut self.secret {
            secret.zeroize();
        }
        for answer in &mut self.answers {
            answer.zeroize();
        }
    }
}

impl PartialEq for SshAuthControlResponse {
    fn eq(&self, other: &Self) -> bool {
        self.client_id == other.client_id
            && self.connection_generation == other.connection_generation
            && self.challenge_id == other.challenge_id
            && self.accepted == other.accepted
            && self.host_key_decision == other.host_key_decision
            && self.remember == other.remember
            && self.secret == other.secret
            && self.answers == other.answers
    }
}

impl Eq for SshAuthControlResponse {}

impl Serialize for SshAuthControlResponse {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Wire<'a> {
            client_id: u64,
            connection_generation: u64,
            challenge_id: &'a str,
            accepted: Option<bool>,
            host_key_decision: Option<super::SshHostKeyDecision>,
            remember: bool,
            secret: Option<&'a Vec<u8>>,
            answers: &'a [Vec<u8>],
        }
        Wire {
            client_id: self.client_id,
            connection_generation: self.connection_generation,
            challenge_id: &self.challenge_id,
            accepted: self.accepted,
            host_key_decision: self.host_key_decision,
            remember: self.remember,
            secret: self.secret.as_ref(),
            answers: &self.answers,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SshAuthControlResponse {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Wire {
            client_id: u64,
            connection_generation: u64,
            challenge_id: String,
            accepted: Option<bool>,
            host_key_decision: Option<super::SshHostKeyDecision>,
            #[serde(default)]
            remember: bool,
            secret: Option<Vec<u8>>,
            #[serde(default)]
            answers: Vec<Vec<u8>>,
        }
        let wire = Wire::deserialize(deserializer)?;
        Ok(Self {
            client_id: wire.client_id,
            connection_generation: wire.connection_generation,
            challenge_id: wire.challenge_id,
            accepted: wire.accepted,
            host_key_decision: wire.host_key_decision,
            remember: wire.remember,
            secret: wire.secret,
            answers: wire.answers,
        })
    }
}

impl From<SshAuthControlResponse> for SshAuthResponse {
    fn from(mut value: SshAuthControlResponse) -> Self {
        Self {
            client_id: value.client_id,
            connection_generation: value.connection_generation,
            challenge_id: std::mem::take(&mut value.challenge_id),
            accepted: value.accepted,
            host_key_decision: value.host_key_decision,
            remember: value.remember,
            secret: value.secret.take(),
            answers: std::mem::take(&mut value.answers),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum SshControlReply {
    /// Serialized configured targets are a UI-only listing; model tools use
    /// SessionTargets, which filters to grants. The raw JSON keeps this pack
    /// independent of native config implementation details.
    ConfiguredTargets(String),
    SessionTargets(Vec<SshTargetAccess>),
    GrantRequested(SshGrantRequest),
    GrantResolved {
        binding: Option<xai_grok_workspace_types::ssh::SshBinding>,
    },
    InheritedBindings(Vec<xai_grok_workspace_types::ssh::SshBinding>),
    ProjectLocationRegistered,
    ProjectGrantRestored {
        binding: Option<xai_grok_workspace_types::ssh::SshBinding>,
    },
    BindingSelected,
    BindingRevoked {
        status: RevokeStatus,
    },
    TargetStatus(SshTargetStatus),
    AuthenticationAccepted,
    OperationApprovalAccepted,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::leader::{ControlCommand, ControlPayload};

    #[test]
    fn ssh_control_frames_preserve_nested_commands_and_non_map_replies() {
        for command in [
            SshControlCommand::ListConfiguredTargets,
            SshControlCommand::Connect {
                target_id: "build-host".into(),
                interactive: false,
            },
        ] {
            let command = ControlCommand::Ssh(command);
            let frame = serde_json::to_vec(&command).unwrap();
            assert_eq!(
                serde_json::from_slice::<ControlCommand>(&frame).unwrap(),
                command
            );
        }
        for reply in [
            SshControlReply::ConfiguredTargets("[{\"id\":\"build-host\"}]".into()),
            SshControlReply::SessionTargets(Vec::new()),
        ] {
            let reply = ControlPayload::Ssh(reply);
            let frame = serde_json::to_vec(&reply).unwrap();
            assert_eq!(
                serde_json::from_slice::<ControlPayload>(&frame).unwrap(),
                reply
            );
        }
    }
}
