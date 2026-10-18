//! Execution targets and session-scoped SSH authority. No credentials live on this wire.

use serde::{Deserialize, Serialize};

/// A filesystem location on its execution host, not a path on the client machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum ProjectLocation {
    Local { root: String },
    Ssh { target_id: String, root: String },
}

impl ProjectLocation {
    pub fn root(&self) -> &str {
        match self {
            Self::Local { root } | Self::Ssh { root, .. } => root,
        }
    }
}

/// Capabilities are a ceiling, not a replacement for per-operation approval.
/// In particular, arbitrary command execution is not a read-only capability.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SshCapabilities {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl SshCapabilities {
    pub const fn read_only() -> Self {
        Self {
            read: true,
            write: false,
            execute: false,
        }
    }

    pub const fn all() -> Self {
        Self {
            read: true,
            write: true,
            execute: true,
        }
    }

    pub const fn is_subset_of(self, parent: Self) -> bool {
        (!self.read || parent.read)
            && (!self.write || parent.write)
            && (!self.execute || parent.execute)
    }

    pub const fn permits(self, operation: SshOperation) -> bool {
        match operation {
            SshOperation::Read => self.read,
            SshOperation::Write => self.write,
            SshOperation::Execute => self.execute,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SshOperation {
    Read,
    Write,
    Execute,
}

/// The identity actually verified by SSH, rather than a model-supplied host label.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshHostIdentity {
    pub hostname: String,
    pub port: u16,
    pub username: String,
    pub fingerprint: String,
}

/// Authority belongs to a session even when the underlying SSH connection is shared.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshBinding {
    pub id: String,
    pub session_id: String,
    pub target_id: String,
    pub identity: SshHostIdentity,
    /// Canonical root on the remote host, verified over SFTP or by the project worker.
    pub root: String,
    pub cwd: String,
    pub capabilities: SshCapabilities,
    /// Monotonic authorization version. Queued requests retain their original version.
    pub epoch: u64,
    #[serde(default)]
    pub revoked: bool,
}

/// Captured before enqueueing, so changing a session default cannot retarget a call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedSshInvocation {
    pub binding_id: String,
    pub target_id: String,
    pub session_id: String,
    pub epoch: u64,
    pub cwd: String,
    pub operation: SshOperation,
    pub call_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execution_is_not_granted_by_read_or_edit_access() {
        let edits = SshCapabilities {
            read: true,
            write: true,
            execute: false,
        };
        assert!(!edits.permits(SshOperation::Execute));
        assert!(!SshCapabilities::all().is_subset_of(edits));
        assert!(SshCapabilities::read_only().is_subset_of(edits));
        assert!(!edits.is_subset_of(SshCapabilities::read_only()));
    }

    #[test]
    fn omitted_capabilities_are_denied() {
        let capabilities: SshCapabilities = serde_json::from_str("{}").unwrap();
        assert!(!capabilities.permits(SshOperation::Read));
        assert!(!capabilities.permits(SshOperation::Write));
        assert!(!capabilities.permits(SshOperation::Execute));
    }
}
