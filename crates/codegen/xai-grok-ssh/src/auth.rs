use crate::config::ConfigError;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;
use uuid::Uuid;
use zeroize::Zeroizing;

/// A secret supplied by an interactive client. Its bytes are zeroized on drop and
/// are deliberately unavailable through `Display` or ordinary string access.
pub struct Secret {
    bytes: Zeroizing<Vec<u8>>,
    remember: bool,
}

impl Secret {
    /// Supplies an ephemeral secret. This is the safe default for passwords,
    /// passphrases, and one-time codes.
    pub fn new(value: impl AsRef<[u8]>) -> Self {
        Self::from_owned(value.as_ref().to_vec())
    }

    /// Adopt bytes returned by a credential backend without leaving an
    /// additional, non-zeroized allocation behind.
    pub(crate) fn from_owned(value: Vec<u8>) -> Self {
        Self {
            bytes: Zeroizing::new(value),
            remember: false,
        }
    }

    /// Supplies a secret that the user explicitly chose to save in the
    /// platform credential store. Unsupported stores fail safely; no plaintext
    /// fallback is ever written.
    pub fn remember(value: impl AsRef<[u8]>) -> Self {
        Self {
            bytes: Zeroizing::new(value.as_ref().to_vec()),
            remember: true,
        }
    }

    pub(crate) fn utf8(&self) -> Result<Zeroizing<String>, SshError> {
        let mut bytes = Zeroizing::new(self.bytes.to_vec());
        match String::from_utf8(std::mem::take(&mut *bytes)) {
            Ok(value) => Ok(Zeroizing::new(value)),
            Err(error) => {
                let _discarded = Zeroizing::new(error.into_bytes());
                Err(SshError::InvalidSecretEncoding)
            }
        }
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn should_remember(&self) -> bool {
        self.remember
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Secret(<redacted>)")
    }
}

/// The type of secret being requested. One-time keyboard-interactive responses
/// are never persisted even if an implementation accidentally marks them so.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    Password,
    PrivateKeyPassphrase,
}

/// An authentication request with a unique challenge and connection generation.
/// The values let a UI reject stale responses after a disconnect/reconnect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretPrompt {
    pub challenge_id: Uuid,
    pub connection_generation: u64,
    pub target_id: String,
    pub username: String,
    pub kind: SecretKind,
    pub message: String,
    pub allow_remember: bool,
}

/// A single keyboard-interactive question. `echo` is a rendering instruction,
/// not permission to put a response into a log or transcript.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyboardInteractiveQuestion {
    pub prompt: String,
    pub echo: bool,
}

/// A keyboard-interactive challenge from the SSH server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyboardInteractivePrompt {
    pub challenge_id: Uuid,
    pub connection_generation: u64,
    pub target_id: String,
    pub username: String,
    pub name: String,
    pub instruction: String,
    pub questions: Vec<KeyboardInteractiveQuestion>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostKeyStatus {
    Unknown,
    Changed,
}

/// A host-key verification decision requested by the native SSH transport.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostKeyPrompt {
    pub challenge_id: Uuid,
    pub connection_generation: u64,
    pub target_id: String,
    pub hostname: String,
    pub port: u16,
    pub algorithm: String,
    pub fingerprint: String,
    pub status: HostKeyStatus,
    /// Matching stale keys, formatted with their SHA-256 fingerprint,
    /// algorithm, source file, and line number.
    pub previous_keys: Vec<String>,
    /// Whether this exact user-owned record can be safely replaced.
    pub can_replace: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostKeyDecision {
    Reject,
    TrustOnce,
    TrustAndStore,
    ReplaceAndStore,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InteractionError {
    #[error("authentication interaction was cancelled")]
    Cancelled,
    #[error("authentication interaction is unavailable")]
    Unavailable,
    #[error("authentication interaction rejected the request")]
    Rejected,
}

/// UI/control-plane bridge for SSH authentication. Implementations must route a
/// request only to the originating client and must not record secrets.
#[async_trait]
pub trait Interaction: Send + Sync {
    async fn confirm_host_key(
        &self,
        prompt: HostKeyPrompt,
    ) -> Result<HostKeyDecision, InteractionError>;

    async fn request_secret(&self, prompt: SecretPrompt) -> Result<Secret, InteractionError>;

    async fn request_keyboard_interactive(
        &self,
        prompt: KeyboardInteractivePrompt,
    ) -> Result<Vec<Secret>, InteractionError>;
}

/// A redacted, structured resolver failure suitable for UI and CLI display.
/// It preserves the configuration location and directive needed to fix an
/// incompatible setup without ever carrying authentication material or the
/// original configuration value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigurationDiagnostic {
    pub kind: ConfigurationDiagnosticKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directive: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_id: Option<String>,
    pub message: String,
}

impl std::error::Error for ConfigurationDiagnostic {}

/// The stable category of a configuration-resolution failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigurationDiagnosticKind {
    Read,
    Parse,
    InvalidTarget,
    TargetNotFound,
    ImmutableImportedTarget,
    InvalidSshConfig,
    UnsupportedDirective,
    IncludeRecursion,
    IncludeDepth,
    MissingEnvironment,
}

impl From<ConfigError> for ConfigurationDiagnostic {
    fn from(error: ConfigError) -> Self {
        match error {
            ConfigError::Io { path, .. } => Self {
                kind: ConfigurationDiagnosticKind::Read,
                path: Some(path),
                line: None,
                directive: None,
                target_id: None,
                message: "could not read SSH configuration".to_owned(),
            },
            ConfigError::GrokyToml { path, .. } => Self {
                kind: ConfigurationDiagnosticKind::Parse,
                path: Some(path),
                line: None,
                directive: None,
                target_id: None,
                message: "could not parse Groky SSH configuration".to_owned(),
            },
            ConfigError::InvalidTarget(_) => Self {
                kind: ConfigurationDiagnosticKind::InvalidTarget,
                path: None,
                line: None,
                directive: None,
                target_id: None,
                message: "the SSH target configuration is invalid".to_owned(),
            },
            ConfigError::TargetNotFound(target_id) => Self {
                kind: ConfigurationDiagnosticKind::TargetNotFound,
                path: None,
                line: None,
                directive: None,
                target_id: Some(target_id),
                message: "the requested SSH target was not found".to_owned(),
            },
            ConfigError::ImmutableImportedTarget(target_id) => Self {
                kind: ConfigurationDiagnosticKind::ImmutableImportedTarget,
                path: None,
                line: None,
                directive: None,
                target_id: Some(target_id),
                message: "the imported SSH target cannot be edited".to_owned(),
            },
            ConfigError::InvalidSshConfig { path, line, .. } => Self {
                kind: ConfigurationDiagnosticKind::InvalidSshConfig,
                path: Some(path),
                line: Some(line),
                directive: None,
                target_id: None,
                message: "the active SSH configuration is invalid".to_owned(),
            },
            ConfigError::UnsupportedDirective {
                path,
                line,
                directive,
                reason,
            } => Self {
                kind: ConfigurationDiagnosticKind::UnsupportedDirective,
                path: Some(path),
                line: Some(line),
                directive: Some(directive),
                target_id: None,
                message: reason,
            },
            ConfigError::IncludeRecursion { path } => Self {
                kind: ConfigurationDiagnosticKind::IncludeRecursion,
                path: Some(path),
                line: None,
                directive: Some("Include".to_owned()),
                target_id: None,
                message: "SSH Include recursion was detected".to_owned(),
            },
            ConfigError::IncludeDepth { path, .. } => Self {
                kind: ConfigurationDiagnosticKind::IncludeDepth,
                path: Some(path),
                line: None,
                directive: Some("Include".to_owned()),
                target_id: None,
                message: "SSH Include nesting exceeds the supported depth".to_owned(),
            },
            ConfigError::MissingEnvironment {
                path,
                line,
                variable,
            } => Self {
                kind: ConfigurationDiagnosticKind::MissingEnvironment,
                path: Some(path),
                line: Some(line),
                directive: None,
                target_id: None,
                message: format!("required environment variable `{variable}` is not set"),
            },
        }
    }
}

impl fmt::Display for ConfigurationDiagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(directive) = &self.directive {
            write!(formatter, "{directive}: ")?;
        }
        formatter.write_str(&self.message)?;
        if let Some(path) = &self.path {
            write!(formatter, " at {}", path.display())?;
            if let Some(line) = self.line {
                write!(formatter, ":{line}")?;
            }
        }
        if let Some(target_id) = &self.target_id {
            write!(formatter, " (target `{target_id}`)")?;
        }
        Ok(())
    }
}

/// Errors deliberately omit credential material and raw interactive responses.
#[derive(Debug, Clone, thiserror::Error)]
pub enum SshError {
    #[error("SSH target configuration failed")]
    Configuration,
    #[error("SSH target configuration failed: {0}")]
    ConfigurationDiagnostic(#[from] ConfigurationDiagnostic),
    #[error("SSH connection timed out")]
    ConnectTimeout,
    #[error("SSH host key is unknown and cannot be trusted without interaction")]
    UnknownHostKey,
    #[error("SSH host key changed or conflicts with a known key")]
    ChangedHostKey,
    #[error("SSH host key is revoked")]
    RevokedHostKey,
    #[error("SSH host key was rejected")]
    HostKeyRejected,
    #[error("SSH host key replacement could not be completed safely: {0}")]
    HostKeyReplacement(String),
    #[error("SSH authentication interaction failed: {0}")]
    Interaction(#[from] InteractionError),
    #[error("SSH authentication failed")]
    AuthenticationFailed,
    #[error("SSH agent authentication failed")]
    AgentAuthenticationFailed,
    #[error("SSH private key could not be loaded")]
    PrivateKey,
    #[error("SSH secret is not valid UTF-8")]
    InvalidSecretEncoding,
    #[error("the configured SSH algorithms are unsupported")]
    UnsupportedAlgorithms,
    #[error("the configured proxy route cannot be established")]
    Proxy,
    #[error("the SSH connection is disconnected")]
    Disconnected,
    #[error("the SSH server rejected a channel request")]
    ChannelRequestRejected,
    #[error("the SSH server did not answer a channel request")]
    ChannelRequestTimeout,
    #[error("the SSH signal name is invalid")]
    InvalidSignal,
    #[error("SSH credential store is unavailable")]
    CredentialStoreUnavailable,
    #[error("SSH transport failed")]
    Transport,
}

#[cfg(test)]
mod tests {
    use super::{ConfigurationDiagnostic, ConfigurationDiagnosticKind, Secret};
    use crate::config::ConfigError;
    use std::path::PathBuf;

    #[test]
    fn secret_debug_is_redacted() {
        let secret = Secret::new("must-not-appear");
        let debug = format!("{secret:?}");
        assert_eq!(debug, "Secret(<redacted>)");
        assert!(!debug.contains("must-not-appear"));
    }

    #[test]
    fn unsupported_directive_keeps_safe_fix_location() {
        let diagnostic = ConfigurationDiagnostic::from(ConfigError::UnsupportedDirective {
            path: PathBuf::from("/home/alice/.ssh/config"),
            line: 42,
            directive: "ProxyUseFdpass".to_owned(),
            reason: "the native SSH transport does not implement this active setting".to_owned(),
        });

        assert_eq!(
            diagnostic.kind,
            ConfigurationDiagnosticKind::UnsupportedDirective
        );
        assert_eq!(
            diagnostic.path,
            Some(PathBuf::from("/home/alice/.ssh/config"))
        );
        assert_eq!(diagnostic.line, Some(42));
        assert_eq!(diagnostic.directive.as_deref(), Some("ProxyUseFdpass"));
        assert!(
            diagnostic
                .to_string()
                .contains("native SSH transport does not implement")
        );
    }

    #[test]
    fn missing_target_keeps_the_requested_identifier() {
        let diagnostic =
            ConfigurationDiagnostic::from(ConfigError::TargetNotFound("missing-target".to_owned()));

        assert_eq!(diagnostic.kind, ConfigurationDiagnosticKind::TargetNotFound);
        assert_eq!(diagnostic.target_id.as_deref(), Some("missing-target"));
        assert_eq!(
            diagnostic.to_string(),
            "the requested SSH target was not found (target `missing-target`)"
        );
    }
}
