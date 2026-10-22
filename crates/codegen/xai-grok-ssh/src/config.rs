//! User-global SSH target persistence and OpenSSH-compatible resolution.
//!
//! This module deliberately reads only the user Groky config and OpenSSH's
//! user/system configuration. Repository configuration is never consulted for
//! SSH connection identity or routing.

mod parser;
mod store;

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use store::{TargetStore, parse_worker_command};

/// The command used when a target does not select a worker explicitly.
pub const DEFAULT_WORKER_COMMAND: &[&str] = &["groky", "worker", "--stdio"];

/// Return the default worker command as owned argv values.
#[must_use]
pub fn default_worker_command() -> Vec<String> {
    DEFAULT_WORKER_COMMAND
        .iter()
        .map(ToString::to_string)
        .collect()
}

/// Return whether a case-sensitive OpenSSH `SendEnv` pattern selects an
/// environment-variable name. Only `*` and `?` are wildcards.
#[must_use]
pub fn send_env_pattern_matches(pattern: &str, variable: &str) -> bool {
    parser::send_env_pattern_matches(pattern, variable)
}

/// A configured SSH connection target. Credential references name secure-store
/// entries; they never contain credential material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshTarget {
    /// Stable user-visible identifier used by sessions and project bindings.
    pub id: String,
    /// Editable display label.
    pub label: String,
    /// OpenSSH host alias or directly-addressable host supplied by the user.
    pub host: String,
    /// Groky-level override, above user and system ssh_config values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Groky-level override, above user and system ssh_config values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Private keys in attempt order. These supplement, rather than replace,
    /// matching OpenSSH `IdentityFile` entries.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub identity_files: Vec<PathBuf>,
    /// Reference to a platform credential-store entry, never a secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_ref: Option<String>,
    /// Executable followed by argv. It is not evaluated by a shell.
    #[serde(default = "default_worker_command")]
    pub worker_command: Vec<String>,
    /// Persisted targets are `User`; imported OpenSSH aliases are read-only.
    #[serde(default)]
    pub source: TargetSource,
}

impl SshTarget {
    /// Create an editable user target with a generated stable identifier.
    #[must_use]
    pub fn new(host: impl Into<String>) -> Self {
        let host = host.into();
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            label: host.clone(),
            host,
            user: None,
            port: None,
            identity_files: Vec::new(),
            credential_ref: None,
            worker_command: default_worker_command(),
            source: TargetSource::User,
        }
    }
}

/// Where a target was discovered. Imported aliases are exposed so users can
/// select their existing SSH setup without copying it into Groky config.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TargetSource {
    /// A target stored under `[ssh.targets.<id>]` in the user-global config.
    #[default]
    User,
    /// A literal `Host` alias discovered in a user or system SSH config file.
    Imported { path: PathBuf, line: usize },
}

/// An evaluated SSH configuration safe for consumption by the native transport.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedSshConfig {
    pub target: SshTarget,
    pub hostname: String,
    pub username: String,
    pub port: u16,
    pub identity_files: Vec<PathBuf>,
    pub agent: AgentConfig,
    pub known_hosts: KnownHostsConfig,
    pub host_key_policy: HostKeyPolicy,
    pub preferred_auth: Vec<AuthMethod>,
    /// Local environment-variable name patterns accepted for forwarding. Values
    /// are read only when the native transport opens a channel.
    #[serde(default)]
    pub send_env: Vec<String>,
    /// Routing is exclusive: OpenSSH honors the first of ProxyJump or
    /// ProxyCommand that takes effect.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<ProxyRoute>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_timeout: Option<DurationSetting>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_alive: Option<KeepAliveConfig>,
    pub algorithms: AlgorithmRequirements,
    /// Provenance for UI inspection and actionable failures.
    pub provenance: ResolvedConfigProvenance,
}

/// Agent selection resolved from `IdentityAgent`, `IdentitiesOnly`, and the
/// public-key authentication setting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentConfig {
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socket: Option<PathBuf>,
    pub identities_only: bool,
}

/// Known-host files and hashing behavior resolved from SSH configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnownHostsConfig {
    pub user_files: Vec<PathBuf>,
    pub global_files: Vec<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash_known_hosts: Option<bool>,
}

/// Host-key verification policy. `Off` is preserved explicitly so the UI and
/// transport never mistake it for verified host-key behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostKeyPolicy {
    Ask,
    AcceptNew,
    Require,
    Off,
}

/// Authentication methods the selected configuration permits, in preference
/// order. Unsupported methods are rejected by resolution rather than dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    PublicKey,
    KeyboardInteractive,
    Password,
}

/// An OpenSSH route to the final target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum ProxyRoute {
    Jump(Vec<JumpHost>),
    Command(String),
}

/// One `ProxyJump` hop.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JumpHost {
    pub hostname: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

/// A duration represented in seconds for a stable, portable config boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurationSetting {
    pub seconds: u64,
}

/// Server-side keepalive behavior. An interval of zero explicitly disables
/// application-level SSH keepalives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeepAliveConfig {
    pub interval: DurationSetting,
    pub count_max: u32,
    /// The OpenSSH `TCPKeepAlive` setting, retained separately from server
    /// keepalives so a transport cannot silently ignore it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_keep_alive: Option<bool>,
}

/// Algorithm requirements which the native transport must verify against its
/// real backend capabilities before it connects.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlgorithmRequirements {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_key: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kex: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ciphers: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub macs: Option<Vec<String>>,
}

/// The source tier of an effective SSH setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SshConfigSource {
    Target,
    UserSsh,
    SystemSsh,
    Default,
}

/// Exact origin of one resolved setting. `line == 0` identifies a value read
/// from the structured Groky target record rather than one SSH config line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigValueSource {
    pub source: SshConfigSource,
    pub path: PathBuf,
    pub line: usize,
}

/// Field-to-source mapping shown by management UI and included in diagnostics.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedConfigProvenance {
    pub fields: BTreeMap<String, ConfigValueSource>,
}

/// Errors are intentionally specific: ambiguous/unsupported SSH settings must
/// not be silently downgraded into a different connection identity or route.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse Groky configuration {path}: {message}")]
    GrokyToml { path: PathBuf, message: String },
    #[error("invalid SSH target: {0}")]
    InvalidTarget(String),
    #[error("target_not_found: SSH target `{0}` was not found")]
    TargetNotFound(String),
    #[error(
        "ambiguous_target: SSH target reference `{reference}` matches multiple configured targets; use one exact target_id: {candidate_ids:?}"
    )]
    AmbiguousTarget {
        reference: String,
        candidate_ids: Vec<String>,
    },
    #[error("imported SSH alias `{0}` is read-only; create a user target to override it")]
    ImmutableImportedTarget(String),
    #[error("SSH target `{0}` was changed or removed before this edit could be saved")]
    StaleTarget(String),
    #[error("invalid SSH configuration at {path}:{line}: {message}")]
    InvalidSshConfig {
        path: PathBuf,
        line: usize,
        message: String,
    },
    #[error("unsupported active SSH directive `{directive}` at {path}:{line}: {reason}")]
    UnsupportedDirective {
        path: PathBuf,
        line: usize,
        directive: String,
        reason: String,
    },
    #[error("SSH Include recursion detected at {path}")]
    IncludeRecursion { path: PathBuf },
    #[error("SSH Include nesting exceeded {limit} files at {path}")]
    IncludeDepth { path: PathBuf, limit: usize },
    #[error("environment variable `{variable}` used at {path}:{line} is not set")]
    MissingEnvironment {
        path: PathBuf,
        line: usize,
        variable: String,
    },
}

#[cfg(test)]
mod tests;
