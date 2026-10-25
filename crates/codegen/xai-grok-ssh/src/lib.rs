#![deny(clippy::indexing_slicing)]
//! Native SSH transport for Groky.
//!
//! This crate evaluates only user-global SSH configuration, verifies host keys,
//! keeps secrets out of ordinary data paths, and multiplexes native russh
//! connections. It does not spawn `ssh` or depend on model/provider auth.

pub mod auth;
pub mod config;
mod connection;
mod credentials;
mod known_hosts;
mod sudo;

pub use auth::{
    ConfigurationDiagnostic, ConfigurationDiagnosticKind, HostKeyDecision, HostKeyPrompt,
    HostKeyStatus, Interaction, InteractionError, KeyboardInteractivePrompt,
    KeyboardInteractiveQuestion, Secret, SecretKind, SecretPrompt, SshError, SudoInteraction,
    SudoPasswordPrompt,
};
pub use config::{
    AgentConfig, AlgorithmRequirements, AuthMethod, ConfigError, ConfigValueSource,
    DEFAULT_WORKER_COMMAND, DurationSetting, HostKeyPolicy, JumpHost, KeepAliveConfig,
    KnownHostsConfig, ProxyRoute, ResolvedConfigProvenance, ResolvedSshConfig, SshConfigSource,
    SshTarget, TargetSource, TargetStore, default_worker_command, parse_worker_command,
};
pub use connection::{
    BoxedSshStream, ConnectionFailure, ConnectionLease, ConnectionManager, ConnectionPhase,
    ConnectionStatus, SftpConnection, SshCommand, SshCommandEvent, SshStream,
};
pub use russh_sftp as sftp;
