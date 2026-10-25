use crate::auth::{
    ConfigurationDiagnostic, ConfigurationDiagnosticKind, Interaction, InteractionError,
    KeyboardInteractivePrompt, KeyboardInteractiveQuestion, SecretKind, SecretPrompt, SshError,
    SudoInteraction,
};
use crate::config::{
    AlgorithmRequirements, AuthMethod, ProxyRoute, ResolvedSshConfig, SshTarget, TargetStore,
    send_env_pattern_matches,
};
use crate::credentials::CredentialStore;
use crate::known_hosts;
use russh::client::{self, Handler, KeyboardInteractiveAuthResponse};
use russh::keys::{
    Algorithm, PrivateKeyWithHashAlg, PublicKeyOrCertificate, agent::client::AgentClient,
};
use russh::{Channel, ChannelMsg, ChannelReadHalf, ChannelStream, Disconnect, Preferred, Sig};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::collections::{HashMap, VecDeque};
use std::convert::TryFrom;
use std::fs;
use std::io::{self, Read};
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::Mutex as AsyncMutex;
use tokio::time::{sleep, timeout};
use uuid::Uuid;
use xai_grok_workspace_types::ssh::SshHostIdentity;
use zeroize::Zeroizing;

const IDLE_DISCONNECT_AFTER: Duration = Duration::from_secs(5 * 60);
const CHANNEL_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_INITIAL_COMMAND_EVENTS: usize = 16;
const MAX_INITIAL_COMMAND_BYTES: usize = 64 * 1024;

/// A read/write SSH channel stream. It is intentionally opaque so users cannot
/// reach the underlying russh handle or credentials.
pub trait SshStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> SshStream for T {}

/// A real bidirectional SSH channel, suitable for the remote workspace wire.
pub type BoxedSshStream = Pin<Box<dyn SshStream>>;

/// An output or termination event emitted by a raw SSH exec channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshCommandEvent {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    ExitStatus(u32),
    ExitSignal(String),
}

/// A pooled SFTP session that keeps its native SSH connection in use.
pub struct SftpConnection {
    session: russh_sftp::client::SftpSession,
    atomic_replace: AsyncMutex<AtomicReplaceState>,
    entry: Arc<ConnectionEntry>,
    generation: u64,
    _use_guard: EntryUse,
}

enum AtomicReplaceState {
    Uninitialized,
    Unsupported,
    Ready(SftpAtomicReplaceSession),
}

struct SftpAtomicReplaceSession {
    session: russh_sftp::client::RawSftpSession,
    _use_guard: EntryUse,
}

/// Owns a raw channel until it is either transferred to its long-lived user or
/// closed. `russh::Channel` itself does not request close when dropped.
pub(crate) struct ClosingChannel {
    channel: Option<Channel<client::Msg>>,
    use_guard: Option<EntryUse>,
    runtime: tokio::runtime::Handle,
    close_sent: AtomicBool,
}

impl ClosingChannel {
    fn new(channel: Channel<client::Msg>, use_guard: EntryUse) -> Self {
        Self {
            channel: Some(channel),
            use_guard: Some(use_guard),
            runtime: tokio::runtime::Handle::current(),
            close_sent: AtomicBool::new(false),
        }
    }

    pub(crate) async fn close(&self) -> Result<(), SshError> {
        if !self.close_sent.load(Ordering::Acquire) {
            close_channel(self).await?;
            self.close_sent.store(true, Ordering::Release);
        }
        Ok(())
    }

    fn into_stream_and_guard(mut self) -> (ChannelStream<client::Msg>, EntryUse) {
        let channel = self
            .channel
            .take()
            .expect("a guarded channel is present until it is transferred");
        let use_guard = self
            .use_guard
            .take()
            .expect("a guarded channel keeps its pool use until it is transferred");
        (channel.into_stream(), use_guard)
    }
}

impl Deref for ClosingChannel {
    type Target = Channel<client::Msg>;

    fn deref(&self) -> &Self::Target {
        self.channel
            .as_ref()
            .expect("a guarded channel is present until it is transferred")
    }
}

impl std::ops::DerefMut for ClosingChannel {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.channel
            .as_mut()
            .expect("a guarded channel is present until it is transferred")
    }
}

impl Drop for ClosingChannel {
    fn drop(&mut self) {
        if self.close_sent.load(Ordering::Acquire) {
            return;
        }
        let Some(channel) = self.channel.take() else {
            return;
        };
        let Some(use_guard) = self.use_guard.take() else {
            return;
        };
        self.runtime.spawn(async move {
            let _ = close_channel(&channel).await;
            drop(channel);
            drop(use_guard);
        });
    }
}

impl std::fmt::Debug for SftpConnection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SftpConnection")
            .finish_non_exhaustive()
    }
}

impl Deref for SftpConnection {
    type Target = russh_sftp::client::SftpSession;

    fn deref(&self) -> &Self::Target {
        &self.session
    }
}

impl SftpConnection {
    /// Check whether this server offers `posix-rename@openssh.com` version 1.
    pub async fn supports_atomic_replace(&self) -> Result<bool, russh_sftp::client::error::Error> {
        let mut state = self.atomic_replace.lock().await;
        self.ensure_atomic_replace_session(&mut state).await
    }

    /// Atomically replace an existing path with a completed temporary file.
    ///
    /// This only sends `posix-rename@openssh.com` after negotiated support
    /// confirms that the server implements its overwrite semantics.
    pub async fn atomic_replace(
        &self,
        from: String,
        to: String,
    ) -> Result<(), russh_sftp::client::error::Error> {
        let payload = posix_rename_payload(&from, &to)?;
        let mut state = self.atomic_replace.lock().await;
        if !self.ensure_atomic_replace_session(&mut state).await? {
            return Err(russh_sftp::client::error::Error::UnexpectedBehavior(
                "the remote SFTP server does not support atomic replacement".to_owned(),
            ));
        }
        let AtomicReplaceState::Ready(session) = &*state else {
            unreachable!("a supported atomic replacement session is retained");
        };
        match session
            .session
            .extended("posix-rename@openssh.com", payload)
            .await?
        {
            russh_sftp::protocol::Packet::Status(status)
                if status.status_code == russh_sftp::protocol::StatusCode::Ok =>
            {
                Ok(())
            }
            russh_sftp::protocol::Packet::Status(status) => Err(status.into()),
            _ => Err(russh_sftp::client::error::Error::UnexpectedPacket),
        }
    }

    async fn ensure_atomic_replace_session(
        &self,
        state: &mut AtomicReplaceState,
    ) -> Result<bool, russh_sftp::client::error::Error> {
        match state {
            AtomicReplaceState::Ready(_) => return Ok(true),
            AtomicReplaceState::Unsupported => return Ok(false),
            AtomicReplaceState::Uninitialized => {}
        }
        *state = match open_atomic_replace_session(&self.entry, self.generation)
            .await
            .map_err(sftp_channel_error)?
        {
            Some(session) => AtomicReplaceState::Ready(session),
            None => AtomicReplaceState::Unsupported,
        };
        Ok(matches!(&*state, AtomicReplaceState::Ready(_)))
    }
}

/// A generation-bound raw SSH exec channel.
pub struct SshCommand {
    pub(crate) channel: ClosingChannel,
    pub(crate) entry: Arc<ConnectionEntry>,
    pub(crate) generation: u64,
    pub(crate) pending: VecDeque<SshCommandEvent>,
    pub(crate) finished: bool,
}

impl std::fmt::Debug for SshCommand {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SshCommand")
            .field("generation", &self.generation)
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

impl SshCommand {
    /// Return the next stdout, stderr, or termination event from the remote
    /// command. A channel which closes without an exit result is disconnected.
    pub async fn next_event(&mut self) -> Result<Option<SshCommandEvent>, SshError> {
        loop {
            if !generation_is_current(&self.entry, self.generation) {
                return Err(SshError::Disconnected);
            }
            if let Some(event) = self.pending.pop_front() {
                return Ok(Some(event));
            }

            let Some(message) = self.channel.wait().await else {
                return command_channel_closed(self.finished);
            };
            if !generation_is_current(&self.entry, self.generation) {
                return Err(SshError::Disconnected);
            }
            if matches!(message, ChannelMsg::Close) {
                return command_channel_closed(self.finished);
            }
            if let Some(event) = command_event(message, &mut self.finished)? {
                return Ok(Some(event));
            }
        }
    }

    /// Send an SSH signal to the remote command without recreating its channel.
    pub async fn signal(&self, signal: &str) -> Result<(), SshError> {
        if !generation_is_current(&self.entry, self.generation) {
            return Err(SshError::Disconnected);
        }
        let signal = signal_from_name(signal)?;
        timeout(CHANNEL_REQUEST_TIMEOUT, self.channel.signal(signal))
            .await
            .map_err(|_| SshError::ChannelRequestTimeout)?
            .map_err(|_| SshError::Transport)
    }

    /// Request closure of the live remote channel without recreating it.
    pub async fn close(&self) -> Result<(), SshError> {
        if !generation_is_current(&self.entry, self.generation) {
            return Err(SshError::Disconnected);
        }
        self.channel.close().await
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionPhase {
    Connecting,
    Connected,
    Disconnected,
    Failed,
}

/// A stable, non-sensitive failure category. Raw remote and credential errors
/// never enter this status value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionFailure {
    Authentication,
    HostKeyUnknown,
    HostKeyChanged,
    HostKeyRevoked,
    HostKeyRejected,
    InteractionCancelled,
    InteractionUnavailable,
    Configuration,
    Algorithms,
    Proxy,
    Transport,
    CredentialStore,
}

/// A snapshot of one pooled effective connection identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionStatus {
    pub target_id: String,
    pub identity: Option<SshHostIdentity>,
    pub phase: ConnectionPhase,
    pub generation: u64,
    pub active_leases: usize,
    pub failure: Option<ConnectionFailure>,
}

#[derive(Clone)]
pub struct ConnectionManager {
    inner: Arc<ManagerInner>,
}

impl std::fmt::Debug for ConnectionManager {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConnectionManager")
            .finish_non_exhaustive()
    }
}

impl ConnectionManager {
    #[must_use]
    pub fn new(home: PathBuf) -> Self {
        Self {
            inner: Arc::new(ManagerInner {
                targets: TargetStore::new(home),
                credentials: CredentialStore,
                pool: Mutex::new(Pool::default()),
            }),
        }
    }

    /// The user-global target store consumed by this manager. No repository
    /// settings are involved in connection identity or credentials.
    #[must_use]
    pub fn targets(&self) -> &TargetStore {
        &self.inner.targets
    }

    /// Acquire a lease for the target's fully resolved effective identity.
    /// Concurrent callers of the same identity wait for one detached
    /// connect/authentication attempt; cancelling one waiter cannot cancel it.
    pub async fn acquire(
        &self,
        target_id: &str,
        interaction: Arc<dyn Interaction>,
    ) -> Result<ConnectionLease, SshError> {
        let plan = ConnectionPlan::resolve(&self.inner.targets, target_id)
            .map_err(|error| SshError::ConfigurationDiagnostic(error.into()))?;
        let key = PoolKey::from_plan(&plan);
        let entry = {
            let mut pool = lock(&self.inner.pool);
            let entry = pool
                .entries
                .entry(key.clone())
                .or_insert_with(|| Arc::new(ConnectionEntry::new()))
                .clone();
            pool.targets.insert(target_id.to_owned(), key);
            entry
        };

        let use_guard = EntryUse::new(Arc::clone(&entry));
        if let Some(generation) = entry.begin_connect() {
            let inner = Arc::clone(&self.inner);
            let entry_for_task = Arc::clone(&entry);
            tokio::spawn(async move {
                let result =
                    establish_connection(&inner, &entry_for_task, plan, interaction, generation)
                        .await;
                entry_for_task.complete(generation, result).await;
            });
        }

        let (generation, identity) = entry.wait_connected().await?;
        Ok(ConnectionLease {
            entry: Arc::clone(&entry),
            identity,
            target_id: target_id.to_owned(),
            generation,
            _use_guard: use_guard,
        })
    }

    /// Read the live transport phase without allocating a full status snapshot.
    #[must_use]
    pub fn phase(&self, target_id: &str) -> ConnectionPhase {
        let entry = {
            let pool = lock(&self.inner.pool);
            pool.targets
                .get(target_id)
                .and_then(|key| pool.entries.get(key))
                .cloned()
        };
        entry.map_or(ConnectionPhase::Disconnected, |entry| entry.phase())
    }

    /// Read a non-blocking snapshot. It does not expose remote diagnostics or
    /// authentication information.
    #[must_use]
    pub fn status(&self, target_id: &str) -> Option<ConnectionStatus> {
        let entry = {
            let pool = lock(&self.inner.pool);
            let key = pool.targets.get(target_id)?;
            Arc::clone(pool.entries.get(key)?)
        };
        Some(entry.status(target_id))
    }

    /// Force-close the target's current pooled connection. Existing leases are
    /// made stale; callers must explicitly acquire a new one. No operation is
    /// replayed by this method.
    pub async fn disconnect(&self, target_id: &str) -> Result<(), SshError> {
        let entry = {
            let pool = lock(&self.inner.pool);
            let Some(key) = pool.targets.get(target_id) else {
                return Ok(());
            };
            pool.entries.get(key).cloned()
        };
        if let Some(entry) = entry {
            entry.disconnect().await;
        }
        Ok(())
    }

    /// Invalidate one target's pooled connection and forget its current pool
    /// identity. Existing leases become stale and a future acquire resolves a
    /// fresh effective configuration instead of reusing old authority.
    pub async fn invalidate(&self, target_id: &str) -> Result<(), SshError> {
        let entry = {
            let mut pool = lock(&self.inner.pool);
            let Some(key) = pool.targets.remove(target_id) else {
                return Ok(());
            };
            pool.entries.get(&key).cloned()
        };
        if let Some(entry) = entry {
            entry.disconnect().await;
        }
        Ok(())
    }

    /// Re-resolve every target with a live pool association and invalidate only
    /// entries whose effective native connection identity changed or can no
    /// longer be resolved. This is the refresh path for externally edited SSH
    /// files; failures are invalidations so callers fail closed.
    pub async fn invalidate_changed_targets(&self) -> Vec<String> {
        let known_targets = {
            let pool = lock(&self.inner.pool);
            pool.targets
                .iter()
                .map(|(target_id, key)| (target_id.clone(), key.clone()))
                .collect::<Vec<_>>()
        };
        let mut invalidated = Vec::new();
        for (target_id, expected_key) in known_targets {
            let current_key = ConnectionPlan::resolve(&self.inner.targets, &target_id)
                .map(|plan| PoolKey::from_plan(&plan))
                .ok();
            if current_key.as_ref() == Some(&expected_key) {
                continue;
            }
            let removed = {
                let mut pool = lock(&self.inner.pool);
                if pool.targets.get(&target_id) != Some(&expected_key) {
                    None
                } else {
                    let key = pool
                        .targets
                        .remove(&target_id)
                        .expect("the matching target mapping is still present");
                    Some(pool.entries.get(&key).cloned())
                }
            };
            if let Some(entry) = removed {
                if let Some(entry) = entry {
                    entry.disconnect().await;
                }
                invalidated.push(target_id);
            }
        }
        invalidated
    }

    /// Delete all credential-store values associated with the target's current
    /// configured credential reference. A missing or unavailable platform store
    /// is reported safely; no file fallback is used.
    pub async fn forget_credential(&self, target_id: &str) -> Result<(), SshError> {
        let resolved = self
            .inner
            .targets
            .resolve(target_id)
            .map_err(|error| SshError::ConfigurationDiagnostic(error.into()))?;
        self.inner
            .credentials
            .forget(&credential_slot(&resolved.target, "password"))?;
        for (index, _) in resolved.identity_files.iter().enumerate() {
            self.inner.credentials.forget(&credential_slot(
                &resolved.target,
                &format!("private-key-passphrase-{index}"),
            ))?;
        }
        Ok(())
    }
}

/// A generation-bound handle on a shared native SSH connection. A lease cannot
/// silently migrate to a reconnect: an operation on a stale lease fails rather
/// than being replayed against a new remote state.
pub struct ConnectionLease {
    entry: Arc<ConnectionEntry>,
    identity: Arc<SshHostIdentity>,
    target_id: String,
    generation: u64,
    _use_guard: EntryUse,
}

impl std::fmt::Debug for ConnectionLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConnectionLease")
            .field("generation", &self.generation)
            .field("identity", &self.identity)
            .finish()
    }
}

impl ConnectionLease {
    #[must_use]
    pub fn identity(&self) -> &SshHostIdentity {
        &self.identity
    }

    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Start a real SSH `exec` channel. The returned stream retains its own
    /// pool use guard, so dropping this lease before the stream still cannot
    /// trigger idle cleanup underneath an active channel.
    pub async fn exec(&self, command: &str) -> Result<BoxedSshStream, SshError> {
        if self.entry.generation.load(Ordering::Acquire) != self.generation
            || self.entry.phase() != ConnectionPhase::Connected
        {
            return Err(SshError::Disconnected);
        }

        let mut transport_guard = self.entry.transport.lock().await;
        let Some(transport) = transport_guard.as_mut() else {
            return Err(SshError::Disconnected);
        };
        if self.entry.generation.load(Ordering::Acquire) != self.generation
            || transport.generation != self.generation
        {
            return Err(SshError::Disconnected);
        }
        if transport.handle.is_closed() {
            self.entry.mark_disconnected();
            return Err(SshError::Disconnected);
        }

        let channel = transport.handle.channel_open_session().await.map_err(|_| {
            self.entry.mark_disconnected();
            SshError::Disconnected
        })?;
        apply_send_environment(&channel, &transport.send_env)
            .await
            .map_err(|_| {
                self.entry.mark_disconnected();
                SshError::Disconnected
            })?;
        channel.exec(true, command).await.map_err(|_| {
            self.entry.mark_disconnected();
            SshError::Disconnected
        })?;
        let (stdout_reader, stdin_writer) = channel.split();
        drop(transport_guard);

        let (stream, stdout_writer) = tokio::io::duplex(64 * 1024);
        let exit = Arc::new(Mutex::new(ExecState {
            exit: ExecExit::Running,
            stderr_bytes: 0,
            stderr_truncated: false,
        }));
        spawn_exec_pump(stdout_reader, stdout_writer, Arc::clone(&exit));
        Ok(Box::pin(ExecStream {
            stdout: stream,
            stdin: stdin_writer.make_writer(),
            exit,
            _use_guard: EntryUse::new(Arc::clone(&self.entry)),
        }))
    }
    /// Open an SFTP subsystem on this connection. The returned session retains
    /// a pool guard until it is dropped.
    pub async fn open_sftp(&self) -> Result<SftpConnection, SshError> {
        let channel = open_sftp_channel(&self.entry, self.generation).await?;
        let (stream, use_guard) = channel.into_stream_and_guard();
        let session = timeout(
            CHANNEL_REQUEST_TIMEOUT,
            russh_sftp::client::SftpSession::new(stream),
        )
        .await
        .map_err(|_| SshError::ChannelRequestTimeout)?
        .map_err(|_| SshError::Transport)?;
        if !generation_is_current(&self.entry, self.generation) {
            return Err(SshError::Disconnected);
        }
        Ok(SftpConnection {
            session,
            atomic_replace: AsyncMutex::new(AtomicReplaceState::Uninitialized),
            entry: Arc::clone(&self.entry),
            generation: self.generation,
            _use_guard: use_guard,
        })
    }

    /// Start a raw SSH exec channel and stream its protocol events directly.
    /// The request is accepted before this method returns.
    pub async fn exec_command(&self, command: &str) -> Result<SshCommand, SshError> {
        let mut channel = open_session_channel(&self.entry, self.generation, true).await?;
        if let Err(error) = send_exec_request(&channel, command).await {
            let _ = channel.close().await;
            return Err(error);
        }
        let (pending, finished) = match await_command_acceptance(&mut channel).await {
            Ok(result) => result,
            Err(error) => {
                let _ = channel.close().await;
                return Err(error);
            }
        };
        if !generation_is_current(&self.entry, self.generation) {
            let _ = channel.close().await;
            return Err(SshError::Disconnected);
        }
        Ok(SshCommand {
            channel,
            entry: Arc::clone(&self.entry),
            generation: self.generation,
            pending,
            finished,
        })
    }

    /// Start one explicitly authorized root command without allocating a PTY.
    ///
    /// The command does not start until the supplied interaction grants the
    /// root-specific authorization gate. Sudo passwords are consumed only when
    /// the remote sudo process emits its unique prompt marker.
    pub async fn exec_sudo_command(
        &self,
        command: &str,
        cwd: &str,
        interaction: Arc<dyn SudoInteraction>,
    ) -> Result<SshCommand, SshError> {
        crate::sudo::exec_sudo_command(
            Arc::clone(&self.entry),
            self.generation,
            &self.target_id,
            &self.identity.username,
            command,
            cwd,
            interaction,
        )
        .await
    }
}

async fn open_sftp_channel(
    entry: &Arc<ConnectionEntry>,
    generation: u64,
) -> Result<ClosingChannel, SshError> {
    let mut channel = open_session_channel(entry, generation, false).await?;
    if let Err(error) = send_subsystem_request(&channel).await {
        let _ = channel.close().await;
        return Err(error);
    }
    if let Err(error) = await_subsystem_acceptance(&mut channel).await {
        let _ = channel.close().await;
        return Err(error);
    }
    if !generation_is_current(entry, generation) {
        let _ = channel.close().await;
        return Err(SshError::Disconnected);
    }
    Ok(channel)
}

pub(crate) async fn open_session_channel(
    entry: &Arc<ConnectionEntry>,
    generation: u64,
    send_environment: bool,
) -> Result<ClosingChannel, SshError> {
    if !generation_is_current(entry, generation) {
        return Err(SshError::Disconnected);
    }

    let mut transport_guard = entry.transport.lock().await;
    let Some(transport) = transport_guard.as_mut() else {
        return Err(SshError::Disconnected);
    };
    if entry.generation.load(Ordering::Acquire) != generation || transport.generation != generation
    {
        return Err(SshError::Disconnected);
    }
    if transport.handle.is_closed() {
        entry.mark_disconnected();
        return Err(SshError::Disconnected);
    }

    let channel = timeout(
        CHANNEL_REQUEST_TIMEOUT,
        transport.handle.channel_open_session(),
    )
    .await
    .map_err(|_| SshError::ChannelRequestTimeout)?
    .map_err(|_| SshError::Transport)?;
    let channel = ClosingChannel::new(channel, EntryUse::new(Arc::clone(entry)));
    let environment_result = if send_environment {
        timeout(
            CHANNEL_REQUEST_TIMEOUT,
            apply_send_environment(&channel, &transport.send_env),
        )
        .await
        .map_err(|_| SshError::ChannelRequestTimeout)?
    } else {
        Ok(())
    };
    drop(transport_guard);
    if let Err(error) = environment_result {
        let _ = channel.close().await;
        return Err(error);
    }
    if !generation_is_current(entry, generation) {
        let _ = channel.close().await;
        return Err(SshError::Disconnected);
    }
    Ok(channel)
}

async fn open_atomic_replace_session(
    entry: &Arc<ConnectionEntry>,
    generation: u64,
) -> Result<Option<SftpAtomicReplaceSession>, SshError> {
    let channel = open_sftp_channel(entry, generation).await?;
    let (stream, use_guard) = channel.into_stream_and_guard();
    let session = russh_sftp::client::RawSftpSession::new(stream);
    let version = timeout(CHANNEL_REQUEST_TIMEOUT, session.init())
        .await
        .map_err(|_| SshError::ChannelRequestTimeout)?
        .map_err(|_| SshError::Transport)?;
    if !generation_is_current(entry, generation) {
        return Err(SshError::Disconnected);
    }
    if version
        .extensions
        .get("posix-rename@openssh.com")
        .is_some_and(|version| version == "1")
    {
        Ok(Some(SftpAtomicReplaceSession {
            session,
            _use_guard: use_guard,
        }))
    } else {
        Ok(None)
    }
}

fn sftp_channel_error(error: SshError) -> russh_sftp::client::error::Error {
    match error {
        SshError::ChannelRequestTimeout => russh_sftp::client::error::Error::Timeout,
        SshError::Disconnected => russh_sftp::client::error::Error::UnexpectedBehavior(
            "the SSH connection was disconnected while opening SFTP".to_owned(),
        ),
        _ => russh_sftp::client::error::Error::UnexpectedBehavior(
            "the SSH transport could not open an SFTP channel".to_owned(),
        ),
    }
}

fn posix_rename_payload(from: &str, to: &str) -> Result<Vec<u8>, russh_sftp::client::error::Error> {
    let capacity = from
        .len()
        .checked_add(to.len())
        .and_then(|length| length.checked_add(8))
        .ok_or_else(|| {
            russh_sftp::client::error::Error::Limited(
                "atomic rename paths exceed the SFTP packet size".to_owned(),
            )
        })?;
    let mut payload = Vec::with_capacity(capacity);
    for path in [from, to] {
        let length = u32::try_from(path.len()).map_err(|_| {
            russh_sftp::client::error::Error::Limited(
                "an atomic rename path exceeds the SFTP packet size".to_owned(),
            )
        })?;
        payload.extend_from_slice(&length.to_be_bytes());
        payload.extend_from_slice(path.as_bytes());
    }
    Ok(payload)
}

async fn apply_send_environment(
    channel: &Channel<client::Msg>,
    patterns: &[String],
) -> Result<(), SshError> {
    let environment = std::env::vars_os()
        .filter_map(|(name, value)| Some((name.into_string().ok()?, value.into_string().ok()?)))
        .filter(|(name, _)| {
            patterns
                .iter()
                .any(|pattern| send_env_pattern_matches(pattern, name))
        })
        .collect::<Vec<_>>();
    for (name, value) in environment {
        channel
            .set_env(false, name, value)
            .await
            .map_err(|_| SshError::Transport)?;
    }
    Ok(())
}

pub(crate) fn generation_is_current(entry: &ConnectionEntry, generation: u64) -> bool {
    entry.generation.load(Ordering::Acquire) == generation
        && entry.phase() == ConnectionPhase::Connected
}

fn command_channel_closed(finished: bool) -> Result<Option<SshCommandEvent>, SshError> {
    if finished {
        Ok(None)
    } else {
        Err(SshError::Disconnected)
    }
}

fn command_event(
    message: ChannelMsg,
    finished: &mut bool,
) -> Result<Option<SshCommandEvent>, SshError> {
    match message {
        ChannelMsg::Data { data } => Ok(Some(SshCommandEvent::Stdout(data.to_vec()))),
        ChannelMsg::ExtendedData { data, .. } => Ok(Some(SshCommandEvent::Stderr(data.to_vec()))),
        ChannelMsg::ExitStatus { exit_status } => {
            *finished = true;
            Ok(Some(SshCommandEvent::ExitStatus(exit_status)))
        }
        ChannelMsg::ExitSignal { signal_name, .. } => {
            *finished = true;
            Ok(Some(SshCommandEvent::ExitSignal(signal_name_to_string(
                signal_name,
            ))))
        }
        ChannelMsg::Failure | ChannelMsg::OpenFailure(_) => Err(SshError::ChannelRequestRejected),
        // EOF closes stdout, not the command: an exit-status request may follow.
        ChannelMsg::Eof => Ok(None),
        ChannelMsg::Close => command_channel_closed(*finished),
        _ => Ok(None),
    }
}

pub(crate) fn queue_initial_command_event(
    pending: &mut VecDeque<SshCommandEvent>,
    pending_bytes: &mut usize,
    event: SshCommandEvent,
) -> Result<(), SshError> {
    let event_bytes = match &event {
        SshCommandEvent::Stdout(data) | SshCommandEvent::Stderr(data) => data.len(),
        SshCommandEvent::ExitStatus(_) | SshCommandEvent::ExitSignal(_) => 0,
    };
    if pending.len() >= MAX_INITIAL_COMMAND_EVENTS
        || *pending_bytes > MAX_INITIAL_COMMAND_BYTES.saturating_sub(event_bytes)
    {
        return Err(SshError::Transport);
    }
    *pending_bytes += event_bytes;
    pending.push_back(event);
    Ok(())
}

async fn await_subsystem_acceptance(channel: &mut Channel<client::Msg>) -> Result<(), SshError> {
    timeout(CHANNEL_REQUEST_TIMEOUT, async {
        loop {
            let Some(message) = channel.wait().await else {
                return Err(SshError::Disconnected);
            };
            match message {
                ChannelMsg::Success => return Ok(()),
                ChannelMsg::Failure | ChannelMsg::OpenFailure(_) => {
                    return Err(SshError::ChannelRequestRejected);
                }
                ChannelMsg::Eof | ChannelMsg::Close => return Err(SshError::Disconnected),
                ChannelMsg::WindowAdjusted { .. } | ChannelMsg::XonXoff { .. } => continue,
                _ => return Err(SshError::Transport),
            }
        }
    })
    .await
    .map_err(|_| SshError::ChannelRequestTimeout)?
}

pub(crate) async fn await_command_acceptance(
    channel: &mut Channel<client::Msg>,
) -> Result<(VecDeque<SshCommandEvent>, bool), SshError> {
    timeout(CHANNEL_REQUEST_TIMEOUT, async {
        let mut pending = VecDeque::new();
        let mut pending_bytes = 0;
        let mut finished = false;
        loop {
            let Some(message) = channel.wait().await else {
                return Err(SshError::Disconnected);
            };
            if matches!(&message, ChannelMsg::Success) {
                return Ok((pending, finished));
            }
            if let Some(event) = command_event(message, &mut finished)? {
                queue_initial_command_event(&mut pending, &mut pending_bytes, event)?;
            }
        }
    })
    .await
    .map_err(|_| SshError::ChannelRequestTimeout)?
}

async fn send_subsystem_request(channel: &Channel<client::Msg>) -> Result<(), SshError> {
    timeout(
        CHANNEL_REQUEST_TIMEOUT,
        channel.request_subsystem(true, "sftp"),
    )
    .await
    .map_err(|_| SshError::ChannelRequestTimeout)?
    .map_err(|_| SshError::Transport)
}

pub(crate) async fn send_exec_request(
    channel: &Channel<client::Msg>,
    command: &str,
) -> Result<(), SshError> {
    timeout(CHANNEL_REQUEST_TIMEOUT, channel.exec(true, command))
        .await
        .map_err(|_| SshError::ChannelRequestTimeout)?
        .map_err(|_| SshError::Transport)
}

async fn close_channel(channel: &Channel<client::Msg>) -> Result<(), SshError> {
    timeout(CHANNEL_REQUEST_TIMEOUT, channel.close())
        .await
        .map_err(|_| SshError::ChannelRequestTimeout)?
        .map_err(|_| SshError::Transport)
}

fn signal_from_name(signal: &str) -> Result<Sig, SshError> {
    let name = signal.strip_prefix("SIG").unwrap_or(signal);
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'+'))
    {
        return Err(SshError::InvalidSignal);
    }
    Ok(match name {
        "ABRT" => Sig::ABRT,
        "ALRM" => Sig::ALRM,
        "FPE" => Sig::FPE,
        "HUP" => Sig::HUP,
        "ILL" => Sig::ILL,
        "INT" => Sig::INT,
        "KILL" => Sig::KILL,
        "PIPE" => Sig::PIPE,
        "QUIT" => Sig::QUIT,
        "SEGV" => Sig::SEGV,
        "TERM" => Sig::TERM,
        "USR1" => Sig::USR1,
        _ => Sig::Custom(name.to_owned()),
    })
}

fn signal_name_to_string(signal: Sig) -> String {
    match signal {
        Sig::ABRT => "ABRT".to_owned(),
        Sig::ALRM => "ALRM".to_owned(),
        Sig::FPE => "FPE".to_owned(),
        Sig::HUP => "HUP".to_owned(),
        Sig::ILL => "ILL".to_owned(),
        Sig::INT => "INT".to_owned(),
        Sig::KILL => "KILL".to_owned(),
        Sig::PIPE => "PIPE".to_owned(),
        Sig::QUIT => "QUIT".to_owned(),
        Sig::SEGV => "SEGV".to_owned(),
        Sig::TERM => "TERM".to_owned(),
        Sig::USR1 => "USR1".to_owned(),
        Sig::Custom(name) => name,
    }
}

struct ManagerInner {
    targets: TargetStore,
    credentials: CredentialStore,
    pool: Mutex<Pool>,
}

#[derive(Default)]
struct Pool {
    entries: HashMap<PoolKey, Arc<ConnectionEntry>>,
    targets: HashMap<String, PoolKey>,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct PoolKey {
    final_target: ConnectionSecurityKey,
    jump_targets: Vec<ConnectionSecurityKey>,
}

#[derive(Clone)]
struct ConnectionPlan {
    final_config: ResolvedSshConfig,
    jump_configs: Vec<ResolvedSshConfig>,
}

impl ConnectionPlan {
    fn resolve(targets: &TargetStore, target_id: &str) -> Result<Self, crate::config::ConfigError> {
        let final_config = targets.resolve(target_id)?;
        let mut jump_configs = Vec::new();
        if let Some(ProxyRoute::Jump(hops)) = &final_config.proxy {
            for hop in hops {
                let mut hop_config = match targets.get(&hop.hostname)? {
                    Some(target) => targets.resolve(&target.id)?,
                    None => hop_config(&final_config, hop),
                };
                if let Some(username) = &hop.username {
                    hop_config.username = username.clone();
                }
                if let Some(port) = hop.port {
                    hop_config.port = port;
                }
                // The final target's explicit ProxyJump is the route plan.
                // Do not recursively apply a hop's own routing rule.
                hop_config.proxy = None;
                jump_configs.push(hop_config);
            }
        }
        Ok(Self {
            final_config,
            jump_configs,
        })
    }
}

impl PoolKey {
    fn from_plan(plan: &ConnectionPlan) -> Self {
        Self {
            final_target: ConnectionSecurityKey::from_config(&plan.final_config),
            jump_targets: plan
                .jump_configs
                .iter()
                .map(ConnectionSecurityKey::from_jump_config)
                .collect(),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct ConnectionSecurityKey {
    hostname: String,
    username: String,
    port: u16,
    credential_context: String,
    /// Worker argv participates in target reuse even though native transport
    /// authentication does not consume it. Reusing a live worker after an
    /// external argv edit would otherwise retain stale remote authority.
    worker_command: Vec<String>,
    identity_files: Vec<MaterialKey>,
    agent: AgentKey,
    known_hosts: KnownHostsKey,
    host_key_policy: u8,
    preferred_auth: Vec<u8>,
    proxy: RouteKey,
    send_env: Vec<String>,
    algorithms: AlgorithmsKey,
    connect_timeout_seconds: Option<u64>,
    server_alive: Option<(u64, u32, Option<bool>)>,
    resolved_sources: Vec<MaterialKey>,
}

impl ConnectionSecurityKey {
    fn from_config(config: &ResolvedSshConfig) -> Self {
        Self::from_effective_config(config, true)
    }

    fn from_jump_config(config: &ResolvedSshConfig) -> Self {
        Self::from_effective_config(config, false)
    }

    fn from_effective_config(config: &ResolvedSshConfig, include_send_env: bool) -> Self {
        let mut resolved_sources = config
            .provenance
            .fields
            .values()
            .map(|source| MaterialKey::from_path(source.path.clone()))
            .collect::<Vec<_>>();
        resolved_sources.sort();
        resolved_sources.dedup();

        Self {
            hostname: config.hostname.clone(),
            username: config.username.clone(),
            port: config.port,
            credential_context: config
                .target
                .credential_ref
                .clone()
                .unwrap_or_else(|| config.target.id.clone()),
            worker_command: config.target.worker_command.clone(),
            identity_files: config
                .identity_files
                .iter()
                .cloned()
                .map(MaterialKey::from_path)
                .collect(),
            agent: AgentKey {
                enabled: config.agent.enabled,
                socket: config.agent.socket.clone().or_else(|| {
                    if config.agent.enabled {
                        std::env::var_os("SSH_AUTH_SOCK").map(PathBuf::from)
                    } else {
                        None
                    }
                }),
                identities_only: config.agent.identities_only,
            },
            known_hosts: KnownHostsKey {
                user_files: config
                    .known_hosts
                    .user_files
                    .iter()
                    .cloned()
                    .map(MaterialKey::from_path)
                    .collect(),
                global_files: config
                    .known_hosts
                    .global_files
                    .iter()
                    .cloned()
                    .map(MaterialKey::from_path)
                    .collect(),
                hash_known_hosts: config.known_hosts.hash_known_hosts,
            },
            host_key_policy: host_key_policy_key(config.host_key_policy),
            preferred_auth: config
                .preferred_auth
                .iter()
                .map(|method| match method {
                    AuthMethod::PublicKey => 0,
                    AuthMethod::KeyboardInteractive => 1,
                    AuthMethod::Password => 2,
                })
                .collect(),
            proxy: RouteKey::from_proxy(config.proxy.as_ref()),
            algorithms: AlgorithmsKey::from_requirements(&config.algorithms),
            send_env: if include_send_env {
                config.send_env.clone()
            } else {
                Vec::new()
            },
            connect_timeout_seconds: config.connect_timeout.map(|setting| setting.seconds),
            server_alive: config.server_alive.as_ref().map(|keepalive| {
                (
                    keepalive.interval.seconds,
                    keepalive.count_max,
                    keepalive.tcp_keep_alive,
                )
            }),
            resolved_sources,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct MaterialKey {
    path: PathBuf,
    revision: FileRevision,
}

impl MaterialKey {
    fn from_path(path: PathBuf) -> Self {
        Self {
            revision: FileRevision::from_path(&path),
            path,
        }
    }
}

impl Ord for MaterialKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.path
            .cmp(&other.path)
            .then(self.revision.cmp(&other.revision))
    }
}

impl PartialOrd for MaterialKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
enum FileRevision {
    Missing,
    Contents([u8; 32]),
    Unavailable,
}

impl FileRevision {
    fn from_path(path: &Path) -> Self {
        let mut file = match fs::File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Self::Missing,
            Err(_) => return Self::Unavailable,
        };
        let mut hasher = Sha256::new();
        let mut buffer = Zeroizing::new([0_u8; 16 * 1024]);
        loop {
            let read = match file.read(&mut *buffer) {
                Ok(read) => read,
                Err(_) => return Self::Unavailable,
            };
            if read == 0 {
                return Self::Contents(hasher.finalize().into());
            }
            let Some(chunk) = buffer.get(..read) else {
                return Self::Unavailable;
            };
            hasher.update(chunk);
        }
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct AgentKey {
    enabled: bool,
    socket: Option<PathBuf>,
    identities_only: bool,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct KnownHostsKey {
    user_files: Vec<MaterialKey>,
    global_files: Vec<MaterialKey>,
    hash_known_hosts: Option<bool>,
}

#[derive(Clone, PartialEq, Eq, Hash)]
enum RouteKey {
    None,
    Jump(Vec<JumpKey>),
    Command(String),
}

impl RouteKey {
    fn from_proxy(proxy: Option<&ProxyRoute>) -> Self {
        match proxy {
            None => Self::None,
            Some(ProxyRoute::Command(command)) => Self::Command(command.clone()),
            Some(ProxyRoute::Jump(hops)) => Self::Jump(
                hops.iter()
                    .map(|hop| JumpKey {
                        hostname: hop.hostname.clone(),
                        username: hop.username.clone(),
                        port: hop.port,
                    })
                    .collect(),
            ),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct JumpKey {
    hostname: String,
    username: Option<String>,
    port: Option<u16>,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct AlgorithmsKey {
    host_key: Option<Vec<String>>,
    public_key: Option<Vec<String>>,
    kex: Option<Vec<String>>,
    ciphers: Option<Vec<String>>,
    macs: Option<Vec<String>>,
}

impl AlgorithmsKey {
    fn from_requirements(requirements: &AlgorithmRequirements) -> Self {
        Self {
            host_key: requirements.host_key.clone(),
            public_key: requirements.public_key.clone(),
            kex: requirements.kex.clone(),
            ciphers: requirements.ciphers.clone(),
            macs: requirements.macs.clone(),
        }
    }
}

fn host_key_policy_key(policy: crate::config::HostKeyPolicy) -> u8 {
    match policy {
        crate::config::HostKeyPolicy::Ask => 0,
        crate::config::HostKeyPolicy::AcceptNew => 1,
        crate::config::HostKeyPolicy::Require => 2,
        crate::config::HostKeyPolicy::Off => 3,
    }
}

pub(crate) struct ConnectionEntry {
    generation: AtomicU64,
    active_uses: AtomicUsize,
    cleanup_scheduled: AtomicBool,
    state: Mutex<EntryState>,
    ready: tokio::sync::Notify,
    transport: AsyncMutex<Option<Transport>>,
}

#[derive(Clone)]
enum EntryState {
    Disconnected,
    Connecting,
    Connected {
        identity: Arc<SshHostIdentity>,
    },
    Failed {
        failure: ConnectionFailure,
        error: SshError,
    },
}

impl ConnectionEntry {
    fn new() -> Self {
        Self {
            generation: AtomicU64::new(0),
            active_uses: AtomicUsize::new(0),
            cleanup_scheduled: AtomicBool::new(false),
            state: Mutex::new(EntryState::Disconnected),
            ready: tokio::sync::Notify::new(),
            transport: AsyncMutex::new(None),
        }
    }

    fn begin_connect(&self) -> Option<u64> {
        let mut state = lock(&self.state);
        match *state {
            EntryState::Connecting | EntryState::Connected { .. } => None,
            EntryState::Disconnected | EntryState::Failed { .. } => {
                *state = EntryState::Connecting;
                Some(self.generation.fetch_add(1, Ordering::AcqRel) + 1)
            }
        }
    }

    async fn complete(self: &Arc<Self>, generation: u64, result: Result<Transport, SshError>) {
        let mut connected = false;
        match result {
            Ok(mut transport) => {
                let mut transport_slot = self.transport.lock().await;
                let mut state = lock(&self.state);
                if self.generation.load(Ordering::Acquire) == generation
                    && matches!(*state, EntryState::Connecting)
                {
                    transport.generation = generation;
                    let identity = Arc::clone(&transport.identity);
                    *transport_slot = Some(transport);
                    *state = EntryState::Connected { identity };
                    connected = true;
                }
            }
            Err(error) => {
                let failure = failure_category(&error);
                let mut state = lock(&self.state);
                if self.generation.load(Ordering::Acquire) == generation
                    && matches!(*state, EntryState::Connecting)
                {
                    *state = EntryState::Failed { failure, error };
                }
            }
        }
        self.ready.notify_waiters();
        if connected && self.active_uses.load(Ordering::Acquire) == 0 {
            self.schedule_idle_disconnect();
        }
    }
    async fn wait_connected(&self) -> Result<(u64, Arc<SshHostIdentity>), SshError> {
        loop {
            let notified = self.ready.notified();
            let state = lock(&self.state).clone();
            match state {
                EntryState::Connected { identity } => {
                    return Ok((self.generation.load(Ordering::Acquire), identity));
                }
                EntryState::Failed { error, .. } => return Err(error),
                EntryState::Disconnected => return Err(SshError::Disconnected),
                EntryState::Connecting => notified.await,
            }
        }
    }

    fn phase(&self) -> ConnectionPhase {
        match *lock(&self.state) {
            EntryState::Connecting => ConnectionPhase::Connecting,
            EntryState::Connected { .. } => ConnectionPhase::Connected,
            EntryState::Disconnected => ConnectionPhase::Disconnected,
            EntryState::Failed { .. } => ConnectionPhase::Failed,
        }
    }

    fn status(&self, target_id: &str) -> ConnectionStatus {
        let state = lock(&self.state).clone();
        let (phase, identity, failure) = match state {
            EntryState::Connecting => (ConnectionPhase::Connecting, None, None),
            EntryState::Connected { identity } => {
                (ConnectionPhase::Connected, Some(identity), None)
            }
            EntryState::Disconnected => (ConnectionPhase::Disconnected, None, None),
            EntryState::Failed { failure, .. } => (ConnectionPhase::Failed, None, Some(failure)),
        };
        ConnectionStatus {
            target_id: target_id.to_owned(),
            identity: identity.map(|identity| (*identity).clone()),
            phase,
            generation: self.generation.load(Ordering::Acquire),
            active_leases: self.active_uses.load(Ordering::Acquire),
            failure,
        }
    }

    fn mark_disconnected(&self) -> u64 {
        let mut state = lock(&self.state);
        if matches!(
            *state,
            EntryState::Connected { .. } | EntryState::Connecting | EntryState::Failed { .. }
        ) {
            let generation = self.generation.fetch_add(1, Ordering::AcqRel) + 1;
            *state = EntryState::Disconnected;
            self.ready.notify_waiters();
            generation
        } else {
            self.generation.load(Ordering::Acquire)
        }
    }

    async fn disconnect(&self) {
        let invalidated_through = self.mark_disconnected();
        let mut transport = self.transport.lock().await;
        if transport
            .as_ref()
            .is_some_and(|transport| transport.generation < invalidated_through)
        {
            if let Some(transport) = transport.take() {
                let _ = transport
                    .handle
                    .disconnect(Disconnect::ByApplication, "closed by groky", "en")
                    .await;
            }
        }
    }

    fn release(self: &Arc<Self>) {
        if self.active_uses.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.schedule_idle_disconnect();
        }
    }

    fn schedule_idle_disconnect(self: &Arc<Self>) {
        if self.cleanup_scheduled.swap(true, Ordering::AcqRel) {
            return;
        }
        let entry = Arc::clone(self);
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                sleep(IDLE_DISCONNECT_AFTER).await;
                if entry.active_uses.load(Ordering::Acquire) == 0 {
                    entry.disconnect().await;
                }
                entry.cleanup_scheduled.store(false, Ordering::Release);
                if entry.active_uses.load(Ordering::Acquire) == 0
                    && entry.phase() == ConnectionPhase::Connected
                {
                    entry.schedule_idle_disconnect();
                }
            });
        } else {
            self.cleanup_scheduled.store(false, Ordering::Release);
        }
    }
}

struct EntryUse {
    entry: Arc<ConnectionEntry>,
}

impl EntryUse {
    fn new(entry: Arc<ConnectionEntry>) -> Self {
        entry.active_uses.fetch_add(1, Ordering::AcqRel);
        Self { entry }
    }
}

impl Drop for EntryUse {
    fn drop(&mut self) {
        self.entry.release();
    }
}

struct Transport {
    generation: u64,
    identity: Arc<SshHostIdentity>,
    send_env: Vec<String>,
    handle: client::Handle<ClientHandler>,
    // Each direct-tcpip stream depends on its previous hop. Retaining all
    // handles keeps a multi-hop ProxyJump chain alive for the final lease.
    _jump_handles: Vec<client::Handle<ClientHandler>>,
}

struct AuthenticatedHandle {
    handle: client::Handle<ClientHandler>,
    identity: Arc<SshHostIdentity>,
}

async fn establish_connection(
    inner: &Arc<ManagerInner>,
    entry: &Arc<ConnectionEntry>,
    plan: ConnectionPlan,
    interaction: Arc<dyn Interaction>,
    generation: u64,
) -> Result<Transport, SshError> {
    let ConnectionPlan {
        mut final_config,
        jump_configs,
    } = plan;
    let send_env = std::mem::take(&mut final_config.send_env);
    match final_config.proxy.as_ref() {
        None => {
            let authenticated = connect_direct(
                &final_config,
                &final_config.hostname,
                final_config.port,
                Arc::clone(&interaction),
                generation,
                Arc::downgrade(entry),
                &inner.credentials,
            )
            .await?;
            Ok(Transport {
                generation: 0,
                identity: authenticated.identity,
                send_env,
                handle: authenticated.handle,
                _jump_handles: Vec::new(),
            })
        }
        Some(ProxyRoute::Command(command)) => {
            let stream = ProxyCommandStream::spawn(command)?;
            let authenticated = connect_stream(
                &final_config,
                stream,
                Arc::clone(&interaction),
                generation,
                Arc::downgrade(entry),
                &inner.credentials,
            )
            .await?;
            Ok(Transport {
                generation: 0,
                identity: authenticated.identity,
                send_env,
                handle: authenticated.handle,
                _jump_handles: Vec::new(),
            })
        }
        Some(ProxyRoute::Jump(_)) => {
            connect_jump_chain(
                &final_config,
                jump_configs,
                interaction,
                generation,
                Arc::downgrade(entry),
                &inner.credentials,
                send_env,
            )
            .await
        }
    }
}

async fn connect_jump_chain(
    config: &ResolvedSshConfig,
    jump_configs: Vec<ResolvedSshConfig>,
    interaction: Arc<dyn Interaction>,
    generation: u64,
    final_entry: Weak<ConnectionEntry>,
    credentials: &CredentialStore,
    send_env: Vec<String>,
) -> Result<Transport, SshError> {
    let Some((first_config, remaining)) = jump_configs.split_first() else {
        return Err(SshError::Proxy);
    };
    let first = connect_direct(
        first_config,
        &first_config.hostname,
        first_config.port,
        Arc::clone(&interaction),
        generation,
        Weak::new(),
        credentials,
    )
    .await?;
    let mut jump_handles = vec![first.handle];

    for next_config in remaining {
        let stream = open_direct_stream(
            jump_handles.last_mut().ok_or(SshError::Proxy)?,
            &next_config.hostname,
            next_config.port,
        )
        .await?;
        let next = connect_stream(
            next_config,
            stream,
            Arc::clone(&interaction),
            generation,
            Weak::new(),
            credentials,
        )
        .await?;
        jump_handles.push(next.handle);
    }

    let stream = open_direct_stream(
        jump_handles.last_mut().ok_or(SshError::Proxy)?,
        &config.hostname,
        config.port,
    )
    .await?;
    let final_connection = connect_stream(
        config,
        stream,
        interaction,
        generation,
        final_entry,
        credentials,
    )
    .await?;
    Ok(Transport {
        generation: 0,
        identity: final_connection.identity,
        send_env,
        handle: final_connection.handle,
        _jump_handles: jump_handles,
    })
}

fn hop_config(config: &ResolvedSshConfig, hop: &crate::config::JumpHost) -> ResolvedSshConfig {
    let mut hop_config = config.clone();
    hop_config.hostname = hop.hostname.clone();
    if let Some(username) = &hop.username {
        hop_config.username = username.clone();
    }
    if let Some(port) = hop.port {
        hop_config.port = port;
    }
    hop_config.proxy = None;
    hop_config
}

async fn open_direct_stream(
    handle: &mut client::Handle<ClientHandler>,
    hostname: &str,
    port: u16,
) -> Result<ChannelStream<client::Msg>, SshError> {
    let channel = handle
        .channel_open_direct_tcpip(hostname, u32::from(port), "127.0.0.1", 0)
        .await
        .map_err(|_| SshError::Proxy)?;
    Ok(channel.into_stream())
}

async fn connect_direct(
    config: &ResolvedSshConfig,
    hostname: &str,
    port: u16,
    interaction: Arc<dyn Interaction>,
    generation: u64,
    entry: Weak<ConnectionEntry>,
    credentials: &CredentialStore,
) -> Result<AuthenticatedHandle, SshError> {
    let client_config = client_config(config)?;
    let (handler, attempt) = ClientHandler::new(config, interaction.clone(), generation, entry);
    let connect = client::connect(client_config, (hostname, port), handler);
    let mut handle = await_connect(config, connect)
        .await
        .map_err(|error| attempt.take_failure().unwrap_or(error))?;
    authenticate(&mut handle, config, interaction, generation, credentials).await?;
    let identity = attempt.take_identity().ok_or(SshError::Transport)?;
    Ok(AuthenticatedHandle { handle, identity })
}

async fn connect_stream<S>(
    config: &ResolvedSshConfig,
    stream: S,
    interaction: Arc<dyn Interaction>,
    generation: u64,
    entry: Weak<ConnectionEntry>,
    credentials: &CredentialStore,
) -> Result<AuthenticatedHandle, SshError>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let client_config = client_config(config)?;
    let (handler, attempt) = ClientHandler::new(config, interaction.clone(), generation, entry);
    let connect = client::connect_stream(client_config, stream, handler);
    let mut handle = await_connect(config, connect)
        .await
        .map_err(|error| attempt.take_failure().unwrap_or(error))?;
    authenticate(&mut handle, config, interaction, generation, credentials).await?;
    let identity = attempt.take_identity().ok_or(SshError::Transport)?;
    Ok(AuthenticatedHandle { handle, identity })
}

async fn await_connect<F>(
    config: &ResolvedSshConfig,
    connect: F,
) -> Result<client::Handle<ClientHandler>, SshError>
where
    F: Future<Output = Result<client::Handle<ClientHandler>, russh::Error>>,
{
    match config.connect_timeout {
        Some(timeout_setting) => timeout(Duration::from_secs(timeout_setting.seconds), connect)
            .await
            .map_err(|_| SshError::ConnectTimeout)?
            .map_err(|_| SshError::Transport),
        None => connect.await.map_err(|_| SshError::Transport),
    }
}

fn client_config(config: &ResolvedSshConfig) -> Result<Arc<client::Config>, SshError> {
    let preferred = preferred_algorithms(&config.algorithms)?;
    let mut client_config = client::Config {
        preferred,
        nodelay: true,
        ..Default::default()
    };
    if let Some(keepalive) = &config.server_alive {
        if keepalive.tcp_keep_alive.is_some() {
            return Err(unsupported_transport_setting(config, "TCPKeepAlive"));
        }
        if keepalive.interval.seconds > 0 {
            client_config.keepalive_interval =
                Some(Duration::from_secs(keepalive.interval.seconds));
            client_config.keepalive_max = keepalive.count_max as usize;
        }
    }
    Ok(Arc::new(client_config))
}

fn unsupported_transport_setting(config: &ResolvedSshConfig, directive: &str) -> SshError {
    let source = config.provenance.fields.get("server_alive");
    SshError::ConfigurationDiagnostic(ConfigurationDiagnostic {
        kind: ConfigurationDiagnosticKind::UnsupportedDirective,
        path: source.map(|source| source.path.clone()),
        line: source.map(|source| source.line),
        directive: Some(directive.to_owned()),
        target_id: Some(config.target.id.clone()),
        message: "the native SSH transport cannot apply this active setting".to_owned(),
    })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AlgorithmListModifier {
    Replace,
    Append,
    Remove,
    Prepend,
}

struct AlgorithmListOperation<'a> {
    modifier: AlgorithmListModifier,
    first: &'a str,
    rest: &'a [String],
}

impl AlgorithmListOperation<'_> {
    fn names(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.first).chain(self.rest.iter().map(String::as_str))
    }

    fn parse<T>(&self, parser: impl Fn(&str) -> Result<T, SshError>) -> Result<Vec<T>, SshError> {
        self.names().map(parser).collect()
    }
}

fn algorithm_list_operation(names: &[String]) -> Result<AlgorithmListOperation<'_>, SshError> {
    let Some((first, rest)) = names.split_first() else {
        return Err(SshError::UnsupportedAlgorithms);
    };
    let (modifier, first) = if let Some(first) = first.strip_prefix('+') {
        (AlgorithmListModifier::Append, first)
    } else if let Some(first) = first.strip_prefix('-') {
        (AlgorithmListModifier::Remove, first)
    } else if let Some(first) = first.strip_prefix('^') {
        (AlgorithmListModifier::Prepend, first)
    } else {
        (AlgorithmListModifier::Replace, first.as_str())
    };
    if first.is_empty() || rest.iter().any(|name| name.is_empty()) {
        return Err(SshError::UnsupportedAlgorithms);
    }
    Ok(AlgorithmListOperation {
        modifier,
        first,
        rest,
    })
}

fn append_unique<T: PartialEq>(values: &mut Vec<T>, additional: impl IntoIterator<Item = T>) {
    for value in additional {
        if !values.contains(&value) {
            values.push(value);
        }
    }
}

fn apply_algorithm_list<T>(
    defaults: &[T],
    names: &[String],
    parser: impl Fn(&str) -> Result<T, SshError>,
) -> Result<Vec<T>, SshError>
where
    T: AsRef<str> + Clone + PartialEq,
{
    let operation = algorithm_list_operation(names)?;
    match operation.modifier {
        AlgorithmListModifier::Replace => operation.parse(parser),
        AlgorithmListModifier::Append => {
            let mut values = defaults.to_vec();
            append_unique(&mut values, operation.parse(parser)?);
            Ok(values)
        }
        AlgorithmListModifier::Prepend => {
            let mut values = operation.parse(parser)?;
            append_unique(&mut values, defaults.iter().cloned());
            Ok(values)
        }
        AlgorithmListModifier::Remove => {
            let values = defaults
                .iter()
                .filter(|value| {
                    !operation
                        .names()
                        .any(|pattern| send_env_pattern_matches(pattern, value.as_ref()))
                })
                .cloned()
                .collect::<Vec<_>>();
            if values.is_empty() {
                return Err(SshError::UnsupportedAlgorithms);
            }
            Ok(values)
        }
    }
}

fn preferred_algorithms(requirements: &AlgorithmRequirements) -> Result<Preferred, SshError> {
    let mut preferred = Preferred::default();
    if let Some(names) = requirements
        .host_key
        .as_ref()
        .filter(|names| !names.is_empty())
    {
        preferred.key = Cow::Owned(apply_algorithm_list(
            preferred.key.as_ref(),
            names,
            |name| {
                name.parse::<Algorithm>()
                    .map_err(|_| SshError::UnsupportedAlgorithms)
            },
        )?);
    }
    if let Some(names) = requirements.kex.as_ref().filter(|names| !names.is_empty()) {
        let mut kex = apply_algorithm_list(preferred.kex.as_ref(), names, |name| {
            russh::kex::Name::try_from(name).map_err(|_| SshError::UnsupportedAlgorithms)
        })?;
        // Extension names are transport capabilities, not policy alternatives;
        // keep strict KEX and ext-info enabled alongside the configured KEX set.
        append_unique(
            &mut kex,
            [
                russh::kex::EXTENSION_SUPPORT_AS_CLIENT,
                russh::kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT,
            ],
        );
        preferred.kex = Cow::Owned(kex);
    }
    if let Some(names) = requirements
        .ciphers
        .as_ref()
        .filter(|names| !names.is_empty())
    {
        preferred.cipher = Cow::Owned(apply_algorithm_list(
            preferred.cipher.as_ref(),
            names,
            |name| russh::cipher::Name::try_from(name).map_err(|_| SshError::UnsupportedAlgorithms),
        )?);
    }
    if let Some(names) = requirements.macs.as_ref().filter(|names| !names.is_empty()) {
        preferred.mac = Cow::Owned(apply_algorithm_list(
            preferred.mac.as_ref(),
            names,
            |name| russh::mac::Name::try_from(name).map_err(|_| SshError::UnsupportedAlgorithms),
        )?);
    }
    // Public-key requirements are enforced before each identity is attempted;
    // russh's `Preferred::key` controls host-key negotiation, not only user
    // authentication, so substituting it here would widen host-key policy.
    if let Some(names) = requirements
        .public_key
        .as_ref()
        .filter(|names| !names.is_empty())
    {
        let operation = algorithm_list_operation(names)?;
        if operation.modifier != AlgorithmListModifier::Remove {
            let _ = operation.parse(|name| {
                name.parse::<Algorithm>()
                    .map_err(|_| SshError::UnsupportedAlgorithms)
            })?;
        }
    }
    Ok(preferred)
}

async fn authenticate(
    handle: &mut client::Handle<ClientHandler>,
    config: &ResolvedSshConfig,
    interaction: Arc<dyn Interaction>,
    generation: u64,
    credentials: &CredentialStore,
) -> Result<(), SshError> {
    for method in &config.preferred_auth {
        let authenticated = match method {
            AuthMethod::PublicKey => {
                authenticate_public_key(handle, config, &interaction, generation, credentials)
                    .await?
            }
            AuthMethod::KeyboardInteractive => {
                authenticate_keyboard_interactive(handle, config, &interaction, generation).await?
            }
            AuthMethod::Password => {
                authenticate_password(handle, config, &interaction, generation, credentials).await?
            }
        };
        if authenticated {
            return Ok(());
        }
    }
    Err(SshError::AuthenticationFailed)
}

async fn authenticate_public_key(
    handle: &mut client::Handle<ClientHandler>,
    config: &ResolvedSshConfig,
    interaction: &Arc<dyn Interaction>,
    generation: u64,
    credentials: &CredentialStore,
) -> Result<bool, SshError> {
    for (index, path) in config.identity_files.iter().enumerate() {
        let Some(key) =
            load_private_key(path, config, interaction, generation, credentials, index).await?
        else {
            continue;
        };
        if !public_key_allowed(&key.algorithm(), &config.algorithms)? {
            continue;
        }
        let hash_algorithm = handle
            .best_supported_rsa_hash()
            .await
            .map_err(|_| SshError::Transport)?
            .flatten();
        let result = handle
            .authenticate_publickey(
                config.username.clone(),
                PrivateKeyWithHashAlg::new(Arc::new(key), hash_algorithm),
            )
            .await
            .map_err(|_| SshError::Transport)?;
        if result.success() {
            return Ok(true);
        }
    }

    if config.agent.enabled {
        return authenticate_agent(handle, config).await;
    }
    Ok(false)
}

async fn load_private_key(
    path: &std::path::Path,
    config: &ResolvedSshConfig,
    interaction: &Arc<dyn Interaction>,
    generation: u64,
    credentials: &CredentialStore,
    index: usize,
) -> Result<Option<russh::keys::PrivateKey>, SshError> {
    match russh::keys::load_secret_key(path, None) {
        Ok(key) => Ok(Some(key)),
        Err(russh::keys::Error::KeyIsEncrypted) => {
            let slot = credential_slot(&config.target, &format!("private-key-passphrase-{index}"));
            let saved = credentials.load(&slot);
            let allow_remember = saved.is_ok();
            if let Ok(Some(secret)) = saved {
                if let Ok(passphrase) = secret.utf8() {
                    if let Ok(key) = russh::keys::load_secret_key(path, Some(passphrase.as_str())) {
                        return Ok(Some(key));
                    }
                }
            }

            let filename = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("SSH private key");
            let secret = interaction
                .request_secret(SecretPrompt {
                    challenge_id: Uuid::new_v4(),
                    connection_generation: generation,
                    target_id: config.target.id.clone(),
                    username: config.username.clone(),
                    kind: SecretKind::PrivateKeyPassphrase,
                    message: format!("Passphrase for {filename}"),
                    allow_remember,
                })
                .await?;
            let passphrase = secret.utf8()?;
            let key = russh::keys::load_secret_key(path, Some(passphrase.as_str()))
                .map_err(|_| SshError::PrivateKey)?;
            // Persist only after explicit user consent and successful local key
            // decryption; no data is ever written outside the platform store.
            if secret.should_remember() {
                credentials.save(&slot, &secret)?;
            }
            Ok(Some(key))
        }
        Err(_) => Ok(None),
    }
}

async fn authenticate_agent(
    handle: &mut client::Handle<ClientHandler>,
    config: &ResolvedSshConfig,
) -> Result<bool, SshError> {
    #[cfg(unix)]
    let agent_result = match &config.agent.socket {
        Some(path) => AgentClient::connect_uds(path).await,
        None => AgentClient::connect_env().await,
    };
    #[cfg(unix)]
    let mut agent = match agent_result {
        Ok(agent) => agent,
        Err(_) => return Ok(false),
    };

    #[cfg(windows)]
    let mut agent = match AgentClient::connect_pageant().await {
        Ok(agent) => agent,
        Err(_) => return Ok(false),
    };

    #[cfg(not(any(unix, windows)))]
    {
        let _ = (handle, config);
        return Ok(false);
    }

    #[cfg(any(unix, windows))]
    {
        let identities = match agent.request_identities().await {
            Ok(identities) => identities,
            Err(_) => return Ok(false),
        };
        for identity in identities {
            let public_key = identity.public_key().into_owned();
            if !public_key_allowed(&public_key.algorithm(), &config.algorithms)? {
                continue;
            }
            let hash_algorithm = handle
                .best_supported_rsa_hash()
                .await
                .map_err(|_| SshError::Transport)?
                .flatten();
            let result = match handle
                .authenticate_publickey_with(
                    config.username.clone(),
                    public_key,
                    hash_algorithm,
                    &mut agent,
                )
                .await
            {
                Ok(result) => result,
                Err(_) => return Ok(false),
            };
            if result.success() {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

fn public_key_allowed(
    algorithm: &Algorithm,
    requirements: &AlgorithmRequirements,
) -> Result<bool, SshError> {
    let Some(names) = requirements
        .public_key
        .as_ref()
        .filter(|names| !names.is_empty())
    else {
        return Ok(true);
    };
    let operation = algorithm_list_operation(names)?;
    match operation.modifier {
        AlgorithmListModifier::Replace => Ok(operation
            .parse(|name| {
                name.parse::<Algorithm>()
                    .map_err(|_| SshError::UnsupportedAlgorithms)
            })?
            .iter()
            .any(|allowed| match (allowed, algorithm) {
                (Algorithm::Rsa { .. }, Algorithm::Rsa { .. }) => true,
                _ => allowed == algorithm,
            })),
        AlgorithmListModifier::Append | AlgorithmListModifier::Prepend => {
            let _ = operation.parse(|name| {
                name.parse::<Algorithm>()
                    .map_err(|_| SshError::UnsupportedAlgorithms)
            })?;
            Ok(true)
        }
        AlgorithmListModifier::Remove => Ok(!operation
            .names()
            .any(|pattern| send_env_pattern_matches(pattern, algorithm.as_ref()))),
    }
}

async fn authenticate_password(
    handle: &mut client::Handle<ClientHandler>,
    config: &ResolvedSshConfig,
    interaction: &Arc<dyn Interaction>,
    generation: u64,
    credentials: &CredentialStore,
) -> Result<bool, SshError> {
    let slot = credential_slot(&config.target, "password");
    let saved = credentials.load(&slot);
    let allow_remember = saved.is_ok();
    if let Ok(Some(secret)) = saved {
        if let Ok(password) = secret.utf8() {
            let result = handle
                .authenticate_password(config.username.clone(), password.to_string())
                .await
                .map_err(|_| SshError::Transport)?;
            if result.success() {
                return Ok(true);
            }
        }
    }

    let secret = interaction
        .request_secret(SecretPrompt {
            challenge_id: Uuid::new_v4(),
            connection_generation: generation,
            target_id: config.target.id.clone(),
            username: config.username.clone(),
            kind: SecretKind::Password,
            message: "SSH password".to_owned(),
            allow_remember,
        })
        .await?;
    let remember = secret.should_remember();
    let password = secret.utf8()?;
    let result = handle
        .authenticate_password(config.username.clone(), password.to_string())
        .await
        .map_err(|_| SshError::Transport)?;
    if !result.success() {
        return Ok(false);
    }
    if remember {
        credentials.save(&slot, &secret)?;
    }
    Ok(true)
}

async fn authenticate_keyboard_interactive(
    handle: &mut client::Handle<ClientHandler>,
    config: &ResolvedSshConfig,
    interaction: &Arc<dyn Interaction>,
    generation: u64,
) -> Result<bool, SshError> {
    let mut reply = handle
        .authenticate_keyboard_interactive_start(config.username.clone(), None::<String>)
        .await
        .map_err(|_| SshError::Transport)?;

    loop {
        match reply {
            KeyboardInteractiveAuthResponse::Success => return Ok(true),
            KeyboardInteractiveAuthResponse::Failure { .. } => return Ok(false),
            KeyboardInteractiveAuthResponse::InfoRequest {
                name,
                instructions,
                prompts,
            } => {
                if prompts.is_empty() {
                    reply = handle
                        .authenticate_keyboard_interactive_respond(Vec::new())
                        .await
                        .map_err(|_| SshError::Transport)?;
                    continue;
                }
                let questions = prompts
                    .iter()
                    .map(|prompt| KeyboardInteractiveQuestion {
                        prompt: prompt.prompt.clone(),
                        echo: prompt.echo,
                    })
                    .collect::<Vec<_>>();
                let answers = interaction
                    .request_keyboard_interactive(KeyboardInteractivePrompt {
                        challenge_id: Uuid::new_v4(),
                        connection_generation: generation,
                        target_id: config.target.id.clone(),
                        username: config.username.clone(),
                        name,
                        instruction: instructions,
                        questions,
                    })
                    .await?;
                if answers.len() != prompts.len() {
                    return Err(SshError::Interaction(InteractionError::Rejected));
                }
                let mut values = Vec::with_capacity(answers.len());
                for answer in answers {
                    values.push(answer.utf8()?.to_string());
                }
                reply = handle
                    .authenticate_keyboard_interactive_respond(values)
                    .await
                    .map_err(|_| SshError::Transport)?;
            }
        }
    }
}

fn credential_slot(target: &SshTarget, purpose: &str) -> String {
    let base = target.credential_ref.as_deref().unwrap_or(&target.id);
    format!("{base}:{purpose}")
}

struct ClientHandler {
    target_id: String,
    hostname: String,
    port: u16,
    username: String,
    known_hosts: crate::config::KnownHostsConfig,
    policy: crate::config::HostKeyPolicy,
    interaction: Arc<dyn Interaction>,
    generation: u64,
    entry: Weak<ConnectionEntry>,
    attempt: ConnectionAttempt,
}

#[derive(Clone)]
struct ConnectionAttempt {
    failure: Arc<Mutex<Option<SshError>>>,
    identity: Arc<Mutex<Option<Arc<SshHostIdentity>>>>,
}

impl ClientHandler {
    fn new(
        config: &ResolvedSshConfig,
        interaction: Arc<dyn Interaction>,
        generation: u64,
        entry: Weak<ConnectionEntry>,
    ) -> (Self, ConnectionAttempt) {
        let attempt = ConnectionAttempt {
            failure: Arc::new(Mutex::new(None)),
            identity: Arc::new(Mutex::new(None)),
        };
        (
            Self {
                target_id: config.target.id.clone(),
                hostname: config.hostname.clone(),
                port: config.port,
                username: config.username.clone(),
                known_hosts: config.known_hosts.clone(),
                policy: config.host_key_policy,
                interaction,
                generation,
                entry,
                attempt: attempt.clone(),
            },
            attempt,
        )
    }

    fn record_failure(&self, error: SshError) {
        *lock(&self.attempt.failure) = Some(error);
    }
}

impl ConnectionAttempt {
    fn take_failure(&self) -> Option<SshError> {
        lock(&self.failure).take()
    }

    fn take_identity(&self) -> Option<Arc<SshHostIdentity>> {
        lock(&self.identity).take()
    }
}

impl Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        if server_public_key.certificate().is_some() {
            // A certificate requires CA validation; accepting it as a bare key
            // would bypass known_hosts policy. Fail closed until CA verification
            // is implemented by the resolver/backend pair.
            self.record_failure(SshError::UnsupportedAlgorithms);
            return Ok(false);
        }
        let public_key = server_public_key.public_key();
        match known_hosts::verify_or_prompt(
            &self.known_hosts,
            self.policy,
            &self.target_id,
            &self.hostname,
            self.port,
            self.generation,
            &public_key,
            &self.interaction,
        )
        .await
        {
            Ok(()) => {
                *lock(&self.attempt.identity) = Some(Arc::new(SshHostIdentity {
                    hostname: self.hostname.clone(),
                    port: self.port,
                    username: self.username.clone(),
                    fingerprint: known_hosts::fingerprint(&public_key),
                }));
                Ok(true)
            }
            Err(error) => {
                self.record_failure(error);
                Ok(false)
            }
        }
    }

    async fn disconnected(
        &mut self,
        _reason: client::DisconnectReason<Self::Error>,
    ) -> Result<(), Self::Error> {
        if let Some(entry) = self.entry.upgrade() {
            if entry.generation.load(Ordering::Acquire) == self.generation {
                entry.mark_disconnected();
            }
        }
        Ok(())
    }
}

const MAX_CAPTURED_STDERR: usize = 8 * 1024;

enum ExecExit {
    Running,
    Success,
    Failed(ExecFailure),
}

#[derive(Clone, Copy)]
enum ExecFailure {
    ExitStatus(u32),
    ExitSignal,
    RequestRejected,
    MissingExitStatus,
}

struct ExecState {
    exit: ExecExit,
    stderr_bytes: usize,
    stderr_truncated: bool,
}

impl ExecState {
    fn record_stderr(&mut self, data: &[u8]) {
        let remaining = MAX_CAPTURED_STDERR.saturating_sub(self.stderr_bytes);
        let captured = data.len().min(remaining);
        self.stderr_bytes += captured;
        self.stderr_truncated |= captured != data.len();
    }

    fn fail(&mut self, reason: ExecFailure) {
        if matches!(self.exit, ExecExit::Running | ExecExit::Success) {
            self.exit = ExecExit::Failed(reason);
        }
    }

    fn succeed(&mut self) {
        if matches!(self.exit, ExecExit::Running) {
            self.exit = ExecExit::Success;
        }
    }

    fn error(&self) -> Option<io::Error> {
        let ExecExit::Failed(reason) = self.exit else {
            return None;
        };
        let reason = match reason {
            ExecFailure::ExitStatus(status) => {
                format!("remote SSH command exited with status {status}")
            }
            ExecFailure::ExitSignal => "remote SSH command exited after a signal".to_owned(),
            ExecFailure::RequestRejected => {
                "remote SSH server rejected the exec request".to_owned()
            }
            ExecFailure::MissingExitStatus => {
                "remote SSH command closed without reporting an exit status".to_owned()
            }
        };
        let diagnostics = if self.stderr_bytes == 0 {
            "no SSH stderr diagnostics were received".to_owned()
        } else if self.stderr_truncated {
            "SSH stderr diagnostics were discarded outside the protocol stream (truncated)"
                .to_owned()
        } else {
            "SSH stderr diagnostics were discarded outside the protocol stream".to_owned()
        };
        Some(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            format!("{reason}; {diagnostics}"),
        ))
    }
}

struct ExecStream<W> {
    stdout: DuplexStream,
    stdin: W,
    exit: Arc<Mutex<ExecState>>,
    _use_guard: EntryUse,
}

impl<W: Unpin> AsyncRead for ExecStream<W> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let filled_before = buffer.filled().len();
        let this = self.as_mut().get_mut();
        match Pin::new(&mut this.stdout).poll_read(context, buffer) {
            std::task::Poll::Ready(Ok(())) if buffer.filled().len() == filled_before => {
                match lock(&this.exit).error() {
                    Some(error) => std::task::Poll::Ready(Err(error)),
                    None => std::task::Poll::Ready(Ok(())),
                }
            }
            result => result,
        }
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for ExecStream<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        buffer: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        if let Some(error) = lock(&self.exit).error() {
            return std::task::Poll::Ready(Err(error));
        }
        Pin::new(&mut self.stdin).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        Pin::new(&mut self.stdin).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        Pin::new(&mut self.stdin).poll_shutdown(context)
    }
}

fn spawn_exec_pump(
    mut reader: ChannelReadHalf,
    mut stdout: DuplexStream,
    exit: Arc<Mutex<ExecState>>,
) {
    tokio::spawn(async move {
        let mut observed_exit_status = false;
        while let Some(message) = reader.wait().await {
            match message {
                ChannelMsg::Data { data } => {
                    if stdout.write_all(&data).await.is_err() {
                        break;
                    }
                }
                ChannelMsg::ExtendedData { data, .. } => lock(&exit).record_stderr(&data),
                ChannelMsg::ExitStatus { exit_status } => {
                    observed_exit_status = true;
                    if exit_status == 0 {
                        lock(&exit).succeed();
                    } else {
                        lock(&exit).fail(ExecFailure::ExitStatus(exit_status));
                    }
                }
                ChannelMsg::ExitSignal { .. } => {
                    observed_exit_status = true;
                    lock(&exit).fail(ExecFailure::ExitSignal);
                }
                ChannelMsg::Failure | ChannelMsg::OpenFailure(_) => {
                    lock(&exit).fail(ExecFailure::RequestRejected);
                }
                ChannelMsg::Close => break,
                ChannelMsg::Eof
                | ChannelMsg::Open { .. }
                | ChannelMsg::RequestPty { .. }
                | ChannelMsg::RequestShell { .. }
                | ChannelMsg::Exec { .. }
                | ChannelMsg::RequestSubsystem { .. }
                | ChannelMsg::RequestX11 { .. }
                | ChannelMsg::SetEnv { .. }
                | ChannelMsg::WindowChange { .. }
                | ChannelMsg::AgentForward { .. }
                | ChannelMsg::XonXoff { .. }
                | ChannelMsg::WindowAdjusted { .. }
                | ChannelMsg::Success => {}
                _ => {}
            }
        }
        if !observed_exit_status {
            lock(&exit).fail(ExecFailure::MissingExitStatus);
        }
    });
}

struct ProxyCommandStream {
    child: Child,
    stdout: ChildStdout,
    stdin: ChildStdin,
}

impl ProxyCommandStream {
    fn spawn(command: &str) -> Result<Self, SshError> {
        #[cfg(windows)]
        let mut child = Command::new("cmd")
            .args(["/C", command])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| SshError::Proxy)?;
        #[cfg(not(windows))]
        let mut child = Command::new("sh")
            .args(["-c", command])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| SshError::Proxy)?;
        let stdout = child.stdout.take().ok_or(SshError::Proxy)?;
        let stdin = child.stdin.take().ok_or(SshError::Proxy)?;
        Ok(Self {
            child,
            stdout,
            stdin,
        })
    }
}

impl Drop for ProxyCommandStream {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

impl AsyncRead for ProxyCommandStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        Pin::new(&mut self.stdout).poll_read(context, buffer)
    }
}

impl AsyncWrite for ProxyCommandStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        buffer: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        Pin::new(&mut self.stdin).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        Pin::new(&mut self.stdin).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        Pin::new(&mut self.stdin).poll_shutdown(context)
    }
}

fn failure_category(error: &SshError) -> ConnectionFailure {
    match error {
        SshError::AuthenticationFailed
        | SshError::AgentAuthenticationFailed
        | SshError::PrivateKey => ConnectionFailure::Authentication,
        SshError::UnknownHostKey => ConnectionFailure::HostKeyUnknown,
        SshError::ChangedHostKey | SshError::HostKeyReplacement(_) => {
            ConnectionFailure::HostKeyChanged
        }
        SshError::RevokedHostKey => ConnectionFailure::HostKeyRevoked,
        SshError::HostKeyRejected => ConnectionFailure::HostKeyRejected,
        SshError::Interaction(InteractionError::Cancelled) => {
            ConnectionFailure::InteractionCancelled
        }
        SshError::Interaction(InteractionError::Unavailable) => {
            ConnectionFailure::InteractionUnavailable
        }
        SshError::Configuration | SshError::ConfigurationDiagnostic(_) => {
            ConnectionFailure::Configuration
        }
        SshError::UnsupportedAlgorithms => ConnectionFailure::Algorithms,
        SshError::Proxy => ConnectionFailure::Proxy,
        SshError::CredentialStoreUnavailable => ConnectionFailure::CredentialStore,
        _ => ConnectionFailure::Transport,
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::{
        ConnectionEntry, ConnectionFailure, ConnectionManager, ConnectionPhase,
        ConnectionPlan, ConnectionSecurityKey, EntryState, FileRevision,
        MAX_INITIAL_COMMAND_BYTES, MAX_INITIAL_COMMAND_EVENTS, MaterialKey,
        PoolKey, SshCommandEvent, command_event, failure_category, lock,
        posix_rename_payload, preferred_algorithms, queue_initial_command_event,
    };
    use crate::auth::SshError;
    use crate::config::{
        AgentConfig, AlgorithmRequirements, AuthMethod, ConfigValueSource, HostKeyPolicy,
        KnownHostsConfig, ResolvedConfigProvenance, ResolvedSshConfig, SshConfigSource, SshTarget,
    };
    use russh::ChannelMsg;
    use std::collections::VecDeque;
    use std::fs;
    use std::sync::Arc;
    use std::sync::atomic::Ordering;
    use tempfile::tempdir;
    use xai_grok_workspace_types::ssh::SshHostIdentity;

    fn config(
        identity_file: std::path::PathBuf,
        known_hosts_file: std::path::PathBuf,
    ) -> ResolvedSshConfig {
        let mut target = SshTarget::new("example.test");
        target.id = "example-target".to_owned();
        ResolvedSshConfig {
            target,
            hostname: "example.test".to_owned(),
            username: "alice".to_owned(),
            port: 22,
            identity_files: vec![identity_file],
            agent: AgentConfig {
                enabled: false,
                socket: None,
                identities_only: false,
            },
            known_hosts: KnownHostsConfig {
                user_files: vec![known_hosts_file],
                global_files: Vec::new(),
                hash_known_hosts: None,
            },
            host_key_policy: HostKeyPolicy::Require,
            preferred_auth: vec![AuthMethod::PublicKey],
            send_env: Vec::new(),
            proxy: None,
            connect_timeout: None,
            server_alive: None,
            algorithms: AlgorithmRequirements::default(),
            provenance: ResolvedConfigProvenance::default(),
        }
    }

    fn identity(fingerprint: &str) -> Arc<SshHostIdentity> {
        Arc::new(SshHostIdentity {
            hostname: "example.test".to_owned(),
            port: 22,
            username: "alice".to_owned(),
            fingerprint: fingerprint.to_owned(),
        })
    }

    #[test]
    fn reconnect_replaces_the_generation_owned_host_identity() {
        let entry = ConnectionEntry::new();
        entry.generation.store(1, Ordering::Release);
        *lock(&entry.state) = EntryState::Connected {
            identity: identity("SHA256:first"),
        };

        entry.generation.store(2, Ordering::Release);
        *lock(&entry.state) = EntryState::Connected {
            identity: identity("SHA256:second"),
        };

        let status = entry.status("example-target");
        assert_eq!(status.generation, 2);
        assert_eq!(
            status
                .identity
                .as_ref()
                .map(|identity| identity.fingerprint.as_str()),
            Some("SHA256:second")
        );
    }

    #[test]
    fn pool_identity_changes_when_key_trust_or_effective_config_changes() {
        let directory = tempdir().expect("temporary directory");
        let identity_file = directory.path().join("identity");
        let known_hosts_file = directory.path().join("known_hosts");
        let ssh_config_file = directory.path().join("config");
        fs::write(&identity_file, b"private-key-one").expect("identity fixture");
        fs::write(&known_hosts_file, b"example.test key-one").expect("known-hosts fixture");
        fs::write(
            &ssh_config_file,
            b"Host example.test\n  ProxyJump bastion\n",
        )
        .expect("SSH config fixture");

        let mut resolved = config(identity_file.clone(), known_hosts_file.clone());
        resolved.provenance.fields.insert(
            "proxy".to_owned(),
            ConfigValueSource {
                source: SshConfigSource::UserSsh,
                path: ssh_config_file.clone(),
                line: 2,
            },
        );
        let initial = ConnectionSecurityKey::from_config(&resolved);

        fs::write(&identity_file, b"private-key-two").expect("identity update");
        let after_key_change = ConnectionSecurityKey::from_config(&resolved);
        assert!(initial != after_key_change);

        fs::write(&known_hosts_file, b"example.test key-two").expect("known-hosts update");
        let after_trust_change = ConnectionSecurityKey::from_config(&resolved);
        assert!(after_key_change != after_trust_change);

        fs::write(
            &ssh_config_file,
            b"Host example.test\n  ProxyJump replacement\n",
        )
        .expect("SSH config update");
        let after_config_change = ConnectionSecurityKey::from_config(&resolved);
        assert!(after_trust_change != after_config_change);

        resolved.send_env.push("LANG".to_owned());
        let after_send_env_change = ConnectionSecurityKey::from_config(&resolved);
        assert!(after_config_change != after_send_env_change);

        resolved.target.worker_command.push("--updated".to_owned());
        let after_worker_command_change = ConnectionSecurityKey::from_config(&resolved);
        assert!(after_send_env_change != after_worker_command_change);
    }

    #[tokio::test]
    async fn external_target_change_invalidates_existing_pool_association() {
        let directory = tempdir().expect("temporary directory");
        fs::write(
            directory.path().join("config.toml"),
            "[ssh.targets.target]\nhost = \"first.example.test\"\n",
        )
        .expect("target fixture");
        let manager = ConnectionManager::new(directory.path().to_owned());
        let plan = ConnectionPlan::resolve(&manager.inner.targets, "target")
            .expect("resolve target");
        let key = PoolKey::from_plan(&plan);
        let entry = Arc::new(ConnectionEntry::new());
        entry.generation.store(1, Ordering::Release);
        *lock(&entry.state) = EntryState::Connected {
            identity: identity("SHA256:first"),
        };
        {
            let mut pool = lock(&manager.inner.pool);
            pool.targets.insert("target".to_owned(), key.clone());
            pool.entries.insert(key, Arc::clone(&entry));
        }

        fs::write(
            directory.path().join("config.toml"),
            "[ssh.targets.target]\nhost = \"second.example.test\"\n",
        )
        .expect("external target update");

        assert_eq!(
            manager.invalidate_changed_targets().await,
            vec!["target".to_owned()]
        );
        assert_eq!(entry.phase(), ConnectionPhase::Disconnected);
        assert_eq!(entry.generation.load(Ordering::Acquire), 2);
        assert!(!lock(&manager.inner.pool).targets.contains_key("target"));
    }

    #[test]
    fn prepended_open_ssh_algorithms_retain_native_fallbacks() {
        let requirements = AlgorithmRequirements {
            ciphers: Some(vec![
                "^aes128-gcm@openssh.com".to_owned(),
                "aes256-gcm@openssh.com".to_owned(),
            ]),
            kex: Some(vec!["^ecdh-sha2-nistp256".to_owned()]),
            macs: Some(vec![
                "^hmac-sha2-256-etm@openssh.com".to_owned(),
                "hmac-sha2-256".to_owned(),
            ]),
            ..AlgorithmRequirements::default()
        };

        let preferred = preferred_algorithms(&requirements).expect("apply algorithm modifiers");
        let ciphers = preferred
            .cipher
            .iter()
            .map(|name| name.as_ref())
            .collect::<Vec<_>>();
        let kex = preferred
            .kex
            .iter()
            .map(|name| name.as_ref())
            .collect::<Vec<_>>();
        let macs = preferred
            .mac
            .iter()
            .map(|name| name.as_ref())
            .collect::<Vec<_>>();

        assert_eq!(ciphers.first(), Some(&"aes128-gcm@openssh.com"));
        assert!(ciphers.contains(&"chacha20-poly1305@openssh.com"));
        assert_eq!(kex.first(), Some(&"ecdh-sha2-nistp256"));
        assert!(kex.contains(&"curve25519-sha256"));
        assert_eq!(macs.first(), Some(&"hmac-sha2-256-etm@openssh.com"));
        assert!(macs.contains(&"hmac-sha2-512-etm@openssh.com"));
    }

    #[tokio::test]
    async fn pooled_failure_preserves_host_key_replacement_detail() {
        let entry = ConnectionEntry::new();
        let error = SshError::HostKeyReplacement(
            "known_hosts changed while confirmation was pending".to_owned(),
        );
        *lock(&entry.state) = EntryState::Failed {
            failure: failure_category(&error),
            error,
        };

        let observed = entry
            .wait_connected()
            .await
            .expect_err("pooled failure must preserve its SSH error");
        assert_eq!(
            failure_category(&observed),
            ConnectionFailure::HostKeyChanged
        );
        assert_eq!(
            observed.to_string(),
            "SSH host key replacement could not be completed safely: known_hosts changed while confirmation was pending"
        );
    }
    #[test]
    fn file_revisions_record_missing_material() {
        let directory = tempdir().expect("temporary directory");
        let missing = MaterialKey::from_path(directory.path().join("missing"));
        assert!(matches!(missing.revision, FileRevision::Missing));
    }

    #[test]
    fn raw_command_closing_without_exit_is_disconnected() {
        let mut finished = false;
        assert!(matches!(
            command_event(ChannelMsg::Close, &mut finished),
            Err(SshError::Disconnected)
        ));
        assert!(!finished);
    }

    #[test]
    fn raw_command_exit_status_is_a_terminal_event() {
        let mut finished = false;
        let event = command_event(ChannelMsg::ExitStatus { exit_status: 23 }, &mut finished)
            .expect("exit status is a valid command event");
        assert_eq!(event, Some(SshCommandEvent::ExitStatus(23)));
        assert!(finished);
    }

    #[test]
    fn raw_command_queues_initial_exit_status_before_following_close() {
        let mut finished = false;
        let mut pending = VecDeque::new();
        let mut pending_bytes = 0;
        let event = command_event(ChannelMsg::ExitStatus { exit_status: 0 }, &mut finished)
            .expect("exit status is a valid command event")
            .expect("exit status must be delivered");
        queue_initial_command_event(&mut pending, &mut pending_bytes, event)
            .expect("terminal event fits the initial queue");

        assert_eq!(pending.pop_front(), Some(SshCommandEvent::ExitStatus(0)));
        assert_eq!(
            command_event(ChannelMsg::Close, &mut finished).unwrap(),
            None
        );
    }

    #[test]
    fn posix_rename_payload_encodes_two_sftp_strings() {
        assert_eq!(
            posix_rename_payload("/tmp/new", "/tmp/old").unwrap(),
            b"\0\0\0\x08/tmp/new\0\0\0\x08/tmp/old".to_vec()
        );
    }

    #[test]
    fn raw_command_stdout_eof_can_precede_exit_status() {
        let mut finished = false;
        assert_eq!(command_event(ChannelMsg::Eof, &mut finished).unwrap(), None);
        assert!(!finished);
        assert_eq!(
            command_event(ChannelMsg::ExitStatus { exit_status: 7 }, &mut finished).unwrap(),
            Some(SshCommandEvent::ExitStatus(7)),
        );
        assert_eq!(
            command_event(ChannelMsg::Close, &mut finished).unwrap(),
            None
        );
    }

    #[test]
    fn raw_command_preacceptance_buffer_is_bounded() {
        let mut pending = VecDeque::new();
        let mut pending_bytes = 0;
        for _ in 0..MAX_INITIAL_COMMAND_EVENTS {
            queue_initial_command_event(
                &mut pending,
                &mut pending_bytes,
                SshCommandEvent::ExitStatus(0),
            )
            .expect("event is within the bounded queue");
        }
        assert!(matches!(
            queue_initial_command_event(
                &mut pending,
                &mut pending_bytes,
                SshCommandEvent::ExitStatus(0),
            ),
            Err(SshError::Transport)
        ));
    }

    #[test]
    fn raw_command_preacceptance_bytes_are_bounded() {
        let mut pending = VecDeque::new();
        let mut pending_bytes = 0;
        queue_initial_command_event(
            &mut pending,
            &mut pending_bytes,
            SshCommandEvent::Stdout(vec![0; MAX_INITIAL_COMMAND_BYTES]),
        )
        .expect("event fills the bounded byte budget");
        assert!(matches!(
            queue_initial_command_event(
                &mut pending,
                &mut pending_bytes,
                SshCommandEvent::Stdout(vec![0]),
            ),
            Err(SshError::Transport)
        ));
    }
}
