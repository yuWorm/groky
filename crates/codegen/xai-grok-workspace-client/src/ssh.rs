//! Authenticated, multiplexed client for the SSH workspace worker.
//!
//! The SSH transport supplies peer authentication. This client adds a bounded
//! structured protocol, request correlation, reconnect bind/resume, worker-lifetime
//! mutation lookup, and callback delivery for progress and approvals.

use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::{Mutex, RwLock, oneshot};
use xai_grok_workspace_types::rpc::WorkspaceRpc;
use xai_grok_workspace_types::ssh::{ResolvedSshInvocation, SshBinding};
#[cfg(test)]
use xai_grok_workspace_types::ssh_wire::local_worker_build_info;
use xai_grok_workspace_types::ssh_wire::{
    SSH_WIRE_MAX_FRAME_BYTES, SSH_WIRE_PROTOCOL_VERSION, SshApprovalDecision, SshApprovalRequest,
    SshCancellation, SshClientHello, SshMutationId, SshOperationId, SshOperationRecord,
    SshResumeToken, SshTaskRecord, SshWireError, SshWireFrame, SshWorkerCapabilities,
    SshWorkerEvent, SshWorkerHello, SshWorkerReply, SshWorkerRequest, SshWorkerResponse,
    local_worker_product_version,
};

/// Native SSH's concrete erased stream type, reused directly to preserve the
/// transport's single allocation and trait-object boundary.
pub use xai_grok_ssh::{BoxedSshStream as BoxSshStream, SshStream};

type SshReader = ReadHalf<BoxSshStream>;
type SshWriter = WriteHalf<BoxSshStream>;

/// Client-side asynchronous hooks. Approval defaults to deny, so unwired
/// callers cannot accidentally make a remote mutation.
#[async_trait]
pub trait SshClientCallbacks: Send + Sync + 'static {
    async fn on_event(&self, _event: SshWorkerEvent) {}

    async fn approve(&self, _request: SshApprovalRequest) -> SshApprovalDecision {
        SshApprovalDecision::Deny
    }
}

/// Fail-closed callback implementation for clients that only issue reads.
#[derive(Debug, Default)]
pub struct DenySshApprovals;
#[async_trait]
impl SshClientCallbacks for DenySshApprovals {}

/// SSH worker client failures. A mutation transport failure must be resolved
/// through [`SshWorkspaceClient::mutation`] rather than replayed.
#[derive(Debug, thiserror::Error)]
pub enum SshClientError {
    #[error("SSH worker transport closed")]
    Closed,
    #[error("SSH worker I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("SSH worker frame serialization failed: {0}")]
    Encode(#[from] serde_json::Error),
    #[error("SSH worker handshake failed: {0}")]
    Handshake(String),
    #[error("SSH worker protocol error: {0}")]
    Protocol(String),
    #[error("SSH worker rejected request: {0:?}")]
    Remote(SshWireError),
    #[error("SSH worker returned an unexpected response")]
    UnexpectedResponse,
}

/// Result of a raw workspace RPC or complete tool stream.
pub struct SshCallResult {
    pub operation: SshOperationRecord,
    pub value: Value,
}

/// Lookup outcome after a mutation's reply was interrupted.
///
/// [`Self::Unknown`] means the current worker has no record for the supplied
/// mutation id, including after a worker restart. It is never a signal to replay.
#[derive(Debug, Clone, PartialEq)]
pub enum SshMutationStatus {
    Known(SshOperationRecord),
    Unknown,
}

/// Confirmation that the current worker received an authorization revocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshRevokeAck {
    pub binding_id: String,
    pub epoch: u64,
}

#[derive(Clone)]
pub struct SshWorkspaceClient {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for SshWorkspaceClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshWorkspaceClient")
            .field("connected", &self.is_connected())
            .field("worker_id", &self.inner.hello.worker_id)
            .finish_non_exhaustive()
    }
}

struct Inner {
    writer: Mutex<SshWriter>,
    pending: Mutex<HashMap<String, oneshot::Sender<Result<SshWorkerResponse, SshClientError>>>>,
    callbacks: Arc<dyn SshClientCallbacks>,
    binding: RwLock<SshBinding>,
    hello: SshWorkerHello,
    connected: AtomicBool,
    next_request: AtomicU64,
}

impl SshWorkspaceClient {
    /// Complete the protocol handshake over an already authenticated stream.
    /// The worker independently validates the supplied binding before it sends
    /// a hello, so a successful transport connection is never authorization.
    pub async fn connect(
        stream: BoxSshStream,
        binding: SshBinding,
        callbacks: Arc<dyn SshClientCallbacks>,
    ) -> Result<Self, SshClientError> {
        Self::connect_with_mode(stream, binding, None, callbacks, false).await
    }

    /// Reconnect a former bridge using its opaque worker-issued resume token.
    pub async fn connect_with_resume(
        stream: BoxSshStream,
        binding: SshBinding,
        resume_token: Option<SshResumeToken>,
        callbacks: Arc<dyn SshClientCallbacks>,
    ) -> Result<Self, SshClientError> {
        Self::connect_with_mode(stream, binding, resume_token, callbacks, false).await
    }

    /// Acknowledge a persisted local revocation after reconnecting. This opens
    /// no workspace and never turns the old binding active: the worker admits
    /// only a revoked tombstone, then records the epoch idempotently.
    pub async fn revoke_tombstone(
        stream: BoxSshStream,
        binding: SshBinding,
    ) -> Result<SshRevokeAck, SshClientError> {
        if !binding.revoked {
            return Err(SshClientError::Protocol(
                "revocation tombstone requires a locally revoked binding".into(),
            ));
        }
        let binding_id = binding.id.clone();
        let epoch = binding.epoch;
        let client =
            Self::connect_with_mode(stream, binding, None, Arc::new(DenySshApprovals), true)
                .await?;
        client.revoke(&binding_id, epoch).await
    }

    async fn connect_with_mode(
        stream: BoxSshStream,
        binding: SshBinding,
        resume_token: Option<SshResumeToken>,
        callbacks: Arc<dyn SshClientCallbacks>,
        revocation_only: bool,
    ) -> Result<Self, SshClientError> {
        let (mut reader, mut writer) = tokio::io::split(stream);
        let expected_product_version = if revocation_only {
            None
        } else {
            local_worker_product_version()
        };
        let hello = SshWireFrame::ClientHello(SshClientHello {
            protocol_version: SSH_WIRE_PROTOCOL_VERSION,
            expected_product_version: expected_product_version.map(str::to_owned),
            client_id: format!("ssh-client-{}", next_id()),
            binding: binding.clone(),
            resume_token,
            revocation_only,
        });
        write_frame(&mut writer, &hello).await.map_err(|error| {
            SshClientError::Handshake(format!(
                "could not send hello to the remote worker ({error}); verify the remote command is `groky worker --stdio`"
            ))
        })?;
        let frame = read_frame(&mut reader).await.map_err(|error| {
            SshClientError::Handshake(format!(
                "remote command did not return a worker hello ({error}); verify a compatible `groky worker --stdio` is installed remotely"
            ))
        })?;
        let hello = match frame {
            Some(SshWireFrame::WorkerHello(hello)) => hello,
            Some(SshWireFrame::HandshakeError(error)) => {
                return Err(SshClientError::Handshake(format!(
                    "remote worker rejected the binding ({}): {}",
                    error.code, error.message
                )));
            }
            Some(_) => {
                return Err(SshClientError::Handshake(
                    "remote command did not speak the SSH worker protocol; verify it runs `groky worker --stdio` and keeps stderr separate from stdout"
                        .into(),
                ));
            }
            None => {
                return Err(SshClientError::Handshake(
                    "remote worker exited before handshake; verify `groky worker --stdio` exists and has a compatible version"
                        .into(),
                ));
            }
        };
        if hello.protocol_version != SSH_WIRE_PROTOCOL_VERSION {
            return Err(SshClientError::Protocol(format!(
                "protocol version mismatch: client={}, worker={}",
                SSH_WIRE_PROTOCOL_VERSION, hello.protocol_version
            )));
        }
        if !revocation_only && hello.product_version.as_deref() != expected_product_version {
            return Err(SshClientError::Protocol(format!(
                "product release mismatch: client={}, worker={}",
                expected_product_version.unwrap_or("development"),
                hello.product_version.as_deref().unwrap_or("development")
            )));
        }
        if hello.binding.id != binding.id
            || hello.binding.session_id != binding.session_id
            || hello.binding.epoch != binding.epoch
        {
            return Err(SshClientError::Protocol(
                "worker hello binding does not match requested binding".into(),
            ));
        }
        if revocation_only && !hello.binding.revoked {
            return Err(SshClientError::Protocol(
                "revocation-only worker hello unexpectedly admitted an active binding".into(),
            ));
        }
        if hello.capabilities != SshWorkerCapabilities::complete() {
            return Err(SshClientError::Protocol(
                "worker does not implement the required SSH workspace capabilities".into(),
            ));
        }
        if hello.root != hello.binding.root {
            return Err(SshClientError::Protocol(
                "worker hello root does not match its canonical binding root".into(),
            ));
        }
        let expected_path_semantics = if hello.os == "windows" {
            xai_grok_workspace_types::ssh_wire::SshPathSemantics::Windows
        } else {
            xai_grok_workspace_types::ssh_wire::SshPathSemantics::Posix
        };
        if hello.path_semantics != expected_path_semantics {
            return Err(SshClientError::Protocol(
                "worker hello OS and path semantics disagree".into(),
            ));
        }
        let inner = Arc::new(Inner {
            writer: Mutex::new(writer),
            pending: Mutex::new(HashMap::new()),
            callbacks,
            binding: RwLock::new(hello.binding.clone()),
            hello,
            connected: AtomicBool::new(true),
            next_request: AtomicU64::new(1),
        });
        let client = Self { inner };
        tokio::spawn(read_loop(reader, client.clone()));
        Ok(client)
    }

    /// Worker identity and path semantics negotiated at handshake time.
    pub fn worker_hello(&self) -> &SshWorkerHello {
        &self.inner.hello
    }

    /// Last worker-acknowledged binding.
    pub async fn binding(&self) -> SshBinding {
        self.inner.binding.read().await.clone()
    }

    /// Resolve a path through the worker's canonical root and reject paths
    /// outside that root. Use the returned value when creating a later binding.
    pub async fn canonicalize_root(&self, path: &str) -> Result<String, SshClientError> {
        let binding = self.binding().await;
        let response = self
            .request(SshWorkerRequest::Canonicalize {
                request_id: self.request_id(),
                binding_id: binding.id,
                path: path.to_owned(),
            })
            .await?;
        let SshWorkerResponse::CanonicalPath(path) = response else {
            return Err(SshClientError::UnexpectedResponse);
        };
        Ok(path)
    }

    pub fn is_connected(&self) -> bool {
        self.inner.connected.load(Ordering::Acquire)
    }

    /// Bind a different granted root/session on an existing authenticated bridge.
    pub async fn bind(&self, binding: SshBinding) -> Result<SshResumeToken, SshClientError> {
        let response = self
            .request(SshWorkerRequest::Bind {
                request_id: self.request_id(),
                binding,
            })
            .await?;
        let SshWorkerResponse::Bound {
            binding,
            resume_token,
        } = response
        else {
            return Err(SshClientError::UnexpectedResponse);
        };
        *self.inner.binding.write().await = binding;
        Ok(resume_token)
    }

    /// Resume a binding only when both its worker token and current binding
    /// authority verify. The returned token replaces the prior one.
    pub async fn resume(
        &self,
        binding: SshBinding,
        resume_token: SshResumeToken,
    ) -> Result<SshResumeToken, SshClientError> {
        let response = self
            .request(SshWorkerRequest::Resume {
                request_id: self.request_id(),
                binding,
                resume_token,
            })
            .await?;
        let SshWorkerResponse::Bound {
            binding,
            resume_token,
        } = response
        else {
            return Err(SshClientError::UnexpectedResponse);
        };
        *self.inner.binding.write().await = binding;
        Ok(resume_token)
    }

    /// Advance the worker's authorization epoch. A result means the remote
    /// worker acknowledged it; a transport error deliberately does not.
    pub async fn revoke(
        &self,
        binding_id: &str,
        epoch: u64,
    ) -> Result<SshRevokeAck, SshClientError> {
        let response = self
            .request(SshWorkerRequest::Revoke {
                request_id: self.request_id(),
                binding_id: binding_id.to_owned(),
                epoch,
            })
            .await?;
        let SshWorkerResponse::Revoked { binding_id, epoch } = response else {
            return Err(SshClientError::UnexpectedResponse);
        };
        Ok(SshRevokeAck { binding_id, epoch })
    }

    /// Dispatch a typed-or-raw existing `workspace.*` RPC remotely. The
    /// invocation is immutable and is checked by the worker before dispatch.
    pub async fn rpc_raw(
        &self,
        invocation: ResolvedSshInvocation,
        method: &str,
        params: Value,
        mutation_id: Option<SshMutationId>,
    ) -> Result<SshCallResult, SshClientError> {
        let response = self
            .request(SshWorkerRequest::Rpc {
                request_id: self.request_id(),
                invocation,
                method: method.to_owned(),
                params,
                mutation_id,
            })
            .await?;
        let SshWorkerResponse::Rpc { operation, value } = response else {
            return Err(SshClientError::UnexpectedResponse);
        };
        Ok(SshCallResult { operation, value })
    }

    /// Typed sibling of [`Self::rpc_raw`]. The request determines its existing
    /// `workspace.*` method and response type; authorization still comes only
    /// from the immutable SSH invocation.
    pub async fn rpc<R: WorkspaceRpc>(
        &self,
        invocation: ResolvedSshInvocation,
        request: &R,
        mutation_id: Option<SshMutationId>,
    ) -> Result<R::Response, SshClientError> {
        let params = serde_json::to_value(request)?;
        let result = self
            .rpc_raw(invocation, R::METHOD, params, mutation_id)
            .await?;
        serde_json::from_value(result.value).map_err(SshClientError::Encode)
    }

    /// Execute one normal registered workspace tool and retain all streaming
    /// progress through [`SshClientCallbacks::on_event`].
    pub async fn call_tool(
        &self,
        invocation: ResolvedSshInvocation,
        tool_name: &str,
        args: Value,
        mutation_id: Option<SshMutationId>,
    ) -> Result<SshCallResult, SshClientError> {
        let response = self
            .request(SshWorkerRequest::ToolCall {
                request_id: self.request_id(),
                invocation,
                tool_name: tool_name.to_owned(),
                args,
                mutation_id,
            })
            .await?;
        let SshWorkerResponse::Tool { operation, value } = response else {
            return Err(SshClientError::UnexpectedResponse);
        };
        Ok(SshCallResult { operation, value })
    }

    /// Find an operation retained by this worker without crossing binding/session authority.
    pub async fn operation(
        &self,
        binding_id: &str,
        session_id: &str,
        operation_id: &str,
    ) -> Result<Option<SshOperationRecord>, SshClientError> {
        let response = self
            .request(SshWorkerRequest::Operation {
                request_id: self.request_id(),
                binding_id: binding_id.to_owned(),
                session_id: session_id.to_owned(),
                operation_id: operation_id.to_owned(),
            })
            .await?;
        let SshWorkerResponse::Operation(operation) = response else {
            return Err(SshClientError::UnexpectedResponse);
        };
        Ok(operation)
    }

    /// Look up a mutation after disconnect. The client must not replay a
    /// mutation based on an absent reply; it can only inspect this result.
    pub async fn mutation(
        &self,
        binding_id: &str,
        session_id: &str,
        mutation_id: &str,
    ) -> Result<Option<SshOperationRecord>, SshClientError> {
        let response = self
            .request(SshWorkerRequest::Mutation {
                request_id: self.request_id(),
                binding_id: binding_id.to_owned(),
                session_id: session_id.to_owned(),
                mutation_id: mutation_id.to_owned(),
            })
            .await?;
        let SshWorkerResponse::Operation(operation) = response else {
            return Err(SshClientError::UnexpectedResponse);
        };
        Ok(operation)
    }

    /// Query a mutation after a disconnected reply without replaying it.
    /// A missing record is explicitly `Unknown`; callers must surface that
    /// uncertainty rather than issue the mutation again.
    pub async fn mutation_status(
        &self,
        binding_id: &str,
        session_id: &str,
        mutation_id: &str,
    ) -> Result<SshMutationStatus, SshClientError> {
        Ok(
            match self.mutation(binding_id, session_id, mutation_id).await? {
                Some(operation) => SshMutationStatus::Known(operation),
                None => SshMutationStatus::Unknown,
            },
        )
    }

    /// List only tasks owned by the supplied binding/session pair.
    pub async fn tasks(
        &self,
        binding_id: &str,
        session_id: &str,
    ) -> Result<Vec<SshTaskRecord>, SshClientError> {
        let response = self
            .request(SshWorkerRequest::Tasks {
                request_id: self.request_id(),
                binding_id: binding_id.to_owned(),
                session_id: session_id.to_owned(),
            })
            .await?;
        let SshWorkerResponse::Tasks(tasks) = response else {
            return Err(SshClientError::UnexpectedResponse);
        };
        Ok(tasks)
    }

    /// Request a cancellation without tearing down the shared transport.
    ///
    /// An operation result may be [`SshCancellation::OperationPending`], which
    /// is not proof that a side effect stopped. A task result is returned only
    /// after the remote terminal manager acknowledges its termination.
    pub async fn cancel(
        &self,
        invocation: ResolvedSshInvocation,
        reference: SshOperationId,
    ) -> Result<SshCancellation, SshClientError> {
        let response = self
            .request(SshWorkerRequest::Cancel {
                request_id: self.request_id(),
                invocation,
                operation_id: reference,
            })
            .await?;
        let SshWorkerResponse::CancellationRequested(cancellation) = response else {
            return Err(SshClientError::UnexpectedResponse);
        };
        Ok(cancellation)
    }

    async fn approve(
        &self,
        request: &SshApprovalRequest,
        decision: SshApprovalDecision,
    ) -> Result<(), SshClientError> {
        let response = self
            .request(SshWorkerRequest::Approval {
                request_id: self.request_id(),
                approval_id: request.approval_id.clone(),
                binding_id: request.binding_id.clone(),
                session_id: request.session_id.clone(),
                decision,
            })
            .await?;
        if matches!(response, SshWorkerResponse::ApprovalRecorded) {
            Ok(())
        } else {
            Err(SshClientError::UnexpectedResponse)
        }
    }

    fn request_id(&self) -> String {
        format!(
            "ssh-{}",
            self.inner.next_request.fetch_add(1, Ordering::Relaxed)
        )
    }

    async fn request(
        &self,
        request: SshWorkerRequest,
    ) -> Result<SshWorkerResponse, SshClientError> {
        let request_id = request_id(&request).to_owned();
        let (tx, rx) = oneshot::channel();
        {
            // Pair the last connected check with registration. The read loop
            // drains this same map on EOF, so no sender can be inserted after
            // cleanup and wait forever for a reply.
            let mut pending = self.inner.pending.lock().await;
            if !self.is_connected() {
                return Err(SshClientError::Closed);
            }
            pending.insert(request_id.clone(), tx);
        }
        let write_result = {
            let mut writer = self.inner.writer.lock().await;
            write_frame(&mut *writer, &SshWireFrame::Request(request)).await
        };
        if let Err(error) = write_result {
            close_pending(&self.inner).await;
            return Err(error);
        }
        rx.await.map_err(|_| SshClientError::Closed)?
    }
}

async fn read_loop(mut reader: SshReader, client: SshWorkspaceClient) {
    loop {
        let frame = match read_frame(&mut reader).await {
            Ok(Some(frame)) => frame,
            Ok(None) | Err(_) => break,
        };
        match frame {
            SshWireFrame::Reply(reply) => deliver_reply(&client.inner, reply).await,
            SshWireFrame::Event(event) => deliver_event(client.clone(), event),
            SshWireFrame::ClientHello(_)
            | SshWireFrame::WorkerHello(_)
            | SshWireFrame::HandshakeError(_)
            | SshWireFrame::Request(_) => {
                client.inner.connected.store(false, Ordering::Release);
                break;
            }
        }
    }
    close_pending(&client.inner).await;
}

async fn deliver_reply(inner: &Inner, reply: SshWorkerReply) {
    let Some(sender) = inner.pending.lock().await.remove(&reply.request_id) else {
        return;
    };
    let result = reply.result.map_err(SshClientError::Remote);
    let _ = sender.send(result);
}

fn deliver_event(client: SshWorkspaceClient, event: SshWorkerEvent) {
    let callbacks = Arc::clone(&client.inner.callbacks);
    tokio::spawn(async move {
        callbacks.on_event(event.clone()).await;
        if let SshWorkerEvent::ApprovalRequired(request) = event {
            let decision = callbacks.approve(request.clone()).await;
            let _ = client.approve(&request, decision).await;
        }
    });
}

async fn close_pending(inner: &Inner) {
    inner.connected.store(false, Ordering::Release);
    let pending = std::mem::take(&mut *inner.pending.lock().await);
    for (_, sender) in pending {
        let _ = sender.send(Err(SshClientError::Closed));
    }
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

fn next_id() -> u64 {
    static NEXT_ID: AtomicU64 = AtomicU64::new(1);
    NEXT_ID.fetch_add(1, Ordering::Relaxed)
}

/// Write one length-prefixed, bounded JSON frame.
pub async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    frame: &SshWireFrame,
) -> Result<(), SshClientError> {
    let encoded = serde_json::to_vec(frame)?;
    if encoded.len() > SSH_WIRE_MAX_FRAME_BYTES {
        return Err(SshClientError::Protocol(
            "outbound frame exceeds size limit".into(),
        ));
    }
    let len = u32::try_from(encoded.len())
        .map_err(|_| SshClientError::Protocol("outbound frame length overflow".into()))?;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(&encoded).await?;
    writer.flush().await?;
    Ok(())
}

/// Read one bounded JSON frame. A clean EOF before a frame is `Ok(None)`.
pub async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Option<SshWireFrame>, SshClientError> {
    let mut length = [0_u8; 4];
    match reader.read_exact(&mut length).await {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error.into()),
    }
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > SSH_WIRE_MAX_FRAME_BYTES {
        return Err(SshClientError::Protocol(
            "invalid inbound frame size".into(),
        ));
    }
    let mut encoded = vec![0_u8; length];
    reader.read_exact(&mut encoded).await?;
    serde_json::from_slice(&encoded)
        .map(Some)
        .map_err(SshClientError::Encode)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn codec_round_trips_bounded_frame() {
        let (mut writer, mut reader) = duplex(1024);
        let frame = SshWireFrame::Request(SshWorkerRequest::Ping {
            request_id: "r".into(),
        });
        let write = tokio::spawn(async move { write_frame(&mut writer, &frame).await });
        let decoded = read_frame(&mut reader)
            .await
            .expect("frame")
            .expect("not EOF");
        write.await.expect("join").expect("write");
        assert!(matches!(
            decoded,
            SshWireFrame::Request(SshWorkerRequest::Ping { .. })
        ));
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
            root: "/tmp".into(),
            cwd: "/tmp".into(),
            capabilities: xai_grok_workspace_types::ssh::SshCapabilities::all(),
            epoch: 1,
            revoked: false,
        }
    }

    #[tokio::test]
    async fn missing_worker_handshake_is_actionable() {
        let (stream, peer) = duplex(1024);
        drop(peer);
        let stream: BoxSshStream = Box::pin(stream);
        let error = SshWorkspaceClient::connect(stream, test_binding(), Arc::new(DenySshApprovals))
            .await
            .expect_err("closed worker bridge must fail");
        assert!(matches!(
            error,
            SshClientError::Handshake(message) if message.contains("groky worker --stdio")
        ));
    }

    #[tokio::test]
    async fn worker_admission_failure_is_actionable() {
        let (stream, mut worker) = duplex(1024);
        let worker_task = tokio::spawn(async move {
            let _ = read_frame(&mut worker)
                .await
                .expect("read client hello")
                .expect("client hello frame");
            write_frame(
                &mut worker,
                &SshWireFrame::HandshakeError(SshWireError::new(
                    "session_setup_failed",
                    "remote workspace cannot initialize its tool registry",
                )),
            )
            .await
            .expect("write handshake error");
        });
        let stream: BoxSshStream = Box::pin(stream);
        let error = SshWorkspaceClient::connect(stream, test_binding(), Arc::new(DenySshApprovals))
            .await
            .expect_err("rejected worker binding must fail");
        assert!(matches!(
            error,
            SshClientError::Handshake(message)
                if message.contains("session_setup_failed")
                    && message.contains("tool registry")
        ));
        worker_task.await.expect("worker task");
    }

    #[tokio::test]
    async fn normal_worker_release_mismatch_is_rejected() {
        let (stream, mut worker) = duplex(4096);
        let binding = test_binding();
        let worker_binding = binding.clone();
        let product_version = match local_worker_build_info().product_version {
            Some(version) => Some(format!("{version}-mismatch")),
            None => Some("test-release".into()),
        };
        let worker_task = tokio::spawn(async move {
            let _ = read_frame(&mut worker)
                .await
                .expect("read client hello")
                .expect("client hello frame");
            write_frame(
                &mut worker,
                &SshWireFrame::WorkerHello(SshWorkerHello {
                    protocol_version: SSH_WIRE_PROTOCOL_VERSION,
                    product_version,
                    worker_id: "worker".into(),
                    os: std::env::consts::OS.into(),
                    path_semantics: if cfg!(windows) {
                        xai_grok_workspace_types::ssh_wire::SshPathSemantics::Windows
                    } else {
                        xai_grok_workspace_types::ssh_wire::SshPathSemantics::Posix
                    },
                    capabilities: SshWorkerCapabilities::complete(),
                    root: worker_binding.root.clone(),
                    binding: worker_binding,
                    resume_token: "resume".into(),
                }),
            )
            .await
            .expect("write worker hello");
        });
        let error =
            SshWorkspaceClient::connect(Box::pin(stream), binding, Arc::new(DenySshApprovals))
                .await
                .expect_err("mismatched worker release must be rejected");
        assert!(matches!(
            error,
            SshClientError::Protocol(message) if message.contains("product release mismatch")
        ));
        worker_task.await.expect("worker task");
    }

    #[tokio::test]
    async fn revocation_tombstone_works_with_a_protocol_one_worker() {
        use tokio::io::AsyncReadExt;

        let (stream, mut worker) = duplex(4096);
        let mut binding = test_binding();
        binding.revoked = true;
        binding.epoch = 2;
        let worker_binding = binding.clone();
        let worker_task = tokio::spawn(async move {
            let mut length = [0_u8; 4];
            worker
                .read_exact(&mut length)
                .await
                .expect("read protocol-one hello frame length");
            let mut bytes = vec![0_u8; u32::from_be_bytes(length) as usize];
            worker
                .read_exact(&mut bytes)
                .await
                .expect("read protocol-one hello frame");
            let hello: serde_json::Value =
                serde_json::from_slice(&bytes).expect("decode protocol-one hello");
            assert_eq!(hello["type"], "client_hello");
            assert!(
                hello["data"].get("expected_product_version").is_none(),
                "tombstones must omit release expectation for protocol-one workers"
            );
            write_frame(
                &mut worker,
                &SshWireFrame::WorkerHello(SshWorkerHello {
                    protocol_version: SSH_WIRE_PROTOCOL_VERSION,
                    product_version: None,
                    worker_id: "protocol-one-worker".into(),
                    os: std::env::consts::OS.into(),
                    path_semantics: if cfg!(windows) {
                        xai_grok_workspace_types::ssh_wire::SshPathSemantics::Windows
                    } else {
                        xai_grok_workspace_types::ssh_wire::SshPathSemantics::Posix
                    },
                    capabilities: SshWorkerCapabilities::complete(),
                    root: worker_binding.root.clone(),
                    binding: worker_binding.clone(),
                    resume_token: "resume".into(),
                }),
            )
            .await
            .expect("write protocol-one worker hello");
            let request = read_frame(&mut worker)
                .await
                .expect("read tombstone acknowledgement")
                .expect("tombstone acknowledgement frame");
            let SshWireFrame::Request(SshWorkerRequest::Revoke {
                request_id,
                binding_id,
                epoch,
            }) = request
            else {
                panic!("protocol-one worker must receive a tombstone revoke");
            };
            assert_eq!(binding_id, worker_binding.id);
            assert_eq!(epoch, worker_binding.epoch);
            write_frame(
                &mut worker,
                &SshWireFrame::Reply(SshWorkerReply {
                    request_id,
                    result: Ok(SshWorkerResponse::Revoked { binding_id, epoch }),
                }),
            )
            .await
            .expect("write tombstone acknowledgement");
        });
        let acknowledged = SshWorkspaceClient::revoke_tombstone(Box::pin(stream), binding.clone())
            .await
            .expect("protocol-one worker acknowledges tombstone");
        assert_eq!(acknowledged.binding_id, binding.id);
        assert_eq!(acknowledged.epoch, binding.epoch);
        worker_task.await.expect("worker task");
    }

    #[tokio::test]
    async fn disconnect_after_request_registration_closes_waiter() {
        let (stream, mut worker) = duplex(4096);
        let binding = test_binding();
        let worker_binding = binding.clone();
        let worker_task = tokio::spawn(async move {
            let hello = read_frame(&mut worker)
                .await
                .expect("read client hello")
                .expect("client hello frame");
            assert!(matches!(hello, SshWireFrame::ClientHello(_)));
            write_frame(
                &mut worker,
                &SshWireFrame::WorkerHello(SshWorkerHello {
                    protocol_version: SSH_WIRE_PROTOCOL_VERSION,
                    product_version: local_worker_build_info().product_version,
                    worker_id: "worker".into(),
                    os: std::env::consts::OS.into(),
                    path_semantics: if cfg!(windows) {
                        xai_grok_workspace_types::ssh_wire::SshPathSemantics::Windows
                    } else {
                        xai_grok_workspace_types::ssh_wire::SshPathSemantics::Posix
                    },
                    capabilities: SshWorkerCapabilities::complete(),
                    root: worker_binding.root.clone(),
                    binding: worker_binding,
                    resume_token: "resume".into(),
                }),
            )
            .await
            .expect("write worker hello");
            let request = read_frame(&mut worker)
                .await
                .expect("read client request")
                .expect("client request frame");
            assert!(matches!(
                request,
                SshWireFrame::Request(SshWorkerRequest::Ping { .. })
            ));
            // Drop the authenticated bridge before responding. The pending
            // request must close rather than wait for a reply that cannot arrive.
        });
        let stream: BoxSshStream = Box::pin(stream);
        let client = SshWorkspaceClient::connect(stream, binding, Arc::new(DenySshApprovals))
            .await
            .expect("complete handshake");
        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            client.request(SshWorkerRequest::Ping {
                request_id: "request-after-handshake".into(),
            }),
        )
        .await
        .expect("disconnect must wake pending requester");
        assert!(matches!(outcome, Err(SshClientError::Closed)));
        worker_task.await.expect("worker task");
    }
}
