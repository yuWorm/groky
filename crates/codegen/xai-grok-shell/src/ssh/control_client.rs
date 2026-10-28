use tokio::sync::broadcast;

use super::{
    SessionSsh, SshControlCommand, SshControlReply, SshEventEnvelope, SshServiceError,
};

/// A thin local-leader control facade for pager and CLI code. It accepts both
/// the public `LeaderConnection` returned by `connect_or_spawn` and an already
/// exposed `LeaderClient`; neither path requires provider/model login.
pub struct SshControlClient<'a> {
    transport: ControlTransport<'a>,
}

enum ControlTransport<'a> {
    Client(&'a crate::leader::LeaderClient),
    Connection(&'a crate::leader::LeaderConnection),
    Service {
        service: &'a SessionSsh,
        client_id: u64,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum SshControlClientError {
    #[error("leader client control transport: {0}")]
    Client(#[from] crate::leader::ClientError),
    #[error("leader connection control transport: {0}")]
    Connection(#[from] crate::leader::ConnectionError),
    #[error("leader rejected SSH control: {0}")]
    Control(#[from] crate::cpu_profile::ControlError),
    #[error("in-process SSH control service: {0}")]
    Service(#[from] SshServiceError),
    #[error("leader returned a non-SSH control reply")]
    UnexpectedReply,
}

impl<'a> SshControlClient<'a> {
    pub fn new(leader: &'a crate::leader::LeaderClient) -> Self {
        Self {
            transport: ControlTransport::Client(leader),
        }
    }

    /// Construct from the public leader discovery/spawn facade. Use
    /// `connect_or_spawn("grok-ssh", ClientMode::Stdio, ...)` first; the
    /// returned connection remains open while this client awaits auth prompts.
    pub fn from_connection(leader: &'a crate::leader::LeaderConnection) -> Self {
        Self {
            transport: ControlTransport::Connection(leader),
        }
    }

    /// Construct a direct in-process control client for an embedded host.
    ///
    /// The supplied ID is the host's stable local interaction identity; it is
    /// not a leader IPC registration ID.
    pub fn from_service(service: &'a SessionSsh, client_id: u64) -> Self {
        Self {
            transport: ControlTransport::Service { service, client_id },
        }
    }

    pub fn client_id(&self) -> u64 {
        match self.transport {
            ControlTransport::Client(leader) => leader.registration().client_id,
            ControlTransport::Connection(leader) => leader.registration().client_id,
            ControlTransport::Service { client_id, .. } => client_id,
        }
    }

    pub fn subscribe_events(&self) -> broadcast::Receiver<SshEventEnvelope> {
        match self.transport {
            ControlTransport::Client(leader) => leader.subscribe_ssh_events(),
            ControlTransport::Connection(leader) => leader.subscribe_ssh_events(),
            ControlTransport::Service { service, .. } => service.subscribe_control_events(),
        }
    }
    pub async fn request(
        &self,
        command: SshControlCommand,
    ) -> Result<SshControlReply, SshControlClientError> {
        match self.transport {
            ControlTransport::Client(leader) => leader
                .send_control(crate::leader::ControlCommand::Ssh(command))
                .await
                .map_err(SshControlClientError::Client)?
                .map_err(SshControlClientError::Control)
                .and_then(|result| match result {
                    crate::leader::ControlPayload::Ssh(reply) => Ok(reply),
                    _ => Err(SshControlClientError::UnexpectedReply),
                }),
            ControlTransport::Connection(leader) => leader
                .send_control(crate::leader::ControlCommand::Ssh(command))
                .await
                .map_err(SshControlClientError::Connection)?
                .map_err(SshControlClientError::Control)
                .and_then(|result| match result {
                    crate::leader::ControlPayload::Ssh(reply) => Ok(reply),
                    _ => Err(SshControlClientError::UnexpectedReply),
                }),
            ControlTransport::Service { service, client_id } => service
                .control(client_id, command)
                .await
                .map_err(SshControlClientError::Service),
        }
    }
}
