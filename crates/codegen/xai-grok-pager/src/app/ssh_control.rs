//! Shared SSH control backend for pager UI effects.
//!
//! An embedded pager uses the exact `SessionSsh` owned by its ACP agent. A
//! leader-backed pager lazily attaches to the persistent leader instead.

use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::sync::{Mutex, OnceCell, broadcast};
use xai_grok_shell::{
    leader::{ClientCapabilities, ClientMode, LeaderConnection, LeaderEnvUrls, connect_or_spawn},
    ssh::{SessionSsh, SshControlClient, SshControlCommand, SshControlReply, SshEvent},
};

struct EmbeddedSsh {
    service: Arc<SessionSsh>,
    client_id: u64,
    events: Mutex<broadcast::Receiver<SshEvent>>,
}

struct LeaderSsh {
    connection: Arc<LeaderConnection>,
    events: Mutex<broadcast::Receiver<SshEvent>>,
}

enum SshControlBackend {
    Embedded(EmbeddedSsh),
    Leader(LeaderSsh),
}

static SSH_CONTROL: OnceCell<SshControlBackend> = OnceCell::const_new();

/// Install the embedded agent's exact SSH service before any control request.
/// The subscription is created up front, so authentication and approval events
/// cannot be lost between individual control replies.
pub(crate) async fn install_embedded(service: Arc<SessionSsh>, client_id: u64) -> Result<()> {
    if SSH_CONTROL.get().is_some() {
        anyhow::bail!("SSH control backend is already initialized");
    }
    let control = SshControlClient::from_service(service.as_ref(), client_id);
    let events = Mutex::new(control.subscribe_events());
    SSH_CONTROL
        .set(SshControlBackend::Embedded(EmbeddedSsh {
            service,
            client_id,
            events,
        }))
        .map_err(|_| anyhow::anyhow!("SSH control backend is already initialized"))
}

async fn backend() -> Result<&'static SshControlBackend> {
    SSH_CONTROL
        .get_or_try_init(|| async {
            let raw = xai_grok_shell::config::load_effective_config().map_err(|error| {
                anyhow::anyhow!("failed to load local SSH configuration: {error}")
            })?;
            let config = xai_grok_shell::agent::config::Config::new_from_toml_cfg(&raw).map_err(
                |error| anyhow::anyhow!("failed to load local leader configuration: {error}"),
            )?;
            let urls = LeaderEnvUrls::from(&config.grok_com_config);
            let connection = Arc::new(
                connect_or_spawn(
                    "groky-ssh",
                    ClientMode::Stdio,
                    &urls,
                    ClientCapabilities {
                        client_version: Some(
                            crate::client_identity::PAGER_CLIENT_VERSION.to_owned(),
                        ),
                        ..Default::default()
                    },
                )
                .await
                .context("failed to connect to the local SSH leader")?,
            );
            let control = SshControlClient::from_connection(connection.as_ref());
            let events = Mutex::new(control.subscribe_events());
            Ok::<_, anyhow::Error>(SshControlBackend::Leader(LeaderSsh { connection, events }))
        })
        .await
}

pub(crate) async fn request(command: SshControlCommand) -> Result<(u64, SshControlReply)> {
    match backend().await? {
        SshControlBackend::Embedded(embedded) => {
            let reply =
                SshControlClient::from_service(embedded.service.as_ref(), embedded.client_id)
                    .request(command)
                    .await?;
            Ok((embedded.client_id, reply))
        }
        SshControlBackend::Leader(leader) => {
            let control = SshControlClient::from_connection(leader.connection.as_ref());
            let client_id = control.client_id();
            let reply = control.request(command).await?;
            Ok((client_id, reply))
        }
    }
}

pub(crate) async fn client_id() -> Result<u64> {
    match backend().await? {
        SshControlBackend::Embedded(embedded) => Ok(embedded.client_id),
        SshControlBackend::Leader(leader) => {
            Ok(SshControlClient::from_connection(leader.connection.as_ref()).client_id())
        }
    }
}

/// Receive the next server SSH event from the receiver subscribed before the
/// first control request. Only event consumption is serialized.
pub(crate) async fn next_event() -> Result<(u64, SshEvent)> {
    let backend = backend().await?;
    let (client_id, events) = match backend {
        SshControlBackend::Embedded(embedded) => (embedded.client_id, &embedded.events),
        SshControlBackend::Leader(leader) => (
            SshControlClient::from_connection(leader.connection.as_ref()).client_id(),
            &leader.events,
        ),
    };
    let mut events = events.lock().await;
    loop {
        match events.recv().await {
            Ok(event) => return Ok((client_id, event)),
            Err(broadcast::error::RecvError::Lagged(_)) => continue,
            Err(broadcast::error::RecvError::Closed) => {
                anyhow::bail!("SSH local event stream closed; reopen SSH manager to reconnect.")
            }
        }
    }
}
