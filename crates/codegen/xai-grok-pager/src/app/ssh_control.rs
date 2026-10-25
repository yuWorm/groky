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

pub(crate) struct EmbeddedSsh {
    service: Arc<SessionSsh>,
    client_id: u64,
    events: Mutex<broadcast::Receiver<SshEvent>>,
}

pub(crate) struct LeaderSsh {
    connection: Arc<LeaderConnection>,
    events: Mutex<broadcast::Receiver<SshEvent>>,
}

pub(crate) enum SshControlBackend {
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
    SSH_CONTROL.get_or_try_init(standalone).await
}

/// An independently owned control connection. Dropping it leaves retained SSH
/// connections in the leader, but releases this client's pending interactions.
/// It never installs the global pager backend, so project handoff can still
/// initialize the final embedded agent's exact service.
pub(crate) async fn standalone() -> Result<SshControlBackend> {
    let raw = xai_grok_shell::config::load_effective_config()
        .map_err(|error| anyhow::anyhow!("failed to load local SSH configuration: {error}"))?;
    let config = xai_grok_shell::agent::config::Config::new_from_toml_cfg(&raw)
        .map_err(|error| anyhow::anyhow!("failed to load local leader configuration: {error}"))?;
    let urls = LeaderEnvUrls::from(&config.grok_com_config);
    let connection = Arc::new(
        connect_or_spawn(
            "groky-ssh",
            ClientMode::Stdio,
            &urls,
            ClientCapabilities {
                client_version: Some(crate::client_identity::PAGER_CLIENT_VERSION.to_owned()),
                ..Default::default()
            },
        )
        .await
        .context("failed to connect to the local SSH leader")?,
    );
    let events = Mutex::new(SshControlClient::from_connection(&connection).subscribe_events());
    Ok(SshControlBackend::Leader(LeaderSsh { connection, events }))
}

pub(crate) async fn request(command: SshControlCommand) -> Result<(u64, SshControlReply)> {
    backend().await?.request(command).await
}

pub(crate) async fn client_id() -> Result<u64> {
    backend().await?.client_id().await
}

pub(crate) async fn next_event() -> Result<(u64, SshEvent)> {
    backend().await?.next_event().await
}

pub(crate) async fn load_targets(
    session_id: Option<&str>,
) -> Result<(u64, Vec<crate::views::ssh_modal::SshTargetView>)> {
    backend().await?.load_targets(session_id).await
}

impl SshControlBackend {
    pub(crate) async fn request(&self, command: SshControlCommand) -> Result<(u64, SshControlReply)> {
        match self {
            Self::Embedded(embedded) => {
                let reply = SshControlClient::from_service(&embedded.service, embedded.client_id)
                    .request(command).await?;
                Ok((embedded.client_id, reply))
            }
            Self::Leader(leader) => {
                let control = SshControlClient::from_connection(&leader.connection);
                let reply = control.request(command).await?;
                Ok((control.client_id(), reply))
            }
        }
    }

    pub(crate) async fn client_id(&self) -> Result<u64> {
        Ok(match self {
            Self::Embedded(embedded) => embedded.client_id,
            Self::Leader(leader) => SshControlClient::from_connection(&leader.connection).client_id(),
        })
    }

    /// The receiver is subscribed before the first request. Only event
    /// consumption is serialized; authentication replies can run concurrently.
    pub(crate) async fn next_event(&self) -> Result<(u64, SshEvent)> {
        let (client_id, events) = match self {
            Self::Embedded(embedded) => (embedded.client_id, &embedded.events),
            Self::Leader(leader) => (
                SshControlClient::from_connection(&leader.connection).client_id(),
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

    pub(crate) async fn load_targets(
        &self,
        session_id: Option<&str>,
    ) -> Result<(u64, Vec<crate::views::ssh_modal::SshTargetView>)> {
        use crate::views::ssh_modal::{SshCapabilitiesView, SshGrantView, SshTargetView};
        use xai_grok_shell::ssh::{SshConnectionState, SshTargetStatus};

        let (client_id, reply) = self.request(SshControlCommand::ListConfiguredTargets).await?;
        let SshControlReply::ConfiguredTargets(configured) = reply else {
            anyhow::bail!("SSH local service returned an unexpected target list.");
        };
        let configured: Vec<xai_grok_ssh::SshTarget> = serde_json::from_str(&configured)
            .context("Could not read SSH target configuration")?;
        let accesses = if let Some(session_id) = session_id {
            match self.request(SshControlCommand::ListSessionTargets {
                session_id: session_id.to_owned(),
            }).await?.1 {
                SshControlReply::SessionTargets(accesses) => accesses,
                _ => anyhow::bail!("SSH local service returned an unexpected session target list."),
            }
        } else {
            Vec::new()
        };
        let mut grants_by_target = std::collections::HashMap::<_, Vec<_>>::new();
        for access in accesses {
            grants_by_target.entry(access.target_id).or_default().push(SshGrantView::Granted {
                binding_id: access.binding_id,
                root: access.root,
                capabilities: SshCapabilitiesView {
                    read: access.capabilities.read,
                    write: access.capabilities.write,
                    execute: access.capabilities.execute,
                },
                is_default: access.is_default,
            });
        }
        let store = xai_grok_ssh::TargetStore::new(xai_grok_shell::util::grok_home::grok_home());
        let mut views = Vec::with_capacity(configured.len());
        for target in configured {
            let effective_address = match store.resolve(&target.id) {
                Ok(resolved) => format!("{}@{}:{}", resolved.username, resolved.hostname, resolved.port),
                Err(error) => format!("configuration error: {error}"),
            };
            let status = match self.request(SshControlCommand::ConnectionStatus {
                target_id: target.id.clone(),
            }).await {
                Ok((_, SshControlReply::TargetStatus(status))) => status,
                result => SshTargetStatus {
                    target_id: target.id.clone(),
                    connection: SshConnectionState::Disconnected,
                    detail: Some(match result {
                        Err(error) => format!("{error:#}"),
                        _ => "Connection status unavailable.".into(),
                    }),
                },
            };
            let connected = matches!(status.connection, SshConnectionState::Connected);
            let connection_detail = status.detail.unwrap_or_else(|| match status.connection {
                SshConnectionState::Disconnected => "Not connected.".into(),
                SshConnectionState::Connecting => "Connecting through local SSH service…".into(),
                SshConnectionState::Connected => "Connected through local SSH service.".into(),
                SshConnectionState::AuthenticationRequired => "Local authentication is required.".into(),
                SshConnectionState::Failed => "Connection failed.".into(),
            });
            let mut grants = grants_by_target.remove(&target.id).unwrap_or_default().into_iter();
            let view = SshTargetView::from_target(
                target,
                effective_address,
                connected,
                connection_detail,
                grants.next_back().unwrap_or(SshGrantView::NotGranted),
            );
            for grant in grants {
                let mut grant_view = view.clone();
                grant_view.grant = grant;
                views.push(grant_view);
            }
            views.push(view);
        }
        Ok((client_id, views))
    }
}

pub(crate) fn add_target(
    draft: crate::views::ssh_modal::SshManualTargetDraft,
) -> std::result::Result<xai_grok_ssh::SshTarget, String> {
    let mut target = xai_grok_ssh::SshTarget::new(draft.host);
    if let Some(label) = draft.label {
        target.label = label;
    }
    target.user = draft.user;
    target.port = draft.port;
    target.identity_files = draft.identity_file.into_iter().map(Into::into).collect();
    if let Some(worker_command) = draft.worker_command {
        target.worker_command = xai_grok_ssh::parse_worker_command(&worker_command)
            .map_err(|error| error.to_string())?;
    }
    xai_grok_ssh::TargetStore::new(xai_grok_shell::util::grok_home::grok_home())
        .upsert(target)
        .map_err(|error| error.to_string())
}

/// Decode local-only authentication once for both embedded and standalone views.
pub(crate) fn authentication_card(
    prompt: xai_grok_shell::ssh::SshAuthPrompt,
) -> std::result::Result<crate::views::ssh_modal::SshAuthCard, String> {
    use crate::views::ssh_modal::{SshAuthCard, SshAuthKind};
    use xai_grok_shell::ssh::{SshAuthPromptDetail, SshAuthPromptKind};
    let kind = match (prompt.kind, prompt.detail) {
        (SshAuthPromptKind::HostKey, SshAuthPromptDetail::HostKey {
            hostname, port, algorithm, fingerprint, status, previous_keys, can_replace,
        }) => SshAuthKind::HostKey {
            hostname, port, algorithm, fingerprint, status, previous_keys, can_replace,
        },
        (SshAuthPromptKind::Password, SshAuthPromptDetail::Secret {
            username, message, allow_remember,
        }) => SshAuthKind::Password { username, message, allow_remember },
        (SshAuthPromptKind::SudoPassword, SshAuthPromptDetail::Secret {
            username, message, allow_remember: false,
        }) => SshAuthKind::SudoPassword { username, message },
        (SshAuthPromptKind::PrivateKeyPassphrase, SshAuthPromptDetail::Secret {
            username, message, allow_remember,
        }) => SshAuthKind::PrivateKeyPassphrase { username, message, allow_remember },
        (SshAuthPromptKind::KeyboardInteractive, SshAuthPromptDetail::KeyboardInteractive {
            name, instruction, questions,
        }) => SshAuthKind::KeyboardInteractive {
            name, instruction, prompts: questions.into_iter().map(|question| question.prompt).collect(),
        },
        _ => return Err("SSH authentication prompt kind did not match its local details.".into()),
    };
    Ok(SshAuthCard::new(prompt.challenge_id, prompt.connection_generation, prompt.target_id, kind))
}
