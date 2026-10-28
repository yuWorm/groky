//! Shared SSH control backend for pager UI effects.
//!
//! An embedded pager uses the exact `SessionSsh` owned by its ACP agent. A
//! leader-backed pager lazily attaches to the persistent leader instead.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::sync::{Mutex, OnceCell, broadcast};
use xai_grok_shell::{
    leader::{ClientCapabilities, ClientMode, LeaderConnection, LeaderEnvUrls, connect_or_spawn},
    ssh::{
        PendingSshInteractions, SessionSsh, SshControlClient, SshControlCommand, SshControlReply,
        SshEventEnvelope,
    },
};

pub(crate) struct EmbeddedSsh {
    service: Arc<SessionSsh>,
    client_id: u64,
    events: Mutex<broadcast::Receiver<SshEventEnvelope>>,
}

pub(crate) struct LeaderSsh {
    connection: Arc<LeaderConnection>,
    events: Mutex<broadcast::Receiver<SshEventEnvelope>>,
}

pub(crate) enum SshControlBackend {
    Embedded(EmbeddedSsh),
    Leader(LeaderSsh),
}

static SSH_CONTROL: OnceCell<Mutex<Option<Arc<SshControlBackend>>>> = OnceCell::const_new();

async fn control_slot() -> &'static Mutex<Option<Arc<SshControlBackend>>> {
    SSH_CONTROL.get_or_init(|| async { Mutex::new(None) }).await
}

/// Install the embedded agent's exact SSH service before control requests.
///
/// Replacing a leader backend is intentional: the embedded service is the
/// authority for this pager generation. Existing disconnected leader clients
/// have their ephemeral interactions cancelled by the leader service.
pub(crate) async fn install_embedded(service: Arc<SessionSsh>, client_id: u64) -> Result<()> {
    let control = SshControlClient::from_service(service.as_ref(), client_id);
    let events = Mutex::new(control.subscribe_events());
    let backend = Arc::new(SshControlBackend::Embedded(EmbeddedSsh {
        service,
        client_id,
        events,
    }));
    let mut slot = control_slot().await.lock().await;
    if matches!(slot.as_deref(), Some(SshControlBackend::Embedded(_))) {
        anyhow::bail!("SSH control backend is already initialized");
    }
    *slot = Some(backend);
    Ok(())
}

async fn backend() -> Result<Arc<SshControlBackend>> {
    let slot = control_slot().await;
    if let Some(existing) = slot.lock().await.clone() {
        return Ok(existing);
    }

    let created = Arc::new(standalone().await?);
    let mut slot = slot.lock().await;
    Ok(slot.get_or_insert_with(|| created.clone()).clone())
}

async fn discard_stale_leader(candidate: &Arc<SshControlBackend>) {
    if !matches!(candidate.as_ref(), SshControlBackend::Leader(_)) {
        return;
    }
    let mut slot = control_slot().await.lock().await;
    if slot.as_ref().is_some_and(|current| Arc::ptr_eq(current, candidate)) {
        *slot = None;
    }
}

fn is_transport_error(error: &anyhow::Error) -> bool {
    matches!(
        error.downcast_ref::<xai_grok_shell::ssh::SshControlClientError>(),
        Some(
            xai_grok_shell::ssh::SshControlClientError::Client(_)
                | xai_grok_shell::ssh::SshControlClientError::Connection(_)
        )
    )
}

/// An independently owned control connection. Dropping it leaves retained SSH
/// connections in the leader, but releases this client's pending interactions.
/// It never installs the global pager backend, so standalone callers own their
/// receiver and recovery lifecycle explicitly.
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
    let current = backend().await?;
    let result = current.request(command).await;
    if result.as_ref().err().is_some_and(is_transport_error) {
        discard_stale_leader(&current).await;
    }
    result
}

pub(crate) async fn client_id() -> Result<u64> {
    backend().await?.client_id().await
}


pub(crate) async fn next_event_envelope() -> Result<(u64, SshEventEnvelope)> {
    let current = backend().await?;
    let result = current.next_event_envelope().await;
    if result
        .as_ref()
        .err()
        .is_some_and(|error| error.to_string().contains("event stream closed"))
    {
        discard_stale_leader(&current).await;
    }
    result
}

pub(crate) async fn pending_interactions() -> Result<(u64, PendingSshInteractions)> {
    let current = backend().await?;
    let result = current.pending_interactions().await;
    if result.as_ref().err().is_some_and(is_transport_error) {
        discard_stale_leader(&current).await;
    }
    result
}

pub(crate) async fn load_targets(
    session_id: Option<&str>,
) -> Result<(u64, Vec<crate::views::ssh_modal::SshTargetView>)> {
    let current = backend().await?;
    let result = current.load_targets(session_id).await;
    if result.as_ref().err().is_some_and(is_transport_error) {
        discard_stale_leader(&current).await;
    }
    result
}

/// Run exactly one persistent event pump for a pager generation. RPC effects
/// never create readers; this pump alone owns the receiver and issues only the
/// safe pending-interactions snapshot while recovering.
pub(crate) fn start_event_pump(
    pump_generation: u64,
    results: tokio::sync::mpsc::UnboundedSender<crate::app::actions::TaskResult>,
) -> tokio::task::AbortHandle {
    let handle = tokio::spawn(async move {
        let mut control_generation = 0;
        loop {
            control_generation += 1;
            let (client_id, snapshot) = match pending_interactions().await {
                Ok(result) => result,
                Err(error) => {
                    if results
                        .send(crate::app::actions::TaskResult::SshEventStreamFailed {
                            pump_generation,
                            control_generation,
                            client_id: None,
                            error: error.to_string(),
                        })
                        .is_err()
                    {
                        return;
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };
            let mut sequence = snapshot.sequence;
            if results
                .send(crate::app::actions::TaskResult::SshEventStreamRecovered {
                    pump_generation,
                    control_generation,
                    client_id,
                    snapshot,
                })
                .is_err()
            {
                return;
            }

            let mut retry = false;
            loop {
                match next_event_envelope().await {
                    Ok((event_client_id, SshEventEnvelope::Event { sequence: event_sequence, event }))
                        if event_client_id == client_id =>
                    {
                        if event_sequence <= sequence {
                            continue;
                        }
                        sequence = event_sequence;
                        if results
                            .send(crate::app::actions::TaskResult::SshEventStreamEvent {
                                pump_generation,
                                control_generation,
                                client_id,
                                event,
                            })
                            .is_err()
                        {
                            return;
                        }
                    }
                    Ok((_, SshEventEnvelope::Event { .. })) => {
                        retry = true;
                        break;
                    }
                    Ok((_, SshEventEnvelope::ResyncRequired)) => break,
                    Err(error) => {
                        retry = true;
                        if results
                            .send(crate::app::actions::TaskResult::SshEventStreamFailed {
                                pump_generation,
                                control_generation,
                                client_id: Some(client_id),
                                error: error.to_string(),
                            })
                            .is_err()
                        {
                            return;
                        }
                        break;
                    }
                }
            }
            if retry {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    });
    handle.abort_handle()
}

impl SshControlBackend {
    pub(crate) async fn request(&self, command: SshControlCommand) -> Result<(u64, SshControlReply)> {
        match self {
            Self::Embedded(embedded) => {
                let reply = SshControlClient::from_service(&embedded.service, embedded.client_id)
                    .request(command)
                    .await?;
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

    /// One receiver is serialized per backend. Lag is surfaced to the
    /// generation-owned pump instead of discarding authentication/grant events.
    pub(crate) async fn next_event_envelope(&self) -> Result<(u64, SshEventEnvelope)> {
        let (client_id, events) = match self {
            Self::Embedded(embedded) => (embedded.client_id, &embedded.events),
            Self::Leader(leader) => (
                SshControlClient::from_connection(&leader.connection).client_id(),
                &leader.events,
            ),
        };
        let disconnect = match self {
            Self::Embedded(_) => None,
            Self::Leader(leader) => Some(leader.connection.disconnect_reason()),
        };
        let mut events = events.lock().await;
        let event = receive_ssh_envelope(&mut events, disconnect).await?;
        Ok((client_id, event))
    }


    pub(crate) async fn pending_interactions(&self) -> Result<(u64, PendingSshInteractions)> {
        let (client_id, reply) = self.request(SshControlCommand::SnapshotPendingInteractions).await?;
        let SshControlReply::PendingInteractions(snapshot) = reply else {
            anyhow::bail!("SSH local service returned an unexpected pending-interactions snapshot.");
        };
        if snapshot.client_id != client_id {
            anyhow::bail!("SSH local service returned a pending-interactions snapshot for another client.");
        }
        Ok((client_id, snapshot))
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

async fn receive_ssh_envelope(
    events: &mut broadcast::Receiver<SshEventEnvelope>,
    disconnect: Option<tokio::sync::watch::Receiver<xai_grok_shell::leader::DisconnectReason>>,
) -> Result<SshEventEnvelope> {
    let received = if let Some(mut disconnect) = disconnect {
        if *disconnect.borrow() != xai_grok_shell::leader::DisconnectReason::Connected {
            anyhow::bail!("SSH local event stream closed; reconnecting");
        }
        tokio::select! {
            biased;
            _ = disconnect.changed() => {
                anyhow::bail!("SSH local event stream closed; reconnecting");
            }
            event = events.recv() => event,
        }
    } else {
        events.recv().await
    };
    match received {
        Ok(event) => Ok(event),
        Err(broadcast::error::RecvError::Lagged(count)) => {
            anyhow::bail!("SSH local event stream lagged by {count} events; recovering pending interactions");
        }
        Err(broadcast::error::RecvError::Closed) => {
            anyhow::bail!("SSH local event stream closed; reconnecting");
        }
    }
}

#[cfg(test)]
mod stream_tests {
    #[tokio::test]
    async fn ssh_transport_disconnect_wakes_reader_even_while_sender_is_retained() {
        use xai_grok_shell::leader::DisconnectReason;
        let (sender, mut events) = tokio::sync::broadcast::channel(8);
        let (disconnect, receiver) = tokio::sync::watch::channel(DisconnectReason::Connected);
        let reading = tokio::spawn(async move {
            super::receive_ssh_envelope(&mut events, Some(receiver)).await
        });
        tokio::task::yield_now().await;
        disconnect.send(DisconnectReason::ConnectionLost).unwrap();
        let result = tokio::time::timeout(std::time::Duration::from_secs(1), reading)
            .await.expect("transport closure must not wait for the retained broadcast sender")
            .unwrap();
        assert!(result.unwrap_err().to_string().contains("event stream closed"));
        drop(sender);
    }
}
