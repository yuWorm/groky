//! Local attention projection, separate from SSH authority and modal visibility.

use std::collections::HashMap;

use xai_grok_shell::ssh::PendingSshInteractions;

use crate::notifications::{NotificationEvent, NotificationEventKind, NotificationService};
use crate::views::ssh_modal::{SshAttention, SshAttentionKind, SshManagerState};

use super::app_view::{ActiveView, AppView};

#[derive(PartialEq, Eq)]
struct NotifiedRequest {
    kind: SshAttentionKind,
    generation: u64,
    target_id: Option<String>,
    session_id: Option<String>,
}

impl NotifiedRequest {
    fn matches(&self, attention: &SshAttention<'_>) -> bool {
        self.kind == attention.kind
            && self.generation == attention.generation
            && self.target_id.as_deref() == attention.target_id
            && self.session_id.as_deref() == attention.session_id
    }
}

#[derive(Default)]
pub(crate) struct SshAttentionState {
    client_id: Option<u64>,
    // IDs are opaque and unique within a control client. Keep completed identities until an
    // authoritative recovery barrier retires them, so a delayed direct reply cannot ring twice.
    notified: HashMap<String, NotifiedRequest>,
    pending: bool,
}

impl SshAttentionState {
    fn set_client(&mut self, client_id: u64) {
        if self.client_id != Some(client_id) {
            self.client_id = Some(client_id);
            self.notified.clear();
            self.pending = false;
        }
    }

    pub(crate) fn begin_update(&mut self, client_id: u64) {
        self.set_client(client_id);
        self.pending = false;
    }

    pub(crate) fn is_pending(&self) -> bool {
        self.pending
    }

    /// Recoveries retain live dedup identities, not the old transport generation. The stream
    /// barrier guarantees that retired identities cannot be replayed by buffered old events.
    pub(crate) fn reconcile(&mut self, snapshot: &PendingSshInteractions) {
        self.set_client(snapshot.client_id);
        self.notified.retain(|id, request| match request.kind {
            SshAttentionKind::Grant => snapshot.grants.iter().any(|grant| grant.id == *id),
            SshAttentionKind::OperationApproval => snapshot.operation_approvals.iter()
                .any(|approval| approval.approval_id == *id),
            SshAttentionKind::WorkerInstall => snapshot.worker_installs.iter()
                .any(|install| install.request_id == *id),
            SshAttentionKind::Authentication => snapshot.authentication.iter().any(|prompt| {
                prompt.challenge_id == *id
                    && prompt.connection_generation == request.generation
                    && request.target_id.as_deref() == Some(prompt.target_id.as_str())
                    && request.session_id.as_deref() == prompt.session_id.as_deref()
            }),
            SshAttentionKind::SudoPassword => snapshot.sudo_authentication.iter().any(|pending| {
                pending.prompt.challenge_id == *id
                    && pending.prompt.connection_generation == request.generation
                    && request.target_id.as_deref() == Some(pending.prompt.target_id.as_str())
            }),
        });
    }

    pub(crate) fn observe(&mut self, manager: &SshManagerState, session_name: Option<&str>, notifications: &NotificationService) {
        manager.for_each_attention(|attention| {
            self.pending = true;
            if self.notified.get(attention.request_id).is_some_and(|known| known.matches(&attention)) {
                return;
            }
            self.notified.insert(attention.request_id.to_owned(), NotifiedRequest {
                kind: attention.kind,
                generation: attention.generation,
                target_id: attention.target_id.map(str::to_owned),
                session_id: attention.session_id.map(str::to_owned),
            });
            notifications.notify(NotificationEvent {
                kind: NotificationEventKind::ApprovalRequired,
                title: session_name.unwrap_or("SSH").to_owned(),
                body: attention.kind.message().to_owned(),
                session_id: attention.session_id.map(str::to_owned),
            });
        });
    }
}

impl AppView {
    /// Called once after an outer action settles all nested mutations, including recovery.
    /// No raw prompt, command, authentication answer, or user editor is copied here.
    pub(crate) fn sync_ssh_attention(&mut self) {
        self.ssh_attention.begin_update(self.ssh_client_id);
        if let Some(manager) = self.welcome_ssh_manager.as_ref() {
            self.ssh_attention.observe(manager, None, &self.notification_service);
        }
        for agent in self.agents.values() {
            if let Some(manager) = agent.ssh_manager.as_ref() {
                self.ssh_attention.observe(
                    manager,
                    agent.display_name.as_deref().or(agent.generated_session_title.as_deref()),
                    &self.notification_service,
                );
            }
        }
    }

    /// Preserve the active ACP permission indicator and include SSH waits anywhere in this
    /// terminal, including a background session or a sessionless Welcome authentication.
    pub(crate) fn needs_user_action(&self) -> bool {
        self.ssh_attention.is_pending()
            || matches!(self.active_view, ActiveView::Agent(id)
                if self.agents.get(&id).is_some_and(|agent| !agent.permission_queue.is_empty()))
    }
}
