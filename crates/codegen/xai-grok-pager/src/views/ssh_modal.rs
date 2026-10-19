//! Local-only SSH target, grant, and authentication modal.
//!
//! The state here deliberately contains no chat blocks, notifications, or replay data. Secrets
//! are accepted only by [`SshAuthCard`], render as bullets with no partial reveal, and leave this
//! modal only as [`SshSecret`].

use crate::input::line_editor::{LineEditOutcome, LineEditor};
use crate::theme::Theme;
use crate::views::modal_window::{
    self, ModalSizing, ModalWindowConfig, ModalWindowOutcome, ModalWindowState, Shortcut,
};
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseEvent};
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use zeroize::Zeroizing;

/// A configured target as displayed by the pager. This is a view model rather than a credential
/// or transport type so the modal cannot accidentally retain authentication material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshTargetView {
    pub target_id: String,
    pub label: String,
    /// User target, imported OpenSSH alias, or system OpenSSH alias.
    pub source: String,
    /// Resolved `user@host:port` (or an explicit resolver error category), never a secret.
    pub effective_address: String,
    pub connected: bool,
    pub connection_detail: String,
    pub grant: SshGrantView,
}

/// The local session authorization state shown for one target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshGrantView {
    NotGranted,
    Granted {
        binding_id: String,
        root: String,
        capabilities: SshCapabilitiesView,
        is_default: bool,
    },
    Revoking {
        binding_id: String,
        /// True only after the worker has acknowledged the new authorization epoch.
        worker_acknowledged: bool,
    },
}

impl SshGrantView {
    fn summary(&self) -> String {
        match self {
            Self::NotGranted => "not granted".into(),
            Self::Granted {
                root,
                capabilities,
                is_default,
                ..
            } => {
                let default = if *is_default { " default" } else { "" };
                format!("{} at {root}{default}", capabilities.compact())
            }
            Self::Revoking {
                worker_acknowledged: true,
                ..
            } => "revoked (worker confirmed)".into(),
            Self::Revoking {
                worker_acknowledged: false,
                ..
            } => "locally revoked; worker confirmation pending".into(),
        }
    }

    fn binding_id(&self) -> Option<&str> {
        match self {
            Self::Granted { binding_id, .. } | Self::Revoking { binding_id, .. } => {
                Some(binding_id)
            }
            Self::NotGranted => None,
        }
    }

    fn granted_root(&self) -> Option<&str> {
        match self {
            Self::Granted { root, .. } => Some(root),
            Self::NotGranted | Self::Revoking { .. } => None,
        }
    }
}

/// Authorization capability checkboxes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SshCapabilitiesView {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl Default for SshCapabilitiesView {
    fn default() -> Self {
        Self {
            read: true,
            write: false,
            execute: false,
        }
    }
}

impl SshCapabilitiesView {
    fn compact(self) -> String {
        let mut names = Vec::with_capacity(3);
        if self.read {
            names.push("read");
        }
        if self.write {
            names.push("write");
        }
        if self.execute {
            names.push("run");
        }
        if names.is_empty() {
            "no capabilities".into()
        } else {
            names.join(",")
        }
    }

    fn any(self) -> bool {
        self.read || self.write || self.execute
    }
}

/// Where a user-approved target authorization is retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshGrantLifetime {
    CurrentSession,
    ProjectRule,
}

impl SshGrantLifetime {
    fn label(self) -> &'static str {
        match self {
            Self::CurrentSession => "current session only",
            Self::ProjectRule => "project rule (explicit opt-in)",
        }
    }

    fn toggle(self) -> Self {
        match self {
            Self::CurrentSession => Self::ProjectRule,
            Self::ProjectRule => Self::CurrentSession,
        }
    }
}

/// Human consent card for a pending model or user SSH access request.
pub struct SshGrantCard {
    pub request_id: String,
    pub target_id: String,
    pub target_label: String,
    /// Verified SSH user/host/fingerprint, present only after transport authentication.
    pub identity: Option<String>,
    pub reason: Option<String>,
    pub root: LineEditor,
    pub capabilities: SshCapabilitiesView,
    pub lifetime: SshGrantLifetime,
    pub set_default: bool,
    pub agent_requested: bool,
    pub error: Option<String>,
}

impl SshGrantCard {
    pub fn new(
        request_id: String,
        target_id: String,
        target_label: String,
        identity: Option<String>,
        root: impl Into<String>,
        reason: Option<String>,
        agent_requested: bool,
    ) -> Self {
        let mut root_editor = LineEditor::default();
        root_editor.set_text(root);
        Self {
            request_id,
            target_id,
            target_label,
            identity,
            reason,
            root: root_editor,
            capabilities: SshCapabilitiesView::default(),
            lifetime: SshGrantLifetime::CurrentSession,
            set_default: false,
            agent_requested,
            error: None,
        }
    }
}

/// Non-secret incoming request data copied from a session SSH event into the local consent UI.
#[derive(Debug, Clone)]
pub struct SshIncomingGrant {
    pub request_id: String,
    pub target_id: Option<String>,
    pub root: Option<String>,
    pub capabilities: SshCapabilitiesView,
    pub verified_identity: Option<String>,
    pub reason: String,
}

#[derive(Clone)]
struct LocalGrantOptions {
    target_id: String,
    root: String,
    capabilities: SshCapabilitiesView,
    lifetime: SshGrantLifetime,
    set_default: bool,
}

/// Immutable record of the tuple actually submitted to the local SSH service.
/// The worker may canonicalize `root`, so that field is only for correlation.
struct SubmittedGrantDecision {
    request_id: String,
    session_id: String,
    target_id: String,
    root: String,
}

/// Authentication kind provided by the shell's local control bridge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshAuthKind {
    HostKey {
        hostname: String,
        port: u16,
        algorithm: String,
        fingerprint: String,
        status: String,
        previous_keys: Vec<String>,
        can_replace: bool,
    },
    Password {
        username: String,
        message: String,
        allow_remember: bool,
    },
    PrivateKeyPassphrase {
        username: String,
        message: String,
        allow_remember: bool,
    },
    KeyboardInteractive {
        name: String,
        instruction: String,
        prompts: Vec<String>,
    },
}

impl SshAuthKind {
    fn title(&self) -> &'static str {
        match self {
            Self::HostKey { .. } => "SSH host key confirmation",
            Self::Password { .. } => "SSH password",
            Self::PrivateKeyPassphrase { .. } => "SSH private-key passphrase",
            Self::KeyboardInteractive { .. } => "SSH authentication challenge",
        }
    }
}

const MAX_SECRET_BYTES: usize = 4096;

/// A deliberately small, non-history editor used only for local SSH secrets.
///
/// The fixed initial capacity prevents allocator reallocation from retaining earlier secret
/// buffers, while `Zeroizing` clears the active allocation on submit, cancel, or drop.
struct SecretEditor {
    value: Zeroizing<String>,
    cursor_byte: usize,
}

impl Default for SecretEditor {
    fn default() -> Self {
        Self {
            value: Zeroizing::new(String::with_capacity(MAX_SECRET_BYTES)),
            cursor_byte: 0,
        }
    }
}

impl SecretEditor {
    fn text(&self) -> &str {
        &self.value
    }

    fn clear(&mut self) {
        self.value = Zeroizing::new(String::with_capacity(MAX_SECRET_BYTES));
        self.cursor_byte = 0;
    }

    fn take_secret(&mut self) -> SshSecret {
        self.cursor_byte = 0;
        SshSecret(std::mem::replace(
            &mut self.value,
            Zeroizing::new(String::with_capacity(MAX_SECRET_BYTES)),
        ))
    }

    fn insert_paste(&mut self, text: &str) -> LineEditOutcome {
        let mut changed = false;
        for character in text
            .chars()
            .filter(|character| !matches!(character, '\r' | '\n'))
        {
            if self.value.len() + character.len_utf8() > MAX_SECRET_BYTES {
                break;
            }
            self.value.insert(self.cursor_byte, character);
            self.cursor_byte += character.len_utf8();
            changed = true;
        }
        if changed {
            LineEditOutcome::TextChanged
        } else {
            LineEditOutcome::HandledNoChange
        }
    }

    fn remove_range(&mut self, start: usize, end: usize) {
        let mut replacement = Zeroizing::new(String::with_capacity(MAX_SECRET_BYTES));
        replacement.push_str(&self.value[..start]);
        replacement.push_str(&self.value[end..]);
        // Replacing, rather than draining, leaves the old editor at its full logical length
        // until Zeroizing clears it; removed bytes are therefore not retained past the edit.
        self.value = replacement;
        self.cursor_byte = start;
    }

    fn handle_key(&mut self, key: &KeyEvent) -> LineEditOutcome {
        if key.kind == KeyEventKind::Release {
            return LineEditOutcome::Unhandled;
        }
        match key.code {
            KeyCode::Char(character)
                if !key.modifiers.intersects(
                    KeyModifiers::CONTROL | KeyModifiers::ALT | KeyModifiers::SUPER,
                ) =>
            {
                self.insert_paste(character.encode_utf8(&mut [0; 4]))
            }
            KeyCode::Backspace => {
                let previous = self.value[..self.cursor_byte]
                    .char_indices()
                    .last()
                    .map(|(index, _)| index);
                match previous {
                    Some(index) => {
                        self.remove_range(index, self.cursor_byte);
                        LineEditOutcome::TextChanged
                    }
                    None => LineEditOutcome::HandledNoChange,
                }
            }
            KeyCode::Delete => {
                let next_len = self.value[self.cursor_byte..]
                    .chars()
                    .next()
                    .map(char::len_utf8);
                match next_len {
                    Some(length) => {
                        self.remove_range(self.cursor_byte, self.cursor_byte + length);
                        LineEditOutcome::TextChanged
                    }
                    None => LineEditOutcome::HandledNoChange,
                }
            }
            KeyCode::Left => {
                let previous = self.value[..self.cursor_byte]
                    .char_indices()
                    .last()
                    .map(|(index, _)| index);
                match previous {
                    Some(index) => {
                        self.cursor_byte = index;
                        LineEditOutcome::CursorChanged
                    }
                    None => LineEditOutcome::HandledNoChange,
                }
            }
            KeyCode::Right => {
                let next_len = self.value[self.cursor_byte..]
                    .chars()
                    .next()
                    .map(char::len_utf8);
                match next_len {
                    Some(length) => {
                        self.cursor_byte += length;
                        LineEditOutcome::CursorChanged
                    }
                    None => LineEditOutcome::HandledNoChange,
                }
            }
            KeyCode::Home => {
                if self.cursor_byte == 0 {
                    LineEditOutcome::HandledNoChange
                } else {
                    self.cursor_byte = 0;
                    LineEditOutcome::CursorChanged
                }
            }
            KeyCode::End => {
                let end = self.value.len();
                if self.cursor_byte == end {
                    LineEditOutcome::HandledNoChange
                } else {
                    self.cursor_byte = end;
                    LineEditOutcome::CursorChanged
                }
            }
            _ => LineEditOutcome::Unhandled,
        }
    }
}

/// Dedicated local auth surface correlated to one transport challenge.
pub struct SshAuthCard {
    pub challenge_id: String,
    pub connection_generation: u64,
    pub target_id: String,
    pub kind: SshAuthKind,
    answers: Vec<SecretEditor>,
    active_answer: usize,
    /// Top wrapped line visible in an authentication card with more content than its viewport.
    scroll_offset: usize,
    /// Render-derived upper bound for [`Self::scroll_offset`].
    max_scroll_offset: usize,
    pub remember: bool,
    pub error: Option<String>,
}

impl SshAuthCard {
    pub fn new(
        challenge_id: String,
        connection_generation: u64,
        target_id: String,
        kind: SshAuthKind,
    ) -> Self {
        let answer_count = match &kind {
            SshAuthKind::HostKey { .. } => 0,
            SshAuthKind::KeyboardInteractive { prompts, .. } => prompts.len().max(1),
            SshAuthKind::Password { .. } | SshAuthKind::PrivateKeyPassphrase { .. } => 1,
        };
        Self {
            challenge_id,
            connection_generation,
            target_id,
            remember: false,
            kind,
            answers: (0..answer_count).map(|_| SecretEditor::default()).collect(),
            active_answer: 0,
            scroll_offset: 0,
            max_scroll_offset: 0,
            error: None,
        }
    }

    fn can_remember(&self) -> bool {
        matches!(
            &self.kind,
            SshAuthKind::Password {
                allow_remember: true,
                ..
            } | SshAuthKind::PrivateKeyPassphrase {
                allow_remember: true,
                ..
            }
        )
    }

    fn answer_mut(&mut self) -> Option<&mut SecretEditor> {
        self.answers.get_mut(self.active_answer)
    }

    fn clear_answers(&mut self) {
        for answer in &mut self.answers {
            answer.clear();
        }
        self.active_answer = 0;
    }

    fn secret_answers(&mut self) -> Vec<SshSecret> {
        self.answers
            .iter_mut()
            .map(SecretEditor::take_secret)
            .collect()
    }

    fn take_auth_response(&mut self) -> (Option<SshSecret>, Vec<SshSecret>) {
        let is_single_secret = matches!(
            &self.kind,
            SshAuthKind::Password { .. } | SshAuthKind::PrivateKeyPassphrase { .. }
        );
        let mut answers = self.secret_answers();
        if is_single_secret {
            (answers.pop(), Vec::new())
        } else {
            (None, answers)
        }
    }
}

impl std::fmt::Debug for SshAuthCard {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SshAuthCard")
            .field("challenge_id", &self.challenge_id)
            .field("connection_generation", &self.connection_generation)
            .field("target_id", &self.target_id)
            .field("kind", &self.kind)
            .field("answer_count", &self.answers.len())
            .field("active_answer", &self.active_answer)
            .field("scroll_offset", &self.scroll_offset)
            .field("max_scroll_offset", &self.max_scroll_offset)
            .field("remember", &self.remember)
            .field("error", &self.error)
            .finish()
    }
}

/// SSH secret in transit from the local modal to the local control bridge.
///
/// It purposely has a redacted Debug implementation. It is never serialized, copied into a
/// notification, or held by the manager after submit.
pub struct SshSecret(Zeroizing<String>);

impl SshSecret {
    pub fn into_bytes(self) -> Vec<u8> {
        // `Zeroizing` deliberately has no consuming extraction. Copy across the local control
        // boundary; the editor allocation is zeroed when `self` drops and the receiving
        // `SshAuthControlResponse` owns and clears the transferred vector on every exit path.
        self.0.as_bytes().to_vec()
    }
}

impl std::fmt::Debug for SshSecret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SshSecret([REDACTED])")
    }
}

/// Manual target configuration gathered by the local UI. It intentionally excludes credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshManualTargetDraft {
    pub host: String,
    pub label: Option<String>,
    pub user: Option<String>,
    pub port: Option<u16>,
    pub identity_file: Option<String>,
    pub worker_command: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ManualTargetField {
    Host,
    Label,
    User,
    Port,
    IdentityFile,
    WorkerCommand,
}

impl ManualTargetField {
    const ALL: [Self; 6] = [
        Self::Host,
        Self::Label,
        Self::User,
        Self::Port,
        Self::IdentityFile,
        Self::WorkerCommand,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::Host => "Host / alias",
            Self::Label => "Label",
            Self::User => "User override",
            Self::Port => "Port override",
            Self::IdentityFile => "Identity file",
            Self::WorkerCommand => "Worker command",
        }
    }

    fn next(self, backwards: bool) -> Self {
        let index = Self::ALL
            .iter()
            .position(|field| *field == self)
            .unwrap_or(0);
        let len = Self::ALL.len();
        let next = if backwards {
            (index + len - 1) % len
        } else {
            (index + 1) % len
        };
        Self::ALL[next]
    }
}

struct SshManualTargetForm {
    host: LineEditor,
    label: LineEditor,
    user: LineEditor,
    port: LineEditor,
    identity_file: LineEditor,
    worker_command: LineEditor,
    active: ManualTargetField,
    error: Option<String>,
}

impl Default for SshManualTargetForm {
    fn default() -> Self {
        Self {
            host: LineEditor::default(),
            label: LineEditor::default(),
            user: LineEditor::default(),
            port: LineEditor::default(),
            identity_file: LineEditor::default(),
            worker_command: LineEditor::default(),
            active: ManualTargetField::Host,
            error: None,
        }
    }
}

impl SshManualTargetForm {
    fn editor(&self, field: ManualTargetField) -> &LineEditor {
        match field {
            ManualTargetField::Host => &self.host,
            ManualTargetField::Label => &self.label,
            ManualTargetField::User => &self.user,
            ManualTargetField::Port => &self.port,
            ManualTargetField::IdentityFile => &self.identity_file,
            ManualTargetField::WorkerCommand => &self.worker_command,
        }
    }

    fn editor_mut(&mut self) -> &mut LineEditor {
        match self.active {
            ManualTargetField::Host => &mut self.host,
            ManualTargetField::Label => &mut self.label,
            ManualTargetField::User => &mut self.user,
            ManualTargetField::Port => &mut self.port,
            ManualTargetField::IdentityFile => &mut self.identity_file,
            ManualTargetField::WorkerCommand => &mut self.worker_command,
        }
    }

    fn draft(&self) -> Result<SshManualTargetDraft, String> {
        let host = self.host.text().trim();
        if host.is_empty() {
            return Err("Host or OpenSSH alias is required.".into());
        }
        let port = match self.port.text().trim() {
            "" => None,
            raw => Some(
                raw.parse::<u16>()
                    .map_err(|_| "Port must be an integer between 1 and 65535.")?,
            ),
        };
        let optional = |value: &str| {
            let trimmed = value.trim();
            (!trimmed.is_empty()).then(|| trimmed.to_owned())
        };
        Ok(SshManualTargetDraft {
            host: host.to_owned(),
            label: optional(self.label.text()),
            user: optional(self.user.text()),
            port,
            identity_file: optional(self.identity_file.text()),
            worker_command: optional(self.worker_command.text()),
        })
    }
}

/// Local-only consent for an individual remote operation after a binding already exists.
///
/// `reviewed_to_end` is deliberately render-derived: allow is unavailable until every wrapped
/// detail line has been reachable in this modal, rather than trusting a truncating single-line
/// preview.
pub struct SshOperationApprovalCard {
    pub approval_id: String,
    pub binding_id: String,
    pub target_label: String,
    pub target_identity: Option<String>,
    pub title: String,
    pub detail: String,
    scroll_offset: usize,
    max_scroll_offset: usize,
    reviewed_to_end: bool,
    submitting: bool,
    error: Option<String>,
}

impl SshOperationApprovalCard {
    pub fn new(
        approval_id: String,
        binding_id: String,
        target_label: String,
        target_identity: Option<String>,
        title: String,
        detail: String,
    ) -> Self {
        Self {
            approval_id,
            binding_id,
            target_label,
            target_identity,
            title,
            detail,
            scroll_offset: 0,
            max_scroll_offset: 0,
            reviewed_to_end: false,
            submitting: false,
            error: None,
        }
    }
}

/// Whether an operation approval interrupted chat or was opened from the SSH manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshOperationApprovalOrigin {
    ExplicitManager,
    TransientEvent,
}

/// Full, wrapped SSH diagnostic retained separately from the one-line manager status.
///
/// Keeping this page local to the manager means opening or leaving it never changes the selected
/// target or consumes a pending SSH authentication challenge.
struct SshDiagnosticCard {
    message: String,
    scroll_offset: usize,
    max_scroll_offset: usize,
}

impl SshDiagnosticCard {
    fn new(message: String) -> Self {
        Self {
            message,
            scroll_offset: 0,
            max_scroll_offset: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SubmittedOperationApproval {
    approval_id: String,
    approved: bool,
    origin: SshOperationApprovalOrigin,
}

enum SshModalPage {
    Manager,
    Add(SshManualTargetForm),
    Grant(SshGrantCard),
    OperationApproval(SshOperationApprovalCard),
    Authentication(SshAuthCard),
    Diagnostic(SshDiagnosticCard),
}

/// Manager state usable from Welcome and from a running session.
pub struct SshManagerState {
    pub window: ModalWindowState,
    page: SshModalPage,
    pub targets: Vec<SshTargetView>,
    pub selected: usize,
    pub loading: bool,
    pub message: Option<(String, bool)>,
    /// Immutable request tuple retained through the displayed consent card so resolution can
    /// be correlated with the original target/root rather than editable card state.
    pending_grant: Option<SshIncomingGrant>,
    /// Exact decision submitted for the displayed request, retained until its resolution.
    submitted_grant: Option<SubmittedGrantDecision>,
    /// Session actually requested by the current human-consent card. Usually this manager's
    /// session, but a remote worktree resume pre-mints a child before it has an AgentView.
    pending_grant_session_id: Option<String>,
    local_grant_options: Option<LocalGrantOptions>,
    /// Session whose grants are shown. `None` is Welcome: connect/config actions remain usable,
    /// but granting and selecting a default requires creating or opening a session first.
    pub session_id: Option<String>,
    /// The opening context of the currently visible or most recently submitted operation card.
    operation_approval_origin: Option<SshOperationApprovalOrigin>,
    /// Exact operation decision awaiting its local-control acknowledgement.
    submitted_operation_approval: Option<SubmittedOperationApproval>,
}

impl SshManagerState {
    pub fn new(session_id: Option<String>) -> Self {
        Self {
            window: ModalWindowState::new(),
            page: SshModalPage::Manager,
            targets: Vec::new(),
            selected: 0,
            loading: true,
            message: None,
            pending_grant: None,
            submitted_grant: None,
            pending_grant_session_id: None,
            local_grant_options: None,
            session_id,
            operation_approval_origin: None,
            submitted_operation_approval: None,
        }
    }

    /// Retain the user's chosen scope/default while transport authentication turns the request
    /// into an identity-backed consent card.
    pub fn remember_local_grant_options(
        &mut self,
        target_id: String,
        root: String,
        capabilities: SshCapabilitiesView,
        lifetime: SshGrantLifetime,
        set_default: bool,
    ) {
        self.local_grant_options = Some(LocalGrantOptions {
            target_id,
            root,
            capabilities,
            lifetime,
            set_default,
        });
    }

    /// Return the pre-minted or current session that owns a displayed/pending grant request.
    pub fn grant_session_id_for(&self, request_id: &str) -> Option<String> {
        let request_matches = self
            .pending_grant
            .as_ref()
            .is_some_and(|request| request.request_id == request_id)
            || matches!(&self.page, SshModalPage::Grant(card) if card.request_id == request_id);
        request_matches
            .then(|| self.pending_grant_session_id.clone())
            .flatten()
    }

    /// Whether this manager owns a still-displayed grant for this exact pre-minted session.
    ///
    /// Worktree children receive their session ID before their optimistic pager agent has bound
    /// it. Target-list completion must use this retained grant correlation rather than treating
    /// that child ID as a normal active-agent session.
    pub fn owns_pending_grant_session(&self, session_id: &str) -> bool {
        self.pending_grant_session_id.as_deref() == Some(session_id)
            && (self.pending_grant.is_some() || matches!(&self.page, SshModalPage::Grant(_)))
    }

    /// Record the exact tuple sent to the service for an approved displayed grant.
    pub fn record_grant_approval(
        &mut self,
        request_id: &str,
        target_id: Option<&str>,
        root: Option<&str>,
    ) -> bool {
        let Some(request) = self.pending_grant.as_ref() else {
            return false;
        };
        let Some(session_id) = self.pending_grant_session_id.as_deref() else {
            return false;
        };
        let Some(request_target_id) = request.target_id.as_deref() else {
            return false;
        };
        let Some(request_root) = request.root.as_deref() else {
            return false;
        };
        if request.request_id != request_id {
            return false;
        }
        let target_id = target_id.unwrap_or(request_target_id);
        if target_id != request_target_id {
            return false;
        }
        self.submitted_grant = Some(SubmittedGrantDecision {
            request_id: request_id.to_owned(),
            session_id: session_id.to_owned(),
            target_id: target_id.to_owned(),
            root: root.unwrap_or(request_root).to_owned(),
        });
        true
    }

    /// Return the raw root submitted for an exact CLI project request.
    ///
    /// Callers must use the worker binding's root for their workspace: this raw path exists
    /// solely to prove that a user-edited consent decision belongs to this request id.
    pub fn submitted_project_grant_root(
        &self,
        request_id: &str,
        session_id: &str,
        target_id: &str,
        requested_root: &str,
    ) -> Option<&str> {
        let request_matches = self.pending_grant_session_id.as_deref() == Some(session_id)
            && self.pending_grant.as_ref().is_some_and(|request| {
                request.request_id == request_id
                    && request.target_id.as_deref() == Some(target_id)
                    && request.root.as_deref() == Some(requested_root)
            });
        let submitted = self.submitted_grant.as_ref()?;
        (request_matches
            && submitted.request_id == request_id
            && submitted.session_id == session_id
            && submitted.target_id == target_id)
            .then_some(submitted.root.as_str())
    }

    pub fn set_targets(&mut self, mut targets: Vec<SshTargetView>) {
        for target in &mut targets {
            if matches!(&target.grant, SshGrantView::NotGranted)
                && let Some((binding_id, worker_acknowledged)) = self
                    .targets
                    .iter()
                    .find(|previous| previous.target_id == target.target_id)
                    .and_then(|previous| match &previous.grant {
                        SshGrantView::Revoking {
                            binding_id,
                            worker_acknowledged,
                        } => Some((binding_id.clone(), *worker_acknowledged)),
                        SshGrantView::NotGranted | SshGrantView::Granted { .. } => None,
                    })
            {
                target.grant = SshGrantView::Revoking {
                    binding_id,
                    worker_acknowledged,
                };
            }
        }
        self.targets = targets;
        self.selected = self.selected.min(self.targets.len().saturating_sub(1));
        self.loading = false;
        if matches!(
            &self.page,
            SshModalPage::Authentication(card)
                if self
                    .targets
                    .iter()
                    .any(|target| target.target_id == card.target_id && target.connected)
        ) {
            self.page = SshModalPage::Manager;
        }
    }

    pub fn show_grant(&mut self, card: SshGrantCard) {
        self.page = SshModalPage::Grant(card);
    }

    pub fn show_authentication(&mut self, card: SshAuthCard) {
        self.page = SshModalPage::Authentication(card);
    }

    /// Display a remote operation approval card and retain whether it interrupted chat.
    pub fn show_operation_approval(
        &mut self,
        card: SshOperationApprovalCard,
        origin: SshOperationApprovalOrigin,
    ) {
        self.page = SshModalPage::OperationApproval(card);
        self.operation_approval_origin = Some(origin);
        self.submitted_operation_approval = None;
    }

    /// Preserve a transient origin across a burst of approvals without treating the overlay as
    /// explicitly opened merely because the previous card is still present.
    pub fn operation_approval_origin(&self) -> Option<SshOperationApprovalOrigin> {
        self.operation_approval_origin
    }

    /// Mark the exact visible card as submitted. Stale input cannot decide another operation.
    pub fn submit_operation_approval(&mut self, approval_id: &str, approved: bool) -> bool {
        let SshModalPage::OperationApproval(card) = &mut self.page else {
            return false;
        };
        if card.approval_id != approval_id || card.submitting {
            return false;
        }
        card.submitting = true;
        card.error = None;
        self.submitted_operation_approval = Some(SubmittedOperationApproval {
            approval_id: approval_id.to_owned(),
            approved,
            origin: self
                .operation_approval_origin
                .unwrap_or(SshOperationApprovalOrigin::ExplicitManager),
        });
        true
    }

    /// Settle one exact local-control submission.
    ///
    /// A successful allow from a transient approval returns to chat. Explicit-manager
    /// approvals and all denials remain visible in the manager; a failure remains on the card.
    /// A late completion for an older card cannot hide a newer approval.
    pub fn settle_operation_approval(&mut self, approval_id: &str, error: Option<String>) -> bool {
        let Some(submitted) = self.submitted_operation_approval.as_ref() else {
            return false;
        };
        if submitted.approval_id != approval_id {
            return false;
        }
        let submitted = self
            .submitted_operation_approval
            .take()
            .expect("submitted operation approval was checked above");
        let displayed = matches!(
            &self.page,
            SshModalPage::OperationApproval(card) if card.approval_id == approval_id
        );
        if let Some(error) = error {
            if let SshModalPage::OperationApproval(card) = &mut self.page
                && card.approval_id == approval_id
            {
                card.submitting = false;
                card.error = Some(error);
            } else {
                self.show_error(error);
            }
            return false;
        }
        if submitted.approved
            && submitted.origin == SshOperationApprovalOrigin::TransientEvent
            && displayed
        {
            return true;
        }
        if displayed {
            self.return_to_manager();
        }
        self.show_info(if submitted.approved {
            "Remote operation approval sent."
        } else {
            "Remote operation denied."
        });
        false
    }

    /// Display a real agent access request only after the selected target's SSH identity was
    /// inspected. A target/root from the initial request is intent, not consent evidence.
    pub fn show_incoming_grant(&mut self, session_id: String, request: SshIncomingGrant) {
        self.pending_grant_session_id = Some(session_id);
        self.submitted_grant = None;
        let Some(target_id) = request.target_id.as_deref() else {
            self.pending_grant = Some(request);
            self.show_error(
                "No SSH target was selected. Select a target and press g to review this request.",
            );
            return;
        };
        if request.verified_identity.is_none() {
            self.pending_grant = Some(request);
            self.page = SshModalPage::Manager;
            self.show_info(
                "Authenticate the selected SSH target before reviewing this access request; press g.",
            );
            return;
        }
        let local_options = (request.reason
            == "User requested SSH access from the local SSH manager.")
            .then(|| {
                self.local_grant_options.as_ref().filter(|options| {
                    options.target_id == target_id
                        && request.root.as_deref() == Some(options.root.as_str())
                })
            })
            .flatten()
            .cloned();
        self.pending_grant = Some(request.clone());
        let target_label = self
            .targets
            .iter()
            .find(|target| target.target_id == target_id)
            .map(|target| target.label.clone())
            .unwrap_or_else(|| target_id.to_owned());
        let mut card = SshGrantCard::new(
            request.request_id,
            target_id.to_owned(),
            target_label,
            request.verified_identity,
            request.root.unwrap_or_default(),
            Some(request.reason),
            local_options.is_none(),
        );
        if let Some(options) = local_options {
            card.capabilities = options.capabilities;
            card.lifetime = options.lifetime;
            card.set_default = options.set_default;
        } else {
            card.capabilities = request.capabilities;
        }
        self.page = SshModalPage::Grant(card);
    }

    /// Apply an asynchronous local connection update without exposing transport state elsewhere.
    pub fn apply_target_status(
        &mut self,
        target_id: &str,
        connected: bool,
        detail: Option<String>,
    ) {
        if let Some(target) = self
            .targets
            .iter_mut()
            .find(|target| target.target_id == target_id)
        {
            target.connected = connected;
            target.connection_detail = detail.unwrap_or_else(|| {
                if connected {
                    "Connected through local SSH service.".into()
                } else {
                    "Disconnected.".into()
                }
            });
        }
        if connected
            && matches!(&self.page, SshModalPage::Authentication(card) if card.target_id == target_id)
        {
            self.page = SshModalPage::Manager;
        }
    }

    /// Keep the distinction between local revocation and worker acknowledgement visible.
    pub fn mark_binding_revoked(&mut self, binding_id: &str, worker_acknowledged: bool) {
        let mut changed = false;
        for target in &mut self.targets {
            if target.grant.binding_id() == Some(binding_id) {
                target.grant = SshGrantView::Revoking {
                    binding_id: binding_id.to_owned(),
                    worker_acknowledged,
                };
                changed = true;
            }
        }
        if changed && worker_acknowledged {
            self.show_info("SSH access revocation confirmed by worker.");
        }
    }

    pub fn has_worker_acknowledged_revocation(&self) -> bool {
        self.targets.iter().any(|target| {
            matches!(
                target.grant,
                SshGrantView::Revoking {
                    worker_acknowledged: true,
                    ..
                }
            )
        })
    }

    /// Return an asynchronously resolved consent card to the manager list.
    pub fn settle_grant(&mut self, approved: bool) {
        self.pending_grant = None;
        self.submitted_grant = None;
        self.pending_grant_session_id = None;
        self.page = SshModalPage::Manager;
        self.show_info(if approved {
            "SSH access grant approved."
        } else {
            "SSH access grant denied."
        });
    }

    pub fn target_label_for_binding(&self, binding_id: &str) -> Option<String> {
        self.targets.iter().find_map(|target| {
            (target.grant.binding_id() == Some(binding_id)).then(|| target.label.clone())
        })
    }

    fn open_error_diagnostic(&mut self) -> bool {
        let Some((message, true)) = self.message.as_ref() else {
            return false;
        };
        self.page = SshModalPage::Diagnostic(SshDiagnosticCard::new(message.clone()));
        true
    }

    pub fn show_error(&mut self, error: impl Into<String>) {
        self.message = Some((error.into(), true));
    }

    pub fn show_info(&mut self, message: impl Into<String>) {
        self.message = Some((message.into(), false));
    }

    fn selected_target(&self) -> Option<&SshTargetView> {
        self.targets.get(self.selected)
    }

    fn return_to_manager(&mut self) {
        self.page = SshModalPage::Manager;
    }
}

/// Intent emitted by the modal; app dispatch maps these to local shell-control calls.
pub enum SshModalOutcome {
    Close,
    Changed,
    Unchanged,
    Refresh,
    AddTarget(SshManualTargetDraft),
    Connect {
        target_id: String,
    },
    Disconnect {
        target_id: String,
    },
    RequestGrant {
        target_id: String,
        root: String,
        capabilities: SshCapabilitiesView,
        lifetime: SshGrantLifetime,
        set_default: bool,
    },
    ApproveGrant {
        request_id: String,
        approved: bool,
        target_id: Option<String>,
        root: Option<String>,
        capabilities: Option<SshCapabilitiesView>,
        lifetime: SshGrantLifetime,
        set_default: bool,
    },
    InspectGrantTarget {
        request_id: String,
        target_id: String,
    },
    UseBinding {
        binding_id: String,
    },
    RevokeBinding {
        binding_id: String,
    },
    OpenProject {
        target_id: String,
        root: String,
        binding_id: String,
        capabilities: SshCapabilitiesView,
    },
    ApproveOperation {
        approval_id: String,
        approved: bool,
    },
    AnswerAuthentication {
        challenge_id: String,
        connection_generation: u64,
        target_id: String,
        host_key_decision: Option<xai_grok_shell::ssh::SshHostKeyDecision>,
        remember: bool,
        secret: Option<SshSecret>,
        answers: Vec<SshSecret>,
    },
}

const MANAGER_SHORTCUTS: &[Shortcut<'static>] = &[
    Shortcut {
        label: "j/k move",
        clickable: false,
        id: 0,
    },
    Shortcut {
        label: "Enter connect",
        clickable: false,
        id: 0,
    },
    Shortcut {
        label: "a add",
        clickable: false,
        id: 0,
    },
    Shortcut {
        label: "g grant",
        clickable: false,
        id: 0,
    },
    Shortcut {
        label: "u use",
        clickable: false,
        id: 0,
    },
    Shortcut {
        label: "r revoke / refresh",
        clickable: false,
        id: 0,
    },
    Shortcut {
        label: "d diagnostic",
        clickable: false,
        id: 0,
    },
    Shortcut {
        label: "o open project",
        clickable: false,
        id: 0,
    },
    Shortcut {
        label: "Esc close",
        clickable: false,
        id: 0,
    },
];

const OPERATION_APPROVAL_SHORTCUTS: &[Shortcut<'static>] = &[
    Shortcut {
        label: "↑/↓ inspect",
        clickable: false,
        id: 0,
    },
    Shortcut {
        label: "y allow after review",
        clickable: false,
        id: 0,
    },
    Shortcut {
        label: "n deny",
        clickable: false,
        id: 0,
    },
    Shortcut {
        label: "Esc deny",
        clickable: false,
        id: 0,
    },
];

const AUTHENTICATION_SHORTCUTS: &[Shortcut<'static>] = &[
    Shortcut {
        label: "Enter submit",
        clickable: false,
        id: 0,
    },
    Shortcut {
        label: "PgUp/PgDn scroll",
        clickable: false,
        id: 0,
    },
    Shortcut {
        label: "Esc cancel",
        clickable: false,
        id: 0,
    },
];

const UNKNOWN_HOST_KEY_SHORTCUTS: &[Shortcut<'static>] = &[
    Shortcut {
        label: "y trust once",
        clickable: false,
        id: 0,
    },
    Shortcut {
        label: "s trust and save",
        clickable: false,
        id: 0,
    },
    Shortcut {
        label: "n/Esc reject",
        clickable: false,
        id: 0,
    },
];

const REPLACE_HOST_KEY_SHORTCUTS: &[Shortcut<'static>] = &[
    Shortcut {
        label: "r replace and save",
        clickable: false,
        id: 0,
    },
    Shortcut {
        label: "n/Esc reject",
        clickable: false,
        id: 0,
    },
    Shortcut {
        label: "↑/↓ inspect",
        clickable: false,
        id: 0,
    },
];

const MANUAL_HOST_KEY_REMEDIATION_SHORTCUTS: &[Shortcut<'static>] = &[
    Shortcut {
        label: "manual known_hosts remediation",
        clickable: false,
        id: 0,
    },
    Shortcut {
        label: "n/Esc reject",
        clickable: false,
        id: 0,
    },
    Shortcut {
        label: "↑/↓ inspect",
        clickable: false,
        id: 0,
    },
];

const DIAGNOSTIC_SHORTCUTS: &[Shortcut<'static>] = &[
    Shortcut {
        label: "↑/↓ or PgUp/PgDn scroll",
        clickable: false,
        id: 0,
    },
    Shortcut {
        label: "Esc back",
        clickable: false,
        id: 0,
    },
];

fn sizing(compact: bool) -> ModalSizing {
    ModalSizing {
        width_pct: 0.78,
        max_width: 112,
        min_width: 52,
        v_margin: 3,
        h_pad: 2,
        v_pad: 1,
        footer_lines: 2,
    }
    .with_compact(compact)
}

fn window_config<'a>(
    title: &'a str,
    compact: bool,
    shortcuts: &'a [Shortcut<'a>],
) -> ModalWindowConfig<'a> {
    ModalWindowConfig {
        title,
        tabs: None,
        shortcuts,
        sizing: sizing(compact),
        fold_info: None,
    }
}

/// Render the current local-only SSH overlay. `None` means the modal is too small to render.
pub fn render_ssh_modal(
    buf: &mut Buffer,
    area: Rect,
    state: &mut SshManagerState,
    compact: bool,
    theme: &Theme,
) -> Option<(u16, u16)> {
    let (title, shortcuts): (&str, &[Shortcut<'_>]) = match &state.page {
        SshModalPage::Manager => ("SSH targets", MANAGER_SHORTCUTS),
        SshModalPage::Add(_) => (
            "Add SSH target",
            &[
                Shortcut {
                    label: "Tab field",
                    clickable: false,
                    id: 0,
                },
                Shortcut {
                    label: "Enter save",
                    clickable: false,
                    id: 0,
                },
                Shortcut {
                    label: "Esc back",
                    clickable: false,
                    id: 0,
                },
            ],
        ),
        SshModalPage::Grant(_) => (
            "SSH access grant",
            &[
                Shortcut {
                    label: "Alt+r/w/x capability",
                    clickable: false,
                    id: 0,
                },
                Shortcut {
                    label: "Alt+l lifetime",
                    clickable: false,
                    id: 0,
                },
                Shortcut {
                    label: "Alt+d default",
                    clickable: false,
                    id: 0,
                },
                Shortcut {
                    label: "Enter allow",
                    clickable: false,
                    id: 0,
                },
                Shortcut {
                    label: "Esc deny",
                    clickable: false,
                    id: 0,
                },
            ],
        ),
        SshModalPage::OperationApproval(_) => {
            ("SSH operation approval", OPERATION_APPROVAL_SHORTCUTS)
        }
        SshModalPage::Authentication(card) => match &card.kind {
            SshAuthKind::HostKey {
                status,
                previous_keys,
                can_replace,
                ..
            } if changed_host_key(status, previous_keys) => (
                "SSH host key changed",
                if *can_replace {
                    REPLACE_HOST_KEY_SHORTCUTS
                } else {
                    MANUAL_HOST_KEY_REMEDIATION_SHORTCUTS
                },
            ),
            SshAuthKind::HostKey { .. } => {
                ("SSH host key confirmation", UNKNOWN_HOST_KEY_SHORTCUTS)
            }
            _ => (card.kind.title(), AUTHENTICATION_SHORTCUTS),
        },
        SshModalPage::Diagnostic(_) => ("SSH diagnostic", DIAGNOSTIC_SHORTCUTS),
    };
    let config = window_config(title, compact, shortcuts);
    let areas = modal_window::render_modal_window(buf, area, &mut state.window, &config, theme)?;
    let content = areas.content;
    match &mut state.page {
        SshModalPage::Manager => render_manager(buf, content, state, theme),
        SshModalPage::Add(form) => render_add(buf, content, form, theme),
        SshModalPage::Grant(card) => render_grant(buf, content, card, theme),
        SshModalPage::OperationApproval(card) => {
            render_operation_approval(buf, content, card, theme)
        }
        SshModalPage::Authentication(card) => render_authentication(buf, content, card, theme),
        SshModalPage::Diagnostic(card) => render_diagnostic(buf, content, card, theme),
    }
    None
}

fn render_manager(buf: &mut Buffer, area: Rect, state: &SshManagerState, theme: &Theme) {
    if area.height == 0 {
        return;
    }
    if state.loading {
        buf.set_string(
            area.x,
            area.y,
            "Loading configured targets…",
            Style::default().fg(theme.text_secondary),
        );
        return;
    }
    if state.targets.is_empty() {
        buf.set_string(
            area.x,
            area.y,
            "No SSH targets. OpenSSH config aliases appear here automatically; press a to add one.",
            Style::default().fg(theme.text_secondary),
        );
        render_message(buf, area, state.message.as_ref(), theme);
        return;
    }
    let row_height = 3u16;
    let visible = area.height.saturating_sub(2) / row_height;
    let start = state
        .selected
        .saturating_sub(visible.saturating_sub(1) as usize);
    for (offset, target) in state
        .targets
        .iter()
        .skip(start)
        .take(visible as usize)
        .enumerate()
    {
        let y = area.y + offset as u16 * row_height;
        let selected = start + offset == state.selected;
        let base = if selected {
            Style::default()
                .fg(theme.accent_user)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(theme.text_secondary)
        };
        let prefix = if selected { "› " } else { "  " };
        let line = format!("{prefix}{}  [{}]", target.label, target.source);
        buf.set_stringn(area.x, y, line, area.width as usize, base);
        let connection = if target.connected {
            "connected"
        } else {
            "disconnected"
        };
        let detail = format!(
            "  {} · {} · {}",
            target.effective_address,
            connection,
            target.grant.summary()
        );
        buf.set_stringn(
            area.x,
            y.saturating_add(1),
            detail,
            area.width as usize,
            Style::default().fg(theme.gray),
        );
        buf.set_stringn(
            area.x,
            y.saturating_add(2),
            format!("  {}", target.connection_detail),
            area.width as usize,
            Style::default().fg(theme.gray_dim),
        );
    }
    render_message(buf, area, state.message.as_ref(), theme);
}

fn render_diagnostic(buf: &mut Buffer, area: Rect, card: &mut SshDiagnosticCard, theme: &Theme) {
    if area.height == 0 {
        return;
    }
    let mut lines = Vec::new();
    append_wrapped_authentication_line(
        &mut lines,
        "Full SSH diagnostic:",
        AuthenticationLineTone::Warning,
        area.width as usize,
    );
    append_wrapped_authentication_line(
        &mut lines,
        "",
        AuthenticationLineTone::Normal,
        area.width as usize,
    );
    append_wrapped_authentication_line(
        &mut lines,
        &card.message,
        AuthenticationLineTone::Error,
        area.width as usize,
    );
    let height = area.height as usize;
    let body_height = if lines.len() > height && height > 1 {
        height - 1
    } else {
        height
    };
    card.max_scroll_offset = lines.len().saturating_sub(body_height);
    card.scroll_offset = card.scroll_offset.min(card.max_scroll_offset);
    for (index, (line, tone)) in lines
        .iter()
        .skip(card.scroll_offset)
        .take(body_height)
        .enumerate()
    {
        let style = match tone {
            AuthenticationLineTone::Normal => Style::default().fg(theme.text_secondary),
            AuthenticationLineTone::Muted => Style::default().fg(theme.gray),
            AuthenticationLineTone::Warning | AuthenticationLineTone::Error => Style::default()
                .fg(theme.accent_error)
                .add_modifier(Modifier::BOLD),
        };
        buf.set_stringn(
            area.x,
            area.y.saturating_add(index as u16),
            line,
            area.width as usize,
            style,
        );
    }
    if card.max_scroll_offset > 0 && height > 1 {
        buf.set_stringn(
            area.x,
            area.bottom().saturating_sub(1),
            format!(
                "Diagnostic {} of {} · ↑/↓ or PgUp/PgDn scroll",
                card.scroll_offset + 1,
                card.max_scroll_offset + 1
            ),
            area.width as usize,
            Style::default().fg(theme.gray),
        );
    }
}

fn render_add(buf: &mut Buffer, area: Rect, form: &SshManualTargetForm, theme: &Theme) {
    let mut y = area.y;
    for field in ManualTargetField::ALL {
        if y >= area.bottom() {
            break;
        }
        let selected = form.active == field;
        let style = if selected {
            Style::default()
                .fg(theme.accent_user)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(theme.text_secondary)
        };
        let label = format!("{}: ", field.label());
        buf.set_string(area.x, y, &label, style);
        let editor = form.editor(field);
        buf.set_stringn(
            area.x + label.len() as u16,
            y,
            editor.text(),
            area.width.saturating_sub(label.len() as u16) as usize,
            Style::default().fg(theme.text_secondary),
        );
        y = y.saturating_add(1);
    }
    if let Some(error) = form.error.as_deref()
        && y < area.bottom()
    {
        buf.set_stringn(
            area.x,
            y,
            error,
            area.width as usize,
            Style::default().fg(theme.accent_error),
        );
    }
}

fn render_grant(buf: &mut Buffer, area: Rect, card: &SshGrantCard, theme: &Theme) {
    let identity = match card.identity.as_deref() {
        Some(identity) => format!("Verified SSH identity: {identity}"),
        None => "Connection identity will be verified before this grant can be approved.".into(),
    };
    let mut lines = vec![
        format!("Target: {} ({})", card.target_label, card.target_id),
        identity,
        format!("Root: {}", card.root.text()),
        format!(
            "Capabilities: [{}] read  [{}] write  [{}] run",
            if card.capabilities.read { "x" } else { " " },
            if card.capabilities.write { "x" } else { " " },
            if card.capabilities.execute { "x" } else { " " },
        ),
        format!("Lifetime: {}", card.lifetime.label()),
        format!(
            "Default SSH target: {}",
            if card.set_default { "yes" } else { "no" }
        ),
    ];
    if card.agent_requested {
        lines.push("This access request came from the agent; allowing it does not expose credentials to it.".into());
    }
    if card.capabilities.execute {
        lines.push(
            "Warning: run executes with this SSH user's remote privileges; cwd is not a sandbox."
                .into(),
        );
    }
    if let Some(reason) = card.reason.as_deref() {
        lines.push(format!("Reason: {reason}"));
    }
    for (index, line) in lines.iter().enumerate() {
        let y = area.y + index as u16;
        if y >= area.bottom() {
            break;
        }
        let warning = line.starts_with("Warning:");
        let style = if warning {
            Style::default()
                .fg(theme.accent_error)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(theme.text_secondary)
        };
        buf.set_stringn(area.x, y, line, area.width as usize, style);
    }
    if let Some(error) = card.error.as_deref() {
        let y = area.bottom().saturating_sub(1);
        buf.set_stringn(
            area.x,
            y,
            error,
            area.width as usize,
            Style::default().fg(theme.accent_error),
        );
    }
}

fn render_operation_approval(
    buf: &mut Buffer,
    area: Rect,
    card: &mut SshOperationApprovalCard,
    theme: &Theme,
) {
    if area.height == 0 {
        return;
    }
    let mut lines = operation_approval_lines(card, area.width as usize);
    card.max_scroll_offset = lines.len().saturating_sub(area.height as usize);
    card.scroll_offset = card.scroll_offset.min(card.max_scroll_offset);
    card.reviewed_to_end =
        card.max_scroll_offset == 0 || card.scroll_offset >= card.max_scroll_offset;
    // The review status is part of the scrollable content, so regenerate it after calculating
    // the viewport-specific end position.
    lines = operation_approval_lines(card, area.width as usize);

    for (index, line) in lines
        .iter()
        .skip(card.scroll_offset)
        .take(area.height as usize)
        .enumerate()
    {
        let y = area.y.saturating_add(index as u16);
        let style = if line.starts_with("Allow this") || line.starts_with("Review all") {
            Style::default()
                .fg(theme.accent_error)
                .add_modifier(Modifier::BOLD)
        } else if line.starts_with("Error:") {
            Style::default().fg(theme.accent_error)
        } else {
            Style::default().fg(theme.text_secondary)
        };
        buf.set_stringn(area.x, y, line, area.width as usize, style);
    }
}

fn operation_approval_lines(card: &SshOperationApprovalCard, width: usize) -> Vec<String> {
    let width = width.max(1);
    let options = textwrap::Options::new(width)
        .break_words(true)
        .wrap_algorithm(textwrap::WrapAlgorithm::FirstFit);
    let mut lines = vec![format!(
        "Target: {} ({})",
        card.target_label, card.binding_id
    )];
    if let Some(identity) = card.target_identity.as_deref() {
        lines.push(format!("Verified SSH identity: {identity}"));
    }
    lines.extend([
        card.title.clone(),
        String::new(),
        "Remote operation details:".into(),
    ]);
    for paragraph in card.detail.lines() {
        if paragraph.is_empty() {
            lines.push(String::new());
        } else {
            lines.extend(
                textwrap::wrap(paragraph, &options)
                    .into_iter()
                    .map(std::borrow::Cow::into_owned),
            );
        }
    }
    if card.detail.is_empty() {
        lines.push("(No additional detail was supplied.)".into());
    }
    lines.push(String::new());
    if let Some(error) = card.error.as_deref() {
        lines.extend(
            textwrap::wrap(&format!("Error: {error}"), &options)
                .into_iter()
                .map(std::borrow::Cow::into_owned),
        );
    }
    lines.push(if card.max_scroll_offset > 0 {
        format!(
            "Details position {} of {} · {}",
            card.scroll_offset + 1,
            card.max_scroll_offset + 1,
            if card.reviewed_to_end {
                "all details reviewed"
            } else {
                "scroll to review all details before allowing"
            }
        )
    } else {
        "All details reviewed.".into()
    });
    lines.push(if card.submitting {
        "Submitting remote operation decision…".into()
    } else {
        "Allow this one remote operation? y allow · n deny".into()
    });
    lines
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AuthenticationLineTone {
    Normal,
    Muted,
    Warning,
    Error,
}

fn append_wrapped_authentication_line(
    lines: &mut Vec<(String, AuthenticationLineTone)>,
    text: &str,
    tone: AuthenticationLineTone,
    width: usize,
) {
    let options = textwrap::Options::new(width.max(1))
        .break_words(true)
        .wrap_algorithm(textwrap::WrapAlgorithm::FirstFit);
    if text.is_empty() {
        lines.push((String::new(), tone));
        return;
    }
    for paragraph in text.split('\n') {
        if paragraph.is_empty() {
            lines.push((String::new(), tone));
        } else {
            lines.extend(
                textwrap::wrap(paragraph, &options)
                    .into_iter()
                    .map(|line| (line.into_owned(), tone)),
            );
        }
    }
}

fn changed_host_key(status: &str, previous_keys: &[String]) -> bool {
    status.eq_ignore_ascii_case("changed") || !previous_keys.is_empty()
}

fn authentication_lines(card: &SshAuthCard, width: usize) -> Vec<(String, AuthenticationLineTone)> {
    let mut lines = Vec::new();
    match &card.kind {
        SshAuthKind::HostKey {
            hostname,
            port,
            algorithm,
            fingerprint,
            status,
            previous_keys,
            can_replace,
        } => {
            let changed = changed_host_key(status, previous_keys);
            append_wrapped_authentication_line(
                &mut lines,
                &format!("Target: {}", card.target_id),
                AuthenticationLineTone::Normal,
                width,
            );
            append_wrapped_authentication_line(
                &mut lines,
                &format!("Endpoint: {hostname}:{port}"),
                AuthenticationLineTone::Normal,
                width,
            );
            append_wrapped_authentication_line(
                &mut lines,
                &format!("Presented key: {algorithm} {fingerprint}"),
                AuthenticationLineTone::Normal,
                width,
            );
            append_wrapped_authentication_line(
                &mut lines,
                &format!("Host key status: {status}"),
                if changed {
                    AuthenticationLineTone::Warning
                } else {
                    AuthenticationLineTone::Muted
                },
                width,
            );
            append_wrapped_authentication_line(
                &mut lines,
                "",
                AuthenticationLineTone::Normal,
                width,
            );
            if changed {
                append_wrapped_authentication_line(
                    &mut lines,
                    "WARNING: This endpoint presented a changed host key.",
                    AuthenticationLineTone::Warning,
                    width,
                );
                append_wrapped_authentication_line(
                    &mut lines,
                    "An attacker could be impersonating this host. Verify the new fingerprint out of band before replacing a stored key.",
                    AuthenticationLineTone::Warning,
                    width,
                );
                append_wrapped_authentication_line(
                    &mut lines,
                    "Previously stored key record(s):",
                    AuthenticationLineTone::Muted,
                    width,
                );
                for previous_key in previous_keys {
                    append_wrapped_authentication_line(
                        &mut lines,
                        &format!("• {previous_key}"),
                        AuthenticationLineTone::Normal,
                        width,
                    );
                }
                if *can_replace {
                    append_wrapped_authentication_line(
                        &mut lines,
                        "Press r to replace the stored key and save the new key. n or Esc rejects.",
                        AuthenticationLineTone::Warning,
                        width,
                    );
                } else {
                    append_wrapped_authentication_line(
                        &mut lines,
                        "Automatic replacement is unavailable. After verifying it, update or remove the listed known_hosts record manually, then reconnect. n or Esc rejects.",
                        AuthenticationLineTone::Warning,
                        width,
                    );
                }
            } else {
                append_wrapped_authentication_line(
                    &mut lines,
                    "Unknown host key. Verify its fingerprint out of band before trusting it.",
                    AuthenticationLineTone::Warning,
                    width,
                );
                append_wrapped_authentication_line(
                    &mut lines,
                    "y trusts once · s trusts and saves · n or Esc rejects",
                    AuthenticationLineTone::Warning,
                    width,
                );
            }
        }
        SshAuthKind::Password {
            username, message, ..
        }
        | SshAuthKind::PrivateKeyPassphrase {
            username, message, ..
        } => {
            append_wrapped_authentication_line(
                &mut lines,
                &format!("Target: {}", card.target_id),
                AuthenticationLineTone::Normal,
                width,
            );
            append_wrapped_authentication_line(
                &mut lines,
                &format!("User: {username}"),
                AuthenticationLineTone::Normal,
                width,
            );
            append_wrapped_authentication_line(
                &mut lines,
                message,
                AuthenticationLineTone::Muted,
                width,
            );
            append_wrapped_authentication_line(
                &mut lines,
                "",
                AuthenticationLineTone::Normal,
                width,
            );
            let bullets = card
                .answers
                .first()
                .map(|answer| "•".repeat(answer.text().chars().count()))
                .unwrap_or_default();
            append_wrapped_authentication_line(
                &mut lines,
                &format!("› {bullets}"),
                AuthenticationLineTone::Normal,
                width,
            );
            if card.can_remember() {
                append_wrapped_authentication_line(
                    &mut lines,
                    &format!(
                        "[{}] remember in system credential store  (Alt+r)",
                        if card.remember { "x" } else { " " }
                    ),
                    AuthenticationLineTone::Muted,
                    width,
                );
            }
        }
        SshAuthKind::KeyboardInteractive {
            name,
            instruction,
            prompts,
        } => {
            append_wrapped_authentication_line(
                &mut lines,
                name,
                AuthenticationLineTone::Normal,
                width,
            );
            append_wrapped_authentication_line(
                &mut lines,
                instruction,
                AuthenticationLineTone::Muted,
                width,
            );
            for (index, prompt) in prompts.iter().enumerate() {
                append_wrapped_authentication_line(
                    &mut lines,
                    prompt,
                    AuthenticationLineTone::Normal,
                    width,
                );
                let bullets = card
                    .answers
                    .get(index)
                    .map(|answer| "•".repeat(answer.text().chars().count()))
                    .unwrap_or_default();
                append_wrapped_authentication_line(
                    &mut lines,
                    &format!(
                        "{} {bullets}",
                        if index == card.active_answer {
                            "›"
                        } else {
                            " "
                        }
                    ),
                    AuthenticationLineTone::Normal,
                    width,
                );
            }
        }
    }
    if let Some(error) = card.error.as_deref() {
        append_wrapped_authentication_line(&mut lines, "", AuthenticationLineTone::Error, width);
        append_wrapped_authentication_line(
            &mut lines,
            &format!("Authentication error: {error}"),
            AuthenticationLineTone::Error,
            width,
        );
    }
    lines
}

fn render_authentication(buf: &mut Buffer, area: Rect, card: &mut SshAuthCard, theme: &Theme) {
    if area.height == 0 {
        return;
    }
    let lines = authentication_lines(card, area.width as usize);
    let height = area.height as usize;
    let body_height = if lines.len() > height && height > 1 {
        height - 1
    } else {
        height
    };
    card.max_scroll_offset = lines.len().saturating_sub(body_height);
    card.scroll_offset = card.scroll_offset.min(card.max_scroll_offset);
    for (index, (line, tone)) in lines
        .iter()
        .skip(card.scroll_offset)
        .take(body_height)
        .enumerate()
    {
        let style = match tone {
            AuthenticationLineTone::Normal => Style::default().fg(theme.text_secondary),
            AuthenticationLineTone::Muted => Style::default().fg(theme.gray),
            AuthenticationLineTone::Warning | AuthenticationLineTone::Error => Style::default()
                .fg(theme.accent_error)
                .add_modifier(Modifier::BOLD),
        };
        buf.set_stringn(
            area.x,
            area.y.saturating_add(index as u16),
            line,
            area.width as usize,
            style,
        );
    }
    if card.max_scroll_offset > 0 && height > 1 {
        let position = format!(
            "Details {} of {} · ↑/↓ or PgUp/PgDn scroll",
            card.scroll_offset + 1,
            card.max_scroll_offset + 1
        );
        buf.set_stringn(
            area.x,
            area.bottom().saturating_sub(1),
            position,
            area.width as usize,
            Style::default().fg(theme.gray),
        );
    }
}

fn render_message(buf: &mut Buffer, area: Rect, message: Option<&(String, bool)>, theme: &Theme) {
    let Some((text, error)) = message else {
        return;
    };
    let y = area.bottom().saturating_sub(1);
    let (summary, style) = if *error {
        (
            "SSH error — press d to inspect the full diagnostic",
            Style::default().fg(theme.accent_error),
        )
    } else {
        (text.as_str(), Style::default().fg(theme.text_secondary))
    };
    buf.set_stringn(area.x, y, summary, area.width as usize, style);
}
/// Handle a key while the SSH modal has focus.
pub fn handle_ssh_key(state: &mut SshManagerState, key: &KeyEvent) -> SshModalOutcome {
    let config = window_config("SSH", false, &[]);
    match modal_window::handle_modal_key(&mut state.window, key, &config) {
        ModalWindowOutcome::CloseRequested => return close_current_page(state),
        ModalWindowOutcome::Handled => return SshModalOutcome::Changed,
        ModalWindowOutcome::Unhandled => {}
        _ => {}
    }
    if matches!(&state.page, SshModalPage::Manager) {
        return handle_manager_key(state, key);
    }
    let outcome = match &mut state.page {
        SshModalPage::Add(form) => handle_add_key(form, key),
        SshModalPage::Grant(card) => handle_grant_key(card, key),
        SshModalPage::OperationApproval(card) => handle_operation_approval_key(card, key),
        SshModalPage::Authentication(card) => handle_authentication_key(card, key),
        SshModalPage::Diagnostic(card) => handle_diagnostic_key(card, key),
        SshModalPage::Manager => unreachable!("manager handled before borrowing modal page"),
    };
    if matches!(&outcome, SshModalOutcome::AnswerAuthentication { .. }) {
        state.return_to_manager();
    }
    outcome
}

/// Paste directly into the focused non-secret or secret local editor. The paste is never placed in
/// chat state, notifications, or a replay buffer.
pub fn handle_ssh_paste(state: &mut SshManagerState, text: &str) -> SshModalOutcome {
    let outcome = match &mut state.page {
        SshModalPage::Add(form) => form.editor_mut().insert_paste(text),
        SshModalPage::Grant(card) => card.root.insert_paste(text),
        SshModalPage::Authentication(card) => card
            .answer_mut()
            .map(|answer| answer.insert_paste(text))
            .unwrap_or(LineEditOutcome::Unhandled),
        SshModalPage::Manager
        | SshModalPage::OperationApproval(_)
        | SshModalPage::Diagnostic(_) => {
            return SshModalOutcome::Unchanged;
        }
    };
    line_outcome(outcome)
}

/// Mouse handling is limited to modal chrome and scrolling review surfaces; operational actions
/// remain keyboard-confirmed so a stale row map can never connect, grant, or revoke the wrong target.
pub fn handle_ssh_mouse(state: &mut SshManagerState, mouse: &MouseEvent) -> SshModalOutcome {
    match modal_window::handle_modal_mouse(&mut state.window, mouse.kind, mouse.column, mouse.row) {
        ModalWindowOutcome::CloseRequested => return close_current_page(state),
        ModalWindowOutcome::Handled => return SshModalOutcome::Changed,
        ModalWindowOutcome::Unhandled => {}
        _ => return SshModalOutcome::Unchanged,
    }
    let delta = match mouse.kind {
        crossterm::event::MouseEventKind::ScrollUp => Some(-3isize),
        crossterm::event::MouseEventKind::ScrollDown => Some(3isize),
        _ => None,
    };
    let Some(delta) = delta else {
        return SshModalOutcome::Unchanged;
    };
    let (scroll, max_scroll_offset) = match &mut state.page {
        SshModalPage::Authentication(card) => (&mut card.scroll_offset, card.max_scroll_offset),
        SshModalPage::Diagnostic(card) => (&mut card.scroll_offset, card.max_scroll_offset),
        _ => return SshModalOutcome::Unchanged,
    };
    *scroll = if delta.is_negative() {
        scroll.saturating_sub(delta.unsigned_abs())
    } else {
        scroll.saturating_add(delta as usize).min(max_scroll_offset)
    };
    SshModalOutcome::Changed
}

fn close_current_page(state: &mut SshManagerState) -> SshModalOutcome {
    if matches!(
        &state.page,
        SshModalPage::Add(_) | SshModalPage::Diagnostic(_)
    ) {
        state.return_to_manager();
        return SshModalOutcome::Changed;
    }
    if let SshModalPage::Authentication(card) = &mut state.page {
        let challenge_id = card.challenge_id.clone();
        let connection_generation = card.connection_generation;
        let target_id = card.target_id.clone();
        let host_key_decision = matches!(&card.kind, SshAuthKind::HostKey { .. })
            .then_some(xai_grok_shell::ssh::SshHostKeyDecision::Reject);
        card.clear_answers();
        state.return_to_manager();
        return SshModalOutcome::AnswerAuthentication {
            challenge_id,
            connection_generation,
            target_id,
            host_key_decision,
            remember: false,
            secret: None,
            answers: Vec::new(),
        };
    }
    match &state.page {
        SshModalPage::Manager => state
            .pending_grant
            .as_ref()
            .map(|request| SshModalOutcome::ApproveGrant {
                request_id: request.request_id.clone(),
                approved: false,
                target_id: None,
                root: None,
                capabilities: None,
                lifetime: SshGrantLifetime::CurrentSession,
                set_default: false,
            })
            .unwrap_or(SshModalOutcome::Close),
        SshModalPage::Grant(card) => SshModalOutcome::ApproveGrant {
            request_id: card.request_id.clone(),
            approved: false,
            target_id: None,
            root: None,
            capabilities: None,
            lifetime: card.lifetime,
            set_default: card.set_default,
        },
        SshModalPage::OperationApproval(card) => SshModalOutcome::ApproveOperation {
            approval_id: card.approval_id.clone(),
            approved: false,
        },
        SshModalPage::Authentication(_) => {
            unreachable!("authentication answers were cleared before read-only match")
        }
        SshModalPage::Add(_) => unreachable!("add page returned before read-only match"),
        SshModalPage::Diagnostic(_) => unreachable!("diagnostic returned before read-only match"),
    }
}

fn handle_manager_key(state: &mut SshManagerState, key: &KeyEvent) -> SshModalOutcome {
    match key.code {
        KeyCode::Esc => close_current_page(state),
        KeyCode::Up | KeyCode::Char('k') if key.modifiers.is_empty() => {
            state.selected = state.selected.saturating_sub(1);
            SshModalOutcome::Changed
        }
        KeyCode::Down | KeyCode::Char('j') if key.modifiers.is_empty() => {
            if state.selected + 1 < state.targets.len() {
                state.selected += 1;
            }
            SshModalOutcome::Changed
        }
        KeyCode::Char('a') if key.modifiers.is_empty() => {
            state.page = SshModalPage::Add(Default::default());
            SshModalOutcome::Changed
        }
        KeyCode::Char('d') if key.modifiers.is_empty() => {
            if state.open_error_diagnostic() {
                SshModalOutcome::Changed
            } else {
                SshModalOutcome::Unchanged
            }
        }
        KeyCode::Char('r') if key.modifiers.is_empty() && state.selected_target().is_none() => {
            SshModalOutcome::Refresh
        }
        KeyCode::Char('r') if key.modifiers.is_empty() => match state.selected_target() {
            Some(target) => match &target.grant {
                SshGrantView::Granted { binding_id, .. } => SshModalOutcome::RevokeBinding {
                    binding_id: binding_id.clone(),
                },
                SshGrantView::NotGranted | SshGrantView::Revoking { .. } => {
                    SshModalOutcome::Refresh
                }
            },
            None => SshModalOutcome::Refresh,
        },
        KeyCode::Enter => match state.selected_target() {
            Some(target) if target.connected => SshModalOutcome::Disconnect {
                target_id: target.target_id.clone(),
            },
            Some(target) => SshModalOutcome::Connect {
                target_id: target.target_id.clone(),
            },
            None => SshModalOutcome::Unchanged,
        },
        KeyCode::Char('g') if key.modifiers.is_empty() => {
            let Some((target_id, target_label, granted_root)) =
                state.selected_target().map(|target| {
                    (
                        target.target_id.clone(),
                        target.label.clone(),
                        target
                            .grant
                            .granted_root()
                            .map(str::to_owned)
                            .unwrap_or_default(),
                    )
                })
            else {
                return SshModalOutcome::Unchanged;
            };
            if state.session_id.is_none() {
                state.show_error("Open or create a session before granting SSH access.");
                return SshModalOutcome::Changed;
            }
            if let Some(request_id) = state
                .pending_grant
                .as_ref()
                .map(|request| request.request_id.clone())
            {
                return SshModalOutcome::InspectGrantTarget {
                    request_id,
                    target_id,
                };
            }
            state.page = SshModalPage::Grant(SshGrantCard::new(
                String::new(),
                target_id,
                target_label,
                None,
                granted_root,
                None,
                false,
            ));
            SshModalOutcome::Changed
        }
        KeyCode::Char('u') if key.modifiers.is_empty() => state
            .selected_target()
            .and_then(|target| target.grant.binding_id())
            .map(|binding_id| SshModalOutcome::UseBinding {
                binding_id: binding_id.to_owned(),
            })
            .unwrap_or(SshModalOutcome::Unchanged),
        KeyCode::Char('o') if key.modifiers.is_empty() => match state.selected_target() {
            Some(target) => match &target.grant {
                SshGrantView::Granted {
                    binding_id,
                    root,
                    capabilities,
                    ..
                } => SshModalOutcome::OpenProject {
                    target_id: target.target_id.clone(),
                    root: root.clone(),
                    binding_id: binding_id.clone(),
                    capabilities: *capabilities,
                },
                SshGrantView::NotGranted | SshGrantView::Revoking { .. } => {
                    state.show_error("Grant a remote root before opening an SSH project.");
                    SshModalOutcome::Changed
                }
            },
            None => SshModalOutcome::Unchanged,
        },
        _ => SshModalOutcome::Unchanged,
    }
}

fn handle_add_key(form: &mut SshManualTargetForm, key: &KeyEvent) -> SshModalOutcome {
    match key.code {
        KeyCode::Esc => SshModalOutcome::Close,
        KeyCode::Tab => {
            form.active = form.active.next(false);
            SshModalOutcome::Changed
        }
        KeyCode::BackTab => {
            form.active = form.active.next(true);
            SshModalOutcome::Changed
        }
        KeyCode::Enter => match form.draft() {
            Ok(draft) => SshModalOutcome::AddTarget(draft),
            Err(error) => {
                form.error = Some(error);
                SshModalOutcome::Changed
            }
        },
        _ => line_outcome(form.editor_mut().handle_key(key)),
    }
}

fn handle_grant_key(card: &mut SshGrantCard, key: &KeyEvent) -> SshModalOutcome {
    match key.code {
        KeyCode::Esc => SshModalOutcome::ApproveGrant {
            request_id: card.request_id.clone(),
            approved: false,
            target_id: None,
            root: None,
            capabilities: None,
            lifetime: card.lifetime,
            set_default: card.set_default,
        },
        KeyCode::Char('r') if key.modifiers == KeyModifiers::ALT => {
            card.capabilities.read = !card.capabilities.read;
            SshModalOutcome::Changed
        }
        KeyCode::Char('w') if key.modifiers == KeyModifiers::ALT => {
            card.capabilities.write = !card.capabilities.write;
            SshModalOutcome::Changed
        }
        KeyCode::Char('x') if key.modifiers == KeyModifiers::ALT => {
            card.capabilities.execute = !card.capabilities.execute;
            SshModalOutcome::Changed
        }
        KeyCode::Char('l') if key.modifiers == KeyModifiers::ALT => {
            card.lifetime = card.lifetime.toggle();
            SshModalOutcome::Changed
        }
        KeyCode::Char('d') if key.modifiers == KeyModifiers::ALT => {
            card.set_default = !card.set_default;
            SshModalOutcome::Changed
        }
        KeyCode::Enter => {
            let root = card.root.text().trim();
            if root.is_empty() {
                card.error = Some("A remote root is required.".into());
                return SshModalOutcome::Changed;
            }
            if !card.capabilities.any() {
                card.error = Some("Choose at least one capability.".into());
                return SshModalOutcome::Changed;
            }
            if card.request_id.is_empty() {
                SshModalOutcome::RequestGrant {
                    target_id: card.target_id.clone(),
                    root: root.to_owned(),
                    capabilities: card.capabilities,
                    lifetime: card.lifetime,
                    set_default: card.set_default,
                }
            } else {
                SshModalOutcome::ApproveGrant {
                    request_id: card.request_id.clone(),
                    approved: true,
                    target_id: Some(card.target_id.clone()),
                    root: Some(root.to_owned()),
                    capabilities: Some(card.capabilities),
                    lifetime: card.lifetime,
                    set_default: card.set_default,
                }
            }
        }
        _ => line_outcome(card.root.handle_key(key)),
    }
}

fn handle_operation_approval_key(
    card: &mut SshOperationApprovalCard,
    key: &KeyEvent,
) -> SshModalOutcome {
    if card.submitting {
        return SshModalOutcome::Unchanged;
    }
    match key.code {
        KeyCode::Up | KeyCode::Char('k') if key.modifiers.is_empty() => {
            card.scroll_offset = card.scroll_offset.saturating_sub(1);
            card.error = None;
            SshModalOutcome::Changed
        }
        KeyCode::Down | KeyCode::Char('j') if key.modifiers.is_empty() => {
            card.scroll_offset = card.scroll_offset.saturating_add(1);
            card.error = None;
            SshModalOutcome::Changed
        }
        KeyCode::PageUp => {
            card.scroll_offset = card.scroll_offset.saturating_sub(8);
            card.error = None;
            SshModalOutcome::Changed
        }
        KeyCode::PageDown => {
            card.scroll_offset = card.scroll_offset.saturating_add(8);
            card.error = None;
            SshModalOutcome::Changed
        }
        KeyCode::Home => {
            card.scroll_offset = 0;
            card.error = None;
            SshModalOutcome::Changed
        }
        KeyCode::End => {
            card.scroll_offset = card.max_scroll_offset;
            card.error = None;
            SshModalOutcome::Changed
        }
        KeyCode::Char('y') if key.modifiers.is_empty() && card.reviewed_to_end => {
            SshModalOutcome::ApproveOperation {
                approval_id: card.approval_id.clone(),
                approved: true,
            }
        }
        KeyCode::Char('y') if key.modifiers.is_empty() => {
            card.error = Some("Review all remote operation details before allowing it.".into());
            SshModalOutcome::Changed
        }
        KeyCode::Char('n') | KeyCode::Esc => SshModalOutcome::ApproveOperation {
            approval_id: card.approval_id.clone(),
            approved: false,
        },
        _ => SshModalOutcome::Unchanged,
    }
}

fn scroll_key(
    scroll_offset: &mut usize,
    max_scroll_offset: usize,
    key: &KeyEvent,
    vim_navigation: bool,
) -> bool {
    let next = match key.code {
        KeyCode::Up | KeyCode::Char('k') if vim_navigation && key.modifiers.is_empty() => {
            scroll_offset.saturating_sub(1)
        }
        KeyCode::Down | KeyCode::Char('j') if vim_navigation && key.modifiers.is_empty() => {
            scroll_offset.saturating_add(1)
        }
        KeyCode::PageUp => scroll_offset.saturating_sub(8),
        KeyCode::PageDown => scroll_offset.saturating_add(8),
        KeyCode::Home if vim_navigation => 0,
        KeyCode::End if vim_navigation => max_scroll_offset,
        _ => return false,
    };
    *scroll_offset = next.min(max_scroll_offset);
    true
}

fn host_key_outcome(
    card: &SshAuthCard,
    host_key_decision: xai_grok_shell::ssh::SshHostKeyDecision,
) -> SshModalOutcome {
    SshModalOutcome::AnswerAuthentication {
        challenge_id: card.challenge_id.clone(),
        connection_generation: card.connection_generation,
        target_id: card.target_id.clone(),
        host_key_decision: Some(host_key_decision),
        remember: false,
        secret: None,
        answers: Vec::new(),
    }
}

fn handle_diagnostic_key(card: &mut SshDiagnosticCard, key: &KeyEvent) -> SshModalOutcome {
    if scroll_key(&mut card.scroll_offset, card.max_scroll_offset, key, true) {
        SshModalOutcome::Changed
    } else {
        SshModalOutcome::Unchanged
    }
}

fn handle_authentication_key(card: &mut SshAuthCard, key: &KeyEvent) -> SshModalOutcome {
    let host_key = match &card.kind {
        SshAuthKind::HostKey {
            status,
            previous_keys,
            can_replace,
            ..
        } => Some((changed_host_key(status, previous_keys), *can_replace)),
        _ => None,
    };
    if let Some((changed, can_replace)) = host_key {
        if scroll_key(&mut card.scroll_offset, card.max_scroll_offset, key, true) {
            return SshModalOutcome::Changed;
        }
        return match key.code {
            KeyCode::Char('r') if changed && can_replace && key.modifiers.is_empty() => {
                host_key_outcome(
                    card,
                    xai_grok_shell::ssh::SshHostKeyDecision::ReplaceAndStore,
                )
            }
            KeyCode::Char('y') if !changed && key.modifiers.is_empty() => {
                host_key_outcome(card, xai_grok_shell::ssh::SshHostKeyDecision::TrustOnce)
            }
            KeyCode::Char('s') if !changed && key.modifiers.is_empty() => {
                host_key_outcome(card, xai_grok_shell::ssh::SshHostKeyDecision::TrustAndStore)
            }
            KeyCode::Char('n') if key.modifiers.is_empty() => {
                host_key_outcome(card, xai_grok_shell::ssh::SshHostKeyDecision::Reject)
            }
            KeyCode::Esc => host_key_outcome(card, xai_grok_shell::ssh::SshHostKeyDecision::Reject),
            _ => SshModalOutcome::Unchanged,
        };
    }
    if scroll_key(&mut card.scroll_offset, card.max_scroll_offset, key, false) {
        return SshModalOutcome::Changed;
    }
    match key.code {
        KeyCode::Esc => {
            let challenge_id = card.challenge_id.clone();
            let connection_generation = card.connection_generation;
            let target_id = card.target_id.clone();
            card.clear_answers();
            SshModalOutcome::AnswerAuthentication {
                challenge_id,
                connection_generation,
                target_id,
                host_key_decision: None,
                remember: false,
                secret: None,
                answers: Vec::new(),
            }
        }
        KeyCode::Tab | KeyCode::BackTab if card.answers.len() > 1 => {
            let len = card.answers.len();
            card.active_answer = if matches!(key.code, KeyCode::BackTab) {
                (card.active_answer + len - 1) % len
            } else {
                (card.active_answer + 1) % len
            };
            SshModalOutcome::Changed
        }
        KeyCode::Char('r') if key.modifiers == KeyModifiers::ALT && card.can_remember() => {
            card.remember = !card.remember;
            SshModalOutcome::Changed
        }
        KeyCode::Enter => {
            if card.answers.iter().any(|answer| answer.text().is_empty()) {
                card.error = Some("Answer every authentication prompt.".into());
                return SshModalOutcome::Changed;
            }
            let (secret, answers) = card.take_auth_response();
            SshModalOutcome::AnswerAuthentication {
                challenge_id: card.challenge_id.clone(),
                connection_generation: card.connection_generation,
                target_id: card.target_id.clone(),
                host_key_decision: None,
                remember: card.remember,
                secret,
                answers,
            }
        }
        _ => card
            .answer_mut()
            .map(|answer| line_outcome(answer.handle_key(key)))
            .unwrap_or(SshModalOutcome::Unchanged),
    }
}
fn line_outcome(outcome: LineEditOutcome) -> SshModalOutcome {
    match outcome {
        LineEditOutcome::TextChanged | LineEditOutcome::CursorChanged => SshModalOutcome::Changed,
        LineEditOutcome::HandledNoChange => SshModalOutcome::Changed,
        LineEditOutcome::Unhandled => SshModalOutcome::Unchanged,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approval(id: &str) -> SshOperationApprovalCard {
        SshOperationApprovalCard::new(
            id.into(),
            "binding-1".into(),
            "target-1".into(),
            Some("user@host:22 (SHA256:test)".into()),
            "Remote operation".into(),
            "{}".into(),
        )
    }

    #[test]
    fn transient_allowed_operation_returns_to_chat_only_after_matching_acknowledgement() {
        let mut state = SshManagerState::new(Some("session-1".into()));
        state.show_operation_approval(
            approval("approval-1"),
            SshOperationApprovalOrigin::TransientEvent,
        );
        assert!(state.submit_operation_approval("approval-1", true));

        assert!(state.settle_operation_approval("approval-1", None));
    }

    #[test]
    fn explicit_or_denied_operation_keeps_a_visible_result() {
        let mut state = SshManagerState::new(Some("session-1".into()));
        state.show_operation_approval(
            approval("approval-1"),
            SshOperationApprovalOrigin::ExplicitManager,
        );
        assert!(state.submit_operation_approval("approval-1", true));

        assert!(!state.settle_operation_approval("approval-1", None));
        assert!(matches!(&state.page, SshModalPage::Manager));
        assert_eq!(
            state.message.as_ref().map(|message| message.0.as_str()),
            Some("Remote operation approval sent.")
        );

        state.show_operation_approval(
            approval("approval-2"),
            SshOperationApprovalOrigin::TransientEvent,
        );
        assert!(state.submit_operation_approval("approval-2", false));
        assert!(!state.settle_operation_approval("approval-2", None));
        assert!(matches!(&state.page, SshModalPage::Manager));
        assert_eq!(
            state.message.as_ref().map(|message| message.0.as_str()),
            Some("Remote operation denied.")
        );
    }

    #[test]
    fn stale_completion_cannot_hide_a_newer_operation_or_its_submission_error() {
        let mut state = SshManagerState::new(Some("session-1".into()));
        state.show_operation_approval(
            approval("approval-1"),
            SshOperationApprovalOrigin::TransientEvent,
        );
        assert!(state.submit_operation_approval("approval-1", true));

        state.show_operation_approval(
            approval("approval-2"),
            SshOperationApprovalOrigin::TransientEvent,
        );
        assert!(!state.settle_operation_approval("approval-1", None));
        assert!(matches!(
            &state.page,
            SshModalPage::OperationApproval(card) if card.approval_id == "approval-2"
        ));

        assert!(state.submit_operation_approval("approval-2", true));
        assert!(
            !state
                .settle_operation_approval("approval-2", Some("local control unavailable".into()))
        );
        assert!(matches!(
            &state.page,
            SshModalPage::OperationApproval(card)
                if card.approval_id == "approval-2"
                    && !card.submitting
                    && card.error.as_deref() == Some("local control unavailable")
        ));
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn host_key_card(status: &str, previous_keys: Vec<String>, can_replace: bool) -> SshAuthCard {
        SshAuthCard::new(
            "challenge-1".into(),
            7,
            "target-1".into(),
            SshAuthKind::HostKey {
                hostname: "build.example.test".into(),
                port: 2222,
                algorithm: "ssh-ed25519".into(),
                fingerprint: "SHA256:new-fingerprint".into(),
                status: status.into(),
                previous_keys,
                can_replace,
            },
        )
    }

    fn host_key_decision(outcome: SshModalOutcome) -> xai_grok_shell::ssh::SshHostKeyDecision {
        match outcome {
            SshModalOutcome::AnswerAuthentication {
                host_key_decision: Some(decision),
                ..
            } => decision,
            _ => panic!("expected a host-key decision"),
        }
    }

    fn buffer_text(buffer: &Buffer) -> String {
        (0..buffer.area.height)
            .flat_map(|y| {
                (0..buffer.area.width)
                    .filter_map(move |x| buffer.cell((x, y)).map(|cell| cell.symbol().to_owned()))
            })
            .collect()
    }

    #[test]
    fn changed_host_key_requires_explicit_replace_and_esc_rejects() {
        let mut changed = host_key_card(
            "changed",
            vec!["SHA256:old-fingerprint ssh-ed25519 ~/.ssh/known_hosts line 37".into()],
            true,
        );
        assert!(matches!(
            handle_authentication_key(&mut changed, &key(KeyCode::Enter)),
            SshModalOutcome::Unchanged
        ));
        assert!(matches!(
            handle_authentication_key(&mut changed, &key(KeyCode::Char('y'))),
            SshModalOutcome::Unchanged
        ));
        assert_eq!(
            host_key_decision(handle_authentication_key(
                &mut changed,
                &key(KeyCode::Char('r'))
            )),
            xai_grok_shell::ssh::SshHostKeyDecision::ReplaceAndStore
        );

        let mut manual_remediation = host_key_card("changed", vec!["old record".into()], false);
        assert!(matches!(
            handle_authentication_key(&mut manual_remediation, &key(KeyCode::Char('r'))),
            SshModalOutcome::Unchanged
        ));

        let mut state = SshManagerState::new(None);
        state.show_authentication(host_key_card("changed", vec!["old record".into()], false));
        assert_eq!(
            host_key_decision(handle_ssh_key(&mut state, &key(KeyCode::Esc))),
            xai_grok_shell::ssh::SshHostKeyDecision::Reject
        );
    }

    #[test]
    fn answered_host_key_closes_stale_card_and_exposes_connection_error() {
        for answer in [KeyCode::Char('n'), KeyCode::Esc, KeyCode::Char('r')] {
            let mut state = SshManagerState::new(None);
            state.show_authentication(host_key_card("changed", vec!["old record".into()], true));
            assert!(matches!(
                handle_ssh_key(&mut state, &key(answer)),
                SshModalOutcome::AnswerAuthentication { .. }
            ));
            assert!(
                matches!(&state.page, SshModalPage::Manager),
                "an answered challenge must not hide its connection result"
            );
            state.show_error("SSH host key was rejected");
            assert!(matches!(
                handle_ssh_key(&mut state, &key(KeyCode::Char('d'))),
                SshModalOutcome::Changed
            ));
            assert!(matches!(&state.page, SshModalPage::Diagnostic(_)));
        }
    }

    #[test]
    fn unknown_host_key_keeps_once_and_store_choices_typed() {
        let mut unknown = host_key_card("unknown", Vec::new(), false);
        assert_eq!(
            host_key_decision(handle_authentication_key(
                &mut unknown,
                &key(KeyCode::Char('y'))
            )),
            xai_grok_shell::ssh::SshHostKeyDecision::TrustOnce
        );
        assert_eq!(
            host_key_decision(handle_authentication_key(
                &mut unknown,
                &key(KeyCode::Char('s'))
            )),
            xai_grok_shell::ssh::SshHostKeyDecision::TrustAndStore
        );
    }

    #[test]
    fn non_host_authentication_keeps_host_key_decision_empty() {
        let mut card = SshAuthCard::new(
            "challenge-2".into(),
            8,
            "target-1".into(),
            SshAuthKind::Password {
                username: "build".into(),
                message: "Password required".into(),
                allow_remember: true,
            },
        );
        assert!(matches!(
            handle_authentication_key(&mut card, &key(KeyCode::Esc)),
            SshModalOutcome::AnswerAuthentication {
                host_key_decision: None,
                secret: None,
                answers,
                ..
            } if answers.is_empty()
        ));
    }

    #[test]
    fn changed_host_key_records_remain_reachable_in_narrow_authentication_card() {
        let mut card = host_key_card(
            "changed",
            vec![
                "SHA256:old-fingerprint ssh-ed25519 ~/.ssh/known_hosts line 37".into(),
                "SHA256:older-rsa ssh-rsa ~/.ssh/known_hosts line 38".into(),
            ],
            false,
        );
        let area = Rect::new(0, 0, 30, 4);
        let theme = Theme::current();
        let mut frames = String::new();
        for _ in 0..256 {
            let mut buffer = Buffer::empty(area);
            render_authentication(&mut buffer, area, &mut card, &theme);
            frames.push_str(&buffer_text(&buffer));
            frames.push('\n');
            if matches!(
                handle_authentication_key(&mut card, &key(KeyCode::Down)),
                SshModalOutcome::Unchanged
            ) {
                break;
            }
        }
        assert!(frames.contains("SHA256:old-fingerprint"));
        assert!(frames.contains("SHA256:older-rsa"));
        assert!(frames.contains("line 37"));
        assert!(frames.contains("line 38"));
    }

    #[test]
    fn long_manager_error_opens_a_scrollable_diagnostic_without_changing_selection() {
        let mut state = SshManagerState::new(None);
        state.selected = 4;
        state.show_error(
            "SSH connection failed after authentication. \
             The remote endpoint closed the tunnel while opening the workspace. \
             Root cause: host certificate policy rejected the requested principal.",
        );
        assert!(matches!(
            handle_manager_key(&mut state, &key(KeyCode::Char('d'))),
            SshModalOutcome::Changed
        ));
        assert_eq!(state.selected, 4);
        let SshModalPage::Diagnostic(card) = &mut state.page else {
            panic!("manager error must open its diagnostic page");
        };
        let area = Rect::new(0, 0, 24, 4);
        let theme = Theme::current();
        let mut buffer = Buffer::empty(area);
        render_diagnostic(&mut buffer, area, card, &theme);
        assert!(card.max_scroll_offset > 0);
        assert!(matches!(
            handle_diagnostic_key(card, &key(KeyCode::End)),
            SshModalOutcome::Changed
        ));
        let mut buffer = Buffer::empty(area);
        render_diagnostic(&mut buffer, area, card, &theme);
        assert!(
            buffer_text(&buffer).contains("principal"),
            "the diagnostic root cause must remain visible after scrolling"
        );
        assert!(matches!(
            close_current_page(&mut state),
            SshModalOutcome::Changed
        ));
        assert!(matches!(&state.page, SshModalPage::Manager));
        assert_eq!(state.selected, 4);
    }
}
