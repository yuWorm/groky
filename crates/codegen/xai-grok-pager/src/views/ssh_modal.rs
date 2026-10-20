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
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseEvent, MouseEventKind};
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use std::sync::atomic::{AtomicU64, Ordering};
use xai_grok_shell::ssh::{SshConnectionState, SshDirectoryListing, SshHostIdentity};
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SshGrantFocus {
    Root,
    Read,
    Write,
    Execute,
    Lifetime,
    Default,
    RememberProject,
}


/// Typed continuation for an advanced authorization flow.
///
/// The app owns dispatching the continuation after the matching approval acknowledgement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshGrantFollowUp {
    UseBinding,
}

impl SshGrantFollowUp {
    fn guidance(self) -> &'static str {
        match self {
            Self::UseBinding => "The newly approved binding will be used automatically.",
        }
    }
}

#[derive(Clone)]
struct SshProjectConsent {
    request_id: u64,
    canonical_root: String,
    remember: bool,
}

#[derive(Clone)]
struct GrantControlHit {
    focus: SshGrantFocus,
    rect: Rect,
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
    focus: SshGrantFocus,
    scroll_offset: usize,
    max_scroll_offset: usize,
    page_size: usize,
    reviewed_to_end: bool,
    control_hits: Vec<GrantControlHit>,
    follow_up: Option<SshGrantFollowUp>,
    project: Option<SshProjectConsent>,
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
            focus: SshGrantFocus::Root,
            scroll_offset: 0,
            max_scroll_offset: 0,
            page_size: 1,
            reviewed_to_end: false,
            control_hits: Vec::new(),
            follow_up: None,
            project: None,
        }
    }

    fn is_project_consent(&self) -> bool {
        self.project.is_some()
    }

    fn focus_next(&mut self, backwards: bool) {
        const PROJECT_FOCUSES: [SshGrantFocus; 5] = [
            SshGrantFocus::Root,
            SshGrantFocus::Read,
            SshGrantFocus::Write,
            SshGrantFocus::Execute,
            SshGrantFocus::RememberProject,
        ];
        const GENERAL_FOCUSES: [SshGrantFocus; 6] = [
            SshGrantFocus::Root,
            SshGrantFocus::Read,
            SshGrantFocus::Write,
            SshGrantFocus::Execute,
            SshGrantFocus::Lifetime,
            SshGrantFocus::Default,
        ];
        let focuses: &[SshGrantFocus] = if self.is_project_consent() {
            &PROJECT_FOCUSES
        } else {
            &GENERAL_FOCUSES
        };
        let index = focuses
            .iter()
            .position(|focus| *focus == self.focus)
            .unwrap_or(0);
        let next = if backwards {
            (index + focuses.len() - 1) % focuses.len()
        } else {
            (index + 1) % focuses.len()
        };
        self.focus = focuses[next];
    }

    fn permits_root(&self, root: &str) -> bool {
        let Some(project) = self.project.as_ref() else {
            return true;
        };
        root == project.canonical_root
            || (root
                .strip_prefix(project.canonical_root.trim_end_matches('/'))
                .is_some_and(|suffix| suffix.starts_with('/'))
                && !root
                    .split('/')
                    .any(|component| matches!(component, "." | "..")))
    }

    fn project_remember(&self) -> bool {
        self.project.as_ref().is_some_and(|project| project.remember)
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
    request_id: Option<String>,
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

    fn input_label(self) -> &'static str {
        match self {
            Self::Host => "Host / alias: ",
            Self::Label => "Label: ",
            Self::User => "User override: ",
            Self::Port => "Port override: ",
            Self::IdentityFile => "Identity file: ",
            Self::WorkerCommand => "Worker command: ",
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
    field_hits: Vec<(ManualTargetField, Rect)>,
    submitting: bool,
    submission_id: Option<u64>,
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
            field_hits: Vec::new(),
            submitting: false,
            submission_id: None,
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
            raw => {
                let port = raw
                    .parse::<u16>()
                    .map_err(|_| "Port must be an integer between 1 and 65535.")?;
                if port == 0 {
                    return Err("Port must be an integer between 1 and 65535.".into());
                }
                Some(port)
            }
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

    fn start_submit(&mut self) -> Result<(SshManualTargetDraft, u64), String> {
        let draft = self.draft()?;
        let submission_id = next_nonzero_id(&NEXT_TARGET_ADD_SUBMISSION_ID);
        self.submitting = true;
        self.submission_id = Some(submission_id);
        self.error = None;
        Ok((draft, submission_id))
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

/// Local-only fallback after the remote host cannot download the exact managed worker build.
///
/// The request tuple is retained verbatim so input, local control, progress, and terminal
/// project setup cannot accidentally cross sessions or bindings.
struct SshWorkerInstallFallbackCard {
    client_id: u64,
    request_id: String,
    session_id: String,
    binding_id: String,
    target_id: String,
    version: String,
    platform: String,
    remote_error: String,
    scroll_offset: usize,
    max_scroll_offset: usize,
    submitting: bool,
    decision_accepted: Option<bool>,
    progress: Option<String>,
    error: Option<String>,
}

impl SshWorkerInstallFallbackCard {
    fn new(request: xai_grok_shell::ssh::SshWorkerInstallRequest) -> Self {
        Self {
            client_id: request.client_id,
            request_id: request.request_id,
            session_id: request.session_id,
            binding_id: request.binding_id,
            target_id: request.target_id,
            version: request.version,
            platform: request.platform,
            remote_error: request.remote_error,
            scroll_offset: 0,
            max_scroll_offset: 0,
            submitting: false,
            decision_accepted: None,
            progress: None,
            error: None,
        }
    }

    fn matches(
        &self,
        client_id: u64,
        request_id: &str,
        session_id: &str,
        binding_id: &str,
    ) -> bool {
        self.client_id == client_id
            && self.request_id == request_id
            && self.session_id == session_id
            && self.binding_id == binding_id
    }

    fn is_decided(&self) -> bool {
        self.decision_accepted.is_some()
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
    is_error: bool,
    scroll_offset: usize,
    max_scroll_offset: usize,
    return_grant: Option<SshGrantCard>,
    return_add: Option<SshManualTargetForm>,
    return_browser: bool,
    connected: Option<bool>,
    latest_error: Option<String>,
}

impl SshDiagnosticCard {
    fn new(message: String) -> Self {
        Self {
            message,
            is_error: true,
            scroll_offset: 0,
            max_scroll_offset: 0,
            return_grant: None,
            return_add: None,
            return_browser: false,
            connected: None,
            latest_error: None,
        }
    }

    fn details(message: String, connected: bool, latest_error: Option<String>) -> Self {
        Self {
            is_error: false,
            connected: Some(connected),
            latest_error,
            ..Self::new(message)
        }
    }
}

#[derive(Clone)]
struct ProjectDirectoryHit {
    index: usize,
    rect: Rect,
}

/// Local browser state for one authenticated remote target.
///
/// It retains only directory metadata from the SSH service. The service resolves every listed
/// path and records the verified identity; this UI never performs local filesystem lookups.
struct SshProjectBrowser {
    target_id: String,
    request_id: u64,
    open_request_id: Option<u64>,
    listing: Option<SshDirectoryListing>,
    path: LineEditor,
    editing_path: bool,
    selected: usize,
    scroll_offset: usize,
    visible_rows: usize,
    loading: bool,
    preparing: bool,
    error: Option<String>,
    notice: Option<String>,
    row_hits: Vec<ProjectDirectoryHit>,
}

impl SshProjectBrowser {
    fn new(target_id: String, path: Option<String>, request_id: u64) -> Self {
        let mut editor = LineEditor::default();
        editor.set_text(path.unwrap_or_else(|| ".".to_owned()));
        Self {
            target_id,
            request_id,
            open_request_id: None,
            listing: None,
            path: editor,
            editing_path: false,
            selected: 0,
            scroll_offset: 0,
            visible_rows: 0,
            loading: true,
            preparing: false,
            error: None,
            notice: None,
            row_hits: Vec::new(),
        }
    }

    fn begin_navigation(&mut self, path: Option<String>, request_id: u64) {
        self.request_id = request_id;
        self.open_request_id = None;
        if let Some(path) = path {
            self.path.set_text(path);
        }
        self.editing_path = false;
        self.loading = true;
        self.error = None;
        self.notice = None;
    }

    fn settle_listing(&mut self, listing: SshDirectoryListing) {
        self.path.set_text(listing.path.clone());
        self.listing = Some(listing);
        self.selected = 0;
        self.scroll_offset = 0;
        self.loading = false;
        self.error = None;
    }

    fn selected_directory_path(&self) -> Option<String> {
        self.listing
            .as_ref()?
            .directories
            .get(self.selected)
            .map(|entry| entry.path.clone())
    }

    fn listed_path(&self) -> Option<&str> {
        self.listing.as_ref().map(|listing| listing.path.as_str())
    }
}

struct PendingProjectOpen {
    request_id: u64,
    session_id: String,
    target_id: String,
    original_root: String,
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
    ProjectBrowser,
    OperationApproval(SshOperationApprovalCard),
    WorkerInstallFallback(SshWorkerInstallFallbackCard),
    Authentication(SshAuthCard),
    Diagnostic(SshDiagnosticCard),
}

#[derive(Clone)]
struct ManagerRowHit {
    target_id: String,
    binding_id: Option<String>,
    rect: Rect,
}

static NEXT_MANAGER_INSTANCE_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_TARGET_ADD_SUBMISSION_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_PROJECT_DIRECTORY_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

fn next_nonzero_id(counter: &AtomicU64) -> u64 {
    loop {
        let id = counter.fetch_add(1, Ordering::Relaxed);
        if id != 0 {
            return id;
        }
    }
}

/// Manager state usable from Welcome and from a running session.
pub struct SshManagerState {
    pub window: ModalWindowState,
    page: SshModalPage,
    pub targets: Vec<SshTargetView>,
    pub selected: usize,
    pub loading: bool,
    pub message: Option<(String, bool)>,
    instance_id: u64,
    manager_scroll_offset: usize,
    manager_visible_rows: usize,
    manager_row_hits: Vec<ManagerRowHit>,
    manager_advanced: bool,
    pending_added_target_id: Option<String>,
    project_browser: Option<SshProjectBrowser>,
    /// The request tuple that owns a preparation, grant, and subsequent project lifecycle.
    pending_project_open: Option<PendingProjectOpen>,
    /// Authentication temporarily overlays the browser but must return to the same listing.
    resume_project_browser_after_authentication: bool,
    /// Target owning the current connect/disconnect progress message.
    pending_connection: Option<String>,
    /// Immutable request tuple retained through the displayed consent card so resolution can
    /// be correlated with the original target/root rather than editable card state.
    pending_grant: Option<SshIncomingGrant>,
    /// Exact decision submitted for the displayed request, retained until its resolution.
    submitted_grant: Option<SubmittedGrantDecision>,
    /// Session actually requested by the current human-consent card. Usually this manager's
    /// session, but a remote worktree resume pre-mints a child before it has an AgentView.
    pending_grant_session_id: Option<String>,
    /// Typed continuation for a local advanced grant, never inferred from rendered prose.
    pending_grant_follow_up: Option<SshGrantFollowUp>,
    settled_grant_follow_up: Option<(String, SshGrantFollowUp)>,
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
            instance_id: next_nonzero_id(&NEXT_MANAGER_INSTANCE_ID),
            manager_scroll_offset: 0,
            manager_visible_rows: 0,
            manager_row_hits: Vec::new(),
            manager_advanced: false,
            pending_added_target_id: None,
            project_browser: None,
            pending_project_open: None,
            resume_project_browser_after_authentication: false,
            pending_connection: None,
            pending_grant: None,
            submitted_grant: None,
            pending_grant_session_id: None,
            pending_grant_follow_up: None,
            settled_grant_follow_up: None,
            local_grant_options: None,
            session_id,
            operation_approval_origin: None,
            submitted_operation_approval: None,
        }
    }

    /// Globally unique identity for matching asynchronous local-control completions to this
    /// concrete manager instance after an overlay is closed and re-opened.
    pub fn instance_id(&self) -> u64 {
        self.instance_id
    }

    /// The exact add-target submission currently displayed by the form.
    pub fn target_add_submission_id(&self) -> Option<u64> {
        match &self.page {
            SshModalPage::Add(form) if form.submitting => form.submission_id,
            SshModalPage::Manager
            | SshModalPage::Add(_)
            | SshModalPage::Grant(_)
            | SshModalPage::ProjectBrowser
            | SshModalPage::OperationApproval(_)
            | SshModalPage::WorkerInstallFallback(_)
            | SshModalPage::Authentication(_)
            | SshModalPage::Diagnostic(_) => None,
        }
    }

    pub fn target_add_is_submitting(&self) -> bool {
        self.target_add_submission_id().is_some()
    }

    /// Correlated variant for lifecycle dispatch. Prefer this when the task result carries the
    /// submission ID echoed from [`SshModalOutcome::AddTarget`].
    pub fn settle_target_add_for_submission(
        &mut self,
        submission_id: u64,
        result: Result<String, String>,
    ) -> bool {
        if self.target_add_submission_id() != Some(submission_id) {
            return false;
        }
        self.settle_target_add(result)
    }

    /// Settle the add form only while its exact submission remains visibly pending.
    ///
    /// Lifecycle dispatch correlates the task's client ID to [`Self::target_add_submission_id`]
    /// before calling this method, so an old completion cannot settle a later form.
    pub fn settle_target_add(&mut self, result: Result<String, String>) -> bool {
        let saved_target_id = match result {
            Ok(target_id) => target_id,
            Err(error) => {
                let SshModalPage::Add(form) = &mut self.page else {
                    return false;
                };
                if !form.submitting {
                    return false;
                }
                form.submitting = false;
                form.submission_id = None;
                self.show_error(error);
                return true;
            }
        };
        let SshModalPage::Add(form) = &self.page else {
            return false;
        };
        if !form.submitting {
            return false;
        }
        self.pending_added_target_id = Some(saved_target_id);
        self.loading = true;
        self.page = SshModalPage::Manager;
        self.show_info("SSH target saved.");
        true
    }

    /// Start the authenticated remote-directory chooser for a selected target.
    pub fn begin_project_browser(
        &mut self,
        target_id: String,
        path: Option<String>,
    ) -> SshModalOutcome {
        if self.pending_project_open.is_some() {
            return SshModalOutcome::Unchanged;
        }
        let request_id = next_nonzero_id(&NEXT_PROJECT_DIRECTORY_REQUEST_ID);
        self.project_browser = Some(SshProjectBrowser::new(target_id.clone(), path.clone(), request_id));
        self.resume_project_browser_after_authentication = false;
        self.page = SshModalPage::ProjectBrowser;
        SshModalOutcome::BrowseProjectDirectory {
            request_id,
            target_id,
            path,
        }
    }

    fn browse_project_directory(&mut self, path: Option<String>) -> SshModalOutcome {
        let request_id = next_nonzero_id(&NEXT_PROJECT_DIRECTORY_REQUEST_ID);
        let Some(browser) = self.project_browser.as_mut() else {
            return SshModalOutcome::Unchanged;
        };
        browser.begin_navigation(path.clone(), request_id);
        SshModalOutcome::BrowseProjectDirectory {
            request_id,
            target_id: browser.target_id.clone(),
            path,
        }
    }

    /// Settle a directory list only when its exact browser request is still current.
    pub fn settle_project_directory(
        &mut self,
        request_id: u64,
        target_id: &str,
        result: Result<SshDirectoryListing, String>,
    ) -> bool {
        let browser_visible = matches!(&self.page, SshModalPage::ProjectBrowser);
        let browser_behind_authentication = self.resume_project_browser_after_authentication
            && matches!(&self.page, SshModalPage::Authentication(_));
        if !browser_visible && !browser_behind_authentication {
            return false;
        }
        let Some(browser) = self.project_browser.as_mut() else {
            return false;
        };
        if browser.request_id != request_id || browser.target_id != target_id {
            return false;
        }
        browser.loading = false;
        match result {
            Ok(listing) if listing.target_id == target_id => browser.settle_listing(listing),
            Ok(_) => {
                browser.error = Some("SSH returned directories for a different target.".into());
            }
            Err(error) => {
                browser.error = Some(error);
            }
        }
        if browser.error.is_some()
            && let Some(listing) = browser.listing.as_ref()
        {
            browser.path.set_text(listing.path.clone());
        }
        if matches!(self.message, Some((_, false))) {
            self.message = None;
        }
        if browser_behind_authentication {
            self.page = SshModalPage::ProjectBrowser;
            self.resume_project_browser_after_authentication = false;
        }
        if let Some(error) = self.project_browser.as_ref().and_then(|browser| browser.error.clone()) {
            self.show_error(error);
        }
        true
    }

    /// True only while this manager still owns a browser selection or preparation tuple.
    pub fn project_directory_request_matches(&self, request_id: u64, target_id: &str) -> bool {
        self.pending_project_open.as_ref().is_some_and(|pending| {
            pending.request_id == request_id && pending.target_id == target_id
        }) || self.project_browser.as_ref().is_some_and(|browser| {
            browser.target_id == target_id
                && (browser.open_request_id == Some(request_id) || browser.request_id == request_id)
        })
    }

    /// Begin one owner-correlated project preparation after a browser selection or direct CLI
    /// path request. A direct caller may pass the request id returned by
    /// [`Self::begin_project_browser`] without waiting for its browse outcome.
    pub fn begin_project_preparation(
        &mut self,
        request_id: u64,
        project_session_id: String,
        target_id: String,
        root: String,
    ) -> bool {
        if self.pending_project_open.is_some() {
            return false;
        }
        {
            let Some(browser) = self.project_browser.as_mut() else {
                return false;
            };
            if browser.target_id != target_id {
                return false;
            }
            let selected_request = browser.open_request_id == Some(request_id);
            let direct_request = browser.request_id == request_id;
            if !selected_request && !direct_request {
                return false;
            }
            if selected_request && browser.listed_path() != Some(root.as_str()) {
                return false;
            }
            browser.preparing = true;
            browser.loading = false;
            browser.error = None;
            browser.notice = Some("Preparing remote project…".into());
        }
        self.pending_project_open = Some(PendingProjectOpen {
            request_id,
            session_id: project_session_id,
            target_id,
            original_root: root,
        });
        true
    }

    /// Session that owns the in-flight project preparation or post-approval open.
    pub fn pending_project_session_id(&self) -> Option<&str> {
        self.pending_project_open
            .as_ref()
            .map(|pending| pending.session_id.as_str())
    }

    /// Target owning an authenticated browse or project preparation, independent of active view.
    pub fn pending_project_target_id(&self) -> Option<&str> {
        if let Some(pending) = self.pending_project_open.as_ref() {
            return Some(pending.target_id.as_str());
        }
        if self.resume_project_browser_after_authentication
            || matches!(&self.page, SshModalPage::ProjectBrowser)
        {
            return self
                .project_browser
                .as_ref()
                .filter(|browser| browser.loading)
                .map(|browser| browser.target_id.as_str());
        }
        None
    }

    /// Browser request that owns the in-flight project preparation or post-approval open.
    pub fn pending_project_request_id(&self) -> Option<u64> {
        self.pending_project_open
            .as_ref()
            .map(|pending| pending.request_id)
    }

    /// Immutable owner tuple for grant-resolution validation: session, target, original root.
    pub fn pending_project_open_tuple(&self) -> Option<(&str, &str, &str)> {
        self.pending_project_open.as_ref().map(|pending| {
            (
                pending.session_id.as_str(),
                pending.target_id.as_str(),
                pending.original_root.as_str(),
            )
        })
    }

    /// Display the exact already-verified consent request for an owned preparation.
    pub fn show_project_consent(
        &mut self,
        request_id: u64,
        request: SshIncomingGrant,
        session_id: String,
    ) -> bool {
        if self.resume_project_browser_after_authentication {
            self.return_after_authentication();
        }
        let Some(target_id) = request.target_id.as_deref().map(str::to_owned) else {
            return false;
        };
        let Some(root) = request
            .root
            .as_deref()
            .filter(|root| !root.trim().is_empty())
            .map(str::to_owned)
        else {
            return false;
        };
        if request.verified_identity.is_none()
            || !matches!(&self.page, SshModalPage::ProjectBrowser)
            || !self.pending_project_open.as_ref().is_some_and(|pending| {
                pending.request_id == request_id
                    && pending.session_id == session_id
                    && pending.target_id == target_id
            })
        {
            return false;
        }
        let target_label = self
            .targets
            .iter()
            .find(|target| target.target_id == target_id)
            .map(|target| target.label.clone())
            .unwrap_or_else(|| "Selected SSH server".to_owned());
        let mut card = SshGrantCard::new(
            request.request_id.clone(),
            target_id,
            target_label,
            request.verified_identity.clone(),
            root.clone(),
            Some(request.reason.clone()),
            false,
        );
        card.capabilities = request.capabilities;
        card.project = Some(SshProjectConsent {
            request_id,
            canonical_root: root.clone(),
            remember: false,
        });
        self.pending_grant = Some(request);
        self.pending_grant_session_id = Some(session_id);
        self.submitted_grant = None;
        self.pending_grant_follow_up = None;
        if let Some(pending) = self.pending_project_open.as_mut() {
            pending.original_root = root;
        }
        if let Some(browser) = self.project_browser.as_mut() {
            browser.preparing = false;
            browser.notice = None;
        }
        self.page = SshModalPage::Grant(card);
        true
    }

    /// Finish a preparation failure or denial without losing the browsed folder to retry.
    pub fn finish_project_preparation(&mut self, request_id: u64, error: Option<String>) -> bool {
        if self.pending_project_request_id() != Some(request_id) {
            return false;
        }
        self.pending_project_open = None;
        if let Some(browser) = self.project_browser.as_mut() {
            browser.loading = false;
            browser.preparing = false;
            browser.open_request_id = None;
            browser.notice = None;
            browser.error = error.clone();
        }
        if self.resume_project_browser_after_authentication {
            self.return_after_authentication();
        }
        if matches!(&self.page, SshModalPage::Grant(card) if card.project.as_ref().is_some_and(|project| project.request_id == request_id)) {
            self.page = SshModalPage::ProjectBrowser;
        }
        if let Some(error) = error {
            self.show_error(error);
        }
        true
    }


    /// Clear visible progress after the terminal project-session lifecycle outcome.
    pub fn settle_project_open(&mut self) {
        self.pending_project_open = None;
        if let Some(browser) = self.project_browser.as_mut() {
            browser.preparing = false;
            browser.open_request_id = None;
            browser.notice = None;
        }
        if matches!(&self.page, SshModalPage::WorkerInstallFallback(_)) {
            self.page = SshModalPage::Manager;
        }
        if matches!(&self.message, Some((message, false)) if message == "Preparing remote SSH project…")
        {
            self.message = None;
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
            request_id: None,
            target_id,
            root,
            capabilities,
            lifetime,
            set_default,
        });
    }

    /// Bind human draft options to the direct control reply before remote canonicalization.
    pub fn bind_local_grant_request(
        &mut self, request_id: &str, target_id: Option<&str>, root: Option<&str>,
    ) -> bool {
        let Some(options) = self.local_grant_options.as_mut() else { return false };
        if options.request_id.is_none()
            && target_id == Some(options.target_id.as_str())
            && root == Some(options.root.as_str())
        {
            options.request_id = Some(request_id.to_owned());
            return true;
        }
        false
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
        let root = root.unwrap_or(request_root);
        if matches!(&self.page, SshModalPage::Grant(card) if card.is_project_consent() && !card.permits_root(root))
        {
            return false;
        }
        self.submitted_grant = Some(SubmittedGrantDecision {
            request_id: request_id.to_owned(),
            session_id: session_id.to_owned(),
            target_id: target_id.to_owned(),
            root: root.to_owned(),
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
        let selected_key = self.selected_target().map(|target| {
            (
                target.target_id.clone(),
                target.grant.binding_id().map(str::to_owned),
            )
        });

        // A local revoke remains visible until the worker's acknowledgement has been observed.
        // Preserve each binding independently: a target can have several rows and revoking one
        // must not rewrite or hide its remaining grants.
        for previous in self
            .targets
            .iter()
            .filter(|target| matches!(&target.grant, SshGrantView::Revoking { .. }))
        {
            let binding_id = previous.grant.binding_id();
            let exact_row = targets.iter_mut().find(|target| {
                target.target_id == previous.target_id && target.grant.binding_id() == binding_id
            });
            if let Some(target) = exact_row {
                target.grant = previous.grant.clone();
            } else {
                let only_ungranted_row = targets
                    .iter()
                    .filter(|target| target.target_id == previous.target_id)
                    .all(|target| matches!(&target.grant, SshGrantView::NotGranted));
                if only_ungranted_row {
                    if let Some(target) = targets
                        .iter_mut()
                        .find(|target| target.target_id == previous.target_id)
                    {
                        target.grant = previous.grant.clone();
                    }
                } else if let Some(index) = targets
                    .iter()
                    .rposition(|target| target.target_id == previous.target_id)
                {
                    targets.insert(index + 1, previous.clone());
                }
            }
        }

        self.targets = targets;
        let pending_added_target_id = self.pending_added_target_id.clone();
        if let Some(target_id) = pending_added_target_id
            && let Some(index) = self
                .targets
                .iter()
                .position(|target| target.target_id == target_id)
        {
            self.selected = index;
            self.pending_added_target_id = None;
        } else if let Some((target_id, binding_id)) = selected_key {
            self.selected = self
                .targets
                .iter()
                .position(|target| {
                    target.target_id == target_id
                        && target.grant.binding_id() == binding_id.as_deref()
                })
                .or_else(|| {
                    self.targets
                        .iter()
                        .position(|target| target.target_id == target_id)
                })
                .unwrap_or_else(|| self.selected.min(self.targets.len().saturating_sub(1)));
        } else {
            self.selected = self.selected.min(self.targets.len().saturating_sub(1));
        }
        self.manager_scroll_offset = self.manager_scroll_offset.min(
            self.targets
                .len()
                .saturating_sub(self.manager_visible_rows.max(1)),
        );
        self.loading = false;
        if matches!(
            &self.page,
            SshModalPage::Authentication(card)
                if self
                    .targets
                    .iter()
                    .any(|target| target.target_id == card.target_id && target.connected)
        ) {
            self.return_after_authentication();
        }
    }

    pub fn show_grant(&mut self, card: SshGrantCard) {
        self.page = SshModalPage::Grant(card);
    }

    pub fn show_authentication(&mut self, card: SshAuthCard) {
        self.resume_project_browser_after_authentication =
            matches!(&self.page, SshModalPage::ProjectBrowser)
                && self
                    .project_browser
                    .as_ref()
                    .is_some_and(|browser| browser.target_id == card.target_id);
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

    /// Display the exact local-download/upload fallback for one managed worker installation.
    ///
    /// A duplicate event preserves the visible progress and a different request deliberately
    /// replaces it: only the service's opaque request tuple decides which fallback is current.
    pub fn show_worker_install_fallback(
        &mut self,
        request: xai_grok_shell::ssh::SshWorkerInstallRequest,
    ) {
        if matches!(
            &self.page,
            SshModalPage::WorkerInstallFallback(card)
                if card.matches(
                    request.client_id,
                    &request.request_id,
                    &request.session_id,
                    &request.binding_id,
                ) && card.target_id == request.target_id
        ) {
            return;
        }
        self.page = SshModalPage::WorkerInstallFallback(SshWorkerInstallFallbackCard::new(request));
    }

    /// Submit exactly the fallback decision visible on this manager.
    pub fn submit_worker_install(
        &mut self,
        client_id: u64,
        request_id: &str,
        session_id: &str,
        binding_id: &str,
        approved: bool,
    ) -> bool {
        let SshModalPage::WorkerInstallFallback(card) = &mut self.page else {
            return false;
        };
        if !card.matches(client_id, request_id, session_id, binding_id)
            || card.submitting
            || card.is_decided()
        {
            return false;
        }
        card.submitting = true;
        card.error = None;
        true
    }

    /// Apply one acknowledgement without erasing progress that arrived first.
    pub fn settle_worker_install_decision(
        &mut self,
        client_id: u64,
        request_id: &str,
        session_id: &str,
        binding_id: &str,
        approved: bool,
        error: Option<String>,
    ) {
        let SshModalPage::WorkerInstallFallback(card) = &mut self.page else {
            return;
        };
        if !card.matches(client_id, request_id, session_id, binding_id) || !card.submitting {
            return;
        }
        card.submitting = false;
        if let Some(error) = error {
            card.error = Some(error);
            return;
        }
        card.decision_accepted = Some(approved);
    }

    /// Update or clear only the matching fallback's phase text.
    pub fn apply_worker_install_progress(
        &mut self,
        client_id: u64,
        request_id: &str,
        session_id: &str,
        binding_id: &str,
        target_id: &str,
        message: Option<String>,
    ) {
        let SshModalPage::WorkerInstallFallback(card) = &mut self.page else {
            return;
        };
        if card.matches(client_id, request_id, session_id, binding_id)
            && card.target_id == target_id
        {
            card.progress = message;
        }
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
        let local_options = self.local_grant_options.as_ref().filter(|options| {
            options.request_id.as_deref() == Some(request.request_id.as_str())
                && options.target_id == target_id
        }).cloned();
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
            card.follow_up = self.pending_grant_follow_up;
        } else {
            card.capabilities = request.capabilities;
        }
        self.page = SshModalPage::Grant(card);
    }

    pub fn begin_connection_action(&mut self, target_id: &str, connect: bool) {
        self.show_info(if connect {
            "Connecting through the local SSH service…"
        } else {
            "Releasing the retained SSH connection…"
        });
        self.pending_connection = Some(target_id.to_owned());
    }

    /// Apply an asynchronous local connection update without exposing transport state elsewhere.
    pub fn apply_target_status(
        &mut self,
        target_id: &str,
        connection: SshConnectionState,
        detail: Option<String>,
    ) {
        let connected = connection == SshConnectionState::Connected;
        let detail = detail.unwrap_or_else(|| {
            match connection {
                SshConnectionState::Disconnected => "Disconnected.",
                SshConnectionState::Connecting => "Connecting through local SSH service…",
                SshConnectionState::Connected => "Connected through local SSH service.",
                SshConnectionState::AuthenticationRequired => "Local authentication is required.",
                SshConnectionState::Failed => "Connection failed.",
            }
            .into()
        });
        for target in self
            .targets
            .iter_mut()
            .filter(|target| target.target_id == target_id)
        {
            target.connected = connected;
            target.connection_detail = detail.clone();
        }
        if connected
            && matches!(&self.page, SshModalPage::Authentication(card) if card.target_id == target_id)
        {
            self.return_after_authentication();
        }
        if self.pending_connection.as_deref() == Some(target_id) {
            match connection {
                SshConnectionState::Connected => self.show_info("SSH connection established."),
                SshConnectionState::Disconnected => self.show_info("SSH connection released."),
                SshConnectionState::Failed => self.show_error("SSH connection failed."),
                SshConnectionState::Connecting | SshConnectionState::AuthenticationRequired => {}
            }
        }
    }

    /// Keep the distinction between local revocation and worker acknowledgement visible.
    pub fn mark_binding_revoked(&mut self, binding_id: &str, worker_acknowledged: bool) {
        let revoked_target_id = self
            .targets
            .iter()
            .find(|target| target.grant.binding_id() == Some(binding_id))
            .map(|target| target.target_id.clone());
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
        let Some(target_id) = revoked_target_id else {
            return;
        };
        if !changed {
            return;
        }
        let remaining = self
            .targets
            .iter()
            .filter(|target| {
                target.target_id == target_id
                    && matches!(&target.grant, SshGrantView::Granted { .. })
            })
            .count();
        let remaining = if remaining == 0 {
            "no other active grants remain".to_owned()
        } else {
            format!(
                "{remaining} other active grant{} remain",
                if remaining == 1 { "" } else { "s" }
            )
        };
        self.show_info(if worker_acknowledged {
            format!("Selected SSH grant revocation confirmed by worker; {remaining}.")
        } else {
            format!("Revoking selected SSH grant; {remaining}.")
        });
    }

    pub fn has_worker_acknowledged_revocation(&self) -> bool {
        self.targets.iter().any(|target| {
            matches!(
                &target.grant,
                SshGrantView::Revoking {
                    worker_acknowledged: true,
                    ..
                }
            )
        })
    }

    /// Return an asynchronously resolved consent card to the manager or its retained browser.
    pub fn settle_grant(&mut self, approved: bool) {
        let request_id = self.pending_grant.as_ref().map(|request| request.request_id.clone());
        let (project_request_id, follow_up) = match &self.page {
            SshModalPage::Grant(card) => (
                card.project.as_ref().map(|project| project.request_id),
                card.follow_up,
            ),
            _ => (None, None),
        };
        if approved {
            if let (Some(request_id), Some(follow_up)) = (request_id.clone(), follow_up) {
                self.settled_grant_follow_up = Some((request_id, follow_up));
            }
        }
        self.pending_grant = None;
        self.submitted_grant = None;
        self.pending_grant_session_id = None;
        self.pending_grant_follow_up = None;
        self.local_grant_options = None;
        if project_request_id.is_some() {
            if let Some(browser) = self.project_browser.as_mut() {
                browser.preparing = false;
                browser.notice = Some(if approved {
                    "Project access approved; opening remote project…".into()
                } else {
                    "Project access was not approved.".into()
                });
            }
            self.page = SshModalPage::ProjectBrowser;
            return;
        }
        self.page = SshModalPage::Manager;
        self.show_info(if approved {
            "SSH access grant approved."
        } else {
            "SSH access grant denied."
        });
    }

    /// Take the typed continuation for the exact advanced grant, before or after settlement.
    pub fn take_grant_follow_up(&mut self, request_id: &str) -> Option<SshGrantFollowUp> {
        if self
            .pending_grant
            .as_ref()
            .is_some_and(|request| request.request_id == request_id)
            && let SshModalPage::Grant(card) = &mut self.page
            && card.request_id == request_id
        {
            return card.follow_up.take();
        }
        let (resolved_request_id, follow_up) = self.settled_grant_follow_up.as_ref()?;
        if resolved_request_id != request_id {
            return None;
        }
        let follow_up = *follow_up;
        self.settled_grant_follow_up = None;
        Some(follow_up)
    }

    pub fn target_label_for_binding(&self, binding_id: &str) -> Option<String> {
        self.targets.iter().find_map(|target| {
            (target.grant.binding_id() == Some(binding_id)).then(|| target.label.clone())
        })
    }

    fn open_diagnostic(&mut self) -> bool {
        if let Some(target) = self.selected_target() {
            let grant = match &target.grant {
                SshGrantView::NotGranted =>
                    "Choose a remote folder to open a project. No project access has been approved yet.".to_owned(),
                SshGrantView::Granted {
                    binding_id,
                    root,
                    capabilities,
                    is_default,
                } => format!(
                    "Grant binding: {binding_id}\nRemote root: {root}\nCapabilities: {}\nDefault binding: {}",
                    capabilities.compact(),
                    if *is_default { "yes" } else { "no" }
                ),
                SshGrantView::Revoking {
                    binding_id,
                    worker_acknowledged,
                } => format!(
                    "Grant binding: {binding_id}\nRevocation: {}",
                    if *worker_acknowledged {
                        "confirmed by worker"
                    } else {
                        "locally revoked; worker confirmation pending"
                    }
                ),
            };
            let latest_error = self
                .message
                .as_ref()
                .filter(|(_, is_error)| *is_error)
                .map(|(message, _)| message.clone());
            let message = format!(
                "Label: {}\nTarget ID: {}\nSource: {}\nResolved address: {}\nConnection detail: {}\n\n{}",
                target.label,
                target.target_id,
                target.source,
                target.effective_address,
                target.connection_detail,
                grant,
            );
            self.page = SshModalPage::Diagnostic(SshDiagnosticCard::details(message, target.connected, latest_error));
            return true;
        }
        let Some((message, true)) = self.message.as_ref() else {
            return false;
        };
        self.page = SshModalPage::Diagnostic(SshDiagnosticCard::new(message.clone()));
        true
    }

    pub fn show_error(&mut self, error: impl Into<String>) {
        self.pending_connection = None;
        let error = error.into();
        match std::mem::replace(&mut self.page, SshModalPage::Manager) {
            SshModalPage::ProjectBrowser | SshModalPage::Authentication(_)
                if self.project_browser.is_some() =>
            {
                self.resume_project_browser_after_authentication = false;
                if let Some(browser) = self.project_browser.as_mut() {
                    browser.loading = false;
                    browser.preparing = false;
                    browser.error = Some(error.clone());
                }
                let mut diagnostic = SshDiagnosticCard::new(error);
                diagnostic.return_browser = true;
                self.page = SshModalPage::Diagnostic(diagnostic);
                self.message = None;
            }
            SshModalPage::Grant(card) => {
                let mut diagnostic = SshDiagnosticCard::new(error);
                diagnostic.return_grant = Some(card);
                self.page = SshModalPage::Diagnostic(diagnostic);
                self.message = None;
            }
            SshModalPage::Add(form) => {
                let mut diagnostic = SshDiagnosticCard::new(error);
                diagnostic.return_add = Some(form);
                self.page = SshModalPage::Diagnostic(diagnostic);
                self.message = None;
            }
            SshModalPage::Diagnostic(mut card) => {
                card.message = error;
                card.is_error = true;
                card.connected = None;
                card.latest_error = None;
                card.scroll_offset = 0;
                self.page = SshModalPage::Diagnostic(card);
            }
            page => {
                self.page = page;
                self.message = Some((error, true));
            }
        }
    }

    pub fn show_info(&mut self, message: impl Into<String>) {
        self.pending_connection = None;
        self.message = Some((message.into(), false));
    }

    fn selected_target(&self) -> Option<&SshTargetView> {
        self.targets.get(self.selected)
    }

    fn return_to_manager(&mut self) {
        self.page = SshModalPage::Manager;
    }

    fn return_after_authentication(&mut self) {
        if self.resume_project_browser_after_authentication && self.project_browser.is_some() {
            self.page = SshModalPage::ProjectBrowser;
        } else {
            self.page = SshModalPage::Manager;
        }
        self.resume_project_browser_after_authentication = false;
    }
}

/// Intent emitted by the modal; app dispatch maps these to local shell-control calls.
pub enum SshModalOutcome {
    Close,
    Changed,
    Unchanged,
    Refresh,
    AddTarget {
        draft: SshManualTargetDraft,
        submission_id: u64,
    },
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
    BrowseProjectDirectory {
        request_id: u64,
        target_id: String,
        path: Option<String>,
    },
    ChooseProjectDirectory {
        request_id: u64,
        target_id: String,
        root: String,
        identity: SshHostIdentity,
    },
    CancelProjectOpen {
        request_id: u64,
    },
    ApproveOperation {
        approval_id: String,
        approved: bool,
    },
    ApproveWorkerInstall {
        request_id: String,
        session_id: String,
        binding_id: String,
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

const FOOTER_MANAGER_OPEN_FOLDER: usize = 101;
const FOOTER_MANAGER_CONNECTION: usize = 102;
const FOOTER_MANAGER_ADD: usize = 103;
const FOOTER_MANAGER_DIAGNOSTIC: usize = 104;
const FOOTER_MANAGER_ADVANCED: usize = 105;
const FOOTER_MANAGER_GRANT: usize = 111;
const FOOTER_MANAGER_USE: usize = 112;
const FOOTER_MANAGER_REVOKE: usize = 113;
const FOOTER_MANAGER_CLOSE: usize = 108;
const FOOTER_ADD_SAVE: usize = 201;
const FOOTER_ADD_CANCEL: usize = 202;
const FOOTER_GRANT_READ: usize = 301;
const FOOTER_GRANT_WRITE: usize = 302;
const FOOTER_GRANT_EXECUTE: usize = 303;
const FOOTER_GRANT_LIFETIME: usize = 304;
const FOOTER_GRANT_DEFAULT: usize = 305;
const FOOTER_GRANT_ALLOW: usize = 306;
const FOOTER_GRANT_DENY: usize = 307;
const FOOTER_BROWSER_PARENT: usize = 308;
const FOOTER_BROWSER_OPEN: usize = 309;
const FOOTER_OPERATION_ALLOW: usize = 401;
const FOOTER_OPERATION_DENY: usize = 402;
const FOOTER_OPERATION_CLOSE: usize = 403;
const FOOTER_WORKER_INSTALL_APPROVE: usize = 404;
const FOOTER_WORKER_INSTALL_DECLINE: usize = 405;
const FOOTER_AUTH_SUBMIT: usize = 501;
const FOOTER_AUTH_CANCEL: usize = 502;
const FOOTER_HOST_TRUST_ONCE: usize = 511;
const FOOTER_HOST_TRUST_STORE: usize = 512;
const FOOTER_HOST_REPLACE: usize = 513;
const FOOTER_HOST_REJECT: usize = 514;
const FOOTER_DIAGNOSTIC_CLOSE: usize = 601;

const PRIMARY_MANAGER_SHORTCUTS: &[Shortcut<'static>] = &[
    Shortcut {
        label: "j/k move",
        clickable: false,
        id: 0,
    },
    Shortcut {
        label: "Enter choose folder",
        clickable: true,
        id: FOOTER_MANAGER_OPEN_FOLDER,
    },
    Shortcut {
        label: "c connect/disconnect",
        clickable: true,
        id: FOOTER_MANAGER_CONNECTION,
    },
    Shortcut {
        label: "a add",
        clickable: true,
        id: FOOTER_MANAGER_ADD,
    },
    Shortcut {
        label: "d details",
        clickable: true,
        id: FOOTER_MANAGER_DIAGNOSTIC,
    },
    Shortcut {
        label: "m advanced",
        clickable: true,
        id: FOOTER_MANAGER_ADVANCED,
    },
    Shortcut {
        label: "Esc close",
        clickable: true,
        id: FOOTER_MANAGER_CLOSE,
    },
];

const ADVANCED_MANAGER_SHORTCUTS: &[Shortcut<'static>] = &[
    Shortcut {
        label: "j/k move",
        clickable: false,
        id: 0,
    },
    Shortcut {
        label: "Enter choose folder",
        clickable: true,
        id: FOOTER_MANAGER_OPEN_FOLDER,
    },
    Shortcut {
        label: "c connect/disconnect",
        clickable: true,
        id: FOOTER_MANAGER_CONNECTION,
    },
    Shortcut {
        label: "g grant",
        clickable: true,
        id: FOOTER_MANAGER_GRANT,
    },
    Shortcut {
        label: "u use",
        clickable: true,
        id: FOOTER_MANAGER_USE,
    },
    Shortcut {
        label: "r revoke / refresh",
        clickable: true,
        id: FOOTER_MANAGER_REVOKE,
    },
    Shortcut {
        label: "d details",
        clickable: true,
        id: FOOTER_MANAGER_DIAGNOSTIC,
    },
    Shortcut {
        label: "m basic",
        clickable: true,
        id: FOOTER_MANAGER_ADVANCED,
    },
    Shortcut {
        label: "Esc close",
        clickable: true,
        id: FOOTER_MANAGER_CLOSE,
    },
];

const PROJECT_BROWSER_SHORTCUTS: &[Shortcut<'static>] = &[
    Shortcut {
        label: "↑/↓ or j/k choose",
        clickable: false,
        id: 0,
    },
    Shortcut {
        label: "Enter child",
        clickable: false,
        id: 0,
    },
    Shortcut {
        label: "/ path",
        clickable: false,
        id: 0,
    },
    Shortcut {
        label: "Backspace parent",
        clickable: true,
        id: FOOTER_BROWSER_PARENT,
    },
    Shortcut {
        label: "o Open this folder",
        clickable: true,
        id: FOOTER_BROWSER_OPEN,
    },
    Shortcut {
        label: "Esc back/cancel",
        clickable: true,
        id: FOOTER_MANAGER_CLOSE,
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
        clickable: true,
        id: FOOTER_OPERATION_ALLOW,
    },
    Shortcut {
        label: "n deny",
        clickable: true,
        id: FOOTER_OPERATION_DENY,
    },
    Shortcut {
        label: "Esc deny",
        clickable: true,
        id: FOOTER_OPERATION_CLOSE,
    },
];

const WORKER_INSTALL_FALLBACK_SHORTCUTS: &[Shortcut<'static>] = &[
    Shortcut {
        label: "↑/↓ inspect",
        clickable: false,
        id: 0,
    },
    Shortcut {
        label: "Enter/y install via this computer",
        clickable: true,
        id: FOOTER_WORKER_INSTALL_APPROVE,
    },
    Shortcut {
        label: "n/Esc decline",
        clickable: true,
        id: FOOTER_WORKER_INSTALL_DECLINE,
    },
];

const WORKER_INSTALL_PROGRESS_SHORTCUTS: &[Shortcut<'static>] = &[
    Shortcut {
        label: "↑/↓ inspect",
        clickable: false,
        id: 0,
    },
    Shortcut {
        label: "Project setup pending…",
        clickable: false,
        id: 0,
    },
];

const AUTHENTICATION_SHORTCUTS: &[Shortcut<'static>] = &[
    Shortcut {
        label: "Enter submit",
        clickable: true,
        id: FOOTER_AUTH_SUBMIT,
    },
    Shortcut {
        label: "PgUp/PgDn scroll",
        clickable: false,
        id: 0,
    },
    Shortcut {
        label: "Esc cancel",
        clickable: true,
        id: FOOTER_AUTH_CANCEL,
    },
];

const UNKNOWN_HOST_KEY_SHORTCUTS: &[Shortcut<'static>] = &[
    Shortcut {
        label: "y trust once",
        clickable: true,
        id: FOOTER_HOST_TRUST_ONCE,
    },
    Shortcut {
        label: "s trust and save",
        clickable: true,
        id: FOOTER_HOST_TRUST_STORE,
    },
    Shortcut {
        label: "n/Esc reject",
        clickable: true,
        id: FOOTER_HOST_REJECT,
    },
];

const REPLACE_HOST_KEY_SHORTCUTS: &[Shortcut<'static>] = &[
    Shortcut {
        label: "r replace and save",
        clickable: true,
        id: FOOTER_HOST_REPLACE,
    },
    Shortcut {
        label: "n/Esc reject",
        clickable: true,
        id: FOOTER_HOST_REJECT,
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
        clickable: true,
        id: FOOTER_HOST_REJECT,
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
        clickable: true,
        id: FOOTER_DIAGNOSTIC_CLOSE,
    },
];

const ADD_SHORTCUTS: &[Shortcut<'static>] = &[
    Shortcut {
        label: "Tab field",
        clickable: false,
        id: 0,
    },
    Shortcut {
        label: "Enter save",
        clickable: true,
        id: FOOTER_ADD_SAVE,
    },
    Shortcut {
        label: "Esc back",
        clickable: true,
        id: FOOTER_ADD_CANCEL,
    },
];

const ADD_SUBMITTING_SHORTCUTS: &[Shortcut<'static>] = &[
    Shortcut {
        label: "Tab field",
        clickable: false,
        id: 0,
    },
    Shortcut {
        label: "Saving…",
        clickable: false,
        id: FOOTER_ADD_SAVE,
    },
    Shortcut {
        label: "Esc back",
        clickable: true,
        id: FOOTER_ADD_CANCEL,
    },
];

const GRANT_SHORTCUTS: &[Shortcut<'static>] = &[
    Shortcut {
        label: "Alt+r read",
        clickable: true,
        id: FOOTER_GRANT_READ,
    },
    Shortcut {
        label: "Alt+w write",
        clickable: true,
        id: FOOTER_GRANT_WRITE,
    },
    Shortcut {
        label: "Alt+x run",
        clickable: true,
        id: FOOTER_GRANT_EXECUTE,
    },
    Shortcut {
        label: "Alt+l lifetime",
        clickable: true,
        id: FOOTER_GRANT_LIFETIME,
    },
    Shortcut {
        label: "Alt+d default",
        clickable: true,
        id: FOOTER_GRANT_DEFAULT,
    },
    Shortcut {
        label: "PgUp/PgDn inspect",
        clickable: false,
        id: 0,
    },
    Shortcut {
        label: "Tab/Space options",
        clickable: false,
        id: 0,
    },
    Shortcut {
        label: "Enter allow",
        clickable: true,
        id: FOOTER_GRANT_ALLOW,
    },
    Shortcut {
        label: "Esc deny",
        clickable: true,
        id: FOOTER_GRANT_DENY,
    },
];

const PROJECT_GRANT_SHORTCUTS: &[Shortcut<'static>] = &[
    Shortcut {
        label: "PgUp/PgDn inspect",
        clickable: false,
        id: 0,
    },
    Shortcut {
        label: "Tab/Space permissions",
        clickable: false,
        id: 0,
    },
    Shortcut {
        label: "Enter allow",
        clickable: true,
        id: FOOTER_GRANT_ALLOW,
    },
    Shortcut {
        label: "Esc deny",
        clickable: true,
        id: FOOTER_GRANT_DENY,
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
    state.manager_row_hits.clear();
    if let Some(browser) = state.project_browser.as_mut() {
        browser.row_hits.clear();
    }
    match &mut state.page {
        SshModalPage::Add(form) => form.field_hits.clear(),
        SshModalPage::Grant(card) => card.control_hits.clear(),
        SshModalPage::Manager
        | SshModalPage::ProjectBrowser
        | SshModalPage::OperationApproval(_)
        | SshModalPage::WorkerInstallFallback(_)
        | SshModalPage::Authentication(_)
        | SshModalPage::Diagnostic(_) => {}
    }
    let (title, shortcuts): (&str, &[Shortcut<'_>]) = match &state.page {
        SshModalPage::Manager => (
            "SSH targets",
            if state.manager_advanced {
                ADVANCED_MANAGER_SHORTCUTS
            } else {
                PRIMARY_MANAGER_SHORTCUTS
            },
        ),
        SshModalPage::Add(form) => (
            "Add SSH target",
            if form.submitting {
                ADD_SUBMITTING_SHORTCUTS
            } else {
                ADD_SHORTCUTS
            },
        ),
        SshModalPage::Grant(card) => (
            if card.is_project_consent() {
                "Open remote project"
            } else {
                "SSH access grant"
            },
            if card.is_project_consent() {
                PROJECT_GRANT_SHORTCUTS
            } else {
                GRANT_SHORTCUTS
            },
        ),
        SshModalPage::ProjectBrowser => ("Choose remote folder", PROJECT_BROWSER_SHORTCUTS),
        SshModalPage::OperationApproval(_) => {
            ("SSH operation approval", OPERATION_APPROVAL_SHORTCUTS)
        }
        SshModalPage::WorkerInstallFallback(card) => (
            "Remote worker fallback",
            if card.submitting || card.is_decided() {
                WORKER_INSTALL_PROGRESS_SHORTCUTS
            } else {
                WORKER_INSTALL_FALLBACK_SHORTCUTS
            },
        ),
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
        SshModalPage::Diagnostic(card) => (
            if card.is_error {
                "SSH diagnostic"
            } else {
                "SSH connection details"
            },
            DIAGNOSTIC_SHORTCUTS,
        ),
    };
    let config = window_config(title, compact || area.height < 16, shortcuts);
    let areas = modal_window::render_modal_window(buf, area, &mut state.window, &config, theme)?;
    let content = areas.content;
    if matches!(&state.page, SshModalPage::Manager) {
        render_manager(buf, content, state, theme);
    } else {
        match &mut state.page {
            SshModalPage::Add(form) => render_add(buf, content, form, theme),
            SshModalPage::Grant(card) => render_grant(buf, content, card, theme),
            SshModalPage::ProjectBrowser => {
                if let Some(browser) = state.project_browser.as_mut() {
                    render_project_browser(buf, content, browser, theme);
                }
            }
            SshModalPage::OperationApproval(card) => {
                render_operation_approval(buf, content, card, theme)
            }
            SshModalPage::WorkerInstallFallback(card) => {
                render_worker_install_fallback(buf, content, card, theme)
            }
            SshModalPage::Authentication(card) => render_authentication(buf, content, card, theme),
            SshModalPage::Diagnostic(card) => render_diagnostic(buf, content, card, theme),
            SshModalPage::Manager => unreachable!("manager rendered before mutable page match"),
        }
    }
    None
}

fn render_manager(buf: &mut Buffer, area: Rect, state: &mut SshManagerState, theme: &Theme) {
    if area.height == 0 {
        state.manager_visible_rows = 0;
        return;
    }
    if state.loading {
        state.manager_visible_rows = 0;
        buf.set_string(
            area.x,
            area.y,
            "Loading configured targets…",
            Style::default().fg(theme.text_secondary),
        );
        return;
    }
    if state.targets.is_empty() {
        state.manager_visible_rows = 0;
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
    let visible = (area.height.saturating_sub(2) / row_height) as usize;
    state.manager_visible_rows = visible;
    if visible == 0 {
        render_message(buf, area, state.message.as_ref(), theme);
        return;
    }
    let max_start = state.targets.len().saturating_sub(visible);
    if state.selected < state.manager_scroll_offset {
        state.manager_scroll_offset = state.selected;
    } else if state.selected >= state.manager_scroll_offset.saturating_add(visible) {
        state.manager_scroll_offset = state.selected + 1 - visible;
    }
    state.manager_scroll_offset = state.manager_scroll_offset.min(max_start);
    let start = state.manager_scroll_offset;
    for (offset, target) in state.targets.iter().skip(start).take(visible).enumerate() {
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
        let connection_style = if target.connected {
            Style::default().fg(theme.accent_success)
        } else {
            Style::default().fg(theme.gray)
        };
        buf.set_stringn(
            area.x,
            y.saturating_add(1),
            detail,
            area.width as usize,
            connection_style,
        );
        buf.set_stringn(
            area.x,
            y.saturating_add(2),
            format!("  {}", target.connection_detail),
            area.width as usize,
            if target.connected {
                Style::default().fg(theme.accent_success)
            } else {
                Style::default().fg(theme.gray_dim)
            },
        );
        state.manager_row_hits.push(ManagerRowHit {
            target_id: target.target_id.clone(),
            binding_id: target.grant.binding_id().map(str::to_owned),
            rect: Rect::new(area.x, y, area.width, row_height),
        });
    }
    render_message(buf, area, state.message.as_ref(), theme);
}

fn render_project_browser(
    buf: &mut Buffer,
    area: Rect,
    browser: &mut SshProjectBrowser,
    theme: &Theme,
) {
    if area.height == 0 || area.width == 0 {
        browser.visible_rows = 0;
        return;
    }
    let mut y = area.y;
    buf.set_stringn(
        area.x,
        y,
        format!("Server: {}", browser.target_id),
        area.width as usize,
        Style::default().fg(theme.text_secondary),
    );
    y = y.saturating_add(1);
    if y < area.bottom() {
        render_line_editor(
            buf,
            Rect::new(area.x, y, area.width, 1),
            "Path: ",
            &browser.path,
            browser.editing_path,
            theme,
        );
        y = y.saturating_add(1);
    }
    let status = if let Some(error) = browser.error.as_deref() {
        Some((error, true))
    } else if let Some(notice) = browser.notice.as_deref() {
        Some((notice, false))
    } else if browser.loading {
        Some(("Loading remote folders…", false))
    } else if browser.preparing {
        Some(("Preparing remote project…", false))
    } else {
        None
    };
    let status_rows = usize::from(status.is_some());
    let parent = browser
        .listing
        .as_ref()
        .and_then(|listing| listing.parent.as_deref())
        .unwrap_or("No parent folder");
    if y < area.bottom().saturating_sub(status_rows as u16) {
        buf.set_stringn(
            area.x,
            y,
            format!("Parent: {parent}"),
            area.width as usize,
            Style::default().fg(theme.gray),
        );
        y = y.saturating_add(1);
    }
    let rows_bottom = area.bottom().saturating_sub(status_rows as u16);
    let available = rows_bottom.saturating_sub(y) as usize;
    browser.visible_rows = available;
    if let Some(listing) = browser.listing.as_ref() {
        let directory_count = listing.directories.len();
        browser.selected = browser.selected.min(directory_count.saturating_sub(1));
        if browser.selected < browser.scroll_offset {
            browser.scroll_offset = browser.selected;
        } else if available > 0 && browser.selected >= browser.scroll_offset + available {
            browser.scroll_offset = browser.selected + 1 - available;
        }
        browser.scroll_offset = browser
            .scroll_offset
            .min(directory_count.saturating_sub(available.max(1)));
        for (offset, entry) in listing
            .directories
            .iter()
            .skip(browser.scroll_offset)
            .take(available)
            .enumerate()
        {
            let index = browser.scroll_offset + offset;
            let selected = index == browser.selected;
            let style = if selected {
                Style::default()
                    .fg(theme.accent_user)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(theme.text_secondary)
            };
            let prefix = if selected { "› " } else { "  " };
            let rect = Rect::new(area.x, y.saturating_add(offset as u16), area.width, 1);
            buf.set_stringn(
                rect.x,
                rect.y,
                format!("{prefix}{}", entry.name),
                rect.width as usize,
                style,
            );
            browser.row_hits.push(ProjectDirectoryHit { index, rect });
        }
        if directory_count == 0 && available > 0 {
            buf.set_stringn(
                area.x,
                y,
                "No child directories in this folder.",
                area.width as usize,
                Style::default().fg(theme.gray),
            );
        }
        if listing.truncated && available > 0 {
            let row = rows_bottom.saturating_sub(1);
            buf.set_stringn(
                area.x,
                row,
                "Directory list truncated; enter a path to navigate further.",
                area.width as usize,
                Style::default().fg(theme.warning),
            );
        }
    }
    if let Some((status, error)) = status {
        let style = if error {
            Style::default()
                .fg(theme.accent_error)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(theme.text_secondary)
        };
        buf.set_stringn(
            area.x,
            area.bottom().saturating_sub(1),
            status,
            area.width as usize,
            style,
        );
    }
}

fn render_diagnostic(buf: &mut Buffer, area: Rect, card: &mut SshDiagnosticCard, theme: &Theme) {
    if area.height == 0 {
        return;
    }
    let mut lines = Vec::new();
    append_wrapped_authentication_line(
        &mut lines,
        if card.is_error {
            "Full SSH diagnostic:"
        } else {
            "SSH connection details:"
        },
        if card.is_error {
            AuthenticationLineTone::Warning
        } else {
            AuthenticationLineTone::Normal
        },
        area.width as usize,
    );
    append_wrapped_authentication_line(
        &mut lines,
        "",
        AuthenticationLineTone::Normal,
        area.width as usize,
    );
    if let Some(connected) = card.connected {
        append_wrapped_authentication_line(
            &mut lines,
            if connected { "Connection: connected" } else { "Connection: disconnected" },
            if connected { AuthenticationLineTone::Success } else { AuthenticationLineTone::Muted },
            area.width as usize,
        );
    }
    append_wrapped_authentication_line(
        &mut lines,
        &card.message,
        if card.is_error {
            AuthenticationLineTone::Error
        } else {
            AuthenticationLineTone::Normal
        },
        area.width as usize,
    );
    if let Some(error) = card.latest_error.as_deref() {
        append_wrapped_authentication_line(
            &mut lines, &format!("\nLatest SSH error:\n{error}"),
            AuthenticationLineTone::Error, area.width as usize,
        );
    }
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
            AuthenticationLineTone::Success => Style::default().fg(theme.accent_success),
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

fn render_line_editor(
    buf: &mut Buffer,
    area: Rect,
    label: &str,
    editor: &LineEditor,
    active: bool,
    theme: &Theme,
) {
    if area.width == 0 {
        return;
    }
    let label_width = (label.len() as u16).min(area.width);
    let label_style = if active {
        Style::default()
            .fg(theme.accent_user)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(theme.text_secondary)
    };
    buf.set_stringn(area.x, area.y, label, label_width as usize, label_style);
    let input_x = area.x.saturating_add(label_width);
    let input_width = area.width.saturating_sub(label_width) as usize;
    if input_width == 0 {
        return;
    }
    let viewport = editor.viewport(input_width);
    let visible = editor
        .text()
        .get(viewport.visible_byte_range)
        .unwrap_or_default();
    buf.set_stringn(
        input_x,
        area.y,
        visible,
        input_width,
        Style::default().fg(theme.text_secondary),
    );
    if active {
        let cursor_x = input_x.saturating_add(
            (viewport.cursor_display_column as u16).min(input_width.saturating_sub(1) as u16),
        );
        if let Some(cell) = buf.cell_mut((cursor_x, area.y)) {
            cell.set_style(theme.block_cursor_over(theme.bg_base));
        }
    }
}

fn render_add(buf: &mut Buffer, area: Rect, form: &mut SshManualTargetForm, theme: &Theme) {
    let mut y = area.y;
    let status = form.error.as_deref().or_else(|| {
        form.submitting
            .then_some("Saving target through the local SSH service…")
    });
    let fields_bottom = area.bottom().saturating_sub(u16::from(status.is_some()));
    let mut worker_command_visible = false;
    for field in ManualTargetField::ALL {
        if y >= fields_bottom {
            break;
        }
        let row = Rect::new(area.x, y, area.width, 1);
        render_line_editor(
            buf,
            row,
            field.input_label(),
            form.editor(field),
            form.active == field,
            theme,
        );
        form.field_hits.push((field, row));
        worker_command_visible |= field == ManualTargetField::WorkerCommand;
        y = y.saturating_add(1);
    }
    if worker_command_visible {
        let helper_lines = modal_window::word_wrap(
            "Blank: automatic managed worker install and updates. Explicit command: user-managed; never overwritten.",
            (area.width as usize).max(1),
        );
        if y.saturating_add(helper_lines.len() as u16) <= fields_bottom {
            for line in helper_lines {
                buf.set_stringn(
                    area.x,
                    y,
                    line,
                    area.width as usize,
                    Style::default().fg(theme.text_secondary),
                );
                y = y.saturating_add(1);
            }
        }
    }
    if let Some(status) = status
        && y < area.bottom()
    {
        buf.set_stringn(
            area.x,
            y,
            status,
            area.width as usize,
            if form.error.is_some() {
                Style::default()
                    .fg(theme.accent_error)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(theme.text_secondary)
            },
        );
    }
}

struct GrantRenderLine {
    text: String,
    focus: Option<SshGrantFocus>,
    warning: bool,
    root_editor: bool,
}

fn push_grant_wrapped(
    lines: &mut Vec<GrantRenderLine>,
    text: impl AsRef<str>,
    width: usize,
    focus: Option<SshGrantFocus>,
    warning: bool,
) {
    for line in modal_window::word_wrap(text.as_ref(), width.max(1)) {
        lines.push(GrantRenderLine {
            text: line.to_owned(),
            focus,
            warning,
            root_editor: false,
        });
    }
}

fn render_grant(buf: &mut Buffer, area: Rect, card: &mut SshGrantCard, theme: &Theme) {
    if area.height == 0 || area.width == 0 {
        card.max_scroll_offset = 0;
        card.reviewed_to_end = false;
        return;
    }
    let width = area.width as usize;
    let mut lines = Vec::new();
    push_grant_wrapped(
        &mut lines,
        if card.is_project_consent() {
            format!("Server: {}", card.target_label)
        } else {
            format!("Target: {} ({})", card.target_label, card.target_id)
        },
        width,
        None,
        false,
    );
    push_grant_wrapped(
        &mut lines,
        match card.identity.as_deref() {
            Some(identity) => format!("Verified SSH identity: {identity}"),
            None => "Connection identity will be verified before authorization can be approved."
                .to_owned(),
        },
        width,
        None,
        false,
    );
    push_grant_wrapped(
        &mut lines,
        if card.is_project_consent() {
            format!("Project folder: {}", card.root.text())
        } else {
            format!("Requested remote root: {}", card.root.text())
        },
        width,
        None,
        false,
    );
    lines.push(GrantRenderLine {
        text: if card.is_project_consent() {
            "Folder (same or narrower): ".into()
        } else {
            "Edit root: ".into()
        },
        focus: Some(SshGrantFocus::Root),
        warning: false,
        root_editor: true,
    });
    for (focus, enabled, label) in [
        (
            SshGrantFocus::Read,
            card.capabilities.read,
            "Read remote files",
        ),
        (
            SshGrantFocus::Write,
            card.capabilities.write,
            "Write remote files",
        ),
        (
            SshGrantFocus::Execute,
            card.capabilities.execute,
            "Run remote commands",
        ),
    ] {
        push_grant_wrapped(
            &mut lines,
            format!("[{}] {label}", if enabled { "x" } else { " " }),
            width,
            Some(focus),
            false,
        );
    }
    if card.is_project_consent() {
        push_grant_wrapped(
            &mut lines,
            format!(
                "[{}] Remember this project",
                if card.project_remember() { "x" } else { " " }
            ),
            width,
            Some(SshGrantFocus::RememberProject),
            false,
        );
    } else {
        push_grant_wrapped(
            &mut lines,
            format!("Lifetime: {}", card.lifetime.label()),
            width,
            Some(SshGrantFocus::Lifetime),
            false,
        );
        push_grant_wrapped(
            &mut lines,
            format!(
                "Default SSH target: {}",
                if card.set_default { "yes" } else { "no" }
            ),
            width,
            Some(SshGrantFocus::Default),
            false,
        );
    }
    if card.agent_requested {
        push_grant_wrapped(
            &mut lines,
            "This access request came from the agent; allowing it does not expose credentials to it.",
            width,
            None,
            false,
        );
    }
    if card.capabilities.execute {
        push_grant_wrapped(
            &mut lines,
            "Warning: run executes with this SSH user's remote privileges; cwd is not a sandbox.",
            width,
            None,
            true,
        );
    }
    if let Some(reason) = card.reason.as_deref() {
        push_grant_wrapped(&mut lines, format!("Reason: {reason}"), width, None, false);
    }
    if let Some(follow_up) = card.follow_up {
        push_grant_wrapped(&mut lines, follow_up.guidance(), width, None, false);
    } else if card.request_id.is_empty() {
        push_grant_wrapped(
            &mut lines,
            "Press Enter to continue to identity verification. A later card will require explicit approval of the verified identity and scope.",
            width,
            None,
            false,
        );
    } else if card.is_project_consent() {
        push_grant_wrapped(
            &mut lines,
            "Review the verified identity, folder, and permissions before opening this project.",
            width,
            None,
            false,
        );
    } else {
        push_grant_wrapped(
            &mut lines,
            "Scroll through every authorization detail before allowing this grant.",
            width,
            None,
            false,
        );
    }

    let body_height = area.height.saturating_sub(u16::from(card.error.is_some())) as usize;
    card.page_size = body_height.max(1);
    card.max_scroll_offset = lines.len().saturating_sub(body_height);
    card.scroll_offset = card.scroll_offset.min(card.max_scroll_offset);
    card.reviewed_to_end = body_height > 0 && card.scroll_offset >= card.max_scroll_offset;
    for (index, line) in lines
        .iter()
        .skip(card.scroll_offset)
        .take(body_height)
        .enumerate()
    {
        let y = area.y.saturating_add(index as u16);
        let rect = Rect::new(area.x, y, area.width, 1);
        let focused = line.focus == Some(card.focus);
        let style = if line.warning {
            Style::default()
                .fg(theme.accent_error)
                .add_modifier(Modifier::BOLD)
        } else if focused {
            Style::default()
                .fg(theme.accent_user)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(theme.text_secondary)
        };
        if line.root_editor {
            render_line_editor(buf, rect, &line.text, &card.root, focused, theme);
        } else {
            buf.set_stringn(area.x, y, &line.text, area.width as usize, style);
        }
        if let Some(focus) = line.focus {
            card.control_hits.push(GrantControlHit { focus, rect });
        }
    }
    if let Some(error) = card.error.as_deref() {
        buf.set_stringn(
            area.x,
            area.bottom().saturating_sub(1),
            error,
            area.width as usize,
            Style::default()
                .fg(theme.accent_error)
                .add_modifier(Modifier::BOLD),
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

fn render_worker_install_fallback(
    buf: &mut Buffer,
    area: Rect,
    card: &mut SshWorkerInstallFallbackCard,
    theme: &Theme,
) {
    if area.height == 0 {
        return;
    }
    let lines = worker_install_fallback_lines(card, area.width as usize);
    card.max_scroll_offset = lines.len().saturating_sub(area.height as usize);
    card.scroll_offset = card.scroll_offset.min(card.max_scroll_offset);
    for (index, line) in lines
        .iter()
        .skip(card.scroll_offset)
        .take(area.height as usize)
        .enumerate()
    {
        let style = if line.starts_with("Remote worker installation")
            || line.starts_with("Remote installation detail:")
            || line.starts_with("Error:")
        {
            Style::default()
                .fg(theme.accent_error)
                .add_modifier(Modifier::BOLD)
        } else if line.starts_with("Requested version:") || line.starts_with("Remote platform:") {
            Style::default()
                .fg(theme.accent_user)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(theme.text_secondary)
        };
        buf.set_stringn(
            area.x,
            area.y.saturating_add(index as u16),
            line,
            area.width as usize,
            style,
        );
    }
}

fn worker_install_fallback_lines(card: &SshWorkerInstallFallbackCard, width: usize) -> Vec<String> {
    let options = textwrap::Options::new(width.max(1))
        .break_words(true)
        .wrap_algorithm(textwrap::WrapAlgorithm::FirstFit);
    let mut paragraphs = vec![
        "Remote worker installation needs a local transfer.".into(),
        format!("Requested version: {}", card.version),
        format!("Remote platform: {}", card.platform),
        format!("SSH target: {}", card.target_id),
        String::new(),
        "Approve to obtain this exact build on this computer and upload it through the already-authenticated SSH connection. Release builds are downloaded using this computer's network; development builds use this computer's executable. No SSH credentials or tokens are sent to the remote host.".into(),
        String::new(),
        "Remote installation detail:".into(),
    ];
    paragraphs.extend(card.remote_error.lines().map(str::to_owned));
    if card.remote_error.is_empty() {
        paragraphs.push("(No remote error detail was supplied.)".into());
    }
    paragraphs.push(String::new());
    paragraphs.push(if let Some(error) = card.error.as_deref() {
        format!("Error: {error}")
    } else if card.submitting {
        "Submitting local fallback decision…".into()
    } else if let Some(progress) = card.progress.as_deref() {
        progress.to_owned()
    } else if card.decision_accepted == Some(true) {
        "Local transfer approved; waiting for project setup…".into()
    } else if card.decision_accepted == Some(false) {
        "Local transfer declined; waiting for project setup…".into()
    } else {
        "Obtain locally and upload this exact build? Enter/y approve · n/Esc decline".into()
    });
    paragraphs.iter().flat_map(|paragraph| {
        textwrap::wrap(paragraph, &options).into_iter().map(std::borrow::Cow::into_owned)
    }).collect()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AuthenticationLineTone {
    Normal,
    Muted,
    Success,
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
            AuthenticationLineTone::Success => Style::default().fg(theme.accent_success),
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
    if matches!(&state.page, SshModalPage::ProjectBrowser) {
        return handle_project_browser_key(state, key);
    }
    let outcome = match &mut state.page {
        SshModalPage::Add(form) => handle_add_key(form, key),
        SshModalPage::Grant(card) => handle_grant_key(card, key),
        SshModalPage::OperationApproval(card) => handle_operation_approval_key(card, key),
        SshModalPage::WorkerInstallFallback(card) => handle_worker_install_fallback_key(card, key),
        SshModalPage::Authentication(card) => handle_authentication_key(card, key),
        SshModalPage::Diagnostic(card) => handle_diagnostic_key(card, key),
        SshModalPage::Manager | SshModalPage::ProjectBrowser => {
            unreachable!("manager and browser are handled before borrowing modal page")
        }
    };
    if matches!(&outcome, SshModalOutcome::AnswerAuthentication { .. }) {
        state.return_after_authentication();
    }
    outcome
}

fn footer_key_for(page: &SshModalPage, id: usize) -> Option<KeyEvent> {
    let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
    let alt = |code| KeyEvent::new(code, KeyModifiers::ALT);
    match (page, id) {
        (SshModalPage::Manager, FOOTER_MANAGER_OPEN_FOLDER) => Some(key(KeyCode::Enter)),
        (SshModalPage::Manager, FOOTER_MANAGER_CONNECTION) => Some(key(KeyCode::Char('c'))),
        (SshModalPage::Manager, FOOTER_MANAGER_ADD) => Some(key(KeyCode::Char('a'))),
        (SshModalPage::Manager, FOOTER_MANAGER_ADVANCED) => Some(key(KeyCode::Char('m'))),
        (SshModalPage::Manager, FOOTER_MANAGER_GRANT) => Some(key(KeyCode::Char('g'))),
        (SshModalPage::Manager, FOOTER_MANAGER_USE) => Some(key(KeyCode::Char('u'))),
        (SshModalPage::Manager, FOOTER_MANAGER_REVOKE) => Some(key(KeyCode::Char('r'))),
        (SshModalPage::Manager, FOOTER_MANAGER_DIAGNOSTIC) => Some(key(KeyCode::Char('d'))),
        (SshModalPage::Manager, FOOTER_MANAGER_CLOSE) => Some(key(KeyCode::Esc)),
        (SshModalPage::Add(form), FOOTER_ADD_SAVE) if !form.submitting => Some(key(KeyCode::Enter)),
        (SshModalPage::Add(_), FOOTER_ADD_CANCEL) => Some(key(KeyCode::Esc)),
        (SshModalPage::Grant(_), FOOTER_GRANT_READ) => Some(alt(KeyCode::Char('r'))),
        (SshModalPage::Grant(_), FOOTER_GRANT_WRITE) => Some(alt(KeyCode::Char('w'))),
        (SshModalPage::Grant(_), FOOTER_GRANT_EXECUTE) => Some(alt(KeyCode::Char('x'))),
        (SshModalPage::Grant(card), FOOTER_GRANT_LIFETIME) if !card.is_project_consent() => {
            Some(alt(KeyCode::Char('l')))
        }
        (SshModalPage::Grant(card), FOOTER_GRANT_DEFAULT) if !card.is_project_consent() => {
            Some(alt(KeyCode::Char('d')))
        }
        (SshModalPage::Grant(_), FOOTER_GRANT_ALLOW) => Some(key(KeyCode::Enter)),
        (SshModalPage::Grant(_), FOOTER_GRANT_DENY) => Some(key(KeyCode::Esc)),
        (SshModalPage::ProjectBrowser, FOOTER_BROWSER_PARENT) => Some(key(KeyCode::Backspace)),
        (SshModalPage::ProjectBrowser, FOOTER_BROWSER_OPEN) => Some(key(KeyCode::Char('o'))),
        (SshModalPage::ProjectBrowser, FOOTER_MANAGER_CLOSE) => Some(key(KeyCode::Esc)),
        (SshModalPage::OperationApproval(_), FOOTER_OPERATION_ALLOW) => {
            Some(key(KeyCode::Char('y')))
        }
        (SshModalPage::OperationApproval(_), FOOTER_OPERATION_DENY) => {
            Some(key(KeyCode::Char('n')))
        }
        (SshModalPage::OperationApproval(_), FOOTER_OPERATION_CLOSE) => Some(key(KeyCode::Esc)),
        (SshModalPage::WorkerInstallFallback(card), FOOTER_WORKER_INSTALL_APPROVE)
            if !card.submitting && !card.is_decided() =>
        {
            Some(key(KeyCode::Enter))
        }
        (SshModalPage::WorkerInstallFallback(card), FOOTER_WORKER_INSTALL_DECLINE)
            if !card.submitting && !card.is_decided() =>
        {
            Some(key(KeyCode::Char('n')))
        }
        (SshModalPage::Authentication(card), FOOTER_AUTH_SUBMIT)
            if !matches!(&card.kind, SshAuthKind::HostKey { .. }) =>
        {
            Some(key(KeyCode::Enter))
        }
        (SshModalPage::Authentication(card), FOOTER_AUTH_CANCEL)
            if !matches!(&card.kind, SshAuthKind::HostKey { .. }) =>
        {
            Some(key(KeyCode::Esc))
        }
        (
            SshModalPage::Authentication(SshAuthCard {
                kind:
                    SshAuthKind::HostKey {
                        status,
                        previous_keys,
                        can_replace,
                        ..
                    },
                ..
            }),
            FOOTER_HOST_REPLACE,
        ) if changed_host_key(status, previous_keys) && *can_replace => {
            Some(key(KeyCode::Char('r')))
        }
        (
            SshModalPage::Authentication(SshAuthCard {
                kind:
                    SshAuthKind::HostKey {
                        status,
                        previous_keys,
                        ..
                    },
                ..
            }),
            FOOTER_HOST_TRUST_ONCE,
        ) if !changed_host_key(status, previous_keys) => Some(key(KeyCode::Char('y'))),
        (
            SshModalPage::Authentication(SshAuthCard {
                kind:
                    SshAuthKind::HostKey {
                        status,
                        previous_keys,
                        ..
                    },
                ..
            }),
            FOOTER_HOST_TRUST_STORE,
        ) if !changed_host_key(status, previous_keys) => Some(key(KeyCode::Char('s'))),
        (
            SshModalPage::Authentication(SshAuthCard {
                kind: SshAuthKind::HostKey { .. },
                ..
            }),
            FOOTER_HOST_REJECT,
        ) => Some(key(KeyCode::Char('n'))),
        (SshModalPage::Diagnostic(_), FOOTER_DIAGNOSTIC_CLOSE) => Some(key(KeyCode::Esc)),
        _ => None,
    }
}

/// Paste directly into the focused non-secret or secret local editor. The paste is never placed in
/// chat state, notifications, or a replay buffer.
pub fn handle_ssh_paste(state: &mut SshManagerState, text: &str) -> SshModalOutcome {
    if matches!(&state.page, SshModalPage::ProjectBrowser) {
        let Some(browser) = state.project_browser.as_mut() else {
            return SshModalOutcome::Unchanged;
        };
        if !browser.editing_path {
            return SshModalOutcome::Unchanged;
        }
        let outcome = browser.path.insert_paste(text);
        if matches!(&outcome, LineEditOutcome::TextChanged) {
            browser.error = None;
        }
        return line_outcome(outcome);
    }
    let outcome = match &mut state.page {
        SshModalPage::Add(form) => {
            if form.submitting {
                return SshModalOutcome::Unchanged;
            }
            let outcome = form.editor_mut().insert_paste(text);
            if matches!(&outcome, LineEditOutcome::TextChanged) {
                form.error = None;
            }
            outcome
        }
        SshModalPage::Grant(card) if card.focus == SshGrantFocus::Root => {
            let outcome = card.root.insert_paste(text);
            if matches!(&outcome, LineEditOutcome::TextChanged) {
                mark_grant_edited(card);
            }
            outcome
        }
        SshModalPage::Grant(_)
        | SshModalPage::Manager
        | SshModalPage::OperationApproval(_)
        | SshModalPage::WorkerInstallFallback(_)
        | SshModalPage::Diagnostic(_) => return SshModalOutcome::Unchanged,
        SshModalPage::Authentication(card) => card
            .answer_mut()
            .map(|answer| answer.insert_paste(text))
            .unwrap_or(LineEditOutcome::Unhandled),
        SshModalPage::ProjectBrowser => {
            unreachable!("browser paste is handled before borrowing modal page")
        }
    };
    line_outcome(outcome)
}

/// Route modal chrome first, then act only on render-time content hitboxes. Footer actions are
/// deliberately translated back into their keyboard event so mouse and keyboard share consent,
/// validation, and pending-operation semantics.
pub fn handle_ssh_mouse(state: &mut SshManagerState, mouse: &MouseEvent) -> SshModalOutcome {
    match modal_window::handle_modal_mouse(&mut state.window, mouse.kind, mouse.column, mouse.row) {
        ModalWindowOutcome::CloseRequested => return close_current_page(state),
        ModalWindowOutcome::ShortcutActivated(id) => {
            let Some(key) = footer_key_for(&state.page, id) else {
                return SshModalOutcome::Unchanged;
            };
            return handle_ssh_key(state, &key);
        }
        ModalWindowOutcome::Handled => return SshModalOutcome::Changed,
        ModalWindowOutcome::Unhandled => {}
        ModalWindowOutcome::TabChanged(_)
        | ModalWindowOutcome::CollapseGroup
        | ModalWindowOutcome::ExpandGroup
        | ModalWindowOutcome::CollapseDetails
        | ModalWindowOutcome::ExpandDetails
        | ModalWindowOutcome::JumpToParent(_) => return SshModalOutcome::Unchanged,
    }

    if matches!(
        mouse.kind,
        MouseEventKind::Down(crossterm::event::MouseButton::Left)
    ) {
        if matches!(&state.page, SshModalPage::Manager) {
            let hit = state
                .manager_row_hits
                .iter()
                .find(|hit| {
                    mouse.column >= hit.rect.x
                        && mouse.column < hit.rect.right()
                        && mouse.row >= hit.rect.y
                        && mouse.row < hit.rect.bottom()
                })
                .cloned();
            let Some(hit) = hit else {
                return SshModalOutcome::Unchanged;
            };
            let Some(index) = state.targets.iter().position(|target| {
                target.target_id == hit.target_id
                    && target.grant.binding_id() == hit.binding_id.as_deref()
            }) else {
                return SshModalOutcome::Unchanged;
            };
            state.selected = index;
            return SshModalOutcome::Changed;
        }
        if matches!(&state.page, SshModalPage::ProjectBrowser) {
            let Some(browser) = state.project_browser.as_mut() else {
                return SshModalOutcome::Unchanged;
            };
            let hit = browser
                .row_hits
                .iter()
                .find(|hit| {
                    mouse.column >= hit.rect.x
                        && mouse.column < hit.rect.right()
                        && mouse.row >= hit.rect.y
                        && mouse.row < hit.rect.bottom()
                })
                .cloned();
            let Some(hit) = hit else {
                return SshModalOutcome::Unchanged;
            };
            browser.selected = hit.index;
            browser.editing_path = false;
            return SshModalOutcome::Changed;
        }
        match &mut state.page {
            SshModalPage::Add(form) if !form.submitting => {
                if let Some((field, _)) = form.field_hits.iter().find(|(_, rect)| {
                    mouse.column >= rect.x
                        && mouse.column < rect.right()
                        && mouse.row >= rect.y
                        && mouse.row < rect.bottom()
                }) {
                    form.active = *field;
                    return SshModalOutcome::Changed;
                }
                return SshModalOutcome::Unchanged;
            }
            SshModalPage::Grant(card) => {
                let focus = card
                    .control_hits
                    .iter()
                    .find(|hit| {
                        mouse.column >= hit.rect.x
                            && mouse.column < hit.rect.right()
                            && mouse.row >= hit.rect.y
                            && mouse.row < hit.rect.bottom()
                    })
                    .map(|hit| hit.focus);
                let Some(focus) = focus else {
                    return SshModalOutcome::Unchanged;
                };
                card.focus = focus;
                if focus != SshGrantFocus::Root {
                    activate_grant_focus(card);
                }
                return SshModalOutcome::Changed;
            }
            SshModalPage::ProjectBrowser => {
                unreachable!("browser mouse rows are handled before borrowing modal page")
            }
            SshModalPage::Manager
            | SshModalPage::Add(_)
            | SshModalPage::OperationApproval(_)
            | SshModalPage::WorkerInstallFallback(_)
            | SshModalPage::Authentication(_)
            | SshModalPage::Diagnostic(_) => return SshModalOutcome::Unchanged,
        }
    }

    let delta = match mouse.kind {
        MouseEventKind::ScrollUp => -3isize,
        MouseEventKind::ScrollDown => 3isize,
        _ => return SshModalOutcome::Unchanged,
    };
    if matches!(&state.page, SshModalPage::Manager) {
        return scroll_manager(state, delta);
    }
    if matches!(&state.page, SshModalPage::ProjectBrowser) {
        return scroll_project_browser(state, delta);
    }
    match &mut state.page {
        SshModalPage::Grant(card) => {
            let next = if delta.is_negative() {
                card.scroll_offset.saturating_sub(delta.unsigned_abs())
            } else {
                card.scroll_offset
                    .saturating_add(delta as usize)
                    .min(card.max_scroll_offset)
            };
            if next == card.scroll_offset {
                SshModalOutcome::Unchanged
            } else {
                card.scroll_offset = next;
                SshModalOutcome::Changed
            }
        }
        SshModalPage::WorkerInstallFallback(card) => {
            let next = if delta.is_negative() {
                card.scroll_offset.saturating_sub(delta.unsigned_abs())
            } else {
                card.scroll_offset
                    .saturating_add(delta as usize)
                    .min(card.max_scroll_offset)
            };
            if next == card.scroll_offset {
                SshModalOutcome::Unchanged
            } else {
                card.scroll_offset = next;
                SshModalOutcome::Changed
            }
        }
        SshModalPage::Authentication(card) => {
            let next = if delta.is_negative() {
                card.scroll_offset.saturating_sub(delta.unsigned_abs())
            } else {
                card.scroll_offset
                    .saturating_add(delta as usize)
                    .min(card.max_scroll_offset)
            };
            if next == card.scroll_offset {
                SshModalOutcome::Unchanged
            } else {
                card.scroll_offset = next;
                SshModalOutcome::Changed
            }
        }
        SshModalPage::Diagnostic(card) => {
            let next = if delta.is_negative() {
                card.scroll_offset.saturating_sub(delta.unsigned_abs())
            } else {
                card.scroll_offset
                    .saturating_add(delta as usize)
                    .min(card.max_scroll_offset)
            };
            if next == card.scroll_offset {
                SshModalOutcome::Unchanged
            } else {
                card.scroll_offset = next;
                SshModalOutcome::Changed
            }
        }
        SshModalPage::ProjectBrowser => {
            unreachable!("browser scrolling is handled before borrowing modal page")
        }
        SshModalPage::Manager | SshModalPage::Add(_) | SshModalPage::OperationApproval(_) => {
            SshModalOutcome::Unchanged
        }
    }
}

fn scroll_manager(state: &mut SshManagerState, delta: isize) -> SshModalOutcome {
    let visible = state.manager_visible_rows;
    if visible == 0 {
        return SshModalOutcome::Unchanged;
    }
    let max_scroll = state.targets.len().saturating_sub(visible);
    let next = if delta.is_negative() {
        state
            .manager_scroll_offset
            .saturating_sub(delta.unsigned_abs())
    } else {
        state
            .manager_scroll_offset
            .saturating_add(delta as usize)
            .min(max_scroll)
    };
    if next == state.manager_scroll_offset {
        return SshModalOutcome::Unchanged;
    }
    state.manager_scroll_offset = next;
    if state.selected < next {
        state.selected = next;
    } else if state.selected >= next.saturating_add(visible) {
        state.selected = next + visible - 1;
    }
    SshModalOutcome::Changed
}

fn scroll_project_browser(state: &mut SshManagerState, delta: isize) -> SshModalOutcome {
    let Some(browser) = state.project_browser.as_mut() else {
        return SshModalOutcome::Unchanged;
    };
    let visible = browser.visible_rows;
    let directory_count = browser
        .listing
        .as_ref()
        .map_or(0, |listing| listing.directories.len());
    if visible == 0 || directory_count == 0 {
        return SshModalOutcome::Unchanged;
    }
    let max_scroll = directory_count.saturating_sub(visible);
    let next = if delta.is_negative() {
        browser.scroll_offset.saturating_sub(delta.unsigned_abs())
    } else {
        browser
            .scroll_offset
            .saturating_add(delta as usize)
            .min(max_scroll)
    };
    if next == browser.scroll_offset {
        return SshModalOutcome::Unchanged;
    }
    browser.scroll_offset = next;
    if browser.selected < next {
        browser.selected = next;
    } else if browser.selected >= next.saturating_add(visible) {
        browser.selected = next + visible - 1;
    }
    SshModalOutcome::Changed
}

fn close_current_page(state: &mut SshManagerState) -> SshModalOutcome {
    if matches!(&state.page, SshModalPage::ProjectBrowser) {
        if let Some(pending) = state.pending_project_open.take() {
            if let Some(browser) = state.project_browser.as_mut() {
                browser.preparing = false;
                browser.open_request_id = None;
                browser.notice = Some("Project opening cancelled.".into());
            }
            return SshModalOutcome::CancelProjectOpen {
                request_id: pending.request_id,
            };
        }
        state.project_browser = None;
        state.page = SshModalPage::Manager;
        return SshModalOutcome::Changed;
    }
    if let SshModalPage::Diagnostic(card) = &mut state.page {
        state.page = if let Some(grant) = card.return_grant.take() {
            SshModalPage::Grant(grant)
        } else if let Some(form) = card.return_add.take() {
            SshModalPage::Add(form)
        } else if card.return_browser && state.project_browser.is_some() {
            SshModalPage::ProjectBrowser
        } else {
            SshModalPage::Manager
        };
        return SshModalOutcome::Changed;
    }
    if matches!(&state.page, SshModalPage::Grant(card) if card.request_id.is_empty()) {
        state.return_to_manager();
        return SshModalOutcome::Changed;
    }
    if matches!(&state.page, SshModalPage::Add(_)) {
        state.return_to_manager();
        return SshModalOutcome::Changed;
    }
    if let SshModalPage::WorkerInstallFallback(card) = &state.page {
        if card.submitting || card.is_decided() {
            return SshModalOutcome::Unchanged;
        }
        return SshModalOutcome::ApproveWorkerInstall {
            request_id: card.request_id.clone(),
            session_id: card.session_id.clone(),
            binding_id: card.binding_id.clone(),
            approved: false,
        };
    }
    if let SshModalPage::Authentication(card) = &mut state.page {
        let challenge_id = card.challenge_id.clone();
        let connection_generation = card.connection_generation;
        let target_id = card.target_id.clone();
        let host_key_decision = matches!(&card.kind, SshAuthKind::HostKey { .. })
            .then_some(xai_grok_shell::ssh::SshHostKeyDecision::Reject);
        card.clear_answers();
        state.return_after_authentication();
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
        SshModalPage::WorkerInstallFallback(_) => {
            unreachable!("worker install fallback was handled before read-only match")
        }
        SshModalPage::Authentication(_) => {
            unreachable!("authentication answers were cleared before read-only match")
        }
        SshModalPage::ProjectBrowser => {
            unreachable!("project browser was handled before read-only match")
        }
        SshModalPage::Add(_) => unreachable!("add page returned before read-only match"),
        SshModalPage::Diagnostic(_) => unreachable!("diagnostic returned before read-only match"),
    }
}

fn begin_grant_flow(
    state: &mut SshManagerState,
    follow_up: Option<SshGrantFollowUp>,
) -> SshModalOutcome {
    let Some((target_id, target_label, granted_root)) = state.selected_target().map(|target| {
        (
            target.target_id.clone(),
            target.label.clone(),
            target
                .grant
                .granted_root()
                .map(str::to_owned)
                .unwrap_or_else(|| ".".to_owned()),
        )
    }) else {
        state.show_error("Select an SSH target before starting an access grant.");
        return SshModalOutcome::Changed;
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
    let mut card = SshGrantCard::new(
        String::new(),
        target_id,
        target_label,
        None,
        granted_root,
        None,
        false,
    );
    card.follow_up = follow_up;
    state.pending_grant_follow_up = follow_up;
    state.page = SshModalPage::Grant(card);
    SshModalOutcome::Changed
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
            if state.open_diagnostic() {
                SshModalOutcome::Changed
            } else {
                state.show_info("Select an SSH target to inspect its configuration.");
                SshModalOutcome::Changed
            }
        }
        KeyCode::Char('m') if key.modifiers.is_empty() => {
            state.manager_advanced = !state.manager_advanced;
            SshModalOutcome::Changed
        }
        KeyCode::Char('c') if key.modifiers.is_empty() => {
            let selected = state
                .selected_target()
                .map(|target| (target.target_id.clone(), target.connected));
            match selected {
                Some((target_id, true)) => SshModalOutcome::Disconnect { target_id },
                Some((target_id, false)) => SshModalOutcome::Connect { target_id },
                None => {
                    state.show_error("Select an SSH target before connecting.");
                    SshModalOutcome::Changed
                }
            }
        }
        KeyCode::Enter => {
            let Some(target_id) = state.selected_target().map(|target| target.target_id.clone())
            else {
                state.show_error("Select an SSH target before choosing a remote folder.");
                return SshModalOutcome::Changed;
            };
            state.begin_project_browser(target_id, None)
        }
        KeyCode::Char('g') if key.modifiers.is_empty() && state.manager_advanced => {
            begin_grant_flow(state, None)
        }
        KeyCode::Char('r') if key.modifiers.is_empty() && state.manager_advanced => {
            let binding_id = state
                .selected_target()
                .and_then(|target| match &target.grant {
                    SshGrantView::Granted { binding_id, .. } => Some(binding_id.clone()),
                    SshGrantView::NotGranted | SshGrantView::Revoking { .. } => None,
                });
            if let Some(binding_id) = binding_id {
                state.mark_binding_revoked(&binding_id, false);
                SshModalOutcome::RevokeBinding { binding_id }
            } else {
                SshModalOutcome::Refresh
            }
        }
        KeyCode::Char('u') if key.modifiers.is_empty() && state.manager_advanced => {
            let binding_id = state
                .selected_target()
                .and_then(|target| match &target.grant {
                    SshGrantView::Granted { binding_id, .. } => Some(binding_id.clone()),
                    SshGrantView::NotGranted | SshGrantView::Revoking { .. } => None,
                });
            if let Some(binding_id) = binding_id {
                SshModalOutcome::UseBinding { binding_id }
            } else if matches!(
                state.selected_target().map(|target| &target.grant),
                Some(SshGrantView::Revoking { .. })
            ) {
                state.show_info("The selected SSH grant is being revoked; refresh before using another binding.");
                SshModalOutcome::Changed
            } else {
                begin_grant_flow(state, Some(SshGrantFollowUp::UseBinding))
            }
        }
        _ => SshModalOutcome::Unchanged,
    }
}

fn handle_project_browser_key(state: &mut SshManagerState, key: &KeyEvent) -> SshModalOutcome {
    if matches!(key.code, KeyCode::Esc) && !key.modifiers.is_empty() {
        return SshModalOutcome::Unchanged;
    }
    let editing_path = state
        .project_browser
        .as_ref()
        .is_some_and(|browser| browser.editing_path);
    if editing_path {
        match key.code {
            KeyCode::Esc => {
                let Some(browser) = state.project_browser.as_mut() else {
                    return SshModalOutcome::Unchanged;
                };
                if let Some(path) = browser.listed_path().map(str::to_owned) {
                    browser.path.set_text(path);
                }
                browser.editing_path = false;
                return SshModalOutcome::Changed;
            }
            KeyCode::Enter => {
                let path = state
                    .project_browser
                    .as_ref()
                    .map(|browser| browser.path.text().trim().to_owned())
                    .unwrap_or_default();
                if path.is_empty() {
                    if let Some(browser) = state.project_browser.as_mut() {
                        browser.error = Some("Enter a remote folder path.".into());
                    }
                    return SshModalOutcome::Changed;
                }
                return state.browse_project_directory(Some(path));
            }
            _ => {
                let Some(browser) = state.project_browser.as_mut() else {
                    return SshModalOutcome::Unchanged;
                };
                let outcome = browser.path.handle_key(key);
                if matches!(&outcome, LineEditOutcome::TextChanged) {
                    browser.error = None;
                }
                return line_outcome(outcome);
            }
        }
    }

    match key.code {
        KeyCode::Esc => close_current_page(state),
        KeyCode::Up | KeyCode::Char('k') if key.modifiers.is_empty() => {
            let Some(browser) = state.project_browser.as_mut() else {
                return SshModalOutcome::Unchanged;
            };
            browser.selected = browser.selected.saturating_sub(1);
            SshModalOutcome::Changed
        }
        KeyCode::Down | KeyCode::Char('j') if key.modifiers.is_empty() => {
            let Some(browser) = state.project_browser.as_mut() else {
                return SshModalOutcome::Unchanged;
            };
            let directory_count = browser
                .listing
                .as_ref()
                .map_or(0, |listing| listing.directories.len());
            if browser.selected + 1 < directory_count {
                browser.selected += 1;
            }
            SshModalOutcome::Changed
        }
        KeyCode::Char('/') if key.modifiers.is_empty() => {
            let Some(browser) = state.project_browser.as_mut() else {
                return SshModalOutcome::Unchanged;
            };
            if browser.loading || browser.preparing {
                return SshModalOutcome::Unchanged;
            }
            browser.path.reset();
            browser.editing_path = true;
            browser.error = None;
            SshModalOutcome::Changed
        }
        KeyCode::Enter => {
            let path = state
                .project_browser
                .as_ref()
                .filter(|browser| !browser.loading && !browser.preparing)
                .and_then(SshProjectBrowser::selected_directory_path);
            match path {
                Some(path) => state.browse_project_directory(Some(path)),
                None => SshModalOutcome::Unchanged,
            }
        }
        KeyCode::Backspace => {
            let path = state
                .project_browser
                .as_ref()
                .filter(|browser| !browser.loading && !browser.preparing)
                .and_then(|browser| {
                    browser
                        .listing
                        .as_ref()
                        .and_then(|listing| listing.parent.clone())
                });
            match path {
                Some(path) => state.browse_project_directory(Some(path)),
                None => SshModalOutcome::Unchanged,
            }
        }
        KeyCode::Char('o') if key.modifiers.is_empty() => {
            let request_id = next_nonzero_id(&NEXT_PROJECT_DIRECTORY_REQUEST_ID);
            let Some(browser) = state.project_browser.as_mut() else {
                return SshModalOutcome::Unchanged;
            };
            if browser.loading || browser.preparing || browser.open_request_id.is_some() {
                return SshModalOutcome::Unchanged;
            }
            let Some((root, identity)) = browser
                .listing
                .as_ref()
                .map(|listing| (listing.path.clone(), listing.identity.clone()))
            else {
                return SshModalOutcome::Unchanged;
            };
            browser.open_request_id = Some(request_id);
            browser.preparing = true;
            browser.notice = Some("Opening this folder…".into());
            SshModalOutcome::ChooseProjectDirectory {
                request_id,
                target_id: browser.target_id.clone(),
                root,
                identity,
            }
        }
        _ => SshModalOutcome::Unchanged,
    }
}

fn handle_add_key(form: &mut SshManualTargetForm, key: &KeyEvent) -> SshModalOutcome {
    if form.submitting {
        return SshModalOutcome::Unchanged;
    }
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
        KeyCode::Enter => match form.start_submit() {
            Ok((draft, submission_id)) => SshModalOutcome::AddTarget {
                draft,
                submission_id,
            },
            Err(error) => {
                form.error = Some(error);
                SshModalOutcome::Changed
            }
        },
        _ => {
            let outcome = form.editor_mut().handle_key(key);
            if matches!(&outcome, LineEditOutcome::TextChanged) {
                form.error = None;
            }
            line_outcome(outcome)
        }
    }
}

fn mark_grant_edited(card: &mut SshGrantCard) {
    card.error = None;
    card.scroll_offset = 0;
    card.reviewed_to_end = false;
}

fn activate_grant_focus(card: &mut SshGrantCard) {
    match card.focus {
        SshGrantFocus::Root => {}
        SshGrantFocus::Read => card.capabilities.read = !card.capabilities.read,
        SshGrantFocus::Write => card.capabilities.write = !card.capabilities.write,
        SshGrantFocus::Execute => card.capabilities.execute = !card.capabilities.execute,
        SshGrantFocus::Lifetime => card.lifetime = card.lifetime.toggle(),
        SshGrantFocus::Default => card.set_default = !card.set_default,
        SshGrantFocus::RememberProject => {
            if let Some(project) = card.project.as_mut() {
                project.remember = !project.remember;
            }
        }
    }
    if card.focus != SshGrantFocus::Root {
        mark_grant_edited(card);
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
            lifetime: if card.is_project_consent() && card.project_remember() {
                SshGrantLifetime::ProjectRule
            } else {
                card.lifetime
            },
            set_default: if card.is_project_consent() {
                false
            } else {
                card.set_default
            },
        },
        KeyCode::Tab => {
            card.focus_next(false);
            SshModalOutcome::Changed
        }
        KeyCode::BackTab => {
            card.focus_next(true);
            SshModalOutcome::Changed
        }
        KeyCode::PageUp => {
            card.scroll_offset = card.scroll_offset.saturating_sub(card.page_size);
            SshModalOutcome::Changed
        }
        KeyCode::PageDown => {
            card.scroll_offset = card
                .scroll_offset
                .saturating_add(card.page_size)
                .min(card.max_scroll_offset);
            SshModalOutcome::Changed
        }
        KeyCode::Home => {
            card.scroll_offset = 0;
            SshModalOutcome::Changed
        }
        KeyCode::End => {
            card.scroll_offset = card.max_scroll_offset;
            SshModalOutcome::Changed
        }
        KeyCode::Char('r') if key.modifiers == KeyModifiers::ALT => {
            card.focus = SshGrantFocus::Read;
            activate_grant_focus(card);
            SshModalOutcome::Changed
        }
        KeyCode::Char('w') if key.modifiers == KeyModifiers::ALT => {
            card.focus = SshGrantFocus::Write;
            activate_grant_focus(card);
            SshModalOutcome::Changed
        }
        KeyCode::Char('x') if key.modifiers == KeyModifiers::ALT => {
            card.focus = SshGrantFocus::Execute;
            activate_grant_focus(card);
            SshModalOutcome::Changed
        }
        KeyCode::Char('l')
            if key.modifiers == KeyModifiers::ALT && !card.is_project_consent() =>
        {
            card.focus = SshGrantFocus::Lifetime;
            activate_grant_focus(card);
            SshModalOutcome::Changed
        }
        KeyCode::Char('d')
            if key.modifiers == KeyModifiers::ALT && !card.is_project_consent() =>
        {
            card.focus = SshGrantFocus::Default;
            activate_grant_focus(card);
            SshModalOutcome::Changed
        }
        KeyCode::Char(' ') if key.modifiers.is_empty() && card.focus != SshGrantFocus::Root => {
            activate_grant_focus(card);
            SshModalOutcome::Changed
        }
        KeyCode::Enter => {
            let root = card.root.text().trim();
            if root.is_empty() {
                card.error = Some("A remote root is required.".into());
                return SshModalOutcome::Changed;
            }
            if card.is_project_consent() && !card.permits_root(root) {
                card.error = Some(
                    "Project access can use the verified folder or a folder beneath it.".into(),
                );
                return SshModalOutcome::Changed;
            }
            if !card.capabilities.any() {
                card.error = Some("Choose at least one capability.".into());
                return SshModalOutcome::Changed;
            }
            if card.is_project_consent() && !card.capabilities.read {
                card.error = Some("Read permission is required to open a remote project.".into());
                return SshModalOutcome::Changed;
            }
            if !card.request_id.is_empty() && !card.reviewed_to_end {
                card.error = Some(
                    "Review every wrapped identity, root, reason, and capability detail before allowing this grant."
                        .into(),
                );
                return SshModalOutcome::Changed;
            }
            let lifetime = if card.is_project_consent() && card.project_remember() {
                SshGrantLifetime::ProjectRule
            } else {
                card.lifetime
            };
            let set_default = !card.is_project_consent() && card.set_default;
            if card.request_id.is_empty() {
                SshModalOutcome::RequestGrant {
                    target_id: card.target_id.clone(),
                    root: root.to_owned(),
                    capabilities: card.capabilities,
                    lifetime,
                    set_default,
                }
            } else {
                SshModalOutcome::ApproveGrant {
                    request_id: card.request_id.clone(),
                    approved: true,
                    target_id: Some(card.target_id.clone()),
                    root: Some(root.to_owned()),
                    capabilities: Some(card.capabilities),
                    lifetime,
                    set_default,
                }
            }
        }
        _ if card.focus == SshGrantFocus::Root => {
            let outcome = card.root.handle_key(key);
            if matches!(&outcome, LineEditOutcome::TextChanged) {
                mark_grant_edited(card);
            }
            line_outcome(outcome)
        }
        _ => SshModalOutcome::Unchanged,
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

fn handle_worker_install_fallback_key(
    card: &mut SshWorkerInstallFallbackCard,
    key: &KeyEvent,
) -> SshModalOutcome {
    if card.submitting || card.is_decided() {
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
        KeyCode::Enter | KeyCode::Char('y') if key.modifiers.is_empty() => {
            SshModalOutcome::ApproveWorkerInstall {
                request_id: card.request_id.clone(),
                session_id: card.session_id.clone(),
                binding_id: card.binding_id.clone(),
                approved: true,
            }
        }
        KeyCode::Char('n') | KeyCode::Esc if key.modifiers.is_empty() => {
            SshModalOutcome::ApproveWorkerInstall {
                request_id: card.request_id.clone(),
                session_id: card.session_id.clone(),
                binding_id: card.binding_id.clone(),
                approved: false,
            }
        }
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

    fn worker_install_request(request_id: &str) -> xai_grok_shell::ssh::SshWorkerInstallRequest {
        xai_grok_shell::ssh::SshWorkerInstallRequest {
            client_id: 7,
            request_id: request_id.into(),
            session_id: "project-session".into(),
            binding_id: "project-binding".into(),
            target_id: "fixture-worker".into(),
            version: "1.2.3-rc.4".into(),
            platform: "linux-aarch64".into(),
            remote_error: format!(
                "remote download failed because proxy rejected artifact request {request_id}; diagnostic-tail-{request_id}"
            ),
        }
    }

    #[test]
    fn worker_fallback_wraps_details_and_routes_keyboard_mouse_and_close_decisions() {
        let mut state = SshManagerState::new(Some("source-session".into()));
        state.show_worker_install_fallback(worker_install_request("fallback-1"));
        let area = Rect::new(0, 0, 60, 12);
        let theme = Theme::current();
        let mut frames = String::new();
        loop {
            let mut buffer = Buffer::empty(area);
            render_ssh_modal(&mut buffer, area, &mut state, false, &theme);
            frames.push_str(&buffer_text(&buffer));
            let at_end = matches!(
                &state.page,
                SshModalPage::WorkerInstallFallback(card)
                    if card.scroll_offset == card.max_scroll_offset
            );
            if at_end {
                break;
            }
            assert!(matches!(
                handle_ssh_key(&mut state, &key(KeyCode::Down)),
                SshModalOutcome::Changed
            ));
        }
        assert!(frames.contains("1.2.3-rc.4"));
        assert!(frames.contains("linux-aarch64"));
        let unwrapped: String = frames.chars().filter(char::is_ascii_alphanumeric).collect();
        assert!(unwrapped.contains("diagnostictailfallback1"), "{frames}");

        let approve = state
            .window
            .shortcut_hits
            .iter()
            .find(|hit| hit.id == FOOTER_WORKER_INSTALL_APPROVE)
            .expect("rendered fallback approve footer")
            .rect;
        let click = MouseEvent {
            kind: MouseEventKind::Down(crossterm::event::MouseButton::Left),
            column: approve.x,
            row: approve.y,
            modifiers: KeyModifiers::NONE,
        };
        assert!(matches!(
            handle_ssh_mouse(&mut state, &click),
            SshModalOutcome::ApproveWorkerInstall { approved: true, .. }
        ));

        let mut declined = SshManagerState::new(Some("source-session".into()));
        declined.show_worker_install_fallback(worker_install_request("fallback-2"));
        assert!(matches!(
            handle_ssh_key(&mut declined, &key(KeyCode::Esc)),
            SshModalOutcome::ApproveWorkerInstall {
                approved: false,
                ..
            }
        ));

        let mut closed = SshManagerState::new(Some("source-session".into()));
        closed.show_worker_install_fallback(worker_install_request("fallback-3"));
        assert!(matches!(
            close_current_page(&mut closed),
            SshModalOutcome::ApproveWorkerInstall {
                approved: false,
                ..
            }
        ));
    }

    #[test]
    fn worker_fallback_completion_preserves_matching_progress_until_project_terminal_state() {
        let mut state = SshManagerState::new(Some("source-session".into()));
        state.show_worker_install_fallback(worker_install_request("fallback-1"));
        assert!(state.submit_worker_install(
            7,
            "fallback-1",
            "project-session",
            "project-binding",
            true,
        ));
        state.apply_worker_install_progress(
            7,
            "fallback-1",
            "project-session",
            "project-binding",
            "fixture-worker",
            Some("Uploading exact build…".into()),
        );
        state.settle_worker_install_decision(
            7,
            "fallback-1",
            "project-session",
            "project-binding",
            true,
            None,
        );
        assert!(matches!(
            &state.page,
            SshModalPage::WorkerInstallFallback(card)
                if card.decision_accepted == Some(true)
                    && card.progress.as_deref() == Some("Uploading exact build…")
        ));

        state.show_worker_install_fallback(worker_install_request("fallback-2"));
        state.settle_worker_install_decision(
            7,
            "fallback-1",
            "project-session",
            "project-binding",
            true,
            Some("late local control failure".into()),
        );
        assert!(matches!(
            &state.page,
            SshModalPage::WorkerInstallFallback(card) if card.request_id == "fallback-2"
        ));

        state.settle_project_open();
        assert!(matches!(&state.page, SshModalPage::Manager));
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

    fn target_view(target_id: &str, grant: SshGrantView) -> SshTargetView {
        SshTargetView {
            target_id: target_id.into(),
            label: format!("{target_id} label"),
            source: "manual".into(),
            effective_address: "user@example.test:22".into(),
            connected: false,
            connection_detail: "Disconnected.".into(),
            grant,
        }
    }

    fn granted(binding_id: &str, root: &str) -> SshGrantView {
        SshGrantView::Granted {
            binding_id: binding_id.into(),
            root: root.into(),
            capabilities: SshCapabilitiesView::default(),
            is_default: false,
        }
    }

    fn remote_identity() -> SshHostIdentity {
        SshHostIdentity {
            hostname: "build.example.test".into(),
            port: 22,
            username: "builder".into(),
            fingerprint: "SHA256:fixture".into(),
        }
    }

    fn directory_listing(
        target_id: &str,
        path: &str,
        parent: Option<&str>,
        directories: &[(&str, &str)],
    ) -> SshDirectoryListing {
        SshDirectoryListing {
            target_id: target_id.into(),
            identity: remote_identity(),
            path: path.into(),
            parent: parent.map(str::to_owned),
            directories: directories
                .iter()
                .map(|(name, path)| xai_grok_shell::ssh::SshDirectoryEntry {
                    name: (*name).into(),
                    path: (*path).into(),
                })
                .collect(),
            truncated: false,
        }
    }

    fn add_submission_id(outcome: SshModalOutcome) -> u64 {
        match outcome {
            SshModalOutcome::AddTarget { submission_id, .. } => submission_id,
            _ => panic!("expected add-target submission"),
        }
    }

    #[test]
    fn failed_folder_navigation_restores_the_displayed_directory_before_opening() {
        let mut state = SshManagerState::new(None);
        let SshModalOutcome::BrowseProjectDirectory { request_id, .. } =
            state.begin_project_browser("server-1".into(), None)
        else { panic!("browse expected") };
        state.settle_project_directory(request_id, "server-1",
            Ok(directory_listing("server-1", "/home/project", Some("/home"), &[])));
        let SshModalOutcome::BrowseProjectDirectory { request_id, .. } =
            state.browse_project_directory(Some("/missing-folder".into()))
        else { panic!("navigation expected") };
        state.settle_project_directory(request_id, "server-1", Err("folder missing".into()));
        assert!(matches!(state.page, SshModalPage::Diagnostic(_)));
        close_current_page(&mut state);
        assert_eq!(state.project_browser.as_ref().unwrap().path.text(), "/home/project");
        assert!(matches!(handle_ssh_key(&mut state, &key(KeyCode::Char('o'))),
            SshModalOutcome::ChooseProjectDirectory { root, .. } if root == "/home/project"));
    }

    #[test]
    fn primary_folder_browser_uses_real_directory_rows_and_ignores_stale_navigation() {
        let mut state = SshManagerState::new(Some("source-session".into()));
        state.set_targets(vec![target_view("server-1", SshGrantView::NotGranted)]);
        assert!(matches!(
            handle_ssh_key(&mut state, &key(KeyCode::Char('g'))),
            SshModalOutcome::Unchanged
        ));
        assert!(matches!(
            handle_ssh_key(&mut state, &key(KeyCode::Char('u'))),
            SshModalOutcome::Unchanged
        ));
        assert!(matches!(
            handle_ssh_key(&mut state, &key(KeyCode::Char('o'))),
            SshModalOutcome::Unchanged
        ));
        let SshModalOutcome::BrowseProjectDirectory {
            request_id,
            target_id,
            path,
        } = handle_ssh_key(&mut state, &key(KeyCode::Enter))
        else {
            panic!("Enter must begin the folder browser");
        };
        assert_eq!(target_id, "server-1");
        assert_eq!(path, None);
        assert!(!state.settle_project_directory(
            request_id,
            "other-server",
            Ok(directory_listing(
                "other-server",
                "/wrong",
                None,
                &[("wrong", "/wrong")],
            )),
        ));
        assert!(state.settle_project_directory(
            request_id,
            "server-1",
            Ok(directory_listing(
                "server-1",
                "/srv/project",
                Some("/srv"),
                &[("alpha", "/srv/project/alpha"), ("beta", "/srv/project/beta")],
            )),
        ));
        let area = Rect::new(0, 0, 80, 18);
        let mut buffer = Buffer::empty(area);
        render_ssh_modal(&mut buffer, area, &mut state, false, &Theme::current());
        let rendered = buffer_text(&buffer);
        assert!(rendered.contains("/srv/project"));
        assert!(rendered.contains("beta"));
        let beta = state
            .project_browser
            .as_ref()
            .and_then(|browser| browser.row_hits.iter().find(|hit| hit.index == 1))
            .expect("rendered beta folder row")
            .rect;
        assert!(matches!(
            handle_ssh_mouse(
                &mut state,
                &MouseEvent {
                    kind: MouseEventKind::Down(crossterm::event::MouseButton::Left),
                    column: beta.x,
                    row: beta.y,
                    modifiers: KeyModifiers::NONE,
                },
            ),
            SshModalOutcome::Changed
        ));
        let SshModalOutcome::BrowseProjectDirectory {
            request_id: child_request,
            path: Some(child_path),
            ..
        } = handle_ssh_key(&mut state, &key(KeyCode::Enter))
        else {
            panic!("Enter must navigate into the selected folder");
        };
        assert_eq!(child_path, "/srv/project/beta");
        assert_ne!(request_id, child_request);
        assert!(!state.settle_project_directory(
            request_id,
            "server-1",
            Ok(directory_listing("server-1", "/srv/project", Some("/srv"), &[])),
        ));
        assert!(state.settle_project_directory(
            child_request,
            "server-1",
            Ok(directory_listing(
                "server-1",
                "/srv/project/beta",
                Some("/srv/project"),
                &[],
            )),
        ));
        assert!(matches!(
            handle_ssh_key(&mut state, &key(KeyCode::Char('/'))),
            SshModalOutcome::Changed
        ));
        for character in "/srv/manual".chars() {
            assert!(matches!(
                handle_ssh_key(&mut state, &key(KeyCode::Char(character))),
                SshModalOutcome::Changed
            ));
        }
        let SshModalOutcome::BrowseProjectDirectory {
            request_id: manual_request,
            path: Some(path),
            ..
        } = handle_ssh_key(&mut state, &key(KeyCode::Enter))
        else {
            panic!("path entry must navigate through the same browser");
        };
        assert_eq!(path, "/srv/manual");
        assert!(state.settle_project_directory(
            manual_request,
            "server-1",
            Ok(directory_listing(
                "server-1",
                "/srv/manual",
                Some("/srv"),
                &[],
            )),
        ));
        assert!(matches!(
            handle_ssh_key(&mut state, &key(KeyCode::Backspace)),
            SshModalOutcome::BrowseProjectDirectory {
                path: Some(path),
                ..
            } if path == "/srv"
        ));
    }

    #[test]
    fn project_consent_keeps_folder_owner_and_submits_remembered_read_scope() {
        let mut state = SshManagerState::new(Some("source-session".into()));
        let mut target = target_view("internal-server-id", SshGrantView::NotGranted);
        target.label = "Build server".into();
        state.set_targets(vec![target]);
        let SshModalOutcome::BrowseProjectDirectory { request_id, .. } =
            state.begin_project_browser("internal-server-id".into(), None)
        else {
            panic!("browser request expected");
        };
        assert!(state.settle_project_directory(
            request_id,
            "internal-server-id",
            Ok(directory_listing(
                "internal-server-id",
                "/srv/project",
                Some("/srv"),
                &[],
            )),
        ));
        let SshModalOutcome::ChooseProjectDirectory {
            request_id: open_request,
            target_id,
            root,
            identity,
        } = handle_ssh_key(&mut state, &key(KeyCode::Char('o')))
        else {
            panic!("open action must choose the current folder");
        };
        assert_eq!(target_id, "internal-server-id");
        assert_eq!(root, "/srv/project");
        assert_eq!(identity, remote_identity());
        assert!(state.begin_project_preparation(
            open_request,
            "project-session".into(),
            target_id,
            root,
        ));
        assert_eq!(
            state.pending_project_open_tuple(),
            Some(("project-session", "internal-server-id", "/srv/project"))
        );
        assert!(state.show_project_consent(
            open_request,
            SshIncomingGrant {
                request_id: "grant-request".into(),
                target_id: Some("internal-server-id".into()),
                root: Some("/srv/project".into()),
                capabilities: SshCapabilitiesView::default(),
                verified_identity: Some("builder@build.example.test:22 (SHA256:fixture)".into()),
                reason: "Open the selected project.".into(),
            },
            "project-session".into(),
        ));
        let area = Rect::new(0, 0, 80, 30);
        let mut buffer = Buffer::empty(area);
        render_ssh_modal(&mut buffer, area, &mut state, false, &Theme::current());
        let rendered = buffer_text(&buffer);
        assert!(rendered.contains("Build server"));
        assert!(rendered.contains("/srv/project"));
        assert!(rendered.contains("SHA256:fixture"));
        for _ in 0..4 {
            assert!(matches!(
                handle_ssh_key(&mut state, &key(KeyCode::Tab)),
                SshModalOutcome::Changed
            ));
        }
        assert!(matches!(
            handle_ssh_key(&mut state, &key(KeyCode::Char(' '))),
            SshModalOutcome::Changed
        ));
        let mut buffer = Buffer::empty(area);
        render_ssh_modal(&mut buffer, area, &mut state, false, &Theme::current());
        assert!(matches!(
            handle_ssh_key(&mut state, &key(KeyCode::Enter)),
            SshModalOutcome::ApproveGrant {
                request_id,
                approved: true,
                root: Some(root),
                capabilities: Some(SshCapabilitiesView { read: true, .. }),
                lifetime: SshGrantLifetime::ProjectRule,
                set_default: false,
                ..
            } if request_id == "grant-request" && root == "/srv/project"
        ));
        state.settle_grant(true);
        assert_eq!(
            state.pending_project_open_tuple(),
            Some(("project-session", "internal-server-id", "/srv/project"))
        );
        state.settle_project_open();
        assert_eq!(state.pending_project_open_tuple(), None);
    }

    #[test]
    fn project_consent_decline_keeps_its_owner_until_preparation_finishes() {
        let mut state = SshManagerState::new(Some("source-session".into()));
        state.set_targets(vec![target_view("server-1", SshGrantView::NotGranted)]);
        let SshModalOutcome::BrowseProjectDirectory { request_id, .. } =
            state.begin_project_browser("server-1".into(), None)
        else {
            panic!("browser request expected");
        };
        assert!(state.settle_project_directory(
            request_id,
            "server-1",
            Ok(directory_listing(
                "server-1",
                "/srv/project",
                Some("/srv"),
                &[],
            )),
        ));
        let SshModalOutcome::ChooseProjectDirectory {
            request_id: open_request,
            target_id,
            root,
            ..
        } = handle_ssh_key(&mut state, &key(KeyCode::Char('o')))
        else {
            panic!("current folder selection expected");
        };
        assert!(state.begin_project_preparation(
            open_request,
            "project-session".into(),
            target_id,
            root,
        ));
        assert!(state.show_project_consent(
            open_request,
            SshIncomingGrant {
                request_id: "grant-request".into(),
                target_id: Some("server-1".into()),
                root: Some("/srv/project".into()),
                capabilities: SshCapabilitiesView::default(),
                verified_identity: Some("builder@build.example.test:22 (SHA256:fixture)".into()),
                reason: "Open the selected project.".into(),
            },
            "project-session".into(),
        ));
        assert!(matches!(
            handle_ssh_key(&mut state, &key(KeyCode::Esc)),
            SshModalOutcome::ApproveGrant {
                request_id,
                approved: false,
                ..
            } if request_id == "grant-request"
        ));
        state.settle_grant(false);
        assert_eq!(
            state.pending_project_open_tuple(),
            Some(("project-session", "server-1", "/srv/project"))
        );
        assert!(state.finish_project_preparation(open_request, None));
        assert_eq!(state.pending_project_open_tuple(), None);
    }

    #[test]
    fn authenticated_browser_restores_matching_owner_and_cancel_clears_project_pending() {
        let mut state = SshManagerState::new(Some("source-session".into()));
        state.set_targets(vec![target_view("server-1", SshGrantView::NotGranted)]);
        let SshModalOutcome::BrowseProjectDirectory { request_id, .. } =
            state.begin_project_browser("server-1".into(), None)
        else {
            panic!("browser request expected");
        };
        state.show_authentication(SshAuthCard::new(
            "challenge-1".into(),
            1,
            "server-1".into(),
            SshAuthKind::Password {
                username: "builder".into(),
                message: "Password".into(),
                allow_remember: false,
            },
        ));
        assert_eq!(state.pending_project_target_id(), Some("server-1"));
        assert!(state.settle_project_directory(
            request_id,
            "server-1",
            Ok(directory_listing(
                "server-1",
                "/srv/project",
                Some("/srv"),
                &[("child", "/srv/project/child")],
            )),
        ));
        let area = Rect::new(0, 0, 70, 18);
        let mut buffer = Buffer::empty(area);
        render_ssh_modal(&mut buffer, area, &mut state, false, &Theme::current());
        assert!(buffer_text(&buffer).contains("child"));
        let SshModalOutcome::ChooseProjectDirectory {
            request_id: open_request,
            target_id,
            root,
            ..
        } = handle_ssh_key(&mut state, &key(KeyCode::Char('o')))
        else {
            panic!("current folder selection expected");
        };
        assert!(state.begin_project_preparation(
            open_request,
            "project-session".into(),
            target_id,
            root,
        ));
        assert!(matches!(
            handle_ssh_key(&mut state, &key(KeyCode::Esc)),
            SshModalOutcome::CancelProjectOpen { request_id } if request_id == open_request
        ));
        assert_eq!(state.pending_project_target_id(), None);
        assert!(!state.finish_project_preparation(open_request, Some("late failure".into())));
    }

    #[test]
    fn advanced_use_grant_exposes_a_typed_continuation_before_settlement() {
        let mut state = SshManagerState::new(Some("source-session".into()));
        state.set_targets(vec![target_view("server-1", SshGrantView::NotGranted)]);
        assert!(matches!(
            handle_ssh_key(&mut state, &key(KeyCode::Char('m'))),
            SshModalOutcome::Changed
        ));
        assert!(matches!(
            handle_ssh_key(&mut state, &key(KeyCode::Char('u'))),
            SshModalOutcome::Changed
        ));
        assert!(matches!(
            handle_ssh_key(&mut state, &key(KeyCode::Enter)),
            SshModalOutcome::RequestGrant { root, .. } if root == "."
        ));
        state.remember_local_grant_options(
            "server-1".into(), ".".into(), SshCapabilitiesView::default(),
            SshGrantLifetime::ProjectRule, false,
        );
        assert!(state.bind_local_grant_request("advanced-use-grant", Some("server-1"), Some(".")));
        state.show_incoming_grant(
            "source-session".into(),
            SshIncomingGrant {
                request_id: "advanced-use-grant".into(),
                target_id: Some("server-1".into()),
                root: Some("/home/builder".into()),
                capabilities: SshCapabilitiesView::default(),
                verified_identity: Some("builder@build.example.test:22 (SHA256:fixture)".into()),
                reason: "Open SSH access".into(),
            },
        );
        let SshModalPage::Grant(card) = &state.page else { panic!("verified grant expected") };
        assert_eq!(card.lifetime, SshGrantLifetime::ProjectRule);
        assert_eq!(card.root.text(), "/home/builder");
        assert_eq!(
            state.take_grant_follow_up("advanced-use-grant"),
            Some(SshGrantFollowUp::UseBinding)
        );
    }

    #[test]
    fn target_add_completion_is_correlated_and_failure_keeps_the_editable_form() {
        let mut state = SshManagerState::new(None);
        assert!(matches!(
            handle_manager_key(&mut state, &key(KeyCode::Char('a'))),
            SshModalOutcome::Changed
        ));
        let SshModalPage::Add(form) = &mut state.page else {
            panic!("add target form must open");
        };
        form.host.set_text("first.example.test");
        let first_submission = add_submission_id(handle_ssh_key(&mut state, &key(KeyCode::Enter)));
        assert_eq!(state.target_add_submission_id(), Some(first_submission));

        assert!(matches!(
            close_current_page(&mut state),
            SshModalOutcome::Changed
        ));
        assert!(matches!(&state.page, SshModalPage::Manager));
        handle_manager_key(&mut state, &key(KeyCode::Char('a')));
        let SshModalPage::Add(form) = &mut state.page else {
            panic!("second add target form must open");
        };
        form.host.set_text("second.example.test");
        let second_submission = add_submission_id(handle_ssh_key(&mut state, &key(KeyCode::Enter)));
        assert_ne!(first_submission, second_submission);

        assert!(
            !state.settle_target_add_for_submission(first_submission, Ok("first-target".into()))
        );
        assert_eq!(state.target_add_submission_id(), Some(second_submission));
        assert!(state.settle_target_add_for_submission(
            second_submission,
            Err("The target already exists.".into())
        ));
        let area = Rect::new(0, 0, 100, 40);
        let mut buffer = Buffer::empty(area);
        render_ssh_modal(&mut buffer, area, &mut state, false, &Theme::current());
        assert!(buffer_text(&buffer).contains("The target already exists."));
        assert!(matches!(&state.page, SshModalPage::Diagnostic(_)));
        close_current_page(&mut state);
        assert!(matches!(
            &state.page,
            SshModalPage::Add(form)
                if !form.submitting
                    && form.host.text() == "second.example.test"
                    && form.error.is_none()
        ));
        assert!(matches!(
            handle_ssh_key(&mut state, &key(KeyCode::Char('x'))),
            SshModalOutcome::Changed
        ));
        assert!(matches!(
            &state.page,
            SshModalPage::Add(form) if form.error.is_none()
        ));

        let third_submission = add_submission_id(handle_ssh_key(&mut state, &key(KeyCode::Enter)));
        assert!(
            state.settle_target_add_for_submission(third_submission, Ok("saved-target".into()))
        );
        assert!(matches!(&state.page, SshModalPage::Manager));
        state.set_targets(vec![target_view("saved-target", SshGrantView::NotGranted)]);
        assert_eq!(
            state
                .selected_target()
                .map(|target| target.target_id.as_str()),
            Some("saved-target")
        );
        let mut replacement = SshManagerState::new(None);
        handle_manager_key(&mut replacement, &key(KeyCode::Char('a')));
        let SshModalPage::Add(form) = &mut replacement.page else {
            panic!("replacement manager must open an add form");
        };
        form.host.set_text("replacement.example.test");
        let replacement_submission =
            add_submission_id(handle_ssh_key(&mut replacement, &key(KeyCode::Enter)));
        assert_ne!(third_submission, replacement_submission);
        assert_ne!(state.instance_id(), replacement.instance_id());
    }

    #[test]
    fn multiple_binding_rows_keep_selected_grant_and_share_connection_state() {
        let mut state = SshManagerState::new(Some("session-1".into()));
        state.set_targets(vec![
            target_view("target-1", granted("binding-a", "/a")),
            target_view("target-1", granted("binding-b", "/b")),
        ]);
        state.selected = 1;
        state.set_targets(vec![
            target_view("target-1", granted("binding-b", "/b")),
            target_view("target-1", granted("binding-a", "/a")),
        ]);
        assert_eq!(
            state
                .selected_target()
                .and_then(|target| target.grant.binding_id()),
            Some("binding-b")
        );

        state.apply_target_status(
            "target-1",
            SshConnectionState::Connected,
            Some("Connected once for every binding row.".into()),
        );
        assert!(state.targets.iter().all(|target| {
            target.target_id == "target-1"
                && target.connected
                && target.connection_detail == "Connected once for every binding row."
        }));

        state.mark_binding_revoked("binding-b", false);
        assert!(matches!(
            state.selected_target().map(|target| &target.grant),
            Some(SshGrantView::Revoking { binding_id, .. }) if binding_id == "binding-b"
        ));
        assert!(matches!(
            state
                .targets
                .iter()
                .find(|target| target.grant.binding_id() == Some("binding-a"))
                .map(|target| &target.grant),
            Some(SshGrantView::Granted { binding_id, .. }) if binding_id == "binding-a"
        ));
        state.set_targets(vec![
            target_view("target-1", granted("binding-a", "/a")),
            target_view("target-2", SshGrantView::NotGranted),
        ]);
        assert_eq!(
            state
                .selected_target()
                .and_then(|target| target.grant.binding_id()),
            Some("binding-b")
        );
        assert_eq!(
            state.targets[state.selected - 1].grant.binding_id(),
            Some("binding-a")
        );
        assert_eq!(state.targets[state.selected + 1].target_id, "target-2");
    }

    #[test]
    fn manual_target_port_rejects_zero_and_accepts_the_u16_upper_bound() {
        let mut form = SshManualTargetForm::default();
        form.host.set_text("build.example.test");
        form.port.set_text("0");
        assert_eq!(
            form.draft()
                .expect_err("zero is outside the TCP port range"),
            "Port must be an integer between 1 and 65535."
        );
        form.port.set_text("65535");
        assert_eq!(
            form.draft().expect("upper bound is valid").port,
            Some(65535)
        );
    }

    #[test]
    fn narrow_grant_card_exposes_wrapped_identity_root_reason_and_run_warning() {
        let mut card = SshGrantCard::new(
            "request-1".into(),
            "target-1".into(),
            "Build host".into(),
            Some("verified@example.test SHA256:verified-fingerprint".into()),
            "/remote/project-root/that-must-remain-inspectable",
            Some("reason-token-visible-after-scrolling".into()),
            true,
        );
        card.capabilities.execute = true;
        assert!(matches!(
            handle_grant_key(&mut card, &key(KeyCode::Enter)),
            SshModalOutcome::Changed
        ));
        card.error = None;
        let area = Rect::new(0, 0, 30, 4);
        let theme = Theme::current();
        let mut frames = String::new();
        for _ in 0..128 {
            let mut buffer = Buffer::empty(area);
            render_grant(&mut buffer, area, &mut card, &theme);
            frames.push_str(&buffer_text(&buffer));
            frames.push('\n');
            if card.scroll_offset == card.max_scroll_offset {
                break;
            }
            assert!(matches!(
                handle_grant_key(&mut card, &key(KeyCode::PageDown)),
                SshModalOutcome::Changed
            ));
        }
        assert!(frames.contains("SHA256:"));
        assert!(frames.contains("fingerprint"));
        assert!(frames.contains("project-root"));
        assert!(frames.contains("reason-token"));
        assert!(frames.contains("scrolling"));
        assert!(frames.contains("Warning:"));
        assert!(card.reviewed_to_end);
    }

    #[test]
    fn grant_controls_support_tab_space_and_alt_activation() {
        let mut card = SshGrantCard::new(
            String::new(),
            "target-1".into(),
            "Build host".into(),
            None,
            "/remote/root",
            None,
            false,
        );
        assert!(matches!(
            handle_grant_key(&mut card, &key(KeyCode::Tab)),
            SshModalOutcome::Changed
        ));
        assert_eq!(card.focus, SshGrantFocus::Read);
        assert!(matches!(
            handle_grant_key(&mut card, &key(KeyCode::Char(' '))),
            SshModalOutcome::Changed
        ));
        assert!(!card.capabilities.read);
        let alt_write = KeyEvent::new(KeyCode::Char('w'), KeyModifiers::ALT);
        assert!(matches!(
            handle_grant_key(&mut card, &alt_write),
            SshModalOutcome::Changed
        ));
        assert_eq!(card.focus, SshGrantFocus::Write);
        assert!(card.capabilities.write);
        assert!(matches!(
            handle_grant_key(&mut card, &key(KeyCode::BackTab)),
            SshModalOutcome::Changed
        ));
        assert_eq!(card.focus, SshGrantFocus::Read);
    }

    #[test]
    fn rendered_mouse_targets_footer_and_form_hits_follow_keyboard_semantics() {
        let mut state = SshManagerState::new(None);
        state.set_targets(
            (0..12)
                .map(|index| target_view(&format!("target-{index}"), SshGrantView::NotGranted))
                .collect(),
        );
        let area = Rect::new(0, 0, 100, 40);
        let theme = Theme::current();
        let mut buffer = Buffer::empty(area);
        render_ssh_modal(&mut buffer, area, &mut state, false, &theme);
        let second_row = state
            .manager_row_hits
            .get(1)
            .expect("second manager row must be visible")
            .rect;
        let left_click = |column, row| MouseEvent {
            kind: MouseEventKind::Down(crossterm::event::MouseButton::Left),
            column,
            row,
            modifiers: KeyModifiers::NONE,
        };
        assert!(matches!(
            handle_ssh_mouse(&mut state, &left_click(second_row.x, second_row.y)),
            SshModalOutcome::Changed
        ));
        assert_eq!(
            state
                .selected_target()
                .map(|target| target.target_id.as_str()),
            Some("target-1")
        );
        let wheel = MouseEvent {
            kind: MouseEventKind::ScrollDown,
            column: second_row.x,
            row: second_row.y,
            modifiers: KeyModifiers::NONE,
        };
        assert!(matches!(
            handle_ssh_mouse(&mut state, &wheel),
            SshModalOutcome::Changed
        ));
        assert!(state.manager_scroll_offset > 0);

        let add_footer = state
            .window
            .shortcut_hits
            .iter()
            .find(|hit| hit.id == FOOTER_MANAGER_ADD)
            .expect("rendered manager add footer")
            .rect;
        assert!(matches!(
            handle_ssh_mouse(&mut state, &left_click(add_footer.x, add_footer.y)),
            SshModalOutcome::Changed
        ));
        assert!(matches!(&state.page, SshModalPage::Add(_)));
        assert!(matches!(
            handle_ssh_mouse(&mut state, &left_click(add_footer.x, add_footer.y)),
            SshModalOutcome::Unchanged
        ));

        let mut buffer = Buffer::empty(area);
        render_ssh_modal(&mut buffer, area, &mut state, false, &theme);
        let port_row = match &state.page {
            SshModalPage::Add(form) => {
                form.field_hits
                    .iter()
                    .find(|(field, _)| *field == ManualTargetField::Port)
                    .expect("rendered port field")
                    .1
            }
            _ => panic!("add target form must remain open"),
        };
        assert!(matches!(
            handle_ssh_mouse(&mut state, &left_click(port_row.x, port_row.y)),
            SshModalOutcome::Changed
        ));
        assert!(matches!(
            &state.page,
            SshModalPage::Add(form) if form.active == ManualTargetField::Port
        ));
    }

    #[test]
    fn unsubmitted_grant_can_be_cancelled_without_a_service_decision() {
        let mut state = SshManagerState::new(Some("session-1".into()));
        state.show_grant(SshGrantCard::new(
            String::new(),
            "target-1".into(),
            "Build host".into(),
            None,
            "/tmp",
            None,
            false,
        ));
        assert!(matches!(
            handle_ssh_key(&mut state, &key(KeyCode::Esc)),
            SshModalOutcome::Changed
        ));
        assert!(matches!(&state.page, SshModalPage::Manager));
        assert!(matches!(
            handle_ssh_key(&mut state, &key(KeyCode::Esc)),
            SshModalOutcome::Close
        ));
    }

    #[test]
    fn grant_failure_is_readable_and_returns_to_the_same_editable_request() {
        let mut state = SshManagerState::new(Some("session-1".into()));
        state.show_grant(SshGrantCard::new(
            "request-1".into(),
            "target-1".into(),
            "Build host".into(),
            Some("user@host SHA256:verified".into()),
            "/missing/project",
            None,
            false,
        ));
        state.show_error("SSH access failed: the requested remote root does not exist");
        assert!(matches!(&state.page, SshModalPage::Diagnostic(_)));
        let area = Rect::new(0, 0, 60, 20);
        let mut buffer = Buffer::empty(area);
        render_ssh_modal(&mut buffer, area, &mut state, false, &Theme::current());
        assert!(buffer_text(&buffer).contains("does not exist"));
        assert!(matches!(
            handle_ssh_key(&mut state, &key(KeyCode::Esc)),
            SshModalOutcome::Changed
        ));
        assert!(matches!(
            &state.page,
            SshModalPage::Grant(card)
                if card.request_id == "request-1" && card.root.text() == "/missing/project"
        ));
        assert!(matches!(
            handle_ssh_key(&mut state, &key(KeyCode::Esc)),
            SshModalOutcome::ApproveGrant { approved: false, request_id, .. }
                if request_id == "request-1"
        ));
    }

    #[test]
    fn terminal_status_clears_only_matching_connection_progress_without_hiding_errors() {
        let mut state = SshManagerState::new(Some("session-1".into()));
        for (connect, terminal) in [
            (true, SshConnectionState::Connected),
            (false, SshConnectionState::Disconnected),
        ] {
            state.begin_connection_action("target-1", connect);
            let progress = state.message.clone();
            state.apply_target_status("other-target", terminal, None);
            assert_eq!(state.message, progress);
            state.apply_target_status("target-1", SshConnectionState::Connecting, None);
            assert_eq!(state.message, progress);
            state.apply_target_status("target-1", terminal, None);
            assert!(state.pending_connection.is_none());
            assert_ne!(state.message, progress);
        }

        state.begin_connection_action("target-1", true);
        state.show_error("a newer operation failed");
        let failure = state.message.clone();
        state.apply_target_status("target-1", SshConnectionState::Connected, None);
        assert_eq!(state.message, failure);
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

    #[test]
    fn connected_details_are_not_an_error_but_actual_failures_remain_red() {
        let mut state = SshManagerState::new(None);
        let mut target = target_view("server-1", SshGrantView::NotGranted);
        target.connected = true;
        state.set_targets(vec![target]);
        state.open_diagnostic();
        let area = Rect::new(0, 0, 120, 30);
        let theme = Theme::default();
        let SshModalPage::Diagnostic(card) = &mut state.page else { panic!("details expected") };
        let mut buffer = Buffer::empty(area);
        render_diagnostic(&mut buffer, area, card, &theme);
        assert!(!buffer.content.iter().any(|cell| cell.fg == theme.accent_error));
        assert!(buffer.content.iter().any(|cell| cell.fg == theme.accent_success));
        state.show_error("connection lost");
        let SshModalPage::Diagnostic(card) = &mut state.page else { panic!("failure expected") };
        let mut buffer = Buffer::empty(area);
        render_diagnostic(&mut buffer, area, card, &theme);
        assert!(buffer.content.iter().any(|cell| cell.fg == theme.accent_error && cell.symbol() == "c"));
        assert!(!buffer.content.iter().any(|cell| cell.fg == theme.accent_success));
    }
}
