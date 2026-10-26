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
use ratatui::text::{Line, Span};
use serde_json::Value;
use std::{
    borrow::Cow,
    sync::atomic::{AtomicU64, Ordering},
};
use xai_grok_shell::ssh::{
    SshConnectionState, SshDirectoryListing, SshHostIdentity, SshOperation,
    SshOperationApprovalScope,
};
use zeroize::Zeroizing;

/// A configured target as displayed by the pager. This view retains its exact, non-secret
/// configuration snapshot so a manual edit can preserve fields the compact form does not expose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshTargetView {
    pub target_id: String,
    pub label: String,
    /// Full target snapshot—including typed source provenance—for optimistic concurrency.
    pub target: xai_grok_ssh::SshTarget,
    /// Resolved `user@host:port` (or an explicit resolver error category), never a secret.
    pub effective_address: String,
    pub connected: bool,
    pub connection_detail: String,
    pub grant: SshGrantView,
}

impl SshTargetView {
    pub fn from_target(
        target: xai_grok_ssh::SshTarget,
        effective_address: String,
        connected: bool,
        connection_detail: String,
        grant: SshGrantView,
    ) -> Self {
        Self {
            target_id: target.id.clone(),
            label: target.label.clone(),
            target,
            effective_address,
            connected,
            connection_detail,
            grant,
        }
    }

    fn source_display(&self) -> Cow<'_, str> {
        match &self.target.source {
            xai_grok_ssh::TargetSource::User => Cow::Borrowed("Groky config"),
            xai_grok_ssh::TargetSource::Imported { path, line } => {
                Cow::Owned(format!("OpenSSH read-only {}:{line}", path.display()))
            }
        }
    }

    fn is_manual(&self) -> bool {
        matches!(&self.target.source, xai_grok_ssh::TargetSource::User)
    }

    fn read_only_message(&self) -> Option<String> {
        let xai_grok_ssh::TargetSource::Imported { path, line } = &self.target.source else {
            return None;
        };
        Some(format!(
            "This OpenSSH target is read-only. Edit {} at line {line} externally, then refresh.",
            path.display()
        ))
    }
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
    /// The model tool is paused on this human decision; approval resumes that exact call.
    awaiting_tool: bool,
    pub error: Option<String>,
    /// A canonical browser-selected root is displayed as evidence, never editable intent.
    verified_root: bool,
    /// Incoming requests may only reduce their requested scope, never add capabilities.
    capability_ceiling: Option<SshCapabilitiesView>,
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
            awaiting_tool: false,
            error: None,
            verified_root: false,
            capability_ceiling: None,
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
        const VERIFIED_GENERAL_FOCUSES: [SshGrantFocus; 5] = [
            SshGrantFocus::Read,
            SshGrantFocus::Write,
            SshGrantFocus::Execute,
            SshGrantFocus::Lifetime,
            SshGrantFocus::Default,
        ];
        let focuses: &[SshGrantFocus] = if self.is_project_consent() {
            &PROJECT_FOCUSES
        } else if self.verified_root {
            &VERIFIED_GENERAL_FOCUSES
        } else {
            &GENERAL_FOCUSES
        };
        let focuses = if self.follow_up.is_some() && !self.is_project_consent() {
            &focuses[..focuses.len() - 1]
        } else {
            focuses
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

    fn set_verified_scope(&mut self, capabilities: SshCapabilitiesView) {
        self.verified_root = true;
        self.capability_ceiling = Some(capabilities);
        self.capabilities = capabilities;
        if self.focus == SshGrantFocus::Root {
            self.focus = SshGrantFocus::Read;
        }
    }

    fn capability_is_requested(&self, focus: SshGrantFocus) -> bool {
        let Some(capabilities) = self.capability_ceiling else {
            return true;
        };
        match focus {
            SshGrantFocus::Read => capabilities.read,
            SshGrantFocus::Write => capabilities.write,
            SshGrantFocus::Execute => capabilities.execute,
            SshGrantFocus::Root
            | SshGrantFocus::Lifetime
            | SshGrantFocus::Default
            | SshGrantFocus::RememberProject => true,
        }
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
    /// True only for a live `ssh_request_access` model-tool call awaiting this decision.
    pub awaiting_tool: bool,
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
    /// A per-command sudo challenge for the remote SSH account; its password is never stored.
    SudoPassword {
        username: String,
        message: String,
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
            Self::SudoPassword { .. } => "Root SSH authentication",
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
    /// Reveal the active input after an edit/focus move, without defeating manual scrolling.
    reveal_answer: bool,
    viewport_size: Option<(u16, u16)>,
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
            SshAuthKind::Password { .. }
            | SshAuthKind::SudoPassword { .. }
            | SshAuthKind::PrivateKeyPassphrase { .. } => 1,
        };
        Self {
            challenge_id,
            connection_generation,
            target_id,
            remember: false,
            kind,
            answers: (0..answer_count).map(|_| SecretEditor::default()).collect(),
            active_answer: 0,
            reveal_answer: true,
            viewport_size: None,
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
        self.reveal_answer = true;
        self.answers.get_mut(self.active_answer)
    }

    fn clear_answers(&mut self) {
        for answer in &mut self.answers {
            answer.clear();
        }
        self.active_answer = 0;
        self.reveal_answer = true;
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
            SshAuthKind::Password { .. }
                | SshAuthKind::SudoPassword { .. }
                | SshAuthKind::PrivateKeyPassphrase { .. }
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
    /// `Some` means this is an edit and carries the exact optimistic-concurrency precondition.
    expected: Option<xai_grok_ssh::SshTarget>,
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
            expected: None,
            active: ManualTargetField::Host,
            error: None,
            field_hits: Vec::new(),
            submitting: false,
            submission_id: None,
        }
    }
}

fn format_worker_command(arguments: &[String]) -> String {
    let capacity = arguments
        .iter()
        .map(|argument| {
            argument.len()
                + 2
                + argument
                    .bytes()
                    .filter(|character| matches!(*character, b'\\' | b'"'))
                    .count()
        })
        .sum::<usize>()
        .saturating_add(arguments.len().saturating_sub(1));
    let mut command = String::with_capacity(capacity);
    for (index, argument) in arguments.iter().enumerate() {
        if index > 0 {
            command.push(' ');
        }
        command.push('"');
        for character in argument.chars() {
            if matches!(character, '\\' | '"') {
                command.push('\\');
            }
            command.push(character);
        }
        command.push('"');
    }
    command
}

impl SshManualTargetForm {
    fn editing(expected: xai_grok_ssh::SshTarget) -> Self {
        let mut form = Self {
            expected: Some(expected.clone()),
            ..Self::default()
        };
        form.host.set_text(expected.host);
        form.label.set_text(expected.label);
        form.user.set_text(expected.user.unwrap_or_default());
        form.port
            .set_text(expected.port.map_or_else(String::new, |port| port.to_string()));
        form.identity_file.set_text(
            expected
                .identity_files
                .first()
                .map_or_else(String::new, |path| path.display().to_string()),
        );
        form.worker_command.set_text(format_worker_command(&expected.worker_command));
        form
    }

    fn is_editing(&self) -> bool {
        self.expected.is_some()
    }

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
    fn replacement(&self, expected: &xai_grok_ssh::SshTarget) -> Result<xai_grok_ssh::SshTarget, String> {
        let draft = self.draft()?;
        let mut replacement = expected.clone();
        replacement.host = draft.host.clone();
        replacement.label = draft.label.unwrap_or(draft.host);
        replacement.user = draft.user;
        replacement.port = draft.port;
        match draft.identity_file {
            Some(identity_file) => {
                let identity_file = std::path::PathBuf::from(identity_file);
                if let Some(first) = replacement.identity_files.first_mut() {
                    *first = identity_file;
                } else {
                    replacement.identity_files.push(identity_file);
                }
            }
            None if !replacement.identity_files.is_empty() => {
                replacement.identity_files.remove(0);
            }
            None => {}
        }
        replacement.worker_command = match draft.worker_command {
            Some(worker_command) => xai_grok_ssh::parse_worker_command(&worker_command)
                .map_err(|error| error.to_string())?,
            None => xai_grok_ssh::default_worker_command(),
        };
        Ok(replacement)
    }

    fn start_submit(&mut self) -> Result<TargetFormSubmission, String> {
        let submission_id = next_nonzero_id(&NEXT_TARGET_MUTATION_SUBMISSION_ID);
        let submission = match self.expected.as_ref() {
            Some(expected) => TargetFormSubmission::Update {
                expected: expected.clone(),
                replacement: self.replacement(expected)?,
                submission_id,
            },
            None => TargetFormSubmission::Add {
                draft: self.draft()?,
                submission_id,
            },
        };
        self.submitting = true;
        self.submission_id = Some(submission_id);
        self.error = None;
        Ok(submission)
    }
}

enum TargetFormSubmission {
    Add {
        draft: SshManualTargetDraft,
        submission_id: u64,
    },
    Update {
        expected: xai_grok_ssh::SshTarget,
        replacement: xai_grok_ssh::SshTarget,
        submission_id: u64,
    },
}

/// Local-only consent for an individual remote operation after a binding already exists.
///
/// `reviewed_to_end` is render-derived and latched: allow is unavailable until every preview
/// line has been reachable in this modal, but inspecting an earlier line cannot revoke that
/// completed review.
pub struct SshOperationApprovalCard {
    pub approval_id: String,
    pub binding_id: String,
    pub target_label: String,
    pub target_identity: Option<String>,
    pub title: String,
    /// Typed payload retained until it has been rendered; no JSON serialization at the boundary.
    pub detail: Value,
    pub operation: SshOperation,
    allow_session: bool,
    operation_id: Option<String>,
    scroll_offset: usize,
    max_scroll_offset: usize,
    page_size: usize,
    reviewed_to_end: bool,
    raw_details: bool,
    submitting: bool,
    copy_status: Option<&'static str>,
    error: Option<String>,

}
impl SshOperationApprovalCard {
    pub fn new(
        approval_id: String,
        binding_id: String,
        target_label: String,
        target_identity: Option<String>,
        title: String,
        detail: Value,
        operation: SshOperation,
    ) -> Self {
        Self {
            approval_id,
            binding_id,
            target_label,
            target_identity,
            title,
            detail,
            operation,
            allow_session: true,
            operation_id: None,
            scroll_offset: 0,
            max_scroll_offset: 0,
            page_size: 1,
            reviewed_to_end: false,
            raw_details: false,
            submitting: false,
            copy_status: None,
            error: None,
        }
    }

    /// Restrict this request to a one-time decision without changing existing card fixtures.
    pub fn with_allow_session(mut self, allow_session: bool) -> Self {
        self.allow_session = allow_session;
        self
    }

    /// Attach the shell operation correlation used by scoped sudo authentication events.
    pub fn with_operation_id(mut self, operation_id: impl Into<String>) -> Self {
        self.operation_id = Some(operation_id.into());
        self
    }

    /// Whether this card may create a session-and-binding operation policy.
    pub fn allows_session(&self) -> bool {
        self.allow_session && !self.is_sudo()
    }

    fn is_sudo(&self) -> bool {
        self.detail
            .get("args")
            .and_then(|args| args.get("sudo"))
            .and_then(Value::as_bool)
            .unwrap_or(false)
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

/// Outcome of settling one exact remote-operation approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshOperationApprovalSettlement {
    /// The matching card remains available with its result or diagnostic.
    KeepVisible,
    /// The matching successful approval can return to its originating chat.
    Dismiss,
    /// Keep only the scoped sudo correlation while no modal is displayed.
    AwaitingSudoAuthentication,
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

/// The operation that owns the shared authenticated directory picker.
///
/// Project opening has a separate preparation lifecycle. Grant purposes instead retain the
/// original request (or typed local continuation) and never create a project session.
#[derive(Clone)]
enum SshDirectoryPurpose {
    ProjectOpen,
    LocalGrant {
        follow_up: Option<SshGrantFollowUp>,
    },
    PendingGrant {
        request_id: String,
    },
}

impl SshDirectoryPurpose {
    fn is_project_open(&self) -> bool {
        matches!(self, Self::ProjectOpen)
    }
}

/// Local browser state for one authenticated remote target.
///
/// It retains only directory metadata from the SSH service. The service resolves every listed
/// path and records the verified identity; this UI never performs local filesystem lookups.
struct SshProjectBrowser {
    target_id: String,
    purpose: SshDirectoryPurpose,
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
    fn new(
        target_id: String,
        path: Option<String>,
        request_id: u64,
        purpose: SshDirectoryPurpose,
    ) -> Self {
        let mut editor = LineEditor::default();
        editor.set_text(path.unwrap_or_else(|| ".".to_owned()));
        Self {
            target_id,
            purpose,
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
}

/// A root command may ask for its password after its operation approval acknowledgement.
///
/// The tuple remains local so an event from a retired operation cannot replace another modal.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingSudoAuthentication {
    operation_id: String,
    client_id: Option<u64>,
    challenge_id: Option<String>,
}

struct SshDeleteConfirmation {
    expected: xai_grok_ssh::SshTarget,
    label: String,
    connected: bool,
    has_active_grants: bool,
    submitting: bool,
    submission_id: Option<u64>,
    error: Option<String>,
}

impl SshDeleteConfirmation {
    fn new(expected: xai_grok_ssh::SshTarget, connected: bool, has_active_grants: bool) -> Self {
        Self {
            label: expected.label.clone(),
            expected,
            connected,
            has_active_grants,
            submitting: false,
            submission_id: None,
            error: None,
        }
    }

    fn start_submit(&mut self) -> u64 {
        let submission_id = next_nonzero_id(&NEXT_TARGET_MUTATION_SUBMISSION_ID);
        self.submitting = true;
        self.submission_id = Some(submission_id);
        self.error = None;
        submission_id
    }
}

enum SshModalPage {
    Manager,
    Add(SshManualTargetForm),
    ConfirmDelete(SshDeleteConfirmation),
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
static NEXT_TARGET_MUTATION_SUBMISSION_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_PROJECT_DIRECTORY_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

fn next_nonzero_id(counter: &AtomicU64) -> u64 {
    loop {
        let id = counter.fetch_add(1, Ordering::Relaxed);
        if id != 0 {
            return id;
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SshManagerMode {
    Manage,
    PromptPicker,
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
    /// A dismissed root approval retains only exact sudo correlation until the service either
    /// asks for its password or the manager is intentionally replaced.
    visible: bool,
    manager_scroll_offset: usize,
    manager_visible_rows: usize,
    manager_row_hits: Vec<ManagerRowHit>,
    manager_advanced: bool,
    mode: SshManagerMode,
    /// Exact disconnected server awaiting the matching owned successful connection result.
    pending_prompt_target_id: Option<String>,
    pending_target_selection_id: Option<String>,
    pending_target_reference: Option<String>,
    /// Removed targets stay retired locally so an older target-list completion cannot resurrect
    /// a just-deleted target before the authoritative refresh arrives.
    retired_target_ids: Vec<String>,
    project_browser: Option<SshProjectBrowser>,
    /// The request tuple that owns a preparation, grant, and subsequent project lifecycle.
    pending_project_open: Option<PendingProjectOpen>,
    /// Authentication temporarily overlays the browser but must return to the same listing.
    resume_project_browser_after_authentication: bool,
    /// Target owning the current connect/disconnect progress message.
    pending_connection: Option<String>,
    /// Only a connect (not a disconnect) may own a local authentication prompt.
    pending_connection_is_connecting: bool,
    /// Immutable request retained while a directory selection or identity inspection is pending.
    pending_grant: Option<SshIncomingGrant>,
    /// Request IDs whose inspection has been dispatched. This suppresses duplicated grant events
    /// until the matching verified event arrives.
    inspecting_grant_ids: Vec<String>,
    /// Recently cancelled or terminally failed picker requests. Keeping this bounded prevents
    /// late browse/inspection completions from reviving a request with no remaining owner.
    cancelled_grant_ids: Vec<String>,
    /// Exact decision submitted for the displayed request, retained until its resolution.
    submitted_grant: Option<SubmittedGrantDecision>,
    /// Session actually requested by the current human-consent card. Usually this manager's
    /// session, but a remote worktree resume pre-mints a child before it has an AgentView.
    pending_grant_session_id: Option<String>,
    /// Typed continuation for a local advanced grant, never inferred from rendered prose.
    pending_grant_follow_up: Option<SshGrantFollowUp>,
    /// Local picker requests cancelled before the service assigned an ID, retained by tuple so a
    /// late request can still be denied exactly once.
    cancelled_local_grant_options: Vec<LocalGrantOptions>,
    settled_grant_follow_up: Option<(String, SshGrantFollowUp)>,
    local_grant_options: Option<LocalGrantOptions>,
    /// Session whose grants are shown. `None` is Welcome: connect/config actions remain usable,
    /// but granting and selecting a default requires creating or opening a session first.
    pub session_id: Option<String>,
    /// Exact operation decision awaiting its local-control acknowledgement.
    submitted_operation_approval: Option<SubmittedOperationApproval>,
    /// Root authentication is accepted only for the exact approved operation in this manager.
    pending_sudo_authentication: Option<PendingSudoAuthentication>,
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
            visible: true,
            manager_scroll_offset: 0,
            manager_visible_rows: 0,
            manager_row_hits: Vec::new(),
            manager_advanced: false,
            mode: SshManagerMode::Manage,
            pending_prompt_target_id: None,
            pending_target_selection_id: None,
            pending_target_reference: None,
            retired_target_ids: Vec::new(),
            project_browser: None,
            pending_project_open: None,
            resume_project_browser_after_authentication: false,
            pending_connection: None,
            pending_connection_is_connecting: false,
            pending_grant: None,
            inspecting_grant_ids: Vec::new(),
            cancelled_grant_ids: Vec::new(),
            submitted_grant: None,
            pending_grant_session_id: None,
            pending_grant_follow_up: None,
            cancelled_local_grant_options: Vec::new(),
            settled_grant_follow_up: None,
            local_grant_options: None,
            session_id,
            submitted_operation_approval: None,
            pending_sudo_authentication: None,
        }
    }

    /// Create a picker for choosing an SSH server to attach to the current chat draft.
    ///
    /// This mode never creates model authority from an ordinary target selection.
    pub fn for_prompt(session_id: Option<String>) -> Self {
        let mut state = Self::new(session_id);
        state.mode = SshManagerMode::PromptPicker;
        state
    }

    /// Whether this overlay chooses a server for the current chat draft rather than managing
    /// access for a model session.
    pub fn is_prompt_picker(&self) -> bool {
        self.mode == SshManagerMode::PromptPicker
    }

    /// Globally unique identity for matching asynchronous local-control completions to this
    /// concrete manager instance after an overlay is closed and re-opened.
    pub fn instance_id(&self) -> u64 {
        self.instance_id
    }

    /// Whether the manager currently owns the visible modal and input surface.
    ///
    /// A root approval may retain its exact sudo tuple while hidden so a later password
    /// challenge can safely reopen this same instance.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Reopen local management without discarding an approved root operation's correlation.
    pub fn reopen(&mut self, for_prompt: bool) {
        self.visible = true;
        self.mode = if for_prompt { SshManagerMode::PromptPicker } else { SshManagerMode::Manage };
        self.manager_advanced = false;
        self.page = SshModalPage::Manager;
        self.pending_target_reference = None;
    }

    /// True means the caller must retain this manager for an outstanding sudo challenge.
    pub fn hide_if_waiting_for_sudo(&mut self) -> bool {
        if self.pending_sudo_authentication.is_none() {
            return false;
        }
        if matches!(&self.page, SshModalPage::Authentication(card)
            if matches!(&card.kind, SshAuthKind::SudoPassword { .. }))
        {
            return true;
        }
        self.visible = false;
        self.page = SshModalPage::Manager;
        self.resume_project_browser_after_authentication = false;
        true
    }


    /// Whether this exact grant still owns the visible consent surface.
    pub fn current_grant_surface_matches(&self, request_id: &str) -> bool {
        self.pending_grant.as_ref().is_some_and(|request| request.request_id == request_id)
            && match &self.page {
                SshModalPage::Manager => true,
                SshModalPage::Grant(card) => card.request_id == request_id,
                SshModalPage::ProjectBrowser => self.project_browser.as_ref().is_some_and(|browser| {
                    matches!(
                        &browser.purpose,
                        SshDirectoryPurpose::PendingGrant {
                            request_id: pending_request_id,
                        } if pending_request_id == request_id
                    )
                }),
                SshModalPage::Add(_)
                | SshModalPage::ConfirmDelete(_)
                | SshModalPage::OperationApproval(_)
                | SshModalPage::WorkerInstallFallback(_)
                | SshModalPage::Authentication(_)
                | SshModalPage::Diagnostic(_) => false,
            }
    }

    fn target_form_submission_id(&self, editing: bool) -> Option<u64> {
        match &self.page {
            SshModalPage::Add(form) if form.submitting && form.is_editing() == editing => {
                form.submission_id
            }
            _ => None,
        }
    }

    /// The exact add-target submission currently displayed by the form.
    pub fn target_add_submission_id(&self) -> Option<u64> {
        self.target_form_submission_id(false)
    }

    pub fn target_add_is_submitting(&self) -> bool {
        self.target_add_submission_id().is_some()
    }

    pub fn target_update_submission_id(&self) -> Option<u64> {
        self.target_form_submission_id(true)
    }

    pub fn target_update_is_submitting(&self) -> bool {
        self.target_update_submission_id().is_some()
    }

    pub fn target_remove_submission_id(&self) -> Option<u64> {
        match &self.page {
            SshModalPage::ConfirmDelete(card) if card.submitting => card.submission_id,
            _ => None,
        }
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
                if !form.submitting || form.is_editing() {
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
        if !form.submitting || form.is_editing() {
            return false;
        }
        self.retired_target_ids.retain(|id| id != &saved_target_id);
        self.pending_target_selection_id = Some(saved_target_id);
        self.loading = true;
        self.page = SshModalPage::Manager;
        self.show_info("SSH target saved.");
        true
    }

    pub fn settle_target_update_for_submission(
        &mut self,
        submission_id: u64,
        result: Result<xai_grok_ssh::SshTarget, String>,
    ) -> bool {
        if self.target_update_submission_id() != Some(submission_id) {
            return false;
        }
        match result {
            Err(error) => {
                let SshModalPage::Add(form) = &mut self.page else {
                    return false;
                };
                form.submitting = false;
                form.submission_id = None;
                form.error = Some(error);
                true
            }
            Ok(target) => {
                let SshModalPage::Add(form) = &self.page else {
                    return false;
                };
                if !form.submitting || !form.is_editing() {
                    return false;
                }
                self.pending_target_selection_id = Some(target.id.clone());
                for view in self
                    .targets
                    .iter_mut()
                    .filter(|view| view.target_id == target.id)
                {
                    view.target_id = target.id.clone();
                    view.label = target.label.clone();
                    view.target = target.clone();
                }
                self.loading = true;
                self.page = SshModalPage::Manager;
                self.show_info("SSH target updated.");
                true
            }
        }
    }

    pub fn settle_target_remove_for_submission(
        &mut self,
        submission_id: u64,
        result: Result<xai_grok_ssh::SshTarget, String>,
    ) -> bool {
        if self.target_remove_submission_id() != Some(submission_id) {
            return false;
        }
        match result {
            Err(error) => {
                let SshModalPage::ConfirmDelete(card) = &mut self.page else {
                    return false;
                };
                card.submitting = false;
                card.submission_id = None;
                card.error = Some(error);
                true
            }
            Ok(target) => {
                if self.pending_prompt_target_id.as_deref() == Some(target.id.as_str()) {
                    self.clear_pending_prompt_target();
                }
                if !self.retired_target_ids.iter().any(|id| id == &target.id) {
                    self.retired_target_ids.push(target.id.clone());
                }
                self.targets.retain(|view| view.target_id != target.id);
                self.selected = self.selected.min(self.targets.len().saturating_sub(1));
                self.manager_scroll_offset = self.manager_scroll_offset.min(
                    self.targets
                        .len()
                        .saturating_sub(self.manager_visible_rows.max(1)),
                );
                self.page = SshModalPage::Manager;
                self.show_info("SSH target deleted; active connections and grants were revoked.");
                true
            }
        }
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
        self.begin_directory_browser(target_id, path, SshDirectoryPurpose::ProjectOpen)
    }

    fn begin_directory_browser(
        &mut self,
        target_id: String,
        path: Option<String>,
        purpose: SshDirectoryPurpose,
    ) -> SshModalOutcome {
        let request_id = next_nonzero_id(&NEXT_PROJECT_DIRECTORY_REQUEST_ID);
        self.project_browser = Some(SshProjectBrowser::new(
            target_id.clone(),
            path.clone(),
            request_id,
            purpose,
        ));
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
        let browser_error = self.project_browser.as_ref().and_then(|browser| browser.error.clone());
        if let Some(error) = browser_error {
            self.show_error(error);
        }
        true
    }

    /// Return the exact pending model request that owns this directory load.
    ///
    /// The browser request itself has no model authority. This tuple only lets dispatch settle
    /// the original request with a real browse error after the current manager/target/request
    /// correlation has been verified.
    pub fn pending_grant_for_directory_request(
        &self,
        directory_request_id: u64,
        target_id: &str,
    ) -> Option<(String, String)> {
        let browser = self.project_browser.as_ref()?;
        let SshDirectoryPurpose::PendingGrant { request_id } = &browser.purpose else {
            return None;
        };
        (browser.request_id == directory_request_id
            && browser.target_id == target_id
            && self
                .pending_grant
                .as_ref()
                .is_some_and(|request| request.request_id == *request_id))
        .then(|| {
            self.pending_grant_session_id
                .as_ref()
                .map(|session_id| (session_id.clone(), request_id.clone()))
        })
        .flatten()
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

    /// Target that currently owns an SSH authentication prompt, independent of active view.
    ///
    /// A live grant inspection also owns authentication: routing by the foreground session would
    /// otherwise present that host's credential challenge in an unrelated SSH manager.
    pub fn pending_authentication_target_id(&self) -> Option<&str> {
        if let Some(pending) = self.pending_project_open.as_ref() {
            return Some(pending.target_id.as_str());
        }
        if (self.resume_project_browser_after_authentication
            || matches!(&self.page, SshModalPage::ProjectBrowser))
            && let Some(target_id) = self
                .project_browser
                .as_ref()
                .filter(|browser| browser.loading)
                .map(|browser| browser.target_id.as_str())
        {
            return Some(target_id);
        }
        self.pending_grant
            .as_ref()
            .and_then(|request| {
                (!self
                    .cancelled_grant_ids
                    .iter()
                    .any(|cancelled| cancelled == &request.request_id))
                .then_some(request.target_id.as_deref())
                .flatten()
            })
            .or(
                self.pending_connection_is_connecting
                    .then_some(self.pending_connection.as_deref())
                    .flatten(),
            )
    }
    
    /// Select a configured target by stable ID without requiring a rendered row hit.
    ///
    /// The standalone manager uses this to make a direct `ssh connect TARGET` failure
    /// retryable from the same target row after its asynchronous listing arrives.
    pub fn select_target_id(&mut self, target_id: &str) -> bool {
        let Some(index) = self
            .targets
            .iter()
            .position(|target| target.target_id == target_id)
        else {
            return false;
        };
        self.selected = index;
        true
    }

    /// Consume the exact prompt selection only after its target is known connected.
    ///
    /// The app additionally correlates the successful connection result to this modal instance
    /// before calling this method, so an unowned global status cannot select a draft target.
    pub fn take_connected_prompt_target(&mut self, target_id: &str) -> Option<String> {
        if self.pending_prompt_target_id.as_deref() != Some(target_id)
            || !self.is_prompt_picker()
            || !matches!(&self.page, SshModalPage::Manager)
            || self.pending_grant.is_some()
            || !self
                .targets
                .iter()
                .any(|target| target.target_id == target_id && target.connected)
        {
            return None;
        }
        self.pending_prompt_target_id.take()
    }

    fn clear_pending_prompt_target(&mut self) {
        self.pending_prompt_target_id = None;
    }

    fn select_prompt_target(&mut self) -> SshModalOutcome {
        let Some((target_id, connected)) = self
            .selected_target()
            .map(|target| (target.target_id.clone(), target.connected))
        else {
            self.show_info("Select an SSH server for the current draft.");
            return SshModalOutcome::Changed;
        };
        self.clear_pending_prompt_target();
        if connected {
            SshModalOutcome::SelectPromptTarget { target_id }
        } else {
            self.pending_prompt_target_id = Some(target_id.clone());
            SshModalOutcome::Connect { target_id }
        }
    }

    pub fn queue_target_reference(&mut self, reference: String) {
        self.pending_target_reference = Some(reference);
    }

    /// Consume a direct configured reference after its target snapshot arrives.
    ///
    /// Prompt pickers accept this without a session because selection only updates the current
    /// draft; management mode retains its existing session requirement.
    pub fn continue_target_reference(&mut self) -> SshModalOutcome {
        if self.loading || (!self.is_prompt_picker() && self.session_id.is_none()) {
            return SshModalOutcome::Unchanged;
        }
        if self.is_prompt_picker()
            && (!matches!(&self.page, SshModalPage::Manager) || self.pending_grant.is_some())
        {
            return SshModalOutcome::Unchanged;
        }
        let Some(reference) = self.pending_target_reference.take() else {
            return SshModalOutcome::Unchanged;
        };
        let target_id = match xai_grok_ssh::TargetStore::resolve_configured_reference(
            &reference, self.targets.iter().map(|view| &view.target),
        ) {
            Ok(Some(target)) => target.id.clone(),
            Ok(None) => {
                self.show_info("SSH target not found. Select a configured server below, or use a full name / ID.");
                return SshModalOutcome::Changed;
            }
            Err(xai_grok_ssh::ConfigError::AmbiguousTarget { candidate_ids, .. }) => {
                self.targets.retain(|view| candidate_ids.contains(&view.target_id));
                self.selected = 0;
                self.show_info("Multiple matching servers. Choose the intended candidate by its ID below.");
                return SshModalOutcome::Changed;
            }
            Err(error) => {
                self.show_error(error.to_string());
                return SshModalOutcome::Changed;
            }
        };
        self.select_target_id(&target_id);
        if !self.is_prompt_picker()
            && self.targets.iter().filter(|view| view.target_id == target_id).count() > 1
        {
            self.show_info("This server has multiple access bindings. Select the intended folder and press Enter.");
            return SshModalOutcome::Changed;
        }
        handle_manager_key(self, &KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
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
        let grants_project = matches!(
            &self.page,
            SshModalPage::Grant(card)
                if card.project.as_ref().is_some_and(|project| project.request_id == request_id)
        );
        let diagnostic_wraps_project = matches!(
            &self.page,
            SshModalPage::Diagnostic(card)
                if card.return_grant.as_ref().is_some_and(|grant| {
                    grant.project.as_ref().is_some_and(|project| project.request_id == request_id)
                })
        );
        if grants_project {
            self.page = SshModalPage::ProjectBrowser;
        } else if diagnostic_wraps_project
            && let SshModalPage::Diagnostic(card) = &mut self.page
        {
            card.return_grant = None;
            card.return_browser = self.project_browser.is_some();
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
        if self.local_grant_options.as_ref().is_some_and(|options| {
            options.request_id.is_none()
                && options.target_id == target_id
                && options.root == root
        }) {
            return;
        }
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
        if let Some(options) = self.local_grant_options.as_mut()
            && options.request_id.is_none()
            && target_id == Some(options.target_id.as_str())
            && root == Some(options.root.as_str())
        {
            options.request_id = Some(request_id.to_owned());
            return true;
        }
        let Some(options) = self
            .cancelled_local_grant_options
            .iter_mut()
            .find(|options| {
                options.request_id.is_none()
                    && target_id == Some(options.target_id.as_str())
                    && root == Some(options.root.as_str())
            })
        else {
            return false;
        };
        options.request_id = Some(request_id.to_owned());
        true
    }

    /// Return the pre-minted or current session that owns a displayed/pending grant request.
    pub fn grant_session_id_for(&self, request_id: &str) -> Option<String> {
        let request_matches = self
            .pending_grant
            .as_ref()
            .is_some_and(|request| request.request_id == request_id)
            || matches!(&self.page, SshModalPage::Grant(card) if card.request_id == request_id);
        if request_matches {
            return self.pending_grant_session_id.clone();
        }
        (self
            .local_grant_options
            .as_ref()
            .is_some_and(|options| options.request_id.as_deref() == Some(request_id))
            || self
                .cancelled_local_grant_options
                .iter()
                .any(|options| options.request_id.as_deref() == Some(request_id)))
        .then(|| self.session_id.clone())
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
        // Once a refresh observes the deletion, a later externally re-created target with
        // the same ID must be visible again; these guards are not a persistent hide list.
        self.retired_target_ids
            .retain(|id| targets.iter().any(|target| &target.target_id == id));
        targets.retain(|target| {
            !self
                .retired_target_ids
                .iter()
                .any(|retired| retired == &target.target_id)
        });
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
        if self.is_prompt_picker() && !self.manager_advanced {
            let mut visible = 0;
            while visible < targets.len() {
                let duplicate = targets[..visible]
                    .iter()
                    .any(|shown| shown.target_id == targets[visible].target_id);
                if duplicate {
                    targets.remove(visible);
                } else {
                    visible += 1;
                }
            }
        }

        self.targets = targets;
        let pending_target_selection_id = self.pending_target_selection_id.clone();
        if let Some(target_id) = pending_target_selection_id
            && let Some(index) = self
                .targets
                .iter()
                .position(|target| target.target_id == target_id)
        {
            self.selected = index;
            self.pending_target_selection_id = None;
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
        if self.is_prompt_picker()
            && self
                .pending_prompt_target_id
                .as_ref()
                .is_some_and(|target_id| !self.targets.iter().any(|target| &target.target_id == target_id))
        {
            self.clear_pending_prompt_target();
        }
        if matches!(
            &self.page,
            SshModalPage::Authentication(card)
                if !matches!(&card.kind, SshAuthKind::SudoPassword { .. })
                    && self
                        .targets
                        .iter()
                        .any(|target| target.target_id == card.target_id && target.connected)
        ) {
            self.return_after_authentication();
        }
    }

    pub fn show_grant(&mut self, card: SshGrantCard) {
        self.visible = true;
        self.page = SshModalPage::Grant(card);
    }

    pub fn show_authentication(&mut self, card: SshAuthCard) {
        self.resume_project_browser_after_authentication =
            matches!(&self.page, SshModalPage::ProjectBrowser)
                && self
                    .project_browser
                    .as_ref()
                    .is_some_and(|browser| browser.target_id == card.target_id);
        self.visible = true;
        self.page = SshModalPage::Authentication(card);
    }

    /// Display a remote operation approval card.
    pub fn show_operation_approval(&mut self, card: SshOperationApprovalCard) {
        self.visible = true;
        self.page = SshModalPage::OperationApproval(card);
        self.submitted_operation_approval = None;
        self.pending_sudo_authentication = None;
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
        self.pending_sudo_authentication = (approved && card.is_sudo())
            .then(|| card.operation_id.as_ref())
            .flatten()
            .map(|operation_id| PendingSudoAuthentication {
                operation_id: operation_id.clone(),
                client_id: None,
                challenge_id: None,
            });
        self.submitted_operation_approval = Some(SubmittedOperationApproval {
            approval_id: approval_id.to_owned(),
            approved,
        });
        true
    }

    /// Display a root-password challenge only for the exact root operation that was approved in
    /// this session. A stale challenge is ignored rather than replacing unrelated user input.
    pub fn show_sudo_authentication(
        &mut self,
        client_id: u64,
        session_id: &str,
        operation_id: &str,
        card: SshAuthCard,
    ) -> bool {
        if self.session_id.as_deref() != Some(session_id) {
            return false;
        }
        let matches_submitted_root = matches!(
            &self.page,
            SshModalPage::OperationApproval(approval)
                if approval.submitting
                    && approval.is_sudo()
                    && approval.operation_id.as_deref() == Some(operation_id)
        );
        let Some(pending) = self.pending_sudo_authentication.as_mut() else {
            return false;
        };
        if pending.operation_id != operation_id {
            return false;
        }
        if let SshModalPage::Authentication(current) = &self.page {
            return pending.client_id == Some(client_id)
                && pending.challenge_id.as_deref() == Some(card.challenge_id.as_str())
                && current.challenge_id == card.challenge_id
                && current.connection_generation == card.connection_generation
                && current.target_id == card.target_id
                && matches!(&current.kind, SshAuthKind::SudoPassword { .. });
        }
        if !matches_submitted_root && !matches!(&self.page, SshModalPage::Manager) {
            return false;
        }
        pending.client_id = Some(client_id);
        pending.challenge_id = Some(card.challenge_id.clone());
        self.resume_project_browser_after_authentication = false;
        self.page = SshModalPage::Authentication(card);
        self.visible = true;
        true
    }

    /// Retire only the sudo challenge that belongs to this manager's exact client and session.
    ///
    /// Dropping the matching [`SshAuthCard`] drops its zeroizing local input buffer. A stale
    /// completion for a previous challenge is deliberately ignored.
    pub fn resolve_sudo_authentication(
        &mut self,
        client_id: u64,
        session_id: &str,
        challenge_id: &str,
        error: Option<String>,
    ) -> bool {
        if self.session_id.as_deref() != Some(session_id) {
            return false;
        }
        let Some(pending) = self.pending_sudo_authentication.as_ref() else {
            return false;
        };
        if pending.client_id != Some(client_id)
            || pending.challenge_id.as_deref() != Some(challenge_id)
        {
            return false;
        }
        self.pending_sudo_authentication = None;
        let visible = matches!(
            &self.page,
            SshModalPage::Authentication(card)
                if card.challenge_id == challenge_id
                    && matches!(&card.kind, SshAuthKind::SudoPassword { .. })
        );
        if visible {
            if let SshModalPage::Authentication(card) = &mut self.page {
                card.clear_answers();
            }
            self.return_after_authentication();
            if error.is_some() {
                self.show_info(
                    "Root authentication was cancelled or timed out; the command was not run.",
                );
            } else {
                self.visible = false;
            }
        }
        true
    }

    /// Retire a specific approval that the local SSH service has expired.
    ///
    /// Only the currently displayed matching card is removed, so a late expiration cannot
    /// dismiss a newer request. No local decision is emitted for the retired operation.
    pub fn expire_operation_approval(&mut self, approval_id: &str) -> bool {
        if !matches!(
            &self.page,
            SshModalPage::OperationApproval(card) if card.approval_id == approval_id
        ) {
            return false;
        }
        if self
            .submitted_operation_approval
            .as_ref()
            .is_some_and(|submitted| submitted.approval_id == approval_id)
        {
            self.submitted_operation_approval = None;
        }
        self.pending_sudo_authentication = None;
        self.loading = true;
        self.return_to_manager();
        self.show_info(
            "Retry operation for a new approval; prior approval expired. \
             No remote command was authorized.",
        );
        true
    }

    /// Settle one exact local-control submission without allowing a stale acknowledgement to
    /// dismiss a replacement card.
    pub fn settle_operation_approval(
        &mut self,
        approval_id: &str,
        error: Option<String>,
    ) -> SshOperationApprovalSettlement {
        let Some(submitted) = self.submitted_operation_approval.as_ref() else {
            return SshOperationApprovalSettlement::KeepVisible;
        };
        if submitted.approval_id != approval_id {
            return SshOperationApprovalSettlement::KeepVisible;
        }
        let submitted = self
            .submitted_operation_approval
            .take()
            .expect("submitted operation approval was checked above");
        let displayed = matches!(
            &self.page,
            SshModalPage::OperationApproval(card) if card.approval_id == approval_id
        );
        let awaiting_sudo_authentication = self.pending_sudo_authentication.is_some();
        if let Some(error) = error {
            self.pending_sudo_authentication = None;
            if let SshModalPage::OperationApproval(card) = &mut self.page
                && card.approval_id == approval_id
            {
                card.submitting = false;
                card.error = Some(error);
            } else if awaiting_sudo_authentication
                && matches!(
                    &self.page,
                    SshModalPage::Authentication(card)
                        if matches!(&card.kind, SshAuthKind::SudoPassword { .. })
                )
            {
                if let SshModalPage::Authentication(card) = &mut self.page {
                    card.clear_answers();
                }
                self.return_after_authentication();
                self.show_error(error);
            } else {
                self.show_error(error);
            }
            return SshOperationApprovalSettlement::KeepVisible;
        }
        if awaiting_sudo_authentication {
            if displayed {
                // The root command can either request a password later or reach its READY gate
                // immediately. Hide the manager but retain this exact pending tuple for either.
                self.return_to_manager();
                self.visible = false;
                return SshOperationApprovalSettlement::AwaitingSudoAuthentication;
            }
            return SshOperationApprovalSettlement::KeepVisible;
        }
        if submitted.approved && displayed {
            return SshOperationApprovalSettlement::Dismiss;
        }
        if displayed {
            self.return_to_manager();
            self.show_info("Remote operation denied.");
        }
        SshOperationApprovalSettlement::KeepVisible
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
        self.visible = true;
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

    /// Display or advance a real agent access request after its SSH target has been inspected.
    ///
    /// Target/root values from the initial request are unverified intent. Rootless requests use
    /// the shared picker; known roots are inspected immediately. A duplicate event never resets
    /// a picker or a human-edited consent card.
    pub fn show_incoming_grant(
        &mut self,
        session_id: String,
        request: SshIncomingGrant,
    ) -> SshModalOutcome {
        let request_id = request.request_id.clone();
        if self.cancelled_grant_ids.iter().any(|id| id == &request_id) {
            return SshModalOutcome::Unchanged;
        }
        self.visible = true;
        let cancelled_local_request = self
            .cancelled_local_grant_options
            .iter()
            .any(|options| {
                options.request_id.as_deref() == Some(request_id.as_str())
                    || (options.request_id.is_none()
                        && request.target_id.as_deref() == Some(options.target_id.as_str())
                        && request.root.as_deref() == Some(options.root.as_str()))
            });
        if cancelled_local_request {
            if let Some(options) = self.cancelled_local_grant_options.iter_mut().find(|options| {
                options.request_id.as_deref() == Some(request_id.as_str())
                    || (options.request_id.is_none()
                        && request.target_id.as_deref() == Some(options.target_id.as_str())
                        && request.root.as_deref() == Some(options.root.as_str()))
            }) {
                options.request_id = Some(request_id.clone());
            }
            self.cancelled_local_grant_options
                .retain(|options| options.request_id.as_deref() != Some(request_id.as_str()));
            self.remember_terminal_grant_id(&request_id);
            self.pending_grant_session_id = Some(session_id);
            self.pending_grant = Some(request);
            self.submitted_grant = None;
            return SshModalOutcome::CancelGrant { request_id };
        }
        if matches!(&self.page, SshModalPage::Grant(card) if card.request_id == request_id) {
            return SshModalOutcome::Unchanged;
        }
        if request.verified_identity.is_none()
            && self.pending_grant.as_ref().is_some_and(|pending| {
                pending.request_id == request_id
                    && (self.inspecting_grant_ids.iter().any(|id| id == &request_id)
                        || self.project_browser.as_ref().is_some_and(|browser| {
                            matches!(
                                &browser.purpose,
                                SshDirectoryPurpose::PendingGrant {
                                    request_id: pending_request_id,
                                } if pending_request_id == &request_id
                            )
                        }))
            })
        {
            return SshModalOutcome::Unchanged;
        }

        self.pending_grant_session_id = Some(session_id);
        self.submitted_grant = None;
        let Some(target_id) = request.target_id.as_deref() else {
            self.pending_grant = Some(request);
            self.page = SshModalPage::Manager;
            self.show_info(
                "Select an SSH target, then press Enter to choose a folder for this request.",
            );
            return SshModalOutcome::Changed;
        };
        if request
            .root
            .as_deref()
            .map_or(true, |root| root.trim().is_empty())
        {
            let target_id = target_id.to_owned();
            self.pending_grant = Some(request);
            return self.begin_directory_browser(
                target_id,
                None,
                SshDirectoryPurpose::PendingGrant { request_id },
            );
        }
        if request.verified_identity.is_none() {
            let target_id = target_id.to_owned();
            self.pending_grant = Some(request);
            self.project_browser = self
                .project_browser
                .take()
                .filter(|browser| browser.purpose.is_project_open());
            self.page = SshModalPage::Manager;
            if !self.inspecting_grant_ids.iter().any(|id| id == &request_id) {
                self.inspecting_grant_ids.push(request_id.clone());
            }
            return SshModalOutcome::InspectGrantTarget {
                request_id,
                target_id,
                selected_root: None,
                expected_identity: None,
            };
        }

        self.inspecting_grant_ids.retain(|id| id != &request_id);
        let local_options = self
            .local_grant_options
            .as_ref()
            .filter(|options| {
                options.request_id.as_deref() == Some(request.request_id.as_str())
                    && options.target_id == target_id
            })
            .cloned();
        let root = request.root.clone().expect("nonempty root was checked above");
        let target_label = self
            .targets
            .iter()
            .find(|target| target.target_id == target_id)
            .map(|target| target.label.clone())
            .unwrap_or_else(|| target_id.to_owned());
        let mut card = SshGrantCard::new(
            request.request_id.clone(),
            target_id.to_owned(),
            target_label,
            request.verified_identity.clone(),
            root,
            Some(request.reason.clone()),
            local_options.is_none(),
        );
        card.awaiting_tool = request.awaiting_tool;
        card.set_verified_scope(request.capabilities);
        if let Some(options) = local_options {
            card.capabilities = options.capabilities;
            card.lifetime = options.lifetime;
            card.set_default = options.set_default;
            card.follow_up = self.pending_grant_follow_up;
        }
        self.pending_grant = Some(request);
        self.project_browser = self
            .project_browser
            .take()
            .filter(|browser| browser.purpose.is_project_open());
        self.page = SshModalPage::Grant(card);
        SshModalOutcome::Changed
    }

    pub fn begin_connection_action(&mut self, target_id: &str, connect: bool) {
        if !connect && self.pending_prompt_target_id.as_deref() == Some(target_id) {
            self.clear_pending_prompt_target();
        }
        self.show_info(if connect {
            "Connecting through the local SSH service…"
        } else {
            "Releasing the retained SSH connection…"
        });
        self.pending_connection = Some(target_id.to_owned());
        self.pending_connection_is_connecting = connect;
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
        if self.pending_prompt_target_id.as_deref() == Some(target_id)
            && matches!(
                connection,
                SshConnectionState::Disconnected | SshConnectionState::Failed
            )
        {
            self.clear_pending_prompt_target();
        }
        if connected
            && matches!(
                &self.page,
                SshModalPage::Authentication(card)
                    if !matches!(&card.kind, SshAuthKind::SudoPassword { .. })
                        && card.target_id == target_id
            )
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
        if let Some(request_id) = request_id.as_deref() {
            self.inspecting_grant_ids.retain(|id| id != request_id);
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

    /// Return the project preparation tied to the exact displayed grant, if any.
    fn project_preparation_for_grant(&self, request_id: &str) -> Option<u64> {
        let grant = match &self.page {
            SshModalPage::Grant(card) => Some(card),
            SshModalPage::Diagnostic(card) => card.return_grant.as_ref(),
            _ => None,
        };
        match grant {
            Some(card) if card.request_id == request_id => {
                card.project.as_ref().map(|project| project.request_id)
            }
            _ => None,
        }
    }

    /// Remember a terminal request so a stale event cannot recreate its grant surface.
    fn remember_terminal_grant_id(&mut self, request_id: &str) {
        if self.cancelled_grant_ids.iter().any(|id| id == request_id) {
            return;
        }
        if self.cancelled_grant_ids.len() == 16 {
            self.cancelled_grant_ids.remove(0);
        }
        self.cancelled_grant_ids.push(request_id.to_owned());
    }

    /// Clear only the exact model request once the service has terminally settled it.
    fn clear_terminal_grant(&mut self, request_id: &str) -> bool {
        if !self
            .pending_grant
            .as_ref()
            .is_some_and(|request| request.request_id == request_id)
        {
            return false;
        }
        self.inspecting_grant_ids.retain(|id| id != request_id);
        self.pending_grant = None;
        self.submitted_grant = None;
        self.pending_grant_session_id = None;
        self.pending_grant_follow_up = None;
        self.local_grant_options = None;
        self.settled_grant_follow_up = None;
        true
    }

    /// Finish an exact cancellation without treating it as an explicit human denial.
    pub fn settle_grant_cancellation(&mut self, request_id: &str) -> bool {
        let project_request_id = self.project_preparation_for_grant(request_id);
        if !self.clear_terminal_grant(request_id) {
            return false;
        }
        self.remember_terminal_grant_id(request_id);
        self.project_browser = self.project_browser.take().filter(|browser| {
            !matches!(
                &browser.purpose,
                SshDirectoryPurpose::PendingGrant {
                    request_id: pending_request_id,
                } if pending_request_id == request_id
            )
        });
        if let Some(project_request_id) = project_request_id {
            self.finish_project_preparation(project_request_id, None);
        }
        self.page = SshModalPage::Manager;
        self.show_info("SSH access request cancelled.");
        true
    }

    /// Keep the original request live when its cancellation command could not be delivered.
    pub fn restore_cancelled_grant(&mut self, request_id: &str, error: String) -> bool {
        if !self
            .pending_grant
            .as_ref()
            .is_some_and(|request| request.request_id == request_id)
        {
            return false;
        }
        self.cancelled_grant_ids.retain(|id| id != request_id);
        self.show_error(error);
        true
    }

    /// Finish an exact service failure while retaining its diagnostic surface.
    pub fn settle_grant_failure(&mut self, request_id: &str, error: String) -> bool {
        let project_request_id = self.project_preparation_for_grant(request_id);
        if !self.clear_terminal_grant(request_id) {
            return false;
        }
        self.remember_terminal_grant_id(request_id);
        if let Some(project_request_id) = project_request_id {
            self.finish_project_preparation(project_request_id, Some(error));
            return true;
        }
        self.project_browser = self.project_browser.take().filter(|browser| {
            !matches!(
                &browser.purpose,
                SshDirectoryPurpose::PendingGrant {
                    request_id: pending_request_id,
                } if pending_request_id == request_id
            )
        });
        if let SshModalPage::Diagnostic(card) = &mut self.page {
            // The diagnostic may have wrapped the in-progress card before the service sent its
            // terminal failure. Returning from it must never revive that settled request.
            card.return_grant = None;
            card.return_browser = false;
        } else {
            self.page = SshModalPage::Diagnostic(SshDiagnosticCard::new(error));
            self.message = None;
        }
        true
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
                target.source_display(),
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

    /// Surface an exact pending-grant failure without allowing an old result to replace a
    /// newer request or revive a cancelled picker.
    pub fn fail_pending_grant(&mut self, request_id: &str, error: String) -> bool {
        if self.cancelled_grant_ids.iter().any(|id| id == request_id)
            || !self
                .pending_grant
                .as_ref()
                .is_some_and(|request| request.request_id == request_id)
        {
            return false;
        }
        self.inspecting_grant_ids.retain(|id| id != request_id);
        let browser_owns_request = self.project_browser.as_ref().is_some_and(|browser| {
            matches!(
                &browser.purpose,
                SshDirectoryPurpose::PendingGrant {
                    request_id: pending_request_id,
                } if pending_request_id == request_id
            )
        });
        if browser_owns_request {
            if let Some(browser) = self.project_browser.as_mut() {
                browser.loading = false;
                browser.preparing = false;
                browser.open_request_id = None;
                browser.notice = None;
                browser.error = Some(error.clone());
            }
            self.show_error(error);
        } else {
            self.page = SshModalPage::Diagnostic(SshDiagnosticCard::new(error));
            self.message = None;
        }
        true
    }

    pub fn show_error(&mut self, error: impl Into<String>) {
        self.clear_pending_prompt_target();
        self.pending_connection = None;
        self.pending_connection_is_connecting = false;
        let error = error.into();
        match std::mem::replace(&mut self.page, SshModalPage::Manager) {
            SshModalPage::ProjectBrowser | SshModalPage::Authentication(_)
                if self.project_browser.is_some() =>
            {
                self.resume_project_browser_after_authentication = false;
                if let Some(browser) = self.project_browser.as_mut() {
                    if !browser.purpose.is_project_open() {
                        browser.loading = false;
                        browser.preparing = false;
                        browser.open_request_id = None;
                    }
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
        self.pending_connection_is_connecting = false;
        self.message = Some((message.into(), false));
    }

    fn selected_target(&self) -> Option<&SshTargetView> {
        self.targets.get(self.selected)
    }

    fn selected_active_binding_id(&self) -> Option<&str> {
        self.selected_target().and_then(|target| match &target.grant {
            SshGrantView::Granted { binding_id, .. } => Some(binding_id.as_str()),
            SshGrantView::NotGranted | SshGrantView::Revoking { .. } => None,
        })
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
    UpdateTarget {
        expected: xai_grok_ssh::SshTarget,
        replacement: xai_grok_ssh::SshTarget,
        submission_id: u64,
    },
    RemoveTarget {
        expected: xai_grok_ssh::SshTarget,
        submission_id: u64,
    },
    SelectPromptTarget {
        target_id: String,
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
    /// Cancel a pending model request without recording an explicit denial.
    CancelGrant {
        request_id: String,
    },
    InspectGrantTarget {
        request_id: String,
        target_id: String,
        selected_root: Option<String>,
        expected_identity: Option<SshHostIdentity>,
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
        scope: SshOperationApprovalScope,
    },
    ResetOperationApprovals {
        binding_id: String,
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
const FOOTER_MANAGER_PROJECT: usize = 109;
const FOOTER_MANAGER_CONNECTION: usize = 102;
const FOOTER_MANAGER_ADD: usize = 103;
const FOOTER_MANAGER_DIAGNOSTIC: usize = 104;
const FOOTER_MANAGER_ADVANCED: usize = 105;
const FOOTER_MANAGER_GRANT: usize = 111;
const FOOTER_MANAGER_EDIT: usize = 106;
const FOOTER_MANAGER_DELETE: usize = 107;
const FOOTER_MANAGER_USE: usize = 112;
const FOOTER_MANAGER_REVOKE: usize = 113;
const FOOTER_MANAGER_RESET_OPERATION_APPROVALS: usize = 114;
const FOOTER_MANAGER_CLOSE: usize = 108;
const FOOTER_DELETE_CONFIRM: usize = 203;
const FOOTER_DELETE_CANCEL: usize = 204;
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
const FOOTER_OPERATION_ALLOW_SESSION: usize = 402;
const FOOTER_OPERATION_DENY: usize = 403;
const FOOTER_OPERATION_CLOSE: usize = 404;
const FOOTER_OPERATION_COPY: usize = 407;
const FOOTER_WORKER_INSTALL_APPROVE: usize = 405;
const FOOTER_WORKER_INSTALL_DECLINE: usize = 406;
const FOOTER_AUTH_SUBMIT: usize = 501;
const FOOTER_AUTH_CANCEL: usize = 502;
const FOOTER_HOST_TRUST_ONCE: usize = 511;
const FOOTER_HOST_TRUST_STORE: usize = 512;
const FOOTER_HOST_REPLACE: usize = 513;
const FOOTER_HOST_REJECT: usize = 514;
const FOOTER_DIAGNOSTIC_CLOSE: usize = 601;


const PROMPT_MANAGER_SHORTCUTS: &[Shortcut<'static>] = &[
    Shortcut {
        label: "j/k move",
        clickable: false,
        id: 0,
    },
    Shortcut {
        label: "Enter select server",
        clickable: true,
        id: FOOTER_MANAGER_OPEN_FOLDER,
    },
    Shortcut {
        label: "c connect/disconnect",
        clickable: true,
        id: FOOTER_MANAGER_CONNECTION,
    },
    Shortcut {
        label: "o open project (worker)",
        clickable: true,
        id: FOOTER_MANAGER_PROJECT,
    },
    Shortcut {
        label: "g grant",
        clickable: true,
        id: FOOTER_MANAGER_GRANT,
    },
    Shortcut {
        label: "a add",
        clickable: true,
        id: FOOTER_MANAGER_ADD,
    },
    Shortcut {
        label: "e edit",
        clickable: true,
        id: FOOTER_MANAGER_EDIT,
    },
    Shortcut {
        label: "x delete",
        clickable: true,
        id: FOOTER_MANAGER_DELETE,
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
const PRIMARY_MANAGER_SHORTCUTS: &[Shortcut<'static>] = &primary_manager_shortcuts(true, false);
const PRIMARY_MANAGER_WITH_BINDING_SHORTCUTS: &[Shortcut<'static>] =
    &primary_manager_shortcuts(true, true);
const STANDALONE_PRIMARY_MANAGER_SHORTCUTS: &[Shortcut<'static>] =
    &primary_manager_shortcuts(false, false);

const fn primary_manager_shortcuts(
    has_session: bool,
    selected_binding: bool,
) -> [Shortcut<'static>; 10] {
    [
        Shortcut {
            label: "j/k move",
            clickable: false,
            id: 0,
        },
        Shortcut {
            label: if !has_session {
                "Enter connect"
            } else if selected_binding {
                "Enter set session default"
            } else {
                "Enter choose access folder"
            },
            clickable: true,
            id: FOOTER_MANAGER_OPEN_FOLDER,
        },
        Shortcut {
            label: "o open project (worker)",
            clickable: true,
            id: FOOTER_MANAGER_PROJECT,
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
            label: "e edit",
            clickable: true,
            id: FOOTER_MANAGER_EDIT,
        },
        Shortcut {
            label: "x delete",
            clickable: true,
            id: FOOTER_MANAGER_DELETE,
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
    ]
}

const ADVANCED_MANAGER_SHORTCUTS: &[Shortcut<'static>] = &[
    Shortcut {
        label: "j/k move",
        clickable: false,
        id: 0,
    },
    Shortcut {
        label: "Enter choose access folder",
        clickable: true,
        id: FOOTER_MANAGER_OPEN_FOLDER,
    },
    Shortcut {
        label: "o open project (worker)",
        clickable: true,
        id: FOOTER_MANAGER_PROJECT,
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
        label: "e edit",
        clickable: true,
        id: FOOTER_MANAGER_EDIT,
    },
    Shortcut {
        label: "x delete",
        clickable: true,
        id: FOOTER_MANAGER_DELETE,
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

const ADVANCED_MANAGER_WITH_BINDING_SHORTCUTS: &[Shortcut<'static>] = &[
    Shortcut {
        label: "j/k move",
        clickable: false,
        id: 0,
    },
    Shortcut {
        label: "Enter set session default",
        clickable: true,
        id: FOOTER_MANAGER_OPEN_FOLDER,
    },
    Shortcut {
        label: "o open project (worker)",
        clickable: true,
        id: FOOTER_MANAGER_PROJECT,
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
        label: "e edit",
        clickable: true,
        id: FOOTER_MANAGER_EDIT,
    },
    Shortcut {
        label: "x delete",
        clickable: true,
        id: FOOTER_MANAGER_DELETE,
    },
    Shortcut {
        label: "p ask each time",
        clickable: true,
        id: FOOTER_MANAGER_RESET_OPERATION_APPROVALS,
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

/// Standalone management has no model session, so it intentionally omits every
/// action that could grant, select, revoke, or otherwise alter model authority.
/// Refresh remains available because configured-target and connection state are
/// meaningful before a project has been opened.
const STANDALONE_ADVANCED_MANAGER_SHORTCUTS: &[Shortcut<'static>] = &[
    Shortcut {
        label: "j/k move",
        clickable: false,
        id: 0,
    },
    Shortcut {
        label: "Enter connect",
        clickable: true,
        id: FOOTER_MANAGER_OPEN_FOLDER,
    },
    Shortcut {
        label: "o open project (worker)",
        clickable: true,
        id: FOOTER_MANAGER_PROJECT,
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
        label: "r refresh",
        clickable: true,
        id: FOOTER_MANAGER_REVOKE,
    },
    Shortcut {
        label: "e edit",
        clickable: true,
        id: FOOTER_MANAGER_EDIT,
    },
    Shortcut {
        label: "x delete",
        clickable: true,
        id: FOOTER_MANAGER_DELETE,
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

const DELETE_SHORTCUTS: &[Shortcut<'static>] = &[
    Shortcut {
        label: "Enter delete",
        clickable: true,
        id: FOOTER_DELETE_CONFIRM,
    },
    Shortcut {
        label: "Esc cancel",
        clickable: true,
        id: FOOTER_DELETE_CANCEL,
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

const GRANT_BROWSER_SHORTCUTS: &[Shortcut<'static>] = &[
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
        label: "o Use this folder for grants",
        clickable: true,
        id: FOOTER_BROWSER_OPEN,
    },
    Shortcut {
        label: "Esc cancel",
        clickable: true,
        id: FOOTER_MANAGER_CLOSE,
    },
];

const OPERATION_APPROVAL_SHORTCUTS: &[Shortcut<'static>] = &[
    Shortcut {
        label: "↑/↓ PgUp/PgDn inspect",
        clickable: false,
        id: 0,
    },
    Shortcut {
        label: "d raw details",
        clickable: false,
        id: 0,
    },
    Shortcut {
        label: "c copy command",
        clickable: true,
        id: FOOTER_OPERATION_COPY,
    },
    Shortcut {
        label: "y allow once",
        clickable: true,
        id: FOOTER_OPERATION_ALLOW,
    },
    Shortcut {
        label: "a allow kind: session+binding",
        clickable: true,
        id: FOOTER_OPERATION_ALLOW_SESSION,
    },
    Shortcut {
        label: "n/Esc deny",
        clickable: true,
        id: FOOTER_OPERATION_DENY,
    },
];

const ROOT_OPERATION_APPROVAL_SHORTCUTS: &[Shortcut<'static>] = &[
    Shortcut {
        label: "↑/↓ PgUp/PgDn inspect",
        clickable: false,
        id: 0,
    },
    Shortcut {
        label: "d raw details",
        clickable: false,
        id: 0,
    },
    Shortcut {
        label: "c copy command",
        clickable: true,
        id: FOOTER_OPERATION_COPY,
    },
    Shortcut {
        label: "y allow once",
        clickable: true,
        id: FOOTER_OPERATION_ALLOW,
    },
    Shortcut {
        label: "n/Esc deny",
        clickable: true,
        id: FOOTER_OPERATION_DENY,
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
        label: "n/Ctrl+d/click deny · Esc cancel",
        clickable: true,
        id: FOOTER_GRANT_DENY,
    },
    Shortcut {
        label: "Alt+d default",
        clickable: true,
        id: FOOTER_GRANT_DEFAULT,
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
        label: "n/Ctrl+d/click deny · Esc cancel",
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

/// Render the SSH overlay and return the visible, focused text input's terminal cursor.
pub fn render_ssh_modal(
    buf: &mut Buffer,
    area: Rect,
    state: &mut SshManagerState,
    compact: bool,
    theme: &Theme,
) -> Option<(u16, u16)> {
    if !state.is_visible() {
        return None;
    }
    state.manager_row_hits.clear();
    if let Some(browser) = state.project_browser.as_mut() {
        browser.row_hits.clear();
    }
    match &mut state.page {
        SshModalPage::Add(form) => form.field_hits.clear(),
        SshModalPage::Grant(card) => card.control_hits.clear(),
        SshModalPage::Manager
        | SshModalPage::ConfirmDelete(_)
        | SshModalPage::ProjectBrowser
        | SshModalPage::OperationApproval(_)
        | SshModalPage::WorkerInstallFallback(_)
        | SshModalPage::Authentication(_)
        | SshModalPage::Diagnostic(_) => {}
    }
    let (title, shortcuts): (&str, &[Shortcut<'_>]) = match &state.page {
        SshModalPage::Manager
            if state.is_prompt_picker() && !state.manager_advanced && state.pending_grant.is_none() => (
            "Choose SSH server for current draft",
            PROMPT_MANAGER_SHORTCUTS,
        ),
        SshModalPage::Manager => (
            "SSH targets",
            if state.session_id.is_none() && state.manager_advanced {
                STANDALONE_ADVANCED_MANAGER_SHORTCUTS
            } else if state.manager_advanced && state.pending_grant.is_some() {
                ADVANCED_MANAGER_SHORTCUTS
            } else if state.manager_advanced && state.selected_active_binding_id().is_some() {
                ADVANCED_MANAGER_WITH_BINDING_SHORTCUTS
            } else if state.manager_advanced {
                ADVANCED_MANAGER_SHORTCUTS
            } else if state.session_id.is_none() && state.pending_grant.is_none() {
                STANDALONE_PRIMARY_MANAGER_SHORTCUTS
            } else if state.pending_grant.is_some() {
                PRIMARY_MANAGER_SHORTCUTS
            } else if state.selected_active_binding_id().is_some() {
                PRIMARY_MANAGER_WITH_BINDING_SHORTCUTS
            } else {
                PRIMARY_MANAGER_SHORTCUTS
            },
        ),
        SshModalPage::Add(form) => (
            if form.is_editing() {
                "Edit SSH target"
            } else {
                "Add SSH target"
            },
            if form.submitting {
                ADD_SUBMITTING_SHORTCUTS
            } else {
                ADD_SHORTCUTS
            },
        ),
        SshModalPage::ConfirmDelete(_) => ("Delete SSH target", DELETE_SHORTCUTS),
        SshModalPage::Grant(card) => (
            if card.is_project_consent() {
                "Open remote project (requires worker)"
            } else {
                "Authorize SSH access (no worker)"
            },
            if card.is_project_consent() {
                PROJECT_GRANT_SHORTCUTS
            } else if card.follow_up.is_some() {
                &GRANT_SHORTCUTS[..GRANT_SHORTCUTS.len() - 1]
            } else {
                GRANT_SHORTCUTS
            },
        ),
        SshModalPage::ProjectBrowser => state
            .project_browser
            .as_ref()
            .is_some_and(|browser| browser.purpose.is_project_open())
            .then_some(("Choose project folder (requires worker)", PROJECT_BROWSER_SHORTCUTS))
            .unwrap_or(("Choose SSH access folder (no worker)", GRANT_BROWSER_SHORTCUTS)),
        SshModalPage::OperationApproval(card) => (
            if card.is_sudo() {
                "Root SSH operation approval"
            } else {
                "SSH operation approval"
            },
            if card.allows_session() {
                OPERATION_APPROVAL_SHORTCUTS
            } else {
                ROOT_OPERATION_APPROVAL_SHORTCUTS
            },
        ),
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
            SshModalPage::Add(form) => return render_add(buf, content, form, theme),
            SshModalPage::ConfirmDelete(card) => render_delete_confirmation(buf, content, card, theme),
            SshModalPage::Grant(card) => return render_grant(buf, content, card, theme),
            SshModalPage::ProjectBrowser => {
                if let Some(browser) = state.project_browser.as_mut() {
                    return render_project_browser(buf, content, browser, theme);
                }
            }
            SshModalPage::OperationApproval(card) => {
                render_operation_approval(buf, content, card, theme)
            }
            SshModalPage::WorkerInstallFallback(card) => {
                render_worker_install_fallback(buf, content, card, theme)
            }
            SshModalPage::Authentication(card) => return render_authentication(buf, content, card, theme),
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
        if let Some((message, false)) = state.message.as_ref() {
            let available = area.height.saturating_sub(1) as usize;
            for (row, line) in modal_window::word_wrap(message, area.width as usize)
                .into_iter()
                .take(available)
                .enumerate()
            {
                buf.set_stringn(
                    area.x,
                    area.y.saturating_add(1).saturating_add(row as u16),
                    line,
                    area.width as usize,
                    Style::default().fg(theme.text_secondary),
                );
            }
        } else {
            render_message(buf, area, state.message.as_ref(), theme);
        }
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
        let line = format!("{prefix}{}  [{}]", target.label, target.source_display());
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
            format!("  ID {} · {}", target.target_id, target.connection_detail),
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
) -> Option<(u16, u16)> {
    if area.height == 0 || area.width == 0 {
        browser.visible_rows = 0;
        return None;
    }
    let mut y = area.y;
    let mut cursor = None;
    let has_status = browser.error.is_some() || browser.notice.is_some()
        || browser.loading || browser.preparing;
    buf.set_stringn(
        area.x,
        y,
        format!("Server: {}", browser.target_id),
        area.width as usize,
        Style::default().fg(theme.text_secondary),
    );
    y = y.saturating_add(1);
    if y < area.bottom().saturating_sub(u16::from(has_status)) {
        cursor = render_line_editor(
            buf,
            Rect::new(area.x, y, area.width, 1),
            "Path: ",
            &browser.path,
            browser.editing_path && !browser.preparing,
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
    cursor
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
            AuthenticationLineTone::Warning => Style::default()
                .fg(theme.warning)
                .add_modifier(Modifier::BOLD),
            AuthenticationLineTone::Error => Style::default()
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
) -> Option<(u16, u16)> {
    if area.width == 0 || area.height == 0 {
        return None;
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
        return None;
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
    active.then(|| (
        input_x.saturating_add(
            (viewport.cursor_display_column as u16).min(input_width.saturating_sub(1) as u16),
        ),
        area.y,
    ))
}

fn render_add(buf: &mut Buffer, area: Rect, form: &mut SshManualTargetForm, theme: &Theme) -> Option<(u16, u16)> {
    let mut y = area.y;
    let mut cursor = None;
    let status = form.error.as_deref().or_else(|| {
        form.submitting
            .then_some("Saving target through the local SSH service…")
    });
    let fields_bottom = area.bottom().saturating_sub(u16::from(status.is_some()));
    let mut worker_command_visible = false;
    let visible_fields = fields_bottom.saturating_sub(area.y) as usize;
    let active_index = ManualTargetField::ALL.iter().position(|field| *field == form.active).unwrap_or(0);
    let first_field = active_index.saturating_sub(visible_fields.saturating_sub(1));
    for field in ManualTargetField::ALL.into_iter().skip(first_field) {
        if y >= fields_bottom {
            break;
        }
        let row = Rect::new(area.x, y, area.width, 1);
        let field_cursor = render_line_editor(
            buf,
            row,
            field.input_label(),
            form.editor(field),
            form.active == field && !form.submitting,
            theme,
        );
        cursor = cursor.or(field_cursor);
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
    cursor
}

fn render_delete_confirmation(
    buf: &mut Buffer,
    area: Rect,
    card: &SshDeleteConfirmation,
    theme: &Theme,
) {
    let impact = match (card.connected, card.has_active_grants) {
        (true, true) => "The active SSH connection will be disconnected and active grants will be revoked.",
        (true, false) => "The active SSH connection will be disconnected.",
        (false, true) => "Active SSH grants will be revoked.",
        (false, false) => "This target has no active connection or grants.",
    };
    let status = card.error.as_deref().or_else(|| card.submitting.then_some("Deleting target…"));
    let mut lines = vec![
        format!("Delete SSH target “{}”?", card.label),
        "This removes its Groky-managed configuration. This cannot be undone here.".into(),
        impact.into(),
    ];
    if let Some(status) = status {
        lines.push(status.into());
    }
    let width = area.width as usize;
    let mut y = area.y;
    for (index, line) in lines.iter().enumerate() {
        let style = if index == 0 {
            Style::default()
                .fg(theme.accent_error)
                .add_modifier(Modifier::BOLD)
        } else if card.error.is_some() && index + 1 == lines.len() {
            Style::default()
                .fg(theme.accent_error)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(theme.text_secondary)
        };
        for wrapped in modal_window::word_wrap(line, width.max(1)) {
            if y >= area.bottom() {
                return;
            }
            buf.set_stringn(area.x, y, wrapped, width, style);
            y = y.saturating_add(1);
        }
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

fn render_grant(buf: &mut Buffer, area: Rect, card: &mut SshGrantCard, theme: &Theme) -> Option<(u16, u16)> {
    if area.height == 0 || area.width == 0 {
        card.max_scroll_offset = 0;
        card.reviewed_to_end = false;
        return None;
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
        if card.is_project_consent() {
            "Opens a separate remote project session. Requires a matching remote worker; Groky installs it when supported."
        } else {
            "Allows SSH tools in this session. Uses SSH/SFTP directly; no remote worker is installed."
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
    if card.verified_root {
        push_grant_wrapped(
            &mut lines,
            format!("Verified remote folder: {}", card.root.text()),
            width,
            None,
            false,
        );
    } else {
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
    }
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
        let requested = card.capability_is_requested(focus);
        push_grant_wrapped(
            &mut lines,
            format!(
                "[{}] {label}{}",
                if enabled { "x" } else { " " },
                if requested { "" } else { " (not requested)" }
            ),
            width,
            requested.then_some(focus),
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
                if card.follow_up.is_some() {
                    "yes (selected after approval)"
                } else if card.set_default {
                    "yes"
                } else {
                    "no"
                }
            ),
            width,
            card.follow_up.is_none().then_some(SshGrantFocus::Default),
            false,
        );
    }
    if card.awaiting_tool {
        push_grant_wrapped(
            &mut lines,
            "The model is waiting for your decision. Allowing access approves this request and continues that tool call.",
            width,
            None,
            false,
        );
    } else if card.agent_requested {
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
    let mut cursor = None;
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
                .fg(theme.warning)
                .add_modifier(Modifier::BOLD)
        } else if focused {
            Style::default()
                .fg(theme.accent_user)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(theme.text_secondary)
        };
        if line.root_editor {
            cursor = render_line_editor(buf, rect, &line.text, &card.root, focused, theme);
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
    cursor
}

struct OperationApprovalRenderLine {
    line: Line<'static>,
}

fn render_operation_approval(
    buf: &mut Buffer,
    area: Rect,
    card: &mut SshOperationApprovalCard,
    theme: &Theme,
) {
    if area.height == 0 || area.width == 0 {
        card.page_size = 1;
        card.max_scroll_offset = 0;
        return;
    }
    let lines = operation_approval_lines(card, area.width as usize, theme);
    card.page_size = area.height.saturating_sub(1).max(1) as usize;
    card.max_scroll_offset = lines.len().saturating_sub(card.page_size);
    card.scroll_offset = card.scroll_offset.min(card.max_scroll_offset);
    card.reviewed_to_end |= card.max_scroll_offset == 0
        || card.scroll_offset >= card.max_scroll_offset;

    for (index, preview_line) in lines
        .iter()
        .skip(card.scroll_offset)
        .take(card.page_size)
        .enumerate()
    {
        buf.set_line(
            area.x,
            area.y.saturating_add(index as u16),
            &preview_line.line,
            area.width,
        );
    }
    if area.height > 1 {
        let status = card.copy_status.map(str::to_owned).unwrap_or_else(|| format!(
            "Details {}/{} · {}",
            card.scroll_offset + 1,
            card.max_scroll_offset + 1,
            if card.reviewed_to_end { "reviewed" } else { "scroll to end before allowing" },
        ));
        buf.set_stringn(area.x, area.bottom() - 1, status, area.width as usize, Style::default().fg(theme.text_secondary));
    }
}

fn operation_approval_lines(
    card: &SshOperationApprovalCard,
    width: usize,
    theme: &Theme,
) -> Vec<OperationApprovalRenderLine> {
    let width = width.max(1);
    let mut lines = Vec::new();
    push_operation_wrapped(
        &mut lines,
        &format!(
            "Target: {} ({})",
            safe_operation_text(&card.target_label),
            safe_operation_text(&card.binding_id)
        ),
        width,
        Style::default().fg(theme.text_secondary),
    );
    if card.is_sudo() {
        let login_identity = card
            .target_identity
            .as_deref()
            .map(safe_operation_text)
            .or_else(|| operation_identity(&card.detail))
            .unwrap_or_else(|| "the verified SSH login identity".into());
        push_operation_wrapped(
            &mut lines,
            &format!("SSH login identity: {login_identity} → root"),
            width,
            Style::default().fg(theme.text_secondary),
        );
    } else if let Some(identity) = card.target_identity.as_deref() {
        push_operation_wrapped(
            &mut lines,
            &format!("Verified SSH identity: {}", safe_operation_text(identity)),
            width,
            Style::default().fg(theme.text_secondary),
        );
    } else if let Some(identity) = operation_identity(&card.detail) {
        push_operation_wrapped(
            &mut lines,
            &format!("Verified SSH identity: {identity}"),
            width,
            Style::default().fg(theme.text_secondary),
        );
    }
    push_operation_context(&mut lines, &card.detail, width, theme);
    push_operation_wrapped(
        &mut lines,
        &card.title,
        width,
        Style::default()
            .fg(theme.accent_user)
            .add_modifier(Modifier::BOLD),
    );
    push_operation_wrapped(
        &mut lines,
        &format!("Requested operation: {}", operation_label(card.operation)),
        width,
        Style::default().fg(theme.text_secondary),
    );
    lines.push(operation_text_line("", Style::default()));

    let recognized = if card.raw_details {
        push_operation_wrapped(
            &mut lines,
            "Raw JSON details:",
            width,
            Style::default()
                .fg(theme.accent_user)
                .add_modifier(Modifier::BOLD),
        );
        let raw = serde_json::to_string_pretty(&card.detail)
            .unwrap_or_else(|_| "JSON serialization failed for the remote operation payload.".into());
        push_operation_source(&mut lines, &raw, width, false, theme);
        true
    } else {
        push_operation_preview(&mut lines, card, width, theme)
    };

    if !recognized {
        push_operation_wrapped(
            &mut lines,
            "The remote operation payload did not match a known preview. Complete technical details:",
            width,
            Style::default()
                .fg(theme.warning)
                .add_modifier(Modifier::BOLD),
        );
        push_operation_technical_value(&mut lines, "payload", &card.detail, width, theme);
    } else if !card.raw_details {
        push_operation_wrapped(
            &mut lines,
            "Press d to inspect the complete raw JSON details.",
            width,
            Style::default().fg(theme.text_secondary),
        );
    }

    if card.operation == SshOperation::Execute {
        let warning = if card.is_sudo() {
            "Warning: this command runs as root. Root access is not confined to this SSH cwd or grant root."
        } else {
            "Warning: remote commands run with this SSH user's privileges; cwd is not a sandbox."
        };
        push_operation_wrapped(
            &mut lines,
            warning,
            width,
            Style::default()
                .fg(theme.warning)
                .add_modifier(Modifier::BOLD),
        );
    }
    if let Some(error) = card.error.as_deref() {
        push_operation_wrapped(
            &mut lines,
            &format!("Error: {error}"),
            width,
            Style::default().fg(theme.accent_error),
        );
    }
    lines.push(operation_text_line("", Style::default()));
    push_operation_wrapped(
        &mut lines,
        if card.submitting {
            "Submitting remote operation decision…"
        } else if card.allows_session() {
            "After review: y allow once · a allow this operation kind for this SSH session and binding · n/Esc deny"
        } else {
            "After review: y allow once · n/Esc deny"
        },
        width,
        if card.submitting {
            Style::default().fg(theme.text_secondary)
        } else {
            Style::default()
                .fg(theme.accent_user)
                .add_modifier(Modifier::BOLD)
        },
    );
    lines
}

fn push_operation_preview(
    lines: &mut Vec<OperationApprovalRenderLine>,
    card: &SshOperationApprovalCard,
    width: usize,
    theme: &Theme,
) -> bool {
    match card.operation {
        SshOperation::Execute => {
            let Some(command) = operation_detail_string(&card.detail, &["command"]) else {
                return false;
            };
            push_operation_wrapped(
                lines,
                "Exact remote command:",
                width,
                Style::default()
                    .fg(theme.accent_user)
                    .add_modifier(Modifier::BOLD),
            );
            push_operation_source(lines, command, width, true, theme);
            true
        }
        SshOperation::Write => {
            let Some(path) = operation_detail_string(
                &card.detail,
                &["target_file", "file_path", "path"],
            ) else {
                return false;
            };
            if let (Some(old), Some(new)) = (
                operation_detail_string(&card.detail, &["old_string", "old", "before"]),
                operation_detail_string(&card.detail, &["new_string", "new", "after"]),
            ) {
                push_operation_wrapped(
                    lines,
                    &format!("Edit remote file: {}", safe_operation_text(path)),
                    width,
                    Style::default()
                        .fg(theme.accent_user)
                        .add_modifier(Modifier::BOLD),
                );
                push_operation_wrapped(
                    lines,
                    "Old source:",
                    width,
                    Style::default().fg(theme.text_secondary),
                );
                push_operation_source(lines, old, width, false, theme);
                push_operation_wrapped(
                    lines,
                    "New source:",
                    width,
                    Style::default().fg(theme.text_secondary),
                );
                push_operation_source(lines, new, width, false, theme);
                return true;
            }
            let Some(content) =
                operation_detail_string(&card.detail, &["content", "contents", "text"])
            else {
                return false;
            };
            push_operation_wrapped(
                lines,
                &format!("Write remote file: {}", safe_operation_text(path)),
                width,
                Style::default()
                    .fg(theme.accent_user)
                    .add_modifier(Modifier::BOLD),
            );
            push_operation_wrapped(
                lines,
                "Exact file content:",
                width,
                Style::default().fg(theme.text_secondary),
            );
            push_operation_source(lines, content, width, false, theme);
            true
        }
        SshOperation::Read => {
            let Some(path) = operation_detail_string(
                &card.detail,
                &["target_file", "file_path", "path"],
            ) else {
                return false;
            };
            push_operation_wrapped(
                lines,
                &format!("Read remote file: {}", safe_operation_text(path)),
                width,
                Style::default()
                    .fg(theme.accent_user)
                    .add_modifier(Modifier::BOLD),
            );
            true
        }
    }
}

fn operation_label(operation: SshOperation) -> &'static str {
    match operation {
        SshOperation::Read => "read",
        SshOperation::Write => "write or edit",
        SshOperation::Execute => "execute",
    }
}

fn push_operation_context(
    lines: &mut Vec<OperationApprovalRenderLine>,
    detail: &Value,
    width: usize,
    theme: &Theme,
) {
    for (label, fields) in [
        ("Target ID", &["target_id", "target"][..]),
        ("Remote user", &["username", "user"][..]),
        ("Remote host", &["hostname", "host"][..]),
        ("Verified remote root", &["root"][..]),
        ("Remote cwd", &["cwd"][..]),
    ] {
        let value = operation_detail_string(detail, fields).or_else(|| match label {
            "Remote user" => operation_identity_component(detail, "username"),
            "Remote host" => operation_identity_component(detail, "hostname"),
            _ => None,
        });
        if let Some(value) = value {
            push_operation_wrapped(
                lines,
                &format!("{label}: {}", safe_operation_text(value)),
                width,
                Style::default().fg(theme.text_secondary),
            );
        }
    }
}

fn operation_identity_component<'a>(detail: &'a Value, field: &str) -> Option<&'a str> {
    operation_detail_field(detail, &["identity"])?
        .get(field)?
        .as_str()
}

fn operation_identity(detail: &Value) -> Option<String> {
    let identity = operation_detail_field(detail, &["identity"])?;
    let object = identity.as_object()?;
    let username = object.get("username")?.as_str()?;
    let hostname = object.get("hostname")?.as_str()?;
    let port = object
        .get("port")
        .map(|port| port.to_string())
        .unwrap_or_else(|| "?".into());
    let fingerprint = object
        .get("fingerprint")
        .and_then(Value::as_str)
        .map(|fingerprint| format!(" ({})", safe_operation_text(fingerprint)))
        .unwrap_or_default();
    Some(format!(
        "{}@{}:{}{}",
        safe_operation_text(username),
        safe_operation_text(hostname),
        port,
        fingerprint
    ))
}

fn operation_detail_string<'a>(detail: &'a Value, fields: &[&str]) -> Option<&'a str> {
    operation_detail_field(detail, fields)?.as_str()
}

fn operation_detail_field<'a>(detail: &'a Value, fields: &[&str]) -> Option<&'a Value> {
    let object = detail.as_object()?;
    fields
        .iter()
        .find_map(|field| object.get(*field))
        .or_else(|| {
            ["args", "input", "params"].iter().find_map(|container| {
                object
                    .get(*container)
                    .and_then(Value::as_object)
                    .and_then(|nested| fields.iter().find_map(|field| nested.get(*field)))
            })
        })
}

fn push_operation_technical_value(
    lines: &mut Vec<OperationApprovalRenderLine>,
    label: &str,
    value: &Value,
    width: usize,
    theme: &Theme,
) {
    match value {
        Value::Object(object) if object.is_empty() => push_operation_wrapped(
            lines,
            &format!("{label}: {{}}"),
            width,
            Style::default().fg(theme.text_secondary),
        ),
        Value::Object(object) => {
            for (key, nested) in object {
                let nested_label = format!("{label}.{key}");
                push_operation_technical_value(lines, &nested_label, nested, width, theme);
            }
        }
        Value::Array(values) if values.is_empty() => push_operation_wrapped(
            lines,
            &format!("{label}: []"),
            width,
            Style::default().fg(theme.text_secondary),
        ),
        Value::Array(values) => {
            for (index, nested) in values.iter().enumerate() {
                let nested_label = format!("{label}[{index}]");
                push_operation_technical_value(lines, &nested_label, nested, width, theme);
            }
        }
        Value::String(text) => {
            push_operation_wrapped(
                lines,
                &format!("{label}:"),
                width,
                Style::default().fg(theme.text_secondary),
            );
            push_operation_source(lines, text, width, false, theme);
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => push_operation_wrapped(
            lines,
            &format!("{label}: {value}"),
            width,
            Style::default().fg(theme.text_secondary),
        ),
    }
}

fn push_operation_source(
    lines: &mut Vec<OperationApprovalRenderLine>,
    source: &str,
    width: usize,
    bash_syntax: bool,
    theme: &Theme,
) {
    let source = safe_operation_text(source);
    let code_width = width.saturating_sub(2).max(1);
    for physical_line in source.split('\n') {
        let spans = if bash_syntax {
            crate::views::tasks_pane::highlight_bash_command(physical_line)
        } else {
            vec![Span::styled(
                physical_line.to_owned(),
                Style::default().fg(theme.text_secondary),
            )]
        };
        for source_row in wrap_operation_spans(&spans, code_width) {
            let mut row = Vec::with_capacity(source_row.len() + 1);
            row.push(Span::styled("  ", theme.dim()));
            row.extend(source_row);
            lines.push(OperationApprovalRenderLine {
                line: Line::from(row),
            });
        }
    }
}

fn wrap_operation_spans(spans: &[Span<'static>], width: usize) -> Vec<Vec<Span<'static>>> {
    let width = width.max(1);
    let mut rows = Vec::new();
    let mut row = Vec::new();
    let mut used = 0usize;
    for span in spans {
        let content = span.content.as_ref();
        let mut chunk_start = 0usize;
        for (index, character) in content.char_indices() {
            let character_width = unicode_width::UnicodeWidthChar::width(character).unwrap_or(0);
            if used > 0 && used + character_width > width {
                if chunk_start < index {
                    row.push(Span::styled(
                        content[chunk_start..index].to_owned(),
                        span.style,
                    ));
                }
                rows.push(std::mem::take(&mut row));
                used = 0;
                chunk_start = index;
            }
            used += character_width;
        }
        if chunk_start < content.len() {
            row.push(Span::styled(content[chunk_start..].to_owned(), span.style));
        }
    }
    rows.push(row);
    rows
}

fn push_operation_wrapped(
    lines: &mut Vec<OperationApprovalRenderLine>,
    text: &str,
    width: usize,
    style: Style,
) {
    let text = safe_operation_text(text);
    for physical_line in text.split('\n') {
        let wrapped = modal_window::word_wrap(physical_line, width.max(1));
        if wrapped.is_empty() {
            lines.push(operation_text_line("", style));
        } else {
            for line in wrapped {
                lines.push(operation_text_line(line, style));
            }
        }
    }
}

fn operation_text_line(text: impl Into<String>, style: Style) -> OperationApprovalRenderLine {
    OperationApprovalRenderLine {
        line: Line::from(Span::styled(text.into(), style)),
    }
}

fn safe_operation_text(text: &str) -> String {
    let mut safe = String::with_capacity(text.len());
    for character in text.chars() {
        if character == '\n' {
            safe.push(character);
        } else if character.is_control() {
            safe.extend(character.escape_default());
        } else {
            safe.push(character);
        }
    }
    safe
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

/// Append only the visible portion of a masked answer; secret bytes never enter display strings.
fn push_authentication_input(
    lines: &mut Vec<(String, AuthenticationLineTone)>,
    card: &SshAuthCard,
    index: usize,
    width: usize,
) -> Option<(usize, usize)> {
    let answer = card.answers.get(index)?;
    let active = index == card.active_answer;
    let columns = width.saturating_sub(2);
    let before = answer.text()[..answer.cursor_byte].chars().count();
    let after = answer.text()[answer.cursor_byte..].chars().count();
    let start = if active { before.saturating_sub(columns.saturating_sub(1)) } else { 0 };
    let visible = (before + after).saturating_sub(start).min(columns);
    let mut line = String::with_capacity(4 + visible * '•'.len_utf8());
    line.push_str(if active { "› " } else { "  " });
    line.extend(std::iter::repeat_n('•', visible));
    let row = lines.len();
    lines.push((line, AuthenticationLineTone::Normal));
    (active && columns > 0).then_some((row, 2 + before - start))
}

fn authentication_lines(
    card: &SshAuthCard,
    width: usize,
) -> (Vec<(String, AuthenticationLineTone)>, Option<(usize, usize)>) {
    let mut lines = Vec::new();
    let mut cursor = None;
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
            cursor = push_authentication_input(&mut lines, card, 0, width);
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
        SshAuthKind::SudoPassword {
            username,
            message: _,
        } => {
            append_wrapped_authentication_line(
                &mut lines,
                &format!("Target: {}", card.target_id),
                AuthenticationLineTone::Normal,
                width,
            );
            append_wrapped_authentication_line(
                &mut lines,
                &format!("SSH login identity: {username} → root"),
                AuthenticationLineTone::Warning,
                width,
            );
            append_wrapped_authentication_line(
                &mut lines,
                "Enter the remote SSH account's sudo password here. It is sent only over this SSH connection for this one root command and is not saved.",
                AuthenticationLineTone::Warning,
                width,
            );
            append_wrapped_authentication_line(
                &mut lines,
                "",
                AuthenticationLineTone::Normal,
                width,
            );
            cursor = push_authentication_input(&mut lines, card, 0, width);
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
                if let Some(position) = push_authentication_input(&mut lines, card, index, width) {
                    cursor = Some(position);
                }
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
    (lines, cursor)
}

fn render_authentication(
    buf: &mut Buffer,
    area: Rect,
    card: &mut SshAuthCard,
    theme: &Theme,
) -> Option<(u16, u16)> {
    if area.height == 0 || area.width == 0 {
        return None;
    }
    let (lines, cursor) = authentication_lines(card, area.width as usize);
    let height = area.height as usize;
    let body_height = if lines.len() > height && height > 1 {
        height - 1
    } else {
        height
    };
    card.max_scroll_offset = lines.len().saturating_sub(body_height);
    let resized = card.viewport_size != Some((area.width, area.height));
    card.viewport_size = Some((area.width, area.height));
    if (card.reveal_answer || resized) && let Some((row, _)) = cursor {
        if row < card.scroll_offset {
            card.scroll_offset = row;
        } else if row >= card.scroll_offset + body_height {
            card.scroll_offset = row + 1 - body_height;
        }
    }
    if cursor.is_some() {
        card.reveal_answer = false;
    }
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
            AuthenticationLineTone::Warning => Style::default()
                .fg(theme.warning)
                .add_modifier(Modifier::BOLD),
            AuthenticationLineTone::Error => Style::default()
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
    cursor.and_then(|(row, column)| {
        let visible_row = row.checked_sub(card.scroll_offset)?;
        (visible_row < body_height && column < area.width as usize)
            .then_some((area.x + column as u16, area.y + visible_row as u16))
    })
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
    if matches!(&state.page, SshModalPage::ConfirmDelete(_)) {
        return handle_delete_key(state, key);
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
        SshModalPage::Manager | SshModalPage::ConfirmDelete(_) | SshModalPage::ProjectBrowser => {
            unreachable!("manager, deletion, and browser pages are handled before borrowing modal page")
        }
    };
    if let SshModalOutcome::AnswerAuthentication {
        host_key_decision,
        secret,
        answers,
        ..
    } = &outcome
    {
        let cancelled = secret.is_none()
            && answers.is_empty()
            && host_key_decision
                .as_ref()
                .map_or(true, |decision| decision == &xai_grok_shell::ssh::SshHostKeyDecision::Reject);
        if cancelled {
            state.clear_pending_prompt_target();
        }
        state.return_after_authentication();
    }
    outcome
}

fn footer_key_for(page: &SshModalPage, id: usize) -> Option<KeyEvent> {
    let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
    let alt = |code| KeyEvent::new(code, KeyModifiers::ALT);
    let ctrl = |code| KeyEvent::new(code, KeyModifiers::CONTROL);
    match (page, id) {
        (SshModalPage::Manager, FOOTER_MANAGER_OPEN_FOLDER) => Some(key(KeyCode::Enter)),
        (SshModalPage::Manager, FOOTER_MANAGER_PROJECT) => Some(key(KeyCode::Char('o'))),
        (SshModalPage::Manager, FOOTER_MANAGER_CONNECTION) => Some(key(KeyCode::Char('c'))),
        (SshModalPage::Manager, FOOTER_MANAGER_ADD) => Some(key(KeyCode::Char('a'))),
        (SshModalPage::Manager, FOOTER_MANAGER_EDIT) => Some(key(KeyCode::Char('e'))),
        (SshModalPage::Manager, FOOTER_MANAGER_DELETE) => Some(key(KeyCode::Char('x'))),
        (SshModalPage::Manager, FOOTER_MANAGER_ADVANCED) => Some(key(KeyCode::Char('m'))),
        (SshModalPage::Manager, FOOTER_MANAGER_GRANT) => Some(key(KeyCode::Char('g'))),
        (SshModalPage::Manager, FOOTER_MANAGER_USE) => Some(key(KeyCode::Char('u'))),
        (SshModalPage::Manager, FOOTER_MANAGER_REVOKE) => Some(key(KeyCode::Char('r'))),
        (SshModalPage::Manager, FOOTER_MANAGER_RESET_OPERATION_APPROVALS) => {
            Some(key(KeyCode::Char('p')))
        }
        (SshModalPage::Manager, FOOTER_MANAGER_DIAGNOSTIC) => Some(key(KeyCode::Char('d'))),
        (SshModalPage::Manager, FOOTER_MANAGER_CLOSE) => Some(key(KeyCode::Esc)),
        (SshModalPage::Add(form), FOOTER_ADD_SAVE) if !form.submitting => Some(key(KeyCode::Enter)),
        (SshModalPage::Add(_), FOOTER_ADD_CANCEL) => Some(key(KeyCode::Esc)),
        (SshModalPage::ConfirmDelete(card), FOOTER_DELETE_CONFIRM) if !card.submitting => {
            Some(key(KeyCode::Enter))
        }
        (SshModalPage::ConfirmDelete(card), FOOTER_DELETE_CANCEL) if !card.submitting => {
            Some(key(KeyCode::Esc))
        }
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
        (SshModalPage::Grant(_), FOOTER_GRANT_DENY) => Some(ctrl(KeyCode::Char('d'))),
        (SshModalPage::ProjectBrowser, FOOTER_BROWSER_PARENT) => Some(key(KeyCode::Backspace)),
        (SshModalPage::ProjectBrowser, FOOTER_BROWSER_OPEN) => Some(key(KeyCode::Char('o'))),
        (SshModalPage::ProjectBrowser, FOOTER_MANAGER_CLOSE) => Some(key(KeyCode::Esc)),
        (SshModalPage::OperationApproval(_), FOOTER_OPERATION_ALLOW) => {
            Some(key(KeyCode::Char('y')))
        }
        (SshModalPage::OperationApproval(card), FOOTER_OPERATION_ALLOW_SESSION)
            if card.allows_session() =>
        {
            Some(key(KeyCode::Char('a')))
        }
        (SshModalPage::OperationApproval(_), FOOTER_OPERATION_DENY) => {
            Some(key(KeyCode::Char('n')))
        }
        (SshModalPage::OperationApproval(_), FOOTER_OPERATION_CLOSE) => Some(key(KeyCode::Esc)),
        (SshModalPage::OperationApproval(_), FOOTER_OPERATION_COPY) => {
            Some(key(KeyCode::Char('c')))
        }
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
        | SshModalPage::ConfirmDelete(_)
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
            if state.is_prompt_picker() && !state.manager_advanced {
                return handle_manager_key(state, &KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
            }
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
            | SshModalPage::ConfirmDelete(_)
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
        SshModalPage::OperationApproval(card) => scroll_operation_approval(card, delta),
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
        SshModalPage::Manager | SshModalPage::ConfirmDelete(_) | SshModalPage::Add(_) => {
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


fn cancel_grant_once(state: &mut SshManagerState, request_id: String) -> SshModalOutcome {
    if state.cancelled_grant_ids.iter().any(|id| id == &request_id) {
        return SshModalOutcome::Changed;
    }
    state.inspecting_grant_ids.retain(|id| id != &request_id);
    state.remember_terminal_grant_id(&request_id);
    SshModalOutcome::CancelGrant { request_id }
}

fn close_current_page(state: &mut SshManagerState) -> SshModalOutcome {
    state.clear_pending_prompt_target();
    if matches!(&state.page, SshModalPage::ProjectBrowser) {
        let purpose = state
            .project_browser
            .as_ref()
            .map(|browser| browser.purpose.clone());
        let browser_dispatched = state
            .project_browser
            .as_ref()
            .is_some_and(|browser| browser.open_request_id.is_some());
        if matches!(&purpose, Some(SshDirectoryPurpose::ProjectOpen))
            && let Some(pending) = state.pending_project_open.take()
        {
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
        return match purpose {
            Some(SshDirectoryPurpose::PendingGrant { request_id }) => {
                cancel_grant_once(state, request_id)
            }
            Some(SshDirectoryPurpose::LocalGrant { .. }) if !browser_dispatched => {
                SshModalOutcome::Changed
            }
            Some(SshDirectoryPurpose::LocalGrant { .. }) => {
                let local_options = state.local_grant_options.clone();
                match local_options {
                    Some(options) if options.request_id.is_none() => {
                        if state.cancelled_local_grant_options.len() == 16 {
                            state.cancelled_local_grant_options.remove(0);
                        }
                        if !state.cancelled_local_grant_options.iter().any(|cancelled| {
                            cancelled.target_id == options.target_id && cancelled.root == options.root
                        }) {
                            state.cancelled_local_grant_options.push(options);
                        }
                        SshModalOutcome::Changed
                    }
                    Some(LocalGrantOptions {
                        request_id: Some(request_id),
                        ..
                    }) => cancel_grant_once(state, request_id),
                    Some(_) => SshModalOutcome::Changed,
                    None => {
                        state.pending_grant_follow_up = None;
                        SshModalOutcome::Changed
                    }
                }
            }
            Some(SshDirectoryPurpose::ProjectOpen) | None => SshModalOutcome::Changed,
        };
    }
    if matches!(&state.page, SshModalPage::ConfirmDelete(_)) {
        state.return_to_manager();
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
    let grant_cancellation = match &state.page {
        SshModalPage::Manager => state
            .pending_grant
            .as_ref()
            .map(|request| request.request_id.clone()),
        SshModalPage::Grant(card) => Some(card.request_id.clone()),
        SshModalPage::Add(_)
        | SshModalPage::ConfirmDelete(_)
        | SshModalPage::ProjectBrowser
        | SshModalPage::OperationApproval(_)
        | SshModalPage::WorkerInstallFallback(_)
        | SshModalPage::Authentication(_)
        | SshModalPage::Diagnostic(_) => None,
    };
    if let Some(request_id) = grant_cancellation {
        return cancel_grant_once(state, request_id);
    }
    match &state.page {
        SshModalPage::Manager => SshModalOutcome::Close,
        SshModalPage::OperationApproval(card) => SshModalOutcome::ApproveOperation {
            approval_id: card.approval_id.clone(),
            approved: false,
            scope: SshOperationApprovalScope::Once,
        },
        SshModalPage::Grant(_) => {
            unreachable!("grant denial was handled before read-only match")
        }
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
        SshModalPage::ConfirmDelete(_) => {
            unreachable!("delete confirmation returned before read-only match")
        }
        SshModalPage::Diagnostic(_) => unreachable!("diagnostic returned before read-only match"),
    }
}

fn begin_grant_flow(
    state: &mut SshManagerState,
    follow_up: Option<SshGrantFollowUp>,
) -> SshModalOutcome {
    if let Some(request) = state.pending_grant.as_ref().cloned() {
        let Some(target_id) = request
            .target_id
            .clone()
            .or_else(|| state.selected_target().map(|target| target.target_id.clone()))
        else {
            state.show_info(
                "Select an SSH target, then press Enter to choose a folder for this request.",
            );
            return SshModalOutcome::Changed;
        };
        if request
            .root
            .as_deref()
            .map_or(true, |root| root.trim().is_empty())
        {
            return state.begin_directory_browser(
                target_id,
                None,
                SshDirectoryPurpose::PendingGrant {
                    request_id: request.request_id,
                },
            );
        }
        if request.verified_identity.is_none() {
            if state
                .inspecting_grant_ids
                .iter()
                .any(|id| id == &request.request_id)
            {
                return SshModalOutcome::Unchanged;
            }
            state.inspecting_grant_ids.push(request.request_id.clone());
            return SshModalOutcome::InspectGrantTarget {
                request_id: request.request_id,
                target_id,
                selected_root: None,
                expected_identity: None,
            };
        }
        return SshModalOutcome::Changed;
    }

    let Some(target_id) = state.selected_target().map(|target| target.target_id.clone()) else {
        state.show_error("Select an SSH target before starting an access grant.");
        return SshModalOutcome::Changed;
    };
    if state.session_id.is_none() {
        state.show_error("Open or create a session before granting SSH access.");
        return SshModalOutcome::Changed;
    }
    state.begin_directory_browser(
        target_id,
        None,
        SshDirectoryPurpose::LocalGrant { follow_up },
    )
}
fn open_target_edit(state: &mut SshManagerState) -> SshModalOutcome {
    let Some((target, connected, read_only_message)) = state.selected_target().map(|target| {
        (
            target.is_manual().then(|| target.target.clone()),
            target.connected,
            target.read_only_message(),
        )
    }) else {
        state.show_info("Select an SSH target to edit.");
        return SshModalOutcome::Changed;
    };
    if let Some(target) = target {
        state.page = SshModalPage::Add(SshManualTargetForm::editing(target));
    } else if let Some(message) = read_only_message {
        state.page = SshModalPage::Diagnostic(SshDiagnosticCard::details(message, connected, None));
    }
    SshModalOutcome::Changed
}

fn open_target_delete(state: &mut SshManagerState) -> SshModalOutcome {
    let Some((target, target_id, connected, read_only_message)) = state.selected_target().map(|target| {
        (
            target.is_manual().then(|| target.target.clone()),
            target.target_id.clone(),
            target.connected,
            target.read_only_message(),
        )
    }) else {
        state.show_info("Select an SSH target to delete.");
        return SshModalOutcome::Changed;
    };
    if let Some(target) = target {
        let has_active_grants = state.targets.iter().any(|view| {
            view.target_id == target_id
                && matches!(
                    &view.grant,
                    SshGrantView::Granted { .. } | SshGrantView::Revoking { .. }
                )
        });
        state.page = SshModalPage::ConfirmDelete(SshDeleteConfirmation::new(
            target,
            connected,
            has_active_grants,
        ));
    } else if let Some(message) = read_only_message {
        state.page = SshModalPage::Diagnostic(SshDiagnosticCard::details(message, connected, None));
    }
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
        KeyCode::Char('e') if key.modifiers.is_empty() => open_target_edit(state),
        KeyCode::Char('x') if key.modifiers.is_empty() => open_target_delete(state),
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
            if state.is_prompt_picker() {
                state.clear_pending_prompt_target();
                state.pending_target_reference = None;
                SshModalOutcome::Refresh
            } else {
                SshModalOutcome::Changed
            }
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
        KeyCode::Enter if key.modifiers.is_empty() => {
            if state.pending_grant.is_some() {
                return begin_grant_flow(state, None);
            }
            if state.is_prompt_picker() && !state.manager_advanced {
                return state.select_prompt_target();
            }
            if state.session_id.is_some() {
                return state
                    .selected_active_binding_id()
                    .map(|binding_id| SshModalOutcome::UseBinding {
                        binding_id: binding_id.to_owned(),
                    })
                    .unwrap_or_else(|| begin_grant_flow(state, Some(SshGrantFollowUp::UseBinding)));
            }
            match state.selected_target() {
                Some(target) if target.connected => {
                    state.show_info("Connected. Use /ssh in a chat to authorize SSH tools without a worker; o opens a remote project with a worker.");
                    SshModalOutcome::Changed
                }
                Some(target) => SshModalOutcome::Connect {
                    target_id: target.target_id.clone(),
                },
                None => {
                    state.show_info("Select an SSH target to connect.");
                    SshModalOutcome::Changed
                }
            }
        }
        KeyCode::Char('o') if key.modifiers.is_empty() => {
            // A model's pending access request must remain an access flow, never become a project.
            if state.pending_grant.is_some() {
                return begin_grant_flow(state, None);
            }
            let Some(target_id) = state.selected_target().map(|target| target.target_id.clone())
            else {
                state.show_info("Select an SSH target before opening a remote project.");
                return SshModalOutcome::Changed;
            };
            state.begin_project_browser(target_id, None)
        }
        KeyCode::Char('g')
            if key.modifiers.is_empty() && state.session_id.is_some() =>
        {
            begin_grant_flow(state, None)
        }
        KeyCode::Char('p')
            if key.modifiers.is_empty()
                && state.manager_advanced
                && state.session_id.is_some() =>
        {
            state
                .selected_active_binding_id()
                .map(|binding_id| SshModalOutcome::ResetOperationApprovals {
                    binding_id: binding_id.to_owned(),
                })
                .unwrap_or(SshModalOutcome::Unchanged)
        }
        KeyCode::Char('r') if key.modifiers.is_empty() && state.manager_advanced => {
            if state.session_id.is_none() {
                return SshModalOutcome::Refresh;
            }
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
        KeyCode::Char('u')
            if key.modifiers.is_empty()
                && state.manager_advanced
                && state.session_id.is_some() =>
        {
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
            let picker_request_id = next_nonzero_id(&NEXT_PROJECT_DIRECTORY_REQUEST_ID);
            let Some((purpose, target_id, root, identity)) = ({
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
                browser.open_request_id = Some(picker_request_id);
                browser.preparing = true;
                browser.notice = Some(
                    match &browser.purpose {
                        SshDirectoryPurpose::ProjectOpen => "Opening this folder…",
                        SshDirectoryPurpose::LocalGrant { .. }
                        | SshDirectoryPurpose::PendingGrant { .. } => {
                            "Checking this folder for an access grant…"
                        }
                    }
                    .into(),
                );
                Some((
                    browser.purpose.clone(),
                    browser.target_id.clone(),
                    root,
                    identity,
                ))
            }) else {
                return SshModalOutcome::Unchanged;
            };
            match purpose {
                SshDirectoryPurpose::ProjectOpen => SshModalOutcome::ChooseProjectDirectory {
                    request_id: picker_request_id,
                    target_id,
                    root,
                    identity,
                },
                SshDirectoryPurpose::LocalGrant { follow_up } => {
                    state.local_grant_options = Some(LocalGrantOptions {
                        request_id: None,
                        target_id: target_id.clone(),
                        root: root.clone(),
                        capabilities: SshCapabilitiesView::default(),
                        lifetime: SshGrantLifetime::CurrentSession,
                        set_default: false,
                    });
                    state.pending_grant_follow_up = follow_up;
                    SshModalOutcome::RequestGrant {
                        target_id,
                        root,
                        capabilities: SshCapabilitiesView {
                            read: true,
                            write: true,
                            execute: true,
                        },
                        lifetime: SshGrantLifetime::CurrentSession,
                        set_default: false,
                    }
                }
                SshDirectoryPurpose::PendingGrant { request_id } => {
                    if !state.inspecting_grant_ids.iter().any(|id| id == &request_id) {
                        state.inspecting_grant_ids.push(request_id.clone());
                    }
                    SshModalOutcome::InspectGrantTarget {
                        request_id,
                        target_id,
                        selected_root: Some(root),
                        expected_identity: Some(identity),
                    }
                }
            }
        }
        _ => SshModalOutcome::Unchanged,
    }
}

fn handle_delete_key(state: &mut SshManagerState, key: &KeyEvent) -> SshModalOutcome {
    match key.code {
        KeyCode::Esc if key.modifiers.is_empty() => {
            state.return_to_manager();
            SshModalOutcome::Changed
        }
        KeyCode::Enter if key.modifiers.is_empty() => {
            let SshModalPage::ConfirmDelete(card) = &mut state.page else {
                return SshModalOutcome::Unchanged;
            };
            if card.submitting {
                return SshModalOutcome::Unchanged;
            }
            let expected = card.expected.clone();
            let submission_id = card.start_submit();
            SshModalOutcome::RemoveTarget {
                expected,
                submission_id,
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
            Ok(TargetFormSubmission::Add {
                draft,
                submission_id,
            }) => SshModalOutcome::AddTarget {
                draft,
                submission_id,
            },
            Ok(TargetFormSubmission::Update {
                expected,
                replacement,
                submission_id,
            }) => SshModalOutcome::UpdateTarget {
                expected,
                replacement,
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
        SshGrantFocus::Read if card.capability_is_requested(SshGrantFocus::Read) => {
            card.capabilities.read = !card.capabilities.read
        }
        SshGrantFocus::Write if card.capability_is_requested(SshGrantFocus::Write) => {
            card.capabilities.write = !card.capabilities.write
        }
        SshGrantFocus::Execute if card.capability_is_requested(SshGrantFocus::Execute) => {
            card.capabilities.execute = !card.capabilities.execute
        }
        SshGrantFocus::Read | SshGrantFocus::Write | SshGrantFocus::Execute => {}
        SshGrantFocus::Lifetime => card.lifetime = card.lifetime.toggle(),
        SshGrantFocus::Default if card.follow_up.is_none() => {
            card.set_default = !card.set_default;
        }
        SshGrantFocus::Default => {}
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

fn explicit_grant_denial(card: &SshGrantCard) -> SshModalOutcome {
    SshModalOutcome::ApproveGrant {
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
    }
}

fn handle_grant_key(card: &mut SshGrantCard, key: &KeyEvent) -> SshModalOutcome {
    match key.code {
        KeyCode::Esc => SshModalOutcome::CancelGrant {
            request_id: card.request_id.clone(),
        },
        KeyCode::Char('n')
            if key.modifiers.is_empty()
                && (card.focus != SshGrantFocus::Root || card.verified_root) =>
        {
            explicit_grant_denial(card)
        }
        KeyCode::Char('d') if key.modifiers == KeyModifiers::CONTROL => {
            explicit_grant_denial(card)
        }
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
            if key.modifiers == KeyModifiers::ALT
                && !card.is_project_consent()
                && card.follow_up.is_none() =>
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
            if !card.reviewed_to_end {
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
        _ if card.focus == SshGrantFocus::Root && !card.verified_root => {
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
            scroll_operation_approval(card, -1)
        }
        KeyCode::Down | KeyCode::Char('j') if key.modifiers.is_empty() => {
            scroll_operation_approval(card, 1)
        }
        KeyCode::PageUp if key.modifiers.is_empty() => {
            scroll_operation_approval(card, -(card.page_size as isize))
        }
        KeyCode::PageDown if key.modifiers.is_empty() => {
            scroll_operation_approval(card, card.page_size as isize)
        }
        KeyCode::Home if key.modifiers.is_empty() => {
            card.scroll_offset = 0;
            card.error = None;
            SshModalOutcome::Changed
        }
        KeyCode::End if key.modifiers.is_empty() => {
            card.scroll_offset = card.max_scroll_offset;
            card.reviewed_to_end = true;
            card.error = None;
            SshModalOutcome::Changed
        }
        KeyCode::Char('d') if key.modifiers.is_empty() => {
            card.raw_details = !card.raw_details;
            card.error = None;
            SshModalOutcome::Changed
        }
        KeyCode::Char('c') if key.modifiers.is_empty() => {
            card.copy_status = Some(match operation_detail_string(&card.detail, &["command"]) {
                Some(command) if card.operation == SshOperation::Execute => {
                    match crate::clipboard::SystemClipboard::try_set(command) {
                        crate::clipboard::ClipboardDelivery::Confirmed => "Command copied.",
                        crate::clipboard::ClipboardDelivery::Unverified => "Copy sent; terminal clipboard delivery is unverified.",
                        crate::clipboard::ClipboardDelivery::Failed => "Command copy failed.",
                    }
                }
                _ => "This operation has no command to copy.",
            });
            SshModalOutcome::Changed
        }
        KeyCode::Char('y') if key.modifiers.is_empty() => {
            approve_operation(card, SshOperationApprovalScope::Once)
        }
        KeyCode::Char('a') if key.modifiers.is_empty() && card.allows_session() => {
            approve_operation(card, SshOperationApprovalScope::Session)
        }
        KeyCode::Char('n') if key.modifiers.is_empty() => SshModalOutcome::ApproveOperation {
            approval_id: card.approval_id.clone(),
            approved: false,
            scope: SshOperationApprovalScope::Once,
        },
        KeyCode::Esc => SshModalOutcome::ApproveOperation {
            approval_id: card.approval_id.clone(),
            approved: false,
            scope: SshOperationApprovalScope::Once,
        },
        _ => SshModalOutcome::Unchanged,
    }
}

fn scroll_operation_approval(card: &mut SshOperationApprovalCard, delta: isize) -> SshModalOutcome {
    let next = if delta.is_negative() {
        card.scroll_offset.saturating_sub(delta.unsigned_abs())
    } else {
        card.scroll_offset
            .saturating_add(delta as usize)
            .min(card.max_scroll_offset)
    };
    card.scroll_offset = next;
    card.reviewed_to_end |= card.max_scroll_offset == 0 || next >= card.max_scroll_offset;
    card.error = None;
    card.copy_status = None;
    SshModalOutcome::Changed
}

fn approve_operation(
    card: &mut SshOperationApprovalCard,
    scope: SshOperationApprovalScope,
) -> SshModalOutcome {
    if !card.reviewed_to_end {
        card.error = Some("Review all remote operation details before allowing it.".into());
        return SshModalOutcome::Changed;
    }
    SshModalOutcome::ApproveOperation {
        approval_id: card.approval_id.clone(),
        approved: true,
        scope,
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
            card.reveal_answer = true;
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
                remember: card.can_remember() && card.remember,
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
            serde_json::json!({
                "target_id": "target-1",
                "root": "/srv/project",
                "cwd": "/srv/project",
                "args": {"command": "printf 'approved\\n'"},
            }),
            SshOperation::Execute,
        )
    }

    fn root_approval(id: &str) -> SshOperationApprovalCard {
        SshOperationApprovalCard::new(
            id.into(),
            "binding-1".into(),
            "target-1".into(),
            Some("build@host:22 (SHA256:test)".into()),
            "Run root operation".into(),
            serde_json::json!({
                "root": "/srv/project",
                "cwd": "/srv/project/scripts",
                "args": {"command": "id -u", "sudo": true},
            }),
            SshOperation::Execute,
        )
        .with_allow_session(false)
        .with_operation_id(format!("operation-{id}"))
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
        state.visible = false;
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
    fn successful_operation_approval_dismisses_every_origin() {
        for approval_id in ["explicit", "transient"] {
            let mut state = SshManagerState::new(Some("session-1".into()));
            state.show_operation_approval(approval(approval_id));
            assert!(state.submit_operation_approval(approval_id, true));

            assert_eq!(
                state.settle_operation_approval(approval_id, None),
                SshOperationApprovalSettlement::Dismiss,
            );
        }
    }

    #[test]
    fn denied_operation_keeps_a_visible_result() {
        let mut state = SshManagerState::new(Some("session-1".into()));
        state.show_operation_approval(approval("approval-1"));
        assert!(state.submit_operation_approval("approval-1", false));

        assert_eq!(
            state.settle_operation_approval("approval-1", None),
            SshOperationApprovalSettlement::KeepVisible,
        );
        assert!(matches!(&state.page, SshModalPage::Manager));
        assert!(state.message.is_some());
    }

    #[test]
    fn stale_completion_cannot_hide_a_newer_operation_or_its_submission_error() {
        let mut state = SshManagerState::new(Some("session-1".into()));
        state.show_operation_approval(approval("approval-1"));
        assert!(state.submit_operation_approval("approval-1", true));

        state.show_operation_approval(approval("approval-2"));
        assert_eq!(
            state.settle_operation_approval("approval-1", None),
            SshOperationApprovalSettlement::KeepVisible,
        );
        assert!(matches!(
            &state.page,
            SshModalPage::OperationApproval(card) if card.approval_id == "approval-2"
        ));

        assert!(state.submit_operation_approval("approval-2", true));
        assert_eq!(
            state.settle_operation_approval("approval-2", Some("local control unavailable".into())),
            SshOperationApprovalSettlement::KeepVisible,
        );
        assert!(matches!(
            &state.page,
            SshModalPage::OperationApproval(card)
                if card.approval_id == "approval-2"
                    && !card.submitting
                    && card.error.as_deref() == Some("local control unavailable")
        ));
    }

    #[test]
    fn expired_operation_retires_the_card_without_sending_a_stale_denial() {
        let mut state = SshManagerState::new(Some("session-1".into()));
        state.show_operation_approval(approval("expired-approval"));
        assert!(state.submit_operation_approval("expired-approval", true));

        assert!(state.expire_operation_approval("expired-approval"));
        assert!(matches!(&state.page, SshModalPage::Manager));
        let area = Rect::new(0, 0, 64, 12);
        let mut buffer = Buffer::empty(area);
        render_ssh_modal(&mut buffer, area, &mut state, false, &Theme::current());
        assert!(matches!(
            handle_ssh_key(&mut state, &key(KeyCode::Char('y'))),
            SshModalOutcome::Unchanged
        ));
        assert!(matches!(
            handle_ssh_key(&mut state, &key(KeyCode::Char('n'))),
            SshModalOutcome::Unchanged
        ));
        assert!(matches!(
            handle_ssh_key(&mut state, &key(KeyCode::Esc)),
            SshModalOutcome::Close
        ));

        state.show_operation_approval(approval("fresh-approval"));
        assert!(matches!(
            handle_ssh_key(&mut state, &key(KeyCode::End)),
            SshModalOutcome::Changed
        ));
        assert!(matches!(
            handle_ssh_key(&mut state, &key(KeyCode::Char('y'))),
            SshModalOutcome::ApproveOperation { approval_id, approved: true, .. }
                if approval_id == "fresh-approval"
        ));
    }

    #[test]
    fn stale_operation_expiration_does_not_clobber_a_newer_card() {
        let mut state = SshManagerState::new(Some("session-1".into()));
        state.show_operation_approval(approval("old-approval"));
        assert!(state.submit_operation_approval("old-approval", true));
        state.show_operation_approval(approval("new-approval"));

        assert!(!state.expire_operation_approval("old-approval"));
        assert!(state.submit_operation_approval("new-approval", true));
    }

    #[test]
    fn operation_approval_colours_warnings_errors_and_instructions_differently() {
        let theme = Theme::current();
        let area = Rect::new(0, 0, 160, 40);
        let mut card = approval("colours");
        card.error = Some("local SSH control is unavailable".into());
        let mut buffer = Buffer::empty(area);
        render_operation_approval(&mut buffer, area, &mut card, &theme);
        let foreground_for_text = |text: &str| {
            (0..area.height).find_map(|row| {
                let start = row as usize * area.width as usize;
                let end = start + area.width as usize;
                let rendered: String = buffer.content[start..end]
                    .iter()
                    .map(|cell| cell.symbol())
                    .collect();
                rendered.find(text).map(|byte_index| {
                    let column = rendered[..byte_index].chars().count();
                    buffer.content[start + column].fg
                })
            })
        };

        assert_eq!(foreground_for_text("Warning:"), Some(theme.warning));
        assert_eq!(foreground_for_text("Error:"), Some(theme.accent_error));
        assert_eq!(foreground_for_text("After review:"), Some(theme.accent_user));
    }

    #[test]
    fn operation_preview_preserves_multiline_heredoc_and_exposes_raw_details() {
        let terminal_escape = char::from_u32(0x1b).expect("escape codepoint");
        let command = format!(
            "cat <<'EOF'\n$HOME is literal\nEOF\nprintf '{terminal_escape}[31mnot a terminal escape\\n'\n"
        );
        let card = SshOperationApprovalCard::new(
            "preview-1".into(),
            "binding-1".into(),
            "build host".into(),
            Some("builder@build.example.test:22 (SHA256:fixture)".into()),
            "Run deployment probe".into(),
            serde_json::json!({
                "target_id": "build-target",
                "identity": {
                    "username": "builder",
                    "hostname": "build.example.test",
                    "port": 22,
                    "fingerprint": "SHA256:fixture",
                },
                "root": "/srv/project",
                "cwd": "/srv/project/scripts",
                "args": {"command": command},
            }),
            SshOperation::Execute,
        );
        let mut state = SshManagerState::new(Some("session-1".into()));
        state.show_operation_approval(card);
        let area = Rect::new(0, 0, 72, 14);
        let mut frames = String::new();
        for _ in 0..128 {
            let mut buffer = Buffer::empty(area);
            render_ssh_modal(&mut buffer, area, &mut state, false, &Theme::current());
            frames.push_str(&buffer_text(&buffer));
            frames.push('\n');
            let at_end = matches!(
                &state.page,
                SshModalPage::OperationApproval(card)
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
        assert!(frames.contains("cat <<'EOF'"), "{frames}");
        assert!(frames.contains("$HOME is literal"), "{frames}");
        assert!(frames.contains("EOF"), "{frames}");
        assert!(frames.contains("Remote cwd: /srv/project/scripts"), "{frames}");
        assert!(!frames.contains('\u{1b}'), "{frames:?}");
        assert!(frames.contains("\\u{1b}"), "{frames}");

        assert!(matches!(
            handle_ssh_key(&mut state, &key(KeyCode::Home)),
            SshModalOutcome::Changed
        ));
        assert!(matches!(
            handle_ssh_key(&mut state, &key(KeyCode::Char('d'))),
            SshModalOutcome::Changed
        ));
        let mut raw_frames = String::new();
        loop {
            let mut buffer = Buffer::empty(area);
            render_ssh_modal(&mut buffer, area, &mut state, false, &Theme::current());
            raw_frames.push_str(&buffer_text(&buffer));
            if matches!(&state.page, SshModalPage::OperationApproval(card)
                if card.scroll_offset == card.max_scroll_offset)
            {
                break;
            }
            handle_ssh_key(&mut state, &key(KeyCode::PageDown));
        }
        assert!(raw_frames.contains("\"args\""), "{raw_frames}");
        assert!(raw_frames.contains("\"command\""), "{raw_frames}");
        assert!(raw_frames.contains("\\n$HOME"), "{raw_frames}");
    }

    #[test]
    fn operation_review_gate_scrolls_with_wheel_and_pages_without_losing_completion() {
        let mut command = String::new();
        for line in 0..48 {
            command.push_str(&format!("printf 'line-{line}\\n'\n"));
        }
        let card = SshOperationApprovalCard::new(
            "review-1".into(),
            "binding-1".into(),
            "build host".into(),
            None,
            "Run long script".into(),
            serde_json::json!({"args": {"command": command}}),
            SshOperation::Execute,
        );
        let mut state = SshManagerState::new(Some("session-1".into()));
        state.show_operation_approval(card);
        let area = Rect::new(0, 0, 64, 13);
        let mut buffer = Buffer::empty(area);
        render_ssh_modal(&mut buffer, area, &mut state, false, &Theme::current());

        assert!(matches!(
            handle_ssh_key(&mut state, &key(KeyCode::Char('y'))),
            SshModalOutcome::Changed
        ));
        assert!(matches!(
            &state.page,
            SshModalPage::OperationApproval(card) if card.error.is_some()
        ));

        assert!(matches!(
            handle_ssh_mouse(
                &mut state,
                &MouseEvent {
                    kind: MouseEventKind::ScrollDown,
                    column: 32,
                    row: 6,
                    modifiers: KeyModifiers::NONE,
                },
            ),
            SshModalOutcome::Changed
        ));
        let before_page = match &state.page {
            SshModalPage::OperationApproval(card) => card.scroll_offset,
            _ => panic!("operation approval must remain displayed"),
        };
        assert!(matches!(
            handle_ssh_key(&mut state, &key(KeyCode::PageDown)),
            SshModalOutcome::Changed
        ));
        assert!(matches!(
            &state.page,
            SshModalPage::OperationApproval(card) if card.scroll_offset >= before_page
        ));
        assert!(matches!(
            handle_ssh_key(&mut state, &key(KeyCode::End)),
            SshModalOutcome::Changed
        ));
        assert!(matches!(
            handle_ssh_key(&mut state, &key(KeyCode::Up)),
            SshModalOutcome::Changed
        ));
        assert!(matches!(
            &state.page,
            SshModalPage::OperationApproval(card) if card.reviewed_to_end
        ));
        assert!(matches!(
            handle_ssh_key(&mut state, &key(KeyCode::Char('y'))),
            SshModalOutcome::ApproveOperation {
                approved: true,
                scope: SshOperationApprovalScope::Once,
                ..
            }
        ));

        state.show_operation_approval(approval("review-2"));
        assert!(matches!(
            &state.page,
            SshModalPage::OperationApproval(card)
                if !card.reviewed_to_end && !card.raw_details && card.scroll_offset == 0
        ));
        let mut buffer = Buffer::empty(area);
        render_ssh_modal(&mut buffer, area, &mut state, false, &Theme::current());
        assert!(matches!(
            handle_ssh_key(&mut state, &key(KeyCode::End)),
            SshModalOutcome::Changed
        ));
        let mut buffer = Buffer::empty(area);
        render_ssh_modal(&mut buffer, area, &mut state, false, &Theme::current());
        let session_allow = state
            .window
            .shortcut_hits
            .iter()
            .find(|hit| hit.id == FOOTER_OPERATION_ALLOW_SESSION)
            .expect("session approval footer is rendered")
            .rect;
        assert!(matches!(
            handle_ssh_mouse(
                &mut state,
                &MouseEvent {
                    kind: MouseEventKind::Down(crossterm::event::MouseButton::Left),
                    column: session_allow.x,
                    row: session_allow.y,
                    modifiers: KeyModifiers::NONE,
                },
            ),
            SshModalOutcome::ApproveOperation {
                approved: true,
                scope: SshOperationApprovalScope::Session,
                ..
            }
        ));
    }

    #[test]
    fn root_operation_only_allows_once_from_keyboard_or_footer() {
        let area = Rect::new(0, 0, 96, 24);
        let mut keyboard = SshManagerState::new(Some("session-1".into()));
        keyboard.show_operation_approval(root_approval("root-keyboard"));
        let mut buffer = Buffer::empty(area);
        render_ssh_modal(&mut buffer, area, &mut keyboard, false, &Theme::current());
        assert!(matches!(
            handle_ssh_key(&mut keyboard, &key(KeyCode::End)),
            SshModalOutcome::Changed
        ));
        assert!(matches!(
            handle_ssh_key(&mut keyboard, &key(KeyCode::Char('a'))),
            SshModalOutcome::Unchanged
        ));
        assert!(matches!(
            handle_ssh_key(&mut keyboard, &key(KeyCode::Char('y'))),
            SshModalOutcome::ApproveOperation {
                approved: true,
                scope: SshOperationApprovalScope::Once,
                ..
            }
        ));

        let mut mouse = SshManagerState::new(Some("session-1".into()));
        mouse.show_operation_approval(root_approval("root-mouse"));
        let mut buffer = Buffer::empty(area);
        render_ssh_modal(&mut buffer, area, &mut mouse, false, &Theme::current());
        assert!(matches!(
            handle_ssh_key(&mut mouse, &key(KeyCode::End)),
            SshModalOutcome::Changed
        ));
        let mut buffer = Buffer::empty(area);
        render_ssh_modal(&mut buffer, area, &mut mouse, false, &Theme::current());
        assert!(!mouse
            .window
            .shortcut_hits
            .iter()
            .any(|hit| hit.id == FOOTER_OPERATION_ALLOW_SESSION));
        let allow_once = mouse
            .window
            .shortcut_hits
            .iter()
            .find(|hit| hit.id == FOOTER_OPERATION_ALLOW)
            .expect("root footer keeps one-time approval")
            .rect;
        assert!(matches!(
            handle_ssh_mouse(
                &mut mouse,
                &MouseEvent {
                    kind: MouseEventKind::Down(crossterm::event::MouseButton::Left),
                    column: allow_once.x,
                    row: allow_once.y,
                    modifiers: KeyModifiers::NONE,
                },
            ),
            SshModalOutcome::ApproveOperation {
                approved: true,
                scope: SshOperationApprovalScope::Once,
                ..
            }
        ));
    }

    #[test]
    fn root_password_keeps_input_hidden_and_never_remembered() {
        let mut card = SshAuthCard::new(
            "sudo-challenge".into(),
            7,
            "target-1".into(),
            SshAuthKind::SudoPassword {
                username: "build".into(),
                message: "Root password required".into(),
            },
        );
        assert!(!card.can_remember());
        assert!(matches!(
            handle_authentication_key(
                &mut card,
                &KeyEvent::new(KeyCode::Char('r'), KeyModifiers::ALT)
            ),
            SshModalOutcome::Unchanged
        ));
        assert!(!card.remember);
        assert!(matches!(
            handle_authentication_key(&mut card, &key(KeyCode::Char('x'))),
            SshModalOutcome::Changed
        ));
        let rendered = authentication_lines(&card, 100)
            .0
            .into_iter()
            .map(|(line, _)| line)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!rendered.contains('x'));
        assert!(matches!(
            handle_authentication_key(&mut card, &key(KeyCode::Enter)),
            SshModalOutcome::AnswerAuthentication {
                remember: false,
                secret: Some(_),
                answers,
                ..
            } if answers.is_empty()
        ));
    }

    #[test]
    fn sudo_prompt_and_resolution_require_the_original_scope() {
        let mut state = SshManagerState::new(Some("session-1".into()));
        state.show_operation_approval(root_approval("root-operation"));
        assert!(state.submit_operation_approval("root-operation", true));
        let sudo_card = || {
            SshAuthCard::new(
                "sudo-challenge".into(),
                9,
                "target-1".into(),
                SshAuthKind::SudoPassword {
                    username: "build".into(),
                    message: "Root password required".into(),
                },
            )
        };

        assert!(!state.show_sudo_authentication(
            7,
            "other-session",
            "operation-root-operation",
            sudo_card(),
        ));
        assert!(!state.show_sudo_authentication(7, "session-1", "other-operation", sudo_card()));
        assert!(state.show_sudo_authentication(
            7,
            "session-1",
            "operation-root-operation",
            sudo_card(),
        ));
        state.apply_target_status("target-1", SshConnectionState::Connected, None);
        assert!(matches!(
            &state.page,
            SshModalPage::Authentication(card) if card.challenge_id == "sudo-challenge"
        ));
        assert!(!state.resolve_sudo_authentication(
            8,
            "session-1",
            "sudo-challenge",
            Some("ignored".into()),
        ));
        assert!(!state.resolve_sudo_authentication(
            7,
            "other-session",
            "sudo-challenge",
            Some("ignored".into()),
        ));
        assert!(matches!(
            &state.page,
            SshModalPage::Authentication(card) if card.challenge_id == "sudo-challenge"
        ));

        state.show_operation_approval(approval("new-operation"));
        assert!(!state.resolve_sudo_authentication(
            7,
            "session-1",
            "sudo-challenge",
            Some("late".into()),
        ));
        assert!(matches!(
            &state.page,
            SshModalPage::OperationApproval(card) if card.approval_id == "new-operation"
        ));
    }

    #[test]
    fn root_approval_hides_until_its_exact_password_challenge_then_returns_to_chat() {
        let mut state = SshManagerState::new(Some("session-1".into()));
        state.show_operation_approval(root_approval("root-operation"));
        assert!(state.submit_operation_approval("root-operation", true));

        assert_eq!(
            state.settle_operation_approval("root-operation", None),
            SshOperationApprovalSettlement::AwaitingSudoAuthentication,
        );
        assert!(!state.is_visible(), "NOPASSWD must leave no server-list modal");

        let sudo_card = || {
            SshAuthCard::new(
                "sudo-challenge".into(),
                9,
                "target-1".into(),
                SshAuthKind::SudoPassword {
                    username: "build".into(),
                    message: "Root password required".into(),
                },
            )
        };
        assert!(!state.show_sudo_authentication(
            7,
            "session-1",
            "different-operation",
            sudo_card(),
        ));
        assert!(!state.is_visible());

        assert!(state.show_sudo_authentication(
            7,
            "session-1",
            "operation-root-operation",
            sudo_card(),
        ));
        assert!(state.is_visible());
        assert!(state.resolve_sudo_authentication(7, "session-1", "sudo-challenge", None));
        assert!(!state.is_visible());
    }

    #[test]
    fn advanced_reset_is_limited_to_the_selected_active_binding() {
        let mut state = SshManagerState::new(Some("session-1".into()));
        state.set_targets(vec![target_view("server-1", granted("binding-1", "/srv/project"))]);
        assert!(matches!(
            handle_ssh_key(&mut state, &key(KeyCode::Char('m'))),
            SshModalOutcome::Changed
        ));
        assert!(matches!(
            handle_ssh_key(&mut state, &key(KeyCode::Char('p'))),
            SshModalOutcome::ResetOperationApprovals { binding_id } if binding_id == "binding-1"
        ));
        let area = Rect::new(0, 0, 88, 20);
        let mut buffer = Buffer::empty(area);
        render_ssh_modal(&mut buffer, area, &mut state, false, &Theme::current());
        let reset = state
            .window
            .shortcut_hits
            .iter()
            .find(|hit| hit.id == FOOTER_MANAGER_RESET_OPERATION_APPROVALS)
            .expect("active binding renders reset footer")
            .rect;
        assert!(matches!(
            handle_ssh_mouse(
                &mut state,
                &MouseEvent {
                    kind: MouseEventKind::Down(crossterm::event::MouseButton::Left),
                    column: reset.x,
                    row: reset.y,
                    modifiers: KeyModifiers::NONE,
                },
            ),
            SshModalOutcome::ResetOperationApprovals { binding_id } if binding_id == "binding-1"
        ));

        state.set_targets(vec![target_view("server-1", SshGrantView::NotGranted)]);
        let mut buffer = Buffer::empty(area);
        render_ssh_modal(&mut buffer, area, &mut state, false, &Theme::current());
        assert!(!state
            .window
            .shortcut_hits
            .iter()
            .any(|hit| hit.id == FOOTER_MANAGER_RESET_OPERATION_APPROVALS));
        assert!(matches!(
            handle_ssh_key(&mut state, &key(KeyCode::Char('p'))),
            SshModalOutcome::Unchanged
        ));
    }


    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn direct_ssh_name_waits_for_session_then_authorizes_once() {
        let mut state = SshManagerState::new(None);
        state.queue_target_reference("server-1 label".into());
        state.set_targets(vec![target_view("server-1", SshGrantView::NotGranted)]);
        assert!(matches!(state.continue_target_reference(), SshModalOutcome::Unchanged));
        state.session_id = Some("session-1".into());
        assert!(matches!(
            state.continue_target_reference(),
            SshModalOutcome::BrowseProjectDirectory { target_id, .. } if target_id == "server-1"
        ));
        assert!(matches!(state.continue_target_reference(), SshModalOutcome::Unchanged));
    }

    #[test]
    fn direct_ssh_selection_reuses_only_an_unambiguous_binding() {
        let mut state = SshManagerState::new(Some("session-1".into()));
        state.set_targets(vec![target_view("server-1", granted("binding-1", "/a"))]);
        state.queue_target_reference("server-1".into());
        assert!(matches!(
            state.continue_target_reference(),
            SshModalOutcome::UseBinding { binding_id } if binding_id == "binding-1"
        ));
        state.set_targets(vec![
            target_view("server-1", granted("binding-1", "/a")),
            target_view("server-1", granted("binding-2", "/b")),
        ]);
        state.queue_target_reference("server-1".into());
        assert!(matches!(state.continue_target_reference(), SshModalOutcome::Changed));
        assert!(state.project_browser.is_none());
        assert!(state.message.as_ref().unwrap().0.contains("multiple access bindings"));
    }

    #[test]
    fn direct_ssh_selection_never_guesses_missing_or_duplicate_names() {
        let mut state = SshManagerState::new(Some("session-1".into()));
        let first = target_view("server-1", SshGrantView::NotGranted);
        let mut second = target_view("server-2", SshGrantView::NotGranted);
        second.target.label = first.target.label.clone();
        state.set_targets(vec![target_view("unrelated", SshGrantView::NotGranted), first, second]);
        for name in ["server-1 label", "server"] {
            state.queue_target_reference(name.into());
            assert!(matches!(state.continue_target_reference(), SshModalOutcome::Changed));
            assert!(state.project_browser.is_none());
            assert!(matches!(state.page, SshModalPage::Manager));
            assert_eq!(
                state.targets.iter().map(|view| view.target_id.as_str()).collect::<Vec<_>>(),
                ["server-1", "server-2"],
            );
        }
        state.queue_target_reference("server-2".into());
        assert!(matches!(
            state.continue_target_reference(),
            SshModalOutcome::BrowseProjectDirectory { target_id, .. } if target_id == "server-2"
        ));
    }

    #[test]
    fn prompt_picker_connected_selection_never_uses_a_grant_or_starts_project_work() {
        let mut state = SshManagerState::for_prompt(Some("session-1".into()));
        let mut target = target_view("server-1", granted("binding-1", "/srv/project"));
        target.connected = true;
        state.set_targets(vec![target]);

        assert!(state.is_prompt_picker());
        assert!(matches!(
            handle_ssh_key(&mut state, &key(KeyCode::Enter)),
            SshModalOutcome::SelectPromptTarget { target_id } if target_id == "server-1"
        ));
        assert!(state.pending_grant.is_none());
        assert!(state.project_browser.is_none());
        assert_eq!(state.take_connected_prompt_target("server-1"), None);
    }

    #[test]
    fn prompt_picker_connect_completion_only_consumes_its_current_pending_target() {
        let mut state = SshManagerState::for_prompt(None);
        state.set_targets(vec![
            target_view("server-1", SshGrantView::NotGranted),
            target_view("server-2", SshGrantView::NotGranted),
        ]);

        assert!(matches!(
            handle_ssh_key(&mut state, &key(KeyCode::Enter)),
            SshModalOutcome::Connect { target_id } if target_id == "server-1"
        ));
        handle_ssh_key(&mut state, &key(KeyCode::Down));
        assert!(matches!(
            handle_ssh_key(&mut state, &key(KeyCode::Enter)),
            SshModalOutcome::Connect { target_id } if target_id == "server-2"
        ));

        state.apply_target_status("server-1", SshConnectionState::Failed, None);
        state.apply_target_status("server-2", SshConnectionState::Connected, None);
        assert_eq!(
            state.take_connected_prompt_target("server-2"),
            Some("server-2".into())
        );
    }

    #[test]
    fn prompt_picker_cancelled_or_failed_connection_cannot_select_later() {
        let mut state = SshManagerState::for_prompt(None);
        state.set_targets(vec![target_view("server-1", SshGrantView::NotGranted)]);

        assert!(matches!(
            handle_ssh_key(&mut state, &key(KeyCode::Enter)),
            SshModalOutcome::Connect { target_id } if target_id == "server-1"
        ));
        assert!(matches!(
            handle_ssh_key(&mut state, &key(KeyCode::Esc)),
            SshModalOutcome::Close
        ));
        state.apply_target_status("server-1", SshConnectionState::Connected, None);
        assert_eq!(state.take_connected_prompt_target("server-1"), None);

        state.apply_target_status("server-1", SshConnectionState::Disconnected, None);
        assert!(matches!(
            handle_ssh_key(&mut state, &key(KeyCode::Enter)),
            SshModalOutcome::Connect { target_id } if target_id == "server-1"
        ));
        state.apply_target_status("server-1", SshConnectionState::Failed, None);
        state.apply_target_status("server-1", SshConnectionState::Connected, None);
        assert_eq!(state.take_connected_prompt_target("server-1"), None);
    }

    #[test]
    fn prompt_picker_authentication_rejection_clears_pending_selection() {
        let mut state = SshManagerState::for_prompt(None);
        state.set_targets(vec![target_view("target-1", SshGrantView::NotGranted)]);
        assert!(matches!(
            handle_ssh_key(&mut state, &key(KeyCode::Enter)),
            SshModalOutcome::Connect { target_id } if target_id == "target-1"
        ));

        state.show_authentication(host_key_card("unknown", Vec::new(), false));
        assert!(matches!(
            handle_ssh_key(&mut state, &key(KeyCode::Char('n'))),
            SshModalOutcome::AnswerAuthentication { .. }
        ));
        state.apply_target_status("target-1", SshConnectionState::Connected, None);
        assert_eq!(state.take_connected_prompt_target("target-1"), None);
    }

    #[test]
    fn prompt_picker_resolves_sessionless_references_and_deduplicates_grant_rows() {
        let mut state = SshManagerState::for_prompt(None);
        let mut second_target = target_view("server-2", SshGrantView::NotGranted);
        second_target.label = "server-1 label".into();
        second_target.target.label = "server-1 label".into();
        state.set_targets(vec![
            target_view("server-1", granted("binding-1", "/a")),
            target_view("server-1", granted("binding-2", "/b")),
            second_target,
        ]);
        assert_eq!(
            state
                .targets
                .iter()
                .map(|target| target.target_id.as_str())
                .collect::<Vec<_>>(),
            ["server-1", "server-2"]
        );

        state.queue_target_reference("server-1".into());
        assert!(matches!(
            state.continue_target_reference(),
            SshModalOutcome::Connect { target_id } if target_id == "server-1"
        ));

        state.queue_target_reference("server-1 label".into());
        assert!(matches!(
            state.continue_target_reference(),
            SshModalOutcome::Changed
        ));
        assert_eq!(state.targets.len(), 2);
        assert!(state
            .message
            .as_ref()
            .is_some_and(|(message, _)| message.contains("Multiple matching servers")));
    }

    #[test]
    fn prompt_picker_advanced_mode_retains_each_existing_grant() {
        let mut state = SshManagerState::for_prompt(Some("session-1".into()));
        let targets = vec![
            target_view("server-1", granted("binding-1", "/a")),
            target_view("server-1", granted("binding-2", "/b")),
        ];
        state.set_targets(targets.clone());
        assert_eq!(state.targets.len(), 1);
        assert!(matches!(handle_ssh_key(&mut state, &key(KeyCode::Char('m'))),
            SshModalOutcome::Refresh));
        state.set_targets(targets.clone());
        state.selected = 1;
        assert!(matches!(handle_ssh_key(&mut state, &key(KeyCode::Enter)),
            SshModalOutcome::UseBinding { binding_id } if binding_id == "binding-2"));
        assert!(matches!(handle_ssh_key(&mut state, &key(KeyCode::Char('m'))),
            SshModalOutcome::Refresh));
        state.set_targets(targets);
        assert_eq!(state.targets.len(), 1);
    }

    fn target_view(target_id: &str, grant: SshGrantView) -> SshTargetView {
        let mut target = xai_grok_ssh::SshTarget::new(target_id);
        target.id = target_id.into();
        target.label = format!("{target_id} label");
        SshTargetView::from_target(
            target,
            "user@example.test:22".into(),
            false,
            "Disconnected.".into(),
            grant,
        )
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
    fn explicit_project_browser_uses_real_directory_rows_and_ignores_stale_navigation() {
        let mut state = SshManagerState::new(Some("source-session".into()));
        state.set_targets(vec![target_view("server-1", SshGrantView::NotGranted)]);
        let SshModalOutcome::BrowseProjectDirectory {
            request_id,
            target_id,
            path,
        } = handle_ssh_key(&mut state, &key(KeyCode::Char('o')))
        else {
            panic!("Explicit project action must begin the project folder browser");
        };
        assert_eq!(target_id, "server-1");
        assert_eq!(path, None);
        assert!(state.project_browser.as_ref().unwrap().purpose.is_project_open());
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
                awaiting_tool: false,
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
                awaiting_tool: false,
            },
            "project-session".into(),
        ));
        assert!(matches!(
            handle_ssh_key(
                &mut state,
                &KeyEvent::new(KeyCode::Char('d'), KeyModifiers::CONTROL),
            ),
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
    fn terminal_grant_cancellation_releases_project_preparation() {
        let mut state = SshManagerState::new(Some("source-session".into()));
        state.pending_project_open = Some(PendingProjectOpen {
            request_id: 7,
            session_id: "project-session".into(),
            target_id: "server-1".into(),
            original_root: "/srv/project".into(),
        });
        state.pending_grant = Some(SshIncomingGrant {
            request_id: "grant-request".into(),
            target_id: Some("server-1".into()),
            root: Some("/srv/project".into()),
            capabilities: SshCapabilitiesView::default(),
            verified_identity: Some("builder@build.example.test:22".into()),
            reason: "Open the selected project.".into(),
            awaiting_tool: false,
        });
        state.pending_grant_session_id = Some("project-session".into());
        let mut card = SshGrantCard::new(
            "grant-request".into(),
            "server-1".into(),
            "Build server".into(),
            Some("builder@build.example.test:22".into()),
            "/srv/project",
            None,
            false,
        );
        card.project = Some(SshProjectConsent {
            request_id: 7,
            canonical_root: "/srv/project".into(),
            remember: false,
        });
        state.page = SshModalPage::Grant(card);

        assert!(state.settle_grant_cancellation("grant-request"));
        assert_eq!(state.pending_project_open_tuple(), None);
        assert!(matches!(&state.page, SshModalPage::Manager));
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
        assert_eq!(state.pending_authentication_target_id(), Some("server-1"));
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
        assert_eq!(state.pending_authentication_target_id(), None);
        assert!(!state.finish_project_preparation(open_request, Some("late failure".into())));
    }

    #[test]
    fn advanced_use_grant_chooses_a_folder_then_preserves_typed_continuation() {
        let mut state = SshManagerState::new(Some("source-session".into()));
        state.set_targets(vec![target_view("server-1", SshGrantView::NotGranted)]);
        assert!(matches!(
            handle_ssh_key(&mut state, &key(KeyCode::Char('m'))),
            SshModalOutcome::Changed
        ));
        let SshModalOutcome::BrowseProjectDirectory { request_id, .. } =
            handle_ssh_key(&mut state, &key(KeyCode::Char('u')))
        else {
            panic!("advanced use must open the shared folder picker");
        };
        assert!(state.settle_project_directory(
            request_id,
            "server-1",
            Ok(directory_listing("server-1", "/home/builder", Some("/home"), &[])),
        ));
        assert!(matches!(
            handle_ssh_key(&mut state, &key(KeyCode::Char('o'))),
            SshModalOutcome::RequestGrant {
                root,
                capabilities: SshCapabilitiesView {
                    read: true,
                    write: true,
                    execute: true,
                },
                lifetime: SshGrantLifetime::CurrentSession,
                ..
            } if root == "/home/builder"
        ));
        assert!(state.bind_local_grant_request(
            "advanced-use-grant",
            Some("server-1"),
            Some("/home/builder"),
        ));
        assert!(matches!(
            state.show_incoming_grant(
                "source-session".into(),
                SshIncomingGrant {
                    request_id: "advanced-use-grant".into(),
                    target_id: Some("server-1".into()),
                    root: Some("/home/builder".into()),
                    capabilities: SshCapabilitiesView {
                        read: true,
                        write: true,
                        execute: true,
                    },
                    verified_identity: Some(
                        "builder@build.example.test:22 (SHA256:fixture)".into(),
                    ),
                    reason: "Open SSH access".into(),
                    awaiting_tool: false,
                },
            ),
            SshModalOutcome::Changed
        ));
        let SshModalPage::Grant(card) = &mut state.page else {
            panic!("verified grant expected");
        };
        assert_eq!(card.lifetime, SshGrantLifetime::CurrentSession);
        assert_eq!(card.root.text(), "/home/builder");
        assert!(card.capabilities.read);
        assert!(!card.capabilities.write);
        assert!(matches!(
            handle_grant_key(card, &KeyEvent::new(KeyCode::Char('w'), KeyModifiers::ALT)),
            SshModalOutcome::Changed
        ));
        assert!(card.capabilities.write);
        card.focus = SshGrantFocus::Lifetime;
        card.focus_next(false);
        assert_eq!(card.focus, SshGrantFocus::Read);
        handle_grant_key(card, &KeyEvent::new(KeyCode::Char('d'), KeyModifiers::ALT));
        assert_eq!(card.focus, SshGrantFocus::Read);
        assert!(!card.set_default);
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
    fn duplicate_candidate_labels_render_stable_identity_and_provenance() {
        let mut manual = target_view("manual-target", SshGrantView::NotGranted);
        manual.label = "Build".into();
        let mut imported = target_view("imported-alias", SshGrantView::NotGranted);
        imported.label = "Build".into();
        imported.target.source = xai_grok_ssh::TargetSource::Imported {
            path: std::path::PathBuf::from("/home/fixture/.ssh/config"),
            line: 42,
        };
        let mut state = SshManagerState::new(Some("session-1".into()));
        state.set_targets(vec![manual, imported]);
        let area = Rect::new(0, 0, 100, 24);
        let mut buffer = Buffer::empty(area);
        render_ssh_modal(&mut buffer, area, &mut state, false, &Theme::current());
        let visible = buffer_text(&buffer);
        assert!(visible.contains("manual-target"));
        assert!(visible.contains("imported-alias"));
        assert!(visible.contains(".ssh/config:42"));
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
            "request-1".into(),
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
    fn grant_root_editor_keeps_n_as_text_while_explicit_deny_remains_available() {
        let mut card = SshGrantCard::new(
            "request-1".into(),
            "target-1".into(),
            "Build host".into(),
            None,
            "/remote/root",
            None,
            false,
        );
        assert_eq!(card.focus, SshGrantFocus::Root);
        assert!(matches!(
            handle_grant_key(&mut card, &key(KeyCode::Char('n'))),
            SshModalOutcome::Changed
        ));
        assert_eq!(card.root.text(), "/remote/rootn");
        assert!(matches!(
            handle_grant_key(
                &mut card,
                &KeyEvent::new(KeyCode::Char('d'), KeyModifiers::CONTROL)
            ),
            SshModalOutcome::ApproveGrant {
                approved: false,
                ..
            }
        ));
        assert!(matches!(
            handle_grant_key(&mut card, &key(KeyCode::Esc)),
            SshModalOutcome::CancelGrant { request_id } if request_id == "request-1"
        ));
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
    fn advanced_grant_mouse_flow_uses_the_shared_picker() {
        let mut state = SshManagerState::new(Some("session-1".into()));
        state.set_targets(vec![target_view("server-1", SshGrantView::NotGranted)]);
        let area = Rect::new(0, 0, 100, 30);
        let theme = Theme::current();
        let left_click = |rect: Rect| MouseEvent {
            kind: MouseEventKind::Down(crossterm::event::MouseButton::Left),
            column: rect.x,
            row: rect.y,
            modifiers: KeyModifiers::NONE,
        };
        let mut buffer = Buffer::empty(area);
        render_ssh_modal(&mut buffer, area, &mut state, false, &theme);
        let advanced = state
            .window
            .shortcut_hits
            .iter()
            .find(|hit| hit.id == FOOTER_MANAGER_ADVANCED)
            .expect("advanced footer")
            .rect;
        assert!(matches!(
            handle_ssh_mouse(&mut state, &left_click(advanced)),
            SshModalOutcome::Changed
        ));
        let mut buffer = Buffer::empty(area);
        render_ssh_modal(&mut buffer, area, &mut state, false, &theme);
        let grant = state
            .window
            .shortcut_hits
            .iter()
            .find(|hit| hit.id == FOOTER_MANAGER_GRANT)
            .expect("advanced grant footer")
            .rect;
        let SshModalOutcome::BrowseProjectDirectory { request_id, .. } =
            handle_ssh_mouse(&mut state, &left_click(grant))
        else {
            panic!("mouse grant must open the shared picker");
        };
        assert!(state.settle_project_directory(
            request_id,
            "server-1",
            Ok(directory_listing("server-1", "/srv/grant", Some("/srv"), &[])),
        ));
        let mut buffer = Buffer::empty(area);
        render_ssh_modal(&mut buffer, area, &mut state, false, &theme);
        let use_folder = state
            .window
            .shortcut_hits
            .iter()
            .find(|hit| hit.id == FOOTER_BROWSER_OPEN)
            .expect("grant picker confirmation footer")
            .rect;
        assert!(matches!(
            handle_ssh_mouse(&mut state, &left_click(use_folder)),
            SshModalOutcome::RequestGrant { root, .. } if root == "/srv/grant"
        ));
    }

    #[test]
    fn grant_picker_error_restores_last_folder_and_allows_retry() {
        let mut state = SshManagerState::new(Some("source-session".into()));
        state.set_targets(vec![target_view("server-1", SshGrantView::NotGranted)]);
        handle_ssh_key(&mut state, &key(KeyCode::Char('m')));
        let SshModalOutcome::BrowseProjectDirectory { request_id, .. } =
            handle_ssh_key(&mut state, &key(KeyCode::Char('g')))
        else { panic!("grant directory picker expected") };
        state.settle_project_directory(request_id, "server-1",
            Ok(directory_listing("server-1", "/srv/project", Some("/srv"), &[])));
        handle_ssh_key(&mut state, &key(KeyCode::Char('/')));
        for character in "/missing".chars() {
            handle_ssh_key(&mut state, &key(KeyCode::Char(character)));
        }
        let SshModalOutcome::BrowseProjectDirectory { request_id, .. } =
            handle_ssh_key(&mut state, &key(KeyCode::Enter))
        else { panic!("manual path navigation expected") };
        state.settle_project_directory(request_id, "server-1", Err("directory missing".into()));
        assert!(matches!(&state.page, SshModalPage::Diagnostic(card) if card.return_browser));
        handle_ssh_key(&mut state, &key(KeyCode::Esc));
        assert!(matches!(handle_ssh_key(&mut state, &key(KeyCode::Char('o'))),
            SshModalOutcome::RequestGrant { root, .. } if root == "/srv/project"));
    }

    #[test]
    fn rootless_incoming_picker_inspects_original_request_and_cancellation_stays_terminal() {
        let mut state = SshManagerState::new(Some("manager-session".into()));
        state.set_targets(vec![target_view("server-1", SshGrantView::NotGranted)]);
        let SshModalOutcome::BrowseProjectDirectory { request_id, .. } =
            state.show_incoming_grant(
                "source-session".into(),
                SshIncomingGrant {
                    request_id: "incoming-rootless".into(),
                    target_id: Some("server-1".into()),
                    root: None,
                    capabilities: SshCapabilitiesView::default(),
                    verified_identity: None,
                    reason: "Inspect a remote checkout.".into(),
                    awaiting_tool: false,
                },
            )
        else {
            panic!("rootless request must open the shared picker");
        };
        assert!(state.settle_project_directory(
            request_id,
            "server-1",
            Ok(directory_listing("server-1", "/srv/checkout", Some("/srv"), &[])),
        ));
        assert!(matches!(
            handle_ssh_key(&mut state, &key(KeyCode::Char('o'))),
            SshModalOutcome::InspectGrantTarget {
                request_id,
                target_id,
                selected_root: Some(root),
                expected_identity: Some(identity),
            } if request_id == "incoming-rootless"
                && target_id == "server-1"
                && root == "/srv/checkout"
                && identity == remote_identity()
        ));
        assert!(matches!(
            handle_ssh_key(&mut state, &key(KeyCode::Esc)),
            SshModalOutcome::CancelGrant { request_id }
                if request_id == "incoming-rootless"
        ));
        assert_eq!(
            state.grant_session_id_for("incoming-rootless").as_deref(),
            Some("source-session")
        );
        assert!(!state.settle_project_directory(
            request_id,
            "server-1",
            Ok(directory_listing("server-1", "/srv/late", Some("/srv"), &[])),
        ));
        assert!(matches!(
            state.show_incoming_grant(
                "source-session".into(),
                SshIncomingGrant {
                    request_id: "incoming-rootless".into(),
                    target_id: Some("server-1".into()),
                    root: Some("/srv/checkout".into()),
                    capabilities: SshCapabilitiesView::default(),
                    verified_identity: Some("builder@build.example.test:22".into()),
                    reason: "late inspection".into(),
                    awaiting_tool: false,
                },
            ),
            SshModalOutcome::Unchanged
        ));
        assert!(!state.fail_pending_grant(
            "incoming-rootless",
            "late inspection failure".into(),
        ));
    }

    #[test]
    fn terminal_failure_cannot_reopen_a_diagnostic_wrapped_grant() {
        let mut state = SshManagerState::new(Some("manager-session".into()));
        state.set_targets(vec![target_view("server-1", SshGrantView::NotGranted)]);
        let request = SshIncomingGrant {
            request_id: "failed-request".into(),
            target_id: Some("server-1".into()),
            root: Some("/srv/checkout".into()),
            capabilities: SshCapabilitiesView::default(),
            verified_identity: Some("builder@build.example.test:22".into()),
            reason: "Inspect a remote checkout.".into(),
            awaiting_tool: false,
        };
        assert!(matches!(
            state.show_incoming_grant("source-session".into(), request.clone()),
            SshModalOutcome::Changed
        ));
        assert!(state.fail_pending_grant("failed-request", "connection failed".into()));
        assert!(state.settle_grant_failure("failed-request", "connection failed".into()));
        assert!(matches!(close_current_page(&mut state), SshModalOutcome::Changed));
        assert!(matches!(&state.page, SshModalPage::Manager));
        assert_eq!(state.grant_session_id_for("failed-request"), None);
        assert!(matches!(
            state.show_incoming_grant("source-session".into(), request),
            SshModalOutcome::Unchanged
        ));
    }

    #[test]
    fn known_root_incoming_request_inspects_without_showing_a_draft() {
        let mut state = SshManagerState::new(Some("manager-session".into()));
        state.set_targets(vec![target_view("server-1", SshGrantView::NotGranted)]);
        assert!(matches!(
            state.show_incoming_grant(
                "source-session".into(),
                SshIncomingGrant {
                    request_id: "known-root".into(),
                    target_id: Some("server-1".into()),
                    root: Some("/srv/known".into()),
                    capabilities: SshCapabilitiesView::default(),
                    verified_identity: None,
                    reason: "Read a known checkout.".into(),
                    awaiting_tool: false,
                },
            ),
            SshModalOutcome::InspectGrantTarget {
                request_id,
                target_id,
                selected_root: None,
                expected_identity: None,
            } if request_id == "known-root" && target_id == "server-1"
        ));
        assert!(matches!(
            state.show_incoming_grant(
                "source-session".into(),
                SshIncomingGrant {
                    request_id: "known-root".into(),
                    target_id: Some("server-1".into()),
                    root: Some("/srv/known".into()),
                    capabilities: SshCapabilitiesView::default(),
                    verified_identity: None,
                    reason: "duplicate inspection event".into(),
                    awaiting_tool: false,
                },
            ),
            SshModalOutcome::Unchanged
        ));
    }

    #[test]
    fn missing_target_enter_uses_the_original_request_and_external_capability_ceiling() {
        let mut state = SshManagerState::new(Some("manager-session".into()));
        state.set_targets(vec![target_view("chosen-target", SshGrantView::NotGranted)]);
        assert!(matches!(
            state.show_incoming_grant(
                "source-session".into(),
                SshIncomingGrant {
                    request_id: "missing-target".into(),
                    target_id: None,
                    root: None,
                    capabilities: SshCapabilitiesView {
                        read: true,
                        write: false,
                        execute: false,
                    },
                    verified_identity: None,
                    reason: "Read the build output.".into(),
                    awaiting_tool: false,
                },
            ),
            SshModalOutcome::Changed
        ));
        let SshModalOutcome::BrowseProjectDirectory { request_id, target_id, .. } =
            handle_ssh_key(&mut state, &key(KeyCode::Enter))
        else {
            panic!("Enter must choose a directory for the original request");
        };
        assert_eq!(target_id, "chosen-target");
        assert!(state.settle_project_directory(
            request_id,
            "chosen-target",
            Ok(directory_listing("chosen-target", "/srv/build", Some("/srv"), &[])),
        ));
        assert!(matches!(
            handle_ssh_key(&mut state, &key(KeyCode::Char('o'))),
            SshModalOutcome::InspectGrantTarget {
                request_id,
                target_id,
                selected_root: Some(root),
                ..
            } if request_id == "missing-target"
                && target_id == "chosen-target"
                && root == "/srv/build"
        ));
        assert!(matches!(
            state.show_incoming_grant(
                "source-session".into(),
                SshIncomingGrant {
                    request_id: "external-read-only".into(),
                    target_id: Some("chosen-target".into()),
                    root: Some("/srv/build".into()),
                    capabilities: SshCapabilitiesView {
                        read: true,
                        write: false,
                        execute: false,
                    },
                    verified_identity: Some("builder@build.example.test:22".into()),
                    reason: "Read the build output.".into(),
                    awaiting_tool: false,
                },
            ),
            SshModalOutcome::Changed
        ));
        let SshModalPage::Grant(card) = &mut state.page else {
            panic!("verified external request must show a consent card");
        };
        assert!(card.verified_root);
        assert!(matches!(
            handle_grant_key(card, &KeyEvent::new(KeyCode::Char('w'), KeyModifiers::ALT)),
            SshModalOutcome::Changed
        ));
        assert!(!card.capabilities.write);
        let area = Rect::new(0, 0, 80, 30);
        let mut buffer = Buffer::empty(area);
        render_ssh_modal(&mut buffer, area, &mut state, false, &Theme::current());
        let rendered = buffer_text(&buffer);
        assert!(rendered.contains("Verified remote folder: /srv/build"));
        assert!(!rendered.contains("Edit root:"));
    }

    #[test]
    fn cancelled_local_picker_cancels_a_late_request_once() {
        let mut state = SshManagerState::new(Some("session-1".into()));
        state.set_targets(vec![target_view("server-1", SshGrantView::NotGranted)]);
        handle_ssh_key(&mut state, &key(KeyCode::Char('m')));
        let SshModalOutcome::BrowseProjectDirectory { request_id, .. } =
            handle_ssh_key(&mut state, &key(KeyCode::Char('g')))
        else {
            panic!("advanced grant must open the picker");
        };
        assert!(state.settle_project_directory(
            request_id,
            "server-1",
            Ok(directory_listing("server-1", "/srv/local", Some("/srv"), &[])),
        ));
        assert!(matches!(
            handle_ssh_key(&mut state, &key(KeyCode::Char('o'))),
            SshModalOutcome::RequestGrant { .. }
        ));
        assert!(matches!(
            handle_ssh_key(&mut state, &key(KeyCode::Esc)),
            SshModalOutcome::Changed
        ));
        assert!(state.bind_local_grant_request(
            "late-local-request",
            Some("server-1"),
            Some("/srv/local"),
        ));
        assert_eq!(
            state.grant_session_id_for("late-local-request").as_deref(),
            Some("session-1")
        );
        assert!(matches!(
            state.show_incoming_grant(
                "session-1".into(),
                SshIncomingGrant {
                    request_id: "late-local-request".into(),
                    target_id: Some("server-1".into()),
                    root: Some("/srv/local".into()),
                    capabilities: SshCapabilitiesView {
                        read: true,
                        write: true,
                        execute: true,
                    },
                    verified_identity: None,
                    reason: "late local request".into(),
                    awaiting_tool: false,
                },
            ),
            SshModalOutcome::CancelGrant { request_id }
                if request_id == "late-local-request"
        ));
        assert!(matches!(
            state.show_incoming_grant(
                "session-1".into(),
                SshIncomingGrant {
                    request_id: "late-local-request".into(),
                    target_id: Some("server-1".into()),
                    root: Some("/srv/local".into()),
                    capabilities: SshCapabilitiesView::default(),
                    verified_identity: Some("builder@build.example.test:22".into()),
                    reason: "late verification".into(),
                    awaiting_tool: false,
                },
            ),
            SshModalOutcome::Unchanged
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
        let SshModalPage::Diagnostic(card) = &state.page else {
            panic!("grant failure must open a diagnostic");
        };
        assert!(card.is_error);
        assert!(matches!(
            &card.return_grant,
            Some(grant) if grant.request_id == "request-1"
        ));
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
            SshModalOutcome::CancelGrant { request_id } if request_id == "request-1"
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

    #[test]
    fn primary_session_access_chooses_a_grant_without_project_preparation() {
        let mut state = SshManagerState::new(Some("local-session".into()));
        state.set_targets(vec![target_view("server-1", SshGrantView::NotGranted)]);
        let area = Rect::new(0, 0, 120, 40);
        render_ssh_modal(&mut Buffer::empty(area), area, &mut state, false, &Theme::current());
        let action = state.window.shortcut_hits.iter()
            .find(|hit| hit.id == FOOTER_MANAGER_OPEN_FOLDER).unwrap().rect;
        let SshModalOutcome::BrowseProjectDirectory { request_id, .. } = handle_ssh_mouse(
            &mut state,
            &MouseEvent {
                kind: MouseEventKind::Down(crossterm::event::MouseButton::Left),
                column: action.x,
                row: action.y,
                modifiers: KeyModifiers::NONE,
            },
        ) else { panic!("Session access must choose an authorization folder"); };
        assert!(!state.project_browser.as_ref().unwrap().purpose.is_project_open());
        assert!(state.settle_project_directory(
            request_id, "server-1",
            Ok(directory_listing("server-1", "/srv", Some("/"), &[])),
        ));
        assert!(matches!(
            handle_ssh_key(&mut state, &key(KeyCode::Char('o'))),
            SshModalOutcome::RequestGrant { target_id, root, .. }
                if target_id == "server-1" && root == "/srv"
        ));
        assert!(state.pending_project_open.is_none());
        assert_eq!(state.session_id.as_deref(), Some("local-session"));
    }

    #[test]
    fn sessionless_enter_connects_without_opening_a_project_or_disconnecting() {
        let mut state = SshManagerState::new(None);
        state.set_targets(vec![target_view("server-1", SshGrantView::NotGranted)]);
        assert!(matches!(
            handle_ssh_key(&mut state, &key(KeyCode::Enter)),
            SshModalOutcome::Connect { target_id } if target_id == "server-1"
        ));
        assert!(state.project_browser.is_none());
        state.targets[0].connected = true;
        assert!(matches!(
            handle_ssh_key(&mut state, &key(KeyCode::Enter)),
            SshModalOutcome::Changed
        ));
        assert!(state.project_browser.is_none());
        let area = Rect::new(0, 0, 120, 40);
        render_ssh_modal(&mut Buffer::empty(area), area, &mut state, false, &Theme::current());
        let action = state.window.shortcut_hits.iter()
            .find(|hit| hit.id == FOOTER_MANAGER_PROJECT).unwrap().rect;
        let SshModalOutcome::BrowseProjectDirectory { request_id, .. } = handle_ssh_mouse(
            &mut state,
            &MouseEvent {
                kind: MouseEventKind::Down(crossterm::event::MouseButton::Left),
                column: action.x,
                row: action.y,
                modifiers: KeyModifiers::NONE,
            },
        ) else { panic!("Only explicit project action should open the project picker"); };
        assert!(state.project_browser.as_ref().unwrap().purpose.is_project_open());
        assert!(state.settle_project_directory(
            request_id, "server-1",
            Ok(directory_listing("server-1", "/srv", Some("/"), &[])),
        ));
        assert!(matches!(
            handle_ssh_key(&mut state, &key(KeyCode::Char('o'))),
            SshModalOutcome::ChooseProjectDirectory { target_id, root, .. }
                if target_id == "server-1" && root == "/srv"
        ));
    }

    #[test]
    fn sessionless_manager_keeps_authority_actions_inert_but_allows_refresh() {
        let mut state = SshManagerState::new(None);
        assert!(matches!(
            handle_ssh_key(&mut state, &key(KeyCode::Char('m'))),
            SshModalOutcome::Changed
        ));
        assert!(matches!(
            handle_ssh_key(&mut state, &key(KeyCode::Char('g'))),
            SshModalOutcome::Unchanged
        ));
        assert!(matches!(
            handle_ssh_key(&mut state, &key(KeyCode::Char('u'))),
            SshModalOutcome::Unchanged
        ));
        assert!(matches!(
            handle_ssh_key(&mut state, &key(KeyCode::Char('p'))),
            SshModalOutcome::Unchanged
        ));
        assert!(matches!(
            handle_ssh_key(&mut state, &key(KeyCode::Char('r'))),
            SshModalOutcome::Refresh
        ));
    }

    #[test]
    fn only_pending_connect_owns_matching_authentication_prompt() {
        let mut connecting = SshManagerState::new(None);
        connecting.begin_connection_action("server-1", true);
        assert_eq!(
            connecting.pending_authentication_target_id(),
            Some("server-1")
        );

        let mut disconnecting = SshManagerState::new(None);
        disconnecting.begin_connection_action("server-1", false);
        assert_eq!(disconnecting.pending_authentication_target_id(), None);
    }

    fn target_view_from_target(target: xai_grok_ssh::SshTarget) -> SshTargetView {
        SshTargetView::from_target(
            target,
            "user@example.test:22".into(),
            false,
            "Disconnected.".into(),
            SshGrantView::NotGranted,
        )
    }

    #[test]
    fn manual_target_edit_preserves_id_credential_extra_identities_and_worker_arguments() {
        let mut target = xai_grok_ssh::SshTarget::new("before.example.test");
        target.id = "manual-id".into();
        target.label = "Before".into();
        target.user = Some("builder".into());
        target.port = Some(2202);
        target.identity_files = vec![
            std::path::PathBuf::from("~/.ssh/first"),
            std::path::PathBuf::from("~/.ssh/second"),
        ];
        target.credential_ref = Some("keychain:build-host".into());
        target.worker_command = vec![
            "groky".into(),
            "worker".into(),
            "--socket".into(),
            "a path/socket".into(),
        ];
        let mut state = SshManagerState::new(None);
        state.set_targets(vec![target_view_from_target(target.clone())]);

        assert!(matches!(
            handle_ssh_key(&mut state, &key(KeyCode::Char('e'))),
            SshModalOutcome::Changed
        ));
        let SshModalPage::Add(form) = &mut state.page else {
            panic!("manual target must open the shared target form")
        };
        assert_eq!(form.worker_command.text(), r#""groky" "worker" "--socket" "a path/socket""#);
        assert_eq!(
            xai_grok_ssh::parse_worker_command(form.worker_command.text())
                .expect("quoted edit field must retain worker argv"),
            target.worker_command
        );
        form.label.set_text("After");
        let SshModalOutcome::UpdateTarget {
            expected,
            replacement,
            submission_id,
        } = handle_ssh_key(&mut state, &key(KeyCode::Enter))
        else {
            panic!("editing a manual target must submit an expected snapshot and replacement")
        };
        assert_eq!(expected, target);
        assert_eq!(replacement.id, "manual-id");
        assert_eq!(replacement.label, "After");
        assert_eq!(replacement.credential_ref.as_deref(), Some("keychain:build-host"));
        assert_eq!(
            replacement.identity_files,
            vec![
                std::path::PathBuf::from("~/.ssh/first"),
                std::path::PathBuf::from("~/.ssh/second"),
            ]
        );
        assert_eq!(replacement.worker_command, target.worker_command);
        assert_ne!(submission_id, 0);
        assert!(matches!(
            handle_ssh_key(&mut state, &key(KeyCode::Enter)),
            SshModalOutcome::Unchanged
        ));
        assert!(state.settle_target_update_for_submission(
            submission_id,
            Err("the target changed in another SSH configuration update".into())
        ));
        assert!(matches!(
            &state.page,
            SshModalPage::Add(form)
                if form.label.text() == "After"
                    && form.error.as_deref()
                        == Some("the target changed in another SSH configuration update")
        ));
    }

    #[test]
    fn imported_target_is_read_only_with_source_path_and_line() {
        let mut target = xai_grok_ssh::SshTarget::new("imported-alias");
        target.id = "imported-id".into();
        target.source = xai_grok_ssh::TargetSource::Imported {
            path: std::path::PathBuf::from("/Users/test/.ssh/config"),
            line: 37,
        };
        let mut state = SshManagerState::new(None);
        state.set_targets(vec![target_view_from_target(target)]);
        let area = Rect::new(0, 0, 120, 24);
        let mut buffer = Buffer::empty(area);
        render_ssh_modal(&mut buffer, area, &mut state, false, &Theme::current());
        let source = buffer_text(&buffer);
        assert!(source.contains("read-only"));
        assert!(source.contains("/Users/test/.ssh/config:37"));


        for action in ['e', 'x'] {
            assert!(matches!(
                handle_ssh_key(&mut state, &key(KeyCode::Char(action))),
                SshModalOutcome::Changed
            ));
            let SshModalPage::Diagnostic(card) = &state.page else {
                panic!("read-only source guidance must be scrollable");
            };
            assert!(!card.is_error);
            assert!(card.message.contains("/Users/test/.ssh/config"));
            assert!(card.message.contains("37"));
            handle_ssh_key(&mut state, &key(KeyCode::Esc));
            assert!(matches!(&state.page, SshModalPage::Manager));
        }
    }

    #[test]
    fn delete_requires_confirmation_and_stale_completion_cannot_settle_a_newer_form() {
        let mut target = xai_grok_ssh::SshTarget::new("delete.example.test");
        target.id = "delete-id".into();
        target.label = "Delete me".into();
        let mut state = SshManagerState::new(Some("session".into()));
        let mut view = target_view_from_target(target.clone());
        view.connected = true;
        view.grant = granted("binding-1", "/srv/project");
        state.set_targets(vec![view]);

        assert!(matches!(
            handle_ssh_key(&mut state, &key(KeyCode::Char('x'))),
            SshModalOutcome::Changed
        ));
        let area = Rect::new(0, 0, 100, 24);
        let mut buffer = Buffer::empty(area);
        render_ssh_modal(&mut buffer, area, &mut state, false, &Theme::current());
        let confirmation = buffer_text(&buffer);
        assert!(confirmation.contains("Delete me"));
        assert!(confirmation.contains("disconnected"));
        assert!(confirmation.contains("revoked"));
        assert!(matches!(
            handle_ssh_key(&mut state, &key(KeyCode::Esc)),
            SshModalOutcome::Changed
        ));
        assert!(matches!(&state.page, SshModalPage::Manager));

        assert!(matches!(
            handle_ssh_key(&mut state, &key(KeyCode::Char('x'))),
            SshModalOutcome::Changed
        ));
        let SshModalOutcome::RemoveTarget {
            expected,
            submission_id: first_submission,
        } = handle_ssh_key(&mut state, &key(KeyCode::Enter))
        else {
            panic!("confirmed deletion must submit the selected target snapshot")
        };
        assert_eq!(expected, target);
        assert!(matches!(
            close_current_page(&mut state),
            SshModalOutcome::Changed
        ));
        assert!(matches!(
            handle_ssh_key(&mut state, &key(KeyCode::Char('e'))),
            SshModalOutcome::Changed
        ));
        let SshModalPage::Add(form) = &mut state.page else {
            panic!("manual target must reopen for an edit")
        };
        form.label.set_text("Newer edit");
        let SshModalOutcome::UpdateTarget {
            submission_id: newer_submission,
            ..
        } = handle_ssh_key(&mut state, &key(KeyCode::Enter))
        else {
            panic!("newer edit must submit")
        };
        assert_ne!(first_submission, newer_submission);
        assert!(!state.settle_target_remove_for_submission(first_submission, Ok(target.clone())));
        assert!(state.target_update_is_submitting());
    }

    #[test]
    fn manual_target_edit_and_delete_footer_controls_are_clickable() {
        let mut target = xai_grok_ssh::SshTarget::new("controls.example.test");
        target.id = "controls-id".into();
        target.label = "Controls".into();
        let mut state = SshManagerState::new(None);
        state.set_targets(vec![target_view_from_target(target)]);
        let area = Rect::new(0, 0, 100, 24);
        let theme = Theme::current();
        let click = |rect: Rect| MouseEvent {
            kind: MouseEventKind::Down(crossterm::event::MouseButton::Left),
            column: rect.x,
            row: rect.y,
            modifiers: KeyModifiers::NONE,
        };

        let mut buffer = Buffer::empty(area);
        render_ssh_modal(&mut buffer, area, &mut state, false, &theme);
        let edit = state
            .window
            .shortcut_hits
            .iter()
            .find(|hit| hit.id == FOOTER_MANAGER_EDIT)
            .expect("manual-target edit footer must render")
            .rect;
        assert!(matches!(
            handle_ssh_mouse(&mut state, &click(edit)),
            SshModalOutcome::Changed
        ));
        assert!(matches!(&state.page, SshModalPage::Add(_)));
        assert!(matches!(
            close_current_page(&mut state),
            SshModalOutcome::Changed
        ));

        let mut buffer = Buffer::empty(area);
        render_ssh_modal(&mut buffer, area, &mut state, false, &theme);
        let delete = state
            .window
            .shortcut_hits
            .iter()
            .find(|hit| hit.id == FOOTER_MANAGER_DELETE)
            .expect("manual-target delete footer must render")
            .rect;
        assert!(matches!(
            handle_ssh_mouse(&mut state, &click(delete)),
            SshModalOutcome::Changed
        ));
        assert!(matches!(&state.page, SshModalPage::ConfirmDelete(_)));

        let mut buffer = Buffer::empty(area);
        render_ssh_modal(&mut buffer, area, &mut state, false, &theme);
        let cancel = state
            .window
            .shortcut_hits
            .iter()
            .find(|hit| hit.id == FOOTER_DELETE_CANCEL)
            .expect("delete-cancel footer must render")
            .rect;
        assert!(matches!(
            handle_ssh_mouse(&mut state, &click(cancel)),
            SshModalOutcome::Changed
        ));
        assert!(matches!(&state.page, SshModalPage::Manager));
    }

    #[test]
    fn refreshed_targets_drop_external_deletions_and_do_not_resurrect_removed_manual_targets() {
        let mut imported = xai_grok_ssh::SshTarget::new("external-alias");
        imported.id = "external-id".into();
        imported.source = xai_grok_ssh::TargetSource::Imported {
            path: std::path::PathBuf::from("/etc/ssh/ssh_config"),
            line: 12,
        };
        let mut state = SshManagerState::new(None);
        state.set_targets(vec![target_view_from_target(imported)]);
        state.set_targets(Vec::new());
        assert!(state.targets.is_empty());

        let mut manual = xai_grok_ssh::SshTarget::new("removed.example.test");
        manual.id = "removed-id".into();
        state.set_targets(vec![target_view_from_target(manual.clone())]);
        assert!(matches!(
            handle_ssh_key(&mut state, &key(KeyCode::Char('x'))),
            SshModalOutcome::Changed
        ));
        let SshModalOutcome::RemoveTarget { submission_id, .. } =
            handle_ssh_key(&mut state, &key(KeyCode::Enter))
        else {
            panic!("manual target deletion must submit")
        };
        assert!(state.settle_target_remove_for_submission(submission_id, Ok(manual.clone())));
        state.set_targets(vec![target_view_from_target(manual.clone())]);
        assert!(
            state.targets.is_empty(),
            "a late list completion must not resurrect a locally removed target"
        );
        state.set_targets(Vec::new());
        state.set_targets(vec![target_view_from_target(manual)]);
        assert_eq!(state.targets[0].target_id, "removed-id");
    }

    #[test]
    fn ssh_target_fields_expose_moving_cursors_and_keep_compact_focus_visible() {
        let theme = Theme::default();
        let area = Rect::new(0, 0, 70, 10);
        let mut form = SshManualTargetForm::default();
        for field in ManualTargetField::ALL {
            form.active = field;
            form.editor_mut().set_text("");
            let before = render_add(&mut Buffer::empty(area), area, &mut form, &theme).unwrap();
            form.editor_mut().insert_paste("界a");
            let after = render_add(&mut Buffer::empty(area), area, &mut form, &theme).unwrap();
            assert_eq!(after, (before.0 + 3, before.1));
            form.editor_mut().handle_key(&key(KeyCode::Left));
            let moved = render_add(&mut Buffer::empty(area), area, &mut form, &theme).unwrap();
            assert_eq!(moved, (before.0 + 2, before.1));
        }
        form.active = ManualTargetField::WorkerCommand;
        let compact = Rect::new(0, 0, 30, 2);
        let cursor = render_add(&mut Buffer::empty(compact), compact, &mut form, &theme).unwrap();
        assert_eq!(cursor.1, 1, "Tab's active field remains visible in a short form");
        assert!(cursor.0 < compact.width);
        form.submitting = true;
        assert!(render_add(&mut Buffer::empty(compact), compact, &mut form, &theme).is_none());
    }

    #[test]
    fn ssh_password_cursor_tracks_masked_unicode_and_horizontal_scrolling() {
        let theme = Theme::default();
        let area = Rect::new(0, 0, 30, 8);
        let mut card = SshAuthCard::new("password".into(), 1, "fixture".into(),
            SshAuthKind::Password { username:"operator".into(), message:"Enter password".into(), allow_remember:false });
        let empty = render_authentication(&mut Buffer::empty(area), area, &mut card, &theme).unwrap();
        card.answer_mut().unwrap().insert_paste("密🙂ab");
        let mut buffer = Buffer::empty(area);
        let after = render_authentication(&mut buffer, area, &mut card, &theme).unwrap();
        assert_eq!(after, (empty.0 + 4, empty.1));
        assert!(!buffer_text(&buffer).contains("密🙂ab"));
        handle_authentication_key(&mut card, &key(KeyCode::Home));
        assert_eq!(render_authentication(&mut Buffer::empty(area), area, &mut card, &theme), Some(empty));
        card.answer_mut().unwrap().insert_paste(&"密".repeat(80));
        let scrolled = render_authentication(&mut Buffer::empty(area), area, &mut card, &theme).unwrap();
        assert_eq!(scrolled.0, area.right() - 1);
        handle_authentication_key(&mut card, &key(KeyCode::Home));
        assert_eq!(render_authentication(&mut Buffer::empty(area), area, &mut card, &theme), Some(empty));
    }

    #[test]
    fn ssh_keyboard_interactive_cursor_follows_answer_focus_and_manual_scroll() {
        let theme = Theme::default();
        let area = Rect::new(0, 0, 32, 4);
        let mut card = SshAuthCard::new("challenge".into(), 1, "fixture".into(),
            SshAuthKind::KeyboardInteractive {
                name:"Authentication".into(), instruction:"Read this instruction.\n".repeat(12),
                prompts:vec!["First challenge".into(), "Second challenge".into()],
            });
        assert!(render_authentication(&mut Buffer::empty(area), area, &mut card, &theme).is_some());
        handle_authentication_key(&mut card, &key(KeyCode::Tab));
        let mut buffer = Buffer::empty(area);
        let second = render_authentication(&mut buffer, area, &mut card, &theme).unwrap();
        assert!(buffer_text(&buffer).contains("Second challenge"));
        card.answer_mut().unwrap().insert_paste("1234");
        let typed = render_authentication(&mut Buffer::empty(area), area, &mut card, &theme).unwrap();
        assert_eq!(typed.0, second.0 + 4);
        assert_eq!(card.answers.first().unwrap().text(), "");
        assert_eq!(card.answers.get(1).unwrap().text(), "1234");
        handle_authentication_key(&mut card, &key(KeyCode::PageUp));
        assert!(render_authentication(&mut Buffer::empty(area), area, &mut card, &theme).is_none());
        handle_authentication_key(&mut card, &key(KeyCode::Left));
        assert!(render_authentication(&mut Buffer::empty(area), area, &mut card, &theme).is_some());
    }

    #[test]
    fn ssh_root_and_directory_inputs_return_cursors_only_while_editing() {
        let theme = Theme::default();
        let area = Rect::new(0, 0, 80, 24);
        let mut grant = SshGrantCard::new("grant".into(), "fixture".into(), "Fixture".into(),
            None, "/tmp", None, false);
        assert!(render_grant(&mut Buffer::empty(area), area, &mut grant, &theme).is_some());
        grant.focus = SshGrantFocus::Read;
        assert!(render_grant(&mut Buffer::empty(area), area, &mut grant, &theme).is_none());
        let mut browser = SshProjectBrowser::new("fixture".into(), Some("/tmp".into()), 1, SshDirectoryPurpose::ProjectOpen);
        assert!(render_project_browser(&mut Buffer::empty(area), area, &mut browser, &theme).is_none());
        browser.editing_path = true;
        let cursor = render_project_browser(&mut Buffer::empty(area), area, &mut browser, &theme).unwrap();
        assert_eq!(cursor.1, area.y + 1);
        browser.preparing = true;
        assert!(render_project_browser(&mut Buffer::empty(area), area, &mut browser, &theme).is_none());
        let mut manager = SshManagerState::new(None);
        assert!(render_ssh_modal(&mut Buffer::empty(area), area, &mut manager, false, &theme).is_none());
    }
}
