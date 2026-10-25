//! Standalone local-only SSH manager.
//!
//! This surface owns one short-lived leader control client and deliberately never creates a
//! model session or a grant.  Selecting a folder returns a verified handoff to the normal pager,
//! which performs the later project-consent lifecycle.

use std::{
    io::{self, Write},
    sync::Arc,
    time::Duration,
};

use anyhow::Result;
use crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers, MouseEvent},
    execute,
    terminal::{self, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    style::Style,
    widgets::Clear,
};
use tokio::{
    sync::mpsc,
    task::JoinSet,
};
use xai_grok_shell::ssh::{
    SshAuthControlResponse, SshConnectionState, SshControlCommand, SshControlReply, SshEvent,
    SshTargetStatus,
};

use crate::{
    app::{SshProjectOpen, ssh_control},
    theme::Theme,
    views::ssh_modal::{
        SshManagerState, SshModalOutcome, SshSecret, SshTargetView, handle_ssh_key,
        handle_ssh_mouse, handle_ssh_paste, render_ssh_modal,
    },
};

/// Initial standalone SSH surface selected by the command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshTuiStart {
    Manager,
    Add,
    Connect { target_id: String },
    Open { target_id: Option<String> },
}

/// Run the local SSH manager without bootstrapping a model or provider session.
///
/// `Some` contains a directory selected from a locally authenticated server.  The caller must
/// hand it to the normal project bootstrap so that the eventual model-access consent remains in
/// the full application.  `None` means management completed; cancelling an explicit connection
/// reports an actionable error rather than pretending the connection succeeded.
pub async fn run(start: SshTuiStart) -> Result<Option<SshProjectOpen>> {
    run_terminal(start).await
}

struct TerminalGuard {
    raw_mode: bool,
}

impl TerminalGuard {
    fn enter() -> io::Result<Self> {
        terminal::enable_raw_mode()?;
        let guard = Self { raw_mode: true };
        let mut stdout = io::stdout();
        // Mark the terminal as needing a complete reset before the first fallible escape write:
        // crossterm can fail after partially writing a multi-command execute! invocation.
        execute!(
            stdout,
            EnterAlternateScreen,
            event::EnableMouseCapture,
            event::EnableBracketedPaste,
            cursor::Hide,
        )?;
        stdout.flush()?;
        Ok(guard)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        if !self.raw_mode {
            return;
        }
        let mut stdout = io::stdout();
        let _ = execute!(
            stdout,
            cursor::Show,
            event::DisableBracketedPaste,
            event::DisableMouseCapture,
            LeaveAlternateScreen,
        );
        let _ = stdout.flush();
        let _ = terminal::disable_raw_mode();
    }
}


struct ConnectionAttempt {
    generation: u64,
    target_id: String,
    exit_when_connected: bool,
}

#[derive(Clone)]
struct AuthenticationSubmission {
    challenge_id: String,
    connection_generation: u64,
    target_id: String,
}

enum UiMessage {
    TargetsLoaded {
        generation: u64,
        client_id: u64,
        result: std::result::Result<Vec<SshTargetView>, String>,
    },
    TargetAdded {
        submission_id: u64,
        result: std::result::Result<String, String>,
    },
    TargetUpdated {
        submission_id: u64,
        result: std::result::Result<xai_grok_ssh::SshTarget, String>,
    },
    TargetRemoved {
        submission_id: u64,
        result: std::result::Result<xai_grok_ssh::SshTarget, String>,
    },
    ConnectionSettled {
        generation: u64,
        client_id: u64,
        target_id: String,
        result: std::result::Result<SshTargetStatus, String>,
    },
    DirectoryLoaded {
        request_id: u64,
        client_id: u64,
        target_id: String,
        result: std::result::Result<xai_grok_shell::ssh::SshDirectoryListing, String>,
    },
    AuthenticationSubmitted {
        submission: AuthenticationSubmission,
        client_id: u64,
        error: Option<String>,
    },
    Event {
        client_id: u64,
        event: SshEvent,
    },
    EventStreamClosed(String),
}

enum LoopAction {
    Continue,
    Exit(Option<SshProjectOpen>),
    ConnectSucceeded,
}

struct StandaloneSshRunner {
    state: SshManagerState,
    backend: Arc<ssh_control::SshControlBackend>,
    client_id: u64,
    messages_tx: mpsc::UnboundedSender<UiMessage>,
    messages_rx: mpsc::UnboundedReceiver<UiMessage>,
    jobs: JoinSet<()>,
    target_generation: u64,
    connection_generation: u64,
    connection_attempt: Option<ConnectionAttempt>,
    connect_only_target: Option<String>,
    last_authentication_submission: Option<AuthenticationSubmission>,
    focus_target: Option<String>,
}

impl StandaloneSshRunner {
    fn new(
        backend: Arc<ssh_control::SshControlBackend>,
        client_id: u64,
        start: SshTuiStart,
    ) -> Self {
        let (messages_tx, messages_rx) = mpsc::unbounded_channel();
        let (connect_only_target, focus_target) = match &start {
            SshTuiStart::Connect { target_id } => (Some(target_id.clone()), Some(target_id.clone())),
            SshTuiStart::Open {
                target_id: Some(target_id),
            } => (None, Some(target_id.clone())),
            SshTuiStart::Manager | SshTuiStart::Add | SshTuiStart::Open { target_id: None } => {
                (None, None)
            }
        };
        Self {
            state: SshManagerState::new(None),
            backend,
            client_id,
            messages_tx,
            messages_rx,
            jobs: JoinSet::new(),
            target_generation: 0,
            connection_generation: 0,
            connection_attempt: None,
            connect_only_target,
            last_authentication_submission: None,
            focus_target,
        }
    }

    fn initialize(&mut self, start: SshTuiStart) {
        self.listen_for_events();
        self.refresh_targets();
        match start {
            SshTuiStart::Manager | SshTuiStart::Open { target_id: None } => {}
            SshTuiStart::Add => {
                let outcome = handle_ssh_key(
                    &mut self.state,
                    &crossterm::event::KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE),
                );
                let _ = self.route_outcome(outcome);
            }
            SshTuiStart::Connect { target_id } => self.start_connection(target_id, true, true),
            SshTuiStart::Open {
                target_id: Some(target_id),
            } => {
                let outcome = self.state.begin_project_browser(target_id, None);
                let _ = self.route_outcome(outcome);
            }
        }
    }

    fn next_generation(current: &mut u64) -> u64 {
        *current = current.wrapping_add(1);
        if *current == 0 {
            *current = 1;
        }
        *current
    }

    fn listen_for_events(&mut self) {
        let backend = Arc::clone(&self.backend);
        let tx = self.messages_tx.clone();
        self.jobs.spawn(async move {
            loop {
                match backend.next_event().await {
                    Ok((client_id, event)) => {
                        if tx.send(UiMessage::Event { client_id, event }).is_err() {
                            break;
                        }
                    }
                    Err(error) => {
                        let _ = tx.send(UiMessage::EventStreamClosed(format!("{error:#}")));
                        break;
                    }
                }
            }
        });
    }

    fn refresh_targets(&mut self) {
        let generation = Self::next_generation(&mut self.target_generation);
        self.state.loading = true;
        let backend = Arc::clone(&self.backend);
        let tx = self.messages_tx.clone();
        let fallback_client_id = self.client_id;
        self.jobs.spawn(async move {
            let (client_id, result) = match backend.load_targets(None).await {
                Ok((client_id, targets)) => (client_id, Ok(targets)),
                Err(error) => (fallback_client_id, Err(format!("{error:#}"))),
            };
            let _ = tx.send(UiMessage::TargetsLoaded {
                generation,
                client_id,
                result,
            });
        });
    }

    fn save_target(&mut self, draft: crate::views::ssh_modal::SshManualTargetDraft, submission_id: u64) {
        let tx = self.messages_tx.clone();
        self.jobs.spawn(async move {
            let result = match tokio::task::spawn_blocking(move || ssh_control::add_target(draft)).await {
                Ok(Ok(target)) => Ok(target.id),
                Ok(Err(error)) => Err(format!("Could not save SSH target: {error}")),
                Err(error) => Err(format!("Could not save SSH target: {error}")),
            };
            let _ = tx.send(UiMessage::TargetAdded {
                submission_id,
                result,
            });
        });
    }


    fn update_target(
        &mut self,
        expected: xai_grok_ssh::SshTarget,
        replacement: xai_grok_ssh::SshTarget,
        submission_id: u64,
    ) {
        let backend = Arc::clone(&self.backend);
        let tx = self.messages_tx.clone();
        self.jobs.spawn(async move {
            let result = match backend
                .request(SshControlCommand::UpdateTarget {
                    expected,
                    replacement,
                })
                .await
            {
                Ok((_, SshControlReply::TargetUpdated(target))) => Ok(target),
                Ok((_, _)) => Err("SSH local service returned an unexpected target update response.".into()),
                Err(error) => Err(format!("{error:#}")),
            };
            let _ = tx.send(UiMessage::TargetUpdated {
                submission_id,
                result,
            });
        });
    }

    fn remove_target(&mut self, expected: xai_grok_ssh::SshTarget, submission_id: u64) {
        let backend = Arc::clone(&self.backend);
        let tx = self.messages_tx.clone();
        self.jobs.spawn(async move {
            let result = match backend
                .request(SshControlCommand::RemoveTarget { expected })
                .await
            {
                Ok((_, SshControlReply::TargetRemoved(target))) => Ok(target),
                Ok((_, _)) => Err("SSH local service returned an unexpected target removal response.".into()),
                Err(error) => Err(format!("{error:#}")),
            };
            let _ = tx.send(UiMessage::TargetRemoved {
                submission_id,
                result,
            });
        });
    }
    fn start_connection(&mut self, target_id: String, connect: bool, exit_when_connected: bool) {
        let generation = Self::next_generation(&mut self.connection_generation);
        self.state.begin_connection_action(&target_id, connect);
        self.connection_attempt = Some(ConnectionAttempt {
            generation,
            target_id: target_id.clone(),
            exit_when_connected: connect && exit_when_connected,
        });
        let backend = Arc::clone(&self.backend);
        let tx = self.messages_tx.clone();
        let fallback_client_id = self.client_id;
        self.jobs.spawn(async move {
            let command = if connect {
                SshControlCommand::Connect {
                    target_id: target_id.clone(),
                    interactive: true,
                }
            } else {
                SshControlCommand::Disconnect {
                    target_id: target_id.clone(),
                }
            };
            let (client_id, result) = match backend.request(command).await {
                Ok((client_id, SshControlReply::TargetStatus(status)))
                    if status.target_id == target_id =>
                {
                    (client_id, Ok(status))
                }
                Ok((client_id, _)) => (
                    client_id,
                    Err("SSH local service returned an unexpected connection response.".into()),
                ),
                Err(error) => (fallback_client_id, Err(format!("{error:#}"))),
            };
            let _ = tx.send(UiMessage::ConnectionSettled {
                generation,
                client_id,
                target_id,
                result,
            });
        });
    }

    fn browse_directory(&mut self, request_id: u64, target_id: String, path: Option<String>) {
        let backend = Arc::clone(&self.backend);
        let tx = self.messages_tx.clone();
        let fallback_client_id = self.client_id;
        self.jobs.spawn(async move {
            let (client_id, result) = match backend
                .request(SshControlCommand::BrowseProjectDirectories {
                    target_id: target_id.clone(),
                    path,
                })
                .await
            {
                Ok((client_id, SshControlReply::ProjectDirectories(listing)))
                    if listing.target_id == target_id =>
                {
                    (client_id, Ok(listing))
                }
                Ok((client_id, SshControlReply::ProjectDirectories(_))) => (
                    client_id,
                    Err("SSH returned directories for a different target.".into()),
                ),
                Ok((client_id, _)) => (
                    client_id,
                    Err("SSH local service returned an unexpected directory response.".into()),
                ),
                Err(error) => (fallback_client_id, Err(format!("{error:#}"))),
            };
            let _ = tx.send(UiMessage::DirectoryLoaded {
                request_id,
                client_id,
                target_id,
                result,
            });
        });
    }

    fn submit_authentication(
        &mut self,
        challenge_id: String,
        connection_generation: u64,
        target_id: String,
        host_key_decision: Option<xai_grok_shell::ssh::SshHostKeyDecision>,
        remember: bool,
        secret: Option<SshSecret>,
        answers: Vec<SshSecret>,
    ) {
        let submission = AuthenticationSubmission {
            challenge_id,
            connection_generation,
            target_id,
        };
        self.last_authentication_submission = Some(submission.clone());
        let backend = Arc::clone(&self.backend);
        let tx = self.messages_tx.clone();
        let fallback_client_id = self.client_id;
        self.jobs.spawn(async move {
            let response = SshAuthControlResponse {
                client_id: fallback_client_id,
                connection_generation: submission.connection_generation,
                challenge_id: submission.challenge_id.clone(),
                accepted: None,
                host_key_decision,
                remember,
                secret: secret.map(SshSecret::into_bytes),
                answers: answers.into_iter().map(SshSecret::into_bytes).collect(),
            };
            let (client_id, error) = match backend
                .request(SshControlCommand::SubmitAuthentication(response))
                .await
            {
                Ok((client_id, SshControlReply::AuthenticationAccepted)) => (client_id, None),
                Ok((client_id, _)) => (
                    client_id,
                    Some("SSH local service returned an unexpected authentication response.".into()),
                ),
                Err(error) => (fallback_client_id, Some(format!("{error:#}"))),
            };
            let _ = tx.send(UiMessage::AuthenticationSubmitted {
                submission,
                client_id,
                error,
            });
        });
    }

    fn route_outcome(&mut self, outcome: SshModalOutcome) -> LoopAction {
        match outcome {
            SshModalOutcome::Close => LoopAction::Exit(None),
            SshModalOutcome::Changed | SshModalOutcome::Unchanged => LoopAction::Continue,
            SshModalOutcome::Refresh => {
                self.refresh_targets();
                LoopAction::Continue
            }
            SshModalOutcome::AddTarget {
                draft,
                submission_id,
            } => {
                self.save_target(draft, submission_id);
                LoopAction::Continue
            }
            SshModalOutcome::UpdateTarget {
                expected,
                replacement,
                submission_id,
            } => {
                self.update_target(expected, replacement, submission_id);
                LoopAction::Continue
            }
            SshModalOutcome::RemoveTarget {
                expected,
                submission_id,
            } => {
                self.remove_target(expected, submission_id);
                LoopAction::Continue
            }
            SshModalOutcome::Connect { target_id } => {
                let exit_when_connected = self.connect_only_target.as_deref() == Some(target_id.as_str());
                self.start_connection(target_id, true, exit_when_connected);
                LoopAction::Continue
            }
            SshModalOutcome::Disconnect { target_id } => {
                self.start_connection(target_id, false, false);
                LoopAction::Continue
            }
            SshModalOutcome::BrowseProjectDirectory {
                request_id,
                target_id,
                path,
            } => {
                self.browse_directory(request_id, target_id, path);
                LoopAction::Continue
            }
            SshModalOutcome::ChooseProjectDirectory {
                target_id,
                root,
                identity,
                ..
            } => LoopAction::Exit(Some(SshProjectOpen {
                target_id,
                root,
                project_session_id: uuid::Uuid::now_v7().to_string(),
                expected_identity: Some(identity),
            })),
            // Standalone management must not mint or manipulate model-visible authority.  These
            // outcomes are unreachable from the session-less shortcuts, but refusing them here
            // also prevents a future modal change from turning this surface into a grant engine.
            SshModalOutcome::RequestGrant { .. }
            | SshModalOutcome::SelectPromptTarget { .. }
            | SshModalOutcome::ApproveGrant { .. }
            | SshModalOutcome::CancelGrant { .. }
            | SshModalOutcome::InspectGrantTarget { .. }
            | SshModalOutcome::UseBinding { .. }
            | SshModalOutcome::RevokeBinding { .. }
            | SshModalOutcome::CancelProjectOpen { .. }
            | SshModalOutcome::ApproveOperation { .. }
            | SshModalOutcome::ResetOperationApprovals { .. }
            | SshModalOutcome::ApproveWorkerInstall { .. } => {
                self.state
                    .show_error("Authorize SSH tools from /ssh inside a chat session; no remote project or worker is required.");
                LoopAction::Continue
            }
            SshModalOutcome::AnswerAuthentication {
                challenge_id,
                connection_generation,
                target_id,
                host_key_decision,
                remember,
                secret,
                answers,
            } => {
                self.submit_authentication(
                    challenge_id,
                    connection_generation,
                    target_id,
                    host_key_decision,
                    remember,
                    secret,
                    answers,
                );
                LoopAction::Continue
            }
        }
    }

    fn route_input(&mut self, input: Event) -> LoopAction {
        match input {
            Event::Key(key) if key.kind != KeyEventKind::Release => {
                if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
                    return LoopAction::Exit(None);
                }
                let outcome = handle_ssh_key(&mut self.state, &key);
                self.route_outcome(outcome)
            }
            Event::Mouse(mouse) => self.route_mouse(mouse),
            Event::Paste(text) => {
                let outcome = handle_ssh_paste(&mut self.state, &text);
                self.route_outcome(outcome)
            }
            Event::FocusGained | Event::FocusLost | Event::Resize(_, _) | Event::Key(_) => {
                LoopAction::Continue
            }
        }
    }

    fn route_mouse(&mut self, mouse: MouseEvent) -> LoopAction {
        let outcome = handle_ssh_mouse(&mut self.state, &mouse);
        self.route_outcome(outcome)
    }

    fn route_message(&mut self, message: UiMessage) -> LoopAction {
        match message {
            UiMessage::TargetsLoaded {
                generation,
                client_id,
                result,
            } => {
                if generation != self.target_generation || client_id != self.client_id {
                    return LoopAction::Continue;
                }
                match result {
                    Ok(targets) => {
                        self.state.set_targets(targets);
                        if let Some(target_id) = self.focus_target.as_deref() {
                            self.state.select_target_id(target_id);
                        }
                    }
                    Err(error) => self.state.show_error(error),
                }
            }
            UiMessage::TargetAdded {
                submission_id,
                result,
            } => {
                if self
                    .state
                    .settle_target_add_for_submission(submission_id, result)
                {
                    self.refresh_targets();
                }
            }
            UiMessage::TargetUpdated {
                submission_id,
                result,
            } => {
                let succeeded = result.is_ok();
                if self
                    .state
                    .settle_target_update_for_submission(submission_id, result)
                    && succeeded
                {
                    self.refresh_targets();
                }
            }
            UiMessage::TargetRemoved {
                submission_id,
                result,
            } => {
                let succeeded = result.is_ok();
                if self
                    .state
                    .settle_target_remove_for_submission(submission_id, result)
                    && succeeded
                {
                    self.refresh_targets();
                }
            }
            UiMessage::ConnectionSettled {
                generation,
                client_id,
                target_id,
                result,
            } => {
                if client_id != self.client_id
                    || !self.connection_attempt.as_ref().is_some_and(|attempt| {
                        attempt.generation == generation && attempt.target_id == target_id
                    })
                {
                    return LoopAction::Continue;
                }
                match result {
                    Ok(status) => {
                        let complete = status.connection == SshConnectionState::Connected
                            && self.connection_attempt.as_ref()
                                .is_some_and(|attempt| attempt.exit_when_connected);
                        self.apply_connection_status(status);
                        if complete {
                            return LoopAction::ConnectSucceeded;
                        }
                    }
                    Err(error) => {
                        self.state.loading = false;
                        self.state.show_error(error);
                    }
                }
            }
            UiMessage::DirectoryLoaded {
                request_id,
                client_id,
                target_id,
                result,
            } => {
                if client_id != self.client_id {
                    return LoopAction::Continue;
                }
                self.state
                    .settle_project_directory(request_id, &target_id, result);
            }
            UiMessage::AuthenticationSubmitted {
                submission,
                client_id,
                error,
            } => {
                if client_id != self.client_id
                    || !self.last_authentication_submission.as_ref().is_some_and(|current| {
                        current.challenge_id == submission.challenge_id
                            && current.connection_generation == submission.connection_generation
                            && current.target_id == submission.target_id
                    })
                {
                    return LoopAction::Continue;
                }
                self.last_authentication_submission = None;
                if let Some(error) = error {
                    self.state.loading = false;
                    self.state.show_error(error);
                }
            }
            UiMessage::Event { client_id, event } => {
                if client_id != self.client_id {
                    return LoopAction::Continue;
                }
                return self.route_control_event(event);
            }
            UiMessage::EventStreamClosed(error) => self.state.show_error(error),
        }
        LoopAction::Continue
    }

    fn route_control_event(&mut self, event: SshEvent) -> LoopAction {
        match event {
            SshEvent::Authentication(prompt)
                if prompt.client_id == self.client_id
                    && !matches!(
                        &prompt.kind,
                        xai_grok_shell::ssh::SshAuthPromptKind::SudoPassword
                    )
                    && self.state.pending_authentication_target_id() == Some(prompt.target_id.as_str()) =>
            {
                if self.last_authentication_submission.as_ref().is_some_and(|submitted| {
                    submitted.challenge_id == prompt.challenge_id
                        && submitted.connection_generation == prompt.connection_generation
                        && submitted.target_id == prompt.target_id
                }) {
                    return LoopAction::Continue;
                }
                self.last_authentication_submission = None;
                match ssh_control::authentication_card(prompt) {
                    Ok(card) => self.state.show_authentication(card),
                    Err(error) => self.state.show_error(error),
                }
            }
            SshEvent::TargetStatus(status) => return self.apply_connection_status(status),
            // Grants, remote operation approvals, worker prompts, and their session-bound events
            // belong to the full pager only.  In particular, never surface an event for another
            // client/session by constructing a card in this temporary manager.
            SshEvent::GrantRequested(_)
            | SshEvent::GrantResolved { .. }
            | SshEvent::GrantCancelled { .. }
            | SshEvent::GrantFailed { .. }
            | SshEvent::BindingRevoked { .. }
            | SshEvent::Worker(_)
            | SshEvent::OperationApproval(_)
            | SshEvent::OperationApprovalExpired { .. }
            | SshEvent::WorkerInstallRequested(_)
            | SshEvent::WorkerInstallProgress(_)
            | SshEvent::SudoAuthentication { .. }
            | SshEvent::SudoAuthenticationResolved { .. } => {}
            SshEvent::Authentication(_) => {}
        }
        LoopAction::Continue
    }

    fn apply_connection_status(&mut self, status: SshTargetStatus) -> LoopAction {
        let target_id = status.target_id.clone();
        // Status broadcasts can belong to another local client's connection
        // attempt. Only our correlated command reply may complete this CLI.
        let failed = status.connection == SshConnectionState::Failed;
        if failed {
            self.state.loading = false;
        }
        self.state
            .apply_target_status(&target_id, status.connection, status.detail);
        LoopAction::Continue
    }

    async fn shutdown(&mut self) {
        self.jobs.abort_all();
        while self.jobs.join_next().await.is_some() {}
    }
}

fn finish_action(start: &SshTuiStart, action: LoopAction) -> Result<Option<SshProjectOpen>> {
    match action {
        LoopAction::Continue => unreachable!("only terminal actions may finish the standalone TUI"),
        LoopAction::ConnectSucceeded => Ok(None),
        LoopAction::Exit(open) => {
            if open.is_none()
                && let SshTuiStart::Connect { target_id } = start
            {
                return Err(anyhow::anyhow!(
                    "SSH connection to '{target_id}' was cancelled before it completed. \
                     Retry with `groky ssh connect {target_id} --interactive`."
                ));
            }
            Ok(open)
        }
    }
}

fn startup_input(input: Event) -> LoopAction {
    match input {
        Event::Key(key)
            if key.kind != KeyEventKind::Release
                && (key.code == KeyCode::Esc
                    || (key.code == KeyCode::Char('c')
                        && key.modifiers.contains(KeyModifiers::CONTROL))) =>
        {
            LoopAction::Exit(None)
        }
        Event::FocusGained
        | Event::FocusLost
        | Event::Key(_)
        | Event::Mouse(_)
        | Event::Paste(_)
        | Event::Resize(_, _) => LoopAction::Continue,
    }
}

async fn run_terminal(start: SshTuiStart) -> Result<Option<SshProjectOpen>> {
    let guard = TerminalGuard::enter()?;
    let mut terminal = match Terminal::new(CrosstermBackend::new(io::stdout())) {
        Ok(terminal) => terminal,
        Err(error) => {
            drop(guard);
            return Err(error.into());
        }
    };
    let theme = Theme::current();
    let mut input_tick = tokio::time::interval(Duration::from_millis(25));
    input_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut sigint = std::pin::pin!(tokio::signal::ctrl_c());
    let mut initialization = Box::pin(async {
        let backend = Arc::new(ssh_control::standalone().await?);
        let client_id = backend.client_id().await?;
        Ok::<_, anyhow::Error>((backend, client_id))
    });
    let mut runner: Option<StandaloneSshRunner> = None;
    let mut dirty = true;

    let result = 'run: loop {
        if dirty {
            let draw_result = terminal.draw(|frame| {
                let area = frame.area();
                frame.render_widget(Clear, area);
                if area.width == 0 || area.height == 0 {
                    return;
                }
                let heading = if runner.is_some() {
                    "SSH management · local-only"
                } else {
                    "Opening local SSH manager…"
                };
                frame.buffer_mut().set_stringn(
                    area.x,
                    area.y,
                    heading,
                    area.width as usize,
                    Style::default().fg(theme.text_secondary),
                );
                if let Some(runner) = runner.as_mut() {
                    let compact = area.height < 16;
                    let _ = render_ssh_modal(
                        frame.buffer_mut(),
                        area,
                        &mut runner.state,
                        compact,
                        &theme,
                    );
                }
            });
            if let Err(error) = draw_result {
                break Err(error.into());
            }
            dirty = false;
        }

        if let Some(active_runner) = runner.as_mut() {
            tokio::select! {
                _ = input_tick.tick() => {
                    loop {
                        let has_input = match event::poll(Duration::ZERO) {
                            Ok(has_input) => has_input,
                            Err(error) => break 'run Err(error.into()),
                        };
                        if !has_input {
                            break;
                        }
                        let input = match event::read() {
                            Ok(input) => input,
                            Err(error) => break 'run Err(error.into()),
                        };
                        let redraw_before_next = match &input {
                            Event::Mouse(_) | Event::Resize(_, _) => true,
                            _ => false,
                        };
                        dirty = true;
                        match active_runner.route_input(input) {
                            LoopAction::Continue => {}
                            action => break 'run finish_action(&start, action),
                        }
                        if redraw_before_next {
                            break;
                        }
                    }
                }
                message = active_runner.messages_rx.recv() => {
                    match message {
                        Some(message) => {
                            dirty = true;
                            match active_runner.route_message(message) {
                                LoopAction::Continue => {}
                                action => break 'run finish_action(&start, action),
                            }
                        }
                        None => break 'run finish_action(&start, LoopAction::Exit(None)),
                    }
                }
                _ = sigint.as_mut() => break 'run finish_action(&start, LoopAction::Exit(None)),
            }
        } else {
            tokio::select! {
                _ = input_tick.tick() => {
                    loop {
                        let has_input = match event::poll(Duration::ZERO) {
                            Ok(has_input) => has_input,
                            Err(error) => break 'run Err(error.into()),
                        };
                        if !has_input {
                            break;
                        }
                        let input = match event::read() {
                            Ok(input) => input,
                            Err(error) => break 'run Err(error.into()),
                        };
                        dirty = true;
                        match startup_input(input) {
                            LoopAction::Continue => {}
                            action => break 'run finish_action(&start, action),
                        }
                    }
                }
                initialized = initialization.as_mut() => {
                    match initialized {
                        Ok((backend, client_id)) => {
                            let mut next_runner =
                                StandaloneSshRunner::new(backend, client_id, start.clone());
                            next_runner.initialize(start.clone());
                            runner = Some(next_runner);
                            dirty = true;
                        }
                        Err(error) => break 'run Err(error),
                    }
                }
                _ = sigint.as_mut() => break 'run finish_action(&start, LoopAction::Exit(None)),
            }
        }
    };

    if let Some(active_runner) = runner.as_mut() {
        active_runner.shutdown().await;
    }
    drop(runner);
    drop(initialization);
    drop(terminal);
    drop(guard);
    result
}

#[cfg(test)]
mod tests {
    use super::{LoopAction, SshTuiStart, finish_action};

    #[test]
    fn cancelled_direct_connect_is_not_reported_as_completion() {
        let result = finish_action(
            &SshTuiStart::Connect {
                target_id: "build-server".into(),
            },
            LoopAction::Exit(None),
        );
        assert!(result.is_err());
    }

    #[test]
    fn connected_direct_connect_completes_without_project_handoff() {
        let result = finish_action(
            &SshTuiStart::Connect {
                target_id: "build-server".into(),
            },
            LoopAction::ConnectSucceeded,
        )
        .expect("connected direct SSH command must complete");
        assert!(result.is_none());
    }
}
