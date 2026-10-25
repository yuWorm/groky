use crate::auth::{
    InteractionError, Secret, SshError, SudoInteraction, SudoPasswordPrompt,
};
use crate::connection::{
    ClosingChannel, ConnectionEntry, SshCommand, SshCommandEvent, await_command_acceptance,
    generation_is_current, open_session_channel, queue_initial_command_event, send_exec_request,
};
use russh::ChannelMsg;
use std::collections::VecDeque;
use std::io::Cursor;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

const SUDO_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(300);
const SUDO_IO_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_SUDO_HANDSHAKE_BYTES: usize = 64 * 1024;

pub(crate) async fn exec_sudo_command(
    entry: Arc<ConnectionEntry>,
    generation: u64,
    target_id: &str,
    username: &str,
    command: &str,
    cwd: &str,
    interaction: Arc<dyn SudoInteraction>,
) -> Result<SshCommand, SshError> {
    let protocol = SudoProtocol::new(command, cwd)?;

    // Fail closed before starting a remote root-capable command. The backend
    // deliberately keeps this approval separate from ordinary execute policy.
    timeout(SUDO_HANDSHAKE_TIMEOUT, interaction.authorize_execution())
        .await
        .map_err(|_| SshError::SudoHandshakeTimeout)?
        .map_err(sudo_authorization_error)?;
    if !generation_is_current(&entry, generation) {
        return Err(SshError::Disconnected);
    }

    let mut channel = open_session_channel(&entry, generation, true).await?;
    if let Err(error) = send_exec_request(&channel, &protocol.remote_command).await {
        let _ = channel.close().await;
        return Err(error);
    }
    let (initial, finished) = match await_command_acceptance(&mut channel).await {
        Ok(result) => result,
        Err(error) => {
            let _ = channel.close().await;
            return Err(error);
        }
    };
    if finished {
        let _ = channel.close().await;
        return Err(SshError::SudoUnavailable);
    }

    let pending = match timeout(
        SUDO_HANDSHAKE_TIMEOUT,
        await_sudo_ready(
            &mut channel,
            initial,
            &protocol,
            &entry,
            generation,
            target_id,
            username,
            interaction,
        ),
    )
    .await
    {
        Ok(Ok(pending)) => pending,
        Ok(Err(error)) => {
            let _ = channel.close().await;
            return Err(error);
        }
        Err(_) => {
            let _ = channel.close().await;
            return Err(SshError::SudoHandshakeTimeout);
        }
    };

    if !generation_is_current(&entry, generation) {
        let _ = channel.close().await;
        return Err(SshError::Disconnected);
    }
    Ok(SshCommand {
        channel,
        entry,
        generation,
        pending,
        finished: false,
    })
}

#[allow(clippy::too_many_arguments)]
async fn await_sudo_ready(
    channel: &mut ClosingChannel,
    mut initial: VecDeque<SshCommandEvent>,
    protocol: &SudoProtocol,
    entry: &Arc<ConnectionEntry>,
    generation: u64,
    target_id: &str,
    username: &str,
    interaction: Arc<dyn SudoInteraction>,
) -> Result<VecDeque<SshCommandEvent>, SshError> {
    let mut scanner = SudoMarkerScanner::new(&protocol.prompt_marker, &protocol.ready_marker);
    let mut state = SudoHandshakeState::AwaitingPromptOrReady;

    loop {
        let event = next_handshake_event(channel, &mut initial).await?;
        if !generation_is_current(entry, generation) {
            return Err(SshError::Disconnected);
        }
        match event {
            HandshakeEvent::Stdout => {
                // Nothing can legitimately be command output before the GO
                // gate. Do not expose pre-authorization process output.
            }
            HandshakeEvent::Stderr(data) => {
                let Some(DetectedMarkerWithTrailing {
                    marker,
                    mut trailing,
                }) = scanner.push(&data)?
                else {
                    continue;
                };
                match state.observe(marker)? {
                    SudoMarkerAction::RequestPassword => {
                        trailing.zeroize();
                        if !generation_is_current(entry, generation) {
                            return Err(SshError::Disconnected);
                        }
                        let password = interaction
                            .request_password(SudoPasswordPrompt {
                                challenge_id: Uuid::new_v4(),
                                connection_generation: generation,
                                target_id: target_id.to_owned(),
                                username: username.to_owned(),
                            })
                            .await?;
                        // A password response is not authority by itself: an
                        // approval can be revoked while a password card is open.
                        interaction
                            .authorize_execution()
                            .await
                            .map_err(sudo_authorization_error)?;
                        if !generation_is_current(entry, generation) {
                            return Err(SshError::Disconnected);
                        }
                        submit_password(channel, password).await?;
                    }
                    SudoMarkerAction::SendGo => {
                        interaction
                            .authorize_execution()
                            .await
                            .map_err(sudo_authorization_error)?;
                        if !generation_is_current(entry, generation) {
                            return Err(SshError::Disconnected);
                        }
                        send_go_and_close_stdin(channel, &protocol.go_line).await?;
                        let mut pending = VecDeque::new();
                        let mut pending_bytes = 0;
                        if !trailing.is_empty() {
                            queue_initial_command_event(
                                &mut pending,
                                &mut pending_bytes,
                                SshCommandEvent::Stderr(trailing),
                            )?;
                        }
                        // Exec acceptance can race with the marker. Events
                        // already buffered after READY belong to the command.
                        for event in initial.drain(..) {
                            queue_initial_command_event(
                                &mut pending,
                                &mut pending_bytes,
                                event,
                            )?;
                        }
                        return Ok(pending);
                    }
                }
            }
            HandshakeEvent::Closed => {
                return Err(if state.password_was_requested() {
                    SshError::SudoAuthenticationFailed
                } else {
                    SshError::SudoUnavailable
                });
            }
        }
    }
}

async fn next_handshake_event(
    channel: &mut ClosingChannel,
    initial: &mut VecDeque<SshCommandEvent>,
) -> Result<HandshakeEvent, SshError> {
    loop {
        if let Some(event) = initial.pop_front() {
            return Ok(match event {
                SshCommandEvent::Stdout(_) => HandshakeEvent::Stdout,
                SshCommandEvent::Stderr(data) => HandshakeEvent::Stderr(data),
                SshCommandEvent::ExitStatus(_) | SshCommandEvent::ExitSignal(_) => {
                    HandshakeEvent::Closed
                }
            });
        }

        let Some(message) = channel.wait().await else {
            return Ok(HandshakeEvent::Closed);
        };
        match message {
            ChannelMsg::Data { .. } => return Ok(HandshakeEvent::Stdout),
            ChannelMsg::ExtendedData { data, .. } => {
                return Ok(HandshakeEvent::Stderr(data.to_vec()));
            }
            ChannelMsg::ExitStatus { .. }
            | ChannelMsg::ExitSignal { .. }
            | ChannelMsg::Eof
            | ChannelMsg::Close
            | ChannelMsg::Failure
            | ChannelMsg::OpenFailure(_) => return Ok(HandshakeEvent::Closed),
            _ => continue,
        }
    }
}

async fn submit_password(channel: &ClosingChannel, password: Secret) -> Result<(), SshError> {
    let mut password = password.into_bytes();
    if password
        .iter()
        .any(|byte| matches!(byte, b'\0' | b'\r' | b'\n'))
    {
        return Err(SshError::InvalidSudoPassword);
    }
    password.push(b'\n');
    let result = timeout(
        SUDO_IO_TIMEOUT,
        channel.data(Cursor::new(password.as_slice())),
    )
    .await
    .map_err(|_| SshError::SudoHandshakeTimeout)?
    .map_err(|_| SshError::Transport);
    password.zeroize();
    result
}

async fn send_go_and_close_stdin(channel: &ClosingChannel, go_line: &str) -> Result<(), SshError> {
    let mut go_line = Zeroizing::new(go_line.as_bytes().to_vec());
    go_line.push(b'\n');
    let result = timeout(
        SUDO_IO_TIMEOUT,
        channel.data(Cursor::new(go_line.as_slice())),
    )
    .await
    .map_err(|_| SshError::SudoHandshakeTimeout)?
    .map_err(|_| SshError::Transport);
    go_line.zeroize();
    result?;
    timeout(SUDO_IO_TIMEOUT, channel.eof())
        .await
        .map_err(|_| SshError::SudoHandshakeTimeout)?
        .map_err(|_| SshError::Transport)
}

fn sudo_authorization_error(error: InteractionError) -> SshError {
    match error {
        InteractionError::Rejected => SshError::SudoAuthorizationDenied,
        other => SshError::Interaction(other),
    }
}

enum HandshakeEvent {
    Stdout,
    Stderr(Vec<u8>),
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DetectedMarker {
    Prompt,
    Ready,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SudoHandshakeState {
    AwaitingPromptOrReady,
    AwaitingReadyAfterPassword,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SudoMarkerAction {
    RequestPassword,
    SendGo,
}

impl SudoHandshakeState {
    fn observe(&mut self, marker: DetectedMarker) -> Result<SudoMarkerAction, SshError> {
        match (*self, marker) {
            (Self::AwaitingPromptOrReady, DetectedMarker::Prompt) => {
                *self = Self::AwaitingReadyAfterPassword;
                Ok(SudoMarkerAction::RequestPassword)
            }
            (_, DetectedMarker::Ready) => Ok(SudoMarkerAction::SendGo),
            (Self::AwaitingReadyAfterPassword, DetectedMarker::Prompt) => {
                // A repeated prompt is a failed password. Never retry it
                // automatically, and never request another secret.
                Err(SshError::SudoAuthenticationFailed)
            }
        }
    }

    const fn password_was_requested(self) -> bool {
        matches!(self, Self::AwaitingReadyAfterPassword)
    }
}

struct SudoMarkerScanner<'a> {
    prompt: &'a [u8],
    ready: &'a [u8],
    buffer: Vec<u8>,
    received: usize,
}

impl<'a> SudoMarkerScanner<'a> {
    fn new(prompt: &'a str, ready: &'a str) -> Self {
        Self {
            prompt: prompt.as_bytes(),
            ready: ready.as_bytes(),
            buffer: Vec::new(),
            received: 0,
        }
    }

    fn push(&mut self, bytes: &[u8]) -> Result<Option<DetectedMarkerWithTrailing>, SshError> {
        self.received = self
            .received
            .checked_add(bytes.len())
            .ok_or(SshError::SudoProtocol)?;
        if self.received > MAX_SUDO_HANDSHAKE_BYTES {
            return Err(SshError::SudoProtocol);
        }
        self.buffer.extend_from_slice(bytes);

        let prompt = find_subslice(&self.buffer, self.prompt).map(|position| (position, DetectedMarker::Prompt));
        let ready = find_subslice(&self.buffer, self.ready).map(|position| (position, DetectedMarker::Ready));
        let Some((position, marker)) = (match (prompt, ready) {
            (Some(left), Some(right)) => Some(if left.0 <= right.0 { left } else { right }),
            (Some(marker), None) | (None, Some(marker)) => Some(marker),
            (None, None) => None,
        }) else {
            self.retain_possible_marker_prefix();
            return Ok(None);
        };

        let marker_length = match marker {
            DetectedMarker::Prompt => self.prompt.len(),
            DetectedMarker::Ready => self.ready.len(),
        };
        let trailing = self.buffer.split_off(
            position
                .checked_add(marker_length)
                .ok_or(SshError::SudoProtocol)?,
        );
        self.buffer.zeroize();
        Ok(Some(DetectedMarkerWithTrailing { marker, trailing }))
    }

    fn retain_possible_marker_prefix(&mut self) {
        let retain = self
            .prompt
            .len()
            .max(self.ready.len())
            .saturating_sub(1);
        let discard = self.buffer.len().saturating_sub(retain);
        if discard == 0 {
            return;
        }
        drop(self.buffer.drain(..discard));
    }
}

impl Drop for SudoMarkerScanner<'_> {
    fn drop(&mut self) {
        self.buffer.zeroize();
    }
}

struct DetectedMarkerWithTrailing {
    marker: DetectedMarker,
    trailing: Vec<u8>,
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|candidate| candidate == needle)
}


struct SudoProtocol {
    prompt_marker: String,
    ready_marker: String,
    go_line: String,
    remote_command: String,
}

impl SudoProtocol {
    fn new(command: &str, cwd: &str) -> Result<Self, SshError> {
        if command.as_bytes().contains(&b'\0') || cwd.as_bytes().contains(&b'\0') {
            return Err(SshError::InvalidSudoInput);
        }
        let prompt_marker = random_marker("PROMPT");
        let ready_marker = random_marker("READY");
        let go_line = format!("GO:{}", random_marker("NONCE"));
        let wrapper = format!(
            "printf '%s' {} >&2; IFS= read -r groky_sudo_gate || exit 125; [ \"$groky_sudo_gate\" = {} ] || exit 125; cd -- {} || exit 125; exec </dev/null; exec sh -c {}",
            shell_quote(&ready_marker),
            shell_quote(&go_line),
            shell_quote(cwd),
            shell_quote(command),
        );
        let remote_command = format!(
            "sudo -k -S -p {} -u root -- sh -c {}",
            shell_quote(&prompt_marker),
            shell_quote(&wrapper),
        );
        Ok(Self {
            prompt_marker,
            ready_marker,
            go_line,
            remote_command,
        })
    }
}

fn random_marker(label: &str) -> String {
    format!("__GROKY_SUDO_{label}_{}__", Uuid::new_v4().simple())
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

#[cfg(test)]
mod tests {
    use super::{
        DetectedMarker, SudoHandshakeState, SudoMarkerAction, SudoMarkerScanner, SudoProtocol,
        shell_quote,
    };
    use crate::auth::SshError;

    #[test]
    fn marker_scanner_waits_for_a_complete_split_marker() {
        let mut scanner = SudoMarkerScanner::new("<PROMPT>", "<READY>");
        assert!(scanner.push(b"status <REA").unwrap().is_none());
        let marker = scanner.push(b"DY>\noutput").unwrap().unwrap();
        assert_eq!(marker.marker, DetectedMarker::Ready);
        assert_eq!(marker.trailing, b"\noutput");
    }

    #[test]
    fn nopasswd_ready_gate_never_requests_a_password() {
        let mut state = SudoHandshakeState::AwaitingPromptOrReady;
        assert_eq!(
            state.observe(DetectedMarker::Ready).unwrap(),
            SudoMarkerAction::SendGo
        );
    }

    #[test]
    fn password_failure_does_not_trigger_a_second_prompt() {
        let mut state = SudoHandshakeState::AwaitingPromptOrReady;
        assert_eq!(
            state.observe(DetectedMarker::Prompt).unwrap(),
            SudoMarkerAction::RequestPassword
        );
        assert!(matches!(
            state.observe(DetectedMarker::Prompt),
            Err(SshError::SudoAuthenticationFailed)
        ));
    }

    #[test]
    fn root_command_rejects_nul_before_opening_a_channel() {
        assert!(matches!(
            SudoProtocol::new("id\0-u", "/tmp"),
            Err(SshError::InvalidSudoInput)
        ));
        assert!(matches!(
            SudoProtocol::new("id -u", "/tmp\0"),
            Err(SshError::InvalidSudoInput)
        ));
    }

    #[test]
    fn root_shell_quoting_preserves_literal_input() {
        let value = "a'b\n$HOME; `id` \"quoted\"";
        let output = std::process::Command::new("sh")
            .args(["-c", &format!("printf '%s' {}", shell_quote(value))])
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, value.as_bytes());
    }
}
