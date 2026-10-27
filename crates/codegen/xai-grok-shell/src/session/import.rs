//! Native persistence for read-only foreign-session imports.
//!
//! The source adapter is the sole reader of a foreign transcript. This module
//! writes a new local session directory only after the complete native snapshot
//! is staged, and never invokes a model or tool while doing so.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use agent_client_protocol as acp;
use chrono::{DateTime, Utc};
use serde::Serialize;
use xai_grok_foreign_sessions::import::{
    ImportCandidate, ImportContent, ImportMessage, ImportedSession,
};

use crate::extensions::notification::{
    CompactionCheckpointInfo, SessionNotification as XaiSessionNotification,
    SessionUpdate as XaiSessionUpdate,
};
use crate::sampling::{AssistantItem, ContentPart, ConversationItem, ToolCall, UserItem};
use crate::session::info::Info;
use crate::session::persistence::{CHAT_FORMAT_VERSION, Summary, sanitize_and_cap_title};
use crate::session::storage::{CHAT_HISTORY_FILE, SUMMARY_FILE, UPDATES_FILE};

const IMPORT_PROVENANCE_FILE: &str = "import_provenance.json";
const CHECKPOINT_SCHEMA_VERSION: u32 = 2;
const HISTORICAL_TOOL_UNAVAILABLE: &str =
    "Historical tool output was not available; the tool was not executed during import.";
const HISTORICAL_TOOL_FAILURE: &str =
    "[Historical tool failed; this result is not a successful execution.]\n";

/// The identity and native location of a newly imported session.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportResult {
    pub session_id: String,
    pub cwd: String,
    pub message_count: usize,
    pub warnings: Vec<String>,
}

/// Import a foreign session into the normal groky home.
pub async fn import_session(
    candidate: ImportCandidate,
    target_cwd: PathBuf,
    model_id: String,
) -> io::Result<ImportResult> {
    import_session_in_root(
        candidate,
        target_cwd,
        model_id,
        crate::util::grok_home::grok_home(),
    )
    .await
}

/// Import a foreign session beneath an explicit groky home.
///
/// The injectable root is intentionally public so callers can smoke-test an
/// import without reading or modifying their real session store.
pub async fn import_session_in_root(
    candidate: ImportCandidate,
    target_cwd: PathBuf,
    model_id: String,
    root: PathBuf,
) -> io::Result<ImportResult> {
    if model_id.trim().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "an imported session requires a current groky model ID",
        ));
    }

    let imported =
        tokio::task::spawn_blocking(move || xai_grok_foreign_sessions::import::load(&candidate))
            .await
            .map_err(|error| {
                io::Error::other(format!("foreign session loader panicked: {error}"))
            })??;

    tokio::task::spawn_blocking(move || {
        write_imported_session(imported, target_cwd, model_id, root)
    })
    .await
    .map_err(|error| io::Error::other(format!("native session import writer panicked: {error}")))?
}

fn write_imported_session(
    imported: ImportedSession,
    target_cwd: PathBuf,
    model_id: String,
    root: PathBuf,
) -> io::Result<ImportResult> {
    let cwd = target_cwd.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "the target working directory is not valid UTF-8",
        )
    })?;
    let cwd = cwd.to_owned();
    let session_id = uuid::Uuid::now_v7().to_string();
    let info = Info {
        id: acp::SessionId::new(session_id.clone()),
        cwd: cwd.clone(),
    };

    let session_parent = crate::util::grok_home::ensure_sessions_cwd_dir_in(&root, &cwd)?;
    let destination = session_parent.join(&session_id);
    ensure_absent(&destination)?;

    let stage = session_parent.join(format!(".{session_id}.import-{}.tmp", uuid::Uuid::now_v7()));
    create_private_dir(&stage)?;
    let mut staged = StagedSession::new(stage);

    let context = context_items(&imported)?;
    let (updates, _) = display_updates(&imported, &session_id)?;
    let now = Utc::now();
    let source_label = source_label(&imported.candidate);
    let mut summary = Summary::new(&info, acp::ModelId::new(model_id))?;
    summary.session_summary = source_label.clone();
    summary.created_at = now;
    summary.updated_at = now;
    summary.last_active_at = Some(now);
    summary.num_chat_messages = context.len();
    summary.grok_home = root.to_str().map(str::to_owned);
    summary.chat_format_version = CHAT_FORMAT_VERSION;
    summary.generated_title = Some(source_label);
    // Imported titles describe foreign history rather than a local human rename.
    summary.title_is_manual = false;
    // Never carry foreign credentials, account slots, agent identity, or permissions.
    summary.vendor_accounts = None;
    summary.agent_id = None;
    summary.attempt_id = None;

    let checkpoint_id = uuid::Uuid::now_v7().to_string();
    let checkpoint_dir = staged.path().join("compaction_checkpoints");
    create_private_dir(&checkpoint_dir)?;
    let checkpoint_file = format!("compaction_checkpoints/{checkpoint_id}.json");
    let prompt_index_at_compaction = context
        .iter()
        .filter(|item| matches!(item, ConversationItem::User(_)))
        .count();
    let checkpoint_created_at = now.to_rfc3339();
    let checkpoint = ImportCheckpoint {
        checkpoint_id: &checkpoint_id,
        prompt_index_at_compaction,
        compacted_history: &context,
        schema_version: CHECKPOINT_SCHEMA_VERSION,
        created_at: &checkpoint_created_at,
        original_user_info: None,
        reread_file_paths: &[],
    };
    write_private_json(
        &checkpoint_dir.join(format!("{checkpoint_id}.json")),
        &checkpoint,
    )?;
    crate::session::storage::sync_dir_durable(&checkpoint_dir)?;

    let mut updates = updates;
    let checkpoint_timestamp = updates
        .last()
        .map(|update| update.timestamp_ms.saturating_add(1))
        .unwrap_or_else(|| source_timestamp_ms(imported.candidate.modified));
    updates.push(HistoricalUpdate::xai(
        checkpoint_timestamp,
        XaiSessionNotification {
            session_id: info.id.clone(),
            update: XaiSessionUpdate::CompactionCheckpoint(Box::new(CompactionCheckpointInfo {
                checkpoint_id,
                prompt_index_at_compaction,
                checkpoint_file,
                auto_continue: None,
                schema_version: CHECKPOINT_SCHEMA_VERSION,
                created_at: checkpoint_created_at,
            })),
            meta: Some(serde_json::Value::Object(timestamp_meta(
                &session_id,
                updates.len(),
                checkpoint_timestamp,
                None,
            ))),
        },
    ));
    summary.num_messages = updates.len();

    write_private_json(&staged.path().join(SUMMARY_FILE), &summary)?;
    write_updates(&staged.path().join(UPDATES_FILE), &updates)?;
    write_chat_history(&staged.path().join(CHAT_HISTORY_FILE), &context)?;
    write_private_json(
        &staged.path().join(IMPORT_PROVENANCE_FILE),
        &ImportProvenance::from_import(&imported, &cwd, &session_id, now),
    )?;
    crate::session::storage::sync_dir_durable(staged.path())?;

    publish_staged_dir(staged.path(), &destination)?;
    if let Err(error) = crate::session::storage::sync_dir_durable(&session_parent) {
        let _ = fs::remove_dir_all(&destination);
        return Err(error);
    }
    staged.publish();

    Ok(ImportResult {
        session_id,
        cwd,
        message_count: imported.messages.len(),
        warnings: imported.warnings,
    })
}

fn source_label(candidate: &ImportCandidate) -> String {
    let title = candidate.title.trim();
    let label = if title.is_empty() {
        format!("Imported from {}", candidate.source)
    } else {
        format!("Imported from {}: {title}", candidate.source)
    };
    sanitize_and_cap_title(&label).unwrap_or_else(|| format!("Imported from {}", candidate.source))
}

fn context_items(imported: &ImportedSession) -> io::Result<Vec<ConversationItem>> {
    let mut context = Vec::with_capacity(imported.context.len());
    for &index in &imported.context {
        let message = imported.messages.get(index).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "foreign import context referenced a missing message",
            )
        })?;
        let item = match message {
            ImportMessage::User { content } => ConversationItem::User(UserItem {
                content: content_parts(content),
                synthetic_reason: Default::default(),
                cwd_generation: None,
                prior_turn_interrupt: None,
                prompt_index: None,
            }),
            ImportMessage::Assistant { text, tool_calls } => {
                ConversationItem::Assistant(AssistantItem {
                    content: Arc::<str>::from(text.as_str()),
                    tool_calls: tool_calls
                        .iter()
                        .map(|call| ToolCall {
                            id: Arc::<str>::from(call.id.as_str()),
                            name: call.name.clone(),
                            arguments: Arc::<str>::from(call.arguments.as_str()),
                        })
                        .collect(),
                    model_id: None,
                    model_fingerprint: None,
                    reasoning_effort: None,
                })
            }
            ImportMessage::ToolResult {
                id,
                content,
                is_error,
            } => tool_result_item(id, content, *is_error),
            // A foreign compaction summary is retained as untrusted historical
            // user content, never elevated into the groky system prompt.
            ImportMessage::Summary { text } => {
                ConversationItem::user(format!("[Imported conversation summary]\n{text}"))
            }
            // The adapter deliberately excludes reasoning from effective context.
            ImportMessage::Reasoning { .. } => continue,
        };
        context.push(item);
    }
    Ok(context)
}

fn tool_result_item(id: &str, content: &[ImportContent], is_error: bool) -> ConversationItem {
    let mut text = if is_error {
        HISTORICAL_TOOL_FAILURE.to_owned()
    } else {
        String::new()
    };
    let mut images = Vec::new();
    for part in content {
        match part {
            ImportContent::Text(value) => text.push_str(value),
            ImportContent::Image { url } => images.push(ContentPart::Image {
                url: Arc::<str>::from(url.as_str()),
            }),
        }
    }
    ConversationItem::tool_result_with_images(id, text, images)
}

fn content_parts(content: &[ImportContent]) -> Vec<ContentPart> {
    content
        .iter()
        .map(|part| match part {
            ImportContent::Text(text) => ContentPart::Text {
                text: Arc::<str>::from(text.as_str()),
            },
            ImportContent::Image { url } => ContentPart::Image {
                url: Arc::<str>::from(url.as_str()),
            },
        })
        .collect()
}

fn display_updates(
    imported: &ImportedSession,
    session_id: &str,
) -> io::Result<(Vec<HistoricalUpdate>, usize)> {
    let mut updates = Vec::with_capacity(imported.messages.len().saturating_mul(2));
    let mut timeline = Timeline::new(imported.candidate.modified);
    let mut open_calls = Vec::new();
    let mut active_turn_start = None;

    for message in &imported.messages {
        match message {
            ImportMessage::User { content } => {
                let timestamp = timeline.next();
                active_turn_start = Some(timestamp);
                let blocks = acp_blocks(content);
                if blocks.is_empty() {
                    push_acp_update(
                        &mut updates,
                        session_id,
                        timestamp,
                        active_turn_start,
                        acp::SessionUpdate::UserMessageChunk(text_chunk(String::new())),
                    );
                } else {
                    for block in blocks {
                        push_acp_update(
                            &mut updates,
                            session_id,
                            timestamp,
                            active_turn_start,
                            acp::SessionUpdate::UserMessageChunk(acp::ContentChunk::new(block)),
                        );
                    }
                }
            }
            ImportMessage::Assistant { text, tool_calls } => {
                let timestamp = timeline.next();
                let turn_start = Some(current_turn_start(&mut active_turn_start, timestamp));
                if !text.is_empty() || tool_calls.is_empty() {
                    push_acp_update(
                        &mut updates,
                        session_id,
                        timestamp,
                        turn_start,
                        acp::SessionUpdate::AgentMessageChunk(text_chunk(text.clone())),
                    );
                }
                for call in tool_calls {
                    let raw_input = serde_json::from_str::<serde_json::Value>(&call.arguments)
                        .map_err(|error| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("validated import tool arguments no longer parse: {error}"),
                            )
                        })?;
                    open_calls.push(call.id.clone());
                    push_acp_update(
                        &mut updates,
                        session_id,
                        timeline.next(),
                        turn_start,
                        acp::SessionUpdate::ToolCall(
                            acp::ToolCall::new(
                                acp::ToolCallId::new(Arc::<str>::from(call.id.as_str())),
                                call.name.clone(),
                            )
                            .kind(acp::ToolKind::Other)
                            .status(acp::ToolCallStatus::Pending)
                            .raw_input(Some(raw_input)),
                        ),
                    );
                }
            }
            ImportMessage::ToolResult {
                id,
                content,
                is_error,
            } if open_calls
                .iter()
                .position(|call_id| call_id == id)
                .map(|index| open_calls.remove(index))
                .is_some() =>
            {
                let timestamp = timeline.next();
                let turn_start = Some(current_turn_start(&mut active_turn_start, timestamp));
                let mut blocks = acp_blocks(content);
                if *is_error {
                    blocks.insert(
                        0,
                        acp::ContentBlock::Text(acp::TextContent::new(HISTORICAL_TOOL_FAILURE)),
                    );
                }
                push_acp_update(
                    &mut updates,
                    session_id,
                    timestamp,
                    turn_start,
                    acp::SessionUpdate::ToolCallUpdate(acp::ToolCallUpdate::new(
                        acp::ToolCallId::new(Arc::<str>::from(id.as_str())),
                        acp::ToolCallUpdateFields::new()
                            .status(Some(if *is_error {
                                acp::ToolCallStatus::Failed
                            } else {
                                acp::ToolCallStatus::Completed
                            }))
                            .content(Some(
                                blocks.into_iter().map(acp::ToolCallContent::from).collect(),
                            )),
                    )),
                );
            }
            ImportMessage::ToolResult {
                id,
                content,
                is_error,
            } => {
                let timestamp = timeline.next();
                let turn_start = Some(current_turn_start(&mut active_turn_start, timestamp));
                push_acp_update(
                    &mut updates,
                    session_id,
                    timestamp,
                    turn_start,
                    acp::SessionUpdate::AgentMessageChunk(text_chunk(format!(
                        "[Historical tool result {id}; originating call is unavailable in this imported display history; error={is_error}]"
                    ))),
                );
                for block in acp_blocks(content) {
                    push_acp_update(
                        &mut updates,
                        session_id,
                        timeline.next(),
                        turn_start,
                        acp::SessionUpdate::AgentMessageChunk(acp::ContentChunk::new(block)),
                    );
                }
            }
            ImportMessage::Summary { text } => {
                let timestamp = timeline.next();
                let turn_start = Some(current_turn_start(&mut active_turn_start, timestamp));
                push_acp_update(
                    &mut updates,
                    session_id,
                    timestamp,
                    turn_start,
                    acp::SessionUpdate::AgentMessageChunk(text_chunk(format!(
                        "[Imported conversation summary]\n{text}"
                    ))),
                );
            }
            ImportMessage::Reasoning { text } if !text.is_empty() => {
                let timestamp = timeline.next();
                let turn_start = Some(current_turn_start(&mut active_turn_start, timestamp));
                push_acp_update(
                    &mut updates,
                    session_id,
                    timestamp,
                    turn_start,
                    acp::SessionUpdate::AgentThoughtChunk(text_chunk(text.clone())),
                );
            }
            ImportMessage::Reasoning { .. } => {}
        }
    }

    // Historical sessions can end during a tool call. Mark those records as
    // finished evidence so opening this session never creates runnable work.
    for id in open_calls {
        let timestamp = timeline.next();
        push_acp_update(
            &mut updates,
            session_id,
            timestamp,
            Some(current_turn_start(&mut active_turn_start, timestamp)),
            acp::SessionUpdate::ToolCallUpdate(acp::ToolCallUpdate::new(
                acp::ToolCallId::new(Arc::<str>::from(id)),
                acp::ToolCallUpdateFields::new()
                    .status(Some(acp::ToolCallStatus::Failed))
                    .content(Some(vec![acp::ToolCallContent::from(
                        acp::ContentBlock::Text(acp::TextContent::new(HISTORICAL_TOOL_UNAVAILABLE)),
                    )])),
            )),
        );
    }

    let message_count = updates.len();
    Ok((updates, message_count))
}

fn current_turn_start(active_turn_start: &mut Option<u64>, timestamp: u64) -> u64 {
    *active_turn_start.get_or_insert(timestamp)
}

fn acp_blocks(content: &[ImportContent]) -> Vec<acp::ContentBlock> {
    content
        .iter()
        .map(|part| match part {
            ImportContent::Text(text) => {
                acp::ContentBlock::Text(acp::TextContent::new(text.clone()))
            }
            ImportContent::Image { url } => acp::ContentBlock::Image(image_from_url(url)),
        })
        .collect()
}

fn image_from_url(url: &str) -> acp::ImageContent {
    let mime_type = url
        .strip_prefix("data:")
        .and_then(|rest| rest.split_once(';').map(|(mime, _)| mime))
        .filter(|mime| mime.starts_with("image/"))
        .unwrap_or("image/*");
    acp::ImageContent::new(String::new(), mime_type).uri(Some(url.to_owned()))
}

fn text_chunk(text: String) -> acp::ContentChunk {
    acp::ContentChunk::new(acp::ContentBlock::Text(acp::TextContent::new(text)))
}

fn push_acp_update(
    updates: &mut Vec<HistoricalUpdate>,
    session_id: &str,
    timestamp_ms: u64,
    turn_start_ms: Option<u64>,
    update: acp::SessionUpdate,
) {
    let event_index = updates.len();
    let notification =
        acp::SessionNotification::new(acp::SessionId::new(session_id.to_owned()), update).meta(
            Some(timestamp_meta(
                session_id,
                event_index,
                timestamp_ms,
                turn_start_ms,
            )),
        );
    updates.push(HistoricalUpdate::acp(timestamp_ms, notification));
}

fn timestamp_meta(
    session_id: &str,
    event_index: usize,
    timestamp_ms: u64,
    turn_start_ms: Option<u64>,
) -> acp::Meta {
    let mut meta = acp::Meta::new();
    meta.insert(
        "eventId".to_owned(),
        format!("import-{session_id}-{event_index}").into(),
    );
    meta.insert("agentTimestampMs".to_owned(), timestamp_ms.into());
    if let Some(turn_start_ms) = turn_start_ms {
        meta.insert("turnStartMs".to_owned(), turn_start_ms.into());
    }
    meta
}

struct Timeline {
    next_ms: u64,
}

impl Timeline {
    fn new(source_modified: SystemTime) -> Self {
        Self {
            next_ms: source_timestamp_ms(source_modified),
        }
    }

    fn next(&mut self) -> u64 {
        let timestamp = self.next_ms;
        self.next_ms = self.next_ms.saturating_add(1);
        timestamp
    }
}

fn source_timestamp_ms(timestamp: SystemTime) -> u64 {
    timestamp
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

enum HistoricalNotification {
    Acp(acp::SessionNotification),
    Xai(XaiSessionNotification),
}

struct HistoricalUpdate {
    timestamp_ms: u64,
    notification: HistoricalNotification,
}

impl HistoricalUpdate {
    fn acp(timestamp_ms: u64, notification: acp::SessionNotification) -> Self {
        Self {
            timestamp_ms,
            notification: HistoricalNotification::Acp(notification),
        }
    }

    fn xai(timestamp_ms: u64, notification: XaiSessionNotification) -> Self {
        Self {
            timestamp_ms,
            notification: HistoricalNotification::Xai(notification),
        }
    }
}

#[derive(Serialize)]
struct UpdateEnvelope<'a, T> {
    timestamp: u64,
    method: &'static str,
    params: &'a T,
}

fn write_updates(path: &Path, updates: &[HistoricalUpdate]) -> io::Result<()> {
    write_private(path, |file| write_update_lines(file, updates))
}

fn write_update_lines(writer: &mut impl Write, updates: &[HistoricalUpdate]) -> io::Result<()> {
    for update in updates {
        match &update.notification {
            HistoricalNotification::Acp(notification) => serde_json::to_writer(
                &mut *writer,
                &UpdateEnvelope {
                    timestamp: update.timestamp_ms / 1_000,
                    method: "session/update",
                    params: notification,
                },
            ),
            HistoricalNotification::Xai(notification) => serde_json::to_writer(
                &mut *writer,
                &UpdateEnvelope {
                    timestamp: update.timestamp_ms / 1_000,
                    method: "_x.ai/session/update",
                    params: notification,
                },
            ),
        }
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        writer.write_all(b"\n")?;
    }
    Ok(())
}

fn write_chat_history(path: &Path, messages: &[ConversationItem]) -> io::Result<()> {
    write_private(path, |file| {
        for message in messages {
            serde_json::to_writer(&mut *file, message)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            file.write_all(b"\n")?;
        }
        Ok(())
    })
}

fn write_private_json(path: &Path, value: &impl Serialize) -> io::Result<()> {
    write_private(path, |file| {
        serde_json::to_writer_pretty(file, value)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    })
}

fn write_private(path: &Path, write: impl FnOnce(&mut File) -> io::Result<()>) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    if let Err(error) =
        write(&mut file).and_then(|()| crate::session::storage::sync_file_durable(&file))
    {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(error);
    }
    Ok(())
}

fn create_private_dir(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder.create(path)?;
    }
    #[cfg(not(unix))]
    fs::create_dir(path)?;
    crate::util::grok_home::set_dir_owner_only(path);
    Ok(())
}

fn ensure_absent(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("refusing to replace existing session {}", path.display()),
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn path_to_cstring(path: &Path) -> io::Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;

    std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "session path contained an interior NUL byte",
        )
    })
}

#[cfg(target_os = "macos")]
fn publish_staged_dir(stage: &Path, destination: &Path) -> io::Result<()> {
    let stage = path_to_cstring(stage)?;
    let destination = path_to_cstring(destination)?;
    let result =
        unsafe { libc::renamex_np(stage.as_ptr(), destination.as_ptr(), libc::RENAME_EXCL) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(target_os = "linux")]
fn publish_staged_dir(stage: &Path, destination: &Path) -> io::Result<()> {
    let stage = path_to_cstring(stage)?;
    let destination = path_to_cstring(destination)?;
    let result = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            stage.as_ptr(),
            libc::AT_FDCWD,
            destination.as_ptr(),
            1,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(all(unix, not(any(target_os = "macos", target_os = "linux"))))]
fn publish_staged_dir(_stage: &Path, _destination: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "atomic no-replace session publication is unsupported on this platform",
    ))
}

#[cfg(windows)]
fn publish_staged_dir(stage: &Path, destination: &Path) -> io::Result<()> {
    ensure_absent(destination)?;
    fs::rename(stage, destination)
}

#[cfg(not(any(unix, windows)))]
fn publish_staged_dir(_stage: &Path, _destination: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "atomic no-replace session publication is unsupported on this platform",
    ))
}

struct StagedSession {
    path: PathBuf,
    published: bool,
}

impl StagedSession {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            published: false,
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn publish(&mut self) {
        self.published = true;
    }
}

impl Drop for StagedSession {
    fn drop(&mut self) {
        if !self.published {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
struct ImportCheckpoint<'a> {
    checkpoint_id: &'a str,
    prompt_index_at_compaction: usize,
    compacted_history: &'a [ConversationItem],
    schema_version: u32,
    created_at: &'a str,
    original_user_info: Option<&'a str>,
    reread_file_paths: &'a [String],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ImportProvenance {
    schema_version: u32,
    session_id: String,
    imported_at: String,
    target_cwd: String,
    source: String,
    source_id: String,
    source_path: String,
    source_cwd: String,
    source_leaf_id: Option<String>,
    source_modified_at: String,
    warnings: Vec<String>,
}

impl ImportProvenance {
    fn from_import(
        imported: &ImportedSession,
        target_cwd: &str,
        session_id: &str,
        imported_at: DateTime<Utc>,
    ) -> Self {
        let candidate = &imported.candidate;
        Self {
            schema_version: 1,
            session_id: session_id.to_owned(),
            imported_at: imported_at.to_rfc3339(),
            target_cwd: target_cwd.to_owned(),
            source: candidate.source.as_str().to_owned(),
            source_id: candidate.id.clone(),
            source_path: candidate.path.to_string_lossy().into_owned(),
            source_cwd: candidate.cwd.to_string_lossy().into_owned(),
            source_leaf_id: candidate.leaf_id.clone(),
            source_modified_at: DateTime::<Utc>::from(candidate.modified).to_rfc3339(),
            warnings: imported.warnings.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::storage::{JsonlStorageAdapter, StorageAdapter};
    use std::time::Duration;

    fn candidate(path: PathBuf) -> ImportCandidate {
        ImportCandidate {
            source: xai_grok_foreign_sessions::import::ImportSource::Pi,
            id: "source-session".to_owned(),
            path,
            cwd: PathBuf::from("/foreign/workspace"),
            title: "Imported example".to_owned(),
            modified: UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            leaf_id: Some("leaf".to_owned()),
        }
    }

    fn imported(source: PathBuf) -> ImportedSession {
        let mut imported = ImportedSession::new(candidate(source));
        imported.push(
            ImportMessage::User {
                content: vec![ImportContent::Text("remember this context".to_owned())],
            },
            true,
        );
        imported.push(
            ImportMessage::Assistant {
                text: "I will inspect it.".to_owned(),
                tool_calls: vec![xai_grok_foreign_sessions::import::ImportToolCall {
                    id: "call-1".to_owned(),
                    name: "read".to_owned(),
                    arguments: "{\"path\":\"src/lib.rs\"}".to_owned(),
                }],
            },
            true,
        );
        imported.push(
            ImportMessage::ToolResult {
                id: "call-1".to_owned(),
                content: vec![ImportContent::Text("file contents".to_owned())],
                is_error: false,
            },
            true,
        );
        imported
    }

    #[tokio::test]
    async fn import_survives_rebuild_without_mutating_its_source() {
        let root = tempfile::tempdir().unwrap();
        let source_dir = tempfile::tempdir().unwrap();
        let source = source_dir.path().join("source.jsonl");
        fs::write(&source, b"foreign transcript remains read-only\n").unwrap();
        let before = fs::read(&source).unwrap();
        let target = PathBuf::from("/target/workspace");

        let result = write_imported_session(
            imported(source.clone()),
            target.clone(),
            "grok-current".to_owned(),
            root.path().to_path_buf(),
        )
        .unwrap();
        assert_eq!(fs::read(&source).unwrap(), before);

        let info = Info {
            id: acp::SessionId::new(result.session_id.clone()),
            cwd: target.to_string_lossy().into_owned(),
        };
        let storage = JsonlStorageAdapter::with_root(root.path().to_path_buf());
        let restored = storage.load_session(&info).await.unwrap();
        assert!(restored
            .chat_history
            .iter()
            .any(|item| matches!(item, ConversationItem::User(user) if user.content.iter().any(|part| matches!(part, ContentPart::Text { text } if text.as_ref() == "remember this context")))));

        let dir = crate::util::grok_home::sessions_cwd_dir_in(root.path(), &info.cwd)
            .join(&result.session_id);
        fs::remove_file(dir.join(CHAT_HISTORY_FILE)).unwrap();
        let rebuilt = storage.load_session(&info).await.unwrap();
        assert!(rebuilt
            .chat_history
            .iter()
            .any(|item| matches!(item, ConversationItem::ToolResult(result) if result.tool_call_id == "call-1")));
        assert!(
            !rebuilt
                .chat_history
                .iter()
                .any(|item| matches!(item, ConversationItem::System(_)))
        );
    }

    #[test]
    fn interrupted_historical_calls_are_closed_without_execution() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source.jsonl");
        let mut imported = ImportedSession::new(candidate(source));
        imported.push(
            ImportMessage::Assistant {
                text: "Interrupted".to_owned(),
                tool_calls: vec![xai_grok_foreign_sessions::import::ImportToolCall {
                    id: "call-1".to_owned(),
                    name: "bash".to_owned(),
                    arguments: "{\"command\":\"rm -rf /\"}".to_owned(),
                }],
            },
            false,
        );
        imported.push(
            ImportMessage::User {
                content: vec![ImportContent::Text("continue safely".to_owned())],
            },
            true,
        );

        let (updates, _) = display_updates(&imported, "native").unwrap();
        let mut serialized = Vec::new();
        write_update_lines(&mut serialized, &updates).unwrap();
        let serialized = String::from_utf8(serialized).unwrap();
        assert!(serialized.contains("failed"));
        assert!(serialized.contains(HISTORICAL_TOOL_UNAVAILABLE));
    }
}
