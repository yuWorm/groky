use std::collections::HashSet;
use std::io;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value, json};

use super::common::{
    invalid, json_head, json_lines_with_warnings, matches_cwd, modified, short_title, walk_files,
};
use super::*;

const DISCOVERY_READ_BYTES: u64 = 64 * 1024;
const MAX_DISCOVERY_DEPTH: usize = 4;

#[derive(Clone)]
struct SessionMeta {
    id: String,
    cwd: PathBuf,
    history_base: Option<HistoryReference>,
    fork: Option<HistoryReference>,
    fork_without_cutoff: Option<String>,
    parent_thread_id: Option<String>,
}

#[derive(Clone)]
struct HistoryReference {
    id: String,
    end_ordinal_exclusive: u64,
}

#[derive(Clone, Copy)]
struct ReplayRecord<'a> {
    value: &'a Value,
    replacement_history: bool,
}

impl<'a> ReplayRecord<'a> {
    fn source(value: &'a Value) -> Self {
        Self {
            value,
            replacement_history: false,
        }
    }

    fn replacement(value: &'a Value) -> Self {
        Self {
            value,
            replacement_history: true,
        }
    }
}

enum CompactionCheckpoint<'a> {
    Replacement {
        position: usize,
        replacement: &'a [Value],
        summary: Option<&'a str>,
    },
    Summary {
        position: usize,
        summary: &'a str,
    },
}

pub(super) fn discover(cwd: Option<&Path>, out: &mut ImportDiscovery) {
    let Some(root) = codex_home() else {
        return;
    };
    let paths = match rollout_paths(&root) {
        Ok(paths) => paths,
        Err(error) => {
            out.warnings.push(format!(
                "Could not scan Codex sessions in {}: {error}",
                root.display()
            ));
            return;
        }
    };
    for path in paths {
        match candidate_from_path(&path) {
            Ok(candidate) if matches_cwd(&candidate.cwd, cwd) => out.sessions.push(candidate),
            Ok(_) => {}
            Err(error) => out.warnings.push(format!(
                "Could not inspect Codex session {}: {error}",
                path.display()
            )),
        }
    }
}

pub(super) fn inspect(path: &Path, id: Option<&str>) -> io::Result<ImportCandidate> {
    if path.is_file() {
        let candidate = candidate_from_path(path)?;
        if let Some(id) = id
            && id != candidate.id
        {
            return Err(invalid(format!(
                "Codex rollout {} has id {}, not {id}",
                path.display(),
                candidate.id
            )));
        }
        return Ok(candidate);
    }
    if !path.is_dir() {
        return Err(invalid(format!(
            "Codex session path {} is not a file or directory",
            path.display()
        )));
    }

    let candidates = rollout_paths(path)?
        .into_iter()
        .filter_map(|rollout| candidate_from_path(&rollout).ok())
        .filter(|candidate| id.is_none_or(|requested| requested == candidate.id))
        .collect::<Vec<_>>();
    match candidates.as_slice() {
        [candidate] => Ok(candidate.clone()),
        [] if id.is_some() => Err(invalid(format!(
            "No Codex session {:?} found under {}",
            id,
            path.display()
        ))),
        [] => Err(invalid(format!(
            "No Codex rollout found under {}",
            path.display()
        ))),
        _ if id.is_some() => Err(invalid(format!(
            "Codex session {:?} is ambiguous under {}",
            id,
            path.display()
        ))),
        _ => Err(invalid(format!(
            "{} contains multiple Codex rollouts; select one with its id",
            path.display()
        ))),
    }
}

pub(super) fn load(candidate: &ImportCandidate) -> io::Result<ImportedSession> {
    let home = codex_home_for(&candidate.path).unwrap_or_else(|| {
        candidate
            .path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."))
    });
    let mut visited = HashSet::new();
    let (records, mut warnings, metadata) =
        load_rollout(&candidate.path, &candidate.id, &home, &mut visited)?;
    if !matches_cwd(&metadata.cwd, Some(&candidate.cwd)) {
        return Err(invalid(format!(
            "Codex rollout {} cwd {} does not match the selected session cwd {}",
            candidate.path.display(),
            metadata.cwd.display(),
            candidate.cwd.display()
        )));
    }

    let checkpoint = latest_compaction(&records)?;
    let (display_replay, effective_replay, compaction_summary) = match checkpoint {
        Some(CompactionCheckpoint::Replacement {
            position,
            replacement,
            summary,
        }) => {
            let display = records
                .iter()
                .take(position)
                .map(ReplayRecord::source)
                .collect::<Vec<_>>();
            let mut effective = replacement
                .iter()
                .map(ReplayRecord::replacement)
                .collect::<Vec<_>>();
            effective.extend(records.iter().skip(position + 1).map(ReplayRecord::source));
            (display, effective, summary.map(str::to_owned))
        }
        Some(CompactionCheckpoint::Summary { position, summary }) => {
            let display = records
                .iter()
                .take(position)
                .map(ReplayRecord::source)
                .collect::<Vec<_>>();
            let effective = records
                .iter()
                .skip(position + 1)
                .map(ReplayRecord::source)
                .collect::<Vec<_>>();
            (display, effective, Some(summary.to_owned()))
        }
        None => (
            Vec::new(),
            records.iter().map(ReplayRecord::source).collect::<Vec<_>>(),
            None,
        ),
    };
    let display_messages = convert_replay(&display_replay, &mut warnings)?;
    let effective_messages = convert_replay(&effective_replay, &mut warnings)?;

    let mut imported = ImportedSession::new(candidate.clone());
    for warning in warnings {
        imported.warn(warning);
    }
    for message in display_messages {
        imported.push(message, false);
    }
    if let Some(text) = compaction_summary {
        imported.push(ImportMessage::Summary { text }, true);
    }
    for message in effective_messages {
        let in_context = !matches!(&message, ImportMessage::Reasoning { .. });
        imported.push(message, in_context);
    }
    if imported.context.is_empty() {
        return Err(invalid(
            "Codex rollout has no recoverable conversation context",
        ));
    }
    Ok(imported)
}

fn codex_home() -> Option<PathBuf> {
    std::env::var_os("CODEX_HOME")
        .map(PathBuf::from)
        .or_else(|| xai_dirs::home_dir().map(|home| home.join(".codex")))
}

fn codex_home_for(path: &Path) -> Option<PathBuf> {
    path.ancestors().find_map(|ancestor| {
        let name = ancestor.file_name()?.to_str()?;
        matches!(name, "sessions" | "archived_sessions")
            .then(|| ancestor.parent())
            .flatten()
            .map(Path::to_path_buf)
    })
}

fn rollout_paths(root: &Path) -> io::Result<Vec<PathBuf>> {
    let accepts_rollout = |path: &Path| {
        path.file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with(".jsonl") || name.ends_with(".jsonl.zst"))
    };
    let root_name = root.file_name().and_then(|name| name.to_str());
    let roots = if matches!(root_name, Some("sessions" | "archived_sessions")) {
        vec![root.to_path_buf()]
    } else {
        let stores = ["sessions", "archived_sessions"]
            .into_iter()
            .map(|name| root.join(name))
            .filter(|path| path.is_dir())
            .collect::<Vec<_>>();
        if stores.is_empty() {
            vec![root.to_path_buf()]
        } else {
            stores
        }
    };
    let mut paths = Vec::new();
    let mut seen = HashSet::new();
    for directory in roots {
        for path in walk_files(&directory, MAX_DISCOVERY_DEPTH, accepts_rollout)? {
            if seen.insert(path.clone()) {
                paths.push(path);
            }
        }
    }
    Ok(paths)
}

fn candidate_from_path(path: &Path) -> io::Result<ImportCandidate> {
    let records = json_head(path, DISCOVERY_READ_BYTES)?;
    let metadata = metadata(&records, path)?;
    let title = records
        .iter()
        .find_map(record_title)
        .map(|text| short_title(&text))
        .filter(|title| !title.is_empty())
        .unwrap_or_else(|| "Codex session".to_owned());
    Ok(ImportCandidate {
        source: ImportSource::Codex,
        id: metadata.id,
        path: path.to_path_buf(),
        cwd: metadata.cwd,
        title,
        modified: modified(path),
        leaf_id: None,
    })
}

fn load_rollout(
    path: &Path,
    expected_id: &str,
    home: &Path,
    visited: &mut HashSet<PathBuf>,
) -> io::Result<(Vec<Value>, Vec<String>, SessionMeta)> {
    let canonical = dunce::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    if !visited.insert(canonical.clone()) {
        return Err(invalid(format!(
            "Codex rollout reference cycle reaches {}",
            path.display()
        )));
    }
    let result = (|| {
        let (records, mut warnings) = json_lines_with_warnings(path)?;
        let metadata = metadata(&records, path)?;
        if metadata.id != expected_id && rollout_file_id(path).as_deref() != Some(expected_id) {
            return Err(invalid(format!(
                "Codex rollout {} identifies itself as {} (file rollout {:?}), not selected session {expected_id}",
                path.display(),
                metadata.id,
                rollout_file_id(path)
            )));
        }
        let inherited = if let Some(reference) = metadata.history_base.as_ref() {
            Some(reference.clone())
        } else {
            metadata.fork.clone()
        };
        let mut merged = if let Some(reference) = inherited {
            let parent = find_rollout(home, &reference.id)?.ok_or_else(|| {
                invalid(format!(
                    "Codex rollout {} requires parent rollout {} through ordinal {}, but it was not found",
                    path.display(),
                    reference.id,
                    reference.end_ordinal_exclusive
                ))
            })?;
            let (parent_records, mut parent_warnings, _) =
                load_rollout(&parent, &reference.id, home, visited)?;
            warnings.append(&mut parent_warnings);
            apply_cutoff(parent_records, &reference, path)?
        } else {
            if let Some(parent) = metadata.parent_thread_id.as_deref() {
                warnings.push(format!(
                    "Codex parent thread {parent} has no recognized ordinal cutoff and was not merged."
                ));
            }
            if let Some(fork) = metadata.fork_without_cutoff.as_deref() {
                warnings.push(format!(
                    "Codex forked-from rollout {fork} has no recognized ordinal cutoff and was not merged."
                ));
            }
            Vec::new()
        };
        merged.extend(records);
        Ok((merged, warnings, metadata))
    })();
    visited.remove(&canonical);
    result
}

fn find_rollout(home: &Path, id: &str) -> io::Result<Option<PathBuf>> {
    for path in rollout_paths(home)? {
        let Ok(candidate) = candidate_from_path(&path) else {
            continue;
        };
        if candidate.id == id || rollout_file_id(&path).as_deref() == Some(id) {
            return Ok(Some(path));
        }
    }
    Ok(None)
}

fn apply_cutoff(
    records: Vec<Value>,
    reference: &HistoryReference,
    child: &Path,
) -> io::Result<Vec<Value>> {
    let mut prefix = Vec::new();
    for value in records {
        let ordinal = value
            .get("ordinal")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                invalid(format!(
                    "Codex parent rollout for {} has no ordinal needed for inherited cutoff {}",
                    child.display(),
                    reference.end_ordinal_exclusive
                ))
            })?;
        if ordinal >= reference.end_ordinal_exclusive {
            break;
        }
        prefix.push(value);
    }
    Ok(prefix)
}

fn metadata(records: &[Value], path: &Path) -> io::Result<SessionMeta> {
    let payload = records
        .iter()
        .find(|record| record_type(record) == Some("session_meta"))
        .and_then(|record| record.get("payload"))
        .and_then(Value::as_object)
        .ok_or_else(|| {
            invalid(format!(
                "Codex rollout {} has no session_meta header",
                path.display()
            ))
        })?;
    let id = string_field(payload, "id")
        .ok_or_else(|| {
            invalid(format!(
                "Codex rollout {} session_meta has no id",
                path.display()
            ))
        })?
        .to_owned();
    let cwd = string_field(payload, "cwd").ok_or_else(|| {
        invalid(format!(
            "Codex rollout {} session_meta has no cwd",
            path.display()
        ))
    })?;
    let fork = fork_reference(payload, path)?;
    let fork_without_cutoff = string_field(payload, "forked_from_id")
        .filter(|id| fork.is_none() && !id.is_empty())
        .map(str::to_owned);
    Ok(SessionMeta {
        id,
        cwd: PathBuf::from(cwd),
        history_base: history_reference(payload.get("history_base"), "history_base", path)?,
        fork,
        fork_without_cutoff,
        parent_thread_id: string_field(payload, "parent_thread_id").map(str::to_owned),
    })
}

fn history_reference(
    value: Option<&Value>,
    field: &str,
    path: &Path,
) -> io::Result<Option<HistoryReference>> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let object = value.as_object().ok_or_else(|| {
        invalid(format!(
            "Codex rollout {} {field} is not an object",
            path.display()
        ))
    })?;
    let id = string_field(object, "thread_id").ok_or_else(|| {
        invalid(format!(
            "Codex rollout {} {field} has no thread_id",
            path.display()
        ))
    })?;
    let end_ordinal_exclusive = u64_field(object, "end_ordinal_exclusive").ok_or_else(|| {
        invalid(format!(
            "Codex rollout {} {field} has no end_ordinal_exclusive",
            path.display()
        ))
    })?;
    Ok(Some(HistoryReference {
        id: id.to_owned(),
        end_ordinal_exclusive,
    }))
}

fn fork_reference(
    payload: &Map<String, Value>,
    path: &Path,
) -> io::Result<Option<HistoryReference>> {
    let Some(id) = string_field(payload, "forked_from_id") else {
        return Ok(None);
    };
    let Some(end_ordinal_exclusive) = u64_field(payload, "forked_from_ordinal_exclusive") else {
        return Ok(None);
    };
    if id.is_empty() {
        return Err(invalid(format!(
            "Codex rollout {} has an empty forked_from_id",
            path.display()
        )));
    }
    Ok(Some(HistoryReference {
        id: id.to_owned(),
        end_ordinal_exclusive,
    }))
}

fn latest_compaction<'a>(records: &'a [Value]) -> io::Result<Option<CompactionCheckpoint<'a>>> {
    let mut selected = None;
    for (index, record) in records.iter().enumerate() {
        if record_type(record) != Some("compacted") {
            continue;
        }
        let payload = record
            .get("payload")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                invalid(format!(
                    "Codex compacted record {} has no object payload",
                    index + 1
                ))
            })?;
        let replacement = payload
            .get("replacement_history")
            .filter(|value| !value.is_null());
        selected = match replacement {
            Some(history) => {
                let replacement = history.as_array().ok_or_else(|| {
                    invalid(format!(
                        "Codex compacted record {} has invalid replacement_history",
                        index + 1
                    ))
                })?;
                Some(CompactionCheckpoint::Replacement {
                    position: index,
                    replacement,
                    summary: string_field(payload, "message")
                        .filter(|text| !text.trim().is_empty()),
                })
            }
            None => {
                let summary = string_field(payload, "message").filter(|text| !text.trim().is_empty()).ok_or_else(|| {
                    invalid(format!(
                        "Codex compacted record {} has neither replacement_history nor a plaintext summary; effective context cannot be reconstructed",
                        index + 1
                    ))
                })?;
                Some(CompactionCheckpoint::Summary {
                    position: index,
                    summary,
                })
            }
        };
    }
    Ok(selected)
}

fn replacement_payload(value: &Value) -> io::Result<&Map<String, Value>> {
    let payload = if value.get("type").is_some() {
        value
    } else {
        value.get("payload").ok_or_else(|| {
            invalid("Codex compaction replacement history item has neither type nor payload")
        })?
    };
    payload
        .as_object()
        .ok_or_else(|| invalid("Codex compaction replacement history payload is not an object"))
}

fn convert_replay(
    replay: &[ReplayRecord<'_>],
    warnings: &mut Vec<String>,
) -> io::Result<Vec<ImportMessage>> {
    let has_response_items = replay.iter().any(|record| {
        record.replacement_history || record_type(record.value) == Some("response_item")
    });
    let mut messages = Vec::new();
    for record in replay {
        if record.replacement_history {
            messages.extend(convert_response_item(
                replacement_payload(record.value)?,
                true,
                warnings,
            )?);
            continue;
        }
        match record_type(record.value) {
            Some("response_item") => {
                let payload = record
                    .value
                    .get("payload")
                    .and_then(Value::as_object)
                    .ok_or_else(|| invalid("Codex response_item has no object payload"))?;
                messages.extend(convert_response_item(payload, false, warnings)?);
            }
            Some("event_msg") => {
                let payload = record
                    .value
                    .get("payload")
                    .and_then(Value::as_object)
                    .ok_or_else(|| invalid("Codex event_msg has no object payload"))?;
                if event_type(payload) == Some("thread_rolled_back") {
                    let turns = u64_field(payload, "num_turns").ok_or_else(|| {
                        invalid("Codex thread_rolled_back event has no numeric num_turns")
                    })?;
                    rollback(&mut messages, turns as usize);
                } else if !has_response_items {
                    messages.extend(convert_event(payload, warnings)?);
                } else if !known_event_type(event_type(payload)) {
                    warnings.push(format!(
                        "Ignored unrecognized Codex event {:?} beside authoritative response items.",
                        event_type(payload)
                    ));
                }
            }
            Some("session_meta" | "turn_context" | "token_usage_record" | "world_state" | "security_risk_score") => {}
            Some("compacted") => {
                let payload = record.value.get("payload").and_then(Value::as_object).ok_or_else(|| {
                    invalid("Codex compacted record has no object payload")
                })?;
                if let Some(text) = string_field(payload, "message").filter(|text| !text.trim().is_empty()) {
                    messages.push(ImportMessage::Summary { text: text.to_owned() });
                } else {
                    warnings.push("Ignored an older Codex compaction without a plaintext display summary.".to_owned());
                }
            }
            Some("inter_agent_communication" | "inter_agent_communication_metadata" | "retained_context" | "realtime_item") => {
                warnings.push(format!(
                    "Ignored non-conversation Codex record type {:?}; it was not promoted into groky context.",
                    record_type(record.value)
                ));
            }
            Some(kind) => warnings.push(format!(
                "Ignored unrecognized Codex rollout record type {kind:?}; effective context may omit source-specific state."
            )),
            None => return Err(invalid("Codex rollout record has no type")),
        }
    }
    Ok(messages)
}

fn convert_response_item(
    payload: &Map<String, Value>,
    required_for_context: bool,
    warnings: &mut Vec<String>,
) -> io::Result<Vec<ImportMessage>> {
    let kind =
        string_field(payload, "type").ok_or_else(|| invalid("Codex response item has no type"))?;
    match kind {
        "message" => convert_response_message(payload, required_for_context, warnings),
        "reasoning" => {
            let text = reasoning_text(payload);
            if text.is_empty() {
                require_plaintext(payload, kind, required_for_context)?;
                return Ok(Vec::new());
            }
            Ok(vec![ImportMessage::Reasoning { text }])
        }
        "function_call" | "custom_tool_call" | "web_search_call" | "tool_search_call"
        | "local_shell_call" => {
            let id =
                call_id(payload).ok_or_else(|| invalid(format!("Codex {kind} has no call id")))?;
            let (name, arguments) = match kind {
                "function_call" | "custom_tool_call" => (
                    string_field(payload, "name")
                        .ok_or_else(|| invalid(format!("Codex {kind} {id} has no name")))?
                        .to_owned(),
                    arguments(payload.get(if kind == "custom_tool_call" {
                        "input"
                    } else {
                        "arguments"
                    }))?,
                ),
                "web_search_call" => ("web_search".to_owned(), arguments(payload.get("action"))?),
                "tool_search_call" => (
                    "tool_search".to_owned(),
                    arguments(payload.get("arguments"))?,
                ),
                "local_shell_call" => ("shell".to_owned(), arguments(payload.get("action"))?),
                _ => unreachable!(),
            };
            Ok(vec![ImportMessage::Assistant {
                text: String::new(),
                tool_calls: vec![ImportToolCall {
                    id: id.to_owned(),
                    name,
                    arguments,
                }],
            }])
        }
        "function_call_output" | "custom_tool_call_output" | "tool_search_output" => {
            let id = string_field(payload, "call_id")
                .ok_or_else(|| invalid(format!("Codex {kind} has no call_id")))?;
            let output = match kind {
                "tool_search_output" => payload.get("tools"),
                _ => payload.get("output"),
            };
            Ok(vec![ImportMessage::ToolResult {
                id: id.to_owned(),
                content: output_content(output, warnings),
                is_error: string_field(payload, "status") == Some("failed"),
            }])
        }
        "image_generation_call" | "configuration_update" | "additional_tools" => {
            require_plaintext(payload, kind, required_for_context)?;
            warnings.push(format!(
                "Ignored non-conversation Codex response item {kind:?}."
            ));
            Ok(Vec::new())
        }
        "compaction" | "context_compaction" | "compaction_summary" => {
            let text = response_summary_text(payload, warnings);
            if text.is_empty() {
                require_plaintext(payload, kind, required_for_context)?;
                warnings.push(format!(
                    "Ignored Codex {kind:?} without a plaintext summary."
                ));
                Ok(Vec::new())
            } else {
                Ok(vec![ImportMessage::Summary { text }])
            }
        }
        "other" => {
            require_plaintext(payload, kind, required_for_context)?;
            warnings.push("Ignored Codex response item tagged other.".to_owned());
            Ok(Vec::new())
        }
        _ => Err(invalid(format!(
            "Unsupported context-bearing Codex response item type {kind:?}"
        ))),
    }
}

fn response_summary_text(payload: &Map<String, Value>, warnings: &mut Vec<String>) -> String {
    for field in ["summary", "message", "text"] {
        if let Some(text) = string_field(payload, field).filter(|text| !text.trim().is_empty()) {
            return text.to_owned();
        }
    }
    join_text(&response_content(payload.get("content"), warnings))
}

fn convert_response_message(
    payload: &Map<String, Value>,
    required_for_context: bool,
    warnings: &mut Vec<String>,
) -> io::Result<Vec<ImportMessage>> {
    let role = string_field(payload, "role")
        .ok_or_else(|| invalid("Codex message response item has no role"))?;
    let content = response_content(payload.get("content"), warnings);
    if content.is_empty() {
        require_plaintext(payload, "message", required_for_context)?;
        return Ok(Vec::new());
    }
    match role {
        "user" => Ok(vec![ImportMessage::User { content }]),
        "assistant" => Ok(vec![ImportMessage::Assistant {
            text: join_text(&content),
            tool_calls: Vec::new(),
        }]),
        "system" | "developer" => {
            warnings.push(format!(
                "Excluded foreign Codex {role} message from groky context."
            ));
            Ok(Vec::new())
        }
        _ => Err(invalid(format!("Unsupported Codex message role {role:?}"))),
    }
}

fn convert_event(
    payload: &Map<String, Value>,
    warnings: &mut Vec<String>,
) -> io::Result<Vec<ImportMessage>> {
    match event_type(payload) {
        Some("user_message") => string_field(payload, "message")
            .filter(|text| !text.is_empty())
            .map(|text| {
                vec![ImportMessage::User {
                    content: vec![ImportContent::Text(text.to_owned())],
                }]
            })
            .ok_or_else(|| invalid("Codex user_message event has no message")),
        Some("agent_message") => string_field(payload, "message")
            .filter(|text| !text.is_empty())
            .map(|text| {
                vec![ImportMessage::Assistant {
                    text: text.to_owned(),
                    tool_calls: Vec::new(),
                }]
            })
            .ok_or_else(|| invalid("Codex agent_message event has no message")),
        Some("agent_reasoning" | "agent_reasoning_raw_content") => {
            Ok(string_field(payload, "text")
                .filter(|text| !text.is_empty())
                .map(|text| {
                    vec![ImportMessage::Reasoning {
                        text: text.to_owned(),
                    }]
                })
                .unwrap_or_default())
        }
        Some("dynamic_tool_call_request") => {
            let id = string_field(payload, "call_id")
                .or_else(|| string_field(payload, "callId"))
                .ok_or_else(|| invalid("Codex dynamic_tool_call_request has no call id"))?;
            let name = string_field(payload, "tool")
                .ok_or_else(|| invalid("Codex dynamic_tool_call_request has no tool"))?;
            Ok(vec![ImportMessage::Assistant {
                text: String::new(),
                tool_calls: vec![ImportToolCall {
                    id: id.to_owned(),
                    name: name.to_owned(),
                    arguments: arguments(payload.get("arguments"))?,
                }],
            }])
        }
        Some("dynamic_tool_call_response") => {
            let id = string_field(payload, "call_id")
                .or_else(|| string_field(payload, "callId"))
                .ok_or_else(|| invalid("Codex dynamic_tool_call_response has no call id"))?;
            let error = string_field(payload, "error");
            Ok(vec![ImportMessage::ToolResult {
                id: id.to_owned(),
                content: error
                    .map(|text| vec![ImportContent::Text(text.to_owned())])
                    .unwrap_or_else(|| output_content(payload.get("content_items"), warnings)),
                is_error: error.is_some()
                    || payload.get("success").and_then(Value::as_bool) == Some(false),
            }])
        }
        Some("web_search_end") => {
            let id = string_field(payload, "call_id")
                .ok_or_else(|| invalid("Codex web_search_end has no call_id"))?;
            Ok(vec![ImportMessage::ToolResult {
                id: id.to_owned(),
                content: output_content(
                    payload.get("results").or_else(|| payload.get("query")),
                    warnings,
                ),
                is_error: false,
            }])
        }
        Some(
            "thread_name_updated"
            | "turn_started"
            | "turn_complete"
            | "turn_aborted"
            | "token_count"
            | "thread_goal_updated"
            | "thread_settings_applied"
            | "item_completed",
        ) => Ok(Vec::new()),
        Some(kind) => {
            warnings.push(format!("Ignored legacy Codex event {kind:?}."));
            Ok(Vec::new())
        }
        None => Err(invalid("Codex event_msg has no type")),
    }
}

fn rollback(messages: &mut Vec<ImportMessage>, turns: usize) {
    for _ in 0..turns {
        let Some(index) = messages
            .iter()
            .rposition(|message| matches!(message, ImportMessage::User { .. }))
        else {
            messages.clear();
            return;
        };
        messages.truncate(index);
    }
}

fn response_content(value: Option<&Value>, warnings: &mut Vec<String>) -> Vec<ImportContent> {
    let Some(values) = value.and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut content = Vec::new();
    for value in values {
        let Some(block) = value.as_object() else {
            warnings.push("Ignored malformed Codex response content block.".to_owned());
            continue;
        };
        match string_field(block, "type") {
            Some("input_text" | "output_text" | "text") => {
                if let Some(text) = string_field(block, "text") {
                    content.push(ImportContent::Text(text.to_owned()));
                }
            }
            Some("input_image") => {
                if let Some(url) =
                    string_field(block, "image_url").filter(|url| url.starts_with("data:image/"))
                {
                    content.push(ImportContent::Image {
                        url: url.to_owned(),
                    });
                } else {
                    warnings.push("Ignored Codex image that is not an inline data URL.".to_owned());
                }
            }
            Some(kind) => warnings.push(format!(
                "Ignored unsupported Codex response content block {kind:?}."
            )),
            None => warnings.push("Ignored untyped Codex response content block.".to_owned()),
        }
    }
    content
}

fn output_content(value: Option<&Value>, warnings: &mut Vec<String>) -> Vec<ImportContent> {
    let Some(value) = value else {
        return Vec::new();
    };
    let structured = response_content(Some(value), warnings);
    if !structured.is_empty() {
        return structured;
    }
    match value {
        Value::String(text) => vec![ImportContent::Text(text.clone())],
        Value::Null => Vec::new(),
        other => match serde_json::to_string(other) {
            Ok(text) => vec![ImportContent::Text(text)],
            Err(_) => {
                warnings.push("Could not serialize a Codex tool result.".to_owned());
                Vec::new()
            }
        },
    }
}

fn reasoning_text(payload: &Map<String, Value>) -> String {
    ["summary", "content"]
        .into_iter()
        .filter_map(|field| payload.get(field).and_then(Value::as_array))
        .flatten()
        .filter_map(|item| item.get("text").and_then(Value::as_str))
        .collect()
}

fn require_plaintext(
    payload: &Map<String, Value>,
    kind: &str,
    required_for_context: bool,
) -> io::Result<()> {
    if required_for_context
        && payload
            .get("encrypted_content")
            .and_then(Value::as_str)
            .is_some()
    {
        return Err(invalid(format!(
            "Codex encrypted {kind} in compaction replacement history has no recoverable plaintext; effective context cannot be reconstructed"
        )));
    }
    Ok(())
}

fn call_id(payload: &Map<String, Value>) -> Option<&str> {
    string_field(payload, "call_id").or_else(|| string_field(payload, "id"))
}

fn arguments(value: Option<&Value>) -> io::Result<String> {
    match value {
        Some(Value::String(value)) if serde_json::from_str::<Value>(value).is_ok() => {
            Ok(value.clone())
        }
        Some(Value::String(value)) => serde_json::to_string(&json!({ "input": value }))
            .map_err(|error| invalid(format!("Could not encode Codex tool input: {error}"))),
        Some(value) => serde_json::to_string(value)
            .map_err(|error| invalid(format!("Could not encode Codex tool arguments: {error}"))),
        None => Ok("{}".to_owned()),
    }
}

fn join_text(content: &[ImportContent]) -> String {
    content
        .iter()
        .filter_map(|part| match part {
            ImportContent::Text(text) => Some(text.as_str()),
            ImportContent::Image { .. } => None,
        })
        .collect()
}

fn record_title(record: &Value) -> Option<String> {
    let payload = record.get("payload")?.as_object()?;
    match record_type(record) {
        Some("event_msg") if event_type(payload) == Some("user_message") => {
            string_field(payload, "message").map(str::to_owned)
        }
        Some("response_item")
            if string_field(payload, "type") == Some("message")
                && string_field(payload, "role") == Some("user") =>
        {
            let mut warnings = Vec::new();
            let text = join_text(&response_content(payload.get("content"), &mut warnings));
            (!text.trim().is_empty()).then_some(text)
        }
        _ => None,
    }
}

fn record_type(value: &Value) -> Option<&str> {
    value.get("type")?.as_str()
}

fn rollout_file_id(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_str()?;
    let stem = name
        .strip_suffix(".jsonl.zst")
        .or_else(|| name.strip_suffix(".jsonl"))?;
    let id = stem.get(stem.len().checked_sub(36)?..)?;
    uuid::Uuid::try_parse(id).ok().map(|_| id.to_owned())
}

fn event_type(payload: &Map<String, Value>) -> Option<&str> {
    string_field(payload, "type")
}

fn known_event_type(kind: Option<&str>) -> bool {
    matches!(
        kind,
        Some(
            "user_message"
                | "agent_message"
                | "agent_reasoning"
                | "agent_reasoning_raw_content"
                | "dynamic_tool_call_request"
                | "dynamic_tool_call_response"
                | "web_search_end"
                | "thread_name_updated"
                | "turn_started"
                | "turn_complete"
                | "turn_aborted"
                | "token_count"
                | "thread_goal_updated"
                | "thread_settings_applied"
                | "item_completed"
        )
    )
}

fn string_field<'a>(value: &'a Map<String, Value>, field: &str) -> Option<&'a str> {
    value.get(field)?.as_str()
}

fn u64_field(value: &Map<String, Value>, field: &str) -> Option<u64> {
    value.get(field)?.as_u64()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    use serde_json::json;
    use tempfile::TempDir;

    fn write_rollout(path: &Path, records: &[Value]) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(
            path,
            format!(
                "{}\n",
                records
                    .iter()
                    .map(Value::to_string)
                    .collect::<Vec<_>>()
                    .join("\n")
            ),
        )
        .unwrap();
    }

    fn candidate(path: &Path, id: &str, cwd: &Path) -> ImportCandidate {
        ImportCandidate {
            source: ImportSource::Codex,
            id: id.to_owned(),
            path: path.to_path_buf(),
            cwd: cwd.to_path_buf(),
            title: "test".to_owned(),
            modified: modified(path),
            leaf_id: None,
        }
    }

    fn meta(id: &str, cwd: &Path) -> Value {
        json!({"type":"session_meta","ordinal":0,"payload":{"id":id,"cwd":cwd}})
    }

    fn context_debug(imported: &ImportedSession) -> String {
        imported
            .context
            .iter()
            .filter_map(|index| imported.messages.get(*index))
            .map(|message| format!("{message:?}"))
            .collect()
    }

    #[test]
    fn loads_response_items_once_applies_latest_compaction_and_rollback() {
        let temp = TempDir::new().unwrap();
        let cwd = temp.path().join("repo");
        fs::create_dir_all(&cwd).unwrap();
        let path = temp
            .path()
            .join("archived_sessions/2026/10/27/rollout.jsonl.zst");
        let records = vec![
            meta("child", &cwd),
            json!({"type":"response_item","ordinal":1,"payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"old"}]}}),
            json!({"type":"event_msg","ordinal":2,"payload":{"type":"user_message","message":"old"}}),
            json!({"type":"compacted","ordinal":3,"payload":{"message":"compacted","replacement_history":[
                {"type":"compaction_summary","summary":"replacement summary"},
                {"type":"message","role":"user","content":[{"type":"input_text","text":"kept"}]},
                {"type":"function_call","call_id":"call","name":"read","arguments":"{\"path\":\"x\"}"},
                {"type":"function_call_output","call_id":"call","output":"contents"}
            ]}}),
            json!({"type":"response_item","ordinal":4,"payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"answer"}]}}),
            json!({"type":"event_msg","ordinal":5,"payload":{"type":"agent_message","message":"answer"}}),
            json!({"type":"response_item","ordinal":6,"payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"undo"}]}}),
            json!({"type":"event_msg","ordinal":7,"payload":{"type":"thread_rolled_back","num_turns":1}}),
        ];
        let encoded = zstd::encode_all(
            format!(
                "{}\n",
                records
                    .iter()
                    .map(Value::to_string)
                    .collect::<Vec<_>>()
                    .join("\n")
            )
            .as_bytes(),
            1,
        )
        .unwrap();
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, encoded).unwrap();
        let discovered = candidate_from_path(&path).unwrap();
        assert_eq!(discovered.id, "child");
        assert_eq!(discovered.title, "old");

        let imported = load(&candidate(&path, "child", &cwd)).unwrap();
        let shown = format!("{:?}", imported.messages);
        let context = context_debug(&imported);
        assert!(shown.contains("old"));
        assert!(!context.contains("old"));
        assert!(shown.contains("kept"));
        assert!(shown.contains("answer"));
        assert!(context.contains("compacted"));
        assert!(context.contains("replacement summary"));
        assert!(!shown.contains("undo"));
        assert_eq!(
            imported
                .messages
                .iter()
                .filter(|message| matches!(message, ImportMessage::User { content } if join_text(content) == "kept"))
                .count(),
            1
        );
        assert_eq!(
            imported
                .messages
                .iter()
                .filter(|message| matches!(message, ImportMessage::Assistant { text, .. } if text == "answer"))
                .count(),
            1
        );
    }

    #[test]
    fn legacy_compaction_keeps_old_display_history_but_replaces_context_with_summary() {
        let temp = TempDir::new().unwrap();
        let cwd = temp.path().join("repo");
        fs::create_dir_all(&cwd).unwrap();
        let path = temp.path().join("sessions/2026/10/27/legacy.jsonl");
        write_rollout(
            &path,
            &[
                meta("legacy", &cwd),
                json!({"type":"response_item","ordinal":1,"payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"obsolete"}]}}),
                json!({"type":"compacted","ordinal":2,"payload":{"message":"legacy summary"}}),
                json!({"type":"response_item","ordinal":3,"payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"continued"}]}}),
            ],
        );

        let imported = load(&candidate(&path, "legacy", &cwd)).unwrap();
        let shown = format!("{:?}", imported.messages);
        let context = context_debug(&imported);
        assert!(shown.contains("obsolete"));
        assert!(!context.contains("obsolete"));
        assert!(context.contains("legacy summary"));
        assert!(context.contains("continued"));
    }

    #[test]
    fn resolves_history_base_at_ordinal_cutoff() {
        let temp = TempDir::new().unwrap();
        let cwd = temp.path().join("repo");
        fs::create_dir_all(&cwd).unwrap();
        let parent = temp.path().join("sessions/2026/10/26/parent.jsonl");
        write_rollout(
            &parent,
            &[
                meta("parent", &cwd),
                json!({"type":"response_item","ordinal":1,"payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"inherited"}]}}),
                json!({"type":"response_item","ordinal":2,"payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"not inherited"}]}}),
            ],
        );
        let child = temp.path().join("sessions/2026/10/27/child.jsonl");
        write_rollout(
            &child,
            &[
                json!({"type":"session_meta","ordinal":0,"payload":{"id":"child","cwd":cwd,"history_base":{"thread_id":"parent","end_ordinal_exclusive":2,"end_byte_offset":0}}}),
                json!({"type":"response_item","ordinal":2,"payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"child answer"}]}}),
            ],
        );

        let imported = load(&candidate(&child, "child", &cwd)).unwrap();
        let shown = format!("{:?}", imported.messages);
        assert!(shown.contains("inherited"));
        assert!(shown.contains("child answer"));
        assert!(!shown.contains("not inherited"));
    }

    #[test]
    fn rejects_encrypted_replacement_history_without_plaintext() {
        let temp = TempDir::new().unwrap();
        let cwd = temp.path().join("repo");
        fs::create_dir_all(&cwd).unwrap();
        let path = temp.path().join("sessions/2026/10/27/child.jsonl");
        write_rollout(
            &path,
            &[
                meta("child", &cwd),
                json!({"type":"compacted","ordinal":1,"payload":{"replacement_history":[{"type":"message","role":"user","content":[],"encrypted_content":"opaque"}]}}),
            ],
        );
        let error = load(&candidate(&path, "child", &cwd)).unwrap_err();
        assert!(error.to_string().contains("encrypted message"));
    }
}
