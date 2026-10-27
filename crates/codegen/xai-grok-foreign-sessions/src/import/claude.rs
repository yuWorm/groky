use std::collections::{HashMap, HashSet};
use std::io;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

use super::common::{
    invalid, json_head, json_lines_with_warnings, matches_cwd, modified, short_title, walk_files,
};
use super::*;

const DISCOVERY_READ_BYTES: u64 = 64 * 1024;
const MAX_DISCOVERY_DEPTH: usize = 2;

#[derive(Clone)]
struct Node {
    value: Value,
    uuid: String,
    parent: Option<String>,
    line: usize,
}

pub(super) fn discover(cwd: Option<&Path>, out: &mut ImportDiscovery) {
    let Some(root) = config_root() else {
        return;
    };
    let paths = match session_paths(&root) {
        Ok(paths) => paths,
        Err(error) => {
            out.warnings.push(format!(
                "Could not scan Claude Code sessions in {}: {error}",
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
                "Could not inspect Claude Code session {}: {error}",
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
                "Claude transcript {} has id {}, not {id}",
                path.display(),
                candidate.id
            )));
        }
        return Ok(candidate);
    }
    if !path.is_dir() {
        return Err(invalid(format!(
            "Claude transcript path {} is not a file or directory",
            path.display()
        )));
    }

    let candidates = session_paths(path)?
        .into_iter()
        .filter_map(|candidate_path| candidate_from_path(&candidate_path).ok())
        .filter(|candidate| id.is_none_or(|requested| requested == candidate.id))
        .collect::<Vec<_>>();
    match candidates.as_slice() {
        [candidate] => Ok(candidate.clone()),
        [] if id.is_some() => Err(invalid(format!(
            "No Claude Code session {:?} found under {}",
            id,
            path.display()
        ))),
        [] => Err(invalid(format!(
            "No Claude Code transcript found under {}",
            path.display()
        ))),
        _ if id.is_some() => Err(invalid(format!(
            "Claude Code session {:?} is ambiguous under {}",
            id,
            path.display()
        ))),
        _ => Err(invalid(format!(
            "{} contains multiple Claude Code transcripts; select one with its id",
            path.display()
        ))),
    }
}

pub(super) fn load(candidate: &ImportCandidate) -> io::Result<ImportedSession> {
    let (records, mut warnings) = json_lines_with_warnings(&candidate.path)?;
    if records.is_empty() {
        return Err(invalid(format!(
            "Claude Code transcript {} is empty",
            candidate.path.display()
        )));
    }

    let mut nodes = HashMap::<String, Node>::new();
    for (offset, value) in records.into_iter().enumerate() {
        let line = offset + 1;
        let Some(record) = value.as_object() else {
            return Err(invalid(format!(
                "Claude Code record {line} is not an object"
            )));
        };
        if bool_field(record, "isSidechain")
            || record.get("teamName").is_some_and(|value| !value.is_null())
            || (bool_field(record, "isMeta") && !bool_field(record, "isCompactSummary"))
        {
            continue;
        }
        if let Some(session_id) =
            string_field(record, "sessionId").or_else(|| string_field(record, "session_id"))
            && session_id != candidate.id
        {
            return Err(invalid(format!(
                "Claude Code transcript {} identifies itself as {session_id}, not selected session {}",
                candidate.path.display(),
                candidate.id
            )));
        }
        let kind = string_field(record, "type");
        // `summary` + `leafUuid` is a picker title, not a context checkpoint.
        if kind == Some("summary") {
            continue;
        }
        if kind == Some("stream_event") {
            continue;
        }
        let Some(uuid) = string_field(record, "uuid") else {
            if matches!(kind, Some("user" | "assistant")) {
                return Err(invalid(format!(
                    "Claude Code {kind:?} record {line} has no uuid"
                )));
            }
            continue;
        };
        let uuid = uuid.to_owned();
        let parent = string_field(record, "parentUuid").map(str::to_owned);
        let candidate_node = Node {
            value,
            uuid: uuid.clone(),
            parent,
            line,
        };
        match nodes.get(&uuid) {
            Some(existing) if node_score(existing) >= node_score(&candidate_node) => {
                warnings.push(format!("Ignored an older duplicate Claude record {uuid}."));
            }
            Some(_) => {
                warnings.push(format!(
                    "Replaced a streamed or duplicate Claude record {uuid} with its complete form."
                ));
                nodes.insert(uuid, candidate_node);
            }
            None => {
                nodes.insert(uuid, candidate_node);
            }
        }
    }

    let leaf = match candidate.leaf_id.as_deref() {
        Some(leaf) if nodes.contains_key(leaf) => leaf.to_owned(),
        Some(leaf) => {
            return Err(invalid(format!(
                "Selected Claude Code branch leaf {leaf} is absent from {}",
                candidate.path.display()
            )));
        }
        None => terminal_leaf(&nodes)
            .ok_or_else(|| invalid("Claude Code transcript has no main-chain messages"))?,
    };
    let chain = selected_chain(&nodes, &leaf, false, &mut warnings)?;
    if chain.is_empty() {
        return Err(invalid(
            "Claude Code transcript selected branch has no records",
        ));
    }

    let display_chain = selected_chain(&nodes, &leaf, true, &mut warnings)?;
    let effective: HashSet<_> = chain.iter().map(String::as_str).collect();
    let mut imported = ImportedSession::new(candidate.clone());
    for warning in warnings {
        imported.warn(warning);
    }
    let mut needs_summary = false;
    for uuid in display_chain {
        let Some(node) = nodes.get(&uuid) else {
            continue;
        };
        let active = effective.contains(uuid.as_str());
        if active && is_compact_boundary(&node.value) {
            imported.context.clear();
            needs_summary = true;
        }
        if active && node.value.get("isCompactSummary").and_then(Value::as_bool) == Some(true) {
            needs_summary = false;
        }
        for message in convert_node(node, &mut imported.warnings)? {
            let in_context = active && !matches!(message, ImportMessage::Reasoning { .. });
            imported.push(message, in_context);
        }
    }
    if needs_summary {
        return Err(invalid(
            "Claude Code compaction has no persisted summary yet; retry after the source finishes saving it",
        ));
    }
    if imported.context.is_empty() {
        return Err(invalid(
            "Claude Code selected branch has no recoverable conversation context",
        ));
    }
    Ok(imported)
}

fn config_root() -> Option<PathBuf> {
    std::env::var_os("CLAUDE_CONFIG_DIR")
        .map(PathBuf::from)
        .or_else(|| xai_dirs::home_dir().map(|home| home.join(".claude")))
}

fn session_paths(root: &Path) -> io::Result<Vec<PathBuf>> {
    let accept = |path: &Path| {
        path.file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with(".jsonl"))
    };
    let mut paths = Vec::new();
    let mut seen = HashSet::new();
    let root_name = root.file_name().and_then(|name| name.to_str());
    let search_roots = if matches!(root_name, Some("projects" | ".projects")) {
        vec![(root.to_path_buf(), MAX_DISCOVERY_DEPTH)]
    } else {
        let stores = ["projects", ".projects"]
            .into_iter()
            .map(|name| root.join(name))
            .filter(|path| path.is_dir())
            .collect::<Vec<_>>();
        if stores.is_empty() {
            vec![(root.to_path_buf(), 0)]
        } else {
            stores
                .into_iter()
                .map(|path| (path, MAX_DISCOVERY_DEPTH))
                .collect()
        }
    };
    for (search_root, depth) in search_roots {
        for path in walk_files(&search_root, depth, accept)? {
            if seen.insert(path.clone()) {
                paths.push(path);
            }
        }
    }
    Ok(paths)
}

fn candidate_from_path(path: &Path) -> io::Result<ImportCandidate> {
    let id = path
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_suffix(".jsonl"))
        .filter(|id| !id.is_empty())
        .ok_or_else(|| {
            invalid(format!(
                "{} is not a Claude Code JSONL transcript",
                path.display()
            ))
        })?
        .to_owned();
    let preview = json_head(path, DISCOVERY_READ_BYTES)?;
    let mut cwd = None;
    let mut title = None;
    let mut sidechain = false;
    for value in preview {
        let Some(record) = value.as_object() else {
            continue;
        };
        sidechain |= bool_field(record, "isSidechain");
        cwd = cwd.or_else(|| string_field(record, "cwd").map(PathBuf::from));
        title = title.or_else(|| record_title(record));
    }
    if sidechain {
        return Err(invalid(format!(
            "{} is a Claude Code sidechain transcript",
            path.display()
        )));
    }
    let cwd = cwd.ok_or_else(|| {
        invalid(format!(
            "{} has no Claude Code cwd in its bounded header",
            path.display()
        ))
    })?;
    Ok(ImportCandidate {
        source: ImportSource::Claude,
        id,
        path: path.to_path_buf(),
        cwd,
        title: title
            .as_deref()
            .map(short_title)
            .filter(|title| !title.is_empty())
            .unwrap_or_else(|| "Claude Code session".to_owned()),
        modified: modified(path),
        leaf_id: None,
    })
}

fn record_title(record: &Map<String, Value>) -> Option<String> {
    for field in ["customTitle", "aiTitle", "lastPrompt", "summary"] {
        if let Some(value) = string_field(record, field).filter(|value| !value.trim().is_empty()) {
            return Some(value.to_owned());
        }
    }
    if string_field(record, "type") != Some("user") {
        return None;
    }
    message_field(record)
        .and_then(|message| message.get("content"))
        .map(claude_text)
        .filter(|text| !text.trim().is_empty())
}

fn terminal_leaf(nodes: &HashMap<String, Node>) -> Option<String> {
    let parents: HashSet<_> = nodes
        .values()
        .filter_map(|node| node.parent.as_deref())
        .collect();
    nodes
        .values()
        .filter(|node| !parents.contains(node.uuid.as_str()))
        .filter_map(|terminal| {
            let mut node = terminal;
            let mut seen = HashSet::new();
            loop {
                if !seen.insert(node.uuid.as_str()) {
                    return None;
                }
                if is_conversation_node(&node.value) {
                    return Some(node);
                }
                node = nodes.get(node.parent.as_ref()?)?;
            }
        })
        .max_by_key(|node| node.line)
        .map(|node| node.uuid.clone())
}

fn is_compact_boundary(value: &Value) -> bool {
    value.get("type").and_then(Value::as_str) == Some("system")
        && value.get("subtype").and_then(Value::as_str) == Some("compact_boundary")
}

fn selected_chain(
    nodes: &HashMap<String, Node>,
    leaf: &str,
    archive: bool,
    warnings: &mut Vec<String>,
) -> io::Result<Vec<String>> {
    let mut chain = Vec::new();
    let mut seen = HashSet::new();
    let mut cursor = Some(leaf);
    while let Some(uuid) = cursor {
        if !seen.insert(uuid) {
            return Err(invalid(format!("Claude Code parent cycle reaches {uuid}")));
        }
        let Some(node) = nodes.get(uuid) else {
            warnings.push(format!(
                "Claude Code branch starts after unavailable parent {uuid}."
            ));
            break;
        };
        chain.push(uuid.to_owned());
        cursor = node.parent.as_deref().or_else(|| {
            (archive && is_compact_boundary(&node.value))
                .then(|| node.value.get("logicalParentUuid").and_then(Value::as_str))
                .flatten()
        });
    }
    chain.reverse();
    Ok(recover_parallel_tools(nodes, chain))
}

fn response_id(node: &Node) -> Option<&str> {
    (node.value.get("type").and_then(Value::as_str) == Some("assistant"))
        .then(|| node.value.get("message")?.get("id")?.as_str())
        .flatten()
}

// Claude writes parallel tool blocks under one API message.id, but each result
// has its own parentUuid. Recover those siblings, not abandoned responses.
// Mirrors the first-party SDK's _recover_orphaned_parallel_tool_results.
fn recover_parallel_tools(nodes: &HashMap<String, Node>, chain: Vec<String>) -> Vec<String> {
    let mut anchors = HashMap::new();
    for uuid in &chain {
        if let Some(node) = nodes.get(uuid)
            && let Some(id) = response_id(node)
        {
            anchors.insert(id, uuid.as_str());
        }
    }
    if anchors.is_empty() {
        return chain;
    }
    let mut members: HashMap<&str, Vec<&Node>> = HashMap::new();
    let mut owners: HashMap<&str, Option<&Node>> = HashMap::new();
    for node in nodes.values() {
        if let Some(id) = response_id(node) {
            members.entry(id).or_default().push(node);
            for call in block_ids(node, "tool_use", "id") {
                owners
                    .entry(call)
                    .and_modify(|owner| {
                        if owner.is_some_and(|old| response_id(old) != Some(id)) {
                            *owner = None;
                        }
                    })
                    .or_insert(Some(node));
            }
        }
    }
    let mut results: HashMap<&str, Vec<&Node>> = HashMap::new();
    for node in nodes
        .values()
        .filter(|node| node.value.get("type").and_then(Value::as_str) == Some("user"))
    {
        let mut groups = HashSet::new();
        for call in block_ids(node, "tool_result", "tool_use_id") {
            if let Some(Some(owner)) = owners.get(call)
                && owner.value.get("agentId") == node.value.get("agentId")
                && let Some(id) = response_id(owner)
            {
                groups.insert(id);
            }
        }
        for id in groups {
            results.entry(id).or_default().push(node);
        }
    }
    let mut seen: HashSet<_> = chain.iter().map(String::as_str).collect();
    let mut answered: HashSet<_> = chain
        .iter()
        .filter_map(|id| nodes.get(id))
        .flat_map(|node| block_ids(node, "tool_result", "tool_use_id"))
        .collect();
    let mut inserts: HashMap<&str, Vec<String>> = HashMap::new();
    for (id, anchor) in anchors {
        let mut siblings = members.remove(id).unwrap_or_default();
        siblings.sort_by_key(|node| node.line);
        let mut recovered = Vec::new();
        for node in siblings {
            if seen.insert(node.uuid.as_str()) {
                recovered.push(node.uuid.clone());
            }
        }
        let mut group_results = results.remove(id).unwrap_or_default();
        group_results.sort_by_key(|node| node.line);
        for node in group_results {
            if seen.contains(node.uuid.as_str()) {
                continue;
            }
            let fresh = block_ids(node, "tool_result", "tool_use_id")
                .fold(false, |fresh, id| answered.insert(id) || fresh);
            if fresh {
                seen.insert(node.uuid.as_str());
                recovered.push(node.uuid.clone());
            }
        }
        if !recovered.is_empty() {
            inserts.insert(anchor, recovered);
        }
    }
    if inserts.is_empty() {
        return chain;
    }
    let mut result =
        Vec::with_capacity(chain.len() + inserts.values().map(Vec::len).sum::<usize>());
    for uuid in &chain {
        result.push(uuid.clone());
        if let Some(extra) = inserts.remove(uuid.as_str()) {
            result.extend(extra);
        }
    }
    result
}

fn block_ids<'a>(node: &'a Node, kind: &'a str, field: &'a str) -> impl Iterator<Item = &'a str> {
    node.value
        .get("message")
        .and_then(|message| message.get("content"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(move |block| block.get("type").and_then(Value::as_str) == Some(kind))
        .filter_map(move |block| block.get(field).and_then(Value::as_str))
}

fn convert_node(node: &Node, warnings: &mut Vec<String>) -> io::Result<Vec<ImportMessage>> {
    let record = node
        .value
        .as_object()
        .ok_or_else(|| invalid(format!("Claude Code record {} is not an object", node.line)))?;
    match string_field(record, "type") {
        Some("system") if is_compact_boundary(&node.value) => Ok(Vec::new()),
        Some("user") if bool_field(record, "isCompactSummary") => {
            let text = message_field(record)
                .and_then(|message| message.get("content"))
                .map(claude_text)
                .unwrap_or_default();
            if text.trim().is_empty() {
                return Err(invalid("Claude compact summary is empty"));
            }
            Ok(vec![ImportMessage::Summary { text }])
        }
        Some("user") => convert_user(record, node.line, warnings),
        Some("assistant") => convert_assistant(record, node.line, warnings),
        Some("system") => {
            warnings.push(format!(
                "Excluded foreign Claude system record {} from groky context.",
                node.line
            ));
            Ok(Vec::new())
        }
        Some(
            "custom-title"
            | "ai-title"
            | "file-history-snapshot"
            | "queue-operation"
            | "progress"
            | "attachment",
        ) => Ok(Vec::new()),
        Some(kind) if message_field(record).is_some() => Err(invalid(format!(
            "Unsupported context-bearing Claude Code record type {kind:?} at line {}",
            node.line
        ))),
        Some(kind) => {
            warnings.push(format!(
                "Ignored Claude Code record type {kind:?} at line {}.",
                node.line
            ));
            Ok(Vec::new())
        }
        None => Ok(Vec::new()),
    }
}

fn convert_user(
    record: &Map<String, Value>,
    line: usize,
    warnings: &mut Vec<String>,
) -> io::Result<Vec<ImportMessage>> {
    let message = message_field(record).ok_or_else(|| {
        invalid(format!(
            "Claude Code user record {line} has no message object"
        ))
    })?;
    let content = message.get("content").unwrap_or(&Value::Null);
    let mut converted = Vec::new();
    let mut normal_parts = Vec::new();
    if let Some(blocks) = content.as_array() {
        for raw_block in blocks {
            let Some(block) = raw_block.as_object() else {
                warnings.push(format!(
                    "Ignored malformed Claude user content block at line {line}."
                ));
                continue;
            };
            if string_field(block, "type") == Some("tool_result") {
                let Some(id) = string_field(block, "tool_use_id") else {
                    return Err(invalid(format!(
                        "Claude Code tool result at line {line} has no tool_use_id"
                    )));
                };
                converted.push(ImportMessage::ToolResult {
                    id: id.to_owned(),
                    content: claude_parts(
                        block.get("content").unwrap_or(&Value::Null),
                        warnings,
                        line,
                    ),
                    is_error: bool_field(block, "is_error"),
                });
            } else {
                normal_parts.extend(claude_parts(raw_block, warnings, line));
            }
        }
    } else {
        normal_parts = claude_parts(content, warnings, line);
    }
    if !normal_parts.is_empty() {
        converted.insert(
            0,
            ImportMessage::User {
                content: normal_parts,
            },
        );
    }
    Ok(converted)
}

fn convert_assistant(
    record: &Map<String, Value>,
    line: usize,
    warnings: &mut Vec<String>,
) -> io::Result<Vec<ImportMessage>> {
    let message = message_field(record).ok_or_else(|| {
        invalid(format!(
            "Claude Code assistant record {line} has no message object"
        ))
    })?;
    let content = message
        .get("content")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            invalid(format!(
                "Claude Code assistant record {line} has no content array"
            ))
        })?;
    let mut text = String::new();
    let mut tool_calls = Vec::new();
    let mut reasoning = Vec::new();
    for block in content {
        let Some(block) = block.as_object() else {
            warnings.push(format!(
                "Ignored malformed Claude assistant content block at line {line}."
            ));
            continue;
        };
        match string_field(block, "type") {
            Some("text") => {
                if let Some(part) = string_field(block, "text") {
                    text.push_str(part);
                }
            }
            Some("thinking") => {
                if let Some(part) = string_field(block, "thinking").filter(|part| !part.is_empty())
                {
                    reasoning.push(ImportMessage::Reasoning {
                        text: part.to_owned(),
                    });
                }
            }
            Some("tool_use") => {
                let id = string_field(block, "id").ok_or_else(|| {
                    invalid(format!("Claude Code tool call at line {line} has no id"))
                })?;
                let name = string_field(block, "name").ok_or_else(|| {
                    invalid(format!(
                        "Claude Code tool call {id} at line {line} has no name"
                    ))
                })?;
                let input = block
                    .get("input")
                    .cloned()
                    .unwrap_or_else(|| Value::Object(Map::new()));
                tool_calls.push(ImportToolCall {
                    id: id.to_owned(),
                    name: name.to_owned(),
                    arguments: serde_json::to_string(&input).map_err(|error| {
                        invalid(format!(
                            "Could not encode Claude Code tool call {id}: {error}"
                        ))
                    })?,
                });
            }
            Some(kind) => warnings.push(format!(
                "Ignored unsupported Claude assistant block {kind:?} at line {line}."
            )),
            None => warnings.push(format!(
                "Ignored untyped Claude assistant block at line {line}."
            )),
        }
    }
    let mut converted = reasoning;
    if !text.is_empty() || !tool_calls.is_empty() {
        converted.push(ImportMessage::Assistant { text, tool_calls });
    }
    Ok(converted)
}

fn claude_parts(value: &Value, warnings: &mut Vec<String>, line: usize) -> Vec<ImportContent> {
    match value {
        Value::String(text) => vec![ImportContent::Text(text.clone())],
        Value::Array(values) => values
            .iter()
            .flat_map(|value| claude_parts(value, warnings, line))
            .collect(),
        Value::Object(block) => match string_field(block, "type") {
            Some("text") => string_field(block, "text")
                .map(|text| vec![ImportContent::Text(text.to_owned())])
                .unwrap_or_default(),
            Some("image") => image_part(block, warnings, line).into_iter().collect(),
            Some("tool_result") => {
                claude_parts(block.get("content").unwrap_or(&Value::Null), warnings, line)
            }
            Some(kind) => {
                warnings.push(format!(
                    "Ignored unsupported Claude content block {kind:?} at line {line}."
                ));
                Vec::new()
            }
            None => Vec::new(),
        },
        Value::Null => Vec::new(),
        _ => {
            warnings.push(format!("Ignored non-text Claude content at line {line}."));
            Vec::new()
        }
    }
}

fn image_part(
    block: &Map<String, Value>,
    warnings: &mut Vec<String>,
    line: usize,
) -> Option<ImportContent> {
    let Some(source) = block.get("source").and_then(Value::as_object) else {
        warnings.push(format!(
            "Ignored Claude image without a source at line {line}."
        ));
        return None;
    };
    let (Some(media_type), Some(data)) = (
        string_field(source, "media_type"),
        string_field(source, "data"),
    ) else {
        warnings.push(format!(
            "Ignored Claude image without base64 data at line {line}."
        ));
        return None;
    };
    Some(ImportContent::Image {
        url: format!("data:{media_type};base64,{data}"),
    })
}

fn claude_text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Array(values) => values.iter().map(claude_text).collect(),
        Value::Object(block) if string_field(block, "type") == Some("text") => {
            string_field(block, "text").unwrap_or_default().to_owned()
        }
        _ => String::new(),
    }
}

fn node_score(node: &Node) -> (bool, usize) {
    let message = node.value.get("message");
    let complete = message
        .and_then(Value::as_object)
        .and_then(|message| message.get("stop_reason"))
        .is_some_and(|reason| !reason.is_null());
    (complete, node.line)
}

fn is_conversation_node(value: &Value) -> bool {
    matches!(
        value.get("type").and_then(Value::as_str),
        Some("user" | "assistant")
    )
}

fn message_field(record: &Map<String, Value>) -> Option<&Map<String, Value>> {
    record.get("message")?.as_object()
}

fn string_field<'a>(record: &'a Map<String, Value>, field: &str) -> Option<&'a str> {
    record.get(field)?.as_str()
}

fn bool_field(record: &Map<String, Value>, field: &str) -> bool {
    record.get(field).and_then(Value::as_bool).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    use serde_json::json;
    use tempfile::TempDir;

    fn write_lines(path: &Path, lines: &[Value]) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(
            path,
            format!(
                "{}\n",
                lines
                    .iter()
                    .map(Value::to_string)
                    .collect::<Vec<_>>()
                    .join("\n")
            ),
        )
        .unwrap();
    }

    fn candidate(path: &Path, cwd: &Path, leaf_id: Option<&str>) -> ImportCandidate {
        ImportCandidate {
            source: ImportSource::Claude,
            id: "session".to_owned(),
            path: path.to_path_buf(),
            cwd: cwd.to_path_buf(),
            title: "test".to_owned(),
            modified: modified(path),
            leaf_id: leaf_id.map(str::to_owned),
        }
    }

    #[test]
    fn selected_branch_keeps_tools_images_and_is_not_truncated_by_picker_titles() {
        let temp = TempDir::new().unwrap();
        let cwd = temp.path().join("repo");
        fs::create_dir_all(&cwd).unwrap();
        let path = temp.path().join("session.jsonl");
        write_lines(
            &path,
            &[
                json!({"type":"user","uuid":"u1","cwd":cwd,"message":{"content":"old prompt"}}),
                json!({"type":"assistant","uuid":"a1","parentUuid":"u1","message":{"content":[{"type":"tool_use","id":"call","name":"read","input":{"path":"x"}}]}}),
                json!({"type":"user","uuid":"r1","parentUuid":"a1","message":{"content":[{"type":"tool_result","tool_use_id":"call","content":"file"}]}}),
                json!({"type":"user","uuid":"side","parentUuid":"u1","message":{"content":"discarded branch"}}),
                json!({"type":"assistant","uuid":"a2","parentUuid":"r1","message":{"content":[{"type":"text","text":"partial"}]}}),
                json!({"type":"assistant","uuid":"a2","parentUuid":"r1","message":{"stop_reason":"end_turn","content":[{"type":"text","text":"final"}]}}),
                json!({"type":"user","uuid":"u2","parentUuid":"a2","message":{"content":[{"type":"image","source":{"media_type":"image/png","data":"YWJj"}},{"type":"text","text":"new prompt"}]}}),
                json!({"type":"assistant","uuid":"a3","parentUuid":"u2","message":{"content":[{"type":"text","text":"done"}]}}),
                json!({"type":"summary","leafUuid":"r1","summary":"old work summarized"}),
                json!({"type":"assistant","uuid":"sub","isSidechain":true,"message":{"content":[{"type":"text","text":"subagent"}]}}),
            ],
        );

        let imported = load(&candidate(&path, &cwd, None)).unwrap();
        assert!(!imported.messages.iter().any(|message| matches!(
            message, ImportMessage::Summary { text } if text == "old work summarized"
        )));
        assert!(imported.messages.iter().any(|message| matches!(
            message,
            ImportMessage::User { content } if content.iter().any(|part| matches!(part, ImportContent::Image { url } if url == "data:image/png;base64,YWJj"))
        )));
        assert!(
            !imported
                .messages
                .iter()
                .any(|message| format!("{message:?}").contains("discarded branch"))
        );
        assert!(
            !imported
                .messages
                .iter()
                .any(|message| format!("{message:?}").contains("partial"))
        );
        let first_context = imported
            .context
            .first()
            .and_then(|index| imported.messages.get(*index));
        assert!(
            matches!(first_context, Some(ImportMessage::User { content })
            if matches!(content.first(), Some(ImportContent::Text(text)) if text == "old prompt"))
        );
    }

    #[test]
    fn compact_boundary_separates_visible_archive_from_effective_summary() {
        let temp = TempDir::new().unwrap();
        let cwd = temp.path().join("repo");
        fs::create_dir_all(&cwd).unwrap();
        let path = temp.path().join("session.jsonl");
        write_lines(
            &path,
            &[
                json!({"type":"user","uuid":"old","cwd":cwd,"message":{"content":"archived request"}}),
                json!({"type":"system","subtype":"compact_boundary","uuid":"boundary","parentUuid":null,"logicalParentUuid":"old"}),
                json!({"type":"user","uuid":"summary","parentUuid":"boundary","isCompactSummary":true,"isMeta":true,"message":{"content":"important retained facts"}}),
                json!({"type":"user","uuid":"next","parentUuid":"summary","message":{"content":"next request"}}),
            ],
        );
        let imported = load(&candidate(&path, &cwd, None)).unwrap();
        assert!(imported.messages.iter().any(|message| matches!(message, ImportMessage::User { content }
            if matches!(content.first(), Some(ImportContent::Text(text)) if text == "archived request"))));
        let context: Vec<_> = imported
            .context
            .iter()
            .filter_map(|index| imported.messages.get(*index))
            .collect();
        assert!(
            matches!(context.as_slice(), [ImportMessage::Summary { text }, ImportMessage::User { content }]
            if text == "important retained facts" && matches!(content.first(), Some(ImportContent::Text(text)) if text == "next request"))
        );
    }

    #[test]
    fn parallel_tool_siblings_are_recovered_without_abandoned_response() {
        let temp = TempDir::new().unwrap();
        let cwd = temp.path().join("repo");
        fs::create_dir_all(&cwd).unwrap();
        let path = temp.path().join("session.jsonl");
        write_lines(
            &path,
            &[
                json!({"type":"user","uuid":"u","cwd":cwd,"message":{"content":"read both"}}),
                json!({"type":"assistant","uuid":"old","parentUuid":"u","message":{"id":"abandoned","content":[{"type":"tool_use","id":"old","name":"read","input":{}}]}}),
                json!({"type":"assistant","uuid":"a1","parentUuid":"u","message":{"id":"parallel","content":[{"type":"tool_use","id":"call1","name":"read","input":{"path":"one"}}]}}),
                json!({"type":"assistant","uuid":"a2","parentUuid":"a1","message":{"id":"parallel","content":[{"type":"tool_use","id":"call2","name":"read","input":{"path":"two"}}]}}),
                json!({"type":"user","uuid":"r2","parentUuid":"a2","message":{"content":[{"type":"tool_result","tool_use_id":"call2","content":"second file"}]}}),
                json!({"type":"user","uuid":"r1","parentUuid":"a1","message":{"content":[{"type":"tool_result","tool_use_id":"call1","content":"first file"}]}}),
                json!({"type":"assistant","uuid":"answer","parentUuid":"r1","message":{"content":[{"type":"text","text":"done"}]}}),
            ],
        );
        let imported = load(&candidate(&path, &cwd, None)).unwrap();
        let calls: Vec<_> = imported
            .messages
            .iter()
            .filter_map(|message| match message {
                ImportMessage::Assistant { tool_calls, .. } => {
                    Some(tool_calls.iter().map(|call| call.id.as_str()))
                }
                _ => None,
            })
            .flatten()
            .collect();
        assert_eq!(calls, ["call1", "call2"]);
        let results: HashSet<_> = imported
            .messages
            .iter()
            .filter_map(|message| match message {
                ImportMessage::ToolResult { id, .. } => Some(id.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(results, HashSet::from(["call1", "call2"]));
        assert!(
            matches!(imported.messages.last(), Some(ImportMessage::Assistant { text, .. }) if text == "done")
        );
    }

    #[test]
    fn discovers_config_override_from_bounded_headers() {
        let temp = TempDir::new().unwrap();
        let cwd = temp.path().join("repo");
        fs::create_dir_all(&cwd).unwrap();
        let project = temp.path().join("projects").join("encoded");
        let path = project.join("session.jsonl");
        write_lines(
            &path,
            &[json!({"type":"user","uuid":"u","cwd":cwd,"message":{"content":"header title"}})],
        );
        let candidate = candidate_from_path(&path).unwrap();
        assert_eq!(candidate.cwd, cwd);
        assert_eq!(candidate.title, "header title");
    }

    #[test]
    fn refuses_unknown_context_bearing_chain_record() {
        let temp = TempDir::new().unwrap();
        let cwd = temp.path().join("repo");
        fs::create_dir_all(&cwd).unwrap();
        let path = temp.path().join("session.jsonl");
        write_lines(
            &path,
            &[
                json!({"type":"user","uuid":"u","cwd":cwd,"message":{"content":"start"}}),
                json!({"type":"future_context","uuid":"x","parentUuid":"u","message":{"content":"unknown"}}),
                json!({"type":"assistant","uuid":"a","parentUuid":"x","message":{"content":[{"type":"text","text":"answer"}]}}),
            ],
        );
        let error = load(&candidate(&path, &cwd, None)).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Unsupported context-bearing Claude Code record")
        );
    }
    #[test]
    fn rejects_source_session_id_mismatch() {
        let temp = TempDir::new().unwrap();
        let cwd = temp.path().join("repo");
        fs::create_dir_all(&cwd).unwrap();
        let path = temp.path().join("session.jsonl");
        write_lines(
            &path,
            &[json!({
                "type":"user",
                "uuid":"u",
                "sessionId":"different",
                "cwd":cwd,
                "message":{"content":"start"}
            })],
        );
        let error = load(&candidate(&path, &cwd, None)).unwrap_err();
        assert!(error.to_string().contains("identifies itself as different"));
    }
}
