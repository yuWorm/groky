//! Read-only foreign transcripts, reconstructed before they become native sessions.
//! Discovery is metadata-only; only a selected session is fully decoded.

mod claude;
mod codex;
mod common;
mod opencode;
mod pi;

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ImportSource {
    Omp,
    Pi,
    Claude,
    Codex,
    #[serde(rename = "opencode")]
    OpenCode,
}

impl ImportSource {
    pub const ALL: [Self; 5] = [
        Self::Omp,
        Self::Pi,
        Self::Claude,
        Self::Codex,
        Self::OpenCode,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Omp => "omp",
            Self::Pi => "pi",
            Self::Claude => "claude",
            Self::Codex => "codex",
            Self::OpenCode => "opencode",
        }
    }
}

impl fmt::Display for ImportSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ImportSource {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|source| source.as_str().eq_ignore_ascii_case(value))
            .or_else(|| {
                value
                    .eq_ignore_ascii_case("claude-code")
                    .then_some(Self::Claude)
            })
            .or_else(|| {
                value
                    .eq_ignore_ascii_case("open-code")
                    .then_some(Self::OpenCode)
            })
            .ok_or_else(|| {
                format!("Unknown session source {value:?}; use omp, pi, claude, codex, or opencode")
            })
    }
}

#[derive(Debug, Clone)]
pub struct ImportCandidate {
    pub source: ImportSource,
    pub id: String,
    pub path: PathBuf,
    pub cwd: PathBuf,
    pub title: String,
    pub modified: SystemTime,
    pub leaf_id: Option<String>,
}

#[derive(Debug, Default)]
pub struct ImportDiscovery {
    pub sessions: Vec<ImportCandidate>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ImportContent {
    Text(String),
    Image { url: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportToolCall {
    pub id: String,
    pub name: String,
    pub arguments: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ImportMessage {
    User {
        content: Vec<ImportContent>,
    },
    Assistant {
        text: String,
        tool_calls: Vec<ImportToolCall>,
    },
    ToolResult {
        id: String,
        content: Vec<ImportContent>,
        is_error: bool,
    },
    Summary {
        text: String,
    },
    Reasoning {
        text: String,
    },
}

/// `messages` is display history on the selected branch. `context` addresses only
/// the effective continuation, in model order, without duplicating large messages.
#[derive(Debug)]
pub struct ImportedSession {
    pub candidate: ImportCandidate,
    pub messages: Vec<ImportMessage>,
    pub context: Vec<usize>,
    pub warnings: Vec<String>,
}

impl ImportedSession {
    pub fn new(candidate: ImportCandidate) -> Self {
        Self {
            candidate,
            messages: Vec::new(),
            context: Vec::new(),
            warnings: Vec::new(),
        }
    }

    pub fn push(&mut self, message: ImportMessage, in_context: bool) -> usize {
        let index = self.messages.len();
        self.messages.push(message);
        if in_context {
            self.context.push(index);
        }
        index
    }

    pub fn warn(&mut self, warning: impl Into<String>) {
        let warning = warning.into();
        if !self.warnings.contains(&warning) {
            self.warnings.push(warning);
        }
    }
}

/// Scan all supported stores, defaulting to an exact canonical cwd match. Passing
/// `None` explicitly widens discovery to all projects. No source agent is launched.
pub fn discover(cwd: Option<&Path>) -> ImportDiscovery {
    let mut out = ImportDiscovery::default();
    pi::discover(ImportSource::Omp, cwd, &mut out);
    pi::discover(ImportSource::Pi, cwd, &mut out);
    claude::discover(cwd, &mut out);
    codex::discover(cwd, &mut out);
    opencode::discover(cwd, &mut out);
    out.sessions.sort_by(|a, b| {
        b.modified
            .cmp(&a.modified)
            .then_with(|| a.source.as_str().cmp(b.source.as_str()))
            .then_with(|| a.id.cmp(&b.id))
            .then_with(|| a.path.cmp(&b.path))
    });
    let mut seen = HashSet::new();
    out.sessions.retain(|candidate| {
        seen.insert((
            candidate.source,
            candidate.id.clone(),
            candidate.path.clone(),
        ))
    });
    out
}

/// Inspect an explicitly selected transcript or store. Multi-session stores need
/// `id`; this function never picks an arbitrary session from a database.
pub fn inspect(source: ImportSource, path: &Path, id: Option<&str>) -> io::Result<ImportCandidate> {
    match source {
        ImportSource::Omp | ImportSource::Pi => pi::inspect(source, path, id),
        ImportSource::Claude => claude::inspect(path, id),
        ImportSource::Codex => codex::inspect(path, id),
        ImportSource::OpenCode => opencode::inspect(path, id),
    }
}

pub fn load(candidate: &ImportCandidate) -> io::Result<ImportedSession> {
    let mut imported = match candidate.source {
        ImportSource::Omp | ImportSource::Pi => pi::load(candidate),
        ImportSource::Claude => claude::load(candidate),
        ImportSource::Codex => codex::load(candidate),
        ImportSource::OpenCode => opencode::load(candidate),
    }?;
    validate(&mut imported)?;
    Ok(imported)
}

fn validate(imported: &mut ImportedSession) -> io::Result<()> {
    let mut seen = HashSet::new();
    for &index in &imported.context {
        if index >= imported.messages.len() || !seen.insert(index) {
            return Err(common::invalid(
                "Invalid or repeated imported context index",
            ));
        }
    }
    imported.context.retain(|&index| {
        !matches!(
            imported.messages.get(index),
            Some(ImportMessage::Reasoning { .. })
        )
    });
    if imported.context.is_empty() {
        return Err(common::invalid(
            "This session has no recoverable conversation context",
        ));
    }

    // Mint transcript-local call IDs, independent of the source's namespaces.
    // A source may legitimately reuse an ID in different turns.
    let mut calls = HashMap::<String, String>::new();
    for (index, message) in imported.messages.iter_mut().enumerate() {
        match message {
            ImportMessage::Assistant { tool_calls, .. } => {
                for (offset, call) in tool_calls.iter_mut().enumerate() {
                    if serde_json::from_str::<serde_json::Value>(&call.arguments).is_err() {
                        return Err(common::invalid(format!(
                            "Invalid JSON arguments for historical tool {}",
                            call.name
                        )));
                    }
                    let new_id = format!("import-{index}-{offset}");
                    calls.insert(std::mem::replace(&mut call.id, new_id.clone()), new_id);
                }
            }
            ImportMessage::ToolResult { id, .. } => {
                if let Some(mapped) = calls.remove(id) {
                    *id = mapped;
                }
            }
            _ => {}
        }
    }

    // A branch/compaction can retain only one half of a tool interaction. Keep
    // the evidence as text, not malformed protocol messages or executable work.
    let mut pending = HashSet::new();
    let mut paired = HashSet::new();
    let mut orphan_results = Vec::new();
    for &index in &imported.context {
        match imported.messages.get(index) {
            Some(ImportMessage::Assistant { tool_calls, .. }) => {
                pending.extend(tool_calls.iter().map(|call| call.id.clone()));
            }
            Some(ImportMessage::ToolResult { id, .. }) => {
                if pending.remove(id) {
                    paired.insert(id.clone());
                } else {
                    orphan_results.push(index);
                }
            }
            _ => {}
        }
    }
    let mut incomplete = false;
    for &index in &imported.context {
        if let Some(ImportMessage::Assistant { text, tool_calls }) =
            imported.messages.get_mut(index)
        {
            tool_calls.retain(|call| {
                if paired.contains(&call.id) {
                    return true;
                }
                incomplete = true;
                use std::fmt::Write as _;
                let _ = write!(text, "\n[Historical tool call {}({}) has no result in the imported context. Its effects are unknown; it has not been rerun.]", call.name, call.arguments);
                false
            });
        }
    }
    for index in orphan_results {
        if let Some(message) = imported.messages.get_mut(index) {
            let old = std::mem::replace(
                message,
                ImportMessage::Summary {
                    text: String::new(),
                },
            );
            if let ImportMessage::ToolResult {
                id,
                content,
                is_error,
            } = old
            {
                let mut parts = vec![ImportContent::Text(format!(
                    "[Historical tool result {id}; originating call is outside the imported context; error={is_error}]"
                ))];
                parts.extend(content);
                *message = ImportMessage::User { content: parts };
            }
        }
        incomplete = true;
    }
    if incomplete {
        imported.warn("Incomplete tool interactions were retained as historical notes, not executable tool calls.");
    }
    imported.warnings.sort();
    imported.warnings.dedup();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> ImportedSession {
        ImportedSession::new(ImportCandidate {
            source: ImportSource::Pi,
            id: "source".into(),
            path: "source.jsonl".into(),
            cwd: "/workspace".into(),
            title: "Example".into(),
            modified: SystemTime::UNIX_EPOCH,
            leaf_id: None,
        })
    }

    #[test]
    fn incomplete_calls_are_evidence_not_pending_work() {
        let mut value = session();
        value.push(
            ImportMessage::Assistant {
                text: "Checking".into(),
                tool_calls: vec![ImportToolCall {
                    id: "call".into(),
                    name: "bash".into(),
                    arguments: "{\"command\":\"touch file\"}".into(),
                }],
            },
            true,
        );
        validate(&mut value).unwrap();
        let Some(ImportMessage::Assistant { text, tool_calls }) = value.messages.first() else {
            panic!()
        };
        assert!(tool_calls.is_empty());
        assert!(text.contains("touch file"));
        assert!(text.contains("effects are unknown"));
    }

    #[test]
    fn reused_source_call_ids_remain_distinct_pairs() {
        let mut value = session();
        for output in ["first", "second"] {
            value.push(
                ImportMessage::Assistant {
                    text: String::new(),
                    tool_calls: vec![ImportToolCall {
                        id: "reused".into(),
                        name: "read".into(),
                        arguments: "{}".into(),
                    }],
                },
                true,
            );
            value.push(
                ImportMessage::ToolResult {
                    id: "reused".into(),
                    content: vec![ImportContent::Text(output.into())],
                    is_error: false,
                },
                true,
            );
        }
        validate(&mut value).unwrap();
        let ids: Vec<_> = value
            .messages
            .iter()
            .filter_map(|message| match message {
                ImportMessage::ToolResult { id, .. } => Some(id.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(ids, ["import-0-0", "import-2-0"]);
    }

    #[test]
    fn compacted_away_call_does_not_leave_orphan_protocol_result() {
        let mut value = session();
        value.push(
            ImportMessage::Assistant {
                text: String::new(),
                tool_calls: vec![ImportToolCall {
                    id: "old".into(),
                    name: "read".into(),
                    arguments: "{}".into(),
                }],
            },
            false,
        );
        value.push(
            ImportMessage::ToolResult {
                id: "old".into(),
                content: vec![ImportContent::Text("evidence".into())],
                is_error: false,
            },
            true,
        );
        validate(&mut value).unwrap();
        assert!(
            matches!(value.messages.get(1), Some(ImportMessage::User { content }) if content.iter().any(|part| matches!(part, ImportContent::Text(text) if text == "evidence")))
        );
    }
}
