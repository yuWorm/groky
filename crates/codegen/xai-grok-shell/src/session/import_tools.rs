//! Presents normalized foreign tool calls as the ACP tool cards the pager already renders.
//!
//! [`ToolView`] says what a historical call did; this module picks the matching ACP kind,
//! canonical `raw_input` keys and result shape (`ToolOutput::Bash` for commands, `Diff`
//! content for edits) so imports show commands, reads and diffs instead of raw JSON.
//! Only the display history uses this; model context keeps the source's own calls.

use std::sync::Arc;

use agent_client_protocol as acp;
use serde_json::json;
use xai_grok_foreign_sessions::import::tools::{ExecOutcome, FileEdit, PlanStatus, ToolView};

/// A presented call; multi-file edits add one card per extra file, sharing the result.
pub(super) struct PresentedCall {
    pub(super) view: ToolView,
    pub(super) calls: Vec<acp::ToolCall>,
}

fn tool_call(id: &str, title: impl Into<String>, kind: acp::ToolKind) -> acp::ToolCall {
    acp::ToolCall::new(acp::ToolCallId::new(Arc::<str>::from(id)), title)
        .kind(kind)
        .status(acp::ToolCallStatus::Pending)
}

fn edit_call(id: &str, edit: &FileEdit) -> acp::ToolCall {
    let mut diff = acp::Diff::new(edit.path.clone(), edit.new_text.clone());
    if edit.old_text.is_some() || edit.deleted {
        diff = diff.old_text(Some(edit.old_text.clone().unwrap_or_default()));
    }
    if let Some(line) = edit.start_line {
        let mut meta = serde_json::Map::new();
        meta.insert("new_line".to_owned(), json!(line));
        diff = diff.meta(Some(meta));
    }
    let mut location = acp::ToolCallLocation::new(edit.path.clone());
    if let Some(line) = edit.start_line.and_then(|line| u32::try_from(line).ok()) {
        location = location.line(Some(line));
    }
    let mut raw_input = json!({ "file_path": edit.path });
    if edit.old_text.is_none() && !edit.deleted {
        raw_input["variant"] = json!("Write");
    }
    let title = if edit.deleted {
        format!("Delete {}", edit.path)
    } else {
        edit.path.clone()
    };
    tool_call(id, title, acp::ToolKind::Edit)
        .raw_input(Some(raw_input))
        .locations(vec![location])
        .content(vec![acp::ToolCallContent::Diff(diff)])
}

fn plan_text(items: &[xai_grok_foreign_sessions::import::tools::PlanItem]) -> String {
    items
        .iter()
        .map(|item| {
            let mark = match item.status {
                PlanStatus::Completed => "☑",
                PlanStatus::InProgress => "◐",
                PlanStatus::Pending => "☐",
            };
            format!("{mark} {}", item.text)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn text_content(text: String) -> acp::ToolCallContent {
    acp::ToolCallContent::from(acp::ContentBlock::Text(acp::TextContent::new(text)))
}

/// Build the cards for one historical call. Extra edit cards use `"{id}#{n}"` IDs.
pub(super) fn present_call(view: ToolView, id: &str, original_name: &str) -> PresentedCall {
    let calls = match &view {
        ToolView::Exec {
            command,
            cwd,
            description,
        } => vec![
            tool_call(id, command.clone(), acp::ToolKind::Execute).raw_input(Some(json!({
                "command": command,
                "cwd": cwd,
                "description": description,
            }))),
        ],
        ToolView::Read {
            path,
            offset,
            limit,
        } => vec![
            tool_call(id, path.clone(), acp::ToolKind::Read)
                .raw_input(Some(json!({ "file_path": path, "offset": offset, "limit": limit })))
                .locations(vec![acp::ToolCallLocation::new(path.clone())]),
        ],
        ToolView::Edit(files) => files
            .iter()
            .enumerate()
            .map(|(index, edit)| {
                if index == 0 {
                    edit_call(id, edit)
                } else {
                    edit_call(&format!("{id}#{index}"), edit)
                }
            })
            .collect(),
        ToolView::Search { pattern, path } => vec![
            tool_call(id, pattern.clone(), acp::ToolKind::Search)
                .raw_input(Some(json!({ "pattern": pattern, "path": path }))),
        ],
        ToolView::WebSearch { query } => vec![
            tool_call(id, format!("Web search: {query}"), acp::ToolKind::Search)
                .raw_input(Some(json!({ "query": query, "variant": "WebSearch" }))),
        ],
        ToolView::WebFetch { url } => vec![
            tool_call(id, format!("Fetch: {url}"), acp::ToolKind::Fetch)
                .raw_input(Some(json!({ "url": url }))),
        ],
        ToolView::Plan(items) => vec![
            tool_call(id, "Update plan", acp::ToolKind::Other)
                .content(vec![text_content(plan_text(items))]),
        ],
        ToolView::Subagent { description } => vec![tool_call(
            id,
            format!("Subagent: {description}"),
            acp::ToolKind::Other,
        )],
        ToolView::Mcp {
            server,
            tool,
            input,
        } => vec![
            tool_call(id, tool.clone(), acp::ToolKind::Other).raw_input(Some(json!({
                "variant": "MCPTool",
                "tool_name": format!("{server} · {tool}"),
                "tool_input": input,
            }))),
        ],
        ToolView::Other { title } => {
            let title = if title.is_empty() {
                original_name.to_owned()
            } else {
                title.clone()
            };
            vec![tool_call(id, title, acp::ToolKind::Other)]
        }
    };
    PresentedCall { view, calls }
}

fn bash_output(command: &str, outcome: &ExecOutcome) -> Option<serde_json::Value> {
    let output = xai_grok_tools::types::output::ToolOutput::Bash(
        xai_grok_tools::types::output::BashOutput {
            output: outcome.output.as_bytes().to_vec(),
            output_for_prompt: String::new(),
            exit_code: outcome.exit_code,
            command: command.to_owned(),
            truncated: false,
            signal: None,
            timed_out: false,
            description: None,
            current_dir: String::new(),
            output_file: String::new(),
            total_bytes: outcome.output.len(),
            output_delta: None,
            was_bare_echo: false,
        },
    );
    serde_json::to_value(output).ok()
}

/// Result fields for every card of a presented call.
///
/// `failure_note` prefixes failed results so they never read as a successful execution.
pub(super) fn result_fields(
    view: &ToolView,
    text: &str,
    blocks: Vec<acp::ContentBlock>,
    is_error: bool,
    failure_note: &str,
) -> acp::ToolCallUpdateFields {
    let status = if is_error {
        acp::ToolCallStatus::Failed
    } else {
        acp::ToolCallStatus::Completed
    };
    let fields = acp::ToolCallUpdateFields::new().status(Some(status));
    let with_blocks = |mut blocks: Vec<acp::ContentBlock>| {
        if is_error {
            blocks.insert(
                0,
                acp::ContentBlock::Text(acp::TextContent::new(failure_note)),
            );
        }
        blocks
            .into_iter()
            .map(acp::ToolCallContent::from)
            .collect::<Vec<_>>()
    };
    match view {
        ToolView::Exec { command, .. } => {
            let outcome = xai_grok_foreign_sessions::import::tools::exec_outcome(text, is_error);
            let fields = fields.raw_output(bash_output(command, &outcome));
            if is_error {
                fields.content(Some(with_blocks(blocks)))
            } else {
                fields
            }
        }
        // The recorded diff or checklist is the useful part; keep it unless the call failed.
        ToolView::Edit(_) | ToolView::Plan(_) if !is_error => fields,
        _ => fields.content(Some(with_blocks(blocks))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multi_file_edits_get_one_card_per_file() {
        let view = ToolView::Edit(vec![
            FileEdit {
                path: "a.rs".into(),
                old_text: Some("x\n".into()),
                new_text: "y\n".into(),
                start_line: Some(3),
                deleted: false,
            },
            FileEdit {
                path: "b.rs".into(),
                old_text: None,
                new_text: "new\n".into(),
                start_line: None,
                deleted: false,
            },
        ]);
        let presented = present_call(view, "call", "apply_patch");
        assert_eq!(presented.calls.len(), 2);
        assert_eq!(presented.calls[1].tool_call_id.0.as_ref(), "call#1");
        assert!(presented.calls.iter().all(|call| call.kind == acp::ToolKind::Edit));
        assert!(matches!(
            presented.calls[0].content.first(),
            Some(acp::ToolCallContent::Diff(diff)) if diff.old_text.as_deref() == Some("x\n")
        ));
        assert_eq!(
            presented.calls[1].raw_input.as_ref().and_then(|raw| raw.get("variant")),
            Some(&json!("Write"))
        );
    }

    #[test]
    fn exec_results_carry_bash_output_with_exit_code() {
        let view = ToolView::Exec {
            command: "false".into(),
            cwd: None,
            description: None,
        };
        let fields = result_fields(
            &view,
            "Process exited with code 1\nOutput:\nnope\n",
            vec![],
            false,
            "failed",
        );
        let raw = fields.raw_output.expect("bash output");
        assert_eq!(raw["type"], "Bash");
        assert_eq!(raw["exit_code"], 1);
    }
}
