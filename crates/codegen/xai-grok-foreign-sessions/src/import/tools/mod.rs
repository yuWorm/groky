//! Display-only normalization of foreign tool calls.
//!
//! Every agent names and shapes its tools differently (`Bash` vs `exec_command` vs `bash`,
//! `old_string` vs `oldText` vs `oldString`, V4A vs hashline patches). [`classify`] maps a
//! recorded call onto one [`ToolView`] so the native transcript can render commands, reads,
//! diffs and searches as real tool cards. The recorded name and arguments are never rewritten;
//! the model context still sees exactly what the source agent ran.

mod patch;

use serde_json::{Map, Value};

use super::ImportSource;

pub use patch::{parse_hashline, parse_v4a};

/// What a historical tool call did, in agent-neutral terms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolView {
    Exec {
        command: String,
        cwd: Option<String>,
        description: Option<String>,
    },
    Read {
        path: String,
        offset: Option<u64>,
        limit: Option<u64>,
    },
    Edit(Vec<FileEdit>),
    /// Content search (`grep`) or path search (`glob`).
    Search {
        pattern: String,
        path: Option<String>,
    },
    WebSearch {
        query: String,
    },
    WebFetch {
        url: String,
    },
    Plan(Vec<PlanItem>),
    Subagent {
        description: String,
    },
    Mcp {
        server: String,
        tool: String,
        input: Value,
    },
    /// Anything else, with the most readable title the source offers.
    Other {
        title: String,
    },
}

/// One file touched by an edit, reduced to the before/after text the source recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEdit {
    pub path: String,
    /// `None` for a created file; `Some("")` when only the inserted lines are known.
    pub old_text: Option<String>,
    pub new_text: String,
    /// 1-based line where the change starts, when the source records it.
    pub start_line: Option<u64>,
    pub deleted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanItem {
    pub text: String,
    pub status: PlanStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanStatus {
    Pending,
    InProgress,
    Completed,
}

/// Command output with the source's bookkeeping removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecOutcome {
    pub exit_code: i32,
    pub output: String,
}

fn str_field<'a>(args: &'a Map<String, Value>, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| args.get(*key).and_then(Value::as_str))
        .filter(|value| !value.trim().is_empty())
}

fn u64_field(args: &Map<String, Value>, keys: &[&str]) -> Option<u64> {
    keys.iter().find_map(|key| {
        args.get(*key).and_then(|value| {
            value
                .as_u64()
                .or_else(|| value.as_str().and_then(|s| s.parse().ok()))
        })
    })
}

/// `bash -lc "cmd"`-style argv arrays collapse to the inner command; others are joined.
fn command_from_array(items: &[Value]) -> Option<String> {
    let parts: Vec<&str> = items.iter().filter_map(Value::as_str).collect();
    match parts.as_slice() {
        [] => None,
        [shell, flag, script]
            if matches!(*shell, "bash" | "sh" | "zsh" | "/bin/bash" | "/bin/sh" | "/bin/zsh")
                && matches!(*flag, "-c" | "-lc" | "-ic") =>
        {
            Some((*script).to_owned())
        }
        _ => Some(parts.join(" ")),
    }
}

fn exec_view(args: &Map<String, Value>, description: Option<&str>) -> Option<ToolView> {
    let command = match args.get("command").or_else(|| args.get("cmd")) {
        Some(Value::String(command)) if !command.trim().is_empty() => command.clone(),
        Some(Value::Array(items)) => command_from_array(items)?,
        _ => return None,
    };
    Some(ToolView::Exec {
        command,
        cwd: str_field(args, &["cwd", "workdir", "working_directory", "workingDirectory"])
            .map(str::to_owned),
        description: str_field(args, &["description"])
            .or(description)
            .map(str::to_owned),
    })
}

/// Agent-internal URIs (`skill://`, `agent://`, `proc://`) are not files on disk.
fn is_file_path(path: &str) -> bool {
    !path.contains("://")
}

fn read_view(args: &Map<String, Value>) -> Option<ToolView> {
    let path = str_field(args, &["file_path", "filePath", "path", "target_file"])?;
    is_file_path(path).then(|| ToolView::Read {
        path: path.to_owned(),
        offset: u64_field(args, &["offset", "start_line", "startLine"]),
        limit: u64_field(args, &["limit", "lines"]),
    })
}

fn replace_view(args: &Map<String, Value>) -> Option<ToolView> {
    let path = str_field(args, &["file_path", "filePath", "path"])?.to_owned();
    let field = |keys: &[&str]| {
        keys.iter()
            .find_map(|key| args.get(*key).and_then(Value::as_str))
            .map(str::to_owned)
    };
    // Claude `MultiEdit` and pi `edits` carry several replacements for one file.
    if let Some(edits) = args.get("edits").and_then(Value::as_array) {
        let files: Vec<FileEdit> = edits
            .iter()
            .filter_map(Value::as_object)
            .filter_map(|edit| {
                let old = str_any(edit, &["old_string", "oldString", "oldText", "old_text"])?;
                let new = str_any(edit, &["new_string", "newString", "newText", "new_text"])?;
                Some(FileEdit {
                    path: path.clone(),
                    old_text: Some(old.to_owned()),
                    new_text: new.to_owned(),
                    start_line: None,
                    deleted: false,
                })
            })
            .collect();
        return (!files.is_empty()).then_some(ToolView::Edit(files));
    }
    let old = field(&["old_string", "oldString", "oldText", "old_text"])?;
    let new = field(&["new_string", "newString", "newText", "new_text"]).unwrap_or_default();
    Some(ToolView::Edit(vec![FileEdit {
        path,
        old_text: Some(old),
        new_text: new,
        start_line: None,
        deleted: false,
    }]))
}

fn str_any<'a>(args: &'a Map<String, Value>, keys: &[&str]) -> Option<&'a str> {
    keys.iter().find_map(|key| args.get(*key).and_then(Value::as_str))
}

fn write_view(args: &Map<String, Value>) -> Option<ToolView> {
    let path = str_field(args, &["file_path", "filePath", "path"])?;
    if !is_file_path(path) {
        return None;
    }
    let content = str_any(args, &["content", "contents", "text"])?;
    Some(ToolView::Edit(vec![FileEdit {
        path: path.to_owned(),
        old_text: None,
        new_text: content.to_owned(),
        start_line: None,
        deleted: false,
    }]))
}

fn patch_view(args: &Map<String, Value>) -> Option<ToolView> {
    let patch = str_any(args, &["input", "patch", "patchText", "patch_text"])?;
    let files = if patch.contains("*** Update File:")
        || patch.contains("*** Add File:")
        || patch.contains("*** Delete File:")
    {
        parse_v4a(patch)
    } else {
        parse_hashline(patch)
    };
    (!files.is_empty()).then_some(ToolView::Edit(files))
}

fn search_view(args: &Map<String, Value>, glob: bool) -> Option<ToolView> {
    // omp's glob puts the pattern in `path`.
    let pattern = str_field(args, &["pattern", "query", "regex", "glob"])
        .or_else(|| glob.then(|| str_field(args, &["path"])).flatten())?;
    let path = str_field(args, &["path", "directory", "dir"]).filter(|path| *path != pattern);
    Some(ToolView::Search {
        pattern: pattern.to_owned(),
        path: path.map(str::to_owned),
    })
}

fn plan_status(value: Option<&str>) -> PlanStatus {
    match value.unwrap_or_default() {
        "completed" | "done" | "complete" => PlanStatus::Completed,
        "in_progress" | "in-progress" | "active" | "doing" => PlanStatus::InProgress,
        _ => PlanStatus::Pending,
    }
}

fn plan_view(args: &Map<String, Value>) -> Option<ToolView> {
    let list = ["todos", "plan", "items", "list"]
        .iter()
        .find_map(|key| args.get(*key).and_then(Value::as_array))?;
    let mut items = Vec::new();
    for entry in list {
        match entry {
            Value::String(text) => items.push(PlanItem {
                text: text.clone(),
                status: PlanStatus::Pending,
            }),
            Value::Object(entry) => {
                // omp groups items under phases: `{phase, items: [...]}`.
                if let Some(nested) = entry.get("items").and_then(Value::as_array) {
                    for item in nested {
                        let text = item
                            .as_str()
                            .or_else(|| item.get("content").and_then(Value::as_str));
                        if let Some(text) = text {
                            items.push(PlanItem {
                                text: text.to_owned(),
                                status: plan_status(item.get("status").and_then(Value::as_str)),
                            });
                        }
                    }
                    continue;
                }
                if let Some(text) = str_any(entry, &["content", "step", "text", "title"]) {
                    items.push(PlanItem {
                        text: text.to_owned(),
                        status: plan_status(str_any(entry, &["status", "state"])),
                    });
                }
            }
            _ => {}
        }
    }
    (!items.is_empty()).then_some(ToolView::Plan(items))
}

fn mcp_view(name: &str, args: &Map<String, Value>) -> Option<ToolView> {
    let rest = name.strip_prefix("mcp__")?;
    let (server, tool) = rest.split_once("__")?;
    Some(ToolView::Mcp {
        server: server.to_owned(),
        tool: tool.to_owned(),
        input: Value::Object(args.clone()),
    })
}

fn humanize(name: &str) -> String {
    let spaced = name.replace(['_', '-'], " ");
    let mut chars = spaced.chars();
    chars
        .next()
        .map(|first| first.to_uppercase().chain(chars).collect())
        .unwrap_or_default()
}

/// The first JSON value starting at `text` (an object or a string literal), if it parses.
fn leading_json(text: &str) -> Option<Value> {
    serde_json::Deserializer::from_str(text)
        .into_iter::<Value>()
        .next()?
        .ok()
}

/// Codex "code mode" wraps calls in JavaScript (`await tools.exec_command({...})`,
/// `const patch = "*** Begin Patch..."`). A script that is one such call is shown as that call.
fn unwrap_code_mode(source: ImportSource, code: &str) -> Option<ToolView> {
    let calls: Vec<(usize, &str)> = code.match_indices("tools.").collect();
    if let [(start, _)] = calls.as_slice() {
        let rest = &code[start + "tools.".len()..];
        let (name, args) = rest.split_once('(')?;
        if name.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '_') {
            if let Some(Value::Object(args)) = leading_json(args.trim_start()) {
                let view = classify(source, name, &Value::Object(args).to_string());
                return (!matches!(view, ToolView::Other { .. })).then_some(view);
            }
        }
    }
    let patch_start = code.find("\"*** Begin Patch")?;
    let Value::String(patch) = leading_json(&code[patch_start..])? else {
        return None;
    };
    let files = parse_v4a(&patch);
    (!files.is_empty()).then_some(ToolView::Edit(files))
}

/// Map one recorded call onto a [`ToolView`]. Unknown or malformed calls become `Other`.
pub fn classify(source: ImportSource, name: &str, arguments: &str) -> ToolView {
    let args = match serde_json::from_str::<Value>(arguments) {
        Ok(Value::Object(args)) => args,
        _ => Map::new(),
    };
    // omp and pi attach a one-line intent (`i`) to every call; it makes the best title.
    let intent = str_field(&args, &["i", "intent"]);
    let lower = name.to_ascii_lowercase();
    let view = match (source, lower.as_str()) {
        (_, "bash" | "shell" | "exec_command" | "local_shell" | "run_terminal_cmd") => {
            exec_view(&args, intent)
        }
        (ImportSource::Codex, "exec" | "js" | "javascript") => {
            str_field(&args, &["input", "code"]).map(|code| {
                unwrap_code_mode(source, code).unwrap_or_else(|| ToolView::Exec {
                    command: code.to_owned(),
                    cwd: None,
                    description: Some("Run script".to_owned()),
                })
            })
        }
        (_, "eval") => str_field(&args, &["code", "input"]).map(|code| ToolView::Exec {
            command: code.to_owned(),
            cwd: None,
            description: intent.map(str::to_owned).or_else(|| {
                str_field(&args, &["language"]).map(|language| format!("Run {language}"))
            }),
        }),
        (_, "read" | "view" | "view_image" | "read_file" | "cat") => read_view(&args),
        (_, "edit" | "multiedit" | "str_replace" | "search_replace") => {
            replace_view(&args).or_else(|| patch_view(&args))
        }
        (_, "write" | "create" | "write_file") => write_view(&args),
        (_, "apply_patch" | "patch") => patch_view(&args),
        (_, "grep" | "rg" | "search" | "ast_grep_search") => search_view(&args, false),
        (_, "glob" | "find" | "list") => search_view(&args, true),
        (_, name)
            if name.starts_with("websearch")
                || name.starts_with("web_search")
                || name == "google_search" =>
        {
            str_field(&args, &["query", "q"]).map(|query| ToolView::WebSearch {
                query: query.to_owned(),
            })
        }
        (_, "webfetch" | "web_fetch" | "fetch") => {
            str_field(&args, &["url"]).map(|url| ToolView::WebFetch { url: url.to_owned() })
        }
        (_, "todowrite" | "todo_write" | "todo" | "update_plan") => plan_view(&args),
        (_, "task" | "agent" | "spawn_agent" | "delegate_task" | "call_omo_agent") => {
            let description = intent
                .or_else(|| str_field(&args, &["description", "task_name", "subagent_type"]))
                .unwrap_or("Subagent task");
            Some(ToolView::Subagent {
                description: description.to_owned(),
            })
        }
        _ => mcp_view(name, &args),
    };
    view.unwrap_or_else(|| ToolView::Other {
        title: intent.map(str::to_owned).unwrap_or_else(|| humanize(name)),
    })
}

/// Codex wraps command output in bookkeeping (`Chunk ID`, `Wall time`, `Process exited with
/// code N`, `Original token count`, `Output:`). Strip it and recover the exit code; other
/// sources record plain output, so only the failure flag decides their exit code.
pub fn exec_outcome(text: &str, is_error: bool) -> ExecOutcome {
    let mut exit_code = None;
    let mut body_start = 0;
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim();
        if let Some(code) = trimmed
            .strip_prefix("Process exited with code ")
            .or_else(|| trimmed.strip_prefix("Exit code: "))
            .and_then(|code| code.trim().parse::<i32>().ok())
        {
            exit_code = Some(code);
        } else if trimmed == "Output:" {
            body_start += line.len();
            break;
        } else if !(trimmed.is_empty()
            || trimmed.starts_with("Chunk ID:")
            || trimmed.starts_with("Wall time:")
            || trimmed.starts_with("Original token count:")
            || trimmed.starts_with("Process running with session ID"))
        {
            break;
        }
        body_start += line.len();
    }
    // Without any recognized header the text is plain output.
    if exit_code.is_none() && !text[..body_start].contains("Wall time:") {
        body_start = 0;
    }
    ExecOutcome {
        exit_code: exit_code.unwrap_or(i32::from(is_error)),
        output: text[body_start..].to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commands_from_every_agent_become_exec() {
        let cases = [
            (ImportSource::Claude, "Bash", r#"{"command":"ls","description":"List"}"#),
            (ImportSource::Codex, "exec_command", r#"{"cmd":"ls","workdir":"/w"}"#),
            (ImportSource::Codex, "shell", r#"{"command":["bash","-lc","ls"]}"#),
            (ImportSource::Omp, "bash", r#"{"command":"ls","i":"List"}"#),
            (ImportSource::OpenCode, "bash", r#"{"command":"ls"}"#),
            (ImportSource::Codex, "js", r#"{"input":"ls"}"#),
        ];
        for (source, name, args) in cases {
            assert!(
                matches!(classify(source, name, args), ToolView::Exec { command, .. } if command == "ls"),
                "{source} {name}"
            );
        }
    }

    #[test]
    fn codex_code_mode_scripts_unwrap_to_the_wrapped_call() {
        let script = r#"{"input":"const r = await tools.exec_command({\"cmd\":\"rg -n foo\",\"workdir\":\"/w\"});\ntext(r);"}"#;
        assert!(matches!(
            classify(ImportSource::Codex, "exec", script),
            ToolView::Exec { command, cwd, .. } if command == "rg -n foo" && cwd.as_deref() == Some("/w")
        ));
        let patch = r#"{"input":"const patch = \"*** Begin Patch\\n*** Add File: a.txt\\n+hi\\n*** End Patch\";\nawait tools.apply_patch(patch);"}"#;
        assert!(matches!(
            classify(ImportSource::Codex, "exec", patch),
            ToolView::Edit(files) if files[0].path == "a.txt" && files[0].new_text == "hi\n"
        ));
        let mixed = r#"{"input":"await tools.a({}); await tools.b({});"}"#;
        assert!(matches!(classify(ImportSource::Codex, "exec", mixed), ToolView::Exec { .. }));
    }

    #[test]
    fn edits_normalize_field_spellings() {
        for args in [
            r#"{"file_path":"a.rs","old_string":"x","new_string":"y"}"#,
            r#"{"filePath":"a.rs","oldString":"x","newString":"y"}"#,
            r#"{"path":"a.rs","oldText":"x","newText":"y"}"#,
        ] {
            let ToolView::Edit(files) = classify(ImportSource::Pi, "edit", args) else {
                panic!("expected edit for {args}");
            };
            assert_eq!(files[0].path, "a.rs");
            assert_eq!(files[0].old_text.as_deref(), Some("x"));
            assert_eq!(files[0].new_text, "y");
        }
    }

    #[test]
    fn agent_uris_and_intents_fall_back_to_readable_titles() {
        let view = classify(
            ImportSource::Omp,
            "read",
            r#"{"path":"skill://code-review","i":"Reading review instructions"}"#,
        );
        assert_eq!(
            view,
            ToolView::Other {
                title: "Reading review instructions".into()
            }
        );
        assert_eq!(
            classify(ImportSource::Codex, "list_agents", "{}"),
            ToolView::Other {
                title: "List agents".into()
            }
        );
    }

    #[test]
    fn plans_and_mcp_calls_are_recognized() {
        let ToolView::Plan(items) = classify(
            ImportSource::Codex,
            "update_plan",
            r#"{"plan":[{"step":"a","status":"completed"},{"step":"b","status":"in_progress"}]}"#,
        ) else {
            panic!("expected plan");
        };
        assert_eq!(items[0].status, PlanStatus::Completed);
        assert_eq!(items[1].status, PlanStatus::InProgress);
        assert!(matches!(
            classify(ImportSource::OpenCode, "websearch_web_search_exa", r#"{"query":"q"}"#),
            ToolView::WebSearch { query } if query == "q"
        ));
        assert!(matches!(
            classify(ImportSource::Claude, "mcp__codegraph__codegraph_context", r#"{"task":"x"}"#),
            ToolView::Mcp { server, tool, .. } if server == "codegraph" && tool == "codegraph_context"
        ));
    }

    #[test]
    fn codex_exec_headers_are_stripped() {
        let outcome = exec_outcome(
            "Chunk ID: 1\nWall time: 0.4 seconds\nProcess exited with code 2\nOriginal token count: 3\nOutput:\nboom\n",
            false,
        );
        assert_eq!(outcome, ExecOutcome { exit_code: 2, output: "boom\n".into() });
        let outcome = exec_outcome("Exit code: 0\nWall time: 0.4 seconds\nOutput:\nSuccess\n", false);
        assert_eq!(outcome.exit_code, 0);
        assert_eq!(outcome.output, "Success\n");
        let plain = exec_outcome("hello\n", true);
        assert_eq!(plain, ExecOutcome { exit_code: 1, output: "hello\n".into() });
    }
}
