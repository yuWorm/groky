//! Upstream grok CLI sessions (`~/.grok/sessions`). They already use the native session layout,
//! so discovery reads `summary.json` and import copies the directory instead of decoding it.

use std::io;
use std::path::{Path, PathBuf};

use serde_json::Value;

use super::common::{invalid, json_file, matches_cwd, modified, short_title};
use super::*;

const MAX_GROK_SESSIONS: usize = 20_000;

/// `$GROK_UPSTREAM_HOME`, else `~/.grok`, unless that is the home this process itself uses.
pub(super) fn root() -> Option<PathBuf> {
    let root = std::env::var_os("GROK_UPSTREAM_HOME")
        .map(PathBuf::from)
        .or_else(|| xai_dirs::home_dir().map(|home| home.join(".grok")))?;
    let own = xai_dirs::user_grok_home();
    let same = |a: &Path, b: &Path| match (dunce::canonicalize(a), dunce::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    };
    (!own.is_some_and(|own| same(&own, &root))).then_some(root)
}

pub(super) fn discover(cwd: Option<&Path>, out: &mut ImportDiscovery) {
    let Some(root) = root() else {
        return;
    };
    let Ok(projects) = std::fs::read_dir(root.join("sessions")) else {
        return;
    };
    let mut seen = 0;
    for project in projects.flatten() {
        let Ok(sessions) = std::fs::read_dir(project.path()) else {
            continue;
        };
        for session in sessions.flatten() {
            seen += 1;
            if seen > MAX_GROK_SESSIONS {
                out.warnings
                    .push("Stopped scanning grok sessions after 20000 entries".to_owned());
                return;
            }
            let path = session.path();
            if !path.join("summary.json").is_file() {
                continue;
            }
            match candidate_from_dir(&path) {
                Ok(Some(candidate)) if matches_cwd(&candidate.cwd, cwd) => {
                    out.sessions.push(candidate);
                }
                Ok(_) => {}
                Err(error) => out.warnings.push(format!(
                    "Could not inspect grok session {}: {error}",
                    path.display()
                )),
            }
        }
    }
}

pub(super) fn inspect(path: &Path, id: Option<&str>) -> io::Result<ImportCandidate> {
    let dir = if path.is_file() {
        path.parent().unwrap_or(path)
    } else {
        path
    };
    let candidate = candidate_from_dir(dir)?.ok_or_else(|| {
        invalid(format!(
            "grok session {} is empty or a subagent session",
            dir.display()
        ))
    })?;
    if let Some(id) = id
        && id != candidate.id
    {
        return Err(invalid(format!(
            "grok session {} has id {}, not {id}",
            dir.display(),
            candidate.id
        )));
    }
    Ok(candidate)
}

/// `None` for sessions a user would not resume: subagent/headless children and empty chats.
fn candidate_from_dir(dir: &Path) -> io::Result<Option<ImportCandidate>> {
    let summary = json_file(&dir.join("summary.json"))?;
    let str_at = |pointer: &str| summary.pointer(pointer).and_then(Value::as_str);
    if str_at("/session_kind").is_some()
        || summary.get("num_chat_messages").and_then(Value::as_u64) == Some(0)
        || !dir.join("chat_history.jsonl").is_file()
    {
        return Ok(None);
    }
    let id = str_at("/info/id")
        .ok_or_else(|| invalid("grok summary.json has no info.id"))?
        .to_owned();
    let cwd = str_at("/info/cwd").ok_or_else(|| invalid("grok summary.json has no info.cwd"))?;
    let title = [
        "/session_summary",
        "/generated_title",
        "/last_turn_summary",
    ]
    .iter()
    .filter_map(|pointer| str_at(pointer))
    .map(short_title)
    .find(|title| !title.is_empty())
    .unwrap_or_else(|| "grok session".to_owned());
    let modified = str_at("/last_active_at")
        .or_else(|| str_at("/updated_at"))
        .and_then(|time| chrono::DateTime::parse_from_rfc3339(time).ok())
        .map(std::time::SystemTime::from)
        .unwrap_or_else(|| modified(&dir.join("summary.json")));
    Ok(Some(ImportCandidate {
        source: ImportSource::Grok,
        id,
        path: dir.to_path_buf(),
        cwd: PathBuf::from(cwd),
        title,
        modified,
        leaf_id: None,
    }))
}

/// Number of model-context items, for the import preview.
pub(super) fn context_len(candidate: &ImportCandidate) -> io::Result<usize> {
    let text = std::fs::read_to_string(candidate.path.join("chat_history.jsonl"))?;
    Ok(text.lines().filter(|line| !line.trim().is_empty()).count())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_session(dir: &Path, summary: Value) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("summary.json"), summary.to_string()).unwrap();
        std::fs::write(dir.join("chat_history.jsonl"), "{}\n{}\n").unwrap();
    }

    #[test]
    fn subagent_and_empty_sessions_are_not_candidates() {
        let temp = tempfile::tempdir().unwrap();
        let main = temp.path().join("main");
        write_session(
            &main,
            serde_json::json!({"info":{"id":"main","cwd":"/w"},"session_summary":"Fix login","num_chat_messages":2,"updated_at":"2026-09-04T02:55:06Z"}),
        );
        let child = temp.path().join("child");
        write_session(
            &child,
            serde_json::json!({"info":{"id":"child","cwd":"/w"},"session_summary":"","session_kind":"subagent","num_chat_messages":2}),
        );
        let candidate = candidate_from_dir(&main).unwrap().unwrap();
        assert_eq!(candidate.title, "Fix login");
        assert_eq!(context_len(&candidate).unwrap(), 2);
        assert!(candidate_from_dir(&child).unwrap().is_none());
    }
}
