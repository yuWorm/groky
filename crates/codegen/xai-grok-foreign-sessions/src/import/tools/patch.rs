//! Patch formats recorded by foreign agents, reduced to per-file before/after text for display.

use super::FileEdit;

/// Joins separate hunks of one file so the rendered diff shows a gap instead of fake adjacency.
const HUNK_GAP: &str = "⋯";

#[derive(Default)]
struct Pending {
    path: String,
    old: Vec<String>,
    new: Vec<String>,
    added: bool,
    deleted: bool,
    start_line: Option<u64>,
    hunks: usize,
}

impl Pending {
    fn new(path: &str) -> Self {
        Self {
            path: path.trim().to_owned(),
            ..Self::default()
        }
    }

    fn begin_hunk(&mut self) {
        if self.hunks > 0 {
            self.old.push(HUNK_GAP.to_owned());
            self.new.push(HUNK_GAP.to_owned());
        }
        self.hunks += 1;
    }

    fn finish(self) -> Option<FileEdit> {
        if self.path.is_empty() {
            return None;
        }
        let join = |lines: Vec<String>| {
            if lines.is_empty() {
                String::new()
            } else {
                lines.join("\n") + "\n"
            }
        };
        Some(FileEdit {
            path: self.path,
            old_text: (!self.added).then(|| join(self.old)),
            new_text: join(self.new),
            start_line: self.start_line,
            deleted: self.deleted,
        })
    }
}

/// Codex / OpenCode `apply_patch` (V4A): `*** Update File:` sections with ` `/`-`/`+` lines.
pub fn parse_v4a(patch: &str) -> Vec<FileEdit> {
    let mut files = Vec::new();
    let mut current: Option<Pending> = None;
    let mut flush = |current: &mut Option<Pending>, files: &mut Vec<FileEdit>| {
        if let Some(file) = current.take().and_then(Pending::finish) {
            files.push(file);
        }
    };
    for line in patch.lines() {
        if let Some(path) = line.strip_prefix("*** Update File:") {
            flush(&mut current, &mut files);
            current = Some(Pending::new(path));
        } else if let Some(path) = line.strip_prefix("*** Add File:") {
            flush(&mut current, &mut files);
            let mut pending = Pending::new(path);
            pending.added = true;
            current = Some(pending);
        } else if let Some(path) = line.strip_prefix("*** Delete File:") {
            flush(&mut current, &mut files);
            let mut pending = Pending::new(path);
            pending.deleted = true;
            current = Some(pending);
        } else if let Some(path) = line.strip_prefix("*** Move to:") {
            if let Some(pending) = current.as_mut() {
                pending.path = path.trim().to_owned();
            }
        } else if line.starts_with("***") {
            // Begin/End Patch and End of File markers.
        } else if let Some(pending) = current.as_mut() {
            if line.starts_with("@@") {
                pending.begin_hunk();
                continue;
            }
            if pending.hunks == 0 {
                pending.begin_hunk();
            }
            match line.split_at_checked(1) {
                Some(("+", rest)) => pending.new.push(rest.to_owned()),
                Some(("-", rest)) => pending.old.push(rest.to_owned()),
                Some((" ", rest)) => {
                    pending.old.push(rest.to_owned());
                    pending.new.push(rest.to_owned());
                }
                _ if line.is_empty() => {
                    pending.old.push(String::new());
                    pending.new.push(String::new());
                }
                _ => {}
            }
        }
    }
    flush(&mut current, &mut files);
    files
}

fn line_number(value: &str) -> Option<u64> {
    value.trim().trim_end_matches(':').parse().ok()
}

/// Parse a hashline op (`PUT 3.=7:`, `PUT >12:`, `PUT <5:`, `PUT 9:`, `CUT 3.=4`, `CUT 10`)
/// into its first line and a note describing the lines it replaced or removed.
fn hashline_op(op: &str, arg: &str) -> (Option<u64>, Option<String>) {
    let arg = arg.trim().trim_end_matches(':');
    let verb = if op == "CUT" { "removed" } else { "replaced" };
    if let Some((from, to)) = arg.split_once(".=") {
        let (from, to) = (line_number(from), line_number(to));
        let note = match (from, to) {
            (Some(from), Some(to)) if from == to => format!("{HUNK_GAP} line {from} {verb}"),
            (Some(from), Some(to)) => format!("{HUNK_GAP} lines {from}–{to} {verb}"),
            _ => format!("{HUNK_GAP} lines {verb}"),
        };
        return (from, Some(note));
    }
    if let Some(after) = arg.strip_prefix('>') {
        return (line_number(after).map(|line| line + 1), None);
    }
    if let Some(before) = arg.strip_prefix('<') {
        return (line_number(before), None);
    }
    let line = line_number(arg);
    (line, line.map(|line| format!("{HUNK_GAP} line {line} {verb}")))
}

/// omp `edit` (hashline): `[path#HASH]` sections of `PUT`/`CUT`/`REM` ops followed by `+` lines.
/// The source records anchors, not the removed text, so replaced ranges show as a note.
pub fn parse_hashline(patch: &str) -> Vec<FileEdit> {
    let mut files = Vec::new();
    let mut current: Option<Pending> = None;
    for line in patch.lines() {
        if let Some(header) = line.strip_prefix('[').and_then(|rest| rest.strip_suffix(']'))
            && let Some((path, _hash)) = header.rsplit_once('#')
        {
            if let Some(file) = current.take().and_then(Pending::finish) {
                files.push(file);
            }
            current = Some(Pending::new(path));
            continue;
        }
        let Some(pending) = current.as_mut() else {
            continue;
        };
        if let Some(added) = line.strip_prefix('+') {
            if pending.hunks == 0 {
                pending.begin_hunk();
            }
            pending.new.push(added.to_owned());
            continue;
        }
        let (op, arg) = line.split_once(' ').unwrap_or((line, ""));
        match op {
            "PUT" | "CUT" => {
                pending.begin_hunk();
                let (start, note) = hashline_op(op, arg);
                if pending.start_line.is_none() {
                    pending.start_line = start;
                }
                if let Some(note) = note {
                    pending.old.push(note);
                }
            }
            "REM" => pending.deleted = true,
            _ => {}
        }
    }
    if let Some(file) = current.take().and_then(Pending::finish) {
        files.push(file);
    }
    files
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4a_splits_files_and_keeps_context() {
        let files = parse_v4a(
            "*** Begin Patch\n*** Update File: src/a.rs\n@@ fn main\n keep\n-old\n+new\n*** Add File: b.txt\n+hello\n*** Delete File: c.txt\n*** End Patch\n",
        );
        assert_eq!(files.len(), 3);
        assert_eq!(files[0].path, "src/a.rs");
        assert_eq!(files[0].old_text.as_deref(), Some("keep\nold\n"));
        assert_eq!(files[0].new_text, "keep\nnew\n");
        assert_eq!(files[1].old_text, None);
        assert_eq!(files[1].new_text, "hello\n");
        assert!(files[2].deleted);
    }

    #[test]
    fn hashline_anchors_become_notes_and_start_lines() {
        let files = parse_hashline(
            "*** Begin Patch\n[src/a.ts#0E3F]\nPUT 31.=36:\n+one\n+two\nCUT 40\n[src/b.rs#0000]\nPUT >12:\n+mod terminal;\n*** End Patch\n",
        );
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].path, "src/a.ts");
        assert_eq!(files[0].start_line, Some(31));
        assert_eq!(
            files[0].old_text.as_deref(),
            Some("⋯ lines 31–36 replaced\n⋯\n⋯ line 40 removed\n")
        );
        assert_eq!(files[0].new_text, "one\ntwo\n⋯\n");
        assert_eq!(files[1].start_line, Some(13));
        assert_eq!(files[1].new_text, "mod terminal;\n");
    }
}
