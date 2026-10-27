use std::fs::File;
use std::io::{self, BufRead, BufReader, Read};
use std::path::{Component, Path, PathBuf};
use std::time::SystemTime;

use serde_json::Value;

use super::ImportContent;
use crate::capability::{ApprovedRoot, ReadTransactionSqlite};

pub(super) const MAX_IMPORT_BYTES: u64 = 128 * 1024 * 1024;
pub(super) const MAX_SCAN_FILES: usize = 20_000;

pub(super) fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn normalized(path: &Path) -> PathBuf {
    if let Ok(path) = dunce::canonicalize(path) {
        return path;
    }
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if matches!(result.components().next_back(), Some(Component::Normal(_))) {
                    result.pop();
                } else if !result.has_root() {
                    result.push(component.as_os_str());
                }
            }
            _ => result.push(component.as_os_str()),
        }
    }
    result
}

pub(super) fn matches_cwd(stored: &Path, filter: Option<&Path>) -> bool {
    filter.is_none_or(|filter| normalized(stored) == normalized(filter))
}

pub(super) fn modified(path: &Path) -> SystemTime {
    path.metadata()
        .and_then(|meta| meta.modified())
        .unwrap_or(SystemTime::UNIX_EPOCH)
}

pub(super) fn short_title(text: &str) -> String {
    text.lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("Untitled session")
        .chars()
        .filter(|ch| {
            !ch.is_control() && !matches!(ch, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        })
        .take(100)
        .collect::<String>()
        .trim()
        .to_owned()
}

pub(super) fn open_source(path: &Path) -> io::Result<File> {
    let parent = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let root = ApprovedRoot::new(parent)
        .ok_or_else(|| invalid(format!("Cannot open source directory {}", parent.display())))?;
    let name = path
        .file_name()
        .ok_or_else(|| invalid("Source path has no filename"))?;
    let opened = root.open_regular_file(Path::new(name)).ok_or_else(|| {
        invalid(format!(
            "Source must be a readable regular file, not a symlink: {}",
            path.display()
        ))
    })?;
    if opened.metadata.len() > MAX_IMPORT_BYTES {
        return Err(invalid(format!(
            "Source exceeds the {} MiB import limit: {}",
            MAX_IMPORT_BYTES / 1024 / 1024,
            path.display()
        )));
    }
    Ok(opened.file)
}

pub(super) fn open_sqlite(path: &Path) -> io::Result<ReadTransactionSqlite> {
    let parent = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let root =
        ApprovedRoot::new(parent).ok_or_else(|| invalid("Cannot open database directory"))?;
    crate::capability::open_sqlite_transaction(&root, path).ok_or_else(|| {
        invalid(format!(
            "Cannot open a consistent read-only local database: {}",
            path.display()
        ))
    })
}

pub(super) fn source_reader(path: &Path) -> io::Result<Box<dyn Read>> {
    let file = open_source(path)?;
    if path.extension().is_some_and(|extension| extension == "zst") {
        Ok(Box::new(zstd::stream::read::Decoder::new(file)?))
    } else {
        Ok(Box::new(file))
    }
}

pub(super) fn json_file(path: &Path) -> io::Result<Value> {
    let mut bytes = Vec::new();
    source_reader(path)?
        .take(MAX_IMPORT_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_IMPORT_BYTES {
        return Err(invalid("Decoded source exceeds the import size limit"));
    }
    serde_json::from_slice(&bytes).map_err(|error| invalid(format!("{}: {error}", path.display())))
}

pub(super) fn json_lines(path: &Path) -> io::Result<Vec<Value>> {
    let (rows, warnings) = json_lines_with_warnings(path)?;
    if let Some(warning) = warnings.first() {
        return Err(invalid(warning.clone()));
    }
    Ok(rows)
}

/// Only an incomplete final append can be ignored, and the caller receives a
/// warning. Corrupt complete/middle records can change branch semantics: fail.
pub(super) fn json_lines_with_warnings(path: &Path) -> io::Result<(Vec<Value>, Vec<String>)> {
    let mut reader = BufReader::new(source_reader(path)?.take(MAX_IMPORT_BYTES + 1));
    let mut rows = Vec::new();
    let mut warnings = Vec::new();
    let mut line = String::new();
    let mut total = 0u64;
    let mut number = 0usize;
    loop {
        line.clear();
        let bytes = reader.read_line(&mut line)?;
        if bytes == 0 {
            break;
        }
        total += bytes as u64;
        number += 1;
        if total > MAX_IMPORT_BYTES {
            return Err(invalid("Decoded transcript exceeds the import size limit"));
        }
        let trimmed = line.trim().trim_start_matches('\u{feff}');
        if trimmed.is_empty() {
            continue;
        }
        match serde_json::from_str(trimmed) {
            Ok(value) => rows.push(value),
            Err(error) if !line.ends_with('\n') && error.is_eof() => {
                warnings.push(format!(
                    "{}: incomplete final record at line {number} was not imported",
                    path.display()
                ));
            }
            Err(error) => return Err(invalid(format!("{}:{number}: {error}", path.display()))),
        }
    }
    Ok((rows, warnings))
}

/// A bounded metadata probe for discovery; not a full transcript load.
pub(super) fn json_head(path: &Path, max_bytes: u64) -> io::Result<Vec<Value>> {
    let reader = BufReader::new(source_reader(path)?.take(max_bytes));
    let mut records = Vec::new();
    for line in reader.lines() {
        let line = line?;
        if let Ok(record) = serde_json::from_str(line.trim()) {
            records.push(record);
        }
    }
    Ok(records)
}

/// Traverse directories without following symlinks. Capability-relative opens
/// keep traversal below the approved root even when directory entries change.
#[cfg(unix)]
pub(super) fn walk_files(
    root: &Path,
    max_depth: usize,
    accept: impl Fn(&Path) -> bool,
) -> io::Result<Vec<PathBuf>> {
    if !root.exists() {
        return Ok(Vec::new());
    }
    let root = ApprovedRoot::new(root).ok_or_else(|| invalid("Cannot open session store root"))?;
    let mut pending = vec![(root, 0usize)];
    let mut files = Vec::new();
    let mut remaining = MAX_SCAN_FILES;
    while let Some((directory, depth)) = pending.pop() {
        let mut names = Vec::new();
        let visit = directory.for_each_entry_bounded(remaining, |name| names.push(name));
        remaining = remaining.saturating_sub(visit.visited);
        if !visit.complete {
            return Err(invalid(format!(
                "Session discovery exceeded {MAX_SCAN_FILES} directory entries or could not read {}. Select a source file explicitly.",
                directory.path().display()
            )));
        }
        names.sort();
        for name in names {
            let relative = Path::new(&name);
            let path = directory.join(relative);
            if accept(&path) && directory.resolve_regular_file(relative).is_some() {
                files.push(path);
            } else if depth < max_depth {
                if let Some(child) = directory.subroot(relative) {
                    pending.push((child, depth + 1));
                }
            }
        }
    }
    Ok(files)
}

#[cfg(not(unix))]
pub(super) fn walk_files(
    root: &Path,
    max_depth: usize,
    accept: impl Fn(&Path) -> bool,
) -> io::Result<Vec<PathBuf>> {
    if !root.exists() {
        return Ok(Vec::new());
    }
    let root = dunce::canonicalize(root)?;
    let mut pending = vec![(root.clone(), 0usize)];
    let mut files = Vec::new();
    let mut visited = 0usize;
    while let Some((directory, depth)) = pending.pop() {
        let approved = ApprovedRoot::new(&directory)
            .ok_or_else(|| invalid("Cannot read session directory"))?;
        if !approved.path().starts_with(&root) {
            continue;
        }
        for entry in std::fs::read_dir(&directory)? {
            visited += 1;
            if visited > MAX_SCAN_FILES {
                return Err(invalid(
                    "Session discovery limit exceeded; select a source file explicitly",
                ));
            }
            let entry = entry?;
            let kind = entry.file_type()?;
            if kind.is_symlink() {
                continue;
            }
            let path = entry.path();
            if kind.is_file() && accept(&path) && approved.resolve_regular_file(&path).is_some() {
                files.push(path);
            } else if kind.is_dir() && depth < max_depth {
                pending.push((path, depth + 1));
            }
        }
    }
    files.sort();
    Ok(files)
}

pub(super) fn text_content(value: &Value) -> String {
    if let Some(text) = value.as_str() {
        return text.to_owned();
    }
    match value {
        Value::Array(parts) => {
            let mut result = String::new();
            let mut first = true;
            for part in parts {
                let text =
                    part.as_str()
                        .or_else(|| match part.get("type").and_then(Value::as_str) {
                            Some("text" | "input_text" | "output_text") => {
                                part.get("text").and_then(Value::as_str)
                            }
                            _ => None,
                        });
                if let Some(text) = text {
                    if !first {
                        result.push('\n');
                    }
                    first = false;
                    result.push_str(text);
                }
            }
            result
        }
        Value::Object(_) => value
            .get("text")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        _ => String::new(),
    }
}

pub(super) fn content_parts(value: &Value, warnings: &mut Vec<String>) -> Vec<ImportContent> {
    if let Some(text) = value.as_str() {
        return vec![ImportContent::Text(text.to_owned())];
    }
    let Some(parts) = value.as_array() else {
        if !value.is_null() {
            warnings.push("Unsupported message content shape was omitted.".into());
        }
        return Vec::new();
    };
    let mut output = Vec::new();
    for part in parts {
        if let Some(text) = part.as_str() {
            output.push(ImportContent::Text(text.to_owned()));
            continue;
        }
        let kind = part.get("type").and_then(Value::as_str).unwrap_or("");
        match kind {
            "text" | "input_text" | "output_text" => {
                if let Some(text) = part.get("text").and_then(Value::as_str) {
                    output.push(ImportContent::Text(text.to_owned()));
                }
            }
            "image" | "image_url" | "input_image" => {
                let source = part.get("source").unwrap_or(part);
                let data = source.get("data").and_then(Value::as_str);
                let mime = source
                    .get("media_type")
                    .or_else(|| source.get("mimeType"))
                    .and_then(Value::as_str);
                let url = part
                    .get("image_url")
                    .and_then(|value| {
                        value
                            .as_str()
                            .or_else(|| value.get("url").and_then(Value::as_str))
                    })
                    .or_else(|| source.get("url").and_then(Value::as_str));
                let inline = data
                    .zip(mime)
                    .filter(|(_, mime)| mime.starts_with("image/"))
                    .map(|(data, mime)| format!("data:{mime};base64,{data}"));
                if let Some(url) = inline.or_else(|| {
                    url.filter(|url| url.starts_with("data:image/"))
                        .map(str::to_owned)
                }) {
                    output.push(ImportContent::Image { url });
                } else {
                    output.push(ImportContent::Text("[Imported image unavailable: external reference or unsupported image data]".into()));
                    warnings.push("An image was not embedded; external URLs/files are not fetched automatically.".into());
                }
            }
            "thinking" | "redacted_thinking" | "reasoning" => {
                warnings.push(
                    "Provider-specific reasoning is not replayed to the continuation model.".into(),
                );
            }
            _ => {
                output.push(ImportContent::Text(format!(
                    "[Unsupported imported content: {kind}]"
                )));
                warnings.push(format!(
                    "Unsupported content block {kind:?} was retained as a marker."
                ));
            }
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matching_is_exact_not_a_directory_prefix() {
        assert!(matches_cwd(
            Path::new("/work/app/./"),
            Some(Path::new("/work/app"))
        ));
        assert!(!matches_cwd(
            Path::new("/work/app-copy"),
            Some(Path::new("/work/app"))
        ));
        assert!(!matches_cwd(
            Path::new("/work/app/sub"),
            Some(Path::new("/work/app"))
        ));
    }

    #[test]
    fn truncated_tail_is_reported_but_middle_corruption_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("history.jsonl");
        std::fs::write(&file, "{\"type\":\"message\"}\n{\"type\":").unwrap();
        let (records, warnings) = json_lines_with_warnings(&file).unwrap();
        assert_eq!(records, vec![serde_json::json!({"type":"message"})]);
        assert!(
            warnings
                .first()
                .is_some_and(|warning| warning.contains("incomplete final record"))
        );
        std::fs::write(&file, "{\"type\":\n{\"type\":\"message\"}\n").unwrap();
        assert!(json_lines_with_warnings(&file).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn discovery_matches_symlinked_cwd_but_does_not_follow_store_links() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path().join("workspace");
        std::fs::create_dir(&workspace).unwrap();
        let alias = dir.path().join("alias");
        symlink(&workspace, &alias).unwrap();
        assert!(matches_cwd(&alias, Some(&workspace)));
        let store = dir.path().join("store");
        std::fs::create_dir(&store).unwrap();
        std::fs::write(workspace.join("outside.jsonl"), "{}").unwrap();
        symlink(&workspace, store.join("linked")).unwrap();
        assert!(
            walk_files(&store, 3, |path| path
                .extension()
                .is_some_and(|ext| ext == "jsonl"))
            .unwrap()
            .is_empty()
        );
    }
}
