use super::common::{
    MAX_IMPORT_BYTES, invalid, json_head, json_lines_with_warnings, matches_cwd, modified,
    open_source, short_title, walk_files,
};
use super::*;
use base64::Engine;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::env;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

const METADATA_PREFIX_BYTES: u64 = 64 * 1024;
const BLOB_PREFIX: &str = "blob:sha256:";

#[derive(Clone)]
struct StorageLayout {
    sessions: PathBuf,
    agent: PathBuf,
}

#[derive(Clone)]
struct Header {
    id: String,
    cwd: PathBuf,
    version: u64,
    title: Option<String>,
}

#[derive(Clone)]
struct StoredEntry {
    id: String,
    parent_id: Option<String>,
    logical_index: usize,
    value: Value,
}

struct SessionDocument {
    header: Header,
    slot_title: Option<String>,
    entries: Vec<StoredEntry>,
    warnings: Vec<String>,
}

#[derive(Default)]
struct Emission {
    model: Vec<usize>,
}

#[derive(Default)]
struct RemoteHistory {
    model: Vec<usize>,
    has_opaque_checkpoint: bool,
}

/// Discover Pi and Oh My Pi JSONL sessions. Discovery intentionally reads only
/// a bounded file prefix; `inspect` and `load` validate the complete journal.
pub(super) fn discover(source: ImportSource, cwd: Option<&Path>, out: &mut ImportDiscovery) {
    let layouts = match storage_layouts(source) {
        Ok(layouts) => layouts,
        Err(error) => {
            out.warnings
                .push(format!("{} session discovery: {error}", source.as_str()));
            return;
        }
    };

    let mut seen = HashSet::new();
    let mut candidates = Vec::new();
    for layout in layouts {
        if !layout.sessions.is_dir() {
            continue;
        }
        let shared_store = shares_store_with_other_source(source, &layout);
        let files = match walk_files(&layout.sessions, 4, is_session_file) {
            Ok(files) => files,
            Err(error) => {
                out.warnings.push(format!(
                    "could not scan {} sessions at {}: {error}",
                    source.as_str(),
                    layout.sessions.display()
                ));
                continue;
            }
        };
        for path in files {
            if !seen.insert(path.clone()) {
                continue;
            }
            let metadata = match read_metadata(&path) {
                Ok(metadata) => metadata,
                Err(error) => {
                    out.warnings.push(format!(
                        "skipped {} session {}: {error}",
                        source.as_str(),
                        path.display()
                    ));
                    continue;
                }
            };
            if shared_store {
                match shared_store_source(&path, &metadata) {
                    Some(found) if found == source => {}
                    Some(_) => continue,
                    None => {
                        push_discovery_warning(
                            out,
                            format!(
                                "OMP and Pi resolve to the same session store at {}; skipped unmarked transcript {} to avoid duplicate source labels. Select it explicitly with --from omp or --from pi.",
                                layout.sessions.display(),
                                path.display()
                            ),
                        );
                        continue;
                    }
                }
            }
            let candidate = candidate_from_metadata(source, &path, &metadata);
            if matches_cwd(&candidate.cwd, cwd) {
                candidates.push(candidate);
            }
        }
    }

    candidates.sort_by(|left, right| {
        right
            .modified
            .cmp(&left.modified)
            .then_with(|| left.id.cmp(&right.id))
            .then_with(|| left.path.cmp(&right.path))
    });
    out.sessions.extend(candidates);
}

fn shares_store_with_other_source(source: ImportSource, layout: &StorageLayout) -> bool {
    let other = match source {
        ImportSource::Omp => ImportSource::Pi,
        ImportSource::Pi => ImportSource::Omp,
        _ => return false,
    };
    storage_layouts(other)
        .ok()
        .into_iter()
        .flatten()
        .any(|other| matches_cwd(&layout.sessions, Some(&other.sessions)))
}

fn shared_store_source(path: &Path, metadata: &Metadata) -> Option<ImportSource> {
    recognizable_store_source(path).or(metadata.dialect.source())
}

fn recognizable_store_source(path: &Path) -> Option<ImportSource> {
    let mut omp = false;
    let mut pi = false;
    for component in path.components() {
        match component.as_os_str().to_str() {
            Some(".omp") => omp = true,
            Some(".pi") => pi = true,
            _ => {}
        }
    }
    match (omp, pi) {
        (true, false) => Some(ImportSource::Omp),
        (false, true) => Some(ImportSource::Pi),
        _ => None,
    }
}

fn push_discovery_warning(out: &mut ImportDiscovery, warning: String) {
    if !out.warnings.contains(&warning) {
        out.warnings.push(warning);
    }
}

/// Inspect one Pi/OMP session file, or select one file by native session id
/// from a directory containing several projects.
pub(super) fn inspect(
    source: ImportSource,
    path: &Path,
    id: Option<&str>,
) -> io::Result<ImportCandidate> {
    ensure_supported_source(source)?;
    if path.is_file() {
        let document = read_document(path)?;
        let candidate = candidate_from_document(source, path, &document)?;
        if let Some(id) = id {
            if candidate.id != id {
                return Err(invalid(format!(
                    "{} session file {} has id {}, not requested id {id}",
                    source.as_str(),
                    path.display(),
                    candidate.id
                )));
            }
        }
        return Ok(candidate);
    }
    if !path.is_dir() {
        return Err(invalid(format!(
            "{} sessions are JSONL files; {} is neither a session file nor directory",
            source.as_str(),
            path.display()
        )));
    }

    let mut matches = Vec::new();
    for file in walk_files(path, 4, is_session_file)? {
        let metadata = match read_metadata(&file) {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };
        if id.is_some_and(|requested| requested != metadata.header.id) {
            continue;
        }
        let document = read_document(&file)?;
        let candidate = candidate_from_document(source, &file, &document)?;
        if id.is_none() || id.is_some_and(|requested| requested == candidate.id) {
            matches.push(candidate);
        }
    }
    matches.sort_by(|left, right| left.path.cmp(&right.path));
    match matches.len() {
        0 => Err(invalid(match id {
            Some(id) => format!(
                "no {} session with id {id} exists below {}",
                source.as_str(),
                path.display()
            ),
            None => format!(
                "no {} JSONL session exists below {}",
                source.as_str(),
                path.display()
            ),
        })),
        1 => Ok(matches.remove(0)),
        _ => Err(invalid(format!(
            "{} contains multiple {} sessions; provide a native session id",
            path.display(),
            source.as_str()
        ))),
    }
}

pub(super) fn load(candidate: &ImportCandidate) -> io::Result<ImportedSession> {
    ensure_supported_source(candidate.source)?;
    let document = read_document(&candidate.path)?;
    if document.header.id != candidate.id {
        return Err(invalid(format!(
            "{} session file {} changed from id {} to {}",
            candidate.source.as_str(),
            candidate.path.display(),
            candidate.id,
            document.header.id
        )));
    }
    if !matches_cwd(&document.header.cwd, Some(&candidate.cwd)) {
        return Err(invalid(format!(
            "{} session file {} changed cwd from {} to {}",
            candidate.source.as_str(),
            candidate.path.display(),
            candidate.cwd.display(),
            document.header.cwd.display()
        )));
    }

    let path = selected_path(&document, candidate.leaf_id.as_deref())?;
    let latest_compaction = path
        .iter()
        .rposition(|entry| entry_type(&entry.value) == Some("compaction"));
    let latest_reset = path
        .iter()
        .rposition(|entry| entry_type(&entry.value) == Some("reset_boundary"));
    let mut imported = ImportedSession::new(candidate.clone());
    for warning in &document.warnings {
        imported.warn(warning.clone());
    }
    let mut blobs = BlobResolver::new(candidate.source, &candidate.path);
    let mut emissions = HashMap::new();
    let mut retained_tails: HashMap<String, Vec<usize>> = HashMap::new();
    let mut remote_histories = HashMap::new();

    for (entry_index, entry) in path.iter().enumerate() {
        let mut emission = Emission::default();
        match entry_type(&entry.value) {
            Some("message") => {
                let message = entry
                    .value
                    .get("message")
                    .filter(|value| value.is_object())
                    .ok_or_else(|| invalid(format!("message entry {} has no message object", entry.id)))?;
                emission = emit_agent_message(message, &entry.id, &mut imported, &mut blobs);
            }
            Some("custom_message") => {
                let content = content_parts(
                    entry.value.get("content").unwrap_or(&Value::Null),
                    &entry.id,
                    &mut imported,
                    &mut blobs,
                );
                let index = imported.push(ImportMessage::User { content }, false);
                emission.model.push(index);
                if entry.value.get("display").and_then(Value::as_bool) == Some(false) {
                    imported.warn(format!(
                        "hidden custom_message {} was retained for model context",
                        entry.id
                    ));
                }
            }
            Some("compaction") => {
                let summary = required_string(&entry.value, "summary", &entry.id)?;
                let summary_index = imported.push(ImportMessage::Summary { text: summary }, false);
                emission.model.push(summary_index);
                if let Some(items) = remote_replacement_history(&entry.value) {
                    let remote = emit_remote_replacement_history(
                        items,
                        &entry.id,
                        &mut imported,
                        &mut blobs,
                    )?;
                    if remote.has_opaque_checkpoint && remote.model.is_empty()
                        && latest_compaction == Some(entry_index)
                        && latest_reset.is_none_or(|reset| reset < entry_index) {
                        return Err(invalid(format!(
                            "compaction {} has only opaque OpenAI remote replacement history; its checkpoint cannot be faithfully imported",
                            entry.id
                        )));
                    }
                    remote_histories.insert(entry.id.clone(), remote);
                }
                if let Some(tail) = entry.value.get("retainedTail") {
                    let tail = tail.as_array().ok_or_else(|| {
                        invalid(format!("compaction entry {} has a non-array retainedTail", entry.id))
                    })?;
                    let mut tail_indexes = Vec::new();
                    for (position, message) in tail.iter().enumerate() {
                        if !message.is_object() {
                            return Err(invalid(format!(
                                "compaction entry {} retainedTail[{position}] is not a message object",
                                entry.id
                            )));
                        }
                        let retained = emit_agent_message(
                            message,
                            &format!("{} retainedTail[{position}]", entry.id),
                            &mut imported,
                            &mut blobs,
                        );
                        tail_indexes.extend(retained.model);
                    }
                    retained_tails.insert(entry.id.clone(), tail_indexes);
                }
            }
            Some("branch_summary") => {
                let summary = required_string(&entry.value, "summary", &entry.id)?;
                let index = imported.push(ImportMessage::Summary { text: summary }, false);
                emission.model.push(index);
            }
            Some("custom")
            | Some("label")
            | Some("model_change")
            | Some("thinking_level_change")
            | Some("service_tier_change")
            | Some("credential_pin")
            | Some("ttsr_injection")
            | Some("mode_change")
            | Some("title_change")
            | Some("session_info")
            | Some("reset_boundary") => {}
            Some("session_init") => imported.warn(format!(
                "omitted source session_init instructions at {}; foreign system prompts are not imported",
                entry.id
            )),
            Some(kind) => imported.warn(format!(
                "unsupported {} session entry type {kind:?} at {} was not imported",
                candidate.source.as_str(),
                entry.id
            )),
            None => {
                return Err(invalid(format!("session entry {} has no type", entry.id)));
            }
        }
        emissions.insert(entry.id.clone(), emission);
    }

    if let Some(reset) =
        latest_reset.filter(|reset| latest_compaction.is_none_or(|compaction| *reset > compaction))
    {
        append_entry_context(
            &mut imported,
            &emissions,
            path.get(reset.saturating_add(1)..).unwrap_or_default(),
        );
    } else if let Some(compaction_index) = latest_compaction {
        let compaction = path
            .get(compaction_index)
            .copied()
            .ok_or_else(|| invalid("latest compaction index is outside the selected path"))?;
        if let Some(summary) = emissions.get(&compaction.id) {
            imported.context.extend(summary.model.iter().copied());
        }
        if let Some(remote) = remote_histories.get(&compaction.id) {
            imported.context.extend(remote.model.iter().copied());
            if let Some(replay_through) =
                optional_string(&compaction.value, "providerReplayThroughEntryId")
            {
                if replay_through != compaction.id {
                    let before_compaction = path.get(..compaction_index).unwrap_or_default();
                    if let Some(replay_index) = before_compaction
                        .iter()
                        .position(|entry| entry.id == replay_through)
                    {
                        append_entry_context(
                            &mut imported,
                            &emissions,
                            path.get(replay_index.saturating_add(1)..compaction_index)
                                .unwrap_or_default(),
                        );
                    } else {
                        imported.warn(format!(
                                "remote compaction {} references missing providerReplayThroughEntryId {replay_through}",
                                compaction.id
                            ));
                    }
                }
            }
        } else if let Some(tail) = retained_tails.get(&compaction.id) {
            imported.context.extend(tail.iter().copied());
        } else if let Some(first_kept) = first_kept_entry_id(&document, compaction) {
            if first_kept != compaction.id {
                let before_compaction = path.get(..compaction_index).unwrap_or_default();
                if let Some(first_kept_index) = before_compaction
                    .iter()
                    .position(|entry| entry.id == first_kept)
                {
                    append_entry_context(
                        &mut imported,
                        &emissions,
                        path.get(first_kept_index..compaction_index)
                            .unwrap_or_default(),
                    );
                } else {
                    imported.warn(format!(
                        "compaction {} references missing firstKeptEntryId {first_kept}",
                        compaction.id
                    ));
                }
            }
        } else {
            imported.warn(format!(
                "compaction {} has neither retainedTail nor firstKeptEntryId",
                compaction.id
            ));
        }
        append_entry_context(
            &mut imported,
            &emissions,
            path.get(compaction_index.saturating_add(1)..)
                .unwrap_or_default(),
        );
    } else {
        append_entry_context(&mut imported, &emissions, &path);
    }

    Ok(imported)
}

fn append_entry_context(
    imported: &mut ImportedSession,
    emissions: &HashMap<String, Emission>,
    entries: &[&StoredEntry],
) {
    for entry in entries {
        // Native context reconstruction emits only the latest compaction
        // summary. Earlier checkpoints remain display history, not nested
        // summaries in the replacement history.
        if entry_type(&entry.value) == Some("compaction") {
            continue;
        }
        if let Some(emission) = emissions.get(&entry.id) {
            imported.context.extend(emission.model.iter().copied());
        }
    }
}

fn ensure_supported_source(source: ImportSource) -> io::Result<()> {
    match source {
        ImportSource::Omp | ImportSource::Pi => Ok(()),
        _ => Err(invalid(format!(
            "{} is not a Pi/OMP session source",
            source.as_str()
        ))),
    }
}

fn is_session_file(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    name.ends_with(".jsonl") || name.ends_with(".jsonl.zst")
}

fn storage_layouts(source: ImportSource) -> io::Result<Vec<StorageLayout>> {
    ensure_supported_source(source)?;
    let home = xai_dirs::home_dir().ok_or_else(|| invalid("could not resolve home directory"))?;
    let layout = match source {
        ImportSource::Pi => pi_storage_layout(&home),
        ImportSource::Omp => omp_storage_layout(&home),
        _ => unreachable!(),
    };
    Ok(vec![layout])
}

fn pi_storage_layout(home: &Path) -> StorageLayout {
    let agent =
        env_path("PI_CODING_AGENT_DIR", home, true).unwrap_or_else(|| home.join(".pi/agent"));
    let sessions = env_path("PI_CODING_AGENT_SESSION_DIR", home, true)
        .unwrap_or_else(|| agent.join("sessions"));
    StorageLayout { sessions, agent }
}

fn omp_storage_layout(home: &Path) -> StorageLayout {
    let config_name = env::var_os("PI_CONFIG_DIR")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".omp"));
    let profile = active_omp_profile();
    let config_root = home.join(config_name);
    let profile_root = profile
        .as_deref()
        .map(|profile| config_root.join("profiles").join(profile));
    let default_agent = profile_root
        .as_ref()
        .map(|root| root.join("agent"))
        .unwrap_or_else(|| config_root.join("agent"));

    // Named profiles deliberately ignore PI_CODING_AGENT_DIR. The OMP resolver
    // accepts an XDG root only when it already exists, mirroring its migration
    // guard instead of creating or probing any new source locations.
    let mut agent = if profile.is_none() {
        env_path("PI_CODING_AGENT_DIR", home, false).unwrap_or(default_agent)
    } else {
        default_agent
    };
    if profile.is_none()
        && env::var_os("PI_CODING_AGENT_DIR").is_some_and(|value| !value.is_empty())
    {
        return StorageLayout {
            sessions: agent.join("sessions"),
            agent,
        };
    }
    if cfg!(any(target_os = "linux", target_os = "macos")) {
        if let Some(data_home) = env::var_os("XDG_DATA_HOME").filter(|value| !value.is_empty()) {
            let xdg_root = PathBuf::from(data_home).join("omp");
            let scoped = profile
                .as_deref()
                .map(|profile| xdg_root.join("profiles").join(profile))
                .unwrap_or(xdg_root);
            if scoped.is_dir() {
                agent = scoped;
            }
        }
    }
    StorageLayout {
        sessions: agent.join("sessions"),
        agent,
    }
}

fn active_omp_profile() -> Option<String> {
    let raw = match env::var_os("OMP_PROFILE") {
        Some(value) => value,
        None => env::var_os("PI_PROFILE")?,
    };
    let profile = raw.to_string_lossy().trim().to_owned();
    if profile.is_empty() || profile == "default" || !valid_omp_profile(&profile) {
        return None;
    }
    Some(profile)
}

fn valid_omp_profile(profile: &str) -> bool {
    if profile.len() > 64 || profile.ends_with('.') || profile == "." || profile == ".." {
        return false;
    }
    let mut chars = profile.bytes();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
        return false;
    }
    if !chars.all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
    }) {
        return false;
    }
    let device = profile.split('.').next().unwrap_or_default();
    let serial_suffix = device
        .strip_prefix("com")
        .or_else(|| device.strip_prefix("lpt"));
    !matches!(device, "con" | "prn" | "aux" | "nul")
        && !serial_suffix.is_some_and(|suffix| {
            suffix.len() == 1 && suffix.bytes().all(|byte| byte.is_ascii_digit())
        })
}

fn env_path(key: &str, home: &Path, expand_tilde: bool) -> Option<PathBuf> {
    let value = env::var_os(key)?;
    if value.is_empty() {
        return None;
    }
    let value = PathBuf::from(value);
    let expanded = if expand_tilde {
        expand_home_path(&value, home)
    } else {
        value
    };
    if expanded.is_absolute() {
        Some(expanded)
    } else {
        env::current_dir().ok().map(|cwd| cwd.join(expanded))
    }
}

fn expand_home_path(path: &Path, home: &Path) -> PathBuf {
    let mut components = path.components();
    let Some(first) = components.next() else {
        return path.to_path_buf();
    };
    if first.as_os_str() != "~" {
        return path.to_path_buf();
    }
    let mut expanded = home.to_path_buf();
    for component in components {
        expanded.push(component.as_os_str());
    }
    expanded
}

#[derive(Clone, Copy)]
enum SessionDialect {
    Unknown,
    Omp,
    Pi,
    Mixed,
}

impl SessionDialect {
    fn observe(self, marker: Option<ImportSource>) -> Self {
        match (self, marker) {
            (current, None) => current,
            (Self::Unknown, Some(ImportSource::Omp)) => Self::Omp,
            (Self::Unknown, Some(ImportSource::Pi)) => Self::Pi,
            (Self::Omp, Some(ImportSource::Omp)) => Self::Omp,
            (Self::Pi, Some(ImportSource::Pi)) => Self::Pi,
            _ => Self::Mixed,
        }
    }

    fn source(self) -> Option<ImportSource> {
        match self {
            Self::Omp => Some(ImportSource::Omp),
            Self::Pi => Some(ImportSource::Pi),
            Self::Unknown | Self::Mixed => None,
        }
    }
}

fn dialect_marker(value: &Value) -> Option<ImportSource> {
    match entry_type(value) {
        Some(
            "title"
            | "reset_boundary"
            | "session_init"
            | "credential_pin"
            | "ttsr_injection"
            | "service_tier_change"
            | "title_change",
        ) => Some(ImportSource::Omp),
        Some("session_info") => Some(ImportSource::Pi),
        Some("session")
            if [
                "additionalDirectories",
                "previousSessionFiles",
                "providerPromptCacheKey",
            ]
            .iter()
            .any(|field| value.get(*field).is_some()) =>
        {
            Some(ImportSource::Omp)
        }
        _ => None,
    }
}

struct Metadata {
    header: Header,
    title: Option<String>,
    dialect: SessionDialect,
}

fn read_metadata(path: &Path) -> io::Result<Metadata> {
    let records = json_head(path, METADATA_PREFIX_BYTES)?;
    let mut header = None;
    let mut title = None;
    let mut first_user_text = None;
    let mut dialect = SessionDialect::Unknown;
    for value in records {
        dialect = dialect.observe(dialect_marker(&value));
        match entry_type(&value) {
            Some("title") => {
                title = optional_string(&value, "title").or(title);
            }
            Some("session") if header.is_none() => {
                let parsed = parse_header(&value)?;
                title = parsed.title.clone().or(title);
                header = Some(parsed);
            }
            Some("session") => {
                return Err(invalid(format!(
                    "{} has multiple session headers",
                    path.display()
                )));
            }
            Some("session_info") | Some("title_change") => {
                title = optional_string(&value, "name")
                    .or_else(|| optional_string(&value, "title"))
                    .or(title);
            }
            Some("message") if first_user_text.is_none() => {
                if value
                    .get("message")
                    .and_then(|message| message.get("role"))
                    .and_then(Value::as_str)
                    .is_some_and(|role| role == "user")
                {
                    first_user_text = value
                        .get("message")
                        .and_then(|message| message.get("content"))
                        .and_then(metadata_text);
                }
            }
            _ => {}
        }
    }
    let header = header.ok_or_else(|| {
        invalid(format!(
            "{} has no session header in metadata prefix",
            path.display()
        ))
    })?;
    let title = title
        .filter(|title| !title.trim().is_empty())
        .or_else(|| first_user_text.map(|text| short_title(&text)))
        .filter(|title| !title.trim().is_empty());
    Ok(Metadata {
        header,
        title,
        dialect,
    })
}

fn metadata_text(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Array(parts) => {
            let text = parts
                .iter()
                .filter_map(|part| {
                    let kind = entry_type(part)?;
                    if matches!(kind, "text" | "input_text" | "output_text") {
                        optional_string(part, "text")
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>()
                .join("");
            (!text.is_empty()).then_some(text)
        }
        _ => None,
    }
}

fn candidate_from_metadata(
    source: ImportSource,
    path: &Path,
    metadata: &Metadata,
) -> ImportCandidate {
    ImportCandidate {
        source,
        id: metadata.header.id.clone(),
        path: path.to_path_buf(),
        cwd: metadata.header.cwd.clone(),
        title: metadata
            .title
            .clone()
            .unwrap_or_else(|| format!("{} session", source.as_str())),
        modified: modified(path),
        leaf_id: None,
    }
}

fn read_document(path: &Path) -> io::Result<SessionDocument> {
    let (values, warnings) = json_lines_with_warnings(path)?;
    if values.is_empty() {
        return Err(invalid(format!("{} is empty", path.display())));
    }

    let mut header = None;
    let mut slot_title = None;
    let mut entries = Vec::new();
    let mut previous_id = None;
    let mut seen_ids = HashSet::new();
    let mut logical_index = 0usize;
    for value in values {
        match entry_type(&value) {
            Some("title") if header.is_none() => {
                slot_title = optional_string(&value, "title").or(slot_title);
            }
            Some("session") if header.is_none() => {
                let parsed = parse_header(&value)?;
                logical_index = logical_index.saturating_add(1);
                header = Some(parsed);
            }
            Some("session") => {
                return Err(invalid(format!(
                    "{} has multiple session headers",
                    path.display()
                )));
            }
            Some(_) if header.is_none() => {
                return Err(invalid(format!(
                    "{} has an entry before its session header",
                    path.display()
                )));
            }
            Some(_) => {
                let current_header = header.as_ref().expect("header checked above");
                let (id, parent_id) = if current_header.version == 1 {
                    let id = format!("v1-{logical_index}");
                    (id, previous_id.clone())
                } else {
                    let id = required_string(&value, "id", "session entry")?;
                    let parent_id = match value.get("parentId") {
                        Some(Value::Null) => None,
                        Some(Value::String(parent)) if !parent.is_empty() => Some(parent.clone()),
                        _ => {
                            return Err(invalid(format!(
                                "session entry {id} has no string-or-null parentId"
                            )));
                        }
                    };
                    (id, parent_id)
                };
                if !seen_ids.insert(id.clone()) {
                    return Err(invalid(format!(
                        "{} has duplicate entry id {id}",
                        path.display()
                    )));
                }
                entries.push(StoredEntry {
                    id: id.clone(),
                    parent_id,
                    logical_index,
                    value,
                });
                previous_id = Some(id);
                logical_index = logical_index.saturating_add(1);
            }
            None => {
                return Err(invalid(format!(
                    "{} contains a JSONL record without type",
                    path.display()
                )));
            }
        }
    }
    let header =
        header.ok_or_else(|| invalid(format!("{} has no session header", path.display())))?;
    Ok(SessionDocument {
        header,
        slot_title,
        entries,
        warnings,
    })
}

fn parse_header(value: &Value) -> io::Result<Header> {
    let id = required_string(value, "id", "session header")?;
    let cwd = PathBuf::from(required_string(value, "cwd", "session header")?);
    if cwd.as_os_str().is_empty() {
        return Err(invalid("session header has an empty cwd"));
    }
    let version = match value.get("version") {
        None | Some(Value::Null) => 1,
        Some(Value::Number(number)) => number
            .as_u64()
            .ok_or_else(|| invalid("session version is not an integer"))?,
        _ => return Err(invalid("session version is not an integer")),
    };
    if !(1..=3).contains(&version) {
        return Err(invalid(format!(
            "unsupported Pi/OMP session version {version}; supported versions are 1, 2, and 3"
        )));
    }
    Ok(Header {
        id,
        cwd,
        version,
        title: optional_string(value, "title"),
    })
}

fn selected_path<'a>(
    document: &'a SessionDocument,
    leaf_id: Option<&str>,
) -> io::Result<Vec<&'a StoredEntry>> {
    if document.entries.is_empty() {
        if let Some(leaf_id) = leaf_id {
            return Err(invalid(format!(
                "requested leaf {leaf_id} does not exist in an empty session"
            )));
        }
        return Ok(Vec::new());
    }
    let by_id: HashMap<&str, &StoredEntry> = document
        .entries
        .iter()
        .map(|entry| (entry.id.as_str(), entry))
        .collect();
    let mut current = match leaf_id {
        Some(id) => by_id
            .get(id)
            .copied()
            .ok_or_else(|| invalid(format!("requested session leaf {id} does not exist")))?,
        None => document
            .entries
            .last()
            .ok_or_else(|| invalid("session unexpectedly has no entries"))?,
    };
    let mut reverse = Vec::new();
    let mut seen = HashSet::new();
    loop {
        if !seen.insert(current.id.as_str()) {
            return Err(invalid(format!(
                "session branch has a parent cycle at {}",
                current.id
            )));
        }
        reverse.push(current);
        let Some(parent_id) = current.parent_id.as_deref() else {
            break;
        };
        current = by_id.get(parent_id).copied().ok_or_else(|| {
            invalid(format!(
                "selected session branch references missing parent {parent_id} from {}",
                reverse
                    .last()
                    .map(|entry| entry.id.as_str())
                    .unwrap_or("entry")
            ))
        })?;
    }
    reverse.reverse();
    Ok(reverse)
}

fn candidate_from_document(
    source: ImportSource,
    path: &Path,
    document: &SessionDocument,
) -> io::Result<ImportCandidate> {
    let selected = selected_path(document, None)?;
    let mut title = document
        .slot_title
        .clone()
        .or_else(|| document.header.title.clone())
        .filter(|title| !title.trim().is_empty());
    let mut first_user_text = None;
    for entry in selected {
        match entry_type(&entry.value) {
            Some("session_info") => {
                title = optional_string(&entry.value, "name")
                    .filter(|name| !name.trim().is_empty())
                    .or(title);
            }
            Some("title_change") => {
                title = optional_string(&entry.value, "title")
                    .filter(|name| !name.trim().is_empty())
                    .or(title);
            }
            Some("message") if first_user_text.is_none() => {
                let message = entry.value.get("message");
                if message
                    .and_then(|message| message.get("role"))
                    .and_then(Value::as_str)
                    == Some("user")
                {
                    first_user_text = message
                        .and_then(|message| message.get("content"))
                        .and_then(metadata_text);
                }
            }
            _ => {}
        }
    }
    Ok(ImportCandidate {
        source,
        id: document.header.id.clone(),
        path: path.to_path_buf(),
        cwd: document.header.cwd.clone(),
        title: title
            .or_else(|| first_user_text.map(|text| short_title(&text)))
            .unwrap_or_else(|| format!("{} session", source.as_str())),
        modified: modified(path),
        leaf_id: None,
    })
}

fn entry_type(value: &Value) -> Option<&str> {
    value.get("type")?.as_str()
}

fn required_string(value: &Value, field: &str, subject: &str) -> io::Result<String> {
    optional_string(value, field)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid(format!("{subject} has no non-empty string {field}")))
}

fn optional_string(value: &Value, field: &str) -> Option<String> {
    value.get(field)?.as_str().map(ToOwned::to_owned)
}

fn first_kept_entry_id(document: &SessionDocument, compaction: &StoredEntry) -> Option<String> {
    if let Some(id) = optional_string(&compaction.value, "firstKeptEntryId") {
        return Some(id);
    }
    if document.header.version == 1 {
        let index = compaction
            .value
            .get("firstKeptEntryIndex")
            .and_then(Value::as_u64)
            .and_then(|index| usize::try_from(index).ok())?;
        return document
            .entries
            .iter()
            .find(|entry| entry.logical_index == index)
            .map(|entry| entry.id.clone());
    }
    None
}

fn remote_replacement_history(compaction: &Value) -> Option<&[Value]> {
    let remote = compaction
        .get("preserveData")?
        .get("openaiRemoteCompaction")?
        .as_object()?;
    remote
        .get("provider")
        .and_then(Value::as_str)
        .filter(|provider| !provider.is_empty())?;
    remote
        .get("replacementHistory")?
        .as_array()
        .map(Vec::as_slice)
}

fn emit_remote_replacement_history(
    items: &[Value],
    compaction_id: &str,
    imported: &mut ImportedSession,
    blobs: &mut BlobResolver,
) -> io::Result<RemoteHistory> {
    let mut history = RemoteHistory::default();
    for (position, item) in items.iter().enumerate() {
        if !item.is_object() {
            return Err(invalid(format!(
                "compaction {compaction_id} has a non-object OpenAI replacementHistory item at {position}"
            )));
        }
        let location = format!("{compaction_id} replacementHistory[{position}]");
        match entry_type(item) {
            Some("message") => history.model.extend(emit_agent_message(item, &location, imported, blobs).model),
            Some("function_call") => history
                .model
                .extend(emit_remote_function_call(item, &location, imported).model),
            Some("function_call_output") => history
                .model
                .extend(emit_remote_function_output(item, &location, imported, blobs).model),
            Some("compaction") | Some("compaction_summary") => {
                let text = optional_string(item, "summary")
                    .or_else(|| optional_string(item, "content"))
                    .or_else(|| item.get("content").and_then(metadata_text));
                if let Some(text) = text.filter(|text| !text.is_empty()) {
                    let index = imported.push(ImportMessage::Summary { text }, false);
                    history.model.push(index);
                } else {
                    history.has_opaque_checkpoint = true;
                    imported.warn(format!(
                        "opaque OpenAI remote compaction item at {location} cannot be replayed by the imported model"
                    ));
                }
            }
            Some("reasoning") => imported.warn(format!(
                "stripped provider-specific OpenAI reasoning from replacement history at {location}"
            )),
            Some(kind) => imported.warn(format!(
                "unsupported OpenAI replacement history item {kind:?} at {location} was not imported"
            )),
            None => {
                return Err(invalid(format!(
                    "compaction {compaction_id} replacementHistory[{position}] has no type"
                )));
            }
        }
    }
    Ok(history)
}

fn emit_remote_function_call(
    item: &Value,
    location: &str,
    imported: &mut ImportedSession,
) -> Emission {
    let id = item
        .get("call_id")
        .or_else(|| item.get("id"))
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty());
    let name = item
        .get("name")
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty());
    let (Some(id), Some(name)) = (id, name) else {
        imported.warn(format!(
            "OpenAI function call at {location} has no call_id or name and was not imported"
        ));
        return Emission::default();
    };
    let Some(arguments) = item.get("arguments") else {
        imported.warn(format!(
            "OpenAI function call {id} at {location} has no arguments and was not imported"
        ));
        return Emission::default();
    };
    let arguments = match arguments {
        Value::String(arguments) => arguments.clone(),
        value => match serde_json::to_string(value) {
            Ok(arguments) => arguments,
            Err(error) => {
                imported.warn(format!(
                    "OpenAI function call {id} at {location} has unserializable arguments: {error}"
                ));
                return Emission::default();
            }
        },
    };
    let index = imported.push(
        ImportMessage::Assistant {
            text: String::new(),
            tool_calls: vec![ImportToolCall {
                id: id.to_owned(),
                name: name.to_owned(),
                arguments,
            }],
        },
        false,
    );
    Emission { model: vec![index] }
}

fn emit_remote_function_output(
    item: &Value,
    location: &str,
    imported: &mut ImportedSession,
    blobs: &mut BlobResolver,
) -> Emission {
    let id = item
        .get("call_id")
        .or_else(|| item.get("id"))
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty());
    let Some(id) = id else {
        imported.warn(format!(
            "OpenAI function output at {location} has no call_id and was not imported"
        ));
        return Emission::default();
    };
    let output = item
        .get("output")
        .or_else(|| item.get("content"))
        .unwrap_or(&Value::Null);
    let content = content_parts(output, location, imported, blobs);
    let is_error = item
        .get("is_error")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || item.get("status").and_then(Value::as_str) == Some("failed");
    let index = imported.push(
        ImportMessage::ToolResult {
            id: id.to_owned(),
            content,
            is_error,
        },
        false,
    );
    Emission { model: vec![index] }
}

fn emit_agent_message(
    message: &Value,
    location: &str,
    imported: &mut ImportedSession,
    blobs: &mut BlobResolver,
) -> Emission {
    let Some(role) = message.get("role").and_then(Value::as_str) else {
        imported.warn(format!(
            "message at {location} has no role and was not imported"
        ));
        return Emission::default();
    };
    match role {
        "user" => {
            let content = content_parts(
                message.get("content").unwrap_or(&Value::Null),
                location,
                imported,
                blobs,
            );
            let index = imported.push(ImportMessage::User { content }, false);
            Emission { model: vec![index] }
        }
        "assistant" => emit_assistant(message, location, imported),
        "toolResult" | "tool" => {
            let Some(id) = message
                .get("toolCallId")
                .or_else(|| message.get("tool_call_id"))
                .and_then(Value::as_str)
                .filter(|id| !id.is_empty())
            else {
                imported.warn(format!(
                    "tool result at {location} has no tool call id and was not imported"
                ));
                return Emission::default();
            };
            let content = content_parts(
                message.get("content").unwrap_or(&Value::Null),
                location,
                imported,
                blobs,
            );
            let is_error = message
                .get("isError")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if message.get("isError").is_some()
                && message.get("isError").and_then(Value::as_bool).is_none()
            {
                imported.warn(format!(
                    "tool result {id} at {location} has non-boolean isError; treated as false"
                ));
            }
            let index = imported.push(
                ImportMessage::ToolResult {
                    id: id.to_owned(),
                    content,
                    is_error,
                },
                false,
            );
            Emission { model: vec![index] }
        }
        "bashExecution" => emit_bash_execution(message, location, imported),
        "custom" | "hookMessage" => {
            let content = content_parts(
                message.get("content").unwrap_or(&Value::Null),
                location,
                imported,
                blobs,
            );
            let index = imported.push(ImportMessage::User { content }, false);
            if message.get("display").and_then(Value::as_bool) == Some(false) {
                imported.warn(format!(
                    "hidden {role} message at {location} was retained for model context"
                ));
            }
            Emission { model: vec![index] }
        }
        "compactionSummary" | "branchSummary" => {
            let text = optional_string(message, "summary")
                .or_else(|| optional_string(message, "content"))
                .unwrap_or_default();
            let index = imported.push(ImportMessage::Summary { text }, false);
            Emission { model: vec![index] }
        }
        "system" | "developer" => {
            let text =
                metadata_text(message.get("content").unwrap_or(&Value::Null)).unwrap_or_default();
            if !text.is_empty() {
                imported.push(ImportMessage::Summary { text }, false);
            }
            imported.warn(format!(
                "source {role} instruction at {location} was kept display-only and excluded from model context"
            ));
            Emission::default()
        }
        _ => {
            imported.warn(format!(
                "unsupported message role {role:?} at {location} was not imported"
            ));
            Emission::default()
        }
    }
}

fn emit_assistant(message: &Value, location: &str, imported: &mut ImportedSession) -> Emission {
    let mut text = String::new();
    let mut calls = Vec::new();
    let mut reasoning = Vec::new();
    match message.get("content") {
        Some(Value::String(content)) => text.push_str(content),
        Some(Value::Array(parts)) => {
            for (position, part) in parts.iter().enumerate() {
                match entry_type(part) {
                    Some("text") | Some("output_text") | Some("input_text") => {
                        if let Some(part_text) = optional_string(part, "text") {
                            text.push_str(&part_text);
                        } else {
                            imported.warn(format!("assistant text block {location}[{position}] has no text"));
                        }
                    }
                    Some("toolCall") | Some("tool_use") | Some("function_call") => {
                        if let Some(call) = parse_tool_call(part, location, position, imported) {
                            calls.push(call);
                        }
                    }
                    Some("thinking") | Some("reasoning") => {
                        if let Some(thought) = optional_string(part, "thinking").or_else(|| optional_string(part, "text")) {
                            reasoning.push(thought);
                        }
                        imported.warn(format!(
                            "stripped provider-specific reasoning from model context at {location}[{position}]"
                        ));
                    }
                    Some("redacted_thinking") | Some("encrypted_reasoning") => imported.warn(format!(
                        "stripped opaque provider reasoning from model context at {location}[{position}]"
                    )),
                    Some(kind) => imported.warn(format!(
                        "unsupported assistant content block {kind:?} at {location}[{position}] was not imported"
                    )),
                    None => imported.warn(format!("assistant content block {location}[{position}] has no type")),
                }
            }
        }
        Some(Value::Null) | None => {}
        Some(_) => imported.warn(format!(
            "assistant content at {location} is neither string nor array"
        )),
    }
    let mut indexes = Vec::new();
    for thought in reasoning {
        imported.push(ImportMessage::Reasoning { text: thought }, false);
    }
    let index = imported.push(
        ImportMessage::Assistant {
            text,
            tool_calls: calls,
        },
        false,
    );
    indexes.push(index);
    if let Some(error) = optional_string(message, "errorMessage").filter(|error| !error.is_empty())
    {
        imported.push(
            ImportMessage::Summary {
                text: format!("[Source assistant error: {error}]"),
            },
            false,
        );
        imported.warn(format!(
            "preserved interrupted assistant error detail at {location} as display-only"
        ));
    }
    if matches!(
        message.get("stopReason").and_then(Value::as_str),
        Some("aborted" | "error" | "pending")
    ) {
        imported.warn(format!("interrupted assistant message at {location} was preserved without synthesizing a result"));
    }
    Emission { model: indexes }
}

fn parse_tool_call(
    value: &Value,
    location: &str,
    position: usize,
    imported: &mut ImportedSession,
) -> Option<ImportToolCall> {
    let id = optional_string(value, "id").filter(|id| !id.is_empty());
    let name = optional_string(value, "name").filter(|name| !name.is_empty());
    let (Some(id), Some(name)) = (id, name) else {
        imported.warn(format!(
            "tool call at {location}[{position}] has no id or name and was not imported"
        ));
        return None;
    };
    let Some(arguments) = value.get("arguments") else {
        imported.warn(format!(
            "tool call {id} at {location}[{position}] has no arguments and was not imported"
        ));
        return None;
    };
    let arguments = match arguments {
        Value::String(arguments) => arguments.clone(),
        value => {
            match serde_json::to_string(value) {
                Ok(arguments) => arguments,
                Err(error) => {
                    imported.warn(format!("tool call {id} at {location}[{position}] has unserializable arguments: {error}"));
                    return None;
                }
            }
        }
    };
    Some(ImportToolCall {
        id,
        name,
        arguments,
    })
}

fn emit_bash_execution(
    message: &Value,
    location: &str,
    imported: &mut ImportedSession,
) -> Emission {
    let command = optional_string(message, "command").unwrap_or_default();
    let output = optional_string(message, "output").unwrap_or_default();
    let id = format!("pi-bash-{location}");
    let arguments = serde_json::json!({ "command": command }).to_string();
    let call = imported.push(
        ImportMessage::Assistant {
            text: String::new(),
            tool_calls: vec![ImportToolCall {
                id: id.clone(),
                name: "bash".to_owned(),
                arguments,
            }],
        },
        false,
    );
    let result = imported.push(
        ImportMessage::ToolResult {
            id,
            content: vec![ImportContent::Text(output)],
            is_error: message
                .get("exitCode")
                .and_then(Value::as_i64)
                .is_some_and(|code| code != 0)
                || message.get("cancelled").and_then(Value::as_bool) == Some(true),
        },
        false,
    );
    if message.get("excludeFromContext").and_then(Value::as_bool) == Some(true) {
        Emission::default()
    } else {
        Emission {
            model: vec![call, result],
        }
    }
}

fn content_parts(
    value: &Value,
    location: &str,
    imported: &mut ImportedSession,
    blobs: &mut BlobResolver,
) -> Vec<ImportContent> {
    match value {
        Value::String(text) => vec![ImportContent::Text(text.clone())],
        Value::Array(parts) => {
            let mut content = Vec::new();
            for (position, part) in parts.iter().enumerate() {
                match entry_type(part) {
                    Some("text") | Some("input_text") | Some("output_text") => {
                        if let Some(text) = optional_string(part, "text") {
                            content.push(ImportContent::Text(text));
                        } else {
                            imported.warn(format!("text content at {location}[{position}] has no text"));
                        }
                    }
                    Some("image") => {
                        if let Some(image) = image_from_block(part, location, position, imported, blobs) {
                            content.push(image);
                        }
                    }
                    Some("image_url") | Some("input_image") => {
                        if let Some(image) = image_from_url_block(part, location, position, imported, blobs) {
                            content.push(image);
                        }
                    }
                    Some(kind) => imported.warn(format!(
                        "unsupported content block {kind:?} at {location}[{position}] was not imported"
                    )),
                    None => imported.warn(format!("content block {location}[{position}] has no type")),
                }
            }
            content
        }
        Value::Null => Vec::new(),
        _ => {
            imported.warn(format!("content at {location} is neither string nor array"));
            Vec::new()
        }
    }
}

fn image_from_block(
    value: &Value,
    location: &str,
    position: usize,
    imported: &mut ImportedSession,
    blobs: &mut BlobResolver,
) -> Option<ImportContent> {
    let data = optional_string(value, "data")?;
    let mime_type = optional_string(value, "mimeType")
        .or_else(|| optional_string(value, "media_type"))
        .filter(|mime| mime.starts_with("image/"));
    let Some(mime_type) = mime_type else {
        imported.warn(format!(
            "image at {location}[{position}] has no supported image mime type"
        ));
        return None;
    };
    image_from_data(&data, &mime_type, location, position, imported, blobs)
}

fn image_from_url_block(
    value: &Value,
    location: &str,
    position: usize,
    imported: &mut ImportedSession,
    blobs: &mut BlobResolver,
) -> Option<ImportContent> {
    let source = value
        .get("source")
        .filter(|value| value.is_object())
        .unwrap_or(value);
    let url = image_url(value).or_else(|| image_url(source))?;
    let mime_type = data_url_mime(url).unwrap_or("image/png");
    image_from_data(url, mime_type, location, position, imported, blobs)
}

fn image_url(value: &Value) -> Option<&str> {
    value
        .get("image_url")
        .and_then(|image| {
            image
                .as_str()
                .or_else(|| image.get("url").and_then(Value::as_str))
        })
        .or_else(|| value.get("url").and_then(Value::as_str))
}

fn image_from_data(
    data: &str,
    mime_type: &str,
    location: &str,
    position: usize,
    imported: &mut ImportedSession,
    blobs: &mut BlobResolver,
) -> Option<ImportContent> {
    if let Some(hash) = data.strip_prefix(BLOB_PREFIX) {
        let bytes = blobs.resolve(hash, location, position, imported)?;
        let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
        return Some(ImportContent::Image {
            url: format!("data:{mime_type};base64,{encoded}"),
        });
    }
    if data.starts_with("data:image/") && data.contains(";base64,") {
        return Some(ImportContent::Image {
            url: data.to_owned(),
        });
    }
    if data.starts_with("http://") || data.starts_with("https://") || data.starts_with("file:") {
        imported.warn(format!(
            "external image URL at {location}[{position}] was not imported; only inline data and safe blob references are supported"
        ));
        return None;
    }
    Some(ImportContent::Image {
        url: format!("data:{mime_type};base64,{data}"),
    })
}

fn data_url_mime(url: &str) -> Option<&str> {
    let rest = url.strip_prefix("data:")?;
    let (mime, _) = rest.split_once(';')?;
    mime.starts_with("image/").then_some(mime)
}

struct BlobResolver {
    roots: Vec<PathBuf>,
}

impl BlobResolver {
    fn new(source: ImportSource, session_path: &Path) -> Self {
        let mut roots = Vec::new();
        if let Ok(layouts) = storage_layouts(source) {
            for layout in layouts {
                roots.push(layout.agent.join("blobs"));
            }
        }
        if let Some(agent) = session_agent_dir(session_path) {
            roots.push(agent.join("blobs"));
        }
        roots.sort();
        roots.dedup();
        Self { roots }
    }

    fn resolve(
        &mut self,
        hash: &str,
        location: &str,
        position: usize,
        imported: &mut ImportedSession,
    ) -> Option<Vec<u8>> {
        if !valid_blob_hash(hash) {
            imported.warn(format!(
                "rejected unsafe blob reference at {location}[{position}]"
            ));
            return None;
        }
        for root in &self.roots {
            let path = root.join(hash);
            let mut file = match open_source(&path) {
                Ok(file) => file,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => {
                    imported.warn(format!(
                        "could not safely open image blob {}: {error}",
                        path.display()
                    ));
                    continue;
                }
            };
            let size = match file.metadata() {
                Ok(metadata) => metadata.len(),
                Err(error) => {
                    imported.warn(format!(
                        "could not inspect image blob {}: {error}",
                        path.display()
                    ));
                    continue;
                }
            };
            if size > MAX_IMPORT_BYTES {
                imported.warn(format!("skipped oversized image blob {}", path.display()));
                continue;
            }
            let mut bytes = Vec::with_capacity(usize::try_from(size).unwrap_or(0));
            match file.read_to_end(&mut bytes) {
                Ok(_) => return Some(bytes),
                Err(error) => imported.warn(format!(
                    "could not read image blob {}: {error}",
                    path.display()
                )),
            }
        }
        imported.warn(format!(
            "missing image blob {hash} referenced at {location}[{position}]"
        ));
        None
    }
}

fn valid_blob_hash(hash: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn session_agent_dir(path: &Path) -> Option<PathBuf> {
    let mut current = path.parent()?;
    loop {
        if current.file_name().and_then(|name| name.to_str()) == Some("sessions") {
            return current.parent().map(Path::to_path_buf);
        }
        current = current.parent()?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn write_jsonl(dir: &Path, name: &str, entries: &[Value]) -> PathBuf {
        let project = dir.join("sessions").join("--project--");
        fs::create_dir_all(&project).unwrap();
        let path = project.join(name);
        let mut body = entries
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        body.push('\n');
        fs::write(&path, body).unwrap();
        path
    }

    fn candidate(path: &Path) -> ImportCandidate {
        inspect(ImportSource::Pi, path, None).unwrap()
    }

    fn header(version: u64) -> Value {
        serde_json::json!({ "type": "session", "version": version, "id": "session", "cwd": "/work" })
    }

    #[test]
    fn selected_branch_keeps_display_history_but_reset_removes_old_context() {
        let temp = tempdir().unwrap();
        let path = write_jsonl(
            temp.path(),
            "branch.jsonl",
            &[
                header(3),
                serde_json::json!({"type":"message","id":"u1","parentId":null,"message":{"role":"user","content":"root"}}),
                serde_json::json!({"type":"message","id":"a1","parentId":"u1","message":{"role":"assistant","content":[{"type":"thinking","thinking":"opaque"},{"type":"toolCall","id":"call","name":"bash","arguments":{"command":"pwd"}}],"stopReason":"aborted"}}),
                serde_json::json!({"type":"message","id":"r1","parentId":"a1","message":{"role":"toolResult","toolCallId":"call","content":"/work","isError":false}}),
                serde_json::json!({"type":"message","id":"old","parentId":"r1","message":{"role":"user","content":"old kept"}}),
                serde_json::json!({"type":"compaction","id":"c1","parentId":"old","summary":"compacted","firstKeptEntryId":"a1"}),
                serde_json::json!({"type":"message","id":"left","parentId":"old","message":{"role":"user","content":"left branch"}}),
                serde_json::json!({"type":"branch_summary","id":"bs","parentId":"c1","summary":"branch summary","fromId":"old"}),
                serde_json::json!({"type":"message","id":"right","parentId":"bs","message":{"role":"user","content":"right branch"}}),
                serde_json::json!({"type":"reset_boundary","id":"reset","parentId":"right"}),
                serde_json::json!({"type":"message","id":"after","parentId":"reset","message":{"role":"user","content":"after reset"}}),
            ],
        );
        let imported = load(&candidate(&path)).unwrap();
        let texts = imported
            .messages
            .iter()
            .filter_map(|message| match message {
                ImportMessage::User { content } => {
                    content.iter().find_map(|content| match content {
                        ImportContent::Text(text) => Some(text.as_str()),
                        _ => None,
                    })
                }
                ImportMessage::Summary { text } | ImportMessage::Reasoning { text } => {
                    Some(text.as_str())
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(texts.contains(&"root"));
        assert!(texts.contains(&"right branch"));
        assert!(!texts.contains(&"left branch"));
        assert!(texts.contains(&"opaque"));
        assert_eq!(imported.context.len(), 1);
        let context_message = imported
            .context
            .first()
            .and_then(|index| imported.messages.get(*index));
        assert!(matches!(
            context_message,
            Some(ImportMessage::User { content })
                if matches!(content.as_slice(), [ImportContent::Text(text)] if text == "after reset")
        ));
        assert!(imported.messages.iter().any(|message| matches!(
            message,
            ImportMessage::Assistant { tool_calls, .. }
                if matches!(tool_calls.as_slice(), [ImportToolCall { id, name, arguments }]
                    if id == "call" && name == "bash" && arguments == "{\"command\":\"pwd\"}")
        )));
        assert!(
            imported
                .warnings
                .iter()
                .any(|warning| warning.contains("reasoning"))
        );
        assert!(
            imported
                .warnings
                .iter()
                .any(|warning| warning.contains("interrupted"))
        );
        let mut alternate = candidate(&path);
        alternate.leaf_id = Some("left".to_owned());
        let alternate = load(&alternate).unwrap();
        assert!(alternate.messages.iter().any(|message| matches!(
            message,
            ImportMessage::User { content }
                if matches!(content.as_slice(), [ImportContent::Text(text)] if text == "left branch")
        )));
        assert!(!alternate.messages.iter().any(|message| matches!(
            message,
            ImportMessage::User { content }
                if matches!(content.as_slice(), [ImportContent::Text(text)] if text == "right branch")
        )));
    }

    #[test]
    fn retained_tail_is_context_after_summary_without_erasing_display_history() {
        let temp = tempdir().unwrap();
        let path = write_jsonl(
            temp.path(),
            "retained.jsonl",
            &[
                header(3),
                serde_json::json!({"type":"message","id":"before","parentId":null,"message":{"role":"user","content":"before"}}),
                serde_json::json!({"type":"compaction","id":"c1","parentId":"before","summary":"summary","retainedTail":[{"role":"user","content":"tail"}]}),
                serde_json::json!({"type":"message","id":"after","parentId":"c1","message":{"role":"user","content":"after"}}),
            ],
        );
        let imported = load(&candidate(&path)).unwrap();
        let context = imported
            .context
            .iter()
            .map(|index| {
                imported
                    .messages
                    .get(*index)
                    .expect("context index must address a message")
            })
            .collect::<Vec<_>>();
        assert!(matches!(context.as_slice(), [
            ImportMessage::Summary { text },
            ImportMessage::User { content: tail },
            ImportMessage::User { content: after },
        ] if text == "summary"
            && matches!(tail.as_slice(), [ImportContent::Text(text)] if text == "tail")
            && matches!(after.as_slice(), [ImportContent::Text(text)] if text == "after")));
        assert!(imported.messages.iter().any(|message| matches!(
            message,
            ImportMessage::User { content } if matches!(content.as_slice(), [ImportContent::Text(text)] if text == "before")
        )));
    }

    #[test]
    fn remote_compaction_replays_plaintext_history_and_provider_tail() {
        let temp = tempdir().unwrap();
        let path = write_jsonl(
            temp.path(),
            "remote.jsonl",
            &[
                header(3),
                serde_json::json!({"type":"message","id":"snapshot","parentId":null,"message":{"role":"user","content":"covered by remote replay"}}),
                serde_json::json!({"type":"message","id":"tail","parentId":"snapshot","message":{"role":"user","content":"local replay tail"}}),
                serde_json::json!({
                    "type":"compaction",
                    "id":"c1",
                    "parentId":"tail",
                    "summary":"remote summary",
                    "firstKeptEntryId":"c1",
                    "providerReplayThroughEntryId":"snapshot",
                    "preserveData":{"openaiRemoteCompaction":{
                        "provider":"openai",
                        "replacementHistory":[
                            {"type":"message","role":"user","content":[{"type":"input_text","text":"remote user"}]},
                            {"type":"function_call","call_id":"remote-call","name":"read","arguments":"{\"path\":\"README.md\"}"},
                            {"type":"function_call_output","call_id":"remote-call","output":"remote output"},
                            {"type":"compaction","encrypted_content":"opaque-checkpoint"}
                        ]
                    }}
                }),
                serde_json::json!({"type":"message","id":"after","parentId":"c1","message":{"role":"user","content":"after remote compaction"}}),
            ],
        );
        let imported = load(&candidate(&path)).unwrap();
        let context = imported
            .context
            .iter()
            .map(|index| {
                imported
                    .messages
                    .get(*index)
                    .expect("context index must address a message")
            })
            .collect::<Vec<_>>();
        assert!(matches!(context.as_slice(), [
            ImportMessage::Summary { text },
            ImportMessage::User { content: remote_user },
            ImportMessage::Assistant { tool_calls, .. },
            ImportMessage::ToolResult { id, content: output, .. },
            ImportMessage::User { content: local_tail },
            ImportMessage::User { content: after },
        ] if text == "remote summary"
            && matches!(remote_user.as_slice(), [ImportContent::Text(text)] if text == "remote user")
            && matches!(tool_calls.as_slice(), [ImportToolCall { id, name, arguments }]
                if id == "remote-call" && name == "read" && arguments == "{\"path\":\"README.md\"}")
            && id == "remote-call"
            && matches!(output.as_slice(), [ImportContent::Text(text)] if text == "remote output")
            && matches!(local_tail.as_slice(), [ImportContent::Text(text)] if text == "local replay tail")
            && matches!(after.as_slice(), [ImportContent::Text(text)] if text == "after remote compaction")));
        assert!(
            imported
                .warnings
                .iter()
                .any(|warning| warning.contains("opaque OpenAI remote compaction"))
        );
    }

    #[test]
    fn opaque_only_remote_compaction_fails_instead_of_claiming_context() {
        let temp = tempdir().unwrap();
        let path = write_jsonl(
            temp.path(),
            "opaque-remote.jsonl",
            &[
                header(3),
                serde_json::json!({"type":"message","id":"before","parentId":null,"message":{"role":"user","content":"before"}}),
                serde_json::json!({
                    "type":"compaction",
                    "id":"c1",
                    "parentId":"before",
                    "summary":"remote summary",
                    "firstKeptEntryId":"c1",
                    "preserveData":{"openaiRemoteCompaction":{
                        "provider":"openai",
                        "replacementHistory":[{"type":"compaction","encrypted_content":"opaque-checkpoint"}]
                    }}
                }),
                serde_json::json!({"type":"message","id":"after","parentId":"c1","message":{"role":"user","content":"after"}}),
            ],
        );
        let error = load(&candidate(&path)).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("only opaque OpenAI remote replacement history")
        );
        // A later clear supersedes the opaque checkpoint, so it must not block
        // importing a context that no longer depends on the encrypted state.
        let (mut records, _) = json_lines_with_warnings(&path).unwrap();
        records.push(serde_json::json!({"type":"reset_boundary","id":"reset","parentId":"after"}));
        records.push(serde_json::json!({"type":"message","id":"fresh","parentId":"reset","message":{"role":"user","content":"fresh task"}}));
        write_jsonl(temp.path(), "opaque-remote.jsonl", &records);
        let imported = load(&candidate(&path)).unwrap();
        assert!(matches!(imported.context.as_slice(), [index]
            if matches!(imported.messages.get(*index), Some(ImportMessage::User { content })
                if matches!(content.as_slice(), [ImportContent::Text(text)] if text == "fresh task"))));
    }

    #[test]
    fn version_one_first_kept_index_is_read_without_mutating_source() {
        let temp = tempdir().unwrap();
        let path = write_jsonl(
            temp.path(),
            "v1.jsonl",
            &[
                serde_json::json!({ "type": "session", "id": "legacy", "cwd": "/work" }),
                serde_json::json!({"type":"message","message":{"role":"user","content":"old"}}),
                serde_json::json!({"type":"message","message":{"role":"user","content":"kept"}}),
                serde_json::json!({"type":"compaction","summary":"legacy summary","firstKeptEntryIndex":2}),
                serde_json::json!({"type":"message","message":{"role":"user","content":"after"}}),
            ],
        );
        let before = fs::read(&path).unwrap();
        let imported = load(&candidate(&path)).unwrap();
        let context = imported
            .context
            .iter()
            .map(|index| {
                imported
                    .messages
                    .get(*index)
                    .expect("context index must address a message")
            })
            .collect::<Vec<_>>();
        assert!(matches!(context.as_slice(), [
            ImportMessage::Summary { text },
            ImportMessage::User { content: kept },
            ImportMessage::User { content: after },
        ] if text == "legacy summary"
            && matches!(kept.as_slice(), [ImportContent::Text(text)] if text == "kept")
            && matches!(after.as_slice(), [ImportContent::Text(text)] if text == "after")));
        assert_eq!(fs::read(&path).unwrap(), before);
    }

    #[test]
    fn version_two_hook_message_is_context_without_source_migration() {
        let temp = tempdir().unwrap();
        let path = write_jsonl(
            temp.path(),
            "v2.jsonl",
            &[
                header(2),
                serde_json::json!({"type":"message","id":"u1","parentId":null,"message":{"role":"user","content":"prompt"}}),
                serde_json::json!({"type":"message","id":"h1","parentId":"u1","message":{"role":"hookMessage","customType":"extension","content":"legacy hook","display":true}}),
            ],
        );
        let before = fs::read(&path).unwrap();
        let imported = load(&candidate(&path)).unwrap();
        assert_eq!(imported.context, vec![0, 1]);
        assert!(matches!(
            imported.messages.get(1),
            Some(ImportMessage::User { content })
                if matches!(content.as_slice(), [ImportContent::Text(text)] if text == "legacy hook")
        ));
        assert_eq!(fs::read(&path).unwrap(), before);
    }

    #[test]
    fn custom_message_is_context_but_custom_state_is_not() {
        let temp = tempdir().unwrap();
        let path = write_jsonl(
            temp.path(),
            "custom.jsonl",
            &[
                header(3),
                serde_json::json!({"type":"custom","id":"state","parentId":null,"customType":"extension","data":{"x":1}}),
                serde_json::json!({"type":"custom_message","id":"message","parentId":"state","customType":"extension","content":"injected","display":false}),
            ],
        );
        let imported = load(&candidate(&path)).unwrap();
        assert_eq!(imported.messages.len(), 1);
        assert_eq!(imported.context, vec![0]);
        assert!(
            imported
                .warnings
                .iter()
                .any(|warning| warning.contains("hidden custom_message"))
        );
    }

    #[test]
    fn blobs_are_confined_to_valid_hashes_and_missing_images_warn() {
        let temp = tempdir().unwrap();
        let hash = "a".repeat(64);
        let blobs = temp.path().join("blobs");
        fs::create_dir_all(&blobs).unwrap();
        fs::write(blobs.join(&hash), b"png-bytes").unwrap();
        let path = write_jsonl(
            temp.path(),
            "images.jsonl",
            &[
                header(3),
                serde_json::json!({"type":"message","id":"u1","parentId":null,"message":{"role":"user","content":[
                    {"type":"image","data":format!("blob:sha256:{hash}"),"mimeType":"image/png"},
                    {"type":"image","data":format!("blob:sha256:{}", "b".repeat(64)),"mimeType":"image/png"},
                    {"type":"image","data":"blob:sha256:../secret","mimeType":"image/png"}
                ]}}),
            ],
        );
        let imported = load(&candidate(&path)).unwrap();
        assert!(matches!(
            imported.messages.first(),
            Some(ImportMessage::User { content })
                if matches!(content.as_slice(), [ImportContent::Image { url }] if url == "data:image/png;base64,cG5nLWJ5dGVz")
        ));
        assert!(
            imported
                .warnings
                .iter()
                .any(|warning| warning.contains("missing image blob"))
        );
        assert!(
            imported
                .warnings
                .iter()
                .any(|warning| warning.contains("unsafe blob"))
        );
    }

    #[test]
    fn shared_override_store_requires_a_source_marker() {
        let metadata = Metadata {
            header: Header {
                id: "session".to_owned(),
                cwd: PathBuf::from("/work"),
                version: 3,
                title: None,
            },
            title: None,
            dialect: SessionDialect::Unknown,
        };
        assert_eq!(
            shared_store_source(Path::new("/tmp/shared/sessions/a.jsonl"), &metadata),
            None
        );
        assert_eq!(
            shared_store_source(Path::new("/tmp/.omp/agent/sessions/a.jsonl"), &metadata),
            Some(ImportSource::Omp)
        );
        let omp_metadata = Metadata {
            dialect: SessionDialect::Omp,
            ..metadata
        };
        assert_eq!(
            shared_store_source(Path::new("/tmp/shared/sessions/a.jsonl"), &omp_metadata),
            Some(ImportSource::Omp)
        );
    }
}
