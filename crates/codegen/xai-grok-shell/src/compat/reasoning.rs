//! Model metadata from models.dev (reasoning menus, context window, output cap).
//!
//! Lookup is by normalized API model id. Unknown ids stay off.
//!
//! 1. Runtime overlay `$GROK_HOME/models-dev-reasoning.json` (`/sync-models-dev`).
//! 2. Committed snapshot baked at release (`scripts/sync_models_dev.py`).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io::{self, Write};
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, SystemTime};

use indexmap::IndexMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use xai_grok_sampling_types::{ReasoningEffort, ReasoningEffortOption};

use crate::agent::config::{ModelEntry, ModelInfo};

const SNAPSHOT: &str = include_str!("data/models_dev_reasoning.json");
const OVERLAY_FILE: &str = "models-dev-reasoning.json";
const MODELS_DEV_URL: &str = "https://models.dev/api.json";
const KNOWN_EFFORTS: &[&str] = &["none", "minimal", "low", "medium", "high", "xhigh", "max"];
const MIN_CONTEXT: u64 = 4_096;
const MAX_CONTEXT: u64 = 16_000_000;
const MAX_OUTPUT: u64 = 16_000_000;
const PREFERRED_PROVIDERS: &[&str] = &[
    "openai",
    "anthropic",
    "xai",
    "zai",
    "minimax",
    "google",
    "deepseek",
];

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct SnapshotEntry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kind: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    values: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    default: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    context: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    output: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct ReasoningMenu {
    pub default: ReasoningEffort,
    pub options: Vec<ReasoningEffortOption>,
}

/// Overlay/snapshot fields for one normalized model id.
#[derive(Debug, Clone, Default)]
pub struct CatalogMeta {
    pub reasoning: Option<ReasoningMenu>,
    pub context_window: Option<u64>,
    pub max_output_tokens: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct ModelsDevSync {
    pub count: usize,
    pub path: PathBuf,
}

#[derive(Debug, thiserror::Error)]
pub enum ModelsDevSyncError {
    #[error("couldn't reach models.dev: {0}")]
    Network(String),
    #[error("models.dev catalog produced no model metadata")]
    Empty,
    #[error("couldn't save {}: {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

fn snapshot() -> &'static HashMap<String, SnapshotEntry> {
    static MAP: OnceLock<HashMap<String, SnapshotEntry>> = OnceLock::new();
    MAP.get_or_init(|| serde_json::from_str(SNAPSHOT).unwrap_or_default())
}

struct OverlayState {
    mtime: Option<SystemTime>,
    entries: Option<HashMap<String, SnapshotEntry>>,
}

fn overlay_state() -> &'static RwLock<OverlayState> {
    static STATE: OnceLock<RwLock<OverlayState>> = OnceLock::new();
    STATE.get_or_init(|| {
        RwLock::new(OverlayState {
            mtime: None,
            entries: None,
        })
    })
}

#[cfg(test)]
fn test_overlay() -> &'static RwLock<Option<HashMap<String, SnapshotEntry>>> {
    static TEST: OnceLock<RwLock<Option<HashMap<String, SnapshotEntry>>>> = OnceLock::new();
    TEST.get_or_init(|| RwLock::new(None))
}

#[cfg(test)]
fn set_test_overlay(map: Option<HashMap<String, SnapshotEntry>>) {
    *test_overlay().write() = map;
}

/// Path of the user overlay written by `/sync-models-dev`.
pub(crate) fn overlay_path() -> PathBuf {
    crate::util::grok_home::grok_home().join(OVERLAY_FILE)
}

pub fn normalize_model_id(id: &str) -> String {
    let mut s = id.trim().to_ascii_lowercase().replace('_', "-");
    if let Some((_, rest)) = s.rsplit_once('/') {
        s = rest.to_owned();
    }
    s = s.replace('.', "-");
    strip_trailing_date(&s).to_owned()
}

fn strip_trailing_date(s: &str) -> &str {
    if s.len() < 11 {
        return s;
    }
    let i = s.len() - 11;
    let b = s.as_bytes();
    if b[i] == b'-'
        && b[i + 1].is_ascii_digit()
        && b[i + 2].is_ascii_digit()
        && b[i + 3].is_ascii_digit()
        && b[i + 4].is_ascii_digit()
        && b[i + 5] == b'-'
        && b[i + 6].is_ascii_digit()
        && b[i + 7].is_ascii_digit()
        && b[i + 8] == b'-'
        && b[i + 9].is_ascii_digit()
        && b[i + 10].is_ascii_digit()
    {
        return &s[..i];
    }
    s
}

fn lookup_entry(api_model: &str) -> Option<SnapshotEntry> {
    let key = normalize_model_id(api_model);
    if let Some(entry) = overlay_entry(&key) {
        return Some(entry);
    }
    snapshot().get(&key).cloned()
}

/// Overlay ∪ baked snapshot ids (normalized), for vendor fallback lists.
pub fn catalog_ids() -> Vec<String> {
    let mut ids: HashSet<String> = snapshot().keys().cloned().collect();
    #[cfg(test)]
    {
        if let Some(map) = test_overlay().read().as_ref() {
            ids.extend(map.keys().cloned());
        }
        return ids.into_iter().collect();
    }
    #[cfg(not(test))]
    {
        refresh_overlay_from_disk();
        if let Some(entries) = overlay_state().read().entries.as_ref() {
            ids.extend(entries.keys().cloned());
        }
        ids.into_iter().collect()
    }
}

pub fn lookup_meta(api_model: &str) -> Option<CatalogMeta> {
    let entry = lookup_entry(api_model)?;
    let reasoning = menu_from_entry(&entry);
    let context_window = entry.context.filter(|n| *n >= MIN_CONTEXT);
    let max_output_tokens = entry.output.filter(|n| *n > 0);
    if reasoning.is_none() && context_window.is_none() && max_output_tokens.is_none() {
        return None;
    }
    Some(CatalogMeta {
        reasoning,
        context_window,
        max_output_tokens,
    })
}

pub fn lookup(api_model: &str) -> Option<ReasoningMenu> {
    lookup_meta(api_model).and_then(|meta| meta.reasoning)
}

pub fn model_supports(api_model: &str) -> bool {
    lookup(api_model).is_some()
}

/// Fill effort / window / output-cap fields from the overlay or baked snapshot.
pub fn apply_to_model_info(info: &mut ModelInfo, api_model: &str) {
    let Some(meta) = lookup_meta(api_model) else {
        return;
    };
    if let Some(menu) = meta.reasoning {
        info.supports_reasoning_effort = true;
        info.reasoning_efforts = menu.options.clone();
        let keep = info
            .reasoning_effort
            .filter(|effort| menu.options.iter().any(|opt| opt.value == *effort));
        info.reasoning_effort = Some(keep.unwrap_or(menu.default));
    }
    if let Some(ctx) = meta.context_window {
        if let Some(nz) = NonZeroU64::new(ctx) {
            info.context_window = nz;
        }
    }
    if let Some(out) = meta.max_output_tokens {
        if out <= u32::MAX as u64 {
            info.max_completion_tokens = Some(out as u32);
        }
    }
}

/// Re-apply overlay/snapshot menus and limits onto vendor catalog entries
/// (not first-party Grok).
pub(crate) fn apply_overlay_to_vendor_entries(models: &mut IndexMap<String, ModelEntry>) {
    for entry in models.values_mut() {
        if crate::compat::is_vendor_catalog_model(entry) {
            let api_model = entry.info.model.clone();
            apply_to_model_info(&mut entry.info, &api_model);
        }
    }
}

/// Prefill for the custom-provider "add model" form: context window and
/// whether models.dev knows a reasoning menu. Unknown ids stay 128k / off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SuggestedModel {
    pub context_window: u64,
    pub supports_reasoning_effort: bool,
    pub matched: bool,
}

pub fn suggest_model(api_model: &str) -> SuggestedModel {
    match lookup_meta(api_model) {
        Some(meta) => SuggestedModel {
            context_window: meta.context_window.unwrap_or(128_000),
            supports_reasoning_effort: meta.reasoning.is_some(),
            matched: true,
        },
        None => SuggestedModel {
            context_window: 128_000,
            supports_reasoning_effort: false,
            matched: false,
        },
    }
}

fn default_reasoning_options() -> Vec<ReasoningEffortOption> {
    vec![
        option(ReasoningEffort::Low, false),
        option(ReasoningEffort::Medium, true),
        option(ReasoningEffort::High, false),
    ]
}

/// Merge models.dev limits with the user's reasoning toggle for a custom model.
///
/// Overlay always fills context / output cap. Reasoning is the user's choice:
/// on + unknown to models.dev gets a generic low/medium/high menu; off strips
/// any overlay menu so a false-positive cannot force `/effort`.
pub fn apply_custom_model_meta(
    info: &mut ModelInfo,
    api_model: &str,
    supports_reasoning_effort: bool,
) {
    apply_to_model_info(info, api_model);
    if supports_reasoning_effort {
        info.supports_reasoning_effort = true;
        if info.reasoning_efforts.is_empty() {
            info.reasoning_efforts = default_reasoning_options();
            info.reasoning_effort = Some(ReasoningEffort::Medium);
        }
    } else {
        info.supports_reasoning_effort = false;
        info.reasoning_efforts.clear();
        info.reasoning_effort = None;
    }
}

fn overlay_entry(key: &str) -> Option<SnapshotEntry> {
    #[cfg(test)]
    {
        return test_overlay()
            .read()
            .as_ref()
            .and_then(|map| map.get(key).cloned());
    }
    #[cfg(not(test))]
    {
        refresh_overlay_from_disk();
        overlay_state()
            .read()
            .entries
            .as_ref()
            .and_then(|map| map.get(key).cloned())
    }
}

fn refresh_overlay_from_disk() {
    let path = overlay_path();
    let meta = fs::metadata(&path).ok();
    let mtime = meta.and_then(|m| m.modified().ok());
    {
        let state = overlay_state().read();
        if state.mtime == mtime && (mtime.is_some() || state.entries.is_none()) {
            return;
        }
    }
    let entries = load_overlay_file(&path);
    let mut state = overlay_state().write();
    state.mtime = mtime;
    state.entries = entries;
}

fn load_overlay_file(path: &Path) -> Option<HashMap<String, SnapshotEntry>> {
    let raw = fs::read_to_string(path).ok()?;
    let map: HashMap<String, SnapshotEntry> = serde_json::from_str(&raw).ok()?;
    (!map.is_empty()).then_some(map)
}

fn install_overlay(entries: HashMap<String, SnapshotEntry>, mtime: Option<SystemTime>) {
    let mut state = overlay_state().write();
    state.mtime = mtime;
    state.entries = Some(entries);
}

/// Compact a models.dev `api.json` document into the snapshot shape.
fn compact_catalog(api: &serde_json::Value) -> BTreeMap<String, SnapshotEntry> {
    let mut out = BTreeMap::new();
    let mut claimed = HashSet::new();
    let Some(providers) = api.as_object() else {
        return out;
    };
    for pid in PREFERRED_PROVIDERS {
        if let Some(provider) = providers.get(*pid) {
            ingest_provider(&mut out, &mut claimed, provider, true);
        }
    }
    for (pid, provider) in providers {
        if PREFERRED_PROVIDERS.contains(&pid.as_str()) {
            continue;
        }
        ingest_provider(&mut out, &mut claimed, provider, false);
    }
    out
}

fn ingest_provider(
    out: &mut BTreeMap<String, SnapshotEntry>,
    claimed: &mut HashSet<String>,
    provider: &serde_json::Value,
    preferred: bool,
) {
    let Some(models) = provider.get("models").and_then(|v| v.as_object()) else {
        return;
    };
    for (model_id, model) in models {
        if !model.is_object() {
            continue;
        }
        let raw_id = model.get("id").and_then(|v| v.as_str()).unwrap_or(model_id);
        let key = normalize_model_id(raw_id);
        if key.is_empty() {
            continue;
        }
        let parsed = effort_values(model.get("reasoning_options"));
        let (context, output) = parse_limit(model);
        if preferred {
            claimed.insert(key.clone());
        }
        if parsed.is_none() && context.is_none() && output.is_none() {
            continue;
        }
        if out.contains_key(&key) {
            continue;
        }
        if claimed.contains(&key) && !preferred {
            continue;
        }
        let mut entry = SnapshotEntry {
            context,
            output,
            ..SnapshotEntry::default()
        };
        if let Some((kind, values)) = parsed {
            entry.default = Some(pick_default(&kind, &values));
            entry.kind = Some(kind);
            entry.values = values;
        }
        out.insert(key, entry);
    }
}

fn parse_limit(model: &serde_json::Value) -> (Option<u64>, Option<u64>) {
    let Some(limit) = model.get("limit") else {
        return (None, None);
    };
    let context = json_u64(limit.get("context"))
        .and_then(|n| (n >= MIN_CONTEXT && n <= MAX_CONTEXT).then_some(n));
    let output =
        json_u64(limit.get("output")).and_then(|n| (n >= 1 && n <= MAX_OUTPUT).then_some(n));
    (context, output)
}

fn json_u64(value: Option<&serde_json::Value>) -> Option<u64> {
    match value? {
        serde_json::Value::Number(n) => n.as_u64().or_else(|| {
            n.as_f64().and_then(|f| {
                if f.is_finite() && f >= 0.0 && f.fract() == 0.0 {
                    Some(f as u64)
                } else {
                    None
                }
            })
        }),
        _ => None,
    }
}

fn effort_values(options: Option<&serde_json::Value>) -> Option<(String, Vec<String>)> {
    let arr = options.and_then(|v| v.as_array())?;
    let mut efforts = Vec::new();
    let mut has_toggle = false;
    for opt in arr {
        let Some(kind) = opt.get("type").and_then(|v| v.as_str()) else {
            continue;
        };
        if kind == "toggle" {
            has_toggle = true;
            continue;
        }
        if kind != "effort" {
            continue;
        }
        let Some(raw) = opt.get("values").and_then(|v| v.as_array()) else {
            continue;
        };
        for item in raw {
            let token = match item {
                serde_json::Value::String(s) => s.trim().to_ascii_lowercase(),
                serde_json::Value::Null => continue,
                other => other.to_string().trim().to_ascii_lowercase(),
            };
            if KNOWN_EFFORTS.contains(&token.as_str()) && !efforts.iter().any(|e| e == &token) {
                efforts.push(token);
            }
        }
    }
    if !efforts.is_empty() {
        Some(("effort".into(), efforts))
    } else if has_toggle {
        Some(("toggle".into(), vec!["none".into(), "high".into()]))
    } else {
        None
    }
}

fn pick_default(kind: &str, values: &[String]) -> String {
    if kind == "toggle" {
        return "high".into();
    }
    if values.iter().any(|v| v == "none") {
        return "none".into();
    }
    values.last().cloned().unwrap_or_else(|| "high".into())
}

fn write_overlay_file(
    path: &Path,
    compact: &BTreeMap<String, SnapshotEntry>,
) -> Result<(), ModelsDevSyncError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| ModelsDevSyncError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    }
    let json = serde_json::to_string_pretty(compact).map_err(|e| ModelsDevSyncError::Io {
        path: path.to_path_buf(),
        source: io::Error::new(io::ErrorKind::InvalidData, e),
    })?;
    let tmp = path.with_extension("json.tmp");
    let mut file = fs::File::create(&tmp).map_err(|source| ModelsDevSyncError::Io {
        path: tmp.clone(),
        source,
    })?;
    file.write_all(json.as_bytes())
        .and_then(|_| file.write_all(b"\n"))
        .and_then(|_| file.sync_all())
        .map_err(|source| ModelsDevSyncError::Io {
            path: tmp.clone(),
            source,
        })?;
    drop(file);
    fs::rename(&tmp, path).map_err(|source| ModelsDevSyncError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(())
}

/// Fetch models.dev, compact, write the user overlay, and swap it in.
pub async fn sync_from_models_dev() -> Result<ModelsDevSync, ModelsDevSyncError> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .user_agent("grok-build-compat-models-dev-sync")
        .build()
        .map_err(|e| ModelsDevSyncError::Network(e.to_string()))?;
    let resp = client
        .get(MODELS_DEV_URL)
        .send()
        .await
        .map_err(|e| ModelsDevSyncError::Network(e.to_string()))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(ModelsDevSyncError::Network(format!(
            "{status} from {MODELS_DEV_URL}"
        )));
    }
    let api: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| ModelsDevSyncError::Network(e.to_string()))?;
    let compact = compact_catalog(&api);
    if compact.is_empty() {
        return Err(ModelsDevSyncError::Empty);
    }
    let path = overlay_path();
    write_overlay_file(&path, &compact)?;
    let mtime = fs::metadata(&path).ok().and_then(|m| m.modified().ok());
    let count = compact.len();
    install_overlay(compact.into_iter().collect(), mtime);
    Ok(ModelsDevSync { count, path })
}

fn menu_from_entry(entry: &SnapshotEntry) -> Option<ReasoningMenu> {
    let default = parse_effort(entry.default.as_deref()?)?;
    let mut options = Vec::new();
    for token in &entry.values {
        let Some(effort) = parse_effort(token) else {
            continue;
        };
        options.push(option(effort, effort == default));
    }
    if options.is_empty() {
        return None;
    }
    if !options.iter().any(|o| o.value == default) {
        options.push(option(default, true));
    }
    Some(ReasoningMenu { default, options })
}

fn parse_effort(token: &str) -> Option<ReasoningEffort> {
    token.parse().ok()
}

fn option(effort: ReasoningEffort, default: bool) -> ReasoningEffortOption {
    let (id, label) = match effort {
        ReasoningEffort::None => ("none", "None"),
        ReasoningEffort::Minimal => ("minimal", "Minimal"),
        ReasoningEffort::Low => ("low", "Low"),
        ReasoningEffort::Medium => ("medium", "Medium"),
        ReasoningEffort::High => ("high", "High"),
        ReasoningEffort::Xhigh => ("xhigh", "X-High"),
        ReasoningEffort::Max => ("max", "Max"),
    };
    ReasoningEffortOption {
        id: id.to_owned(),
        value: effort,
        label: label.to_owned(),
        description: None,
        default,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        SnapshotEntry, apply_custom_model_meta, apply_to_model_info, compact_catalog, lookup,
        lookup_meta, normalize_model_id, set_test_overlay, suggest_model,
    };
    use crate::agent::config::ModelInfo;
    use std::collections::HashMap;
    use xai_grok_sampling_types::ReasoningEffort;

    #[test]
    fn normalize_strips_provider_dot_and_date() {
        assert_eq!(normalize_model_id("openai/gpt-5.6-sol"), "gpt-5-6-sol");
        assert_eq!(normalize_model_id("gpt-5-2025-08-07"), "gpt-5");
        assert_eq!(
            normalize_model_id("anthropic/claude-sonnet-4.6"),
            "claude-sonnet-4-6"
        );
    }

    #[test]
    fn snapshot_mainstream_effort_and_off() {
        let sol = lookup("openai/gpt-5.6-sol").expect("gpt-5.6-sol");
        assert_eq!(sol.default, ReasoningEffort::None);
        assert!(sol.options.iter().any(|o| o.value == ReasoningEffort::Max));

        assert!(lookup("gpt-4o").is_none());
        assert!(lookup("claude-haiku-4-5").is_none());
        let gpt4o = lookup_meta("gpt-4o").expect("gpt-4o limits");
        assert!(gpt4o.reasoning.is_none());
        assert_eq!(gpt4o.context_window, Some(128_000));
        assert_eq!(gpt4o.max_output_tokens, Some(16_384));

        let sol_meta = lookup_meta("openai/gpt-5.6-sol").expect("sol limits");
        assert_eq!(sol_meta.context_window, Some(1_050_000));
        assert_eq!(sol_meta.max_output_tokens, Some(128_000));

        let sonnet = lookup_meta("claude-sonnet-4-6").expect("sonnet 4.6");
        assert_eq!(sonnet.context_window, Some(1_000_000));

        let glm = lookup("glm-5.3").expect("glm-5.3");
        assert_eq!(glm.default, ReasoningEffort::Max);
        assert!(!glm.options.iter().any(|o| o.value == ReasoningEffort::None));

        let mm = lookup("MiniMax-M3").expect("minimax-m3");
        assert_eq!(mm.default, ReasoningEffort::High);
        assert_eq!(mm.options.len(), 2);
        assert!(
            mm.options
                .iter()
                .any(|o| o.id == "none" && o.label == "None")
        );

        let opus = lookup("claude-opus-4-8").expect("opus 4.8");
        assert!(
            opus.options
                .iter()
                .any(|o| o.value == ReasoningEffort::Xhigh)
        );
    }

    #[test]
    fn compact_preferred_wins_and_toggle() {
        let api = serde_json::json!({
            "openai": {
                "models": {
                    "gpt-5.6-sol": {
                        "id": "gpt-5.6-sol",
                        "reasoning_options": [{
                            "type": "effort",
                            "values": ["none", "low", "medium", "high", "xhigh", "max"]
                        }],
                        "limit": { "context": 1050000, "output": 128000 }
                    },
                    "gpt-4o": {
                        "id": "gpt-4o",
                        "reasoning": false,
                        "limit": { "context": 128000, "output": 16384 }
                    }
                }
            },
            "other": {
                "models": {
                    "openai/gpt-5.6-sol": {
                        "id": "openai/gpt-5.6-sol",
                        "reasoning_options": [{ "type": "effort", "values": ["low", "high"] }]
                    },
                    "minimax-m3": {
                        "id": "minimax-m3",
                        "reasoning_options": [{ "type": "toggle" }]
                    }
                }
            }
        });
        let compact = compact_catalog(&api);
        let sol = compact.get("gpt-5-6-sol").expect("sol");
        assert_eq!(
            sol.values,
            ["none", "low", "medium", "high", "xhigh", "max"]
        );
        assert_eq!(sol.default.as_deref(), Some("none"));
        assert_eq!(sol.context, Some(1_050_000));
        assert_eq!(sol.output, Some(128_000));
        let gpt4o = compact.get("gpt-4o").expect("gpt-4o");
        assert!(gpt4o.kind.is_none());
        assert_eq!(gpt4o.context, Some(128_000));
        assert_eq!(gpt4o.output, Some(16_384));
        let mm = compact.get("minimax-m3").expect("m3");
        assert_eq!(mm.kind.as_deref(), Some("toggle"));
        assert_eq!(mm.values, ["none", "high"]);
        assert_eq!(mm.default.as_deref(), Some("high"));
    }

    #[test]
    fn compact_glm_keeps_official_list() {
        let api = serde_json::json!({
            "zai": {
                "models": {
                    "glm-5.3": {
                        "id": "glm-5.3",
                        "reasoning_options": [{
                            "type": "effort",
                            "values": ["low", "high", "max"]
                        }]
                    }
                }
            },
            "dump": {
                "models": {
                    "glm-5.3": {
                        "id": "glm-5.3",
                        "reasoning_options": [{
                            "type": "effort",
                            "values": ["none", "minimal", "low", "medium", "high", "xhigh", "max"]
                        }]
                    }
                }
            }
        });
        let mut compact = compact_catalog(&api);
        let glm = compact.remove("glm-5-3").expect("glm");
        assert_eq!(glm.values, ["low", "high", "max"]);
        assert_eq!(glm.default.as_deref(), Some("max"));
    }

    #[test]
    fn overlay_wins_over_baked_snapshot() {
        assert!(lookup("gpt-4o").is_none());
        let mut map = HashMap::new();
        map.insert(
            "gpt-4o".into(),
            SnapshotEntry {
                kind: Some("toggle".into()),
                values: vec!["none".into(), "high".into()],
                default: Some("high".into()),
                context: Some(128_000),
                output: Some(16_384),
            },
        );
        set_test_overlay(Some(map));
        let menu = lookup("gpt-4o").expect("overlay gpt-4o");
        assert_eq!(menu.default, ReasoningEffort::High);
        assert_eq!(menu.options.len(), 2);
        let meta = lookup_meta("gpt-4o").expect("overlay limits");
        assert_eq!(meta.context_window, Some(128_000));
        set_test_overlay(None);
        assert!(lookup("gpt-4o").is_none());
    }

    #[test]
    fn apply_fills_window_and_output_without_turning_on_effort() {
        let mut info = ModelInfo::fallback("gpt-4o");
        apply_to_model_info(&mut info, "gpt-4o");
        assert!(!info.supports_reasoning_effort);
        assert_eq!(info.context_window.get(), 128_000);
        assert_eq!(info.max_completion_tokens, Some(16_384));
    }

    #[test]
    fn suggest_model_matches_snapshot_and_unknown() {
        let sol = suggest_model("gpt-5.6-sol");
        assert!(sol.matched);
        assert!(sol.supports_reasoning_effort);
        assert_eq!(sol.context_window, 1_050_000);

        let unknown = suggest_model("proxy-mystery-v1");
        assert!(!unknown.matched);
        assert!(!unknown.supports_reasoning_effort);
        assert_eq!(unknown.context_window, 128_000);
    }

    #[test]
    fn custom_meta_user_off_strips_overlay_reasoning() {
        let mut info = ModelInfo::fallback("gpt-5.6-sol");
        apply_custom_model_meta(&mut info, "gpt-5.6-sol", false);
        assert!(!info.supports_reasoning_effort);
        assert!(info.reasoning_efforts.is_empty());
        assert_eq!(info.context_window.get(), 1_050_000);
    }

    #[test]
    fn custom_meta_user_on_unknown_gets_default_menu() {
        let mut info = ModelInfo::fallback("proxy-mystery-v1");
        apply_custom_model_meta(&mut info, "proxy-mystery-v1", true);
        assert!(info.supports_reasoning_effort);
        assert_eq!(info.reasoning_efforts.len(), 3);
        assert_eq!(info.reasoning_effort, Some(ReasoningEffort::Medium));
    }
}
