//! Groky release notes bundled in the binary.
//!
//! Official grok fetches `{version}.external.md` from `x.ai/cli/changelogs`.
//! That CDN is the other product, so groky serves these files instead.
//! Welcome bullets, `/release-notes`, and the once-per-version prompt all
//! read [`fetch`].

use std::path::{Path, PathBuf};

use crate::util::changelog::{Changelog, ChangelogEntry};

const BUNDLED_MD: &str = include_str!("changelogs/CHANGELOG.md");
const BUNDLED_JSON: &str = include_str!("changelogs/CHANGELOG.json");
const SEEN_FILE: &str = ".changelog_seen_version";

/// Markdown + JSON for the Welcome Changelog block and `/release-notes`.
pub fn fetch() -> Changelog {
    let markdown = (!BUNDLED_MD.trim().is_empty()).then(|| BUNDLED_MD.to_string());
    let entries = serde_json::from_str::<Vec<ChangelogEntry>>(BUNDLED_JSON)
        .map_err(|e| {
            tracing::debug!(error = %e, "bundled changelog JSON failed to parse");
            e
        })
        .ok();
    Changelog { markdown, entries }
}

/// Version key for the once-per-upgrade prompt: groky product version when
/// stamped, otherwise the compiled grok `VERSION`.
pub fn prompt_version() -> String {
    super::product_version()
        .unwrap_or(xai_grok_version::VERSION)
        .to_string()
}

/// True when this install has not yet shown Release Notes for [`prompt_version`].
/// PTY / integration tests set `GROK_CHANGELOG_OFFLINE` and must not auto-open.
pub fn is_unseen() -> bool {
    is_unseen_in(&grok_home(), &prompt_version(), changelog_offline())
}

pub fn is_unseen_in(home: &Path, current: &str, offline: bool) -> bool {
    if offline || current.trim().is_empty() {
        return false;
    }
    read_seen_in(home).as_deref() != Some(current.trim())
}

pub fn mark_prompted(version: &str) {
    mark_prompted_in(&grok_home(), version);
}

pub fn mark_prompted_in(home: &Path, version: &str) {
    let version = version.trim();
    if version.is_empty() {
        return;
    }
    let _ = std::fs::create_dir_all(home);
    if let Err(e) = std::fs::write(home.join(SEEN_FILE), version) {
        tracing::debug!(error = %e, "changelog seen-version write failed");
    }
}

fn grok_home() -> PathBuf {
    crate::util::grok_home::grok_home()
}

fn read_seen_in(home: &Path) -> Option<String> {
    std::fs::read_to_string(home.join(SEEN_FILE))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn changelog_offline() -> bool {
    std::env::var_os("GROK_CHANGELOG_OFFLINE").is_some_and(|v| !v.is_empty() && v != "0")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_fetch_has_markdown_and_entries() {
        let changelog = fetch();
        let md = changelog.markdown.expect("bundled markdown");
        assert!(
            md.contains("0.1.17"),
            "bundled notes must include the latest shipped groky version, got {md}"
        );
        let entries = changelog.entries.expect("bundled json entries");
        assert!(
            !entries.is_empty(),
            "bundled JSON must have at least one welcome bullet"
        );
        assert!(
            entries.iter().all(|e| !e.description.is_empty()),
            "bundled entries must have descriptions"
        );
    }

    #[test]
    fn unseen_when_no_seen_file() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(is_unseen_in(tmp.path(), "0.1.18", false));
    }

    #[test]
    fn seen_matching_version_is_not_unseen() {
        let tmp = tempfile::tempdir().unwrap();
        mark_prompted_in(tmp.path(), "0.1.18");
        assert!(!is_unseen_in(tmp.path(), "0.1.18", false));
    }

    #[test]
    fn version_bump_is_unseen_again() {
        let tmp = tempfile::tempdir().unwrap();
        mark_prompted_in(tmp.path(), "0.1.17");
        assert!(is_unseen_in(tmp.path(), "0.1.18", false));
    }

    #[test]
    fn offline_never_unseen() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(!is_unseen_in(tmp.path(), "0.1.18", true));
    }

    #[test]
    fn empty_version_is_not_unseen() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(!is_unseen_in(tmp.path(), "  ", false));
    }
}
