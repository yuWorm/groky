//! Groky GitHub-release updater. Reuses the pager's check / Welcome / ctrl+u
//! / `update` command flow; does not call x.ai/cli.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const DEFAULT_REPO: &str = "yuWorm/groky";
const TTL: Duration = Duration::from_secs(30 * 60);
const INSTALL_HINT: &str = "curl -fsSL https://raw.githubusercontent.com/yuWorm/groky/main/scripts/install-groky.sh | bash";

static PRODUCT_VERSION: OnceLock<&'static str> = OnceLock::new();

#[derive(Debug, thiserror::Error)]
pub enum SelfUpdateError {
    #[error("{0}")]
    Message(String),
    #[error(transparent)]
    Io(#[from] io::Error),
}

#[derive(Debug, Clone)]
pub struct UpdateStatus {
    pub current_version: String,
    pub latest_version: String,
    pub update_available: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct CacheFile {
    #[serde(default)]
    latest: String,
    #[serde(default)]
    checked_at: u64,
}

#[derive(Debug, Deserialize)]
struct GithubRelease {
    tag_name: String,
}

/// Injected once from the binary (`GROKY_VERSION`). Empty / unset = dev build.
pub fn set_product_version(v: &'static str) {
    let _ = PRODUCT_VERSION.set(v);
}

pub fn product_version() -> Option<&'static str> {
    PRODUCT_VERSION
        .get()
        .copied()
        .map(str::trim)
        .filter(|v| !v.is_empty())
}

pub fn is_release_build() -> bool {
    product_version().is_some_and(is_release_version)
}

pub(crate) fn is_release_version(v: &str) -> bool {
    semver::Version::parse(v.trim()).is_ok_and(|ver| ver.pre.is_empty())
}

pub fn updates_allowed() -> bool {
    if !is_release_build() {
        return false;
    }
    if env_flag("GROKY_DISABLE_AUTOUPDATER") || env_flag("GROK_DISABLE_AUTOUPDATER") {
        return false;
    }
    true
}

pub(crate) fn groky_home() -> PathBuf {
    xai_dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".groky")
}

pub(crate) fn managed_bin() -> PathBuf {
    let name = if cfg!(windows) { "groky.exe" } else { "groky" };
    groky_home().join("bin").join(name)
}

pub fn is_managed_install() -> bool {
    let Ok(exe) = std::env::current_exe() else {
        return false;
    };
    let managed = managed_bin();
    match (dunce::canonicalize(&exe), dunce::canonicalize(&managed)) {
        (Ok(exe), Ok(managed)) => exe == managed,
        _ => false,
    }
}

pub(crate) fn repo() -> String {
    std::env::var("GROKY_REPO")
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_REPO.to_owned())
}

pub(crate) fn platform_asset(version: &str) -> Result<String, SelfUpdateError> {
    let (os, arch) = detect_platform()?;
    let mut name = format!("groky-{version}-{os}-{arch}");
    if os == "windows" {
        name.push_str(".exe");
    }
    Ok(name)
}

pub(crate) fn needs_update(current: &str, latest: &str) -> bool {
    match (
        semver::Version::parse(current.trim()),
        semver::Version::parse(latest.trim()),
    ) {
        (Ok(c), Ok(l)) => l > c,
        _ => false,
    }
}

pub async fn check_status() -> Result<UpdateStatus, SelfUpdateError> {
    let current = product_version()
        .map(str::to_owned)
        .ok_or_else(|| SelfUpdateError::Message("GROKY_VERSION is not set (dev build)".into()))?;
    let latest = match cached_latest_if_fresh() {
        Some(latest) => latest,
        None => {
            let latest = fetch_latest().await?;
            write_cache(&latest);
            latest
        }
    };
    Ok(UpdateStatus {
        update_available: needs_update(&current, &latest),
        current_version: current,
        latest_version: latest,
    })
}

/// Background TUI check. Spawns `groky update --trigger=auto` when the
/// running binary is the managed install and auto-update is on.
pub async fn check_background() -> BackgroundCheck {
    if auto_update_disabled().await {
        return BackgroundCheck::none();
    }
    let Ok(status) = check_status().await else {
        return BackgroundCheck::none();
    };
    if !status.update_available {
        return BackgroundCheck::none();
    }
    let download = if is_managed_install() {
        spawn_update_child().ok()
    } else {
        None
    };
    BackgroundCheck {
        latest_version: Some(status.latest_version),
        download,
    }
}

pub struct BackgroundCheck {
    pub latest_version: Option<String>,
    pub download: Option<tokio::process::Child>,
}

impl BackgroundCheck {
    fn none() -> Self {
        Self {
            latest_version: None,
            download: None,
        }
    }
}

pub async fn install(target: Option<&str>, force: bool) -> Result<Option<String>, SelfUpdateError> {
    let latest = match target {
        Some(v) => v.trim().trim_start_matches('v').to_owned(),
        None => fetch_latest().await?,
    };
    if let Some(current) = product_version()
        && !force
        && !needs_update(current, &latest)
    {
        eprintln!("Already up to date (groky {current}).");
        write_cache(&current);
        return Ok(None);
    }

    let asset = platform_asset(&latest)?;
    // Asset names are deterministic (`groky-{ver}-{os}-{arch}`). Skip
    // `/releases/tags` so a pinned `groky update --version` does not spend
    // the unauthenticated GitHub API quota (shared VPN IPs in CN burn it).
    let url = tagged_download_url(&latest, &asset);
    let sha_url = tagged_download_url(&latest, &format!("{asset}.sha256"));

    let dest = managed_bin();
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }
    let downloads = groky_home().join("downloads");
    fs::create_dir_all(&downloads)?;
    let tmp = downloads.join(format!("{asset}.tmp"));

    eprintln!("  Downloading groky v{latest} ({asset})...");
    download_file(&url, &tmp).await?;
    // HTTP download does not keep the Release asset's +x; chmod before exec.
    chmod_unix_exec(&tmp)?;
    if let Some(expected) = download_text(&sha_url)
        .await
        .ok()
        .and_then(|s| parse_sha256(&s))
    {
        let actual = sha256_file(&tmp)?;
        if actual != expected {
            let _ = fs::remove_file(&tmp);
            return Err(SelfUpdateError::Message(format!(
                "sha256 mismatch for {asset} (got {actual}, expected {expected})"
            )));
        }
    }
    smoke_test(&tmp)?;
    if dest.exists() {
        let old = dest.with_extension("old");
        let _ = fs::remove_file(&old);
        fs::rename(&dest, &old)?;
        if let Err(e) = fs::rename(&tmp, &dest) {
            let _ = fs::rename(&old, &dest);
            return Err(e.into());
        }
        let _ = fs::remove_file(&old);
    } else if let Err(e) = fs::rename(&tmp, &dest) {
        return Err(e.into());
    }
    let _ = chmod_unix_exec(&dest);
    write_cache(&latest);
    eprintln!("  Installed {}", dest.display());
    Ok(Some(latest))
}

pub async fn ensure_latest_on_disk() -> Result<(Option<String>, bool), SelfUpdateError> {
    if auto_update_disabled().await {
        return Ok((None, false));
    }
    let status = check_status().await?;
    if !status.update_available {
        return Ok((None, false));
    }
    if !is_managed_install() {
        return Ok((None, false));
    }
    let installed = install(Some(&status.latest_version), false).await?;
    Ok((installed, true))
}

pub(crate) fn spawn_update_child() -> io::Result<tokio::process::Child> {
    let exe = std::env::current_exe()?;
    let mut cmd = tokio::process::Command::new(exe);
    cmd.arg("update")
        .arg("--trigger=auto_background")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    xai_tty_utils::detach_command(&mut cmd);
    #[allow(clippy::disallowed_methods)]
    cmd.spawn()
}

pub fn install_hint() -> &'static str {
    INSTALL_HINT
}

async fn auto_update_disabled() -> bool {
    let cfg = crate::util::config::load_config().await;
    cfg.cli.auto_update == Some(false)
}

fn env_flag(name: &str) -> bool {
    std::env::var_os(name).is_some_and(|v| {
        let s = v.to_string_lossy();
        let t = s.trim();
        t == "1" || t.eq_ignore_ascii_case("true") || t.eq_ignore_ascii_case("yes")
    })
}

fn detect_platform() -> Result<(&'static str, &'static str), SelfUpdateError> {
    let os = match std::env::consts::OS {
        "macos" => "macos",
        "linux" => "linux",
        "windows" => "windows",
        other => {
            return Err(SelfUpdateError::Message(format!(
                "unsupported OS for groky updates: {other}"
            )));
        }
    };
    let arch = match std::env::consts::ARCH {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64",
        other => {
            return Err(SelfUpdateError::Message(format!(
                "unsupported architecture for groky updates: {other}"
            )));
        }
    };
    Ok((os, arch))
}

fn cache_path() -> PathBuf {
    groky_home().join("update-cache.json")
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn cached_latest_if_fresh() -> Option<String> {
    let raw = fs::read_to_string(cache_path()).ok()?;
    let cache: CacheFile = serde_json::from_str(&raw).ok()?;
    if cache.latest.trim().is_empty() {
        return None;
    }
    let age = now_secs().saturating_sub(cache.checked_at);
    (age < TTL.as_secs()).then_some(cache.latest)
}

fn write_cache(latest: &str) {
    let cache = CacheFile {
        latest: latest.to_owned(),
        checked_at: now_secs(),
    };
    let path = cache_path();
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(json) = serde_json::to_string_pretty(&cache) {
        let tmp = path.with_extension("json.tmp");
        if fs::write(&tmp, json).is_ok() {
            let _ = fs::rename(&tmp, &path);
        }
    }
}

fn github_client() -> Result<reqwest::Client, SelfUpdateError> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent(format!("groky/{}", product_version().unwrap_or("dev")))
        .build()
        .map_err(|e| SelfUpdateError::Message(e.to_string()))
}

fn auth_header() -> Option<String> {
    std::env::var("GROKY_GITHUB_TOKEN")
        .ok()
        .or_else(|| std::env::var("GITHUB_TOKEN").ok())
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}

async fn github_get(url: &str) -> Result<reqwest::Response, SelfUpdateError> {
    let client = github_client()?;
    let mut req = client
        .get(url)
        .header("Accept", "application/vnd.github+json");
    if let Some(token) = auth_header() {
        req = req.bearer_auth(token);
    }
    req.send()
        .await
        .map_err(|e| SelfUpdateError::Message(e.to_string()))
}

async fn fetch_latest() -> Result<String, SelfUpdateError> {
    let url = format!("https://api.github.com/repos/{}/releases/latest", repo());
    let resp = github_get(&url).await?;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(SelfUpdateError::Message(format!(
            "GitHub latest release {status}: {}",
            body.chars().take(180).collect::<String>()
        )));
    }
    let release: GithubRelease = serde_json::from_str(&body)
        .map_err(|e| SelfUpdateError::Message(format!("GitHub latest JSON: {e}")))?;
    Ok(parse_tag(&release.tag_name))
}

fn parse_tag(tag: &str) -> String {
    tag.trim().trim_start_matches('v').to_owned()
}

pub(crate) fn release_download_url(repo: &str, tag: &str, asset: &str) -> String {
    format!("https://github.com/{repo}/releases/download/{tag}/{asset}")
}

fn tagged_download_url(version: &str, asset: &str) -> String {
    let tag = format!("v{}", version.trim().trim_start_matches('v'));
    release_download_url(&repo(), &tag, asset)
}

async fn download_file(url: &str, dest: &Path) -> Result<(), SelfUpdateError> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .user_agent(format!("groky/{}", product_version().unwrap_or("dev")))
        .build()
        .map_err(|e| SelfUpdateError::Message(e.to_string()))?;
    let mut req = client.get(url);
    if let Some(token) = auth_header() {
        req = req.bearer_auth(token);
    }
    let resp = req
        .send()
        .await
        .map_err(|e| SelfUpdateError::Message(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(SelfUpdateError::Message(format!(
            "download failed: {} from {url}",
            resp.status()
        )));
    }
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| SelfUpdateError::Message(e.to_string()))?;
    let mut file = fs::File::create(dest)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

async fn download_text(url: &str) -> Result<String, SelfUpdateError> {
    let tmp = groky_home().join("downloads").join(".sha256.tmp");
    if let Some(parent) = tmp.parent() {
        fs::create_dir_all(parent)?;
    }
    download_file(url, &tmp).await?;
    let text = fs::read_to_string(&tmp)?;
    let _ = fs::remove_file(&tmp);
    Ok(text)
}

pub(crate) fn parse_sha256(text: &str) -> Option<String> {
    let token = text.split_whitespace().next()?.trim().to_ascii_lowercase();
    (token.len() == 64 && token.chars().all(|c| c.is_ascii_hexdigit())).then_some(token)
}

fn sha256_file(path: &Path) -> Result<String, SelfUpdateError> {
    let data = fs::read(path)?;
    let digest = Sha256::digest(&data);
    Ok(digest.iter().map(|b| format!("{b:02x}")).collect())
}

fn chmod_unix_exec(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

fn smoke_test(path: &Path) -> Result<(), SelfUpdateError> {
    let out = std::process::Command::new(path)
        .arg("--version")
        .stdin(std::process::Stdio::null())
        .output();
    match out {
        Ok(out) if out.status.success() => Ok(()),
        Ok(out) => Err(SelfUpdateError::Message(format!(
            "downloaded groky failed --version ({})",
            out.status
        ))),
        Err(e) => Err(SelfUpdateError::Message(format!(
            "couldn't exec downloaded groky: {e}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_version_rejects_git_describe() {
        assert!(is_release_version("0.1.5"));
        assert!(!is_release_version("0.1.5-3-gabc"));
        assert!(!is_release_version(""));
        assert!(!is_release_version("1.0.10 (deadbeef)"));
    }

    #[test]
    fn semver_only_upgrades() {
        assert!(needs_update("0.1.4", "0.1.5"));
        assert!(!needs_update("0.1.5", "0.1.5"));
        assert!(!needs_update("0.1.5", "0.1.4"));
        assert!(!needs_update("1.0.10", "0.1.5"));
    }

    #[test]
    fn parse_tag_strips_v() {
        assert_eq!(parse_tag("v0.1.5"), "0.1.5");
        assert_eq!(parse_tag("0.1.5"), "0.1.5");
    }

    #[cfg(unix)]
    #[test]
    fn smoke_test_requires_execute_bit() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("groky-tmp");
        fs::write(&path, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let err = smoke_test(&path).unwrap_err().to_string();
        assert!(
            err.contains("couldn't exec") || err.contains("Permission denied"),
            "{err}"
        );
        chmod_unix_exec(&path).unwrap();
        smoke_test(&path).expect("chmod +x must happen before --version smoke");
    }

    #[test]
    fn sha256_line() {
        let hash = "a".repeat(64);
        assert_eq!(
            parse_sha256(&format!("{hash}  groky-0.1.5-macos-aarch64")),
            Some(hash.clone())
        );
        assert!(parse_sha256("short").is_none());
    }

    #[test]
    fn github_json_reads_latest_tag() {
        let release: GithubRelease = serde_json::from_str(r#"{"tag_name": "v0.1.5"}"#).unwrap();
        assert_eq!(parse_tag(&release.tag_name), "0.1.5");
    }

    #[test]
    fn pinned_version_uses_releases_download_not_api() {
        let url = release_download_url(
            "yuWorm/groky",
            "v0.1.15",
            "groky-0.1.15-macos-aarch64",
        );
        assert_eq!(
            url,
            "https://github.com/yuWorm/groky/releases/download/v0.1.15/groky-0.1.15-macos-aarch64"
        );
        assert!(
            !url.contains("api.github.com"),
            "pinned downloads must not use the rate-limited GitHub API: {url}"
        );
    }

    #[test]
    fn tagged_download_url_accepts_v_prefix() {
        let asset = "groky-0.1.15-linux-x86_64";
        assert_eq!(
            tagged_download_url("0.1.15", asset),
            tagged_download_url("v0.1.15", asset)
        );
        assert!(tagged_download_url("0.1.15", asset).contains("/v0.1.15/"));
    }
}
