//! GROK_COMPAT: groky's default `$GROK_HOME` is `~/.groky`.
//!
//! Official `grok` still uses `~/.grok`. On first launch (and every later
//! upgrade) this module fills in anything groky does not have yet:
//!
//! - **Copy** user config and groky-only files (`config.toml`, `vendor-*.json`, …)
//!   so the default model and vendor keys do not fight with official grok.
//!   Existing groky files are never overwritten. A leftover symlink of
//!   `config.toml` onto `~/.grok/config.toml` is replaced with a real copy.
//! - **Symlink** live-shared directories (`sessions`, memory, skills, plugins, …)
//!   onto `~/.grok/…`. Directory links survive atomic file writes inside them.
//! - **Do not symlink** `auth.json`: token refresh does tmp+rename and would
//!   replace the link. The product home instead points `GROK_AUTH_PATH` at
//!   `~/.grok/auth.json` so xAI login stays shared.
//!
//! `$GROK_HOME` pointing anywhere other than the default `~/.groky` skips this
//! (tests, explicit isolation). `GROKY_SKIP_HOME_MIGRATE=1` also skips.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use crate::{PRODUCT_HOME_DIR, home_dir};

/// Marker written into the product home so a later groky can see which layout
/// pass last ran. Missing files are still repaired every process (idempotent).
const LAYOUT_VERSION: &str = "1";
const LAYOUT_MARKER: &str = "groky-layout";

/// Copied once from official grok when groky does not have the file yet.
const COPY_FILES: &[&str] = &[
    "config.toml",
    "pager.toml",
    "sandbox.toml",
    "vendor-auth.json",
    "vendor-providers.json",
    "vendor-catalog.json",
    "models-dev-reasoning.json",
    "mcp_credentials.json",
    "mcp_preferences.json",
    "trusted_folders.toml",
    "trusted-plugins",
    "trusted-hook-projects",
];

/// Always share: create the official dir if needed, then link.
const SHARED_DIRS_ALWAYS: &[&str] = &[
    "sessions",
    "memory-v2",
    "skills",
    "plugins",
    "installed-plugins",
    "hooks",
    "rules",
];

/// Share only when official grok already has the directory (do not create empty
/// official trees just to hold a link).
const SHARED_DIRS_IF_SOURCE: &[&str] = &[
    "marketplace-cache",
    "workflows",
    "long-running-background-tasks",
];

/// Run the product-home migration when `dest` is the default `~/.groky`.
pub(crate) fn ensure_if_product_home(dest: &Path) {
    if skip_migrate() {
        return;
    }
    if !is_product_home(dest) {
        return;
    }
    static ENSURED: OnceLock<()> = OnceLock::new();
    ENSURED.get_or_init(|| {
        let official = official_home();
        if let Err(err) = ensure_layout(dest, &official) {
            tracing::warn!(
                dest = %dest.display(),
                official = %official.display(),
                %err,
                "groky home layout migration failed"
            );
        }
        share_auth_path(&official);
    });
}

fn skip_migrate() -> bool {
    if std::env::var_os("GROKY_SKIP_HOME_MIGRATE").is_some_and(|v| !v.is_empty()) {
        return true;
    }
    // `cargo test` binaries live in `target/**/deps/`. Never rewrite the
    // developer's real ~/.groky as a unit-test side effect.
    looks_like_cargo_test_bin()
}

fn looks_like_cargo_test_bin() -> bool {
    let Ok(exe) = std::env::current_exe() else {
        return false;
    };
    exe.parent()
        .and_then(|p| p.file_name())
        .is_some_and(|name| name == "deps")
}

fn is_product_home(dest: &Path) -> bool {
    let Some(os_home) = home_dir() else {
        return false;
    };
    let product = crate::home_join(&os_home, PRODUCT_HOME_DIR);
    paths_equal(dest, &product)
}

fn official_home() -> PathBuf {
    let os_home = home_dir().unwrap_or_else(|| PathBuf::from("."));
    crate::home_join(&os_home, crate::OFFICIAL_HOME_DIR)
}

fn paths_equal(a: &Path, b: &Path) -> bool {
    if a == b {
        return true;
    }
    match (dunce::canonicalize(a), dunce::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

/// Copy missing files and create missing shared-dir links. Never deletes a
/// real (non-symlink) destination. Idempotent.
pub(crate) fn ensure_layout(product_home: &Path, official_home: &Path) -> io::Result<()> {
    fs::create_dir_all(product_home)?;
    fs::create_dir_all(official_home)?;

    for name in COPY_FILES {
        if let Err(err) = ensure_copied_file(
            &official_home.join(name),
            &product_home.join(name),
            is_secret(name),
        ) {
            tracing::warn!(file = name, %err, "groky layout: copy skipped");
        }
    }

    for name in SHARED_DIRS_ALWAYS {
        if let Err(err) =
            ensure_dir_symlink(&official_home.join(name), &product_home.join(name), true)
        {
            tracing::warn!(dir = name, %err, "groky layout: shared dir skipped");
        }
    }

    for name in SHARED_DIRS_IF_SOURCE {
        if let Err(err) =
            ensure_dir_symlink(&official_home.join(name), &product_home.join(name), false)
        {
            tracing::warn!(dir = name, %err, "groky layout: optional shared dir skipped");
        }
    }

    write_layout_marker(product_home);
    Ok(())
}

fn is_secret(name: &str) -> bool {
    name == "vendor-auth.json" || name == "mcp_credentials.json"
}

fn ensure_copied_file(src: &Path, dest: &Path, secret: bool) -> io::Result<()> {
    if !src.is_file() {
        return Ok(());
    }

    if is_symlink(dest) {
        // Previous layouts (or a hand-made link) would keep config shared.
        // Replace the link with a real copy so groky owns the file.
        let bytes = fs::read(dest).or_else(|_| fs::read(src))?;
        remove_symlink(dest)?;
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(dest, bytes)?;
        if secret {
            tighten_secret(dest);
        }
        tracing::info!(
            dest = %dest.display(),
            "groky layout: replaced shared symlink with a private copy"
        );
        return Ok(());
    }

    if dest.exists() {
        return Ok(());
    }

    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::copy(src, dest)?;
    if secret {
        tighten_secret(dest);
    }
    tracing::info!(dest = %dest.display(), "groky layout: copied from official grok home");
    Ok(())
}

fn ensure_dir_symlink(src: &Path, dest: &Path, create_src: bool) -> io::Result<()> {
    if create_src {
        fs::create_dir_all(src)?;
    } else if !src.is_dir() {
        return Ok(());
    }

    let src_abs = abs_path(src);

    if is_symlink(dest) {
        if symlink_points_at(dest, &src_abs) {
            return Ok(());
        }
        tracing::info!(
            dest = %dest.display(),
            src = %src_abs.display(),
            "groky layout: replacing stale shared-dir symlink"
        );
        remove_symlink(dest)?;
    } else if dest.exists() {
        // Windows junctions often look like real directories. Same inode/path
        // as the official dir means sharing already works.
        if dest.is_dir() && paths_equal(&abs_path(dest), &src_abs) {
            return Ok(());
        }
        tracing::warn!(
            dest = %dest.display(),
            "groky layout: leaving existing path in place (not a symlink)"
        );
        return Ok(());
    }

    symlink_dir(&src_abs, dest)?;
    tracing::info!(
        dest = %dest.display(),
        src = %src_abs.display(),
        "groky layout: linked shared directory"
    );
    Ok(())
}

fn share_auth_path(official_home: &Path) {
    if std::env::var_os("GROK_AUTH_PATH").is_some_and(|v| !v.is_empty()) {
        return;
    }
    if let Err(err) = fs::create_dir_all(official_home) {
        tracing::warn!(
            path = %official_home.display(),
            %err,
            "groky layout: could not create official grok home for shared auth.json"
        );
        return;
    }
    let auth = official_home.join("auth.json");
    // SAFETY: AuthManager reads GROK_AUTH_PATH on each call. This runs once
    // from grok-home init on the product default (~/.groky), never from tests
    // (those set GROK_HOME to a temp dir and skip this function).
    unsafe {
        std::env::set_var("GROK_AUTH_PATH", &auth);
    }
    tracing::info!(
        path = %auth.display(),
        "groky layout: sharing xAI auth.json with official grok"
    );
}

fn write_layout_marker(product_home: &Path) {
    let path = product_home.join(LAYOUT_MARKER);
    if let Err(err) = fs::write(&path, format!("{LAYOUT_VERSION}\n")) {
        tracing::debug!(path = %path.display(), %err, "groky layout: marker write skipped");
    }
}

fn is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
}

fn symlink_points_at(link: &Path, expected: &Path) -> bool {
    let Ok(target) = fs::read_link(link) else {
        return false;
    };
    let resolved = if target.is_absolute() {
        target
    } else {
        match link.parent() {
            Some(parent) => parent.join(target),
            None => target,
        }
    };
    paths_equal(&resolved, expected)
}

fn remove_symlink(path: &Path) -> io::Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.file_type().is_symlink() {
        return Ok(());
    }
    #[cfg(windows)]
    {
        if meta.file_type().is_dir() {
            fs::remove_dir(path)
        } else {
            fs::remove_file(path)
        }
    }
    #[cfg(not(windows))]
    {
        fs::remove_file(path)
    }
}

fn abs_path(path: &Path) -> PathBuf {
    dunce::canonicalize(path).unwrap_or_else(|_| {
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()
                .map(|cwd| cwd.join(path))
                .unwrap_or_else(|_| path.to_path_buf())
        }
    })
}

fn tighten_secret(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

fn symlink_dir(original: &Path, link: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(original, link)
    }
    #[cfg(windows)]
    {
        match std::os::windows::fs::symlink_dir(original, link) {
            Ok(()) => Ok(()),
            Err(err) => {
                let status = std::process::Command::new("cmd")
                    .args(["/C", "mklink", "/J"])
                    .arg(link)
                    .arg(original)
                    .status();
                match status {
                    Ok(s) if s.success() => Ok(()),
                    _ => Err(err),
                }
            }
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (original, link);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "directory symlink is not supported on this platform",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use tempfile::TempDir;

    fn pair() -> (TempDir, PathBuf, PathBuf) {
        let tmp = TempDir::new().unwrap();
        let official = tmp.path().join("official");
        let product = tmp.path().join("product");
        fs::create_dir_all(&official).unwrap();
        fs::create_dir_all(&product).unwrap();
        (tmp, official, product)
    }

    #[test]
    fn copies_config_when_product_has_none() {
        let (_tmp, official, product) = pair();
        fs::write(
            official.join("config.toml"),
            "[models]\ndefault = \"grok-4.6\"\n",
        )
        .unwrap();

        ensure_layout(&product, &official).unwrap();

        assert_eq!(
            fs::read_to_string(product.join("config.toml")).unwrap(),
            "[models]\ndefault = \"grok-4.6\"\n"
        );
        assert_eq!(
            fs::read_to_string(product.join(LAYOUT_MARKER))
                .unwrap()
                .trim(),
            LAYOUT_VERSION
        );
    }

    #[test]
    fn does_not_overwrite_existing_product_config() {
        let (_tmp, official, product) = pair();
        fs::write(official.join("config.toml"), "from = \"grok\"\n").unwrap();
        fs::write(product.join("config.toml"), "from = \"groky\"\n").unwrap();

        ensure_layout(&product, &official).unwrap();

        assert_eq!(
            fs::read_to_string(product.join("config.toml")).unwrap(),
            "from = \"groky\"\n"
        );
    }

    #[test]
    fn copies_vendor_auth_without_removing_official_copy() {
        let (_tmp, official, product) = pair();
        fs::write(official.join("vendor-auth.json"), "{\"providers\":{}}\n").unwrap();

        ensure_layout(&product, &official).unwrap();

        assert_eq!(
            fs::read_to_string(product.join("vendor-auth.json")).unwrap(),
            "{\"providers\":{}}\n"
        );
        assert!(official.join("vendor-auth.json").is_file());
    }

    #[test]
    fn skips_copy_when_official_file_missing() {
        let (_tmp, official, product) = pair();
        ensure_layout(&product, &official).unwrap();
        assert!(!product.join("config.toml").exists());
    }

    #[cfg(unix)]
    #[test]
    fn replaces_config_symlink_with_a_real_copy() {
        let (_tmp, official, product) = pair();
        fs::write(official.join("config.toml"), "shared = true\n").unwrap();
        std::os::unix::fs::symlink(official.join("config.toml"), product.join("config.toml"))
            .unwrap();

        ensure_layout(&product, &official).unwrap();

        assert!(!is_symlink(&product.join("config.toml")));
        assert_eq!(
            fs::read_to_string(product.join("config.toml")).unwrap(),
            "shared = true\n"
        );
        // Official file is untouched so a downgrade of groky still sees it.
        assert_eq!(
            fs::read_to_string(official.join("config.toml")).unwrap(),
            "shared = true\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn links_sessions_and_is_idempotent() {
        let (_tmp, official, product) = pair();
        fs::create_dir_all(official.join("sessions").join("proj")).unwrap();
        fs::write(
            official.join("sessions").join("proj").join("summary.json"),
            "{}",
        )
        .unwrap();

        ensure_layout(&product, &official).unwrap();
        ensure_layout(&product, &official).unwrap();

        let dest = product.join("sessions");
        assert!(is_symlink(&dest));
        assert!(symlink_points_at(
            &dest,
            &abs_path(&official.join("sessions"))
        ));
        assert_eq!(
            fs::read_to_string(dest.join("proj").join("summary.json")).unwrap(),
            "{}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn repairs_broken_sessions_symlink() {
        let (_tmp, official, product) = pair();
        std::os::unix::fs::symlink(official.join("missing-sessions"), product.join("sessions"))
            .unwrap();

        ensure_layout(&product, &official).unwrap();

        let dest = product.join("sessions");
        assert!(is_symlink(&dest));
        assert!(dest.is_dir());
        assert!(symlink_points_at(
            &dest,
            &abs_path(&official.join("sessions"))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn does_not_replace_real_sessions_directory() {
        let (_tmp, official, product) = pair();
        fs::create_dir_all(product.join("sessions")).unwrap();
        fs::write(product.join("sessions").join("keep.txt"), "mine").unwrap();
        fs::create_dir_all(official.join("sessions")).unwrap();

        ensure_layout(&product, &official).unwrap();

        assert!(!is_symlink(&product.join("sessions")));
        assert_eq!(
            fs::read_to_string(product.join("sessions").join("keep.txt")).unwrap(),
            "mine"
        );
    }

    #[cfg(unix)]
    #[test]
    fn optional_shared_dir_only_when_official_has_it() {
        let (_tmp, official, product) = pair();
        ensure_layout(&product, &official).unwrap();
        assert!(!product.join("marketplace-cache").exists());

        fs::create_dir_all(official.join("marketplace-cache")).unwrap();
        ensure_layout(&product, &official).unwrap();
        assert!(is_symlink(&product.join("marketplace-cache")));
    }

    #[cfg(unix)]
    #[test]
    fn second_version_pass_adds_missing_links() {
        let (_tmp, official, product) = pair();
        fs::write(official.join("config.toml"), "ok = true\n").unwrap();
        ensure_layout(&product, &official).unwrap();
        // Simulate an older groky that copied config but had no sessions link.
        let _ = fs::remove_file(product.join("sessions"));
        assert!(!product.join("sessions").exists());

        ensure_layout(&product, &official).unwrap();
        assert!(is_symlink(&product.join("sessions")));
        assert!(product.join("config.toml").is_file());
    }

    #[cfg(unix)]
    #[test]
    fn vendor_auth_copy_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let (_tmp, official, product) = pair();
        fs::write(official.join("vendor-auth.json"), "{}\n").unwrap();
        ensure_layout(&product, &official).unwrap();
        let mode = fs::metadata(product.join("vendor-auth.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
}
