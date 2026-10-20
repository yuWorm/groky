//! Authenticated, workerless remote directory browsing for SSH project selection.

use xai_grok_ssh::{ConnectionLease, SftpConnection};

use super::model::{SshDirectoryEntry, SshDirectoryListing};

const MAX_DIRECTORY_ENTRIES: usize = 512;
const MAX_DIRECTORY_SCAN: usize = MAX_DIRECTORY_ENTRIES * 8;

/// Lists immediate remote directories without creating SSH grant or worker authority.
pub(super) async fn browse(
    lease: &ConnectionLease,
    target_id: String,
    requested_path: Option<&str>,
) -> Result<SshDirectoryListing, String> {
    let sftp = lease.open_sftp().await.map_err(transport_error)?;
    let path = canonical_directory(&sftp, requested_path).await?;
    let parent = parent_directory(&path)?;
    let entries = sftp
        .read_dir(path.clone())
        .await
        .map_err(|error| format!("could not list SSH directory {path:?}: {error}"))?;
    let mut directories = Vec::with_capacity(MAX_DIRECTORY_ENTRIES);
    let mut truncated = false;

    for (index, entry) in entries.enumerate() {
        if index == MAX_DIRECTORY_SCAN {
            truncated = true;
            break;
        }
        let name = entry.file_name();
        validate_entry_name(&name)?;
        let entry_path = entry.path();
        let file_type = entry.file_type();
        let is_directory = if file_type.is_dir() {
            true
        } else if file_type.is_symlink() || file_type.is_other() {
            navigable_directory(&sftp, &entry_path).await?
        } else {
            false
        };
        if !is_directory {
            continue;
        }
        if directories.len() == MAX_DIRECTORY_ENTRIES {
            truncated = true;
            continue;
        }
        directories.push(SshDirectoryEntry {
            name,
            path: entry_path,
        });
    }
    directories.sort_by(|left, right| left.name.cmp(&right.name));

    Ok(SshDirectoryListing {
        target_id,
        identity: lease.identity().clone(),
        path,
        parent,
        directories,
        truncated,
    })
}

async fn canonical_directory(
    sftp: &SftpConnection,
    requested_path: Option<&str>,
) -> Result<String, String> {
    let requested = requested_path.unwrap_or(".");
    reject_nul("SSH directory", requested)?;
    if requested.is_empty() {
        return Err("SSH directory must not be empty".into());
    }
    let expanded = expand_remote_home(sftp, requested).await?;
    let canonical = sftp
        .canonicalize(expanded)
        .await
        .map_err(|error| format!("could not canonicalize SSH directory {requested:?}: {error}"))?;
    ensure_absolute_canonical_path(&canonical)?;
    let metadata = sftp
        .metadata(canonical.clone())
        .await
        .map_err(|error| format!("could not inspect SSH directory {canonical:?}: {error}"))?;
    if !metadata.is_dir() {
        return Err(format!("SSH directory {canonical:?} is not a directory"));
    }
    Ok(canonical)
}

async fn expand_remote_home(sftp: &SftpConnection, requested: &str) -> Result<String, String> {
    if !requested.starts_with('~') {
        return Ok(requested.to_owned());
    }
    match sftp.expand_path(requested.to_owned()).await {
        Ok(Some(expanded)) => Ok(expanded),
        Ok(None) if requested == "~" => Ok(".".into()),
        Ok(None) if requested.starts_with("~/") => {
            let home = sftp
                .canonicalize(".")
                .await
                .map_err(|error| format!("could not resolve SSH home directory: {error}"))?;
            let suffix = requested
                .strip_prefix("~/")
                .expect("the checked remote home path has a suffix");
            Ok(join_remote_path(&home, suffix))
        }
        Ok(None) => Err(format!(
            "SSH server cannot expand remote directory {requested:?}; only the current remote home directory is available"
        )),
        Err(error) => Err(format!(
            "could not expand SSH directory {requested:?}: {error}"
        )),
    }
}

async fn navigable_directory(sftp: &SftpConnection, path: &str) -> Result<bool, String> {
    let canonical = match sftp.canonicalize(path.to_owned()).await {
        Ok(canonical) => canonical,
        Err(_) => return Ok(false),
    };
    let metadata = match sftp.metadata(canonical).await {
        Ok(metadata) => metadata,
        Err(_) => return Ok(false),
    };
    Ok(metadata.is_dir())
}

fn parent_directory(path: &str) -> Result<Option<String>, String> {
    ensure_absolute_canonical_path(path)?;
    if path == "/" {
        return Ok(None);
    }
    let parent = path
        .rsplit_once('/')
        .map(|(parent, _)| if parent.is_empty() { "/" } else { parent })
        .ok_or_else(|| "SSH server returned a non-canonical directory path".to_owned())?;
    Ok(Some(parent.to_owned()))
}

fn join_remote_path(parent: &str, suffix: &str) -> String {
    if parent == "/" {
        format!("/{suffix}")
    } else {
        format!("{parent}/{suffix}")
    }
}

fn ensure_absolute_canonical_path(path: &str) -> Result<(), String> {
    reject_nul("canonical SSH directory", path)?;
    if path == "/"
        || (path.starts_with('/')
            && path
                .split('/')
                .skip(1)
                .all(|component| !component.is_empty() && component != "." && component != ".."))
    {
        Ok(())
    } else {
        Err("SSH server returned a non-canonical directory path".into())
    }
}

fn validate_entry_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') {
        return Err("SSH server returned an invalid directory entry name".into());
    }
    reject_nul("SSH directory entry name", name)
}

fn reject_nul(name: &str, value: &str) -> Result<(), String> {
    if value.contains('\0') {
        Err(format!("{name} must not contain NUL"))
    } else {
        Ok(())
    }
}

fn transport_error(error: impl std::fmt::Display) -> String {
    format!("SSH transport: {error}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_directory_parent_is_keyboard_navigable() {
        assert_eq!(parent_directory("/").unwrap(), None);
        assert_eq!(parent_directory("/remote/project").unwrap(), Some("/remote".into()));
        assert!(parent_directory("relative").is_err());
    }

    #[test]
    fn home_fallback_only_uses_remote_home() {
        assert_eq!(join_remote_path("/home/alice", "projects/demo"), "/home/alice/projects/demo");
        assert_eq!(join_remote_path("/", "projects/demo"), "/projects/demo");
    }
}
