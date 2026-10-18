//! Stable local storage identities for projects that execute on another host.
//!
//! An SSH root is a path on the remote host, so it must never become a local
//! working directory.  SSH session data instead lives in an opaque bucket
//! keyed by both the configured target and the remote root.

use std::path::Path;

use agent_client_protocol as acp;
use xai_grok_workspace_types::ssh::ProjectLocation;

use super::Info;

const SSH_STORAGE_PREFIX: &str = "ssh-v1-";

/// Return the local storage key for a project location.
///
/// Local projects intentionally retain their historical cwd key. SSH keys are
/// opaque and include both the target and root, preventing equal remote paths
/// on distinct hosts from sharing histories or permission state.
pub fn storage_cwd(location: &ProjectLocation) -> String {
    match location {
        ProjectLocation::Local { root } => root.clone(),
        ProjectLocation::Ssh { target_id, root } => {
            let mut hash = blake3::Hasher::new();
            hash.update(b"groky-session-storage/ssh-v1\0");
            hash.update(&(target_id.len() as u64).to_le_bytes());
            hash.update(target_id.as_bytes());
            hash.update(&(root.len() as u64).to_le_bytes());
            hash.update(root.as_bytes());
            format!("{SSH_STORAGE_PREFIX}{}", hash.finalize().to_hex())
        }
    }
}

/// Build the storage identity for a session at `location`.
pub fn info_for_location(id: acp::SessionId, location: &ProjectLocation) -> Info {
    Info {
        id,
        cwd: storage_cwd(location),
    }
}

/// True only for the opaque local keys assigned to SSH project histories.
///
/// Callers use this boundary to avoid applying local filesystem behavior (git
/// discovery, worktree management, `set_current_dir`, and similar) to a remote
/// project merely because it has local persistence.
pub fn is_ssh_storage_cwd(cwd: &str) -> bool {
    cwd.strip_prefix(SSH_STORAGE_PREFIX).is_some_and(|digest| {
        digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

/// Decode a local history bucket without mistaking an SSH storage identity for
/// a filesystem working directory.
pub fn storage_cwd_from_dirname(dir: &Path) -> Option<String> {
    if let Some(key) = dir.file_name().and_then(|name| name.to_str())
        && is_ssh_storage_cwd(key)
    {
        return Some(key.to_owned());
    }
    xai_grok_config::decode_cwd_from_dirname(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_storage_keys_isolate_target_and_do_not_expose_remote_root() {
        let first = ProjectLocation::Ssh {
            target_id: "production".to_owned(),
            root: "/srv/app".to_owned(),
        };
        let same_root_other_target = ProjectLocation::Ssh {
            target_id: "staging".to_owned(),
            root: "/srv/app".to_owned(),
        };

        let first_key = storage_cwd(&first);
        let second_key = storage_cwd(&same_root_other_target);

        assert!(is_ssh_storage_cwd(&first_key));
        assert_ne!(first_key, second_key);
        assert!(!first_key.contains("/srv/app"));
    }

    #[test]
    fn local_storage_key_remains_legacy_cwd() {
        let location = ProjectLocation::Local {
            root: "/Users/me/project".to_owned(),
        };

        assert_eq!(storage_cwd(&location), "/Users/me/project");
    }
}
