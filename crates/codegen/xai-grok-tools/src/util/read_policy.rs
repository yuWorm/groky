//! Shared read preflight, separate from acquisition and model read tracking.

use std::path::{Path, PathBuf};

use crate::types::resources::{GitignoreFilter, RespectGitignore, SharedResources};

pub async fn resolve_read_path(logical: &Path) -> (PathBuf, Option<String>) {
    match crate::util::fs::try_canonicalize(logical).await {
        Ok(path) => (path, None),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            match crate::util::try_resolve_unicode_filename(logical).await {
                Some(found) => (found.resolved_path, Some(found.note)),
                None => (logical.to_path_buf(), None),
            }
        }
        Err(_) => (logical.to_path_buf(), None),
    }
}

/// Apply memory and opted-in ignored-file policy without recording a model read.
///
/// # Errors
/// Returns the existing memory-policy or ignored-file denial message.
pub async fn validate_read_paths(
    resources: &SharedResources,
    logical: &Path,
    physical: &Path,
    ignored_display: Option<&Path>,
) -> Result<(), String> {
    crate::types::memory_v2::validate_memory_v2_read(resources, logical).await?;
    if physical != logical {
        crate::types::memory_v2::validate_memory_v2_read(resources, physical).await?;
    }
    if let Some(display) = ignored_display {
        let filter = {
            let resources = resources.lock().await;
            if resources
                .get::<RespectGitignore>()
                .is_some_and(|respect| respect.0)
            {
                resources.get::<GitignoreFilter>().cloned()
            } else {
                None
            }
        };
        if let Some(filter) = filter {
            let logical = logical.to_path_buf();
            let physical = physical.to_path_buf();
            let ignored =
                tokio_util::task::AbortOnDropHandle::new(tokio::task::spawn_blocking(move || {
                    filter.is_logical_path_ignored(&logical) || filter.is_ignored(&physical)
                }))
                .await
                .map_err(|_| "Read policy worker failed".to_owned())?;
            if ignored {
                return Err(format!(
                    "Error: {} is ignored by .gitignore and cannot be read.",
                    display.display()
                ));
            }
        }
    }
    Ok(())
}
