//! Project-location routing shared by pager startup and the ACP session boundary.
//!
//! SSH roots are deliberately carried only as project metadata.  They are never
//! converted to a local [`std::path::Path`] or used as the local process cwd.

use agent_client_protocol as acp;
use xai_grok_workspace_types::ssh::ProjectLocation;

/// ACP metadata key carrying the tagged [`ProjectLocation`] wire value.
pub const PROJECT_LOCATION_META_KEY: &str = "x.ai/projectLocation";
/// ACP metadata key carrying the session-scoped SSH authorization binding.
pub const SSH_BINDING_ID_META_KEY: &str = "x.ai/sshBindingId";

/// A pager-to-shell request to open one project on an already-authorized SSH target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshProjectStart {
    target_id: String,
    root: String,
    binding_id: Option<String>,
    session_id: Option<String>,
}

/// Invalid external SSH project-start input.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SshProjectStartError {
    #[error("SSH target id must not be empty")]
    EmptyTarget,
    #[error("SSH project root must not be empty")]
    EmptyRoot,
    #[error("SSH binding id must not be empty when provided")]
    EmptyBinding,
    #[error("SSH session id must not be empty when provided")]
    EmptySession,
}

impl SshProjectStart {
    /// Validate an SSH project request without inspecting the remote path locally.
    pub fn new(
        target_id: impl Into<String>,
        root: impl Into<String>,
        binding_id: Option<String>,
        session_id: Option<String>,
    ) -> Result<Self, SshProjectStartError> {
        let target_id = target_id.into();
        let root = root.into();
        if target_id.trim().is_empty() {
            return Err(SshProjectStartError::EmptyTarget);
        }
        if root.trim().is_empty() {
            return Err(SshProjectStartError::EmptyRoot);
        }
        if binding_id.as_deref().is_some_and(|id| id.trim().is_empty()) {
            return Err(SshProjectStartError::EmptyBinding);
        }
        if session_id.as_deref().is_some_and(|id| id.trim().is_empty()) {
            return Err(SshProjectStartError::EmptySession);
        }
        Ok(Self {
            target_id,
            root,
            binding_id,
            session_id,
        })
    }

    pub fn target_id(&self) -> &str {
        &self.target_id
    }

    pub fn root(&self) -> &str {
        &self.root
    }

    pub fn binding_id(&self) -> Option<&str> {
        self.binding_id.as_deref()
    }

    pub fn requested_session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }

    pub fn project_location(&self) -> ProjectLocation {
        ProjectLocation::Ssh {
            target_id: self.target_id.clone(),
            root: self.root.clone(),
        }
    }

    /// Metadata for the ordinary ACP `session/new` or `session/load` path.
    ///
    /// The caller retains ownership of the actual local launch cwd used by ACP;
    /// this metadata is the sole authority for the remote execution root.
    pub fn session_meta(&self) -> acp::Meta {
        let mut meta = acp::Meta::new();
        meta.insert(
            PROJECT_LOCATION_META_KEY.to_owned(),
            serde_json::to_value(self.project_location())
                .expect("ProjectLocation is always serializable"),
        );
        if let Some(binding_id) = &self.binding_id {
            meta.insert(
                SSH_BINDING_ID_META_KEY.to_owned(),
                serde_json::Value::String(binding_id.clone()),
            );
        }
        if let Some(session_id) = &self.session_id {
            meta.insert(
                "sessionId".to_owned(),
                serde_json::Value::String(session_id.clone()),
            );
        }
        meta
    }

    /// Add the remote project routing to metadata created by normal session UI.
    pub fn merge_session_meta(&self, meta: &mut Option<acp::Meta>) {
        meta.get_or_insert_with(acp::Meta::new)
            .extend(self.session_meta());
    }
}

/// Parse a project location at the ACP boundary.
///
/// Missing metadata is legacy local behavior. Malformed or non-SSH metadata is
/// refused rather than falling through to a local workspace with a remote root.
pub fn ssh_project_location_from_meta(
    meta: Option<&acp::Meta>,
) -> Result<Option<ProjectLocation>, acp::Error> {
    let Some(value) = meta.and_then(|meta| meta.get(PROJECT_LOCATION_META_KEY)) else {
        return Ok(None);
    };
    let location = serde_json::from_value::<ProjectLocation>(value.clone()).map_err(|error| {
        acp::Error::invalid_params().data(format!("invalid {PROJECT_LOCATION_META_KEY}: {error}"))
    })?;
    match &location {
        ProjectLocation::Ssh { target_id, root }
            if !target_id.trim().is_empty() && !root.trim().is_empty() =>
        {
            Ok(Some(location))
        }
        ProjectLocation::Ssh { .. } => Err(acp::Error::invalid_params()
            .data(format!("invalid {PROJECT_LOCATION_META_KEY}: target and root must not be empty"))),
        ProjectLocation::Local { .. } => Err(acp::Error::invalid_params()
            .data(format!("invalid {PROJECT_LOCATION_META_KEY}: SSH project metadata must name an SSH location"))),
    }
}

/// Read the optional pre-authorized binding identifier from session metadata.
pub fn ssh_binding_id_from_meta(meta: Option<&acp::Meta>) -> Result<Option<String>, acp::Error> {
    let Some(value) = meta.and_then(|meta| meta.get(SSH_BINDING_ID_META_KEY)) else {
        return Ok(None);
    };
    let binding_id = value.as_str().ok_or_else(|| {
        acp::Error::invalid_params().data(format!("invalid {SSH_BINDING_ID_META_KEY}: expected a string"))
    })?;
    if binding_id.trim().is_empty() {
        return Err(acp::Error::invalid_params()
            .data(format!("invalid {SSH_BINDING_ID_META_KEY}: must not be empty")));
    }
    Ok(Some(binding_id.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_start_metadata_round_trips_without_rewriting_remote_root() {
        let start = SshProjectStart::new(
            "staging",
            "/srv/groky",
            Some("binding-1".to_owned()),
            Some("session-1".to_owned()),
        )
        .unwrap();

        let meta = start.session_meta();

        assert_eq!(
            ssh_project_location_from_meta(Some(&meta)).unwrap(),
            Some(ProjectLocation::Ssh {
                target_id: "staging".to_owned(),
                root: "/srv/groky".to_owned(),
            })
        );
        assert_eq!(ssh_binding_id_from_meta(Some(&meta)).unwrap().as_deref(), Some("binding-1"));
        assert_eq!(meta.get("sessionId").and_then(serde_json::Value::as_str), Some("session-1"));
    }

    #[test]
    fn ssh_metadata_never_accepts_a_local_project_location() {
        let mut meta = acp::Meta::new();
        meta.insert(
            PROJECT_LOCATION_META_KEY.to_owned(),
            serde_json::json!({"type": "local", "data": {"root": "/srv/groky"}}),
        );

        assert!(ssh_project_location_from_meta(Some(&meta)).is_err());
    }
}
