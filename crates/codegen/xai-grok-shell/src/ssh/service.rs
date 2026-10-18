use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Weak};
use std::time::Duration;

use async_trait::async_trait;
use thiserror::Error;
use zeroize::Zeroize;

use tokio::sync::{Mutex, RwLock, broadcast, oneshot};
use uuid::Uuid;
use xai_grok_ssh::{
    ConnectionLease, ConnectionManager, ConnectionPhase, HostKeyDecision, HostKeyPrompt,
    Interaction, InteractionError, KeyboardInteractivePrompt, Secret, SecretKind, SecretPrompt,
    SshError, TargetStore,
};
use xai_grok_tools::types::output::{ToolOutput, ToolRunResult};
use xai_grok_workspace_client::ssh::{SshClientCallbacks, SshClientError, SshWorkspaceClient};
use xai_grok_workspace_types::ssh::{
    ProjectLocation, ResolvedSshInvocation, SshBinding, SshCapabilities, SshHostIdentity,
    SshOperation,
};
use xai_grok_workspace_types::ssh_wire::{
    SshApprovalDecision, SshApprovalRequest, SshCancellation, SshOperationRecord,
    SshPostToolHookOutcome, SshTaskRecord, SshWorkerEvent,
};

use super::control::{SshControlCommand, SshControlReply};
use super::model::{
    PersistedSshGrant, PersistedSshState, ProjectSshBinding, RevokeStatus, SshAuthPrompt,
    SshAuthPromptDetail, SshAuthPromptKind, SshAuthResponse, SshConnectionState,
    SshDispatchRequest, SshDispatchResult, SshEvent, SshGrantDecision, SshGrantRequest,
    SshGrantScope, SshGrantStatus, SshHostKeyDecision, SshKeyboardInteractiveQuestion,
    SshOperationApproval, SshOperationApprovalDecision, SshSessionWorkerEvent, SshTargetAccess,
    SshTargetStatus,
};

const INTERACTION_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Debug, Error)]
pub enum SshServiceError {
    #[error("SSH target access requires a human grant")]
    GrantRequired,
    #[error("SSH grant request {0} was not found")]
    UnknownGrantRequest(String),
    #[error("SSH grant decision came from a different local client")]
    WrongClient,
    #[error("SSH request is already resolved")]
    RequestResolved,
    #[error("SSH target must be selected by a local user")]
    TargetSelectionRequired,
    #[error("SSH root must be selected by a local user")]
    RootSelectionRequired,
    #[error("SSH grant decision expands the requested target, root, or capabilities")]
    GrantExpansion,
    #[error("SSH binding {0} was not found")]
    UnknownBinding(String),
    #[error("SSH binding {0} is revoked")]
    RevokedBinding(String),
    #[error("SSH target {0} has multiple grants; select a binding")]
    AmbiguousTarget(String),
    #[error("no SSH default is selected for this session")]
    NoDefaultBinding,
    #[error("SSH operation is outside the grant capability ceiling")]
    CapabilityDenied,
    #[error("SSH invocation epoch is no longer valid")]
    StaleInvocation,
    #[error("SSH remote path escapes the granted root")]
    RootEscape,
    #[error("SSH host identity changed since the grant was approved")]
    IdentityChanged,
    #[error("SSH worker canonical root changed since the grant was approved")]
    CanonicalRootChanged,
    #[error("SSH authentication response is stale or belongs to another client")]
    StaleAuthentication,
    #[error("SSH operation approval is stale or belongs to another client")]
    StaleOperationApproval,
    #[error("SSH transport: {0}")]
    Transport(String),
    #[error("SSH worker: {0}")]
    Worker(String),
    #[error("SSH worker: {message}")]
    WorkerHook {
        message: String,
        outcome: SshPostToolHookOutcome,
    },
    #[error("SSH operation belongs to a different binding or session")]
    OperationNotOwned,
    #[error("SSH configuration: {0}")]
    Configuration(String),
    #[error("a project-scoped SSH grant requires the session's originating project location")]
    ProjectLocationRequired,
    #[error("SSH project rule storage: {0}")]
    ProjectRuleStorage(String),
}

impl From<SshError> for SshServiceError {
    fn from(value: SshError) -> Self {
        match value {
            SshError::Interaction(InteractionError::Unavailable) => Self::Transport(
                "SSH authentication requires interaction; open /ssh (Welcome: Ctrl+S) to sign in or trust the host, or configure a usable key/agent".into(),
            ),
            error => Self::Transport(error.to_string()),
        }
    }
}

impl From<SshClientError> for SshServiceError {
    fn from(value: SshClientError) -> Self {
        match value {
            SshClientError::Remote(error) => {
                let message = format!("{}: {}", error.code, error.message);
                match error.post_hook {
                    Some(outcome) => Self::WorkerHook { message, outcome },
                    None => Self::Worker(message),
                }
            }
            error => Self::Worker(error.to_string()),
        }
    }
}

#[derive(Clone)]
pub struct SessionSsh {
    inner: Arc<SessionSshInner>,
}

impl std::fmt::Debug for SessionSsh {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("SessionSsh").finish_non_exhaustive()
    }
}

struct SessionSshInner {
    home: PathBuf,
    targets: TargetStore,
    connections: ConnectionManager,
    sessions: RwLock<HashMap<String, SessionState>>,
    resolution_claims: std::sync::Mutex<HashSet<String>>,
    workers: Mutex<HashMap<String, Arc<WorkerConnection>>>,
    worker_locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
    manual_holds: Mutex<HashMap<String, ConnectionLease>>,
    auth_waiters: Mutex<HashMap<String, PendingAuthentication>>,
    session_event_sinks: Mutex<HashMap<String, broadcast::Sender<SshSessionWorkerEvent>>>,
    approval_waiters: Mutex<HashMap<String, PendingOperationApproval>>,
    project_registrations: RwLock<HashMap<String, ProjectRegistration>>,
    project_rules_path: PathBuf,
    project_rules: Mutex<ProjectRuleStore>,
    events: broadcast::Sender<SshEvent>,
}

#[derive(Clone, Default)]
struct SessionState {
    grants: HashMap<String, GrantRecord>,
    default_binding_id: Option<String>,
    pending_requests: HashMap<String, SshGrantRequest>,
}

impl SessionState {
    fn persisted(&self) -> PersistedSshState {
        let mut grants = self
            .grants
            .values()
            .map(|record| record.persisted.clone())
            .collect::<Vec<_>>();
        grants.sort_by(|left, right| left.binding.id.cmp(&right.binding.id));
        let mut pending_requests = self.pending_requests.values().cloned().collect::<Vec<_>>();
        pending_requests.sort_by(|left, right| left.id.cmp(&right.id));
        PersistedSshState {
            grants,
            default_binding_id: self.default_binding_id.clone(),
            pending_requests,
        }
    }
}

#[derive(Clone)]
struct GrantRecord {
    persisted: PersistedSshGrant,
}

struct WorkerConnection {
    binding: SshBinding,
    client: SshWorkspaceClient,
    client_id: Option<u64>,
    // The lease, rather than the worker channel, owns the shared native connection lifetime.
    _lease: ConnectionLease,
}

struct PendingAuthentication {
    client_id: u64,
    connection_generation: u64,
    response: oneshot::Sender<SshAuthResponse>,
}

struct PendingOperationApproval {
    client_id: u64,
    response: oneshot::Sender<bool>,
}
#[derive(Clone)]
struct ProjectRegistration {
    location: ProjectLocation,
    session_info: Option<crate::session::info::Info>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct ProjectSshRule {
    owner_location: ProjectLocation,
    /// A pre-open SSH project is registered with the user's path spelling.
    /// Retain its verified location too, so resume and revoke use the same rule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    canonical_owner_location: Option<ProjectLocation>,
    target_id: String,
    root: String,
    cwd: String,
    identity: SshHostIdentity,
    capabilities: SshCapabilities,
    make_default: bool,
}

impl ProjectSshRule {
    fn owns(&self, location: &ProjectLocation) -> bool {
        self.owner_location == *location
            || self.canonical_owner_location.as_ref() == Some(location)
    }
}

#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
struct ProjectRuleFile {
    version: u32,
    rules: Vec<ProjectSshRule>,
}

enum ProjectRuleStore {
    Loaded(ProjectRuleFile),
    Invalid(String),
}

struct GrantResolutionClaim<'a> {
    claims: &'a std::sync::Mutex<HashSet<String>>,
    request_id: &'a str,
}

impl Drop for GrantResolutionClaim<'_> {
    fn drop(&mut self) {
        self.claims
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(self.request_id);
    }
}

/// Resource inserted into each SSH-capable tool registry. A resource is scoped
/// to one session, so a shared native connection cannot accidentally share an
/// authorization grant with another session.
#[derive(Clone)]
pub struct SessionSshResource {
    pub service: Arc<SessionSsh>,
    pub session_id: String,
    pub client_id: Option<u64>,
}

impl SessionSsh {
    pub fn new(home: PathBuf) -> Self {
        let (events, _) = broadcast::channel(128);
        let project_rules_path = home.join("ssh-project-rules.json");
        let project_rules = load_project_rules(&project_rules_path);
        Self {
            inner: Arc::new(SessionSshInner {
                targets: TargetStore::new(home.clone()),
                connections: ConnectionManager::new(home.clone()),
                home,
                sessions: RwLock::new(HashMap::new()),
                resolution_claims: std::sync::Mutex::new(HashSet::new()),
                workers: Mutex::new(HashMap::new()),
                worker_locks: Mutex::new(HashMap::new()),
                manual_holds: Mutex::new(HashMap::new()),
                auth_waiters: Mutex::new(HashMap::new()),
                session_event_sinks: Mutex::new(HashMap::new()),
                approval_waiters: Mutex::new(HashMap::new()),
                project_registrations: RwLock::new(HashMap::new()),
                project_rules_path,
                project_rules: Mutex::new(project_rules),
                events,
            }),
        }
    }

    pub fn home(&self) -> &std::path::Path {
        &self.inner.home
    }

    pub fn subscribe_events(&self) -> broadcast::Receiver<SshEvent> {
        self.inner.events.subscribe()
    }

    /// Subscribe to worker-originated progress and operation updates for one
    /// session. This sink is independent of SSH manager/control visibility.
    pub async fn subscribe_session_events(
        &self,
        session_id: impl Into<String>,
    ) -> broadcast::Receiver<SshSessionWorkerEvent> {
        let session_id = session_id.into();
        let sender = {
            let mut sinks = self.inner.session_event_sinks.lock().await;
            sinks
                .entry(session_id)
                .or_insert_with(|| broadcast::channel(128).0)
                .clone()
        };
        sender.subscribe()
    }
    /// Registers the exact location that owns this session. The location is
    /// never inferred from a host, cwd, or repository configuration.
    pub async fn register_project_location(
        &self,
        session_id: &str,
        session_info: Option<crate::session::info::Info>,
        location: &ProjectLocation,
    ) -> Result<(), SshServiceError> {
        let mut registrations = self.inner.project_registrations.write().await;
        let session_info = session_info.or_else(|| {
            registrations
                .get(session_id)
                .and_then(|registration| registration.session_info.clone())
        });
        registrations.insert(
            session_id.to_owned(),
            ProjectRegistration {
                location: location.clone(),
                session_info,
            },
        );
        Ok(())
    }

    /// Recreates saved grants only for their exact originating local or SSH
    /// project. Target/root authority is independent of that owner location
    /// and is revalidated on the first worker bind.
    pub async fn restore_project_rules(
        &self,
        session_id: &str,
        location: &ProjectLocation,
    ) -> Result<(), SshServiceError> {
        self.register_project_location(session_id, None, location)
            .await?;
        let mut sessions = self.inner.sessions.write().await;
        let rules = {
            let rules = self.inner.project_rules.lock().await;
            match &*rules {
                ProjectRuleStore::Loaded(file) => file
                    .rules
                    .iter()
                    .filter(|rule| rule.owns(location))
                    .cloned()
                    .collect::<Vec<_>>(),
                ProjectRuleStore::Invalid(error) => {
                    return Err(SshServiceError::ProjectRuleStorage(error.clone()));
                }
            }
        };
        if rules.is_empty() {
            return Ok(());
        }
        let state = sessions.entry(session_id.to_owned()).or_default();
        let mut candidate = state.clone();
        for rule in rules {
            let duplicate = candidate.grants.values().any(|record| {
                let binding = &record.persisted.binding;
                record.persisted.scope == SshGrantScope::ProjectRule
                    && !binding.revoked
                    && binding.target_id == rule.target_id
                    && binding.root == rule.root
                    && binding.identity == rule.identity
                    && binding.capabilities == rule.capabilities
            });
            if duplicate {
                continue;
            }
            let binding = SshBinding {
                id: Uuid::now_v7().to_string(),
                session_id: session_id.to_owned(),
                target_id: rule.target_id,
                identity: rule.identity,
                root: rule.root,
                cwd: rule.cwd,
                capabilities: rule.capabilities,
                epoch: 1,
                revoked: false,
            };
            if rule.make_default && candidate.default_binding_id.is_none() {
                candidate.default_binding_id = Some(binding.id.clone());
            }
            candidate.grants.insert(
                binding.id.clone(),
                GrantRecord {
                    persisted: PersistedSshGrant {
                        binding,
                        parent_binding_id: None,
                        requires_revalidation: true,
                        scope: SshGrantScope::ProjectRule,
                        revoke_status: None,
                    },
                },
            );
        }
        self.persist_state(session_id, &candidate).await?;
        *state = candidate;
        Ok(())
    }

    async fn restore_project_grant(
        &self,
        session_id: &str,
        location: &ProjectLocation,
        client_id: u64,
    ) -> Result<Option<SshBinding>, SshServiceError> {
        let ProjectLocation::Ssh { target_id, root } = location else {
            return Err(SshServiceError::ProjectLocationRequired);
        };
        self.restore_project_rules(session_id, location).await?;
        for access in self.list_targets(session_id).await {
            if access.target_id != *target_id || !access.capabilities.read {
                continue;
            }
            let client = self
                .project_workspace_client(session_id, &access.binding_id, Some(client_id))
                .await?;
            let canonical_root = match client.canonicalize_root(root).await {
                Ok(root) => root,
                Err(SshClientError::Remote(error)) if error.code == "invalid_path" => continue,
                Err(error) => return Err(SshServiceError::Worker(error.to_string())),
            };
            let binding = client.binding().await;
            if canonical_root == binding.root {
                return Ok(Some(binding));
            }
        }
        Ok(None)
    }
    async fn persist_registered_session(&self, session_id: &str) -> Result<(), SshServiceError> {
        let sessions = self.inner.sessions.read().await;
        if let Some(state) = sessions.get(session_id) {
            self.persist_state(session_id, state).await?;
        }
        Ok(())
    }

    async fn persist_state(
        &self,
        session_id: &str,
        state: &SessionState,
    ) -> Result<(), SshServiceError> {
        let info = self
            .inner
            .project_registrations
            .read()
            .await
            .get(session_id)
            .and_then(|registration| registration.session_info.clone());
        if let Some(info) = info {
            crate::session::persistence::persist_ssh_state(&info, state.persisted())
                .await
                .map_err(|error| SshServiceError::Configuration(error.to_string()))?;
        }
        Ok(())
    }
    async fn persist_grant_state(
        &self,
        session_id: &str,
        state: &SessionState,
        binding: &SshBinding,
        scope: SshGrantScope,
        make_default: bool,
    ) -> Result<(), SshServiceError> {
        if scope != SshGrantScope::ProjectRule {
            return self.persist_state(session_id, state).await;
        }
        let registration = self
            .inner
            .project_registrations
            .read()
            .await
            .get(session_id)
            .cloned()
            .ok_or(SshServiceError::ProjectLocationRequired)?;
        let canonical_owner_location = match &registration.location {
            ProjectLocation::Ssh { target_id, .. }
                if registration.session_info.is_none() && *target_id == binding.target_id =>
            {
                Some(ProjectLocation::Ssh {
                    target_id: binding.target_id.clone(),
                    root: binding.root.clone(),
                })
            }
            _ => None,
        };
        let owner_location = registration.location;
        let mut store = self.inner.project_rules.lock().await;
        let file = match &mut *store {
            ProjectRuleStore::Loaded(file) => file,
            ProjectRuleStore::Invalid(error) => {
                return Err(SshServiceError::ProjectRuleStorage(error.clone()));
            }
        };
        let mut candidate = file.clone();
        candidate.rules.retain(|rule| {
            !rule.owns(&owner_location)
                || rule.target_id != binding.target_id
                || rule.root != binding.root
        });
        if make_default {
            for rule in &mut candidate.rules {
                if rule.owns(&owner_location) {
                    rule.make_default = false;
                }
            }
        }
        candidate.rules.push(ProjectSshRule {
            owner_location,
            canonical_owner_location,
            target_id: binding.target_id.clone(),
            root: binding.root.clone(),
            cwd: binding.cwd.clone(),
            identity: binding.identity.clone(),
            capabilities: binding.capabilities,
            make_default,
        });
        candidate.version = 1;
        write_project_rules(&self.inner.project_rules_path, &candidate)?;
        if let Err(error) = self.persist_state(session_id, state).await {
            write_project_rules(&self.inner.project_rules_path, file).map_err(|rollback| {
                SshServiceError::ProjectRuleStorage(format!(
                    "{error}; restoring previous rules failed: {rollback}"
                ))
            })?;
            return Err(error);
        }
        *file = candidate;
        Ok(())
    }

    async fn remove_project_rule(
        &self,
        session_id: &str,
        binding: &SshBinding,
    ) -> Result<(), SshServiceError> {
        let owner_location = self
            .inner
            .project_registrations
            .read()
            .await
            .get(session_id)
            .map(|registration| registration.location.clone())
            .ok_or(SshServiceError::ProjectLocationRequired)?;
        let mut store = self.inner.project_rules.lock().await;
        let file = match &mut *store {
            ProjectRuleStore::Loaded(file) => file,
            ProjectRuleStore::Invalid(error) => {
                return Err(SshServiceError::ProjectRuleStorage(error.clone()));
            }
        };
        let mut candidate = file.clone();
        candidate.rules.retain(|rule| {
            !rule.owns(&owner_location)
                || rule.target_id != binding.target_id
                || rule.root != binding.root
                || rule.identity != binding.identity
                || rule.capabilities != binding.capabilities
        });
        if candidate.rules.len() != file.rules.len() {
            write_project_rules(&self.inner.project_rules_path, &candidate)?;
            *file = candidate;
        }
        Ok(())
    }

    /// The originating local UI owner of an already live binding. Child/fork
    /// grant requests use it only to route new human consent and never to
    /// transfer the parent's authority.
    pub async fn interaction_client_id(&self, binding_id: &str) -> Option<u64> {
        self.inner
            .workers
            .lock()
            .await
            .get(binding_id)
            .and_then(|worker| worker.client_id)
    }

    pub fn resource(
        self: &Arc<Self>,
        session_id: impl Into<String>,
        client_id: Option<u64>,
    ) -> SessionSshResource {
        SessionSshResource {
            service: Arc::clone(self),
            session_id: session_id.into(),
            client_id,
        }
    }

    pub async fn seed_resources(
        self: &Arc<Self>,
        bridge: &xai_grok_tools::bridge::ToolBridge,
        session_id: impl Into<String>,
    ) {
        bridge
            .update_resource(self.resource(session_id, None))
            .await;
    }

    pub async fn seed_resources_for_client(
        self: &Arc<Self>,
        bridge: &xai_grok_tools::bridge::ToolBridge,
        session_id: impl Into<String>,
        client_id: u64,
    ) {
        bridge
            .update_resource(self.resource(session_id, Some(client_id)))
            .await;
    }

    /// Run an SSH control command as its originating local client.
    ///
    /// The leader server and embedded hosts both enter through this boundary so
    /// interactive approvals cannot be attributed to a different client.
    pub async fn control(
        &self,
        client_id: u64,
        command: SshControlCommand,
    ) -> Result<SshControlReply, SshServiceError> {
        match command {
            SshControlCommand::ListConfiguredTargets => {
                let targets = self.list_configured_targets()?;
                let encoded = serde_json::to_string(&targets)
                    .map_err(|error| SshServiceError::Configuration(error.to_string()))?;
                Ok(SshControlReply::ConfiguredTargets(encoded))
            }
            SshControlCommand::ListSessionTargets { session_id } => Ok(
                SshControlReply::SessionTargets(self.list_targets(&session_id).await),
            ),
            SshControlCommand::RequestGrant {
                session_id,
                target_id,
                root,
                capabilities,
                reason,
            } => Ok(SshControlReply::GrantRequested(
                self.request_grant(
                    session_id,
                    target_id,
                    root,
                    capabilities,
                    reason,
                    Some(client_id),
                )
                .await?,
            )),
            SshControlCommand::InspectGrantTarget {
                request_id,
                target_id,
            } => Ok(SshControlReply::GrantRequested(
                self.inspect_grant_target(&request_id, target_id, client_id)
                    .await?,
            )),
            SshControlCommand::ApproveGrant(decision) => {
                if decision.client_id != client_id {
                    return Err(SshServiceError::WrongClient);
                }
                Ok(SshControlReply::GrantResolved {
                    binding: self.approve_grant(decision).await?,
                })
            }
            SshControlCommand::InheritSession {
                source_session_id,
                binding_id,
                target_session_id,
                capabilities,
            } => Ok(SshControlReply::InheritedBindings(
                self.inherit_session(
                    &source_session_id,
                    target_session_id,
                    &[binding_id],
                    capabilities,
                )
                .await?,
            )),
            SshControlCommand::RegisterProjectLocation {
                session_id,
                location,
            } => {
                self.register_project_location(&session_id, None, &location)
                    .await?;
                Ok(SshControlReply::ProjectLocationRegistered)
            }
            SshControlCommand::RestoreProjectGrant { session_id, location } => {
                Ok(SshControlReply::ProjectGrantRestored {
                    binding: self.restore_project_grant(&session_id, &location, client_id).await?,
                })
            }
            SshControlCommand::UseBinding {
                session_id,
                binding_id,
            } => {
                self.use_binding(&session_id, &binding_id).await?;
                Ok(SshControlReply::BindingSelected)
            }
            SshControlCommand::RevokeBinding {
                session_id,
                binding_id,
            } => Ok(SshControlReply::BindingRevoked {
                status: self.revoke_binding(&session_id, &binding_id).await?,
            }),
            SshControlCommand::Connect {
                target_id,
                interactive,
            } => Ok(SshControlReply::TargetStatus(
                self.connect_target(&target_id, client_id, interactive)
                    .await?,
            )),
            SshControlCommand::Disconnect { target_id } => Ok(SshControlReply::TargetStatus(
                self.disconnect_target(&target_id).await?,
            )),
            SshControlCommand::ConnectionStatus { target_id } => Ok(SshControlReply::TargetStatus(
                self.connection_status(&target_id).await,
            )),
            SshControlCommand::SubmitAuthentication(response) => {
                if response.client_id != client_id {
                    return Err(SshServiceError::WrongClient);
                }
                self.submit_auth_response(response.into()).await?;
                Ok(SshControlReply::AuthenticationAccepted)
            }
            SshControlCommand::SubmitOperationApproval(decision) => {
                if decision.client_id != client_id {
                    return Err(SshServiceError::WrongClient);
                }
                self.submit_operation_approval(decision).await?;
                Ok(SshControlReply::OperationApprovalAccepted)
            }
        }
    }

    pub fn list_configured_targets(&self) -> Result<Vec<xai_grok_ssh::SshTarget>, SshServiceError> {
        self.inner
            .targets
            .list()
            .map_err(|error| SshServiceError::Configuration(error.to_string()))
    }

    /// Returns only active grants. It must be used by model-facing `ssh_targets`,
    /// never `list_configured_targets`.
    pub async fn list_targets(&self, session_id: &str) -> Vec<SshTargetAccess> {
        let session = self.inner.sessions.read().await;
        let Some(state) = session.get(session_id) else {
            return Vec::new();
        };
        let mut accesses = state
            .grants
            .values()
            .filter(|record| !record.persisted.binding.revoked)
            .map(|record| {
                let binding = &record.persisted.binding;
                SshTargetAccess {
                    binding_id: binding.id.clone(),
                    target_id: binding.target_id.clone(),
                    root: binding.root.clone(),
                    cwd: binding.cwd.clone(),
                    capabilities: binding.capabilities,
                    identity: binding.identity.clone(),
                    epoch: binding.epoch,
                    is_default: state.default_binding_id.as_deref() == Some(binding.id.as_str()),
                    connection: self.connection_state(&binding.target_id),
                }
            })
            .collect::<Vec<_>>();
        accesses.sort_by(|left, right| left.binding_id.cmp(&right.binding_id));
        accesses
    }

    pub async fn snapshot_session(&self, session_id: &str) -> PersistedSshState {
        let sessions = self.inner.sessions.read().await;
        let Some(state) = sessions.get(session_id) else {
            return PersistedSshState::default();
        };
        state.persisted()
    }

    /// Restored authority is never immediately executable: identity and remote
    /// canonical root are revalidated by the next dispatch before use.
    pub async fn restore_session(&self, session_id: impl Into<String>, state: PersistedSshState) {
        let session_id = session_id.into();
        let mut grants = HashMap::new();
        for mut persisted in state.grants {
            persisted.requires_revalidation = !persisted.binding.revoked;
            grants.insert(persisted.binding.id.clone(), GrantRecord { persisted });
        }
        let pending_requests = state
            .pending_requests
            .into_iter()
            .map(|mut request| {
                request.verified_identity = None;
                request.client_id = None;
                (request.id.clone(), request)
            })
            .collect();
        self.inner.sessions.write().await.insert(
            session_id,
            SessionState {
                grants,
                default_binding_id: state.default_binding_id,
                pending_requests,
            },
        );
    }

    /// Creates a request only. This function cannot grant target authority and
    /// is therefore safe for model tools even when normal operation approvals
    /// are configured to always approve.
    pub async fn request_grant(
        &self,
        session_id: impl Into<String>,
        target_id: Option<String>,
        root: Option<String>,
        capabilities: SshCapabilities,
        reason: String,
        client_id: Option<u64>,
    ) -> Result<SshGrantRequest, SshServiceError> {
        let request = SshGrantRequest {
            id: Uuid::now_v7().to_string(),
            session_id: session_id.into(),
            originating_session_id: None,
            target_id,
            root,
            capabilities,
            reason,
            verified_identity: None,
            client_id,
        };
        self.publish_grant_request(request).await
    }

    pub(crate) async fn request_worktree_grant(
        &self,
        session_id: String,
        source: &SshBinding,
        root: String,
        client_id: u64,
    ) -> Result<SshGrantRequest, SshServiceError> {
        let current = self.binding(&source.session_id, &source.id).await?;
        if current.revoked {
            return Err(SshServiceError::RevokedBinding(source.id.clone()));
        }
        if current != *source {
            return Err(SshServiceError::StaleInvocation);
        }
        if self.interaction_client_id(&source.id).await != Some(client_id) {
            return Err(SshServiceError::WrongClient);
        }
        self.publish_grant_request(SshGrantRequest {
            id: Uuid::now_v7().to_string(),
            session_id,
            originating_session_id: Some(source.session_id.clone()),
            target_id: Some(source.target_id.clone()),
            reason: format!(
                "Resume SSH session {} in remote worktree {}",
                source.session_id, root
            ),
            root: Some(root),
            capabilities: source.capabilities,
            verified_identity: None,
            client_id: Some(client_id),
        })
        .await
    }

    async fn publish_grant_request(
        &self,
        request: SshGrantRequest,
    ) -> Result<SshGrantRequest, SshServiceError> {
        self.inner
            .sessions
            .write()
            .await
            .entry(request.session_id.clone())
            .or_default()
            .pending_requests
            .insert(request.id.clone(), request.clone());
        self.persist_registered_session(&request.session_id).await?;
        let _ = self
            .inner
            .events
            .send(SshEvent::GrantRequested(request.clone()));
        Ok(request)
    }

    /// Acquires only the native connection required for a user to inspect the
    /// actual authenticated identity before deciding a grant. It does not create
    /// a binding and does not expose a worker to a model.
    pub async fn inspect_grant_target(
        &self,
        request_id: &str,
        target_id: String,
        client_id: u64,
    ) -> Result<SshGrantRequest, SshServiceError> {
        let request = self.pending_request(request_id).await?;
        self.check_request_client(&request, client_id)?;
        if let Some(requested_target) = &request.target_id {
            if requested_target != &target_id {
                return Err(SshServiceError::GrantExpansion);
            }
        }
        let lease = self
            .acquire(target_id.as_str(), Some(client_id), true)
            .await?;
        let identity = lease.identity().clone();
        drop(lease);
        let updated = {
            let mut sessions = self.inner.sessions.write().await;
            let state = sessions
                .get_mut(&request.session_id)
                .ok_or_else(|| SshServiceError::UnknownGrantRequest(request_id.to_owned()))?;
            let current = state
                .pending_requests
                .get_mut(request_id)
                .ok_or_else(|| SshServiceError::UnknownGrantRequest(request_id.to_owned()))?;
            current.target_id = Some(target_id);
            current.verified_identity = Some(identity);
            current.client_id = Some(client_id);
            current.clone()
        };
        self.persist_registered_session(&updated.session_id).await?;
        let _ = self
            .inner
            .events
            .send(SshEvent::GrantRequested(updated.clone()));
        Ok(updated)
    }

    /// Human-only grant completion. Identity, canonical root, and final binding
    /// are captured from real native/worker handshakes rather than from the UI.
    pub async fn approve_grant(
        &self,
        decision: SshGrantDecision,
    ) -> Result<Option<SshBinding>, SshServiceError> {
        let request = self.pending_request(&decision.request_id).await?;
        self.check_request_client(&request, decision.client_id)?;
        let _claim = self.claim_grant_resolution(&decision.request_id)?;
        if !decision.approved {
            let mut sessions = self.inner.sessions.write().await;
            let state = sessions
                .get_mut(&request.session_id)
                .ok_or_else(|| SshServiceError::UnknownGrantRequest(request.id.clone()))?;
            let mut candidate = state.clone();
            candidate
                .pending_requests
                .remove(&request.id)
                .ok_or(SshServiceError::RequestResolved)?;
            self.persist_state(&request.session_id, &candidate).await?;
            *state = candidate;
            drop(sessions);
            let _ = self.inner.events.send(SshEvent::GrantResolved {
                request_id: request.id,
                approved: false,
                binding: None,
            });
            return Ok(None);
        }

        let target_id = choose_narrower_target(&request, decision.target_id.as_deref())?;
        let root = choose_narrower_root(&request, decision.root.as_deref())?;
        let capabilities = choose_narrower_capabilities(&request, decision.capabilities)?;
        let lease = self
            .acquire(&target_id, Some(decision.client_id), true)
            .await?;
        let identity = lease.identity().clone();
        if let Some(inspected) = &request.verified_identity {
            if inspected != &identity {
                return Err(SshServiceError::IdentityChanged);
            }
        }
        let proposed = SshBinding {
            id: Uuid::now_v7().to_string(),
            session_id: request.session_id.clone(),
            target_id,
            identity,
            root: root.clone(),
            cwd: root,
            capabilities,
            epoch: 1,
            revoked: false,
        };
        let worker = self
            .open_worker(lease, proposed, Some(decision.client_id))
            .await?;
        let binding = worker.binding.clone();
        let persisted = PersistedSshGrant {
            binding: binding.clone(),
            parent_binding_id: None,
            requires_revalidation: false,
            scope: decision.scope,
            revoke_status: None,
        };
        {
            let mut sessions = self.inner.sessions.write().await;
            let state = sessions.entry(request.session_id.clone()).or_default();
            let mut candidate = state.clone();
            candidate
                .pending_requests
                .remove(&request.id)
                .ok_or(SshServiceError::RequestResolved)?;
            if decision.make_default {
                candidate.default_binding_id = Some(binding.id.clone());
            }
            candidate
                .grants
                .insert(binding.id.clone(), GrantRecord { persisted });
            if let Err(error) = self
                .persist_grant_state(
                    &request.session_id,
                    &candidate,
                    &binding,
                    decision.scope,
                    decision.make_default,
                )
                .await
            {
                let client = worker.client.clone();
                let rejected = binding.clone();
                tokio::spawn(async move {
                    let _ = client.revoke(&rejected.id, rejected.epoch + 1).await;
                });
                return Err(error);
            }
            self.inner
                .workers
                .lock()
                .await
                .insert(binding.id.clone(), Arc::new(worker));
            *state = candidate;
        }
        let _ = self.inner.events.send(SshEvent::GrantResolved {
            request_id: request.id,
            approved: true,
            binding: Some(binding.clone()),
        });
        Ok(Some(binding))
    }

    pub async fn use_binding(
        &self,
        session_id: &str,
        binding_id: &str,
    ) -> Result<(), SshServiceError> {
        let mut sessions = self.inner.sessions.write().await;
        let state = sessions.entry(session_id.to_owned()).or_default();
        let record = state
            .grants
            .get(binding_id)
            .ok_or_else(|| SshServiceError::UnknownBinding(binding_id.to_owned()))?;
        if record.persisted.binding.revoked {
            return Err(SshServiceError::RevokedBinding(binding_id.to_owned()));
        }
        let mut candidate = state.clone();
        candidate.default_binding_id = Some(binding_id.to_owned());
        self.persist_state(session_id, &candidate).await?;
        *state = candidate;
        Ok(())
    }

    /// Revocation is local-first. The returned state is immediately pending;
    /// each live worker is notified asynchronously, and only its acknowledgement
    /// changes the visible state to confirmed.
    pub async fn revoke_binding(
        &self,
        session_id: &str,
        binding_id: &str,
    ) -> Result<RevokeStatus, SshServiceError> {
        let mut persistence_error = None;
        let affected = {
            let mut sessions = self.inner.sessions.write().await;
            if !sessions
                .get(session_id)
                .is_some_and(|state| state.grants.contains_key(binding_id))
            {
                return Err(SshServiceError::UnknownBinding(binding_id.to_owned()));
            }
            let affected = revoke_authority_tree(&mut sessions, binding_id);
            for (affected_session_id, binding, scope) in &affected {
                if *scope == SshGrantScope::ProjectRule {
                    if let Err(error) = self.remove_project_rule(affected_session_id, binding).await
                    {
                        persistence_error.get_or_insert(error);
                    }
                }
                if let Some(state) = sessions.get(affected_session_id) {
                    if let Err(error) = self.persist_state(affected_session_id, state).await {
                        persistence_error.get_or_insert(error);
                    }
                }
            }
            affected
        };
        for (affected_session_id, binding, _) in &affected {
            let _ = self.inner.events.send(SshEvent::BindingRevoked {
                session_id: affected_session_id.clone(),
                binding_id: binding.id.clone(),
                status: RevokeStatus::LocalPending,
            });
            self.spawn_revoke_ack(affected_session_id.clone(), binding.clone());
        }
        if let Some(error) = persistence_error {
            return Err(error);
        }
        Ok(RevokeStatus::LocalPending)
    }

    /// Child sessions receive only selected strict subsets. The parent binding
    /// relationship is durable so a parent revoke propagates to every child.
    pub async fn inherit_session(
        &self,
        parent_session_id: &str,
        child_session_id: impl Into<String>,
        binding_ids: &[String],
        capabilities: SshCapabilities,
    ) -> Result<Vec<SshBinding>, SshServiceError> {
        let child_session_id = child_session_id.into();
        let mut sessions = self.inner.sessions.write().await;
        let parent_default = sessions
            .get(parent_session_id)
            .and_then(|state| state.default_binding_id.clone());
        let parent_records = {
            let state = sessions
                .get(parent_session_id)
                .ok_or_else(|| SshServiceError::UnknownBinding("parent session".into()))?;
            binding_ids
                .iter()
                .map(|binding_id| {
                    state
                        .grants
                        .get(binding_id)
                        .cloned()
                        .ok_or_else(|| SshServiceError::UnknownBinding(binding_id.clone()))
                })
                .collect::<Result<Vec<_>, _>>()?
        };
        let mut inherited = Vec::with_capacity(parent_records.len());
        for parent in parent_records {
            let binding = &parent.persisted.binding;
            if binding.revoked {
                return Err(SshServiceError::RevokedBinding(binding.id.clone()));
            }
            if !capabilities.is_subset_of(binding.capabilities) {
                return Err(SshServiceError::GrantExpansion);
            }
            inherited.push(PersistedSshGrant {
                binding: SshBinding {
                    id: Uuid::now_v7().to_string(),
                    session_id: child_session_id.clone(),
                    target_id: binding.target_id.clone(),
                    identity: binding.identity.clone(),
                    root: binding.root.clone(),
                    cwd: binding.cwd.clone(),
                    capabilities,
                    epoch: binding.epoch,
                    revoked: false,
                },
                parent_binding_id: Some(binding.id.clone()),
                requires_revalidation: true,
                scope: SshGrantScope::CurrentSession,
                revoke_status: None,
            });
        }
        let bindings = inherited
            .iter()
            .map(|grant| grant.binding.clone())
            .collect::<Vec<_>>();
        let child = sessions.entry(child_session_id.clone()).or_default();
        let mut candidate = child.clone();
        if candidate.default_binding_id.is_none() {
            if let Some(grant) = inherited
                .iter()
                .find(|grant| parent_default.is_some() && grant.parent_binding_id == parent_default)
            {
                candidate.default_binding_id = Some(grant.binding.id.clone());
            }
        }
        for grant in inherited {
            candidate
                .grants
                .insert(grant.binding.id.clone(), GrantRecord { persisted: grant });
        }
        self.persist_state(&child_session_id, &candidate).await?;
        *child = candidate;
        Ok(bindings)
    }

    /// Create a child-local binding and open a distinct worker client for it.
    /// The native connection may be pooled, but the binding/session and worker
    /// authorization remain child-specific.
    pub async fn inherit_binding(
        &self,
        parent_session_id: &str,
        child_session_id: &str,
        parent_binding_id: &str,
    ) -> Result<SshWorkspaceClient, SshServiceError> {
        let parent = self.binding(parent_session_id, parent_binding_id).await?;
        let client_id = self
            .inner
            .workers
            .lock()
            .await
            .get(parent_binding_id)
            .and_then(|worker| worker.client_id);
        let bindings = self
            .inherit_session(
                parent_session_id,
                child_session_id,
                &[parent_binding_id.to_owned()],
                parent.capabilities,
            )
            .await?;
        let binding = bindings
            .into_iter()
            .next()
            .ok_or_else(|| SshServiceError::UnknownBinding(parent_binding_id.to_owned()))?;
        Ok(self
            .ensure_worker(&binding, client_id)
            .await?
            .client
            .clone())
    }

    /// Project binding is a lookup, never an implicit grant. Project open flows
    /// must go through `request_grant`/`approve_grant` first.
    pub async fn authorize_project(
        &self,
        session_id: &str,
        target_id: &str,
        root: &str,
        capabilities: SshCapabilities,
    ) -> Result<ProjectSshBinding, SshServiceError> {
        let sessions = self.inner.sessions.read().await;
        let state = sessions
            .get(session_id)
            .ok_or(SshServiceError::GrantRequired)?;
        state
            .grants
            .values()
            .find_map(|record| {
                let binding = &record.persisted.binding;
                (!binding.revoked
                    && binding.target_id == target_id
                    && binding.root == root
                    && capabilities.is_subset_of(binding.capabilities))
                .then(|| ProjectSshBinding {
                    binding: binding.clone(),
                })
            })
            .ok_or(SshServiceError::GrantRequired)
    }

    pub async fn bind_project(
        &self,
        session_id: &str,
        binding_id: &str,
    ) -> Result<ProjectSshBinding, SshServiceError> {
        let binding = self.binding(session_id, binding_id).await?;
        if binding.revoked {
            return Err(SshServiceError::RevokedBinding(binding_id.to_owned()));
        }
        Ok(ProjectSshBinding { binding })
    }

    /// Returns the remote client for a previously authorized project binding.
    /// A headless resume may pass no local interaction owner: key/agent-backed
    /// reads remain available, while host trust, authentication, and mutation
    /// approval fail promptly without creating a waiter.
    pub async fn project_workspace_client(
        &self,
        session_id: &str,
        binding_id: &str,
        client_id: Option<u64>,
    ) -> Result<SshWorkspaceClient, SshServiceError> {
        let binding = self.binding(session_id, binding_id).await?;
        if binding.revoked {
            return Err(SshServiceError::RevokedBinding(binding_id.to_owned()));
        }
        Ok(self
            .ensure_worker(&binding, client_id)
            .await?
            .client
            .clone())
    }

    pub async fn resolve_invocation(
        &self,
        session_id: &str,
        target: Option<&str>,
        cwd: Option<&str>,
        operation: SshOperation,
        call_id: impl Into<String>,
    ) -> Result<ResolvedSshInvocation, SshServiceError> {
        let binding = self.resolve_binding(session_id, target).await?;
        if !binding.capabilities.permits(operation) {
            return Err(SshServiceError::CapabilityDenied);
        }
        let cwd = resolve_remote_cwd(&binding, cwd)?;
        Ok(ResolvedSshInvocation {
            binding_id: binding.id.clone(),
            target_id: binding.target_id.clone(),
            session_id: session_id.to_owned(),
            epoch: binding.epoch,
            cwd,
            operation,
            call_id: call_id.into(),
        })
    }

    /// Rechecks local authority immediately before remote dispatch. The worker
    /// repeats the epoch/root/capability check before side effects; there is no
    /// local filesystem or shell fallback and no mutation retry path.
    pub async fn dispatch(
        &self,
        request: SshDispatchRequest,
        client_id: Option<u64>,
    ) -> Result<SshDispatchResult, SshServiceError> {
        let binding = self.binding_for_invocation(&request.invocation).await?;
        let worker = self.ensure_worker(&binding, client_id).await?;
        // A revoke may have raced native authentication/worker startup.
        self.binding_for_invocation(&request.invocation).await?;
        let response = worker
            .client
            .call_tool(
                request.invocation.clone(),
                &request.tool_name,
                request.args,
                request.mutation_id,
            )
            .await?;
        let mut result =
            serde_json::from_value::<ToolRunResult>(response.value).map_err(|error| {
                SshServiceError::Worker(format!(
                    "remote tool result deserialization failed: {error}"
                ))
            })?;
        let prompt_text = if let Some(outcome) = response.operation.post_hook.as_ref() {
            let _ = xai_grok_workspace::workspace_ops::apply_ssh_post_tool_outcome(
                &mut result,
                outcome,
            );
            render_remote_hook_prompt(result.prompt_text, outcome)
        } else {
            result.prompt_text
        };
        let prompt_text = render_ssh_dispatch_prompt(
            prompt_text,
            Some(&result.output),
            &request.invocation,
            &response.operation.operation_id,
        );
        let mut output = serde_json::to_value(&result.output).map_err(|error| {
            SshServiceError::Worker(format!("remote tool output serialization failed: {error}"))
        })?;
        attach_remote_scope(
            &mut output,
            &request.invocation,
            &response.operation.operation_id,
        );
        Ok(SshDispatchResult {
            output,
            prompt_text,
        })
    }

    pub async fn query_task(
        &self,
        session_id: &str,
        target: Option<&str>,
        operation_id: &str,
        call_id: impl Into<String>,
        client_id: Option<u64>,
    ) -> Result<Option<SshDispatchResult>, SshServiceError> {
        let binding = self.resolve_binding(session_id, target).await?;
        let worker = self.ensure_worker(&binding, client_id).await?;
        let operation = worker
            .client
            .operation(&binding.id, session_id, operation_id)
            .await?;
        operation
            .map(|operation| render_operation_query(&binding, operation, call_id.into()))
            .transpose()
    }

    /// Retrieve the actual output for one remote background task through the
    /// authorized worker. The task-output tool itself verifies session ownership.
    pub async fn query_task_output(
        &self,
        session_id: &str,
        target: Option<&str>,
        task_id: String,
        call_id: impl Into<String>,
        client_id: Option<u64>,
    ) -> Result<SshDispatchResult, SshServiceError> {
        let invocation = self
            .resolve_invocation(session_id, target, None, SshOperation::Read, call_id)
            .await?;
        self.dispatch(
            SshDispatchRequest {
                invocation,
                tool_name: "get_command_or_subagent_output".into(),
                args: serde_json::json!({ "task_ids": [task_id] }),
                mutation_id: None,
            },
            client_id,
        )
        .await
    }

    pub async fn list_tasks(
        &self,
        session_id: &str,
        target: Option<&str>,
        client_id: Option<u64>,
    ) -> Result<Vec<SshTaskRecord>, SshServiceError> {
        let binding = self.resolve_binding(session_id, target).await?;
        let worker = self.ensure_worker(&binding, client_id).await?;
        worker
            .client
            .tasks(&binding.id, session_id)
            .await
            .map_err(Into::into)
    }

    pub async fn cancel_task(
        &self,
        session_id: &str,
        target: Option<&str>,
        task_reference: String,
        call_id: impl Into<String>,
        client_id: Option<u64>,
    ) -> Result<SshCancellation, SshServiceError> {
        let invocation = self
            .resolve_invocation(session_id, target, None, SshOperation::Read, call_id)
            .await?;
        let binding = self.binding_for_invocation(&invocation).await?;
        let worker = self.ensure_worker(&binding, client_id).await?;
        self.binding_for_invocation(&invocation).await?;
        worker
            .client
            .cancel(invocation, task_reference)
            .await
            .map_err(Into::into)
    }

    pub async fn connection_status(&self, target_id: &str) -> SshTargetStatus {
        SshTargetStatus {
            target_id: target_id.to_owned(),
            connection: self.connection_state(target_id),
            detail: None,
        }
    }

    fn connection_state(&self, target_id: &str) -> SshConnectionState {
        // A retained lease is ownership, not liveness. The native disconnect
        // callback invalidates its generation even while the user keeps a hold.
        match self.inner.connections.phase(target_id) {
            ConnectionPhase::Connecting => SshConnectionState::Connecting,
            ConnectionPhase::Connected => SshConnectionState::Connected,
            ConnectionPhase::Disconnected => SshConnectionState::Disconnected,
            ConnectionPhase::Failed => SshConnectionState::Failed,
        }
    }

    /// Hold a real native connection in the leader process. A CLI client can
    /// exit after this succeeds; `disconnect_target` later releases the same
    /// lease through the leader's shared service.
    pub async fn connect_target(
        &self,
        target_id: &str,
        client_id: u64,
        interactive: bool,
    ) -> Result<SshTargetStatus, SshServiceError> {
        let lease = self
            .acquire(target_id, Some(client_id), interactive)
            .await?;
        let identity = lease.identity();
        let status = SshTargetStatus {
            target_id: target_id.to_owned(),
            connection: SshConnectionState::Connected,
            detail: Some(format!(
                "connected as {}@{}:{}",
                identity.username, identity.hostname, identity.port
            )),
        };
        self.inner
            .manual_holds
            .lock()
            .await
            .insert(target_id.to_owned(), lease);
        let _ = self
            .inner
            .events
            .send(SshEvent::TargetStatus(status.clone()));
        Ok(status)
    }

    pub async fn disconnect_target(
        &self,
        target_id: &str,
    ) -> Result<SshTargetStatus, SshServiceError> {
        self.inner
            .workers
            .lock()
            .await
            .retain(|_, worker| worker.binding.target_id != target_id);
        self.inner.manual_holds.lock().await.remove(target_id);
        self.inner.connections.disconnect(target_id).await?;
        let status = SshTargetStatus {
            target_id: target_id.to_owned(),
            connection: SshConnectionState::Disconnected,
            detail: None,
        };
        let _ = self
            .inner
            .events
            .send(SshEvent::TargetStatus(status.clone()));
        Ok(status)
    }

    /// Flush locally persisted revoke tombstones after a target has been
    /// authenticated again. This never obtains another connection or creates a
    /// normal worker: each pending tombstone uses a short-lived authenticated
    /// worker bridge that can only acknowledge its revoked epoch.
    ///
    /// Callers must invoke this after acquiring `lease`. The pending snapshot is
    /// taken before any worker I/O, so a reconnect cannot block session-state
    /// writers or accidentally reauthorize an old grant.
    pub async fn sync_pending_revocations(
        &self,
        lease: &ConnectionLease,
        target_id: &str,
    ) -> Result<(), SshServiceError> {
        let identity = lease.identity();
        let pending = {
            let sessions = self.inner.sessions.read().await;
            let mut pending = Vec::new();
            for (session_id, state) in sessions.iter() {
                for record in state.grants.values() {
                    let persisted = &record.persisted;
                    if persisted.binding.revoked
                        && persisted.revoke_status == Some(SshGrantStatus::RevokedLocalPending)
                        && persisted.binding.target_id == target_id
                        && &persisted.binding.identity == identity
                    {
                        pending.push((session_id.clone(), persisted.binding.clone()));
                    }
                }
            }
            pending
        };
        if pending.is_empty() {
            return Ok(());
        }
        let resolved = self
            .inner
            .targets
            .resolve(target_id)
            .map_err(|error| SshServiceError::Configuration(error.to_string()))?;
        let command = shell_command(&resolved.target.worker_command)?;

        for (session_id, binding) in pending {
            let acknowledged = match lease.exec(&command).await {
                Ok(stream) => {
                    match SshWorkspaceClient::revoke_tombstone(stream, binding.clone()).await {
                        Ok(ack) => ack.binding_id == binding.id && ack.epoch == binding.epoch,
                        Err(error) => {
                            tracing::warn!(
                                binding_id = %binding.id,
                                target_id,
                                error = %error,
                                "SSH revocation tombstone acknowledgement remains pending"
                            );
                            false
                        }
                    }
                }
                Err(error) => {
                    tracing::warn!(
                        binding_id = %binding.id,
                        target_id,
                        error = %error,
                        "SSH revocation tombstone bridge could not start"
                    );
                    false
                }
            };
            if acknowledged {
                self.confirm_revoke_ack(&session_id, &binding).await?;
            }
        }
        Ok(())
    }

    pub async fn submit_auth_response(
        &self,
        response: SshAuthResponse,
    ) -> Result<(), SshServiceError> {
        let waiter = {
            let mut waiters = self.inner.auth_waiters.lock().await;
            let current = waiters
                .get(&response.challenge_id)
                .ok_or(SshServiceError::StaleAuthentication)?;
            if current.client_id != response.client_id
                || current.connection_generation != response.connection_generation
            {
                return Err(SshServiceError::StaleAuthentication);
            }
            waiters
                .remove(&response.challenge_id)
                .expect("waiter was present while holding the lock")
        };
        waiter
            .response
            .send(response)
            .map_err(|_| SshServiceError::StaleAuthentication)
    }

    pub async fn submit_operation_approval(
        &self,
        decision: SshOperationApprovalDecision,
    ) -> Result<(), SshServiceError> {
        let waiter = {
            let mut waiters = self.inner.approval_waiters.lock().await;
            let current = waiters
                .get(&decision.approval_id)
                .ok_or(SshServiceError::StaleOperationApproval)?;
            if current.client_id != decision.client_id {
                return Err(SshServiceError::StaleOperationApproval);
            }
            waiters
                .remove(&decision.approval_id)
                .expect("approval was present while holding the lock")
        };
        waiter
            .response
            .send(decision.approved)
            .map_err(|_| SshServiceError::StaleOperationApproval)
    }

    async fn pending_request(&self, request_id: &str) -> Result<SshGrantRequest, SshServiceError> {
        self.inner
            .sessions
            .read()
            .await
            .values()
            .find_map(|state| state.pending_requests.get(request_id).cloned())
            .ok_or_else(|| SshServiceError::UnknownGrantRequest(request_id.to_owned()))
    }

    fn check_request_client(
        &self,
        request: &SshGrantRequest,
        client_id: u64,
    ) -> Result<(), SshServiceError> {
        if request.client_id.is_some_and(|owner| owner != client_id) {
            return Err(SshServiceError::WrongClient);
        }
        Ok(())
    }

    fn claim_grant_resolution<'a>(
        &'a self,
        request_id: &'a str,
    ) -> Result<GrantResolutionClaim<'a>, SshServiceError> {
        if !self
            .inner
            .resolution_claims
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(request_id.to_owned())
        {
            return Err(SshServiceError::RequestResolved);
        }
        Ok(GrantResolutionClaim {
            claims: &self.inner.resolution_claims,
            request_id,
        })
    }

    async fn binding(
        &self,
        session_id: &str,
        binding_id: &str,
    ) -> Result<SshBinding, SshServiceError> {
        self.inner
            .sessions
            .read()
            .await
            .get(session_id)
            .and_then(|state| state.grants.get(binding_id))
            .map(|record| record.persisted.binding.clone())
            .ok_or_else(|| SshServiceError::UnknownBinding(binding_id.to_owned()))
    }

    async fn resolve_binding(
        &self,
        session_id: &str,
        target: Option<&str>,
    ) -> Result<SshBinding, SshServiceError> {
        let sessions = self.inner.sessions.read().await;
        let state = sessions
            .get(session_id)
            .ok_or(SshServiceError::NoDefaultBinding)?;
        let binding = match target {
            Some(selector) => {
                if let Some(record) = state.grants.get(selector) {
                    record.persisted.binding.clone()
                } else {
                    let mut matches = state
                        .grants
                        .values()
                        .filter(|record| {
                            !record.persisted.binding.revoked
                                && record.persisted.binding.target_id == selector
                        })
                        .map(|record| record.persisted.binding.clone());
                    let first = matches
                        .next()
                        .ok_or_else(|| SshServiceError::GrantRequired)?;
                    if matches.next().is_some() {
                        return Err(SshServiceError::AmbiguousTarget(selector.to_owned()));
                    }
                    first
                }
            }
            None => state
                .default_binding_id
                .as_ref()
                .and_then(|binding_id| state.grants.get(binding_id))
                .map(|record| record.persisted.binding.clone())
                .ok_or(SshServiceError::NoDefaultBinding)?,
        };
        if binding.revoked {
            return Err(SshServiceError::RevokedBinding(binding.id));
        }
        Ok(binding)
    }

    async fn binding_for_invocation(
        &self,
        invocation: &ResolvedSshInvocation,
    ) -> Result<SshBinding, SshServiceError> {
        let binding = self
            .binding(&invocation.session_id, &invocation.binding_id)
            .await?;
        if binding.revoked {
            return Err(SshServiceError::RevokedBinding(binding.id));
        }
        if binding.epoch != invocation.epoch
            || binding.target_id != invocation.target_id
            || !binding.capabilities.permits(invocation.operation)
        {
            return Err(SshServiceError::StaleInvocation);
        }
        Ok(binding)
    }

    async fn ensure_worker(
        &self,
        binding: &SshBinding,
        client_id: Option<u64>,
    ) -> Result<Arc<WorkerConnection>, SshServiceError> {
        if let Some(worker) = self.inner.workers.lock().await.get(&binding.id).cloned() {
            if worker.client.is_connected()
                && worker.binding.epoch == binding.epoch
                && worker.client_id == client_id
            {
                return Ok(worker);
            }
        }
        let lock = {
            let mut locks = self.inner.worker_locks.lock().await;
            locks
                .entry(binding.id.clone())
                .or_insert_with(|| Arc::new(Mutex::new(())))
                .clone()
        };
        let _guard = lock.lock().await;
        if let Some(worker) = self.inner.workers.lock().await.get(&binding.id).cloned() {
            if worker.client.is_connected()
                && worker.binding.epoch == binding.epoch
                && worker.client_id == client_id
            {
                return Ok(worker);
            }
        }
        let lease = self
            .acquire(&binding.target_id, client_id, client_id.is_some())
            .await?;
        if lease.identity() != &binding.identity {
            return Err(SshServiceError::IdentityChanged);
        }
        let worker = self.open_worker(lease, binding.clone(), client_id).await?;
        if worker.binding.root != binding.root || worker.binding.cwd != binding.cwd {
            return Err(SshServiceError::CanonicalRootChanged);
        }
        let worker = Arc::new(worker);
        self.inner
            .workers
            .lock()
            .await
            .insert(binding.id.clone(), worker.clone());
        self.mark_revalidated(&binding.session_id, &binding.id)
            .await;
        Ok(worker)
    }

    async fn open_worker(
        &self,
        lease: ConnectionLease,
        binding: SshBinding,
        client_id: Option<u64>,
    ) -> Result<WorkerConnection, SshServiceError> {
        let resolved = self
            .inner
            .targets
            .resolve(&binding.target_id)
            .map_err(|error| SshServiceError::Configuration(error.to_string()))?;
        let command = shell_command(&resolved.target.worker_command)?;
        let stream = lease.exec(&command).await?;
        let callbacks: Arc<dyn SshClientCallbacks> = Arc::new(WorkerCallbacks {
            service: Arc::downgrade(&self.inner),
            client_id,
            session_id: binding.session_id.clone(),
            binding_id: binding.id.clone(),
        });
        let client = SshWorkspaceClient::connect(stream, binding, callbacks).await?;
        let binding = client.binding().await;
        Ok(WorkerConnection {
            binding,
            client,
            client_id,
            _lease: lease,
        })
    }

    async fn acquire(
        &self,
        target_id: &str,
        client_id: Option<u64>,
        interactive: bool,
    ) -> Result<ConnectionLease, SshServiceError> {
        let interaction: Arc<dyn Interaction> = Arc::new(LocalInteractionBridge {
            service: Arc::downgrade(&self.inner),
            client_id,
            interactive,
        });
        let lease = self
            .inner
            .connections
            .acquire(target_id, interaction)
            .await?;
        self.sync_pending_revocations(&lease, target_id).await?;
        Ok(lease)
    }

    async fn mark_revalidated(&self, session_id: &str, binding_id: &str) {
        if let Some(record) = self
            .inner
            .sessions
            .write()
            .await
            .get_mut(session_id)
            .and_then(|state| state.grants.get_mut(binding_id))
        {
            record.persisted.requires_revalidation = false;
        }
    }

    async fn confirm_revoke_ack(
        &self,
        session_id: &str,
        binding: &SshBinding,
    ) -> Result<(), SshServiceError> {
        let mut sessions = self.inner.sessions.write().await;
        let Some(state) = sessions.get_mut(session_id) else {
            return Ok(());
        };
        let mut candidate = state.clone();
        let scope = {
            let Some(record) = candidate.grants.get(&binding.id) else {
                return Ok(());
            };
            if !record.persisted.binding.revoked
                || record.persisted.binding.epoch != binding.epoch
                || record.persisted.revoke_status != Some(SshGrantStatus::RevokedLocalPending)
            {
                return Ok(());
            }
            record.persisted.scope
        };
        if scope == SshGrantScope::ProjectRule {
            self.remove_project_rule(session_id, binding).await?;
        }
        candidate
            .grants
            .get_mut(&binding.id)
            .expect("grant was checked in the local candidate")
            .persisted
            .revoke_status = Some(SshGrantStatus::RevokedConfirmed);
        self.persist_state(session_id, &candidate).await?;
        *state = candidate;
        drop(sessions);
        let _ = self.inner.events.send(SshEvent::BindingRevoked {
            session_id: session_id.to_owned(),
            binding_id: binding.id.clone(),
            status: RevokeStatus::Confirmed,
        });
        Ok(())
    }

    fn spawn_revoke_ack(&self, session_id: String, binding: SshBinding) {
        let service = self.clone();
        tokio::spawn(async move {
            let worker = service.inner.workers.lock().await.get(&binding.id).cloned();
            let Some(worker) = worker else {
                return;
            };
            let acknowledged = matches!(
                worker.client.revoke(&binding.id, binding.epoch).await,
                Ok(ack) if ack.binding_id == binding.id && ack.epoch == binding.epoch
            );
            if acknowledged {
                let _ = service.confirm_revoke_ack(&session_id, &binding).await;
            }
        });
    }
}

struct LocalInteractionBridge {
    service: Weak<SessionSshInner>,
    client_id: Option<u64>,
    interactive: bool,
}

#[async_trait]
impl Interaction for LocalInteractionBridge {
    async fn confirm_host_key(
        &self,
        prompt: HostKeyPrompt,
    ) -> Result<HostKeyDecision, InteractionError> {
        let Some(client_id) = self.client_id else {
            return Err(InteractionError::Unavailable);
        };
        if !self.interactive {
            return Err(InteractionError::Unavailable);
        }
        let response = await_auth_response(
            &self.service,
            client_id,
            prompt.connection_generation,
            prompt.challenge_id.to_string(),
            SshAuthPrompt {
                client_id,
                connection_generation: prompt.connection_generation,
                challenge_id: prompt.challenge_id.to_string(),
                target_id: prompt.target_id,
                kind: SshAuthPromptKind::HostKey,
                detail: SshAuthPromptDetail::HostKey {
                    hostname: prompt.hostname,
                    port: prompt.port,
                    algorithm: prompt.algorithm,
                    fingerprint: prompt.fingerprint,
                    status: format!("{:?}", prompt.status).to_lowercase(),
                },
            },
        )
        .await?;
        match response
            .host_key_decision
            .unwrap_or(SshHostKeyDecision::Reject)
        {
            SshHostKeyDecision::Reject => Ok(HostKeyDecision::Reject),
            SshHostKeyDecision::TrustOnce => Ok(HostKeyDecision::TrustOnce),
            SshHostKeyDecision::TrustAndStore => Ok(HostKeyDecision::TrustAndStore),
        }
    }

    async fn request_secret(&self, prompt: SecretPrompt) -> Result<Secret, InteractionError> {
        let Some(client_id) = self.client_id else {
            return Err(InteractionError::Unavailable);
        };
        if !self.interactive {
            return Err(InteractionError::Unavailable);
        }
        let kind = match prompt.kind {
            SecretKind::Password => SshAuthPromptKind::Password,
            SecretKind::PrivateKeyPassphrase => SshAuthPromptKind::PrivateKeyPassphrase,
        };
        let response = await_auth_response(
            &self.service,
            client_id,
            prompt.connection_generation,
            prompt.challenge_id.to_string(),
            SshAuthPrompt {
                client_id,
                connection_generation: prompt.connection_generation,
                challenge_id: prompt.challenge_id.to_string(),
                target_id: prompt.target_id,
                kind,
                detail: SshAuthPromptDetail::Secret {
                    username: prompt.username,
                    message: prompt.message,
                    allow_remember: prompt.allow_remember,
                },
            },
        )
        .await?;
        let mut response = response;
        let mut secret = response.secret.take().ok_or(InteractionError::Rejected)?;
        let result = if response.remember && prompt.allow_remember {
            Secret::remember(&secret)
        } else {
            Secret::new(&secret)
        };
        secret.zeroize();
        Ok(result)
    }

    async fn request_keyboard_interactive(
        &self,
        prompt: KeyboardInteractivePrompt,
    ) -> Result<Vec<Secret>, InteractionError> {
        let Some(client_id) = self.client_id else {
            return Err(InteractionError::Unavailable);
        };
        if !self.interactive {
            return Err(InteractionError::Unavailable);
        }
        let expected_answers = prompt.questions.len();
        let mut response = await_auth_response(
            &self.service,
            client_id,
            prompt.connection_generation,
            prompt.challenge_id.to_string(),
            SshAuthPrompt {
                client_id,
                connection_generation: prompt.connection_generation,
                challenge_id: prompt.challenge_id.to_string(),
                target_id: prompt.target_id,
                kind: SshAuthPromptKind::KeyboardInteractive,
                detail: SshAuthPromptDetail::KeyboardInteractive {
                    name: prompt.name,
                    instruction: prompt.instruction,
                    questions: prompt
                        .questions
                        .into_iter()
                        .map(|question| SshKeyboardInteractiveQuestion {
                            prompt: question.prompt,
                            echo: question.echo,
                        })
                        .collect(),
                },
            },
        )
        .await?;
        if response.answers.len() != expected_answers {
            return Err(InteractionError::Rejected);
        }
        let mut answers = std::mem::take(&mut response.answers);
        let secrets = answers.iter().map(Secret::new).collect();
        for answer in &mut answers {
            answer.zeroize();
        }
        Ok(secrets)
    }
}

struct WorkerCallbacks {
    service: Weak<SessionSshInner>,
    client_id: Option<u64>,
    session_id: String,
    binding_id: String,
}

#[async_trait]
impl SshClientCallbacks for WorkerCallbacks {
    async fn on_event(&self, event: SshWorkerEvent) {
        if !worker_event_matches_binding(&event, &self.session_id, &self.binding_id) {
            return;
        }
        let Some(service) = self.service.upgrade() else {
            return;
        };
        let event = SshSessionWorkerEvent {
            session_id: self.session_id.clone(),
            binding_id: self.binding_id.clone(),
            event,
        };
        let sender = {
            let mut sinks = service.session_event_sinks.lock().await;
            sinks
                .entry(event.session_id.clone())
                .or_insert_with(|| broadcast::channel(128).0)
                .clone()
        };
        let _ = sender.send(event.clone());
        let _ = service.events.send(SshEvent::Worker(event));
    }

    async fn approve(&self, request: SshApprovalRequest) -> SshApprovalDecision {
        if request.session_id != self.session_id || request.binding_id != self.binding_id {
            return SshApprovalDecision::Deny;
        }
        let Some(service) = self.service.upgrade() else {
            return SshApprovalDecision::Deny;
        };
        let Some(client_id) = self.client_id else {
            return SshApprovalDecision::Deny;
        };
        let (response, receiver) = oneshot::channel();
        {
            let mut waiters = service.approval_waiters.lock().await;
            if waiters
                .insert(
                    request.approval_id.clone(),
                    PendingOperationApproval {
                        client_id,
                        response,
                    },
                )
                .is_some()
            {
                return SshApprovalDecision::Deny;
            }
        }
        let _ = service
            .events
            .send(SshEvent::OperationApproval(SshOperationApproval {
                client_id,
                approval_id: request.approval_id.clone(),
                operation_id: request.operation_id,
                binding_id: request.binding_id,
                session_id: request.session_id,
                operation: request.operation,
                title: request.title,
                detail: request.detail,
            }));
        let approved = tokio::time::timeout(INTERACTION_TIMEOUT, receiver)
            .await
            .ok()
            .and_then(Result::ok)
            .unwrap_or(false);
        service
            .approval_waiters
            .lock()
            .await
            .remove(&request.approval_id);
        if approved {
            SshApprovalDecision::Approve
        } else {
            SshApprovalDecision::Deny
        }
    }
}
fn worker_event_matches_binding(
    event: &SshWorkerEvent,
    session_id: &str,
    binding_id: &str,
) -> bool {
    match event {
        SshWorkerEvent::ApprovalRequired(request) => {
            request.session_id == session_id && request.binding_id == binding_id
        }
        SshWorkerEvent::Operation(record) => {
            record.session_id == session_id && record.binding_id == binding_id
        }
        SshWorkerEvent::ToolProgress { .. } | SshWorkerEvent::ToolNotification { .. } => true,
    }
}

async fn await_auth_response(
    service: &Weak<SessionSshInner>,
    client_id: u64,
    connection_generation: u64,
    challenge_id: String,
    prompt: SshAuthPrompt,
) -> Result<SshAuthResponse, InteractionError> {
    let Some(service) = service.upgrade() else {
        return Err(InteractionError::Unavailable);
    };
    let (response, receiver) = oneshot::channel();
    {
        let mut waiters = service.auth_waiters.lock().await;
        if waiters
            .insert(
                challenge_id.clone(),
                PendingAuthentication {
                    client_id,
                    connection_generation,
                    response,
                },
            )
            .is_some()
        {
            return Err(InteractionError::Unavailable);
        }
    }
    let _ = service.events.send(SshEvent::Authentication(prompt));
    let result = tokio::time::timeout(INTERACTION_TIMEOUT, receiver)
        .await
        .ok()
        .and_then(Result::ok)
        .ok_or(InteractionError::Unavailable);
    service.auth_waiters.lock().await.remove(&challenge_id);
    result
}

fn choose_narrower_target(
    request: &SshGrantRequest,
    selected: Option<&str>,
) -> Result<String, SshServiceError> {
    match (&request.target_id, selected) {
        (Some(requested), Some(selected)) if requested != selected => {
            Err(SshServiceError::GrantExpansion)
        }
        (Some(requested), _) => Ok(requested.clone()),
        (None, Some(selected)) if !selected.trim().is_empty() => Ok(selected.to_owned()),
        (None, _) => Err(SshServiceError::TargetSelectionRequired),
    }
}

fn choose_narrower_root(
    request: &SshGrantRequest,
    selected: Option<&str>,
) -> Result<String, SshServiceError> {
    let root = match (&request.root, selected) {
        (Some(requested), Some(selected)) if remote_path_within(selected, requested) => {
            selected.to_owned()
        }
        (Some(requested), None) => requested.clone(),
        (Some(_), Some(_)) => return Err(SshServiceError::GrantExpansion),
        (None, Some(selected)) if is_absolute_remote_path(selected) => selected.to_owned(),
        (None, _) => return Err(SshServiceError::RootSelectionRequired),
    };
    if !is_absolute_remote_path(&root) {
        return Err(SshServiceError::RootEscape);
    }
    Ok(root)
}

fn choose_narrower_capabilities(
    request: &SshGrantRequest,
    selected: Option<SshCapabilities>,
) -> Result<SshCapabilities, SshServiceError> {
    let capabilities = selected.unwrap_or(request.capabilities);
    if capabilities.is_subset_of(request.capabilities) {
        Ok(capabilities)
    } else {
        Err(SshServiceError::GrantExpansion)
    }
}

fn revoke_authority_tree(
    sessions: &mut HashMap<String, SessionState>,
    binding_id: &str,
) -> Vec<(String, SshBinding, SshGrantScope)> {
    let mut pending = vec![binding_id.to_owned()];
    let mut seen = HashSet::new();
    let mut revoked = Vec::new();
    while let Some(current) = pending.pop() {
        if !seen.insert(current.clone()) {
            continue;
        }
        for state in sessions.values() {
            for (child_id, record) in &state.grants {
                if record.persisted.parent_binding_id.as_deref() == Some(current.as_str()) {
                    pending.push(child_id.clone());
                }
            }
        }
        for (session_id, state) in sessions.iter_mut() {
            let Some(record) = state.grants.get_mut(&current) else {
                continue;
            };
            if record.persisted.binding.revoked {
                continue;
            }
            record.persisted.binding.revoked = true;
            record.persisted.binding.epoch = record.persisted.binding.epoch.saturating_add(1);
            record.persisted.revoke_status = Some(SshGrantStatus::RevokedLocalPending);
            if state.default_binding_id.as_deref() == Some(current.as_str()) {
                state.default_binding_id = None;
            }
            revoked.push((
                session_id.clone(),
                record.persisted.binding.clone(),
                record.persisted.scope,
            ));
        }
    }
    revoked
}

fn resolve_remote_cwd(
    binding: &SshBinding,
    requested: Option<&str>,
) -> Result<String, SshServiceError> {
    let Some(requested) = requested else {
        return Ok(binding.cwd.clone());
    };
    let candidate = if is_absolute_remote_path(requested) {
        requested.to_owned()
    } else {
        format!("{}/{}", binding.cwd.trim_end_matches('/'), requested)
    };
    if remote_path_within(&candidate, &binding.root) {
        Ok(candidate)
    } else {
        Err(SshServiceError::RootEscape)
    }
}

fn is_absolute_remote_path(path: &str) -> bool {
    path == "/"
        || (path.starts_with('/')
            && path
                .split('/')
                .skip(1)
                .all(|part| !part.is_empty() && part != "." && part != ".."))
}

fn remote_path_within(candidate: &str, root: &str) -> bool {
    is_absolute_remote_path(candidate)
        && is_absolute_remote_path(root)
        && (candidate == root
            || candidate
                .strip_prefix(root.trim_end_matches('/'))
                .is_some_and(|suffix| suffix.starts_with('/')))
}

fn shell_command(arguments: &[String]) -> Result<String, SshServiceError> {
    if arguments.is_empty()
        || arguments
            .first()
            .is_some_and(|argument| argument.is_empty())
    {
        return Err(SshServiceError::Configuration(
            "SSH worker command must not be empty".into(),
        ));
    }
    Ok(arguments
        .iter()
        .map(|argument| format!("'{}'", argument.replace('\'', "'\"'\"'")))
        .collect::<Vec<_>>()
        .join(" "))
}
fn load_project_rules(path: &std::path::Path) -> ProjectRuleStore {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(ProjectRuleStore::Loaded)
            .unwrap_or_else(|error| ProjectRuleStore::Invalid(error.to_string())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            ProjectRuleStore::Loaded(ProjectRuleFile::default())
        }
        Err(error) => ProjectRuleStore::Invalid(error.to_string()),
    }
}

fn write_project_rules(
    path: &std::path::Path,
    rules: &ProjectRuleFile,
) -> Result<(), SshServiceError> {
    let parent = path
        .parent()
        .ok_or_else(|| SshServiceError::ProjectRuleStorage("rules path has no parent".into()))?;
    std::fs::create_dir_all(parent)
        .map_err(|error| SshServiceError::ProjectRuleStorage(error.to_string()))?;
    let encoded = serde_json::to_vec_pretty(rules)
        .map_err(|error| SshServiceError::ProjectRuleStorage(error.to_string()))?;
    let temporary = path.with_extension(format!("{}.tmp", Uuid::now_v7()));
    std::fs::write(&temporary, encoded)
        .map_err(|error| SshServiceError::ProjectRuleStorage(error.to_string()))?;
    std::fs::rename(&temporary, path)
        .map_err(|error| SshServiceError::ProjectRuleStorage(error.to_string()))
}

pub(super) fn render_remote_hook_prompt(
    mut prompt_text: String,
    outcome: &SshPostToolHookOutcome,
) -> String {
    for note in &outcome.pre_tool_context {
        append_remote_hook_note(
            &mut prompt_text,
            "PreToolUse context",
            &note.hook_name,
            &note.text,
        );
    }
    let event = if outcome.post_tool_failure {
        "PostToolUseFailure context"
    } else {
        "PostToolUse context"
    };
    for note in &outcome.additional_context {
        append_remote_hook_note(&mut prompt_text, event, &note.hook_name, &note.text);
    }
    for note in &outcome.blocks {
        append_remote_hook_note(
            &mut prompt_text,
            "PostToolUse feedback",
            &note.hook_name,
            &note.text,
        );
    }
    prompt_text
}

fn append_remote_hook_note(prompt_text: &mut String, kind: &str, hook_name: &str, text: &str) {
    if !prompt_text.is_empty() {
        prompt_text.push_str("\n\n");
    }
    use std::fmt::Write;
    let _ = write!(prompt_text, "[Remote {kind}: {hook_name}]\n{text}");
}
fn render_operation_query(
    binding: &SshBinding,
    operation: SshOperationRecord,
    call_id: String,
) -> Result<SshDispatchResult, SshServiceError> {
    if operation.binding_id != binding.id || operation.session_id != binding.session_id {
        return Err(SshServiceError::OperationNotOwned);
    }
    let operation_id = operation.operation_id.clone();
    let invocation = ResolvedSshInvocation {
        binding_id: binding.id.clone(),
        target_id: binding.target_id.clone(),
        session_id: binding.session_id.clone(),
        epoch: binding.epoch,
        cwd: binding.cwd.clone(),
        operation: SshOperation::Read,
        call_id,
    };
    let prompt_text = match operation.result.as_ref() {
        Some(result) => match serde_json::from_value::<ToolRunResult>(result.clone()) {
            Ok(mut result) => {
                let prompt_text = if let Some(outcome) = operation.post_hook.as_ref() {
                    let _ = xai_grok_workspace::workspace_ops::apply_ssh_post_tool_outcome(
                        &mut result,
                        outcome,
                    );
                    render_remote_hook_prompt(result.prompt_text, outcome)
                } else {
                    result.prompt_text
                };
                render_ssh_dispatch_prompt(
                    prompt_text,
                    Some(&result.output),
                    &invocation,
                    &operation_id,
                )
            }
            Err(error) => render_ssh_dispatch_prompt(
                format!(
                    "Remote SSH operation {operation_id} completed, but its clean result could not be decoded: {error}",
                ),
                None,
                &invocation,
                &operation_id,
            ),
        },
        None => {
            let mut prompt_text = match operation.error.as_ref() {
                Some(error) => format!(
                    "Remote SSH operation {operation_id} is {:?}: {}: {}",
                    operation.state, error.code, error.message
                ),
                None => format!(
                    "Remote SSH operation {operation_id} is {:?}.",
                    operation.state
                ),
            };
            if let Some(outcome) = operation.post_hook.as_ref() {
                prompt_text = render_remote_hook_prompt(prompt_text, outcome);
            }
            render_ssh_dispatch_prompt(prompt_text, None, &invocation, &operation_id)
        }
    };
    let mut output = serde_json::to_value(operation).map_err(|error| {
        SshServiceError::Worker(format!("remote operation serialization failed: {error}"))
    })?;
    attach_remote_scope(&mut output, &invocation, &operation_id);
    Ok(SshDispatchResult {
        output,
        prompt_text,
    })
}

fn render_ssh_dispatch_prompt(
    mut prompt_text: String,
    output: Option<&ToolOutput>,
    invocation: &ResolvedSshInvocation,
    operation_id: &str,
) -> String {
    if let Some(ToolOutput::BackgroundTaskStarted(task)) = output {
        let target = serde_json::to_string(&invocation.target_id).unwrap_or_default();
        let task_id = serde_json::to_string(&task.task_id).unwrap_or_default();
        let guidance = format!(
            "This is an SSH background task. Retrieve its remote output with \
             ssh_task_query({{\"target\":{target},\"task_id\":{task_id}}}). \
             Stop it only with ssh_task_cancel({{\"target\":{target},\"task_id\":{task_id}}})."
        );
        if task.retrieval_hint.is_empty() {
            append_model_note(&mut prompt_text, &guidance);
        } else if prompt_text.contains(&task.retrieval_hint) {
            prompt_text = prompt_text.replacen(&task.retrieval_hint, &guidance, 1);
        } else {
            append_model_note(&mut prompt_text, &guidance);
        }
    }
    let scope = remote_scope(invocation, operation_id);
    append_model_note(
        &mut prompt_text,
        &format!("<ssh-remote-scope>{scope}</ssh-remote-scope>"),
    );
    prompt_text
}

fn append_model_note(prompt_text: &mut String, note: &str) {
    if !prompt_text.is_empty() {
        prompt_text.push_str("\n\n");
    }
    prompt_text.push_str(note);
}

fn remote_scope(invocation: &ResolvedSshInvocation, operation_id: &str) -> serde_json::Value {
    serde_json::json!({
        "binding_id": &invocation.binding_id,
        "target_id": &invocation.target_id,
        "session_id": &invocation.session_id,
        "epoch": invocation.epoch,
        "cwd": &invocation.cwd,
        "operation_id": operation_id,
    })
}

fn attach_remote_scope(
    value: &mut serde_json::Value,
    invocation: &ResolvedSshInvocation,
    operation_id: &str,
) {
    let scope = remote_scope(invocation, operation_id);
    if let Some(object) = value.as_object_mut() {
        object.insert("_ssh".to_owned(), scope);
    } else {
        *value = serde_json::json!({
            "value": std::mem::take(value),
            "_ssh": scope,
        });
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn worker_command_preserves_shell_sensitive_arguments() {
        let arguments = [
            "printf".to_owned(),
            "%s|%s".to_owned(),
            "it's a worker path".to_owned(),
            "$HOME \"quoted\"".to_owned(),
        ];
        let output = std::process::Command::new("/bin/sh")
            .args(["-c", &shell_command(&arguments).unwrap()])
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"it's a worker path|$HOME \"quoted\"");
    }

    #[tokio::test]
    async fn embedded_control_rejects_mismatched_interactive_identity() {
        let home = tempfile::tempdir().unwrap();
        let service = SessionSsh::new(home.path().to_owned());
        let control = crate::ssh::SshControlClient::from_service(&service, 7);
        let grant_error = control
            .request(SshControlCommand::ApproveGrant(SshGrantDecision {
                request_id: "request".into(),
                approved: false,
                target_id: None,
                root: None,
                capabilities: None,
                scope: SshGrantScope::CurrentSession,
                make_default: false,
                client_id: 8,
            }))
            .await
            .unwrap_err();
        assert!(matches!(
            grant_error,
            crate::ssh::SshControlClientError::Service(SshServiceError::WrongClient)
        ));
        let auth_error = control
            .request(SshControlCommand::SubmitAuthentication(
                crate::ssh::SshAuthControlResponse {
                    client_id: 8,
                    connection_generation: 1,
                    challenge_id: "challenge".into(),
                    accepted: Some(false),
                    host_key_decision: None,
                    remember: false,
                    secret: None,
                    answers: Vec::new(),
                },
            ))
            .await
            .unwrap_err();
        assert!(matches!(
            auth_error,
            crate::ssh::SshControlClientError::Service(SshServiceError::WrongClient)
        ));
    }

    #[tokio::test]
    async fn headless_worker_never_registers_auth_or_approval_waiters() {
        let home = tempfile::tempdir().unwrap();
        let service = SessionSsh::new(home.path().to_owned());
        let bridge = LocalInteractionBridge {
            service: Arc::downgrade(&service.inner),
            client_id: None,
            interactive: false,
        };
        let error = bridge
            .confirm_host_key(HostKeyPrompt {
                challenge_id: Uuid::now_v7(),
                connection_generation: 1,
                target_id: "target".into(),
                hostname: "host".into(),
                port: 22,
                algorithm: "ssh-ed25519".into(),
                fingerprint: "fingerprint".into(),
                status: xai_grok_ssh::HostKeyStatus::Unknown,
            })
            .await
            .unwrap_err();
        assert_eq!(error, InteractionError::Unavailable);
        assert!(service.inner.auth_waiters.lock().await.is_empty());

        let callbacks = WorkerCallbacks {
            service: Arc::downgrade(&service.inner),
            client_id: None,
            session_id: "session".into(),
            binding_id: "binding".into(),
        };
        assert_eq!(
            callbacks
                .approve(SshApprovalRequest {
                    approval_id: "approval".into(),
                    operation_id: "operation".into(),
                    binding_id: "binding".into(),
                    session_id: "session".into(),
                    operation: SshOperation::Execute,
                    title: "mutate remote workspace".into(),
                    detail: serde_json::Value::Null,
                })
                .await,
            SshApprovalDecision::Deny
        );
        assert!(service.inner.approval_waiters.lock().await.is_empty());
    }

    fn binding(id: &str, session_id: &str, root: &str) -> SshBinding {
        SshBinding {
            id: id.into(),
            session_id: session_id.into(),
            target_id: "target".into(),
            identity: SshHostIdentity {
                hostname: "host".into(),
                port: 22,
                username: "user".into(),
                fingerprint: "fingerprint".into(),
            },
            root: root.into(),
            cwd: root.into(),
            capabilities: SshCapabilities::all(),
            epoch: 1,
            revoked: false,
        }
    }

    #[test]
    fn remote_background_prompt_uses_ssh_task_controls_and_scope() {
        let binding = binding("binding", "session", "/remote/project");
        let invocation = ResolvedSshInvocation {
            binding_id: binding.id.clone(),
            target_id: binding.target_id.clone(),
            session_id: binding.session_id.clone(),
            epoch: binding.epoch,
            cwd: binding.cwd.clone(),
            operation: SshOperation::Execute,
            call_id: "call-background".into(),
        };
        let output = ToolOutput::BackgroundTaskStarted(
            xai_grok_tools::types::output::BackgroundTaskStarted {
                task_id: "bg-remote".into(),
                task_type: "bash".into(),
                output_file: "/remote/project/.groky/tasks/bg-remote".into(),
                status: "running".into(),
                command: "sleep 10".into(),
                summary: "Background task bg-remote started".into(),
                retrieval_hint:
                    "Use get_command_or_subagent_output with task_ids=[\"bg-remote\"] when you need the output."
                        .into(),
                pre_formatted: None,
                pid: None,
            },
        );

        let prompt = render_ssh_dispatch_prompt(
            output.to_prompt_format(),
            Some(&output),
            &invocation,
            "ssh-op-background",
        );

        assert!(prompt.contains(r#"ssh_task_query({"target":"target","task_id":"bg-remote"})"#));
        assert!(prompt.contains(r#"ssh_task_cancel({"target":"target","task_id":"bg-remote"})"#));
        assert!(!prompt.contains("get_command_or_subagent_output"));
        assert!(prompt.contains(r#""operation_id":"ssh-op-background""#));
        assert!(prompt.contains(r#""binding_id":"binding""#));
        assert!(prompt.contains(r#""cwd":"/remote/project""#));
    }

    #[test]
    fn operation_query_rejects_cross_binding_and_redacts_model_prompt() {
        let binding = binding("binding-a", "session-a", "/remote/a");
        let other_binding = self::binding("binding-b", "session-b", "/remote/b");
        let raw = "REMOTE_OPERATION_RAW_20261016";
        let replacement = ToolOutput::Text("REMOTE_OPERATION_REPLACED_20261016".into());
        let result = ToolRunResult {
            output: ToolOutput::Text(raw.into()),
            prompt_text: raw.into(),
            effective_tool_name: None,
        };
        let record = SshOperationRecord {
            operation_id: "ssh-op-query".into(),
            mutation_id: None,
            binding_id: other_binding.id.clone(),
            session_id: other_binding.session_id.clone(),
            operation: SshOperation::Read,
            state: xai_grok_workspace_types::ssh_wire::SshOperationState::Completed,
            result: Some(serde_json::to_value(result).expect("serialize result")),
            post_hook: Some(SshPostToolHookOutcome {
                builtin_replacement: Some(
                    xai_grok_workspace_types::ssh_wire::SshPostToolReplacement {
                        value: serde_json::to_value(replacement).expect("serialize replacement"),
                        run_index: 0,
                    },
                ),
                ..SshPostToolHookOutcome::default()
            }),
            error: None,
        };

        assert!(matches!(
            render_operation_query(&binding, record.clone(), "query-a".into()),
            Err(SshServiceError::OperationNotOwned)
        ));

        let result = render_operation_query(&other_binding, record, "query-b".into())
            .expect("matching binding may render its own operation");
        assert!(
            result
                .prompt_text
                .contains("REMOTE_OPERATION_REPLACED_20261016")
        );
        assert!(!result.prompt_text.contains(raw));
        assert!(
            result.output.to_string().contains(raw),
            "clean operation output remains available to UI consumers"
        );
        assert_eq!(result.output["_ssh"]["operation_id"], "ssh-op-query");
    }

    #[tokio::test]
    async fn grant_resolution_is_exclusive_and_released_on_cancellation() {
        let home = tempfile::tempdir().unwrap();
        let service = SessionSsh::new(home.path().to_owned());
        let request = service
            .request_grant(
                "session",
                None,
                None,
                SshCapabilities::read_only(),
                "inspect a remote project".into(),
                Some(7),
            )
            .await
            .unwrap();
        let decision = SshGrantDecision {
            request_id: request.id.clone(),
            approved: false,
            target_id: None,
            root: None,
            capabilities: None,
            scope: SshGrantScope::CurrentSession,
            make_default: false,
            client_id: 7,
        };
        let claim = service.claim_grant_resolution(&request.id).unwrap();
        assert!(matches!(
            service.approve_grant(decision.clone()).await,
            Err(SshServiceError::RequestResolved)
        ));
        assert_eq!(
            service
                .snapshot_session("session")
                .await
                .pending_requests
                .len(),
            1
        );
        drop(claim);
        assert!(
            service
                .approve_grant(decision.clone())
                .await
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            service.approve_grant(decision).await,
            Err(SshServiceError::UnknownGrantRequest(_))
        ));
        assert!(service.list_targets("session").await.is_empty());
    }

    #[tokio::test]
    async fn saved_remote_rules_belong_to_exact_origin_and_preserve_explicit_default() {
        let home = tempfile::tempdir().unwrap();
        let service = SessionSsh::new(home.path().to_owned());
        let owner = ProjectLocation::Local {
            root: "/local/project".into(),
        };
        service
            .register_project_location("original", None, &owner)
            .await
            .unwrap();
        let first = binding("first", "original", "/remote/repo");
        let mut second = binding("second", "original", "/remote/other");
        second.target_id = "other-host".into();
        let state = SessionState::default();
        service
            .persist_grant_state(
                "original",
                &state,
                &first,
                SshGrantScope::ProjectRule,
                false,
            )
            .await
            .unwrap();
        let restored = SessionSsh::new(home.path().to_owned());
        restored
            .restore_project_rules("resumed", &owner)
            .await
            .unwrap();
        let snapshot = restored.snapshot_session("resumed").await;
        assert_eq!(snapshot.grants[0].binding.root, "/remote/repo");
        assert!(snapshot.grants[0].requires_revalidation);
        assert!(snapshot.default_binding_id.is_none());
        assert!(matches!(
            restored
                .resolve_invocation("resumed", None, None, SshOperation::Read, "read")
                .await,
            Err(SshServiceError::NoDefaultBinding)
        ));
        service
            .persist_grant_state(
                "original",
                &state,
                &second,
                SshGrantScope::ProjectRule,
                true,
            )
            .await
            .unwrap();
        let restored = SessionSsh::new(home.path().to_owned());
        restored
            .restore_project_rules("resumed", &owner)
            .await
            .unwrap();
        let invocation = restored
            .resolve_invocation("resumed", None, None, SshOperation::Read, "default")
            .await
            .unwrap();
        assert_eq!(invocation.target_id, "other-host");
        assert_eq!(invocation.cwd, "/remote/other");
        assert_eq!(restored.list_targets("resumed").await.len(), 2);
        restored
            .restore_project_rules(
                "unrelated",
                &ProjectLocation::Local {
                    root: "/local/other".into(),
                },
            )
            .await
            .unwrap();
        assert!(restored.list_targets("unrelated").await.is_empty());
    }

    #[tokio::test]
    async fn saved_ssh_project_rule_tracks_raw_and_verified_owner_until_revoke() {
        let home = tempfile::tempdir().unwrap();
        let service = SessionSsh::new(home.path().to_owned());
        let raw = ProjectLocation::Ssh {
            target_id: "target".into(),
            root: "/alias/repo".into(),
        };
        let canonical = ProjectLocation::Ssh {
            target_id: "target".into(),
            root: "/canonical/repo".into(),
        };
        service.register_project_location("original", None, &raw).await.unwrap();
        let granted = binding("original-binding", "original", "/canonical/repo");
        service.persist_grant_state(
            "original", &SessionState::default(), &granted, SshGrantScope::ProjectRule, true,
        ).await.unwrap();

        let restored = SessionSsh::new(home.path().to_owned());
        for (session_id, location) in [("raw-open", &raw), ("resumed", &canonical)] {
            restored.restore_project_rules(session_id, location).await.unwrap();
            let invocation = restored.resolve_invocation(
                session_id, None, None, SshOperation::Read, "read",
            ).await.unwrap();
            assert_eq!(invocation.cwd, "/canonical/repo");
        }
        restored.restore_project_rules(
            "other-project",
            &ProjectLocation::Ssh { target_id: "target".into(), root: "/elsewhere".into() },
        ).await.unwrap();
        assert!(restored.list_targets("other-project").await.is_empty());

        restored.remove_project_rule("resumed", &granted).await.unwrap();
        let after_revoke = SessionSsh::new(home.path().to_owned());
        after_revoke.restore_project_rules("reopened", &raw).await.unwrap();
        assert!(matches!(
            after_revoke.resolve_invocation("reopened", None, None, SshOperation::Read, "read").await,
            Err(SshServiceError::NoDefaultBinding)
        ));
    }

    #[tokio::test]
    async fn failed_rule_save_does_not_publish_new_authority_or_default() {
        let home = tempfile::tempdir().unwrap();
        let service = SessionSsh::new(home.path().to_owned());
        let owner = ProjectLocation::Local {
            root: "/local/project".into(),
        };
        service
            .register_project_location("original", None, &owner)
            .await
            .unwrap();
        let original = binding("original", "original", "/remote/original");
        service
            .persist_grant_state(
                "original",
                &SessionState::default(),
                &original,
                SshGrantScope::ProjectRule,
                false,
            )
            .await
            .unwrap();
        // A real rename failure, independent of platform permission semantics.
        std::fs::remove_file(&service.inner.project_rules_path).unwrap();
        std::fs::create_dir(&service.inner.project_rules_path).unwrap();
        let expanded = binding("expanded", "original", "/");
        assert!(
            service
                .persist_grant_state(
                    "original",
                    &SessionState::default(),
                    &expanded,
                    SshGrantScope::ProjectRule,
                    true,
                )
                .await
                .is_err()
        );
        service
            .restore_project_rules("resumed", &owner)
            .await
            .unwrap();
        let snapshot = service.snapshot_session("resumed").await;
        assert!(snapshot.default_binding_id.is_none());
        assert_eq!(snapshot.grants.len(), 1);
        assert_eq!(snapshot.grants[0].binding.root, "/remote/original");
    }

    #[test]
    fn grant_root_can_only_narrow_requested_root() {
        let request = SshGrantRequest {
            id: "request".into(),
            session_id: "session".into(),
            originating_session_id: None,
            target_id: Some("target".into()),
            root: Some("/repo".into()),
            capabilities: SshCapabilities::all(),
            reason: "test".into(),
            verified_identity: None,
            client_id: None,
        };
        assert_eq!(
            choose_narrower_root(&request, Some("/repo/subdir")).unwrap(),
            "/repo/subdir"
        );
        assert!(matches!(
            choose_narrower_root(&request, Some("/other")),
            Err(SshServiceError::GrantExpansion)
        ));
    }

    #[test]
    fn parent_revoke_invalidates_inherited_binding_and_default() {
        let parent = binding("parent", "parent-session", "/repo");
        let child = binding("child", "child-session", "/repo");
        let mut sessions = HashMap::from([
            (
                "parent-session".into(),
                SessionState {
                    grants: HashMap::from([(
                        parent.id.clone(),
                        GrantRecord {
                            persisted: PersistedSshGrant {
                                binding: parent,
                                parent_binding_id: None,
                                requires_revalidation: false,
                                scope: SshGrantScope::CurrentSession,
                                revoke_status: None,
                            },
                        },
                    )]),
                    default_binding_id: Some("parent".into()),
                    pending_requests: HashMap::new(),
                },
            ),
            (
                "child-session".into(),
                SessionState {
                    grants: HashMap::from([(
                        child.id.clone(),
                        GrantRecord {
                            persisted: PersistedSshGrant {
                                binding: child,
                                parent_binding_id: Some("parent".into()),
                                requires_revalidation: true,
                                scope: SshGrantScope::CurrentSession,
                                revoke_status: None,
                            },
                        },
                    )]),
                    default_binding_id: Some("child".into()),
                    pending_requests: HashMap::new(),
                },
            ),
        ]);

        let revoked = revoke_authority_tree(&mut sessions, "parent");
        assert_eq!(revoked.len(), 2);
        for state in sessions.values() {
            assert!(
                state
                    .grants
                    .values()
                    .all(|record| record.persisted.binding.revoked)
            );
            assert_eq!(state.default_binding_id, None);
        }
    }
}
