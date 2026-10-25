use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex, Weak};
use std::time::Duration;

use async_trait::async_trait;
use thiserror::Error;
use zeroize::Zeroize;

use tokio::sync::{Mutex, RwLock, broadcast, oneshot};
use uuid::Uuid;
use xai_grok_ssh::{
    ConfigError, ConnectionLease, ConnectionManager, ConnectionPhase, HostKeyDecision,
    HostKeyPrompt, Interaction, InteractionError, KeyboardInteractivePrompt, Secret, SecretKind,
    SecretPrompt, SshError, SudoInteraction, SudoPasswordPrompt, TargetSource, TargetStore,
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
    SshDirectoryListing, SshDispatchRequest, SshDispatchResult, SshEvent, SshGrantDecision,
    SshGrantRequest, SshGrantScope, SshGrantStatus, SshHostKeyDecision,
    SshKeyboardInteractiveQuestion, SshOperationApproval, SshOperationApprovalDecision,
    SshOperationApprovalScope, SshProjectPreparation, SshSessionWorkerEvent, SshTargetAccess,
    SshTargetCandidate, SshTargetCandidateSource, SshTargetDiscovery, SshTargetStatus,
    SshWorkerInstallDecision, SshWorkerInstallProgress, SshWorkerInstallRequest,
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
    #[error("target_not_found: SSH target `{0}` is not configured")]
    TargetNotFound(String),
    #[error(
        "ambiguous_target: SSH target reference `{reference}` matches multiple configured targets; retry with an exact target_id: {candidate_ids:?}"
    )]
    AmbiguousConfiguredTarget {
        reference: String,
        candidate_ids: Vec<String>,
    },
    #[error("SSH target must be selected by a local user")]
    TargetSelectionRequired,
    #[error("SSH root must be selected by a local user")]
    RootSelectionRequired,
    #[error(
        "SSH grant target inspection requires both a selected root and a browser-verified host identity"
    )]
    InvalidInspectionSelection,
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
    #[error("root SSH commands require a one-time approval")]
    SessionApprovalNotAllowed,
    #[error("SSH worker installation consent is stale or belongs to another client or grant")]
    StaleWorkerInstall,
    #[error("SSH access request was denied by the local user")]
    GrantDenied,
    #[error("SSH access request was cancelled")]
    GrantCancelled,
    #[error("SSH access request failed: {0}")]
    GrantFailed(String),
    #[error("timed out waiting for a local SSH access decision")]
    GrantTimedOut,
    #[error("SSH access requires an interactive local client")]
    InteractiveClientRequired,
    #[error("an SSH access request is already awaiting a local decision for this session")]
    GrantRequestPending,


    #[error("SSH transport: {0}")]
    Transport(String),
    #[error("SSH worker: {0}")]
    Worker(String),
    #[error("SSH native operation: {0}")]
    Native(String),
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
    /// Monotonically changes before local authority is invalidated for a
    /// connection-relevant target mutation.
    target_config_epoch: AtomicU64,
    /// Serializes only target mutation and authority commit points. It is never
    /// held while waiting for SSH, a worker, or human interaction.
    target_commit: Mutex<()>,
    sessions: RwLock<HashMap<String, SessionState>>,
    resolution_claims: std::sync::Mutex<HashSet<String>>,
    workers: Mutex<HashMap<String, Arc<WorkerConnection>>>,
    native_operations: super::native_tasks::NativeOperations,
    worker_locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
    manual_holds: Mutex<HashMap<String, ConnectionLease>>,
    auth_waiters: Mutex<HashMap<String, PendingAuthentication>>,
    sudo_auth_waiters: Mutex<HashMap<String, PendingSudoAuthentication>>,
    sudo_gates: Mutex<HashMap<String, PendingSudoGate>>,
    worker_install_waiters: Mutex<HashMap<String, PendingWorkerInstall>>,
    session_event_sinks: Mutex<HashMap<String, broadcast::Sender<SshSessionWorkerEvent>>>,
    grant_waiters: StdMutex<HashMap<String, PendingToolGrant>>,
    approval_waiters: Mutex<HashMap<String, PendingOperationApproval>>,
    approval_generation: AtomicU64,
    operation_approval_policies: Mutex<Vec<OperationApprovalPolicy>>,
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
        let mut pending_requests = self
            .pending_requests
            .values()
            .filter(|request| !request.awaiting_tool)
            .cloned()
            .collect::<Vec<_>>();
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
    revoked: Arc<AtomicBool>,
}

impl GrantRecord {
    fn new(persisted: PersistedSshGrant) -> Self {
        Self {
            revoked: Arc::new(AtomicBool::new(persisted.binding.revoked)),
            persisted,
        }
    }
}

struct WorkerConnection {
    command: Vec<String>,
    binding: SshBinding,
    client: SshWorkspaceClient,
    client_id: Option<u64>,
    target_epoch: u64,
    // The lease, rather than the worker channel, owns the shared native connection lifetime.
    _lease: ConnectionLease,
}

struct PendingAuthentication {
    target_id: String,
    target_epoch: u64,
    client_id: u64,
    connection_generation: u64,
    response: oneshot::Sender<SshAuthResponse>,
}

struct PendingSudoAuthentication {
    client_id: u64,
    binding: SshBinding,
    target_epoch: u64,
    connection_generation: u64,
    operation_id: String,
    gate_id: String,
    active: Arc<AtomicBool>,
    resolved: Arc<AtomicBool>,
    response: oneshot::Sender<SshAuthResponse>,
}

struct PendingSudoGate {
    client_id: u64,
    binding: SshBinding,
    target_epoch: u64,
    operation_id: String,
    active: Arc<AtomicBool>,
    resolved: Arc<AtomicBool>,
    challenge_id: Arc<StdMutex<Option<String>>>,
}

struct PendingToolGrant {
    session_id: String,
    client_id: u64,
    cancelled: Arc<AtomicBool>,
    response: Option<oneshot::Sender<ToolGrantResolution>>,
    /// Set after grant state commits and before the model's waiter is woken.
    /// The wait guard removes this only after the tool observes the result.
    delivered: Option<(String, String)>,
}

#[derive(Debug, Clone)]
enum ToolGrantResolution {
    Granted(SshBinding),
    Denied,
    Cancelled,
    Failed(String),
    TimedOut,
}

struct PendingOperationApproval {
    client_id: u64,
    binding: SshBinding,
    target_epoch: u64,
    operation: SshOperation,
    /// False for root commands, which can only receive one-time consent.
    allow_session: bool,
    generation: u64,
    response: oneshot::Sender<bool>,
}

#[derive(Clone)]
struct OperationApprovalPolicy {
    client_id: u64,
    session_id: String,
    binding_id: String,
    epoch: u64,
    identity: SshHostIdentity,
    operation: SshOperation,
}

struct ToolGrantWaitGuard {
    service: SessionSsh,
    request_id: String,
    armed: bool,
}

impl ToolGrantWaitGuard {
    fn new(service: SessionSsh, request_id: String) -> Self {
        Self {
            service,
            request_id,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
        self.service
            .inner
            .grant_waiters
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.request_id);
    }
}

impl Drop for ToolGrantWaitGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let request_id = self.request_id.clone();
        let service = self.service.clone();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                service
                    .abandon_tool_grant(&request_id, ToolGrantResolution::Cancelled)
                    .await;
            });
        }
    }
}

struct OperationApprovalWaitGuard {
    service: Weak<SessionSshInner>,
    client_id: u64,
    session_id: String,
    approval_id: String,
    generation: u64,
    armed: bool,
}

impl OperationApprovalWaitGuard {
    fn new(
        service: Weak<SessionSshInner>,
        client_id: u64,
        session_id: String,
        approval_id: String,
        generation: u64,
    ) -> Self {
        Self {
            service,
            client_id,
            session_id,
            approval_id,
            generation,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for OperationApprovalWaitGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let Some(service) = self.service.upgrade() else {
            return;
        };
        let client_id = self.client_id;
        let session_id = std::mem::take(&mut self.session_id);
        let approval_id = std::mem::take(&mut self.approval_id);
        let generation = self.generation;
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                expire_operation_approvals(&service, |current_approval_id, waiter| {
                    current_approval_id == approval_id.as_str()
                        && waiter.client_id == client_id
                        && waiter.binding.session_id.as_str() == session_id.as_str()
                        && waiter.generation == generation
                })
                .await;
            });
        }
    }
}

struct OperationApprovalSubmissionGuard {
    service: Arc<SessionSshInner>,
    client_id: u64,
    session_id: String,
    approval_id: String,
    armed: bool,
}

impl OperationApprovalSubmissionGuard {
    fn new(
        service: Arc<SessionSshInner>,
        client_id: u64,
        session_id: String,
        approval_id: String,
    ) -> Self {
        Self {
            service,
            client_id,
            session_id,
            approval_id,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for OperationApprovalSubmissionGuard {
    fn drop(&mut self) {
        if self.armed {
            notify_operation_approval_expired(
                &self.service,
                self.client_id,
                std::mem::take(&mut self.session_id),
                std::mem::take(&mut self.approval_id),
            );
        }
    }
}

async fn expire_operation_approvals(
    service: &SessionSshInner,
    mut should_expire: impl FnMut(&str, &PendingOperationApproval) -> bool,
) {
    let mut waiters = service.approval_waiters.lock().await;
    // Broadcast delivery is synchronous and cannot re-enter this mutex.
    waiters.retain(|approval_id, waiter| {
        if should_expire(approval_id, waiter) {
            notify_operation_approval_expired(
                service,
                waiter.client_id,
                waiter.binding.session_id.clone(),
                approval_id.clone(),
            );
            false
        } else {
            true
        }
    });
}

fn notify_operation_approval_expired(
    service: &SessionSshInner,
    client_id: u64,
    session_id: String,
    approval_id: String,
) {
    let _ = service.events.send(SshEvent::OperationApprovalExpired {
        client_id,
        session_id,
        approval_id,
    });
}

struct PendingWorkerInstall {
    client_id: u64,
    binding: SshBinding,
    target_epoch: u64,
    response: oneshot::Sender<bool>,
}
#[derive(Clone)]
struct ProjectRegistration {
    location: ProjectLocation,
    session_info: Option<crate::session::info::Info>,
    /// Prevent generic session setup from restoring broader saved authority
    /// after `PrepareProjectOpen` has chosen the exact project binding.
    project_open_prepared: bool,
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
        self.owner_location == *location || self.canonical_owner_location.as_ref() == Some(location)
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
                target_config_epoch: AtomicU64::new(0),
                target_commit: Mutex::new(()),
                sessions: RwLock::new(HashMap::new()),
                resolution_claims: std::sync::Mutex::new(HashSet::new()),
                workers: Mutex::new(HashMap::new()),
                native_operations: Default::default(),
                worker_locks: Mutex::new(HashMap::new()),
                manual_holds: Mutex::new(HashMap::new()),
                auth_waiters: Mutex::new(HashMap::new()),
                sudo_auth_waiters: Mutex::new(HashMap::new()),
                sudo_gates: Mutex::new(HashMap::new()),
                session_event_sinks: Mutex::new(HashMap::new()),
                grant_waiters: StdMutex::new(HashMap::new()),
                approval_waiters: Mutex::new(HashMap::new()),
                approval_generation: AtomicU64::new(0),
                operation_approval_policies: Mutex::new(Vec::new()),
                worker_install_waiters: Mutex::new(HashMap::new()),
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

    fn target_config_epoch(&self) -> u64 {
        self.inner.target_config_epoch.load(Ordering::Acquire)
    }

    fn advance_target_config_epoch(&self) {
        self.inner.target_config_epoch.fetch_add(1, Ordering::AcqRel);
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
        let previous = registrations.get(session_id);
        let session_info = session_info
            .or_else(|| previous.and_then(|registration| registration.session_info.clone()));
        let project_open_prepared = previous.is_some_and(|registration| {
            registration.project_open_prepared && registration.location == *location
        });
        registrations.insert(
            session_id.to_owned(),
            ProjectRegistration {
                location: location.clone(),
                session_info,
                project_open_prepared,
            },
        );
        Ok(())
    }

    async fn mark_project_open_prepared(&self, session_id: &str) {
        if let Some(registration) = self
            .inner
            .project_registrations
            .write()
            .await
            .get_mut(session_id)
        {
            registration.project_open_prepared = true;
        }
    }

    async fn project_open_prepared(&self, session_id: &str) -> bool {
        self.inner
            .project_registrations
            .read()
            .await
            .get(session_id)
            .is_some_and(|registration| registration.project_open_prepared)
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
        if self.project_open_prepared(session_id).await {
            return Ok(());
        }
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
                        worker_bound: false,
                        worker_commands: Vec::new(),
                    },
                    revoked: Arc::new(AtomicBool::new(false)),
                },
            );
        }
        self.persist_state(session_id, &candidate).await?;
        *state = candidate;
        Ok(())
    }

    /// Lists remote directories through native SFTP without creating model-visible
    /// authority or starting a worker. A successful browse retains the existing
    /// manual connection hold for subsequent picker navigation.
    pub async fn browse_project_directories(
        &self,
        target_id: &str,
        path: Option<&str>,
        client_id: u64,
    ) -> Result<SshDirectoryListing, SshServiceError> {
        let target_id = self.canonical_target_id(target_id)?;
        let target_epoch = self.target_config_epoch();
        let lease = self
            .acquire_native(&target_id, Some(client_id), true)
            .await?;
        let listing = super::project_browser::browse(&lease, target_id.clone(), path)
            .await
            .map_err(SshServiceError::Native)?;
        {
            let _commit = self.inner.target_commit.lock().await;
            if self.target_config_epoch() != target_epoch {
                return Err(SshServiceError::StaleInvocation);
            }
            self.inner
                .manual_holds
                .lock()
                .await
                .insert(target_id, lease);
        }
        Ok(listing)
    }

    /// Prepares one child-owned remote project binding or emits the exact,
    /// already verified approval request required to create it. Native
    /// authentication and SFTP validation are deliberately workerless.
    pub async fn prepare_project_open(
        &self,
        session_id: &str,
        source_session_id: Option<&str>,
        target_id: &str,
        root: &str,
        expected_identity: Option<&SshHostIdentity>,
        capabilities: Option<SshCapabilities>,
        client_id: u64,
    ) -> Result<SshProjectPreparation, SshServiceError> {
        self.refresh_external_target_changes().await?;
        let target_id = self.canonical_target_id(target_id)?;
        if root.trim().is_empty() {
            return Err(SshServiceError::RootSelectionRequired);
        }
        let target_epoch = self.target_config_epoch();
        let lease = self
            .acquire_native_after_refresh(&target_id, Some(client_id), true)
            .await?;
        let identity = lease.identity().clone();
        if expected_identity.is_some_and(|expected| expected != &identity) {
            return Err(SshServiceError::IdentityChanged);
        }
        let canonical_root = super::native_files::canonical_root(&lease, root)
            .await
            .map_err(SshServiceError::Native)?;
        let _commit = self.inner.target_commit.lock().await;
        if self.target_config_epoch() != target_epoch {
            return Err(SshServiceError::StaleInvocation);
        }
        let location = ProjectLocation::Ssh {
            target_id: target_id.to_owned(),
            root: canonical_root.clone(),
        };
        self.register_project_location(session_id, None, &location)
            .await?;
        self.mark_project_open_prepared(session_id).await;

        if let Some(source_session_id) = source_session_id {
            if let Some(source) = self
                .matching_live_project_binding(
                    source_session_id,
                    &target_id,
                    &identity,
                    &canonical_root,
                    capabilities,
                )
                .await
            {
                let child_capabilities = capabilities.unwrap_or(source.capabilities);
                let bindings = self
                    .inherit_session(
                        source_session_id,
                        session_id,
                        std::slice::from_ref(&source.id),
                        child_capabilities,
                    )
                    .await?;
                let binding = bindings
                    .into_iter()
                    .next()
                    .ok_or_else(|| SshServiceError::UnknownBinding(source.id.clone()))?;
                return Ok(SshProjectPreparation::Ready(binding));
            }
        }

        if let Some(binding) = self
            .restore_matching_project_rule(
                session_id,
                &location,
                &identity,
                capabilities,
            )
            .await?
        {
            return Ok(SshProjectPreparation::Ready(binding));
        }

        let request = self
            .publish_grant_request(SshGrantRequest {
                id: Uuid::now_v7().to_string(),
                session_id: session_id.to_owned(),
                originating_session_id: None,
                target_id: Some(target_id.to_owned()),
                root: Some(canonical_root),
                capabilities: capabilities.unwrap_or_else(SshCapabilities::all),
                reason: "Open selected remote project".into(),
                verified_identity: Some(identity),
                client_id: Some(client_id),
                awaiting_tool: false,
            })
            .await?;
        Ok(SshProjectPreparation::NeedsApproval(request))
    }

    async fn matching_live_project_binding(
        &self,
        source_session_id: &str,
        target_id: &str,
        identity: &SshHostIdentity,
        canonical_root: &str,
        capabilities: Option<SshCapabilities>,
    ) -> Option<SshBinding> {
        let sessions = self.inner.sessions.read().await;
        let state = sessions.get(source_session_id)?;
        let matches = |binding: &SshBinding| {
            !binding.revoked
                && binding.capabilities.read
                && binding.target_id == target_id
                && binding.identity == *identity
                && binding.root == canonical_root
                && capabilities
                    .map(|requested| requested.is_subset_of(binding.capabilities))
                    .unwrap_or(true)
        };
        if let Some(binding) = state
            .default_binding_id
            .as_ref()
            .and_then(|binding_id| state.grants.get(binding_id))
            .map(|record| &record.persisted.binding)
            .filter(|binding| matches(binding))
        {
            return Some(binding.clone());
        }
        state
            .grants
            .values()
            .map(|record| &record.persisted.binding)
            .filter(|binding| matches(binding))
            .min_by(|left, right| {
                capability_priority(left.capabilities)
                    .cmp(&capability_priority(right.capabilities))
                    .then_with(|| left.id.cmp(&right.id))
            })
            .cloned()
    }

    async fn restore_matching_project_rule(
        &self,
        session_id: &str,
        location: &ProjectLocation,
        identity: &SshHostIdentity,
        capabilities: Option<SshCapabilities>,
    ) -> Result<Option<SshBinding>, SshServiceError> {
        let rule = {
            let rules = self.inner.project_rules.lock().await;
            let file = match &*rules {
                ProjectRuleStore::Loaded(file) => file,
                ProjectRuleStore::Invalid(error) => {
                    return Err(SshServiceError::ProjectRuleStorage(error.clone()));
                }
            };
            choose_matching_project_rule(file, location, identity, capabilities).cloned()
        };
        let Some(rule) = rule else {
            return Ok(None);
        };
        let binding_capabilities = capabilities.unwrap_or(rule.capabilities);
        let scope = if binding_capabilities == rule.capabilities {
            SshGrantScope::ProjectRule
        } else {
            SshGrantScope::CurrentSession
        };
        let binding = SshBinding {
            id: Uuid::now_v7().to_string(),
            session_id: session_id.to_owned(),
            target_id: rule.target_id.clone(),
            identity: rule.identity.clone(),
            root: rule.root.clone(),
            cwd: rule.cwd.clone(),
            capabilities: binding_capabilities,
            epoch: 1,
            revoked: false,
        };
        let persisted = PersistedSshGrant {
            binding: binding.clone(),
            parent_binding_id: None,
            requires_revalidation: false,
            scope,
            revoke_status: None,
            worker_bound: false,
            worker_commands: Vec::new(),
        };
        let mut sessions = self.inner.sessions.write().await;
        let state = sessions.entry(session_id.to_owned()).or_default();
        let mut candidate = state.clone();
        if rule.make_default
            && scope == SshGrantScope::ProjectRule
            && candidate.default_binding_id.is_none()
        {
            candidate.default_binding_id = Some(binding.id.clone());
        }
        candidate
            .grants
            .insert(binding.id.clone(), GrantRecord::new(persisted));
        self.persist_state(session_id, &candidate).await?;
        *state = candidate;
        Ok(Some(binding))
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
                let targets = self.list_configured_targets().await?;
                let encoded = serde_json::to_string(&targets)
                    .map_err(|error| SshServiceError::Configuration(error.to_string()))?;
                Ok(SshControlReply::ConfiguredTargets(encoded))
            }
            SshControlCommand::UpdateTarget {
                expected,
                replacement,
            } => Ok(SshControlReply::TargetUpdated(
                self.update_target(expected, replacement).await?,
            )),
            SshControlCommand::RemoveTarget { expected } => Ok(SshControlReply::TargetRemoved(
                self.remove_target(expected).await?,
            )),
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
                selected_root,
                expected_identity,
            } => Ok(SshControlReply::GrantRequested(
                self.inspect_grant_target(
                    &request_id,
                    target_id,
                    selected_root,
                    expected_identity,
                    client_id,
                )
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
            SshControlCommand::CancelGrant {
                session_id,
                request_id,
            } => {
                self.cancel_grant(&session_id, &request_id, client_id).await?;
                Ok(SshControlReply::GrantCancelled { request_id })
            }
            SshControlCommand::FailGrant {
                session_id,
                request_id,
                error,
            } => {
                self.fail_grant(&session_id, &request_id, client_id, error)
                    .await?;
                Ok(SshControlReply::GrantFailed { request_id })
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
            SshControlCommand::BrowseProjectDirectories { target_id, path } => {
                Ok(SshControlReply::ProjectDirectories(
                    self.browse_project_directories(&target_id, path.as_deref(), client_id)
                        .await?,
                ))
            }
            SshControlCommand::PrepareProjectOpen {
                session_id,
                source_session_id,
                target_id,
                root,
                expected_identity,
                capabilities,
            } => Ok(SshControlReply::ProjectPrepared(
                self.prepare_project_open(
                    &session_id,
                    source_session_id.as_deref(),
                    &target_id,
                    &root,
                    expected_identity.as_ref(),
                    capabilities,
                    client_id,
                )
                .await?,
            )),
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
                self.connection_status(&target_id).await?,
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
                match self.submit_operation_approval(decision).await {
                    Ok(()) => Ok(SshControlReply::OperationApprovalAccepted),
                    Err(SshServiceError::StaleOperationApproval) => {
                        Ok(SshControlReply::OperationApprovalExpired)
                    }
                    Err(error) => Err(error),
                }
            }
            SshControlCommand::ResetOperationApprovals {
                session_id,
                binding_id,
            } => {
                self.reset_operation_approvals(&session_id, &binding_id, client_id)
                    .await?;
                Ok(SshControlReply::OperationApprovalsReset)
            }

            SshControlCommand::SubmitWorkerInstall(decision) => {
                if decision.client_id != client_id {
                    return Err(SshServiceError::WrongClient);
                }
                self.submit_worker_install(decision).await?;
                Ok(SshControlReply::WorkerInstallAccepted)
            }
        }
    }

    /// Re-read all persisted and imported targets, invalidating active authority
    /// whenever an external SSH configuration change alters an effective native
    /// connection identity or makes it unresolvable.
    pub async fn list_configured_targets(
        &self,
    ) -> Result<Vec<xai_grok_ssh::SshTarget>, SshServiceError> {
        let targets = self
            .inner
            .targets
            .list()
            .map_err(|error| SshServiceError::Configuration(error.to_string()))?;
        self.invalidate_changed_target_authority_inner().await?;
        Ok(targets)
    }

    /// Resolve externally supplied target text before it can enter persisted
    /// request state or an authority comparison. This never opens a connection.
    fn canonical_target_id(&self, reference: &str) -> Result<String, SshServiceError> {
        self.inner
            .targets
            .canonical_id(reference)
            .map_err(|error| match error {
                ConfigError::TargetNotFound(_) => SshServiceError::TargetNotFound(reference.into()),
                ConfigError::AmbiguousTarget {
                    reference,
                    candidate_ids,
                } => SshServiceError::AmbiguousConfiguredTarget {
                    reference,
                    candidate_ids,
                },
                error => SshServiceError::Configuration(error.to_string()),
            })
    }

    /// Safely update a manual target from its UI snapshot. A label-only change
    /// retains active access, while any connection or worker setting change
    /// disconnects the target and revokes its grants before returning.
    pub async fn update_target(
        &self,
        expected: xai_grok_ssh::SshTarget,
        replacement: xai_grok_ssh::SshTarget,
    ) -> Result<xai_grok_ssh::SshTarget, SshServiceError> {
        let connection_changed = target_connection_settings_changed(&expected, &replacement);
        let updated = {
            let _commit = self.inner.target_commit.lock().await;
            let updated = self
                .inner
                .targets
                .update(expected, replacement)
                .map_err(|error| SshServiceError::Configuration(error.to_string()))?;
            if connection_changed {
                self.advance_target_config_epoch();
            }
            updated
        };
        if connection_changed {
            self.invalidate_target_authority_inner(&updated.id).await?;
        }
        Ok(updated)
    }

    /// Safely remove a manual target from its UI snapshot and immediately
    /// invalidate every connection and grant that names it.
    pub async fn remove_target(
        &self,
        expected: xai_grok_ssh::SshTarget,
    ) -> Result<xai_grok_ssh::SshTarget, SshServiceError> {
        let removed = {
            let _commit = self.inner.target_commit.lock().await;
            let removed = self
                .inner
                .targets
                .remove_expected(expected)
                .map_err(|error| SshServiceError::Configuration(error.to_string()))?;
            self.advance_target_config_epoch();
            removed
        };
        self.invalidate_target_authority_inner(&removed.id).await?;
        Ok(removed)
    }

    /// Check externally managed OpenSSH files before native acquisition. An
    /// already-running worker must never survive a changed effective target.
    async fn refresh_external_target_changes(&self) -> Result<(), SshServiceError> {
        self.invalidate_changed_target_authority_inner().await
    }

    async fn invalidate_changed_target_authority_inner(&self) -> Result<(), SshServiceError> {
        let changed = self.inner.connections.invalidate_changed_targets().await;
        if changed.is_empty() {
            return Ok(());
        }
        {
            let _commit = self.inner.target_commit.lock().await;
            self.advance_target_config_epoch();
        }
        for target_id in changed {
            self.invalidate_target_authority_inner(&target_id).await?;
        }
        Ok(())
    }

    /// Returns only active grants. It remains the grant-only internal listing
    /// used by authority checks and management callers.
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

    /// Discover configured target metadata safe for model output, paired only
    /// with existing grants from `session_id`. Discovery neither acquires a
    /// connection nor creates authority.
    pub async fn discover_targets(
        &self,
        session_id: &str,
    ) -> Result<SshTargetDiscovery, SshServiceError> {
        let configured = self.list_configured_targets().await?;
        let mut access_by_target = HashMap::new();
        for access in self.list_targets(session_id).await {
            access_by_target
                .entry(access.target_id.clone())
                .or_insert_with(Vec::new)
                .push(access);
        }
        let mut targets = configured
            .into_iter()
            .map(|target| {
                let source = match target.source {
                    TargetSource::User => SshTargetCandidateSource::Manual,
                    TargetSource::Imported { .. } => SshTargetCandidateSource::Imported,
                };
                SshTargetCandidate {
                    access: access_by_target.remove(&target.id).unwrap_or_default(),
                    target_id: target.id,
                    label: target.label,
                    host: target.host,
                    source,
                }
            })
            .collect::<Vec<_>>();
        targets.sort_by(|left, right| left.target_id.cmp(&right.target_id));
        Ok(SshTargetDiscovery { targets })
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
            if persisted.binding.revoked && !persisted.worker_bound {
                persisted.revoke_status = Some(SshGrantStatus::RevokedConfirmed);
            }
            grants.insert(persisted.binding.id.clone(), GrantRecord::new(persisted));
        }
        let pending_requests = state
            .pending_requests
            .into_iter()
            .map(|mut request| {
                request.verified_identity = None;
                request.client_id = None;
                request.awaiting_tool = false;
                (request.id.clone(), request)
            })
            .collect();
        let mut sessions = self.inner.sessions.write().await;
        if let Some(previous) = sessions.get(&session_id) {
            for grant in previous.grants.values() {
                grant.revoked.store(true, Ordering::Release);
            }
        }
        sessions.insert(
            session_id.clone(),
            SessionState {
                grants,
                default_binding_id: state.default_binding_id,
                pending_requests,
            },
        );
        drop(sessions);
        self.inner
            .grant_waiters
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|_, waiter| waiter.session_id != session_id);
        expire_operation_approvals(&self.inner, |_, waiter| {
            waiter.binding.session_id.as_str() == session_id.as_str()
        })
        .await;
        retire_sudo_gates(
            &self.inner,
            |gate| gate.binding.session_id.as_str() == session_id.as_str(),
            "Root password entry was cancelled",
        )
        .await;
        self.inner
            .operation_approval_policies
            .lock()
            .await
            .retain(|policy| policy.session_id != session_id);
        self.inner
            .worker_install_waiters
            .lock()
            .await
            .retain(|_, waiter| waiter.binding.session_id != session_id);
    }

    /// Removes ephemeral approvals and unanswered interaction waiters owned by
    /// a disconnected local client. Durable SSH grants are intentionally not
    /// affected.
    pub async fn clear_client_interactions(&self, client_id: u64) {
        expire_operation_approvals(&self.inner, |_, waiter| waiter.client_id == client_id).await;
        retire_sudo_gates(
            &self.inner,
            |gate| gate.client_id == client_id,
            "Root password entry was cancelled",
        )
        .await;
        self.inner
            .operation_approval_policies
            .lock()
            .await
            .retain(|policy| policy.client_id != client_id);
        self.inner
            .auth_waiters
            .lock()
            .await
            .retain(|_, waiter| waiter.client_id != client_id);
        self.inner
            .worker_install_waiters
            .lock()
            .await
            .retain(|_, waiter| waiter.client_id != client_id);
        let request_ids = {
            let waiters = self
                .inner
                .grant_waiters
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            waiters
                .iter()
                .filter_map(|(request_id, waiter)| {
                    (waiter.client_id == client_id).then(|| request_id.clone())
                })
                .collect::<Vec<_>>()
        };
        for request_id in request_ids {
            self.abandon_tool_grant(&request_id, ToolGrantResolution::Cancelled)
                .await;
        }
    }

    /// Removes all nonpersistent approval state for a terminal session close.
    pub async fn clear_session_interactions(&self, session_id: &str) {
        expire_operation_approvals(&self.inner, |_, waiter| {
            waiter.binding.session_id.as_str() == session_id
        })
        .await;
        retire_sudo_gates(
            &self.inner,
            |gate| gate.binding.session_id == session_id,
            "Root password entry was cancelled",
        )
        .await;
        self.inner
            .operation_approval_policies
            .lock()
            .await
            .retain(|policy| policy.session_id != session_id);
        self.inner
            .worker_install_waiters
            .lock()
            .await
            .retain(|_, waiter| waiter.binding.session_id != session_id);
        let request_ids = {
            let waiters = self
                .inner
                .grant_waiters
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            waiters
                .iter()
                .filter_map(|(request_id, waiter)| {
                    (waiter.session_id == session_id).then(|| request_id.clone())
                })
                .collect::<Vec<_>>()
        };
        for request_id in request_ids {
            self.abandon_tool_grant(&request_id, ToolGrantResolution::Cancelled)
                .await;
        }
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
        let target_id = target_id
            .as_deref()
            .map(|reference| self.canonical_target_id(reference))
            .transpose()?;
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
            awaiting_tool: false,

        };
        self.publish_grant_request(request).await
    }

    /// Publishes a model-originated grant request and waits for its exact human
    /// decision. Unlike [`Self::request_grant`], this does not return a pending
    /// request to the model.
    pub async fn request_tool_grant(
        &self,
        session_id: impl Into<String>,
        target_id: Option<String>,
        root: Option<String>,
        capabilities: SshCapabilities,
        reason: String,
        client_id: Option<u64>,
        cancellation: Option<tokio_util::sync::CancellationToken>,
    ) -> Result<SshBinding, SshServiceError> {
        let client_id = client_id.ok_or(SshServiceError::InteractiveClientRequired)?;
        if cancellation
            .as_ref()
            .is_some_and(|token| token.is_cancelled())
        {
            return Err(SshServiceError::GrantCancelled);
        }
        let target_id = target_id
            .as_deref()
            .map(|reference| self.canonical_target_id(reference))
            .transpose()?;
        let request = SshGrantRequest {
            id: Uuid::now_v7().to_string(),
            session_id: session_id.into(),
            originating_session_id: None,
            target_id,
            root,
            capabilities,
            reason,
            verified_identity: None,
            client_id: Some(client_id),
            awaiting_tool: true,
        };
        let receiver = self.register_tool_grant_waiter(&request).await?;
        let mut guard = ToolGrantWaitGuard::new(self.clone(), request.id.clone());
        if let Err(error) = self.publish_tool_grant_request(request.clone()).await {
            self.abandon_tool_grant(&request.id, ToolGrantResolution::Cancelled).await;
            guard.disarm();
            return Err(error);
        }
        let resolution = if let Some(cancellation) = cancellation {
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => {
                    self.abandon_tool_grant(&request.id, ToolGrantResolution::Cancelled).await;
                    guard.disarm();
                    return Err(SshServiceError::GrantCancelled);
                }
                result = tokio::time::timeout(INTERACTION_TIMEOUT, receiver) => match result {
                    Ok(Ok(resolution)) => resolution,
                    Ok(Err(_)) => ToolGrantResolution::Cancelled,
                    Err(_) => {
                        self.abandon_tool_grant(&request.id, ToolGrantResolution::TimedOut).await;
                        guard.disarm();
                        return Err(SshServiceError::GrantTimedOut);
                    }
                },
            }
        } else {
            match tokio::time::timeout(INTERACTION_TIMEOUT, receiver).await {
                Ok(Ok(resolution)) => resolution,
                Ok(Err(_)) => ToolGrantResolution::Cancelled,
                Err(_) => {
                    self.abandon_tool_grant(&request.id, ToolGrantResolution::TimedOut).await;
                    guard.disarm();
                    return Err(SshServiceError::GrantTimedOut);
                }
            }
        };
        guard.disarm();
        match resolution {
            ToolGrantResolution::Granted(binding) => Ok(binding),
            ToolGrantResolution::Denied => Err(SshServiceError::GrantDenied),
            ToolGrantResolution::Cancelled => Err(SshServiceError::GrantCancelled),
            ToolGrantResolution::Failed(error) => Err(SshServiceError::GrantFailed(error)),
            ToolGrantResolution::TimedOut => Err(SshServiceError::GrantTimedOut),
        }
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
            awaiting_tool: false,

        })
        .await
    }

    async fn publish_grant_request(
        &self,
        request: SshGrantRequest,
    ) -> Result<SshGrantRequest, SshServiceError> {
        self.record_grant_request(&request).await?;
        let _ = self
            .inner
            .events
            .send(SshEvent::GrantRequested(request.clone()));
        Ok(request)
    }

    async fn publish_tool_grant_request(
        &self,
        request: SshGrantRequest,
    ) -> Result<(), SshServiceError> {
        let mut sessions = self.inner.sessions.write().await;
        let state = sessions.entry(request.session_id.clone()).or_default();
        let mut candidate = state.clone();
        candidate.pending_requests.insert(request.id.clone(), request.clone());
        self.persist_state(&request.session_id, &candidate).await?;
        // Publication and cancellation share this lock: a detached client cannot
        // leave a newly published prompt after its waiter has already been cleared.
        let waiters = self.inner.grant_waiters.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !waiters.get(&request.id).is_some_and(|waiter| {
            !waiter.cancelled.load(Ordering::Acquire)
                && waiter.response.as_ref().is_some_and(|response| !response.is_closed())
        }) {
            return Err(SshServiceError::GrantCancelled);
        }
        *state = candidate;
        self.inner.events.send(SshEvent::GrantRequested(request))
            .map(|_| ())
            .map_err(|_| SshServiceError::InteractiveClientRequired)
    }

    async fn record_grant_request(&self, request: &SshGrantRequest) -> Result<(), SshServiceError> {
        self.inner
            .sessions
            .write()
            .await
            .entry(request.session_id.clone())
            .or_default()
            .pending_requests
            .insert(request.id.clone(), request.clone());
        self.persist_registered_session(&request.session_id).await
    }

    async fn register_tool_grant_waiter(
        &self,
        request: &SshGrantRequest,
    ) -> Result<oneshot::Receiver<ToolGrantResolution>, SshServiceError> {
        let client_id = request.client_id.ok_or(SshServiceError::InteractiveClientRequired)?;
        let (response, receiver) = oneshot::channel();
        let waiter = PendingToolGrant {
            session_id: request.session_id.clone(),
            client_id,
            cancelled: Arc::new(AtomicBool::new(false)),
            response: Some(response),
            delivered: None,
        };
        let mut waiters = self
            .inner
            .grant_waiters
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if waiters
            .values()
            .any(|pending| pending.session_id == request.session_id)
        {
            return Err(SshServiceError::GrantRequestPending);
        }
        if waiters.insert(request.id.clone(), waiter).is_some() {
            return Err(SshServiceError::RequestResolved);
        }
        Ok(receiver)
    }

    async fn remove_pending_grant(&self, request: &SshGrantRequest) -> Result<(), SshServiceError> {
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
        Ok(())
    }

    async fn finish_tool_grant(
        &self,
        request_id: &str,
        resolution: ToolGrantResolution,
    ) -> bool {
        let (response, retained_delivery) = {
            let mut waiters = self
                .inner
                .grant_waiters
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match &resolution {
                ToolGrantResolution::Granted(binding) => {
                    if waiters
                        .get(request_id)
                        .is_some_and(|waiter| waiter.cancelled.load(Ordering::Acquire))
                    {
                        waiters.remove(request_id);
                        return false;
                    }
                    let Some(waiter) = waiters.get_mut(request_id) else {
                        return false;
                    };
                    waiter.delivered = Some((binding.session_id.clone(), binding.id.clone()));
                    (waiter.response.take(), true)
                }
                _ => (
                    waiters
                        .remove(request_id)
                        .map(|waiter| waiter.response)
                        .unwrap_or(None),
                    false,
                ),
            }
        };
        let sent = response.is_some_and(|response| response.send(resolution).is_ok());
        if !sent && retained_delivery {
            self.inner
                .grant_waiters
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(request_id);
        }
        sent
    }

    async fn tool_grant_cancelled(&self, request_id: &str) -> bool {
        self.inner
            .grant_waiters
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(request_id)
            .is_some_and(|waiter| waiter.cancelled.load(Ordering::Acquire))
    }

    async fn abandon_tool_grant(&self, request_id: &str, resolution: ToolGrantResolution) {
        let delivered = {
            let mut waiters = self
                .inner
                .grant_waiters
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let Some(waiter) = waiters.get_mut(request_id) else {
                return;
            };
            waiter.cancelled.store(true, Ordering::Release);
            let delivered = waiter.delivered.take();
            if delivered.is_some() {
                waiters.remove(request_id);
            }
            delivered
        };
        if let Some((session_id, binding_id)) = delivered {
            let _ = self.revoke_binding(&session_id, &binding_id).await;
            return;
        }
        let Ok(_claim) = self.claim_grant_resolution(request_id) else {
            return;
        };
        let Ok(request) = self.pending_request(request_id).await else {
            let _ = self.finish_tool_grant(request_id, resolution).await;
            return;
        };
        if !request.awaiting_tool {
            return;
        }
        if self.remove_pending_grant(&request).await.is_ok() {
            let event = match &resolution {
                ToolGrantResolution::Cancelled => SshEvent::GrantCancelled {
                    request_id: request.id.clone(),
                    session_id: request.session_id.clone(),
                    client_id: request.client_id.unwrap_or_default(),
                },
                ToolGrantResolution::Failed(error) => SshEvent::GrantFailed {
                    request_id: request.id.clone(),
                    session_id: request.session_id.clone(),
                    client_id: request.client_id.unwrap_or_default(),
                    error: error.clone(),
                },
                ToolGrantResolution::Granted(_)
                | ToolGrantResolution::Denied
                | ToolGrantResolution::TimedOut => SshEvent::GrantResolved {
                    request_id: request.id.clone(),
                    approved: false,
                    binding: None,
                },
            };
            let _ = self.inner.events.send(event);
        }
        let _ = self.finish_tool_grant(request_id, resolution).await;
    }

    /// Cancel one pending request only when the caller owns its exact session,
    /// client, and request ID. Cancellation is terminal and never becomes a
    /// generic denied decision.
    pub async fn cancel_grant(
        &self,
        session_id: &str,
        request_id: &str,
        client_id: u64,
    ) -> Result<(), SshServiceError> {
        let request = self.pending_request(request_id).await?;
        self.check_terminal_grant_owner(&request, session_id, client_id)?;
        let _claim = self.claim_grant_resolution(request_id)?;
        self.remove_pending_grant(&request).await?;
        let _ = self.inner.events.send(SshEvent::GrantCancelled {
            request_id: request.id.clone(),
            session_id: request.session_id.clone(),
            client_id,
        });
        if request.awaiting_tool {
            let _ = self
                .finish_tool_grant(&request.id, ToolGrantResolution::Cancelled)
                .await;
        }
        Ok(())
    }

    /// Fail one pending request after a local inspection could not complete.
    /// The supplied diagnostic is delivered to the original waiting tool and
    /// is intentionally distinct from the user's explicit denial.
    pub async fn fail_grant(
        &self,
        session_id: &str,
        request_id: &str,
        client_id: u64,
        error: String,
    ) -> Result<(), SshServiceError> {
        let error = error.trim().to_owned();
        if error.is_empty() {
            return Err(SshServiceError::GrantFailed(
                "local SSH inspection failed without a diagnostic".to_owned(),
            ));
        }
        let request = self.pending_request(request_id).await?;
        self.check_terminal_grant_owner(&request, session_id, client_id)?;
        let _claim = self.claim_grant_resolution(request_id)?;
        self.remove_pending_grant(&request).await?;
        let _ = self.inner.events.send(SshEvent::GrantFailed {
            request_id: request.id.clone(),
            session_id: request.session_id.clone(),
            client_id,
            error: error.clone(),
        });
        if request.awaiting_tool {
            let _ = self
                .finish_tool_grant(&request.id, ToolGrantResolution::Failed(error))
                .await;
        }
        Ok(())
    }

    /// Acquires only the native connection required for a user to inspect the
    /// actual authenticated identity before deciding a grant. It does not create
    /// a binding and does not expose a worker to a model.
    pub async fn inspect_grant_target(
        &self,
        request_id: &str,
        target_id: String,
        selected_root: Option<String>,
        expected_identity: Option<SshHostIdentity>,
        client_id: u64,
    ) -> Result<SshGrantRequest, SshServiceError> {
        self.refresh_external_target_changes().await?;
        let request = self.pending_request(request_id).await?;
        self.check_request_client(&request, client_id)?;
        let selected_target_id = self.canonical_target_id(&target_id)?;
        let target_id = choose_narrower_target(&request, Some(&selected_target_id))?;
        match (selected_root.as_deref(), expected_identity.as_ref()) {
            (None, None) | (Some(_), Some(_)) => {}
            _ => return Err(SshServiceError::InvalidInspectionSelection),
        }
        if selected_root.as_deref().is_some_and(|root| root.trim().is_empty()) {
            return Err(SshServiceError::RootSelectionRequired);
        }

        let target_epoch = self.target_config_epoch();
        let lease = self
            .acquire_native_after_refresh(target_id.as_str(), Some(client_id), true)
            .await?;
        let identity = lease.identity().clone();
        ensure_inspection_identity(&request, expected_identity.as_ref(), &identity)?;
        let canonical_requested_root = match request.root.as_deref() {
            Some(root) => Some(
                super::native_files::canonical_root(&lease, root)
                    .await
                    .map_err(SshServiceError::Native)?,
            ),
            None => None,
        };
        let canonical_selected_root = match selected_root.as_deref() {
            Some(root) => Some(
                super::native_files::canonical_root(&lease, root)
                    .await
                    .map_err(SshServiceError::Native)?,
            ),
            None => None,
        };
        ensure_inspection_root_within_limit(
            canonical_selected_root.as_deref(),
            canonical_requested_root.as_deref(),
        )?;
        drop(lease);

        self.finish_grant_inspection(
            &request,
            target_id,
            canonical_selected_root.or(canonical_requested_root),
            identity,
            target_epoch,
        )
        .await
    }

    async fn finish_grant_inspection(
        &self,
        request: &SshGrantRequest,
        target_id: String,
        root: Option<String>,
        identity: SshHostIdentity,
        target_epoch: u64,
    ) -> Result<SshGrantRequest, SshServiceError> {
        let _commit = self.inner.target_commit.lock().await;
        if self.target_config_epoch() != target_epoch {
            return Err(SshServiceError::StaleInvocation);
        }
        ensure_inspection_identity(request, None, &identity)?;
        let updated = SshGrantRequest {
            target_id: Some(target_id),
            root,
            verified_identity: Some(identity),
            ..request.clone()
        };
        let mut sessions = self.inner.sessions.write().await;
        let state = sessions
            .get_mut(&request.session_id)
            .ok_or_else(|| SshServiceError::UnknownGrantRequest(request.id.clone()))?;
        let current = state
            .pending_requests
            .get(&request.id)
            .ok_or_else(|| SshServiceError::UnknownGrantRequest(request.id.clone()))?;
        if current != request {
            return Err(SshServiceError::RequestResolved);
        }
        let mut candidate = state.clone();
        candidate
            .pending_requests
            .insert(updated.id.clone(), updated.clone());
        self.persist_state(&updated.session_id, &candidate).await?;
        *state = candidate;
        // Publish while the request state remains locked so a concurrent denial
        // cannot publish GrantResolved before this inspection update.
        let _ = self
            .inner
            .events
            .send(SshEvent::GrantRequested(updated.clone()));
        Ok(updated)
    }

    /// Human-only grant completion. Identity and canonical root are inspected
    /// over native SSH/SFTP; granting authority never deploys or starts a worker.
    pub async fn approve_grant(
        &self,
        decision: SshGrantDecision,
    ) -> Result<Option<SshBinding>, SshServiceError> {
        self.refresh_external_target_changes().await?;
        let request = self.pending_request(&decision.request_id).await?;
        self.check_request_client(&request, decision.client_id)?;
        let _claim = self.claim_grant_resolution(&decision.request_id)?;
        if request.awaiting_tool && self.tool_grant_cancelled(&request.id).await {
            self.remove_pending_grant(&request).await?;
            let _ = self.inner.events.send(SshEvent::GrantCancelled {
                request_id: request.id.clone(),
                session_id: request.session_id.clone(),
                client_id: request.client_id.unwrap_or_default(),
            });
            let _ = self
                .finish_tool_grant(&request.id, ToolGrantResolution::Cancelled)
                .await;
            return Ok(None);
        }
        if !decision.approved {
            self.remove_pending_grant(&request).await?;
            let _ = self.inner.events.send(SshEvent::GrantResolved {
                request_id: request.id.clone(),
                approved: false,
                binding: None,
            });
            if request.awaiting_tool {
                let _ = self
                    .finish_tool_grant(&request.id, ToolGrantResolution::Denied)
                    .await;
            }
            return Ok(None);
        }

        let selected_target_id = decision
            .target_id
            .as_deref()
            .map(|reference| self.canonical_target_id(reference))
            .transpose()?;
        let target_id = choose_narrower_target(&request, selected_target_id.as_deref())?;
        let root = choose_narrower_root(&request, decision.root.as_deref())?;
        let capabilities = choose_narrower_capabilities(&request, decision.capabilities)?;
        let target_epoch = self.target_config_epoch();
        let lease = self
            .acquire_native_after_refresh(&target_id, Some(decision.client_id), true)
            .await?;
        let identity = lease.identity().clone();
        if let Some(inspected) = &request.verified_identity {
            if inspected != &identity {
                return Err(SshServiceError::IdentityChanged);
            }
        }
        let canonical_root = super::native_files::canonical_root(&lease, &root)
            .await
            .map_err(SshServiceError::Native)?;
        if let Some(requested_root) = request.root.as_deref() {
            let within = if request.verified_identity.is_some() {
                // Inspection/preparation returned this canonical root for explicit consent.
                remote_path_within(&canonical_root, requested_root)
            } else if requested_root == root {
                true
            } else {
                let canonical_requested = super::native_files::canonical_root(&lease, requested_root)
                    .await.map_err(SshServiceError::Native)?;
                remote_path_within(&canonical_root, &canonical_requested)
            };
            if !within {
                return Err(SshServiceError::GrantExpansion);
            }
        }
        if request.awaiting_tool && self.tool_grant_cancelled(&request.id).await {
            self.remove_pending_grant(&request).await?;
            let _ = self.inner.events.send(SshEvent::GrantCancelled {
                request_id: request.id.clone(),
                session_id: request.session_id.clone(),
                client_id: request.client_id.unwrap_or_default(),
            });
            let _ = self
                .finish_tool_grant(&request.id, ToolGrantResolution::Cancelled)
                .await;
            return Ok(None);
        }

        let binding = SshBinding {
            id: Uuid::now_v7().to_string(),
            session_id: request.session_id.clone(),
            target_id,
            identity,
            root: canonical_root.clone(),
            cwd: canonical_root,
            capabilities,
            epoch: 1,
            revoked: false,
        };
        let persisted = PersistedSshGrant {
            binding: binding.clone(),
            parent_binding_id: None,
            requires_revalidation: false,
            scope: decision.scope,
            revoke_status: None,
            worker_bound: false,
            worker_commands: Vec::new(),
        };
        {
            let _commit = self.inner.target_commit.lock().await;
            if self.target_config_epoch() != target_epoch {
                return Err(SshServiceError::StaleInvocation);
            }
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
                .insert(binding.id.clone(), GrantRecord::new(persisted));
            self.persist_grant_state(
                &request.session_id,
                &candidate,
                &binding,
                decision.scope,
                decision.make_default,
            )
            .await?;
            *state = candidate;
        }
        let _ = self.inner.events.send(SshEvent::GrantResolved {
            request_id: request.id.clone(),
            approved: true,
            binding: Some(binding.clone()),
        });
        if request.awaiting_tool
            && !self
                .finish_tool_grant(&request.id, ToolGrantResolution::Granted(binding.clone()))
                .await
        {
            self.revoke_binding(&request.session_id, &binding.id).await?;
            return Ok(None);
        }
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
        expire_operation_approvals(&self.inner, |_, waiter| {
            affected.iter().any(|(session_id, binding, _)| {
                waiter.binding.session_id.as_str() == session_id.as_str()
                    && waiter.binding.id == binding.id
            })
        })
        .await;
        retire_sudo_gates(
            &self.inner,
            |gate| {
                affected.iter().any(|(session_id, binding, _)| {
                    gate.binding.session_id == *session_id && gate.binding.id == binding.id
                })
            },
            "Root password entry was cancelled",
        )
        .await;
        self.inner
            .operation_approval_policies
            .lock()
            .await
            .retain(|policy| {
                !affected.iter().any(|(session_id, binding, _)| {
                    policy.session_id == *session_id
                        && policy.binding_id == binding.id
                        && policy.epoch == binding.epoch
                        && policy.identity == binding.identity
                })
            });

        {
            let mut waiters = self.inner.worker_install_waiters.lock().await;
            waiters.retain(|_, waiter| {
                !affected.iter().any(|(session_id, binding, _)| {
                    waiter.binding.session_id == *session_id && waiter.binding.id == binding.id
                })
            });
        }
        let mut pending = false;
        for (affected_session_id, binding, _) in &affected {
            let needs_ack = self
                .inner
                .sessions
                .read()
                .await
                .get(affected_session_id)
                .and_then(|state| state.grants.get(&binding.id))
                .is_some_and(|record| {
                    record.persisted.revoke_status == Some(SshGrantStatus::RevokedLocalPending)
                });
            if needs_ack {
                pending = true;
                let _ = self.inner.events.send(SshEvent::BindingRevoked {
                    session_id: affected_session_id.clone(),
                    binding_id: binding.id.clone(),
                    status: RevokeStatus::LocalPending,
                });
                self.spawn_revoke_ack(affected_session_id.clone(), binding.clone());
            } else {
                let _ = self.inner.events.send(SshEvent::BindingRevoked {
                    session_id: affected_session_id.clone(),
                    binding_id: binding.id.clone(),
                    status: RevokeStatus::Confirmed,
                });
            }
        }
        if let Some(error) = persistence_error {
            return Err(error);
        }
        Ok(if pending {
            RevokeStatus::LocalPending
        } else {
            RevokeStatus::Confirmed
        })
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
                worker_bound: false,
                worker_commands: Vec::new(),
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
                .insert(grant.binding.id.clone(), GrantRecord::new(grant));
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
        let target_id = self.canonical_target_id(target_id)?;
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

    /// Explicit tools always use native SSH/SFTP, including inside SSH projects.
    /// The worker path is reserved for project workspace operations.
    pub async fn dispatch(
        &self,
        request: SshDispatchRequest,
        client_id: Option<u64>,
    ) -> Result<SshDispatchResult, SshServiceError> {
        let expected = match request.tool_name.as_str() {
            "GrokBuild:read_file" | "GrokBuild:grep" => SshOperation::Read,
            "OpenCode:write" | "OpenCode:edit" => SshOperation::Write,
            "GrokBuild:run_terminal_cmd" => SshOperation::Execute,
            _ => {
                return Err(SshServiceError::Native(
                    "unsupported explicit SSH tool".into(),
                ));
            }
        };
        if request.invocation.operation != expected {
            return Err(SshServiceError::CapabilityDenied);
        }
        // Explicit native dispatches can bypass the model tool's typed input.
        // Validate the complete run input before connection/approval so malformed
        // root requests cannot leave a pending approval card behind.
        let command_args = (expected == SshOperation::Execute)
            .then(|| {
                serde_json::from_value::<super::tools::SshCommandArgs>(request.args.clone())
                    .map_err(|error| SshServiceError::Native(format!("invalid ssh_run input: {error}")))
            })
            .transpose()?;
        let is_sudo = command_args.as_ref().is_some_and(|args| args.sudo);
        let target_epoch = self.target_config_epoch();
        let binding = self.binding_for_invocation(&request.invocation).await?;
        let lease = self
            .acquire(&binding.target_id, client_id, client_id.is_some())
            .await?;
        if lease.identity() != &binding.identity {
            return Err(SshServiceError::IdentityChanged);
        }
        let cwd = super::native_files::validate_cwd(&lease, &binding, &request.invocation.cwd)
            .await
            .map_err(SshServiceError::Native)?;
        self.mark_revalidated(&binding.session_id, &binding.id)
            .await;
        let revoked = {
            let sessions = self.inner.sessions.read().await;
            sessions
                .get(&binding.session_id)
                .and_then(|state| state.grants.get(&binding.id))
                .ok_or_else(|| SshServiceError::UnknownBinding(binding.id.clone()))?
                .revoked
                .clone()
        };
        self.binding_for_invocation(&request.invocation).await?;
        let operation = self
            .inner
            .native_operations
            .reserve(&request)
            .await
            .map_err(SshServiceError::Native)?;
        let callbacks: Arc<dyn SshClientCallbacks> = Arc::new(WorkerCallbacks {
            service: Arc::downgrade(&self.inner),
            client_id,
            binding: binding.clone(),
            target_epoch,
            allow_session: !is_sudo,
        });
        let mut completion_guard = operation.guard(callbacks.clone());
        let mut effects_started = false;
        let result = async {
            if expected != SshOperation::Read {
                let approved = callbacks.approve(SshApprovalRequest {
                    approval_id: Uuid::now_v7().to_string(), operation_id: operation.id.clone(),
                    binding_id: binding.id.clone(), session_id: binding.session_id.clone(),
                    operation: expected,
                    title: if is_sudo { "SSH root command".into() } else { format!("SSH {}", request.tool_name) },
                    detail: serde_json::json!({
                        "target_id": binding.target_id, "identity": binding.identity,
                        "root": binding.root, "cwd": cwd, "tool": request.tool_name,
                        "args": request.args, "sudo": is_sudo,
                    }),
                }).await;
                if approved != SshApprovalDecision::Approve {
                    return Err(SshServiceError::Native("operation denied by user".into()));
                }
            }
            self.binding_for_invocation(&request.invocation).await?;
            if revoked.load(Ordering::Acquire) {
                return Err(SshServiceError::RevokedBinding(binding.id.clone()));
            }
            if expected == SshOperation::Execute {
                let command_args = command_args
                    .as_ref()
                    .expect("execute input was validated before dispatch");
                let args = xai_grok_tools::implementations::grok_build::bash::BashToolInput {
                    command: command_args.command.clone(),
                    description: command_args.description.clone(),
                    timeout: command_args.timeout,
                    is_background: command_args.is_background,
                    block_until_ms: command_args.block_until_ms,
                };
                let channel = if is_sudo {
                    let client_id = client_id.ok_or(SshServiceError::InteractiveClientRequired)?;
                    let interaction: Arc<dyn SudoInteraction> = Arc::new(
                        SudoInteractionBridge::register(
                            Arc::downgrade(&self.inner),
                            client_id,
                            binding.clone(),
                            target_epoch,
                            operation.id.clone(),
                        )
                        .await?,
                    );
                    // Once the root-capable channel starts, cancellation or a
                    // lost GO acknowledgement cannot prove no remote effects.
                    effects_started = true;
                    lease
                        .exec_sudo_command(&args.command, &cwd, interaction)
                        .await?
                } else {
                    let command = format!(
                        "cd -- {} && exec sh -c {}",
                        super::native_tasks::shell_quote(&cwd).map_err(SshServiceError::Native)?,
                        super::native_tasks::shell_quote(&args.command)
                            .map_err(SshServiceError::Native)?
                    );
                    lease.exec_command(&command).await?
                };
                effects_started = true;
                return Ok(operation.clone().run(channel, args, callbacks.clone()).await);
            }
            effects_started = expected != SshOperation::Read;
            let mut result = super::native_files::execute(
                &lease, &binding, &request.invocation, &request.tool_name, request.args,
                &|| !revoked.load(Ordering::Acquire),
            ).await.map_err(SshServiceError::Native)?;
            attach_remote_scope(&mut result.output, &request.invocation, &operation.id);
            result.prompt_text = render_ssh_dispatch_prompt(result.prompt_text, None, &request.invocation, &operation.id);
            Ok(result)
        }.await;
        if expected != SshOperation::Execute || result.is_err() {
            operation
                .finish(
                    result.as_ref().cloned().map_err(ToString::to_string),
                    effects_started,
                    callbacks.as_ref(),
                )
                .await;
        }
        completion_guard.disarm();
        result.map_err(|error| {
            if effects_started {
                SshServiceError::Native(format!(
                    "{error}. Operation {} on binding {} may have reached the remote host; query it with ssh_task_query using that binding and operation_id. Do not replay the mutation.",
                    operation.id, binding.id,
                ))
            } else { error }
        })
    }

    async fn worker_bound(&self, binding: &SshBinding) -> bool {
        self.inner
            .sessions
            .read()
            .await
            .get(&binding.session_id)
            .and_then(|state| state.grants.get(&binding.id))
            .is_some_and(|record| record.persisted.worker_bound)
    }

    /// Rechecks local authority immediately before remote dispatch. The worker
    /// repeats the epoch/root/capability check before side effects; there is no
    /// local filesystem or shell fallback and no mutation retry path.
    async fn dispatch_worker(
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
        if operation_id.starts_with("ssh-native-") {
            return Ok(self
                .inner
                .native_operations
                .query(&binding, operation_id)
                .await);
        }
        if !self.worker_bound(&binding).await {
            return Ok(None);
        }
        let worker = self.ensure_worker(&binding, client_id).await?;
        let operation = worker
            .client
            .operation(&binding.id, session_id, operation_id)
            .await?;
        operation
            .map(|operation| render_operation_query(&binding, operation, call_id.into()))
            .transpose()
    }

    /// Read only output owned by this binding/session. Native task output is
    /// local accounting; project-worker task output remains worker-authorized.
    pub async fn query_task_output(
        &self,
        session_id: &str,
        target: Option<&str>,
        task_id: String,
        call_id: impl Into<String>,
        client_id: Option<u64>,
    ) -> Result<SshDispatchResult, SshServiceError> {
        if task_id.starts_with("ssh-native-") {
            let binding = self.resolve_binding(session_id, target).await?;
            return self
                .inner
                .native_operations
                .query(&binding, &task_id)
                .await
                .ok_or_else(|| {
                    SshServiceError::Native("SSH task not found for this binding/session".into())
                });
        }
        let invocation = self
            .resolve_invocation(session_id, target, None, SshOperation::Read, call_id)
            .await?;
        let binding = self.binding_for_invocation(&invocation).await?;
        if !self.worker_bound(&binding).await {
            return Err(SshServiceError::Native(
                "SSH task not found for this binding/session".into(),
            ));
        }
        self.dispatch_worker(
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
        let mut tasks = self.inner.native_operations.list(&binding).await;
        if self.worker_bound(&binding).await {
            let worker = self.ensure_worker(&binding, client_id).await?;
            tasks.extend(worker.client.tasks(&binding.id, session_id).await?);
        }
        Ok(tasks)
    }

    pub async fn cancel_task(
        &self,
        session_id: &str,
        target: Option<&str>,
        task_reference: String,
        call_id: impl Into<String>,
        client_id: Option<u64>,
    ) -> Result<SshCancellation, SshServiceError> {
        if task_reference.starts_with("ssh-native-") {
            // Revocation prevents new work, not stopping an already-owned
            // command. An explicit revoked binding id may only cancel locally
            // tracked commands through their existing channel.
            let binding = match self.resolve_binding(session_id, target).await {
                Ok(binding) => binding,
                Err(SshServiceError::RevokedBinding(id)) => self.binding(session_id, &id).await?,
                Err(error) => return Err(error),
            };
            return self
                .inner
                .native_operations
                .cancel(&binding, &task_reference)
                .await
                .map_err(SshServiceError::Native);
        }
        let invocation = self
            .resolve_invocation(session_id, target, None, SshOperation::Read, call_id)
            .await?;
        let binding = self.binding_for_invocation(&invocation).await?;
        if !self.worker_bound(&binding).await {
            return Err(SshServiceError::Native(
                "SSH task not found for this binding/session".into(),
            ));
        }
        let worker = self.ensure_worker(&binding, client_id).await?;
        self.binding_for_invocation(&invocation).await?;
        worker
            .client
            .cancel(invocation, task_reference)
            .await
            .map_err(Into::into)
    }

    pub async fn connection_status(
        &self,
        target_id: &str,
    ) -> Result<SshTargetStatus, SshServiceError> {
        let target_id = self.canonical_target_id(target_id)?;
        Ok(SshTargetStatus {
            connection: self.connection_state(&target_id),
            target_id,
            detail: None,
        })
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
        let target_id = self.canonical_target_id(target_id)?;
        let target_epoch = self.target_config_epoch();
        let lease = self
            .acquire(&target_id, Some(client_id), interactive)
            .await?;
        let identity = lease.identity();
        let status = SshTargetStatus {
            target_id: target_id.clone(),
            connection: SshConnectionState::Connected,
            detail: Some(format!(
                "connected as {}@{}:{}",
                identity.username, identity.hostname, identity.port
            )),
        };
        {
            let _commit = self.inner.target_commit.lock().await;
            if self.target_config_epoch() != target_epoch {
                return Err(SshServiceError::StaleInvocation);
            }
            self.inner
                .manual_holds
                .lock()
                .await
                .insert(target_id, lease);
        }
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
        let target_id = self.canonical_target_id(target_id)?;
        self.inner
            .workers
            .lock()
            .await
            .retain(|_, worker| worker.binding.target_id != target_id);
        self.inner.manual_holds.lock().await.remove(&target_id);
        self.inner.connections.disconnect(&target_id).await?;
        let status = SshTargetStatus {
            target_id,
            connection: SshConnectionState::Disconnected,
            detail: None,
        };
        let _ = self
            .inner
            .events
            .send(SshEvent::TargetStatus(status.clone()));
        Ok(status)
    }

    /// The target epoch makes pre-mutation authentication and worker work
    /// stale before this cleanup runs. This method performs no nested target
    /// commit locking, so it can disconnect and revoke without delaying I/O.
    async fn invalidate_target_authority_inner(
        &self,
        target_id: &str,
    ) -> Result<(), SshServiceError> {
        self.inner
            .auth_waiters
            .lock()
            .await
            .retain(|_, waiter| waiter.target_id != target_id);
        retire_sudo_gates(
            &self.inner,
            |gate| gate.binding.target_id == target_id,
            "Root password entry was cancelled",
        )
        .await;
        self.inner
            .workers
            .lock()
            .await
            .retain(|_, worker| worker.binding.target_id != target_id);
        self.inner.manual_holds.lock().await.remove(target_id);
        self.inner.connections.invalidate(target_id).await?;

        let cancelled_requests = {
            let mut sessions = self.inner.sessions.write().await;
            let session_ids = sessions.keys().cloned().collect::<Vec<_>>();
            let mut cancelled = Vec::new();
            for session_id in session_ids {
                let Some(state) = sessions.get_mut(&session_id) else {
                    continue;
                };
                let mut candidate = state.clone();
                let requests = candidate
                    .pending_requests
                    .values()
                    .filter(|request| request.target_id.as_deref() == Some(target_id))
                    .cloned()
                    .collect::<Vec<_>>();
                if requests.is_empty() {
                    continue;
                }
                candidate.pending_requests.retain(|request_id, _| {
                    !requests.iter().any(|request| request.id == *request_id)
                });
                self.persist_state(&session_id, &candidate).await?;
                *state = candidate;
                cancelled.extend(requests);
            }
            cancelled
        };
        for request in cancelled_requests {
            let _ = self.inner.events.send(SshEvent::GrantCancelled {
                request_id: request.id.clone(),
                session_id: request.session_id.clone(),
                client_id: request.client_id.unwrap_or_default(),
            });
            let _ = self
                .finish_tool_grant(&request.id, ToolGrantResolution::Cancelled)
                .await;
        }

        let bindings = {
            let sessions = self.inner.sessions.read().await;
            sessions
                .iter()
                .flat_map(|(session_id, state)| {
                    state.grants.values().filter_map(move |record| {
                        (!record.persisted.binding.revoked
                            && record.persisted.binding.target_id == target_id)
                            .then(|| (session_id.clone(), record.persisted.binding.id.clone()))
                    })
                })
                .collect::<Vec<_>>()
        };
        for (session_id, binding_id) in bindings {
            self.revoke_binding(&session_id, &binding_id).await?;
        }
        Ok(())
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
                        && persisted.worker_bound
                        && persisted.revoke_status == Some(SshGrantStatus::RevokedLocalPending)
                        && persisted.binding.target_id == target_id
                        && &persisted.binding.identity == identity
                    {
                        pending.push((
                            session_id.clone(),
                            persisted.binding.clone(),
                            persisted.worker_commands.clone(),
                        ));
                    }
                }
            }
            pending
        };
        if pending.is_empty() {
            return Ok(());
        }
        let configured = self
            .inner
            .targets
            .resolve(target_id)
            .map_err(|error| SshServiceError::Configuration(error.to_string()))?
            .target
            .worker_command;
        for (session_id, binding, mut commands) in pending {
            if commands.is_empty()
                || (!is_default_worker_command(&configured) && !commands.contains(&configured))
            {
                commands.push(configured.clone());
            }
            let acknowledged = self
                .revoke_worker_commands(lease, &binding, &commands)
                .await;
            if acknowledged {
                self.confirm_revoke_ack(&session_id, &binding).await?;
            }
        }
        Ok(())
    }

    async fn revoke_worker_commands(
        &self,
        lease: &ConnectionLease,
        binding: &SshBinding,
        commands: &[Vec<String>],
    ) -> bool {
        let current = self.inner.workers.lock().await.get(&binding.id).cloned();
        let mut all_acknowledged = !commands.is_empty();
        for arguments in commands {
            let acknowledgement = async {
                if let Some(worker) = current
                    .as_ref()
                    .filter(|worker| worker.command == *arguments && worker.client.is_connected())
                {
                    return worker
                        .client
                        .revoke(&binding.id, binding.epoch)
                        .await
                        .map_err(SshServiceError::from);
                }
                let command = shell_command(arguments)?;
                let stream = lease.exec(&command).await?;
                SshWorkspaceClient::revoke_tombstone(stream, binding.clone())
                    .await
                    .map_err(SshServiceError::from)
            }
            .await;
            match acknowledgement {
                Ok(ack) if ack.binding_id == binding.id && ack.epoch == binding.epoch => {}
                other => {
                    all_acknowledged = false;
                    tracing::warn!(
                        binding_id = %binding.id,
                        target_id = %binding.target_id,
                        result = ?other,
                        "SSH worker version revocation remains pending"
                    );
                }
            }
        }
        all_acknowledged
    }

    pub async fn submit_auth_response(
        &self,
        response: SshAuthResponse,
    ) -> Result<(), SshServiceError> {
        let sudo_waiter = {
            // Hold the exact grant read lock while claiming a root-password
            // response, so revoke cannot authorize a stale GO handshake.
            let sessions = self.inner.sessions.read().await;
            let mut waiters = self.inner.sudo_auth_waiters.lock().await;
            match waiters.get(&response.challenge_id) {
                Some(current) => {
                    if current.client_id != response.client_id
                        || current.connection_generation != response.connection_generation
                    {
                        return Err(SshServiceError::StaleAuthentication);
                    }
                    let stale = current.target_epoch != self.target_config_epoch()
                        || current.operation_id != current.gate_id
                        || !current.active.load(Ordering::Acquire)
                        || !sessions
                            .get(&current.binding.session_id)
                            .and_then(|state| state.grants.get(&current.binding.id))
                            .is_some_and(|record| {
                                !record.persisted.binding.revoked
                                    && record.persisted.binding == current.binding
                                    && record
                                        .persisted
                                        .binding
                                        .capabilities
                                        .permits(SshOperation::Execute)
                            });
                    let waiter = waiters
                        .remove(&response.challenge_id)
                        .expect("sudo authentication waiter was present while holding the lock");
                    Some((stale, waiter))
                }
                None => None,
            }
        };
        if let Some((stale, waiter)) = sudo_waiter {
            if stale {
                waiter.active.store(false, Ordering::Release);
                emit_sudo_auth_resolution(
                    &self.inner,
                    waiter.client_id,
                    waiter.binding.session_id,
                    response.challenge_id.clone(),
                    &waiter.resolved,
                    Some("Root password entry is no longer valid".into()),
                );
                return Err(SshServiceError::StaleAuthentication);
            }
            let challenge_id = response.challenge_id.clone();
            return waiter.response.send(response).map_err(|_| {
                emit_sudo_auth_resolution(
                    &self.inner,
                    waiter.client_id,
                    waiter.binding.session_id,
                    challenge_id,
                    &waiter.resolved,
                    Some("Root password entry was cancelled".into()),
                );
                SshServiceError::StaleAuthentication
            });
        }

        let waiter = {
            let mut waiters = self.inner.auth_waiters.lock().await;
            let current = waiters
                .get(&response.challenge_id)
                .ok_or(SshServiceError::StaleAuthentication)?;
            if current.client_id != response.client_id
                || current.connection_generation != response.connection_generation
                || current.target_epoch != self.target_config_epoch()
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
        let SshOperationApprovalDecision {
            client_id: submitted_client_id,
            approval_id,
            approved,
            scope,
        } = decision;
        // Keep the exact grant read lock through policy installation. A revoke
        // cannot turn a stale reply into a session-level approval rule.
        let sessions = self.inner.sessions.read().await;
        let pending = {
            let mut waiters = self.inner.approval_waiters.lock().await;
            let current = waiters
                .get(&approval_id)
                .ok_or(SshServiceError::StaleOperationApproval)?;
            if current.client_id != submitted_client_id {
                return Err(SshServiceError::StaleOperationApproval);
            }
            if scope == SshOperationApprovalScope::Session && !current.allow_session {
                // Do not retire the card: the client may resubmit the same
                // one-time root decision with `Once`.
                return Err(SshServiceError::SessionApprovalNotAllowed);
            }
            let stale = current.target_epoch != self.target_config_epoch()
                || current.response.is_closed()
                || !sessions
                    .get(&current.binding.session_id)
                    .and_then(|state| state.grants.get(&current.binding.id))
                    .is_some_and(|record| {
                        !record.persisted.binding.revoked
                            && record.persisted.binding == current.binding
                            && record.persisted.binding.capabilities.permits(current.operation)
                    });
            if stale {
                let PendingOperationApproval {
                    client_id,
                    binding,
                    ..
                } = waiters
                    .remove(&approval_id)
                    .expect("approval was present while holding the lock");
                drop(waiters);
                drop(sessions);
                notify_operation_approval_expired(
                    &self.inner,
                    client_id,
                    binding.session_id,
                    approval_id,
                );
                return Err(SshServiceError::StaleOperationApproval);
            }
            waiters
                .remove(&approval_id)
                .expect("approval was present while holding the lock")
        };
        let PendingOperationApproval {
            client_id,
            binding,
            target_epoch,
            operation,
            allow_session,
            response,
            ..
        } = pending;
        let mut submission_guard = OperationApprovalSubmissionGuard::new(
            self.inner.clone(),
            client_id,
            binding.session_id.clone(),
            approval_id.clone(),
        );
        if approved
            && allow_session
            && scope == SshOperationApprovalScope::Session
            && matches!(operation, SshOperation::Write | SshOperation::Execute)
        {
            let mut policies = self.inner.operation_approval_policies.lock().await;
            if self.target_config_epoch() != target_epoch {
                drop(policies);
                drop(sessions);
                submission_guard.disarm();
                notify_operation_approval_expired(
                    &self.inner,
                    client_id,
                    binding.session_id,
                    approval_id,
                );
                return Err(SshServiceError::StaleOperationApproval);
            }
            policies.retain(|policy| {
                !(policy.client_id == client_id
                    && policy.session_id == binding.session_id
                    && policy.binding_id == binding.id
                    && policy.epoch == binding.epoch
                    && policy.identity == binding.identity
                    && policy.operation == operation)
            });
            policies.push(OperationApprovalPolicy {
                client_id,
                session_id: binding.session_id,
                binding_id: binding.id,
                epoch: binding.epoch,
                identity: binding.identity,
                operation,
            });
            if response.send(true).is_err() {
                let policy = policies
                    .pop()
                    .expect("new approval policy was present while holding the lock");
                drop(policies);
                drop(sessions);
                submission_guard.disarm();
                notify_operation_approval_expired(
                    &self.inner,
                    policy.client_id,
                    policy.session_id,
                    approval_id,
                );
                return Err(SshServiceError::StaleOperationApproval);
            }
        } else if response.send(approved).is_err() {
            drop(sessions);
            submission_guard.disarm();
            notify_operation_approval_expired(
                &self.inner,
                client_id,
                binding.session_id,
                approval_id,
            );
            return Err(SshServiceError::StaleOperationApproval);
        }
        submission_guard.disarm();
        Ok(())
    }

    async fn reset_operation_approvals(
        &self,
        session_id: &str,
        binding_id: &str,
        client_id: u64,
    ) -> Result<(), SshServiceError> {
        let binding = self.binding(session_id, binding_id).await?;
        if binding.revoked {
            return Err(SshServiceError::RevokedBinding(binding_id.to_owned()));
        }
        self.inner
            .operation_approval_policies
            .lock()
            .await
            .retain(|policy| {
                !(policy.client_id == client_id
                    && policy.session_id == binding.session_id
                    && policy.binding_id == binding.id
                    && policy.epoch == binding.epoch
                    && policy.identity == binding.identity)
            });
        Ok(())
    }


    async fn submit_worker_install(
        &self,
        decision: SshWorkerInstallDecision,
    ) -> Result<(), SshServiceError> {
        // Keep the grant read lock until the one-shot decision is sent: a concurrent
        // revoke cannot turn an approved stale epoch into upload authority.
        let sessions = self.inner.sessions.read().await;
        let mut waiters = self.inner.worker_install_waiters.lock().await;
        let waiter = waiters
            .get(&decision.request_id)
            .ok_or(SshServiceError::StaleWorkerInstall)?;
        if waiter.client_id != decision.client_id
            || waiter.target_epoch != self.target_config_epoch()
            || waiter.binding.session_id != decision.session_id
            || waiter.binding.id != decision.binding_id
            || !sessions
                .get(&decision.session_id)
                .and_then(|state| state.grants.get(&decision.binding_id))
                .is_some_and(|record| {
                    !record.persisted.binding.revoked && record.persisted.binding == waiter.binding
                })
        {
            return Err(SshServiceError::StaleWorkerInstall);
        }
        waiters
            .remove(&decision.request_id)
            .expect("the checked request remains locked")
            .response
            .send(decision.approved)
            .map_err(|_| SshServiceError::StaleWorkerInstall)
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

    fn check_terminal_grant_owner(
        &self,
        request: &SshGrantRequest,
        session_id: &str,
        client_id: u64,
    ) -> Result<(), SshServiceError> {
        if request.session_id != session_id {
            return Err(SshServiceError::UnknownGrantRequest(request.id.clone()));
        }
        if request.client_id != Some(client_id) {
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
        if let Some(selector) = target {
            let direct_binding = {
                let sessions = self.inner.sessions.read().await;
                let state = sessions
                    .get(session_id)
                    .ok_or(SshServiceError::NoDefaultBinding)?;
                state
                    .grants
                    .get(selector)
                    .map(|record| record.persisted.binding.clone())
            };
            let binding = if let Some(binding) = direct_binding {
                binding
            } else {
                let target_id = self.canonical_target_id(selector)?;
                let sessions = self.inner.sessions.read().await;
                let state = sessions
                    .get(session_id)
                    .ok_or(SshServiceError::NoDefaultBinding)?;
                let mut matches = state
                    .grants
                    .values()
                    .filter(|record| {
                        !record.persisted.binding.revoked
                            && record.persisted.binding.target_id == target_id
                    })
                    .map(|record| record.persisted.binding.clone());
                let first = matches.next().ok_or(SshServiceError::GrantRequired)?;
                if matches.next().is_some() {
                    return Err(SshServiceError::AmbiguousTarget(target_id));
                }
                first
            };
            if binding.revoked {
                return Err(SshServiceError::RevokedBinding(binding.id));
            }
            return Ok(binding);
        }

        let sessions = self.inner.sessions.read().await;
        let state = sessions
            .get(session_id)
            .ok_or(SshServiceError::NoDefaultBinding)?;
        let binding = state
            .default_binding_id
            .as_ref()
            .and_then(|binding_id| state.grants.get(binding_id))
            .map(|record| record.persisted.binding.clone())
            .ok_or(SshServiceError::NoDefaultBinding)?;
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
        self.refresh_external_target_changes().await?;
        let target_epoch = self.target_config_epoch();
        let current = self.binding(&binding.session_id, &binding.id).await?;
        if current != *binding || current.revoked {
            return Err(SshServiceError::StaleInvocation);
        }
        if let Some(worker) = self.inner.workers.lock().await.get(&binding.id).cloned() {
            if worker.client.is_connected()
                && worker.binding == *binding
                && worker.client_id == client_id
                && worker.target_epoch == target_epoch
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
        if self.target_config_epoch() != target_epoch {
            return Err(SshServiceError::StaleInvocation);
        }
        if let Some(worker) = self.inner.workers.lock().await.get(&binding.id).cloned() {
            if worker.client.is_connected()
                && worker.binding == *binding
                && worker.client_id == client_id
                && worker.target_epoch == target_epoch
            {
                return Ok(worker);
            }
        }
        let lease = self
            .acquire_native_after_refresh(&binding.target_id, client_id, client_id.is_some())
            .await?;
        self.sync_pending_revocations(&lease, &binding.target_id).await?;
        if lease.identity() != &binding.identity {
            return Err(SshServiceError::IdentityChanged);
        }
        let worker = self
            .open_worker(lease, binding.clone(), client_id, target_epoch)
            .await?;
        if worker.binding.root != binding.root || worker.binding.cwd != binding.cwd {
            return Err(SshServiceError::CanonicalRootChanged);
        }
        let worker = Arc::new(worker);
        let current = {
            // This is the final local-authority commit point after all worker
            // setup I/O. A target mutation can neither race the insertion nor
            // leave this new worker reachable with an old target epoch.
            let _commit = self.inner.target_commit.lock().await;
            if self.target_config_epoch() != target_epoch {
                None
            } else {
                let sessions = self.inner.sessions.read().await;
                let current = sessions
                    .get(&binding.session_id)
                    .and_then(|state| state.grants.get(&binding.id))
                    .map(|record| record.persisted.binding.clone());
                if current.as_ref() == Some(binding)
                    && current.as_ref().is_some_and(|binding| !binding.revoked)
                {
                    self.inner
                        .workers
                        .lock()
                        .await
                        .insert(binding.id.clone(), worker.clone());
                }
                current
            }
        };
        if current.as_ref() != Some(binding)
            || current.as_ref().is_some_and(|binding| binding.revoked)
        {
            let epoch = current
                .as_ref()
                .map_or(binding.epoch.saturating_add(1), |current| {
                    current.epoch.max(binding.epoch.saturating_add(1))
                });
            let acknowledged = matches!(worker.client.revoke(&binding.id, epoch).await,
                Ok(ack) if ack.binding_id == binding.id && ack.epoch == epoch);
            if acknowledged {
                if let Some(current) = current.filter(|current| current.revoked) {
                    self.sync_pending_revocations(&worker._lease, &current.target_id)
                        .await?;
                }
            }
            return Err(SshServiceError::StaleInvocation);
        }
        self.mark_revalidated(&binding.session_id, &binding.id)
            .await;
        Ok(worker)
    }

    async fn open_worker(
        &self,
        lease: ConnectionLease,
        binding: SshBinding,
        client_id: Option<u64>,
        target_epoch: u64,
    ) -> Result<WorkerConnection, SshServiceError> {
        if self.target_config_epoch() != target_epoch {
            return Err(SshServiceError::StaleInvocation);
        }
        let resolved = self
            .inner
            .targets
            .resolve(&binding.target_id)
            .map_err(|error| SshServiceError::Configuration(error.to_string()))?;
        let managed = is_default_worker_command(&resolved.target.worker_command);
        let command_args = if managed {
            let interaction = WorkerInstallBridge {
                service: Arc::downgrade(&self.inner),
                client_id,
                binding: binding.clone(),
                request_id: Uuid::now_v7().to_string(),
                target_epoch,
            };
            let result =
                super::worker_install::prepare_worker(&lease, &self.inner.home, &interaction).await;
            drop(interaction);
            result.map_err(SshServiceError::Worker)?
        } else {
            resolved.target.worker_command.clone()
        };
        // Record managed executables before sending authority. An interrupted handshake
        // can still bind a daemon. Never copy potentially secret custom argv into session state.
        {
            // This is a local authority commit; do not let a target mutation
            // advance its epoch between the check below and persistence.
            let _commit = self.inner.target_commit.lock().await;
            let mut sessions = self.inner.sessions.write().await;
            let state = sessions
                .get_mut(&binding.session_id)
                .ok_or_else(|| SshServiceError::UnknownBinding(binding.id.clone()))?;
            let mut candidate = state.clone();
            let record = candidate
                .grants
                .get_mut(&binding.id)
                .ok_or_else(|| SshServiceError::UnknownBinding(binding.id.clone()))?;
            if record.persisted.binding != binding
                || binding.revoked
                || self.target_config_epoch() != target_epoch
            {
                return Err(SshServiceError::StaleInvocation);
            }
            if managed {
                if record.persisted.worker_bound && record.persisted.worker_commands.is_empty() {
                    record
                        .persisted
                        .worker_commands
                        .push(xai_grok_ssh::default_worker_command());
                }
                if !record.persisted.worker_commands.contains(&command_args) {
                    record.persisted.worker_commands.push(command_args.clone());
                }
            }
            record.persisted.worker_bound = true;
            self.persist_state(&binding.session_id, &candidate).await?;
            *state = candidate;
        }
        let command = shell_command(&command_args)?;
        let stream = lease.exec(&command).await?;
        let callbacks: Arc<dyn SshClientCallbacks> = Arc::new(WorkerCallbacks {
            service: Arc::downgrade(&self.inner),
            client_id,
            binding: binding.clone(),
            target_epoch,
            allow_session: true,
        });
        let client = SshWorkspaceClient::connect(stream, binding, callbacks).await?;
        let binding = client.binding().await;
        Ok(WorkerConnection {
            binding,
            client,
            client_id,
            target_epoch,
            command: command_args,
            _lease: lease,
        })
    }

    async fn acquire_native(
        &self,
        target_id: &str,
        client_id: Option<u64>,
        interactive: bool,
    ) -> Result<ConnectionLease, SshServiceError> {
        self.refresh_external_target_changes().await?;
        self.acquire_native_after_refresh(target_id, client_id, interactive)
            .await
    }

    async fn acquire_native_after_refresh(
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
        self.inner
            .connections
            .acquire(target_id, interaction)
            .await
            .map_err(Into::into)
    }

    async fn acquire(
        &self,
        target_id: &str,
        client_id: Option<u64>,
        interactive: bool,
    ) -> Result<ConnectionLease, SshServiceError> {
        let lease = self
            .acquire_native(target_id, client_id, interactive)
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
            let binding_lock = service
                .inner
                .worker_locks
                .lock()
                .await
                .get(&binding.id)
                .cloned();
            let _guard = match &binding_lock {
                Some(lock) => Some(lock.lock().await),
                None => None,
            };
            let worker = service.inner.workers.lock().await.get(&binding.id).cloned();
            let Some(worker) = worker else {
                return;
            };
            let mut commands = service
                .inner
                .sessions
                .read()
                .await
                .get(&session_id)
                .and_then(|state| state.grants.get(&binding.id))
                .map(|record| record.persisted.worker_commands.clone())
                .unwrap_or_default();
            if !commands.contains(&worker.command) {
                commands.push(worker.command.clone());
            }
            let acknowledged = service
                .revoke_worker_commands(&worker._lease, &binding, &commands)
                .await;
            if acknowledged {
                let _ = service.confirm_revoke_ack(&session_id, &binding).await;
            }
        });
    }
}

fn target_connection_settings_changed(
    expected: &xai_grok_ssh::SshTarget,
    replacement: &xai_grok_ssh::SshTarget,
) -> bool {
    expected.host != replacement.host
        || expected.user != replacement.user
        || expected.port != replacement.port
        || expected.identity_files != replacement.identity_files
        || expected.credential_ref != replacement.credential_ref
        || expected.worker_command != replacement.worker_command
}

fn is_default_worker_command(command: &[String]) -> bool {
    command
        .iter()
        .map(String::as_str)
        .eq(xai_grok_ssh::DEFAULT_WORKER_COMMAND.iter().copied())
}

struct WorkerInstallBridge {
    service: Weak<SessionSshInner>,
    client_id: Option<u64>,
    binding: SshBinding,
    request_id: String,
    target_epoch: u64,
}

impl WorkerInstallBridge {
    fn send_progress(&self, message: Option<String>) {
        let (Some(service), Some(client_id)) = (self.service.upgrade(), self.client_id) else {
            return;
        };
        let _ = service
            .events
            .send(SshEvent::WorkerInstallProgress(SshWorkerInstallProgress {
                client_id,
                request_id: self.request_id.clone(),
                session_id: self.binding.session_id.clone(),
                binding_id: self.binding.id.clone(),
                target_id: self.binding.target_id.clone(),
                message,
            }));
    }
}

impl Drop for WorkerInstallBridge {
    fn drop(&mut self) {
        self.send_progress(None);
        if let (Some(service), Ok(runtime)) = (
            self.service.upgrade(),
            tokio::runtime::Handle::try_current(),
        ) {
            let request_id = self.request_id.clone();
            runtime.spawn(async move {
                service
                    .worker_install_waiters
                    .lock()
                    .await
                    .remove(&request_id);
            });
        }
    }
}

#[async_trait]
impl super::worker_install::WorkerInstallInteraction for WorkerInstallBridge {
    fn progress(&self, message: &str) {
        self.send_progress(Some(message.to_owned()));
    }

    async fn approve_local_upload(
        &self,
        version: &str,
        platform: &str,
        remote_error: &str,
    ) -> Result<bool, String> {
        let service = self
            .service
            .upgrade()
            .ok_or("SSH service closed during worker installation")?;
        let client_id = self.client_id.ok_or_else(|| format!(
            "Remote worker installation failed: {remote_error}. Local download/upload requires confirmation; open the project in the interactive SSH manager."
        ))?;
        let (response, receiver) = oneshot::channel();
        {
            let sessions = service.sessions.read().await;
            if service.target_config_epoch.load(Ordering::Acquire) != self.target_epoch
                || !sessions
                    .get(&self.binding.session_id)
                    .and_then(|state| state.grants.get(&self.binding.id))
                    .is_some_and(|record| {
                        !record.persisted.binding.revoked
                            && record.persisted.binding == self.binding
                    })
            {
                return Err("SSH grant changed during worker installation".into());
            }
            service.worker_install_waiters.lock().await.insert(
                self.request_id.clone(),
                PendingWorkerInstall {
                    client_id,
                    binding: self.binding.clone(),
                    target_epoch: self.target_epoch,
                    response,
                },
            );
        }
        if service
            .events
            .send(SshEvent::WorkerInstallRequested(SshWorkerInstallRequest {
                client_id,
                request_id: self.request_id.clone(),
                session_id: self.binding.session_id.clone(),
                binding_id: self.binding.id.clone(),
                target_id: self.binding.target_id.clone(),
                version: version.to_owned(),
                platform: platform.to_owned(),
                remote_error: remote_error.to_owned(),
            }))
            .is_err()
        {
            service
                .worker_install_waiters
                .lock()
                .await
                .remove(&self.request_id);
            return Err(
                "Worker installation needs confirmation, but no interactive SSH client is attached"
                    .into(),
            );
        }
        let decision = tokio::time::timeout(INTERACTION_TIMEOUT, receiver).await;
        service
            .worker_install_waiters
            .lock()
            .await
            .remove(&self.request_id);
        match decision {
            Ok(Ok(approved)) => {
                let sessions = service.sessions.read().await;
                if service.target_config_epoch.load(Ordering::Acquire) != self.target_epoch
                    || !sessions
                        .get(&self.binding.session_id)
                        .and_then(|state| state.grants.get(&self.binding.id))
                        .is_some_and(|record| {
                            !record.persisted.binding.revoked
                                && record.persisted.binding == self.binding
                        })
                {
                    return Err(
                        "SSH grant changed while waiting for worker installation consent".into(),
                    );
                }
                Ok(approved)
            }
            Ok(Err(_)) => Err("SSH worker installation was cancelled".into()),
            Err(_) => Err("Timed out waiting for local worker download/upload confirmation".into()),
        }
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
                    previous_keys: prompt.previous_keys,
                    can_replace: prompt.can_replace,
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
            SshHostKeyDecision::ReplaceAndStore => Ok(HostKeyDecision::ReplaceAndStore),
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
    binding: SshBinding,
    target_epoch: u64,
    allow_session: bool,
}

#[async_trait]
impl SshClientCallbacks for WorkerCallbacks {
    async fn on_event(&self, event: SshWorkerEvent) {
        if !worker_event_matches_binding(&event, &self.binding.session_id, &self.binding.id) {
            return;
        }
        let Some(service) = self.service.upgrade() else {
            return;
        };
        let event = SshSessionWorkerEvent {
            session_id: self.binding.session_id.clone(),
            binding_id: self.binding.id.clone(),
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
        if request.session_id != self.binding.session_id || request.binding_id != self.binding.id {
            return SshApprovalDecision::Deny;
        }
        let Some(service) = self.service.upgrade() else {
            return SshApprovalDecision::Deny;
        };
        let Some(client_id) = self.client_id else {
            return SshApprovalDecision::Deny;
        };
        if service.target_config_epoch.load(Ordering::Acquire) != self.target_epoch
            || !binding_is_live_for_operation(&service, &self.binding, request.operation).await
        {
            return SshApprovalDecision::Deny;
        }
        if self.allow_session
            && matches!(request.operation, SshOperation::Write | SshOperation::Execute)
            && operation_policy_allows(&service, &self.binding, client_id, request.operation).await
        {
            return SshApprovalDecision::Approve;
        }
        let (response, receiver) = oneshot::channel();
        let approval_id = request.approval_id.clone();
        let generation = service.approval_generation.fetch_add(1, Ordering::Relaxed);
        {
            let mut waiters = service.approval_waiters.lock().await;
            if waiters.contains_key(&approval_id) {
                return SshApprovalDecision::Deny;
            }
            waiters.insert(
                approval_id.clone(),
                PendingOperationApproval {
                    client_id,
                    binding: self.binding.clone(),
                    target_epoch: self.target_epoch,
                    operation: request.operation,
                    allow_session: self.allow_session,
                    generation,
                    response,
                },
            );
        }
        let mut guard = OperationApprovalWaitGuard::new(
            self.service.clone(),
            client_id,
            self.binding.session_id.clone(),
            approval_id.clone(),
            generation,
        );
        if service
            .events
            .send(SshEvent::OperationApproval(SshOperationApproval {
                client_id,
                approval_id: approval_id.clone(),
                operation_id: request.operation_id,
                binding_id: self.binding.id.clone(),
                session_id: self.binding.session_id.clone(),
                operation: request.operation,
                title: request.title,
                detail: request.detail,
                allow_session: self.allow_session,
            }))
            .is_err()
        {
            let mut waiters = service.approval_waiters.lock().await;
            if waiters
                .get(&approval_id)
                .is_some_and(|waiter| waiter.generation == generation)
            {
                waiters.remove(&approval_id);
            }
            guard.disarm();
            return SshApprovalDecision::Deny;
        }
        match tokio::time::timeout(INTERACTION_TIMEOUT, receiver).await {
            Ok(Ok(true)) => {
                guard.disarm();
                SshApprovalDecision::Approve
            }
            Ok(Ok(false)) | Ok(Err(_)) => {
                guard.disarm();
                SshApprovalDecision::Deny
            }
            Err(_) => {
                expire_operation_approvals(&service, |current_approval_id, waiter| {
                    current_approval_id == approval_id.as_str() && waiter.generation == generation
                })
                .await;
                guard.disarm();
                SshApprovalDecision::Deny
            }
        }
    }
}

async fn binding_is_live_for_operation(
    service: &SessionSshInner,
    binding: &SshBinding,
    operation: SshOperation,
) -> bool {
    service
        .sessions
        .read()
        .await
        .get(&binding.session_id)
        .and_then(|state| state.grants.get(&binding.id))
        .is_some_and(|record| {
            !record.persisted.binding.revoked
                && record.persisted.binding == *binding
                && record.persisted.binding.capabilities.permits(operation)
        })
}

async fn operation_policy_allows(
    service: &SessionSshInner,
    binding: &SshBinding,
    client_id: u64,
    operation: SshOperation,
) -> bool {
    let sessions = service.sessions.read().await;
    let live = sessions
        .get(&binding.session_id)
        .and_then(|state| state.grants.get(&binding.id))
        .is_some_and(|record| {
            !record.persisted.binding.revoked
                && record.persisted.binding == *binding
                && record.persisted.binding.capabilities.permits(operation)
        });
    if !live {
        return false;
    }
    service
        .operation_approval_policies
        .lock()
        .await
        .iter()
        .any(|policy| {
            policy.client_id == client_id
                && policy.session_id == binding.session_id
                && policy.binding_id == binding.id
                && policy.epoch == binding.epoch
                && policy.identity == binding.identity
                && policy.operation == operation
        })
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
                    target_id: prompt.target_id.clone(),
                    target_epoch: service.target_config_epoch.load(Ordering::Acquire),
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

fn emit_sudo_auth_resolution(
    service: &SessionSshInner,
    client_id: u64,
    session_id: String,
    challenge_id: String,
    resolved: &AtomicBool,
    error: Option<String>,
) {
    if resolved.swap(true, Ordering::AcqRel) {
        return;
    }
    let _ = service.events.send(SshEvent::SudoAuthenticationResolved {
        client_id,
        session_id,
        challenge_id,
        error,
    });
}

async fn retire_sudo_gates(
    service: &SessionSshInner,
    mut should_retire: impl FnMut(&PendingSudoGate) -> bool,
    error: &str,
) {
    let retired = {
        let mut gates = service.sudo_gates.lock().await;
        let ids = gates
            .iter()
            .filter_map(|(id, gate)| should_retire(gate).then(|| id.clone()))
            .collect::<Vec<_>>();
        ids.into_iter()
            .filter_map(|id| {
                gates.remove(&id).map(|gate| {
                    gate.active.store(false, Ordering::Release);
                    (id, gate)
                })
            })
            .collect::<Vec<_>>()
    };
    if retired.is_empty() {
        return;
    }
    let retired_ids = retired
        .iter()
        .map(|(id, _)| id.clone())
        .collect::<HashSet<_>>();
    let waiters = {
        let mut waiters = service.sudo_auth_waiters.lock().await;
        let challenge_ids = waiters
            .iter()
            .filter_map(|(challenge_id, waiter)| {
                retired_ids
                    .contains(&waiter.gate_id)
                    .then(|| challenge_id.clone())
            })
            .collect::<Vec<_>>();
        challenge_ids
            .into_iter()
            .filter_map(|challenge_id| {
                waiters.remove(&challenge_id).map(|waiter| (challenge_id, waiter))
            })
            .collect::<Vec<_>>()
    };
    for (challenge_id, waiter) in waiters {
        emit_sudo_auth_resolution(
            service,
            waiter.client_id,
            waiter.binding.session_id,
            challenge_id,
            &waiter.resolved,
            Some(error.into()),
        );
    }
    for (_, gate) in retired {
        let challenge_id = gate
            .challenge_id
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if let Some(challenge_id) = challenge_id {
            emit_sudo_auth_resolution(
                service,
                gate.client_id,
                gate.binding.session_id,
                challenge_id,
                &gate.resolved,
                Some(error.into()),
            );
        }
    }
}

struct SudoInteractionBridge {
    service: Weak<SessionSshInner>,
    client_id: u64,
    binding: SshBinding,
    target_epoch: u64,
    operation_id: String,
    active: Arc<AtomicBool>,
    resolved: Arc<AtomicBool>,
    challenge_id: Arc<StdMutex<Option<String>>>,
}

impl SudoInteractionBridge {
    async fn register(
        service: Weak<SessionSshInner>,
        client_id: u64,
        binding: SshBinding,
        target_epoch: u64,
        operation_id: String,
    ) -> Result<Self, SshServiceError> {
        let Some(inner) = service.upgrade() else {
            return Err(SshServiceError::InteractiveClientRequired);
        };
        if inner.target_config_epoch.load(Ordering::Acquire) != target_epoch
            || !binding_is_live_for_operation(&inner, &binding, SshOperation::Execute).await
        {
            return Err(SshServiceError::StaleInvocation);
        }
        let active = Arc::new(AtomicBool::new(true));
        let resolved = Arc::new(AtomicBool::new(false));
        let challenge_id = Arc::new(StdMutex::new(None));
        let mut gates = inner.sudo_gates.lock().await;
        if gates.contains_key(&operation_id) {
            return Err(SshServiceError::Native(
                "root SSH operation identifier is already active".into(),
            ));
        }
        gates.insert(
            operation_id.clone(),
            PendingSudoGate {
                client_id,
                binding: binding.clone(),
                target_epoch,
                operation_id: operation_id.clone(),
                active: active.clone(),
                resolved: resolved.clone(),
                challenge_id: challenge_id.clone(),
            },
        );
        drop(gates);
        Ok(Self {
            service,
            client_id,
            binding,
            target_epoch,
            operation_id,
            active,
            resolved,
            challenge_id,
        })
    }

    async fn authorize(&self) -> Result<(), InteractionError> {
        if !self.active.load(Ordering::Acquire) {
            return Err(InteractionError::Unavailable);
        }
        let Some(service) = self.service.upgrade() else {
            self.active.store(false, Ordering::Release);
            return Err(InteractionError::Unavailable);
        };
        if service.target_config_epoch.load(Ordering::Acquire) != self.target_epoch
            || !binding_is_live_for_operation(&service, &self.binding, SshOperation::Execute).await
        {
            self.active.store(false, Ordering::Release);
            return Err(InteractionError::Rejected);
        }
        Ok(())
    }

    fn resolve(&self, challenge_id: String, error: Option<String>) {
        if let Some(service) = self.service.upgrade() {
            emit_sudo_auth_resolution(
                &service,
                self.client_id,
                self.binding.session_id.clone(),
                challenge_id,
                &self.resolved,
                error,
            );
        }
    }
}

impl Drop for SudoInteractionBridge {
    fn drop(&mut self) {
        self.active.store(false, Ordering::Release);
        let Some(service) = self.service.upgrade() else {
            return;
        };
        let operation_id = std::mem::take(&mut self.operation_id);
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                retire_sudo_gates(
                    &service,
                    |gate| gate.operation_id == operation_id,
                    "Root password entry was cancelled",
                )
                .await;
            });
        }
    }
}

#[async_trait]
impl SudoInteraction for SudoInteractionBridge {
    async fn request_password(
        &self,
        prompt: SudoPasswordPrompt,
    ) -> Result<Secret, InteractionError> {
        if prompt.target_id != self.binding.target_id {
            self.resolve(
                prompt.challenge_id.to_string(),
                Some("Root password entry is no longer valid".into()),
            );
            return Err(InteractionError::Rejected);
        }
        if let Err(error) = self.authorize().await {
            self.resolve(
                prompt.challenge_id.to_string(),
                Some("Root command authorization was cancelled".into()),
            );
            return Err(error);
        }
        let challenge_id = prompt.challenge_id.to_string();
        let mut response = match await_sudo_auth_response(self, prompt).await {
            Ok(response) => response,
            Err(error) => {
                self.resolve(
                    challenge_id,
                    Some("Root password entry was cancelled or expired".into()),
                );
                return Err(error);
            }
        };
        if response.accepted == Some(false) {
            self.resolve(
                challenge_id,
                Some("Root password entry was declined".into()),
            );
            return Err(InteractionError::Rejected);
        }
        let mut secret = match response.secret.take() {
            Some(secret) => secret,
            None => {
                self.resolve(
                    challenge_id,
                    Some("Root password entry was declined".into()),
                );
                return Err(InteractionError::Rejected);
            }
        };
        if secret
            .iter()
            .any(|byte| matches!(byte, b'\0' | b'\r' | b'\n'))
        {
            secret.zeroize();
            self.resolve(
                challenge_id,
                Some("Root password may not contain NUL, CR, or LF".into()),
            );
            return Err(InteractionError::Rejected);
        }
        // `remember` is deliberately ignored: root credentials never enter a
        // session cache, persisted state, event, trace, or model history.
        self.resolve(challenge_id, None);
        Ok(Secret::from_owned(secret))
    }

    async fn authorize_execution(&self) -> Result<(), InteractionError> {
        self.authorize().await
    }
}

async fn await_sudo_auth_response(
    bridge: &SudoInteractionBridge,
    prompt: SudoPasswordPrompt,
) -> Result<SshAuthResponse, InteractionError> {
    let Some(service) = bridge.service.upgrade() else {
        return Err(InteractionError::Unavailable);
    };
    if bridge.authorize().await.is_err() {
        return Err(InteractionError::Rejected);
    }
    let challenge_id = prompt.challenge_id.to_string();
    *bridge
        .challenge_id
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(challenge_id.clone());
    let (response, receiver) = oneshot::channel();
    {
        let gates = service.sudo_gates.lock().await;
        let Some(gate) = gates.get(&bridge.operation_id) else {
            return Err(InteractionError::Unavailable);
        };
        if gate.client_id != bridge.client_id
            || gate.binding != bridge.binding
            || gate.target_epoch != bridge.target_epoch
            || !Arc::ptr_eq(&gate.active, &bridge.active)
            || !Arc::ptr_eq(&gate.resolved, &bridge.resolved)
            || !Arc::ptr_eq(&gate.challenge_id, &bridge.challenge_id)
        {
            return Err(InteractionError::Unavailable);
        }
        let mut waiters = service.sudo_auth_waiters.lock().await;
        if waiters.contains_key(&challenge_id) {
            return Err(InteractionError::Unavailable);
        }
        waiters.insert(
            challenge_id.clone(),
            PendingSudoAuthentication {
                client_id: bridge.client_id,
                binding: bridge.binding.clone(),
                target_epoch: bridge.target_epoch,
                connection_generation: prompt.connection_generation,
                operation_id: bridge.operation_id.clone(),
                gate_id: bridge.operation_id.clone(),
                active: bridge.active.clone(),
                resolved: bridge.resolved.clone(),
                response,
            },
        );
    }
    let prompt = SshAuthPrompt {
        client_id: bridge.client_id,
        connection_generation: prompt.connection_generation,
        challenge_id: challenge_id.clone(),
        target_id: prompt.target_id,
        kind: SshAuthPromptKind::SudoPassword,
        detail: SshAuthPromptDetail::Secret {
            username: prompt.username,
            message: "Enter the SSH account's sudo password locally for this one root command.".into(),
            allow_remember: false,
        },
    };
    if service
        .events
        .send(SshEvent::SudoAuthentication {
            session_id: bridge.binding.session_id.clone(),
            operation_id: bridge.operation_id.clone(),
            prompt,
        })
        .is_err()
    {
        service.sudo_auth_waiters.lock().await.remove(&challenge_id);
        return Err(InteractionError::Unavailable);
    }
    let result = tokio::time::timeout(INTERACTION_TIMEOUT, receiver)
        .await
        .ok()
        .and_then(Result::ok)
        .ok_or(InteractionError::Unavailable);
    service
        .sudo_auth_waiters
        .lock()
        .await
        .remove(&challenge_id);
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

fn ensure_inspection_identity(
    request: &SshGrantRequest,
    expected_identity: Option<&SshHostIdentity>,
    identity: &SshHostIdentity,
) -> Result<(), SshServiceError> {
    if expected_identity.is_some_and(|expected| expected != identity)
        || request
            .verified_identity
            .as_ref()
            .is_some_and(|verified| verified != identity)
    {
        return Err(SshServiceError::IdentityChanged);
    }
    Ok(())
}

/// The arguments are canonical remote paths acquired from the same native
/// lease. A browser-selected path may only narrow an existing request limit.
fn ensure_inspection_root_within_limit(
    selected_root: Option<&str>,
    requested_root: Option<&str>,
) -> Result<(), SshServiceError> {
    if matches!(
        (selected_root, requested_root),
        (Some(selected), Some(requested)) if !remote_path_within(selected, requested)
    ) {
        return Err(SshServiceError::GrantExpansion);
    }
    Ok(())
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

fn choose_matching_project_rule<'a>(
    file: &'a ProjectRuleFile,
    location: &ProjectLocation,
    identity: &SshHostIdentity,
    capabilities: Option<SshCapabilities>,
) -> Option<&'a ProjectSshRule> {
    let default = file
        .rules
        .iter()
        .filter(|rule| {
            rule.make_default && project_rule_matches(rule, location, identity, capabilities)
        })
        .min_by(|left, right| project_rule_priority(left).cmp(&project_rule_priority(right)));
    default.or_else(|| {
        file.rules
            .iter()
            .filter(|rule| project_rule_matches(rule, location, identity, capabilities))
            .min_by(|left, right| project_rule_priority(left).cmp(&project_rule_priority(right)))
    })
}

fn project_rule_matches(
    rule: &ProjectSshRule,
    location: &ProjectLocation,
    identity: &SshHostIdentity,
    capabilities: Option<SshCapabilities>,
) -> bool {
    let ProjectLocation::Ssh { target_id, root } = location else {
        return false;
    };
    rule.owns(location)
        && rule.target_id == *target_id
        && rule.root == *root
        && rule.capabilities.read
        && rule.identity == *identity
        && capabilities
            .map(|requested| requested.is_subset_of(rule.capabilities))
            .unwrap_or(true)
}

fn project_rule_priority(rule: &ProjectSshRule) -> ((u8, u8), &str, &str, &str) {
    (
        capability_priority(rule.capabilities),
        rule.cwd.as_str(),
        rule.target_id.as_str(),
        rule.root.as_str(),
    )
}

fn capability_priority(capabilities: SshCapabilities) -> (u8, u8) {
    let bits = (u8::from(capabilities.read) << 2)
        | (u8::from(capabilities.write) << 1)
        | u8::from(capabilities.execute);
    (bits.count_ones() as u8, bits)
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
            record.revoked.store(true, Ordering::Release);
            if !record.persisted.binding.revoked {
                record.persisted.binding.revoked = true;
                record.persisted.binding.epoch = record.persisted.binding.epoch.saturating_add(1);
                record.persisted.revoke_status = Some(if record.persisted.worker_bound {
                    SshGrantStatus::RevokedLocalPending
                } else {
                    SshGrantStatus::RevokedConfirmed
                });
            }
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

pub(super) fn render_ssh_dispatch_prompt(
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

pub(super) fn remote_scope(
    invocation: &ResolvedSshInvocation,
    operation_id: &str,
) -> serde_json::Value {
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
                previous_keys: Vec::new(),
                can_replace: false,
            })
            .await
            .unwrap_err();
        assert_eq!(error, InteractionError::Unavailable);
        assert!(service.inner.auth_waiters.lock().await.is_empty());

        let callbacks = WorkerCallbacks {
            service: Arc::downgrade(&service.inner),
            client_id: None,
            binding: binding("binding", "session", "/remote/project"),
            target_epoch: service.target_config_epoch(),
            allow_session: true,
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
        use super::super::worker_install::WorkerInstallInteraction;
        let installer = WorkerInstallBridge {
            service: Arc::downgrade(&service.inner),
            client_id: None,
            binding: binding("binding", "session", "/remote/project"),
            request_id: "install".into(),
            target_epoch: service.target_config_epoch(),
        };
        assert!(
            installer
                .approve_local_upload("0.2.0", "linux-x86_64", "download failed")
                .await
                .is_err()
        );
        assert!(service.inner.worker_install_waiters.lock().await.is_empty());
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

    async fn service_with_execute_grant() -> (tempfile::TempDir, SessionSsh, SshBinding) {
        let home = tempfile::tempdir().unwrap();
        let service = SessionSsh::new(home.path().to_owned());
        let granted = binding("binding", "session", "/remote/project");
        service
            .restore_session(
                "session",
                PersistedSshState {
                    grants: vec![PersistedSshGrant {
                        binding: granted.clone(),
                        parent_binding_id: None,
                        requires_revalidation: false,
                        scope: SshGrantScope::CurrentSession,
                        revoke_status: None,
                        worker_bound: false,
                        worker_commands: Vec::new(),
                    }],
                    default_binding_id: Some(granted.id.clone()),
                    pending_requests: Vec::new(),
                },
            )
            .await;
        (home, service, granted)
    }

    #[tokio::test]
    async fn malformed_direct_sudo_input_fails_before_approval_or_connection() {
        let home = tempfile::tempdir().unwrap();
        let service = SessionSsh::new(home.path().to_owned());
        let error = service
            .dispatch(
                SshDispatchRequest {
                    invocation: ResolvedSshInvocation {
                        binding_id: "missing-binding".into(),
                        target_id: "missing-target".into(),
                        session_id: "session".into(),
                        epoch: 1,
                        cwd: "/remote/project".into(),
                        operation: SshOperation::Execute,
                        call_id: "call".into(),
                    },
                    tool_name: "GrokBuild:run_terminal_cmd".into(),
                    args: serde_json::json!({
                        "command": "id",
                        "description": "Inspect remote identity.",
                        "sudo": "not-a-boolean",
                    }),
                    mutation_id: Some("call".into()),
                },
                Some(7),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            SshServiceError::Native(message) if message.contains("invalid ssh_run input")
        ));
        assert!(service.inner.approval_waiters.lock().await.is_empty());
    }

    #[tokio::test]
    async fn root_operation_ignores_execute_session_policy_and_requires_once_approval() {
        let (_home, service, granted) = service_with_execute_grant().await;
        service
            .inner
            .operation_approval_policies
            .lock()
            .await
            .push(OperationApprovalPolicy {
                client_id: 7,
                session_id: granted.session_id.clone(),
                binding_id: granted.id.clone(),
                epoch: granted.epoch,
                identity: granted.identity.clone(),
                operation: SshOperation::Execute,
            });
        let callbacks = WorkerCallbacks {
            service: Arc::downgrade(&service.inner),
            client_id: Some(7),
            binding: granted,
            target_epoch: service.target_config_epoch(),
            allow_session: false,
        };
        let mut events = service.subscribe_events();
        let waiting = tokio::spawn(async move {
            callbacks
                .approve(SshApprovalRequest {
                    approval_id: "root-once".into(),
                    operation_id: "operation".into(),
                    binding_id: "binding".into(),
                    session_id: "session".into(),
                    operation: SshOperation::Execute,
                    title: "SSH root command".into(),
                    detail: serde_json::json!({"args": {"sudo": true, "command": "id"}}),
                })
                .await
        });
        assert!(matches!(
            events.recv().await.unwrap(),
            SshEvent::OperationApproval(approval)
                if approval.approval_id == "root-once" && !approval.allow_session
        ));
        service
            .submit_operation_approval(SshOperationApprovalDecision {
                client_id: 7,
                approval_id: "root-once".into(),
                approved: true,
                scope: SshOperationApprovalScope::Once,
            })
            .await
            .unwrap();
        assert_eq!(waiting.await.unwrap(), SshApprovalDecision::Approve);
    }

    #[tokio::test]
    async fn root_session_scope_is_rejected_without_retiring_once_approval() {
        let (_home, service, granted) = service_with_execute_grant().await;
        let (response, receiver) = oneshot::channel();
        service.inner.approval_waiters.lock().await.insert(
            "root-once".into(),
            PendingOperationApproval {
                client_id: 7,
                binding: granted,
                target_epoch: service.target_config_epoch(),
                operation: SshOperation::Execute,
                allow_session: false,
                generation: 1,
                response,
            },
        );
        assert!(matches!(
            service
                .submit_operation_approval(SshOperationApprovalDecision {
                    client_id: 7,
                    approval_id: "root-once".into(),
                    approved: true,
                    scope: SshOperationApprovalScope::Session,
                })
                .await,
            Err(SshServiceError::SessionApprovalNotAllowed)
        ));
        assert!(service
            .inner
            .approval_waiters
            .lock()
            .await
            .contains_key("root-once"));
        service
            .submit_operation_approval(SshOperationApprovalDecision {
                client_id: 7,
                approval_id: "root-once".into(),
                approved: true,
                scope: SshOperationApprovalScope::Once,
            })
            .await
            .unwrap();
        assert!(receiver.await.unwrap());
    }

    #[tokio::test]
    async fn sudo_password_reply_is_client_scoped_and_never_enters_events() {
        let (_home, service, granted) = service_with_execute_grant().await;
        let bridge = Arc::new(
            SudoInteractionBridge::register(
                Arc::downgrade(&service.inner),
                7,
                granted,
                service.target_config_epoch(),
                "root-operation".into(),
            )
            .await
            .unwrap(),
        );
        let challenge_id = Uuid::now_v7();
        let mut events = service.subscribe_events();
        let waiting = {
            let bridge = bridge.clone();
            tokio::spawn(async move {
                bridge
                    .request_password(SudoPasswordPrompt {
                        challenge_id,
                        connection_generation: 42,
                        target_id: "target".into(),
                        username: "user".into(),
                    })
                    .await
            })
        };
        let prompt = events.recv().await.unwrap();
        assert!(matches!(
            &prompt,
            SshEvent::SudoAuthentication { prompt, .. }
                if prompt.challenge_id == challenge_id.to_string()
                    && prompt.kind == SshAuthPromptKind::SudoPassword
        ));
        let password = b"only-local-root-password".to_vec();
        assert!(matches!(
            service
                .submit_auth_response(SshAuthResponse {
                    client_id: 8,
                    connection_generation: 42,
                    challenge_id: challenge_id.to_string(),
                    accepted: None,
                    host_key_decision: None,
                    remember: false,
                    secret: None,
                    answers: Vec::new(),
                })
                .await,
            Err(SshServiceError::StaleAuthentication)
        ));
        assert!(service
            .inner
            .sudo_auth_waiters
            .lock()
            .await
            .contains_key(&challenge_id.to_string()));
        service
            .submit_auth_response(SshAuthResponse {
                client_id: 7,
                connection_generation: 42,
                challenge_id: challenge_id.to_string(),
                accepted: None,
                host_key_decision: None,
                remember: true,
                secret: Some(password.clone()),
                answers: Vec::new(),
            })
            .await
            .unwrap();
        drop(waiting.await.unwrap().unwrap());
        let resolved = events.recv().await.unwrap();
        let serialized = serde_json::to_string(&prompt).unwrap()
            + serde_json::to_string(&resolved).unwrap().as_str();
        assert!(!serialized.contains(std::str::from_utf8(&password).unwrap()));
        assert!(matches!(
            resolved,
            SshEvent::SudoAuthenticationResolved {
                client_id: 7,
                error: None,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn revoking_a_binding_cancels_pending_sudo_authentication() {
        let (_home, service, granted) = service_with_execute_grant().await;
        let bridge = Arc::new(
            SudoInteractionBridge::register(
                Arc::downgrade(&service.inner),
                7,
                granted.clone(),
                service.target_config_epoch(),
                "root-operation".into(),
            )
            .await
            .unwrap(),
        );
        let mut events = service.subscribe_events();
        let waiting = {
            let bridge = bridge.clone();
            tokio::spawn(async move {
                bridge
                    .request_password(SudoPasswordPrompt {
                        challenge_id: Uuid::now_v7(),
                        connection_generation: 42,
                        target_id: "target".into(),
                        username: "user".into(),
                    })
                    .await
            })
        };
        assert!(matches!(
            events.recv().await.unwrap(),
            SshEvent::SudoAuthentication { .. }
        ));
        service.revoke_binding("session", &granted.id).await.unwrap();
        assert!(waiting.await.unwrap().is_err());
        let resolved = events.recv().await.unwrap();
        assert!(matches!(
            resolved,
            SshEvent::SudoAuthenticationResolved {
                client_id: 7,
                error: Some(_),
                ..
            }
        ));
        assert!(service.inner.sudo_auth_waiters.lock().await.is_empty());
    }

    #[tokio::test]
    async fn cancelled_sudo_password_reply_never_reaches_the_transport_secret() {
        let (_home, service, granted) = service_with_execute_grant().await;
        let bridge = Arc::new(
            SudoInteractionBridge::register(
                Arc::downgrade(&service.inner),
                7,
                granted,
                service.target_config_epoch(),
                "root-operation".into(),
            )
            .await
            .unwrap(),
        );
        let challenge_id = Uuid::now_v7();
        let mut events = service.subscribe_events();
        let waiting = {
            let bridge = bridge.clone();
            tokio::spawn(async move {
                bridge
                    .request_password(SudoPasswordPrompt {
                        challenge_id,
                        connection_generation: 42,
                        target_id: "target".into(),
                        username: "user".into(),
                    })
                    .await
            })
        };
        assert!(matches!(
            events.recv().await.unwrap(),
            SshEvent::SudoAuthentication { .. }
        ));
        service
            .submit_auth_response(SshAuthResponse {
                client_id: 7,
                connection_generation: 42,
                challenge_id: challenge_id.to_string(),
                accepted: Some(false),
                host_key_decision: None,
                remember: true,
                secret: Some(b"never-adopted".to_vec()),
                answers: Vec::new(),
            })
            .await
            .unwrap();
        assert!(waiting.await.unwrap().is_err());
        assert!(matches!(
            events.recv().await.unwrap(),
            SshEvent::SudoAuthenticationResolved {
                error: Some(_),
                ..
            }
        ));
    }

    fn write_manual_target(home: &std::path::Path, id: &str, label: &str, host: &str) {
        std::fs::write(
            home.join("config.toml"),
            format!(
                "[ssh.targets.{id}]\nlabel = {label:?}\nhost = {host:?}\ncredential_ref = \"secret-reference\"\nidentity_files = [\"/private/identity\"]\nworker_command = [\"secret-worker\", \"--token\", \"secret-argv\"]\n"
            ),
        )
        .expect("write target configuration");
    }

    #[tokio::test]
    async fn discovery_lists_safe_configured_metadata_without_granting_or_leaking_sessions() {
        let home = tempfile::tempdir().unwrap();
        write_manual_target(
            home.path(),
            "manual-discovery-id",
            "manual-discovery-label",
            "manual-discovery-host.invalid",
        );
        let service = SessionSsh::new(home.path().to_owned());
        let mut other_binding = binding("other-binding", "other-session", "/remote/project");
        other_binding.target_id = "manual-discovery-id".into();
        service
            .restore_session(
                "other-session",
                PersistedSshState {
                    grants: vec![PersistedSshGrant {
                        binding: other_binding,
                        parent_binding_id: None,
                        requires_revalidation: false,
                        scope: SshGrantScope::CurrentSession,
                        revoke_status: None,
                        worker_bound: false,
                        worker_commands: Vec::new(),
                    }],
                    ..Default::default()
                },
            )
            .await;

        let fresh = service.discover_targets("fresh-session").await.unwrap();
        let candidate = fresh
            .targets
            .iter()
            .find(|candidate| candidate.target_id == "manual-discovery-id")
            .expect("manual target appears in discovery");
        assert_eq!(candidate.label, "manual-discovery-label");
        assert_eq!(candidate.host, "manual-discovery-host.invalid");
        assert_eq!(candidate.source, SshTargetCandidateSource::Manual);
        assert!(candidate.access.is_empty(), "discovery must not grant access");
        assert!(service.list_targets("fresh-session").await.is_empty());
        let serialized = serde_json::to_string(candidate).unwrap();
        for secret_configuration in [
            "secret-reference",
            "/private/identity",
            "secret-worker",
            "secret-argv",
        ] {
            assert!(!serialized.contains(secret_configuration));
        }

        let other = service.discover_targets("other-session").await.unwrap();
        let other_candidate = other
            .targets
            .iter()
            .find(|candidate| candidate.target_id == "manual-discovery-id")
            .expect("manual target appears for the granted session");
        assert_eq!(other_candidate.access.len(), 1);
        assert_eq!(other_candidate.access[0].binding_id, "other-binding");
    }

    #[tokio::test]
    async fn named_tool_grant_canonicalizes_a_unique_manual_label_before_publication() {
        let home = tempfile::tempdir().unwrap();
        write_manual_target(
            home.path(),
            "manual-canonical-id",
            "manual-canonical-label",
            "manual-canonical-host.invalid",
        );
        let service = SessionSsh::new(home.path().to_owned());
        let mut events = service.subscribe_events();
        let waiting_service = service.clone();
        let waiting = tokio::spawn(async move {
            waiting_service
                .request_tool_grant(
                    "session",
                    Some("manual-canonical-label".into()),
                    Some("/remote/project".into()),
                    SshCapabilities::read_only(),
                    "inspect configured host".into(),
                    Some(7),
                    None,
                )
                .await
        });
        let request = match events.recv().await.unwrap() {
            SshEvent::GrantRequested(request) => request,
            event => panic!("expected grant request, got {event:?}"),
        };
        assert_eq!(request.target_id.as_deref(), Some("manual-canonical-id"));
        service
            .cancel_grant("session", &request.id, 7)
            .await
            .unwrap();
        assert!(matches!(
            waiting.await.unwrap(),
            Err(SshServiceError::GrantCancelled)
        ));
    }

    #[tokio::test]
    async fn named_tool_grant_rejects_missing_or_ambiguous_target_before_opening_a_prompt() {
        let home = tempfile::tempdir().unwrap();
        std::fs::write(
            home.path().join("config.toml"),
            r#"
                [ssh.targets.first]
                label = "duplicate-target-label-20261021"
                host = "first.example.test"

                [ssh.targets.second]
                label = "duplicate-target-label-20261021"
                host = "second.example.test"
            "#,
        )
        .unwrap();
        let service = SessionSsh::new(home.path().to_owned());
        let mut events = service.subscribe_events();
        assert!(matches!(
            service
                .request_tool_grant(
                    "session",
                    Some("missing target".into()),
                    None,
                    SshCapabilities::read_only(),
                    "missing target".into(),
                    Some(7),
                    None,
                )
                .await,
            Err(SshServiceError::TargetNotFound(reference)) if reference == "missing target"
        ));
        assert!(matches!(
            service
                .request_tool_grant(
                    "session",
                    Some("duplicate-target-label-20261021".into()),
                    None,
                    SshCapabilities::read_only(),
                    "ambiguous target".into(),
                    Some(7),
                    None,
                )
                .await,
            Err(SshServiceError::AmbiguousConfiguredTarget {
                reference,
                candidate_ids,
            }) if reference == "duplicate-target-label-20261021"
                && candidate_ids == vec!["first".to_owned(), "second".to_owned()]
        ));
        assert!(events.try_recv().is_err(), "rejected names must not open a prompt");
        assert!(service.snapshot_session("session").await.pending_requests.is_empty());
    }

    #[tokio::test]
    async fn terminal_control_paths_preserve_owner_and_original_tool_error() {
        let home = tempfile::tempdir().unwrap();
        let service = SessionSsh::new(home.path().to_owned());
        let mut events = service.subscribe_events();

        let waiting_service = service.clone();
        let cancelled = tokio::spawn(async move {
            waiting_service
                .request_tool_grant(
                    "session",
                    None,
                    Some("/remote/project".into()),
                    SshCapabilities::read_only(),
                    "cancelled request".into(),
                    Some(7),
                    None,
                )
                .await
        });
        let cancelled_request = match events.recv().await.unwrap() {
            SshEvent::GrantRequested(request) => request,
            event => panic!("expected grant request, got {event:?}"),
        };
        assert!(matches!(
            service
                .control(
                    8,
                    SshControlCommand::CancelGrant {
                        session_id: "session".into(),
                        request_id: cancelled_request.id.clone(),
                    }
                )
                .await,
            Err(SshServiceError::WrongClient)
        ));
        assert!(matches!(
            service
                .control(
                    7,
                    SshControlCommand::CancelGrant {
                        session_id: "different-session".into(),
                        request_id: cancelled_request.id.clone(),
                    }
                )
                .await,
            Err(SshServiceError::UnknownGrantRequest(request_id))
                if request_id == cancelled_request.id
        ));
        assert!(matches!(
            service
                .control(
                    7,
                    SshControlCommand::CancelGrant {
                        session_id: "session".into(),
                        request_id: cancelled_request.id.clone(),
                    }
                )
                .await,
            Ok(SshControlReply::GrantCancelled { request_id })
                if request_id == cancelled_request.id
        ));
        assert!(matches!(
            events.recv().await.unwrap(),
            SshEvent::GrantCancelled {
                request_id,
                session_id,
                client_id,
            } if request_id == cancelled_request.id && session_id == "session" && client_id == 7
        ));
        assert!(matches!(
            cancelled.await.unwrap(),
            Err(SshServiceError::GrantCancelled)
        ));
        assert!(matches!(
            service
                .approve_grant(SshGrantDecision {
                    request_id: cancelled_request.id,
                    approved: false,
                    target_id: None,
                    root: None,
                    capabilities: None,
                    scope: SshGrantScope::CurrentSession,
                    make_default: false,
                    client_id: 7,
                })
                .await,
            Err(SshServiceError::UnknownGrantRequest(_))
        ));

        let waiting_service = service.clone();
        let failed = tokio::spawn(async move {
            waiting_service
                .request_tool_grant(
                    "session",
                    None,
                    Some("/remote/project".into()),
                    SshCapabilities::read_only(),
                    "failed inspection".into(),
                    Some(7),
                    None,
                )
                .await
        });
        let failed_request = match events.recv().await.unwrap() {
            SshEvent::GrantRequested(request) => request,
            event => panic!("expected grant request, got {event:?}"),
        };
        assert!(matches!(
            service
                .control(
                    8,
                    SshControlCommand::FailGrant {
                        session_id: "session".into(),
                        request_id: failed_request.id.clone(),
                        error: "SSH configuration failed at candidate-fixture".into(),
                    }
                )
                .await,
            Err(SshServiceError::WrongClient)
        ));
        assert!(matches!(
            service
                .control(
                    7,
                    SshControlCommand::FailGrant {
                        session_id: "session".into(),
                        request_id: failed_request.id.clone(),
                        error: "SSH configuration failed at candidate-fixture".into(),
                    }
                )
                .await,
            Ok(SshControlReply::GrantFailed { request_id }) if request_id == failed_request.id
        ));
        assert!(matches!(
            events.recv().await.unwrap(),
            SshEvent::GrantFailed {
                request_id,
                session_id,
                client_id,
                error,
            } if request_id == failed_request.id
                && session_id == "session"
                && client_id == 7
                && error == "SSH configuration failed at candidate-fixture"
        ));
        assert!(matches!(
            failed.await.unwrap(),
            Err(SshServiceError::GrantFailed(error))
                if error == "SSH configuration failed at candidate-fixture"
        ));
        assert!(matches!(
            service
                .approve_grant(SshGrantDecision {
                    request_id: failed_request.id,
                    approved: false,
                    target_id: None,
                    root: None,
                    capabilities: None,
                    scope: SshGrantScope::CurrentSession,
                    make_default: false,
                    client_id: 7,
                })
                .await,
            Err(SshServiceError::UnknownGrantRequest(_))
        ));
    }

    async fn worker_install_fixture() -> (tempfile::TempDir, SessionSsh, WorkerInstallBridge) {
        let home = tempfile::tempdir().unwrap();
        let service = SessionSsh::new(home.path().to_owned());
        let granted = binding("binding", "session", "/remote/project");
        service
            .restore_session(
                "session",
                PersistedSshState {
                    grants: vec![PersistedSshGrant {
                        binding: granted.clone(),
                        parent_binding_id: None,
                        requires_revalidation: true,
                        scope: SshGrantScope::CurrentSession,
                        revoke_status: None,
                        worker_bound: false,
                        worker_commands: Vec::new(),
                    }],
                    ..Default::default()
                },
            )
            .await;
        let bridge = WorkerInstallBridge {
            service: Arc::downgrade(&service.inner),
            client_id: Some(7),
            binding: granted,
            request_id: "install".into(),
            target_epoch: service.target_config_epoch(),
        };
        (home, service, bridge)
    }

    #[tokio::test]
    async fn worker_upload_consent_rejects_foreign_owners_without_consuming_request() {
        use super::super::worker_install::WorkerInstallInteraction;
        let (_home, service, bridge) = worker_install_fixture().await;
        let mut events = service.subscribe_events();
        let pending = tokio::spawn(async move {
            bridge
                .approve_local_upload("0.2.0", "linux-aarch64", "download failed")
                .await
        });
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(1), events.recv())
                .await
                .unwrap()
                .unwrap(),
            SshEvent::WorkerInstallRequested(_)
        ));
        let decision = SshWorkerInstallDecision {
            client_id: 7,
            request_id: "install".into(),
            session_id: "session".into(),
            binding_id: "binding".into(),
            approved: true,
        };
        for foreign in [
            SshWorkerInstallDecision {
                client_id: 8,
                ..decision.clone()
            },
            SshWorkerInstallDecision {
                session_id: "other-session".into(),
                ..decision.clone()
            },
            SshWorkerInstallDecision {
                binding_id: "other-binding".into(),
                ..decision.clone()
            },
        ] {
            assert!(matches!(
                service
                    .control(
                        foreign.client_id,
                        SshControlCommand::SubmitWorkerInstall(foreign)
                    )
                    .await,
                Err(SshServiceError::StaleWorkerInstall)
            ));
        }
        service
            .control(7, SshControlCommand::SubmitWorkerInstall(decision.clone()))
            .await
            .unwrap();
        assert!(pending.await.unwrap().unwrap());
        assert!(matches!(
            service
                .control(7, SshControlCommand::SubmitWorkerInstall(decision))
                .await,
            Err(SshServiceError::StaleWorkerInstall)
        ));
    }

    #[tokio::test]
    async fn revocation_cancels_pending_worker_upload_before_authority_is_sent() {
        use super::super::worker_install::WorkerInstallInteraction;
        let (_home, service, bridge) = worker_install_fixture().await;
        let mut events = service.subscribe_events();
        let pending = tokio::spawn(async move {
            bridge
                .approve_local_upload("0.2.0", "linux-aarch64", "download failed")
                .await
        });
        tokio::time::timeout(Duration::from_secs(1), events.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            service.revoke_binding("session", "binding").await.unwrap(),
            RevokeStatus::Confirmed
        );
        assert!(
            tokio::time::timeout(Duration::from_secs(1), pending)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        let state = service.snapshot_session("session").await;
        let grant = state
            .grants
            .iter()
            .find(|grant| grant.binding.id == "binding")
            .unwrap();
        assert!(grant.binding.revoked);
        assert!(!grant.worker_bound);
        assert!(grant.worker_commands.is_empty());
        assert!(matches!(
            service
                .control(
                    7,
                    SshControlCommand::SubmitWorkerInstall(SshWorkerInstallDecision {
                        client_id: 7,
                        request_id: "install".into(),
                        session_id: "session".into(),
                        binding_id: "binding".into(),
                        approved: true,
                    })
                )
                .await,
            Err(SshServiceError::StaleWorkerInstall)
        ));
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
    async fn tool_grant_waits_for_human_decision_and_rejects_concurrent_requests() {
        let home = tempfile::tempdir().unwrap();
        let service = SessionSsh::new(home.path().to_owned());
        assert!(matches!(
            service
                .request_tool_grant(
                    "headless",
                    None,
                    Some("/remote/project".into()),
                    SshCapabilities::read_only(),
                    "headless access".into(),
                    None,
                    None,
                )
                .await,
            Err(SshServiceError::InteractiveClientRequired)
        ));
        let mut events = service.subscribe_events();
        let waiting_service = service.clone();
        let waiting = tokio::spawn(async move {
            waiting_service
                .request_tool_grant(
                    "session",
                    None,
                    Some("/remote/project".into()),
                    SshCapabilities::read_only(),
                    "inspect a remote project".into(),
                    Some(7),
                    None,
                )
                .await
        });
        let request = match events.recv().await.unwrap() {
            SshEvent::GrantRequested(request) => request,
            event => panic!("expected live grant request, got {event:?}"),
        };
        assert!(request.awaiting_tool);
        assert!(!waiting.is_finished(), "tool must await a human decision");
        assert!(matches!(
            service
                .request_tool_grant(
                    "session",
                    None,
                    Some("/remote/project".into()),
                    SshCapabilities::read_only(),
                    "duplicate request".into(),
                    Some(7),
                    None,
                )
                .await,
            Err(SshServiceError::GrantRequestPending)
        ));
        assert!(service
            .approve_grant(SshGrantDecision {
                request_id: request.id.clone(),
                approved: false,
                target_id: None,
                root: None,
                capabilities: None,
                scope: SshGrantScope::CurrentSession,
                make_default: false,
                client_id: 7,
            })
            .await
            .unwrap()
            .is_none());
        assert!(matches!(
            events.recv().await.unwrap(),
            SshEvent::GrantResolved {
                request_id,
                approved: false,
                binding: None,
            } if request_id == request.id
        ));
        assert!(matches!(
            waiting.await.unwrap(),
            Err(SshServiceError::GrantDenied)
        ));
        assert!(service.snapshot_session("session").await.pending_requests.is_empty());
    }

    #[tokio::test]
    async fn disconnected_tool_client_cannot_publish_a_late_grant_prompt() {
        let home = tempfile::tempdir().unwrap();
        let service = SessionSsh::new(home.path().to_owned());
        let mut events = service.subscribe_events();
        let request = SshGrantRequest {
            id: "not-published-yet".into(),
            session_id: "session".into(),
            target_id: Some("target".into()),
            root: Some("/remote/project".into()),
            capabilities: SshCapabilities::read_only(),
            reason: "inspect remote project".into(),
            verified_identity: None,
            client_id: Some(7),
            originating_session_id: None,
            awaiting_tool: true,
        };
        let receiver = service.register_tool_grant_waiter(&request).await.unwrap();
        service.clear_client_interactions(7).await;
        assert!(matches!(receiver.await.unwrap(), ToolGrantResolution::Cancelled));
        assert!(matches!(
            service.publish_tool_grant_request(request).await,
            Err(SshServiceError::GrantCancelled)
        ));
        assert!(events.try_recv().is_err(), "a disconnected client must not receive a stale prompt");
        assert!(service.snapshot_session("session").await.pending_requests.is_empty());
    }

    #[tokio::test]
    async fn cancelling_live_tool_grant_removes_the_request_before_late_approval() {
        let home = tempfile::tempdir().unwrap();
        let service = SessionSsh::new(home.path().to_owned());
        let mut events = service.subscribe_events();
        let cancellation = tokio_util::sync::CancellationToken::new();
        let waiting_service = service.clone();
        let waiting_cancellation = cancellation.clone();
        let waiting = tokio::spawn(async move {
            waiting_service
                .request_tool_grant(
                    "session",
                    None,
                    Some("/remote/project".into()),
                    SshCapabilities::read_only(),
                    "inspect a remote project".into(),
                    Some(7),
                    Some(waiting_cancellation),
                )
                .await
        });
        let request = match events.recv().await.unwrap() {
            SshEvent::GrantRequested(request) => request,
            event => panic!("expected live grant request, got {event:?}"),
        };
        cancellation.cancel();
        assert!(matches!(
            waiting.await.unwrap(),
            Err(SshServiceError::GrantCancelled)
        ));
        assert!(matches!(
            events.recv().await.unwrap(),
            SshEvent::GrantCancelled {
                request_id,
                session_id,
                client_id,
            } if request_id == request.id && session_id == "session" && client_id == 7
        ));
        assert!(matches!(
            service
                .approve_grant(SshGrantDecision {
                    request_id: request.id,
                    approved: true,
                    target_id: Some("target".into()),
                    root: Some("/remote/project".into()),
                    capabilities: None,
                    scope: SshGrantScope::CurrentSession,
                    make_default: false,
                    client_id: 7,
                })
                .await,
            Err(SshServiceError::UnknownGrantRequest(_))
        ));
        assert!(service.list_targets("session").await.is_empty());
    }
    #[tokio::test]
    async fn closing_a_session_cancels_its_live_tool_grant() {
        let home = tempfile::tempdir().unwrap();
        let service = SessionSsh::new(home.path().to_owned());
        let mut events = service.subscribe_events();
        let waiting_service = service.clone();
        let waiting = tokio::spawn(async move {
            waiting_service
                .request_tool_grant(
                    "session",
                    None,
                    Some("/remote/project".into()),
                    SshCapabilities::read_only(),
                    "inspect a remote project".into(),
                    Some(7),
                    None,
                )
                .await
        });
        let request = match events.recv().await.unwrap() {
            SshEvent::GrantRequested(request) => request,
            event => panic!("expected live grant request, got {event:?}"),
        };

        service.clear_session_interactions("session").await;

        assert!(matches!(
            events.recv().await.unwrap(),
            SshEvent::GrantCancelled {
                request_id,
                session_id,
                client_id,
            } if request_id == request.id && session_id == "session" && client_id == 7
        ));
        assert!(matches!(
            waiting.await.unwrap(),
            Err(SshServiceError::GrantCancelled)
        ));
        assert!(matches!(
            service
                .approve_grant(SshGrantDecision {
                    request_id: request.id,
                    approved: true,
                    target_id: Some("target".into()),
                    root: Some("/remote/project".into()),
                    capabilities: None,
                    scope: SshGrantScope::CurrentSession,
                    make_default: false,
                    client_id: 7,
                })
                .await,
            Err(SshServiceError::UnknownGrantRequest(_))
        ));
    }


    #[tokio::test]
    async fn dropped_live_tool_grant_future_cancels_its_pending_request() {
        let home = tempfile::tempdir().unwrap();
        let service = SessionSsh::new(home.path().to_owned());
        let mut events = service.subscribe_events();
        let waiting_service = service.clone();
        let waiting = tokio::spawn(async move {
            waiting_service
                .request_tool_grant(
                    "session",
                    None,
                    Some("/remote/project".into()),
                    SshCapabilities::read_only(),
                    "inspect a remote project".into(),
                    Some(7),
                    None,
                )
                .await
        });
        let request = match events.recv().await.unwrap() {
            SshEvent::GrantRequested(request) => request,
            event => panic!("expected live grant request, got {event:?}"),
        };
        waiting.abort();
        assert!(waiting.await.unwrap_err().is_cancelled());
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(1), events.recv())
                .await
                .unwrap()
                .unwrap(),
            SshEvent::GrantCancelled {
                request_id,
                session_id,
                client_id,
            } if request_id == request.id && session_id == "session" && client_id == 7
        ));
        assert!(service.snapshot_session("session").await.pending_requests.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn operation_approval_timeout_notifies_the_client_and_allows_a_fresh_request() {
        let home = tempfile::tempdir().unwrap();
        let service = SessionSsh::new(home.path().to_owned());
        let granted = binding("binding", "session", "/remote/project");
        service.restore_session("session", PersistedSshState {
            grants: vec![PersistedSshGrant {
                binding: granted.clone(),
                parent_binding_id: None,
                requires_revalidation: true,
                scope: SshGrantScope::CurrentSession,
                revoke_status: None,
                worker_bound: false,
                worker_commands: Vec::new(),
            }],
            default_binding_id: Some(granted.id.clone()),
            pending_requests: Vec::new(),
        }).await;
        let mut events = service.subscribe_events();
        let callbacks = WorkerCallbacks {
            service: Arc::downgrade(&service.inner),
            client_id: Some(7),
            binding: granted,
            target_epoch: service.target_config_epoch(),
            allow_session: true,
        };
        let request = |id: &str| SshApprovalRequest {
            approval_id: id.into(),
            operation_id: id.into(),
            binding_id: "binding".into(),
            session_id: "session".into(),
            operation: SshOperation::Execute,
            title: "run remote command".into(),
            detail: serde_json::json!({"command": "pwd"}),
        };
        let approval = callbacks.approve(request("expired"));
        tokio::pin!(approval);
        tokio::select! {
            result = &mut approval => panic!("approval ended before review: {result:?}"),
            event = events.recv() => assert!(matches!(event.unwrap(), SshEvent::OperationApproval(_))),
        }
        tokio::time::advance(INTERACTION_TIMEOUT).await;
        assert_eq!(approval.await, SshApprovalDecision::Deny);
        let terminal = events.try_recv().expect("expired approval must retire the client card");
        let terminal = serde_json::to_value(terminal).unwrap();
        assert_eq!(terminal["type"], "operation_approval_expired");
        assert_eq!(terminal["approval_id"], "expired");
        assert!(matches!(
            service
                .control(
                    7,
                    SshControlCommand::SubmitOperationApproval(SshOperationApprovalDecision {
                        client_id: 7,
                        approval_id: "expired".into(),
                        approved: true,
                        scope: SshOperationApprovalScope::Session,
                    }),
                )
                .await,
            Ok(SshControlReply::OperationApprovalExpired)
        ));
        let fresh = callbacks.approve(request("fresh"));
        tokio::pin!(fresh);
        tokio::select! {
            result = &mut fresh => panic!("fresh request bypassed review: {result:?}"),
            event = events.recv() => assert!(matches!(event.unwrap(), SshEvent::OperationApproval(_))),
        }
        service.submit_operation_approval(SshOperationApprovalDecision {
            client_id: 7,
            approval_id: "fresh".into(),
            approved: true,
            scope: SshOperationApprovalScope::Once,
        }).await.unwrap();
        assert_eq!(fresh.await, SshApprovalDecision::Approve);
    }

    #[tokio::test]
    async fn dropped_operation_approval_future_retires_the_card_and_requires_a_fresh_request() {
        let home = tempfile::tempdir().unwrap();
        let service = SessionSsh::new(home.path().to_owned());
        let granted = binding("binding", "session", "/remote/project");
        service
            .restore_session(
                "session",
                PersistedSshState {
                    grants: vec![PersistedSshGrant {
                        binding: granted.clone(),
                        parent_binding_id: None,
                        requires_revalidation: true,
                        scope: SshGrantScope::CurrentSession,
                        revoke_status: None,
                        worker_bound: false,
                        worker_commands: Vec::new(),
                    }],
                    default_binding_id: Some(granted.id.clone()),
                    pending_requests: Vec::new(),
                },
            )
            .await;
        let mut events = service.subscribe_events();
        let callbacks = WorkerCallbacks {
            service: Arc::downgrade(&service.inner),
            client_id: Some(7),
            binding: granted.clone(),
            target_epoch: service.target_config_epoch(),
            allow_session: true,
        };
        let waiting = tokio::spawn(async move {
            callbacks
                .approve(SshApprovalRequest {
                    approval_id: "dropped".into(),
                    operation_id: "dropped".into(),
                    binding_id: "binding".into(),
                    session_id: "session".into(),
                    operation: SshOperation::Execute,
                    title: "run remote command".into(),
                    detail: serde_json::json!({"command": "pwd"}),
                })
                .await
        });
        assert!(matches!(
            events.recv().await.unwrap(),
            SshEvent::OperationApproval(approval) if approval.approval_id == "dropped"
        ));
        waiting.abort();
        assert!(waiting.await.unwrap_err().is_cancelled());
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(1), events.recv())
                .await
                .unwrap()
                .unwrap(),
            SshEvent::OperationApprovalExpired {
                client_id: 7,
                ref session_id,
                ref approval_id,
            } if session_id == "session" && approval_id == "dropped"
        ));
        assert!(service.inner.approval_waiters.lock().await.is_empty());
        assert!(matches!(
            service
                .submit_operation_approval(SshOperationApprovalDecision {
                    client_id: 7,
                    approval_id: "dropped".into(),
                    approved: true,
                    scope: SshOperationApprovalScope::Session,
                })
                .await,
            Err(SshServiceError::StaleOperationApproval)
        ));
        assert!(
            !operation_policy_allows(&service.inner, &granted, 7, SshOperation::Execute).await
        );

        let callbacks = WorkerCallbacks {
            service: Arc::downgrade(&service.inner),
            client_id: Some(7),
            binding: granted.clone(),
            target_epoch: service.target_config_epoch(),
            allow_session: true,
        };
        let fresh = tokio::spawn(async move {
            callbacks
                .approve(SshApprovalRequest {
                    approval_id: "fresh".into(),
                    operation_id: "fresh".into(),
                    binding_id: "binding".into(),
                    session_id: "session".into(),
                    operation: SshOperation::Execute,
                    title: "run remote command".into(),
                    detail: serde_json::json!({"command": "pwd"}),
                })
                .await
        });
        assert!(matches!(
            events.recv().await.unwrap(),
            SshEvent::OperationApproval(approval) if approval.approval_id == "fresh"
        ));
        service
            .submit_operation_approval(SshOperationApprovalDecision {
                client_id: 7,
                approval_id: "fresh".into(),
                approved: true,
                scope: SshOperationApprovalScope::Once,
            })
            .await
            .unwrap();
        assert_eq!(fresh.await.unwrap(), SshApprovalDecision::Approve);
    }

    #[tokio::test]
    async fn dropped_submission_after_claiming_an_approval_retires_the_card() {
        let home = tempfile::tempdir().unwrap();
        let service = SessionSsh::new(home.path().to_owned());
        let granted = binding("binding", "session", "/remote/project");
        service
            .restore_session(
                "session",
                PersistedSshState {
                    grants: vec![PersistedSshGrant {
                        binding: granted.clone(),
                        parent_binding_id: None,
                        requires_revalidation: true,
                        scope: SshGrantScope::CurrentSession,
                        revoke_status: None,
                        worker_bound: false,
                        worker_commands: Vec::new(),
                    }],
                    default_binding_id: Some(granted.id.clone()),
                    pending_requests: Vec::new(),
                },
            )
            .await;
        let mut events = service.subscribe_events();
        let callbacks = WorkerCallbacks {
            service: Arc::downgrade(&service.inner),
            client_id: Some(7),
            binding: granted.clone(),
            target_epoch: service.target_config_epoch(),
            allow_session: true,
        };
        let waiting = tokio::spawn(async move {
            callbacks
                .approve(SshApprovalRequest {
                    approval_id: "submit-dropped".into(),
                    operation_id: "submit-dropped".into(),
                    binding_id: "binding".into(),
                    session_id: "session".into(),
                    operation: SshOperation::Execute,
                    title: "run remote command".into(),
                    detail: serde_json::json!({"command": "pwd"}),
                })
                .await
        });
        assert!(matches!(
            events.recv().await.unwrap(),
            SshEvent::OperationApproval(approval) if approval.approval_id == "submit-dropped"
        ));

        let policy_lock = service.inner.operation_approval_policies.lock().await;
        let mut submission = Box::pin(service.submit_operation_approval(
            SshOperationApprovalDecision {
                client_id: 7,
                approval_id: "submit-dropped".into(),
                approved: true,
                scope: SshOperationApprovalScope::Session,
            },
        ));
        std::future::poll_fn(|context| {
            match Future::poll(submission.as_mut(), context) {
                std::task::Poll::Pending => std::task::Poll::Ready(()),
                std::task::Poll::Ready(result) => {
                    panic!("submission completed while its policy lock was held: {result:?}")
                }
            }
        })
        .await;
        assert!(service.inner.approval_waiters.lock().await.is_empty());

        drop(submission);
        drop(policy_lock);
        assert!(matches!(
            events.recv().await.unwrap(),
            SshEvent::OperationApprovalExpired {
                client_id: 7,
                ref session_id,
                ref approval_id,
            } if session_id == "session" && approval_id == "submit-dropped"
        ));
        assert_eq!(waiting.await.unwrap(), SshApprovalDecision::Deny);
        assert!(
            !operation_policy_allows(&service.inner, &granted, 7, SshOperation::Execute).await
        );
    }

    #[tokio::test]
    async fn session_operation_approval_is_binding_scoped_and_reset_or_revoke_clears_it() {
        let home = tempfile::tempdir().unwrap();
        let service = SessionSsh::new(home.path().to_owned());
        let granted = binding("binding", "session", "/remote/project");
        service
            .restore_session(
                "session",
                PersistedSshState {
                    grants: vec![PersistedSshGrant {
                        binding: granted.clone(),
                        parent_binding_id: None,
                        requires_revalidation: true,
                        scope: SshGrantScope::CurrentSession,
                        revoke_status: None,
                        worker_bound: false,
                        worker_commands: Vec::new(),
                    }],
                    default_binding_id: Some(granted.id.clone()),
                    pending_requests: Vec::new(),
                },
            )
            .await;
        let (response, receiver) = oneshot::channel();
        service.inner.approval_waiters.lock().await.insert(
            "foreign-client".into(),
            PendingOperationApproval {
                client_id: 7,
                binding: granted.clone(),
                target_epoch: service.target_config_epoch(),
                operation: SshOperation::Execute,
                allow_session: true,
                generation: 0,
                response,
            },
        );
        assert!(matches!(
            service
                .submit_operation_approval(SshOperationApprovalDecision {
                    client_id: 8,
                    approval_id: "foreign-client".into(),
                    approved: true,
                    scope: SshOperationApprovalScope::Session,
                })
                .await,
            Err(SshServiceError::StaleOperationApproval)
        ));
        assert!(
            !operation_policy_allows(&service.inner, &granted, 7, SshOperation::Execute).await
        );
        service
            .submit_operation_approval(SshOperationApprovalDecision {
                client_id: 7,
                approval_id: "foreign-client".into(),
                approved: true,
                scope: SshOperationApprovalScope::Once,
            })
            .await
            .unwrap();
        assert!(receiver.await.unwrap());


        async fn approve(
            service: &SessionSsh,
            binding: &SshBinding,
            approval_id: &str,
            scope: SshOperationApprovalScope,
        ) {
            let (response, receiver) = oneshot::channel();
            service.inner.approval_waiters.lock().await.insert(
                approval_id.into(),
                PendingOperationApproval {
                    client_id: 7,
                    binding: binding.clone(),
                    target_epoch: service.target_config_epoch(),
                    operation: SshOperation::Execute,
                    allow_session: true,
                    generation: 0,
                    response,
                },
            );
            service
                .submit_operation_approval(SshOperationApprovalDecision {
                    client_id: 7,
                    approval_id: approval_id.into(),
                    approved: true,
                    scope,
                })
                .await
                .unwrap();
            assert!(receiver.await.unwrap());
        }

        approve(
            &service,
            &granted,
            "once",
            SshOperationApprovalScope::Once,
        )
        .await;
        assert!(
            !operation_policy_allows(&service.inner, &granted, 7, SshOperation::Execute).await
        );

        approve(
            &service,
            &granted,
            "session",
            SshOperationApprovalScope::Session,
        )
        .await;
        assert!(
            operation_policy_allows(&service.inner, &granted, 7, SshOperation::Execute).await
        );
        let mut different_binding = granted.clone();
        different_binding.id = "other-binding".into();
        assert!(
            !operation_policy_allows(
                &service.inner,
                &different_binding,
                7,
                SshOperation::Execute,
            )
            .await
        );
        assert!(
            !operation_policy_allows(&service.inner, &granted, 8, SshOperation::Execute).await
        );
        assert!(!operation_policy_allows(&service.inner, &granted, 7, SshOperation::Write).await);
        service.clear_client_interactions(8).await;
        assert!(
            operation_policy_allows(&service.inner, &granted, 7, SshOperation::Execute).await
        );
        service.clear_client_interactions(7).await;
        assert!(
            !operation_policy_allows(&service.inner, &granted, 7, SshOperation::Execute).await
        );
        approve(
            &service,
            &granted,
            "after-client-clear",
            SshOperationApprovalScope::Session,
        )
        .await;


        assert!(matches!(
            service
                .control(
                    7,
                    SshControlCommand::ResetOperationApprovals {
                        session_id: "session".into(),
                        binding_id: granted.id.clone(),
                    },
                )
                .await,
            Ok(SshControlReply::OperationApprovalsReset)
        ));
        assert!(
            !operation_policy_allows(&service.inner, &granted, 7, SshOperation::Execute).await
        );
        approve(
            &service,
            &granted,
            "after-session-close",
            SshOperationApprovalScope::Session,
        )
        .await;
        service.clear_session_interactions("session").await;
        assert!(
            !operation_policy_allows(&service.inner, &granted, 7, SshOperation::Execute).await
        );


        approve(
            &service,
            &granted,
            "revoke",
            SshOperationApprovalScope::Session,
        )
        .await;
        assert!(
            operation_policy_allows(&service.inner, &granted, 7, SshOperation::Execute).await
        );
        let mut events = service.subscribe_events();
        let (response, _receiver) = oneshot::channel();
        service.inner.approval_waiters.lock().await.insert(
            "revoked-reply".into(),
            PendingOperationApproval {
                client_id: 7,
                binding: granted.clone(),
                target_epoch: service.target_config_epoch(),
                operation: SshOperation::Execute,
                allow_session: true,
                generation: 0,
                response,
            },
        );
        service.revoke_binding("session", &granted.id).await.unwrap();
        assert!(matches!(
            events.recv().await.unwrap(),
            SshEvent::OperationApprovalExpired {
                client_id: 7,
                ref session_id,
                ref approval_id,
            } if session_id == "session" && approval_id == "revoked-reply"
        ));
        assert!(service.inner.approval_waiters.lock().await.is_empty());
        assert!(matches!(
            service
                .submit_operation_approval(SshOperationApprovalDecision {
                    client_id: 7,
                    approval_id: "revoked-reply".into(),
                    approved: true,
                    scope: SshOperationApprovalScope::Session,
                })
                .await,
            Err(SshServiceError::StaleOperationApproval)
        ));
        assert!(
            !operation_policy_allows(&service.inner, &granted, 7, SshOperation::Execute).await
        );

        service
            .restore_session(
                "session",
                PersistedSshState {
                    grants: Vec::new(),
                    default_binding_id: None,
                    pending_requests: Vec::new(),
                },
            )
            .await;
        assert!(
            !operation_policy_allows(&service.inner, &granted, 7, SshOperation::Execute).await
        );
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
        service
            .register_project_location("original", None, &raw)
            .await
            .unwrap();
        let granted = binding("original-binding", "original", "/canonical/repo");
        service
            .persist_grant_state(
                "original",
                &SessionState::default(),
                &granted,
                SshGrantScope::ProjectRule,
                true,
            )
            .await
            .unwrap();

        let restored = SessionSsh::new(home.path().to_owned());
        for (session_id, location) in [("raw-open", &raw), ("resumed", &canonical)] {
            restored
                .restore_project_rules(session_id, location)
                .await
                .unwrap();
            let invocation = restored
                .resolve_invocation(session_id, None, None, SshOperation::Read, "read")
                .await
                .unwrap();
            assert_eq!(invocation.cwd, "/canonical/repo");
        }
        restored
            .restore_project_rules(
                "other-project",
                &ProjectLocation::Ssh {
                    target_id: "target".into(),
                    root: "/elsewhere".into(),
                },
            )
            .await
            .unwrap();
        assert!(restored.list_targets("other-project").await.is_empty());

        restored
            .remove_project_rule("resumed", &granted)
            .await
            .unwrap();
        let after_revoke = SessionSsh::new(home.path().to_owned());
        after_revoke
            .restore_project_rules("reopened", &raw)
            .await
            .unwrap();
        assert!(matches!(
            after_revoke
                .resolve_invocation("reopened", None, None, SshOperation::Read, "read")
                .await,
            Err(SshServiceError::NoDefaultBinding)
        ));
    }

    #[tokio::test]
    async fn project_open_reuses_only_the_exact_verified_saved_remote_rule() {
        let home = tempfile::tempdir().unwrap();
        let location = ProjectLocation::Ssh {
            target_id: "target".into(),
            root: "/canonical/project".into(),
        };
        let service = SessionSsh::new(home.path().to_owned());
        service
            .register_project_location("original", None, &location)
            .await
            .unwrap();
        let mut remembered = binding("remembered", "original", "/canonical/project");
        remembered.capabilities = SshCapabilities::read_only();
        service
            .persist_grant_state(
                "original",
                &SessionState::default(),
                &remembered,
                SshGrantScope::ProjectRule,
                true,
            )
            .await
            .unwrap();

        let restored = SessionSsh::new(home.path().to_owned());
        restored
            .register_project_location("child", None, &location)
            .await
            .unwrap();
        restored.mark_project_open_prepared("child").await;
        let prepared = restored
            .restore_matching_project_rule(
                "child",
                &location,
                &remembered.identity,
                Some(SshCapabilities::read_only()),
            )
            .await
            .unwrap()
            .expect("exact remembered remote project is reusable");
        assert_eq!(prepared.root, "/canonical/project");
        assert_eq!(prepared.capabilities, SshCapabilities::read_only());
        assert!(restored.inner.workers.lock().await.is_empty());
        restored
            .restore_project_rules("child", &location)
            .await
            .unwrap();

        let snapshot = restored.snapshot_session("child").await;
        assert_eq!(snapshot.grants.len(), 1);
        assert_eq!(snapshot.grants[0].binding.capabilities, SshCapabilities::read_only());
        let changed_identity = SshHostIdentity {
            fingerprint: "SHA256:changed".into(),
            ..remembered.identity.clone()
        };
        assert!(
            restored
                .restore_matching_project_rule(
                    "identity-changed",
                    &location,
                    &changed_identity,
                    Some(SshCapabilities::read_only()),
                )
                .await
                .unwrap()
                .is_none()
        );
        let changed_root = ProjectLocation::Ssh {
            target_id: "target".into(),
            root: "/canonical/other".into(),
        };
        assert!(
            restored
                .restore_matching_project_rule(
                    "root-changed",
                    &changed_root,
                    &remembered.identity,
                    Some(SshCapabilities::read_only()),
                )
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            restored
                .restore_matching_project_rule(
                    "capabilities-expanded",
                    &location,
                    &remembered.identity,
                    Some(SshCapabilities::all()),
                )
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn project_open_source_reuse_is_exact_and_never_unions_capabilities() {
        let home = tempfile::tempdir().unwrap();
        let service = SessionSsh::new(home.path().to_owned());
        let broad = binding("broad", "source", "/remote/project");
        let mut narrow = binding("narrow", "source", "/remote/project");
        narrow.capabilities = SshCapabilities::read_only();
        service
            .restore_session(
                "source",
                PersistedSshState {
                    grants: vec![
                        PersistedSshGrant {
                            binding: broad.clone(),
                            parent_binding_id: None,
                            requires_revalidation: false,
                            scope: SshGrantScope::CurrentSession,
                            revoke_status: None,
                            worker_bound: false,
                            worker_commands: Vec::new(),
                        },
                        PersistedSshGrant {
                            binding: narrow.clone(),
                            parent_binding_id: None,
                            requires_revalidation: false,
                            scope: SshGrantScope::CurrentSession,
                            revoke_status: None,
                            worker_bound: false,
                            worker_commands: Vec::new(),
                        },
                    ],
                    ..Default::default()
                },
            )
            .await;

        let selected = service
            .matching_live_project_binding(
                "source",
                "target",
                &broad.identity,
                "/remote/project",
                None,
            )
            .await
            .expect("the exact source authority is available");
        assert_eq!(selected.id, "narrow");
        assert_eq!(selected.capabilities, SshCapabilities::read_only());
        assert!(
            service
                .matching_live_project_binding(
                    "source",
                    "target",
                    &broad.identity,
                    "/different/project",
                    None,
                )
                .await
                .is_none()
        );
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
    fn inspection_rejects_changed_identity_or_scope_expansion() {
        let identity = SshHostIdentity {
            hostname: "host".into(),
            port: 22,
            username: "user".into(),
            fingerprint: "fingerprint".into(),
        };
        let request = SshGrantRequest {
            id: "request".into(),
            session_id: "session".into(),
            originating_session_id: None,
            target_id: Some("target".into()),
            root: Some("/canonical/project".into()),
            capabilities: SshCapabilities::read_only(),
            reason: "test".into(),
            verified_identity: Some(identity.clone()),
            client_id: Some(7),
            awaiting_tool: false,

        };

        assert!(ensure_inspection_identity(&request, Some(&identity), &identity).is_ok());
        assert!(matches!(
            ensure_inspection_identity(
                &request,
                Some(&SshHostIdentity {
                    fingerprint: "unexpected".into(),
                    ..identity.clone()
                }),
                &identity,
            ),
            Err(SshServiceError::IdentityChanged)
        ));
        assert!(matches!(
            ensure_inspection_identity(
                &request,
                Some(&identity),
                &SshHostIdentity {
                    fingerprint: "changed".into(),
                    ..identity.clone()
                },
            ),
            Err(SshServiceError::IdentityChanged)
        ));
        assert!(ensure_inspection_root_within_limit(
            Some("/canonical/project/subdir"),
            Some("/canonical/project"),
        )
        .is_ok());
        assert!(matches!(
            ensure_inspection_root_within_limit(
                Some("/canonical/other"),
                Some("/canonical/project"),
            ),
            Err(SshServiceError::GrantExpansion)
        ));
        assert!(matches!(
            choose_narrower_target(&request, Some("other-target")),
            Err(SshServiceError::GrantExpansion)
        ));
    }

    #[tokio::test]
    async fn inspection_commit_retains_original_request_owner_and_scope() {
        let home = tempfile::tempdir().unwrap();
        let service = SessionSsh::new(home.path().to_owned());
        let request = service
            .publish_grant_request(SshGrantRequest {
                id: "request".into(),
                session_id: "session".into(),
                originating_session_id: Some("origin".into()),
                target_id: Some("target".into()),
                root: Some("/requested/root".into()),
                capabilities: SshCapabilities::read_only(),
                reason: "retain request metadata".into(),
                verified_identity: None,
                client_id: Some(7),
                awaiting_tool: false,

            })
            .await
            .unwrap();
        let identity = SshHostIdentity {
            hostname: "host".into(),
            port: 22,
            username: "user".into(),
            fingerprint: "fingerprint".into(),
        };

        let updated = service
            .finish_grant_inspection(
                &request,
                "target".into(),
                Some("/requested/root/subdir".into()),
                identity.clone(),
                service.target_config_epoch(),
            )
            .await
            .unwrap();

        assert_eq!(updated.id, request.id);
        assert_eq!(updated.session_id, request.session_id);
        assert_eq!(updated.originating_session_id, request.originating_session_id);
        assert_eq!(updated.capabilities, request.capabilities);
        assert_eq!(updated.client_id, request.client_id);
        assert_eq!(updated.root.as_deref(), Some("/requested/root/subdir"));
        assert_eq!(updated.verified_identity.as_ref(), Some(&identity));
        assert!(matches!(
            service.check_request_client(&updated, 8),
            Err(SshServiceError::WrongClient)
        ));
        assert_eq!(
            service.pending_request(&request.id).await.unwrap(),
            updated,
        );
    }

    #[tokio::test]
    async fn late_inspection_result_after_denial_cannot_reopen_request() {
        let home = tempfile::tempdir().unwrap();
        let service = SessionSsh::new(home.path().to_owned());
        let mut events = service.subscribe_events();
        let request = service
            .request_grant(
                "session",
                None,
                Some("/requested/root".into()),
                SshCapabilities::read_only(),
                "inspect a remote project".into(),
                Some(7),
            )
            .await
            .unwrap();
        assert!(matches!(
            events.recv().await.unwrap(),
            SshEvent::GrantRequested(published) if published == request
        ));

        assert!(
            service
                .approve_grant(SshGrantDecision {
                    request_id: request.id.clone(),
                    approved: false,
                    target_id: None,
                    root: None,
                    capabilities: None,
                    scope: SshGrantScope::CurrentSession,
                    make_default: false,
                    client_id: 7,
                })
                .await
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            events.recv().await.unwrap(),
            SshEvent::GrantResolved {
                request_id,
                approved: false,
                binding: None,
            } if request_id == request.id
        ));

        assert!(matches!(
            service
                .finish_grant_inspection(
                    &request,
                    "target".into(),
                    Some("/requested/root".into()),
                    SshHostIdentity {
                        hostname: "host".into(),
                        port: 22,
                        username: "user".into(),
                        fingerprint: "fingerprint".into(),
                    },
                    service.target_config_epoch(),
                )
                .await,
            Err(SshServiceError::UnknownGrantRequest(_))
        ));
        assert!(matches!(
            events.try_recv(),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty)
        ));
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
            awaiting_tool: false,

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
                                worker_bound: false,
                                worker_commands: Vec::new(),
                            },
                            revoked: Arc::new(AtomicBool::new(false)),
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
                                worker_bound: false,
                                worker_commands: Vec::new(),
                            },
                            revoked: Arc::new(AtomicBool::new(false)),
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

    #[tokio::test]
    async fn native_ssh_revoke_is_offline_and_invalidates_child_inflight_authority() {
        let home = tempfile::tempdir().unwrap();
        let service = SessionSsh::new(home.path().to_owned());
        let parent = binding("native-parent", "parent-session", "/repo");
        service
            .restore_session(
                "parent-session",
                PersistedSshState {
                    grants: vec![PersistedSshGrant {
                        binding: parent.clone(),
                        parent_binding_id: None,
                        requires_revalidation: true,
                        scope: SshGrantScope::CurrentSession,
                        revoke_status: None,
                        worker_bound: false,
                        worker_commands: Vec::new(),
                    }],
                    default_binding_id: Some(parent.id.clone()),
                    pending_requests: vec![],
                },
            )
            .await;
        let children = service
            .inherit_session(
                "parent-session",
                "child-session",
                &[parent.id.clone()],
                SshCapabilities::read_only(),
            )
            .await
            .unwrap();
        let token = service.inner.sessions.read().await["child-session"].grants[&children[0].id]
            .revoked
            .clone();
        assert!(!token.load(Ordering::Acquire));
        assert_eq!(
            service
                .revoke_binding("parent-session", &parent.id)
                .await
                .unwrap(),
            RevokeStatus::Confirmed
        );
        assert!(token.load(Ordering::Acquire));
        for session in ["parent-session", "child-session"] {
            let state = service.snapshot_session(session).await;
            assert!(state.default_binding_id.is_none());
            assert!(state.grants.iter().all(|grant| grant.binding.revoked
                && grant.revoke_status == Some(SshGrantStatus::RevokedConfirmed)));
        }
    }

    #[tokio::test]
    async fn pre_native_ssh_grant_still_requires_remote_revoke_confirmation() {
        let home = tempfile::tempdir().unwrap();
        let service = SessionSsh::new(home.path().to_owned());
        let legacy: PersistedSshGrant = serde_json::from_value(serde_json::json!({
            "binding": binding("legacy", "legacy-session", "/repo"),
            "scope": "current_session"
        }))
        .unwrap();
        service
            .restore_session(
                "legacy-session",
                PersistedSshState {
                    grants: vec![legacy],
                    default_binding_id: Some("legacy".into()),
                    pending_requests: vec![],
                },
            )
            .await;
        assert_eq!(
            service
                .revoke_binding("legacy-session", "legacy")
                .await
                .unwrap(),
            RevokeStatus::LocalPending
        );
        assert_eq!(
            service
                .revoke_binding("legacy-session", "legacy")
                .await
                .unwrap(),
            RevokeStatus::LocalPending
        );
        let restored = service.snapshot_session("legacy-session").await;
        assert_eq!(
            restored.grants[0].revoke_status,
            Some(SshGrantStatus::RevokedLocalPending)
        );
    }

    #[tokio::test]
    async fn native_ssh_pending_revoke_recovers_locally_without_worker_authority() {
        let home = tempfile::tempdir().unwrap();
        let service = SessionSsh::new(home.path().to_owned());
        let mut revoked = binding("native-recovery", "recovery", "/repo");
        revoked.revoked = true;
        revoked.epoch = 2;
        service
            .restore_session(
                "recovery",
                PersistedSshState {
                    grants: vec![PersistedSshGrant {
                        binding: revoked,
                        parent_binding_id: None,
                        requires_revalidation: false,
                        scope: SshGrantScope::CurrentSession,
                        revoke_status: Some(SshGrantStatus::RevokedLocalPending),
                        worker_bound: false,
                        worker_commands: Vec::new(),
                    }],
                    default_binding_id: None,
                    pending_requests: vec![],
                },
            )
            .await;
        assert_eq!(
            service
                .revoke_binding("recovery", "native-recovery")
                .await
                .unwrap(),
            RevokeStatus::Confirmed
        );
        assert_eq!(
            service.snapshot_session("recovery").await.grants[0].revoke_status,
            Some(SshGrantStatus::RevokedConfirmed)
        );
    }

    #[tokio::test]
    async fn target_control_preserves_label_only_access_and_revokes_changed_or_deleted_targets() {
        let home = tempfile::tempdir().unwrap();
        let service = SessionSsh::new(home.path().to_owned());
        let mut target = xai_grok_ssh::SshTarget::new("first.example.test");
        target.id = "target".into();
        target.label = "First host".into();
        let target = service.inner.targets.upsert(target).unwrap();
        let granted = binding("binding", "session", "/repo");
        service
            .restore_session(
                "session",
                PersistedSshState {
                    grants: vec![PersistedSshGrant {
                        binding: granted.clone(),
                        parent_binding_id: None,
                        requires_revalidation: true,
                        scope: SshGrantScope::CurrentSession,
                        revoke_status: None,
                        worker_bound: false,
                        worker_commands: Vec::new(),
                    }],
                    default_binding_id: Some(granted.id.clone()),
                    pending_requests: Vec::new(),
                },
            )
            .await;

        let mut label_update = target.clone();
        label_update.label = "Renamed host".into();
        assert!(matches!(
            service
                .control(
                    7,
                    SshControlCommand::UpdateTarget {
                        expected: target.clone(),
                        replacement: label_update.clone(),
                    },
                )
                .await,
            Ok(SshControlReply::TargetUpdated(updated)) if updated == label_update
        ));
        assert_eq!(service.list_targets("session").await.len(), 1);

        let (response, receiver) = oneshot::channel();
        service.inner.approval_waiters.lock().await.insert(
            "old-approval".into(),
            PendingOperationApproval {
                client_id: 7,
                binding: granted.clone(),
                target_epoch: service.target_config_epoch(),
                operation: SshOperation::Execute,
                allow_session: true,
                generation: 0,
                response,
            },
        );
        let mut connection_update = label_update.clone();
        connection_update.host = "second.example.test".into();
        assert!(matches!(
            service
                .control(
                    7,
                    SshControlCommand::UpdateTarget {
                        expected: label_update,
                        replacement: connection_update.clone(),
                    },
                )
                .await,
            Ok(SshControlReply::TargetUpdated(updated)) if updated == connection_update
        ));
        assert!(service.list_targets("session").await.is_empty());
        assert!(receiver.await.is_err());
        assert!(matches!(
            service
                .control(
                    7,
                    SshControlCommand::SubmitOperationApproval(
                        SshOperationApprovalDecision {
                            client_id: 7,
                            approval_id: "old-approval".into(),
                            approved: true,
                            scope: SshOperationApprovalScope::Session,
                        },
                    ),
                )
                .await,
            Ok(SshControlReply::OperationApprovalExpired)
        ));

        let deleted_grant = binding("deleted-binding", "deleted-session", "/repo");
        service
            .restore_session(
                "deleted-session",
                PersistedSshState {
                    grants: vec![PersistedSshGrant {
                        binding: deleted_grant.clone(),
                        parent_binding_id: None,
                        requires_revalidation: true,
                        scope: SshGrantScope::CurrentSession,
                        revoke_status: None,
                        worker_bound: false,
                        worker_commands: Vec::new(),
                    }],
                    default_binding_id: Some(deleted_grant.id.clone()),
                    pending_requests: Vec::new(),
                },
            )
            .await;
        assert!(matches!(
            service
                .control(
                    7,
                    SshControlCommand::RemoveTarget {
                        expected: connection_update,
                    },
                )
                .await,
            Ok(SshControlReply::TargetRemoved(removed)) if removed.id == "target"
        ));
        assert!(service.list_targets("deleted-session").await.is_empty());
        assert!(
            service
                .inner
                .targets
                .get("target")
                .unwrap()
                .is_none()
        );
    }
}
