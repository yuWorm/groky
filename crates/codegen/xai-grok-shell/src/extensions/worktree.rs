//! Handler for x.ai/git/worktree/* extension methods.

use anyhow::Context;

use agent_client_protocol as acp;
use xai_acp_lib::AcpAgentGatewaySender as GatewaySender;

use crate::extensions::agent_runtime::AgentRuntime;
use crate::extensions::worktree_seed;
use crate::session::ExtMethodResult;
use crate::session::persistence::{LocalSessionResolutionKind, find_summary_by_session_id, persist_ssh_state};
use crate::session::worktree::{
    ApplyWorktreeRequest, CreateWorktreeFromWorktreeRequest, CreateWorktreeRequest,
    CreateWorktreeResponse, RehydrateSessionRequest, RemoveWorktreeRequest,
    ResumeSessionInWorktreeRequest, WorktreeNotificationSender, WorktreeStatus, WorktreeType,
    create_jj_workspace, create_worktree_async, create_worktree_from_worktree_async,
    rehydrate_session_in_worktree, resolve_session_repo_wide, resume_session_in_worktree,
};
use xai_grok_tools::types::output::ToolOutput;
use xai_grok_workspace_types::ssh::ProjectLocation;
use xai_grok_telemetry::instrument_task;
use xai_grok_telemetry::region::Parent;
use xai_grok_telemetry::session_ctx::spawn_local_in_session_ctx;

type ExtResult = Result<acp::ExtResponse, acp::Error>;

pub(super) const WORKTREE_EXT_LOG: &str = "xai_worktree";

/// Wrapper to send worktree progress notifications via gateway.
#[derive(Clone)]
struct GatewayWorktreeNotifier {
    gateway: GatewaySender,
}

#[async_trait::async_trait]
impl WorktreeNotificationSender for GatewayWorktreeNotifier {
    async fn send_worktree_status(&self, progress: WorktreeStatus) {
        let params = match serde_json::value::to_raw_value(&progress) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("Failed to serialize worktree progress: {}", e);
                return;
            }
        };
        let notification = acp::ExtNotification::new("x.ai/git/worktree/status", params.into());
        if let Err(e) = self.gateway.send(notification).await {
            tracing::warn!("Failed to send worktree progress notification: {}", e);
        }
    }
}

fn to_response<T: serde::Serialize>(result: anyhow::Result<T>) -> ExtResult {
    ExtMethodResult::from_result(result)
        .to_ext_response()
        .map_err(|e| acp::Error::internal_error().data(e.to_string()))
}

/// `resolved_source_git_root` is `serde(skip)`; copy it in-process from Creating.
fn extract_creating(resp: &CreateWorktreeResponse) -> Option<(String, Option<String>)> {
    if let CreateWorktreeResponse::Creating {
        worktree_path,
        source_git_root,
        ..
    } = resp
    {
        Some((worktree_path.clone(), source_git_root.clone()))
    } else {
        None
    }
}

fn shell_quote_remote_arg(argument: &str) -> anyhow::Result<String> {
    if argument.as_bytes().contains(&0) {
        anyhow::bail!("remote worktree argument contains a NUL byte");
    }
    Ok(format!("'{}'", argument.replace('\'', "'\"'\"'")))
}

fn canonical_remote_worktree_root(command_output: &[u8]) -> anyhow::Result<String> {
    let root = std::str::from_utf8(command_output)
        .context("remote worktree command returned non-UTF-8 canonical path")?
        .lines()
        .rev()
        .find(|line| !line.is_empty())
        .ok_or_else(|| anyhow::anyhow!("remote worktree command did not report its canonical path"))?;
    if !root.starts_with('/') || root.as_bytes().contains(&0) {
        anyhow::bail!("remote worktree command returned an invalid canonical path");
    }
    Ok(root.to_owned())
}

async fn run_remote_worktree_command(
    ops: &xai_grok_workspace::WorkspaceOps,
    session_id: &str,
    command: String,
) -> anyhow::Result<String> {
    let call_id = format!("ssh-worktree-{}", uuid::Uuid::now_v7());
    let result = ops
        .call_tool(
            "GrokBuild:run_terminal_cmd",
            serde_json::json!({
                "command": command,
                "description": "Create or inspect the requested remote Git worktree",
            }),
            &call_id,
            Some(session_id),
        )
        .await
        .map_err(|error| anyhow::anyhow!("remote worktree command was not completed: {error}"))?;
    match result.output {
        ToolOutput::Bash(output) if output.exit_code == 0 => {
            String::from_utf8(output.output)
                .context("remote worktree command returned non-UTF-8 output")
        }
        ToolOutput::Bash(output) => anyhow::bail!(
            "remote worktree command failed with exit code {}: {}",
            output.exit_code,
            String::from_utf8_lossy(&output.output).trim()
        ),
        _ => anyhow::bail!("remote worktree command did not return terminal output"),
    }
}

async fn resume_ssh_session_in_worktree(
    agent: &dyn AgentRuntime,
    fallback_ops: &xai_grok_workspace::WorkspaceOps,
    req: &ResumeSessionInWorktreeRequest,
    worktree_type_default: crate::util::config::WorktreeType,
    grove_worktree: bool,
    grove_gate_source: &'static str,
    agent_id: &str,
) -> anyhow::Result<xai_grok_workspace::worktree::ResumeSessionInWorktreeResponse> {
    let source_summary = find_summary_by_session_id(&req.session_id).ok_or_else(|| {
        anyhow::anyhow!(
            "SSH session {} has no persisted project location; it cannot be resumed into a worktree",
            req.session_id
        )
    })?;
    let source_location = source_summary.project_location.ok_or_else(|| {
        anyhow::anyhow!(
            "session {} is a legacy local history, not an SSH project session",
            req.session_id
        )
    })?;
    let ProjectLocation::Ssh {
        target_id: source_target_id,
        root: source_root,
    } = &source_location
    else {
        anyhow::bail!("session {} is not an SSH project session", req.session_id);
    };

    let source_ops = agent
        .workspace_ops_for_session(&acp::SessionId::new(req.session_id.clone()))
        .unwrap_or_else(|_| fallback_ops.clone());
    let source_client = source_ops.ssh_client().ok_or_else(|| {
        anyhow::anyhow!("SSH worktree resume requires the source session's remote workspace")
    })?;
    let source_binding = source_client.binding().await;
    if source_binding.session_id != req.session_id
        || source_binding.target_id != *source_target_id
        || source_binding.root != *source_root
    {
        anyhow::bail!(
            "SSH worktree resume requires the source session's exact approved project binding"
        );
    }
    if !source_binding.capabilities.execute {
        anyhow::bail!(
            "SSH worktree resume requires Execute capability on the source project binding"
        );
    }
    if !source_root.starts_with('/') || source_root.as_bytes().contains(&0) {
        anyhow::bail!("SSH worktree resume requires an absolute canonical remote project root");
    }

    let new_session_id = uuid::Uuid::now_v7().to_string();
    let worktree_request = CreateWorktreeFromWorktreeRequest {
        source_worktree_path: source_root.clone(),
        new_session_id: new_session_id.clone(),
        copy_mode: if req.git_ref.is_some() {
            crate::session::worktree::WorktreeCopyMode::Clean
        } else {
            req.copy_mode
        },
        git_ref: req.git_ref.clone(),
        worktree_type: Some(req.worktree_type.unwrap_or(worktree_type_default.into())),
        label: None,
        grove_worktree: Some(grove_worktree),
        grove_gate_source: Some(grove_gate_source.to_owned()),
        cancellation_token: None,
        resolved_dest_path: None,
        resolved_source_git_root: None,
    };
    // Use the worker's existing worktree implementation so Dirty/Clean,
    // standalone/linked and the selected Git ref retain their normal semantics.
    let created = source_ops
        .dispatch(
            &xai_grok_workspace::workspace_ops::CreateWorktreeFromWorktreeSyncReq {
                inner: worktree_request.into_wire(),
            },
            Some(&req.session_id),
        )
        .await
        .map_err(|error| anyhow::anyhow!("remote worktree creation failed: {error}"))?;
    let worktree_path = created.worktree_path;
    if !worktree_path.starts_with('/') || worktree_path.as_bytes().contains(&0) {
        anyhow::bail!("remote worktree creation returned a non-absolute destination");
    }
    let destination = shell_quote_remote_arg(&worktree_path)?;
    let inspect_command = format!("cd -- {destination} && pwd -P");
    let command_output = run_remote_worktree_command(&source_ops, &req.session_id, inspect_command)
        .await
        .map_err(|error| {
            anyhow::anyhow!(
                "remote worktree at {worktree_path} may already exist; original session {} was left unchanged: {error}",
                req.session_id
            )
        })?;
    let canonical_root = canonical_remote_worktree_root(command_output.as_bytes()).map_err(|error| {
        anyhow::anyhow!(
            "remote worktree at {worktree_path} was created but its canonical root could not be confirmed; original session {} was left unchanged: {error}",
            req.session_id
        )
    })?;
    let child_location = ProjectLocation::Ssh {
        target_id: source_target_id.clone(),
        root: canonical_root.clone(),
    };
    let service = agent.session_ssh().ok_or_else(|| {
        anyhow::anyhow!(
            "remote worktree at {canonical_root} was created but SSH approval is unavailable; original session {} was left unchanged",
            req.session_id
        )
    })?;
    let approval_client_id = service
        .interaction_client_id(&source_binding.id)
        .await
        .ok_or_else(|| {
            anyhow::anyhow!(
                "remote worktree at {canonical_root} was created but its source SSH interaction owner is no longer connected; original session {} was left unchanged",
                req.session_id
            )
        })?;
    service
        .register_project_location(&new_session_id, None, &child_location)
        .await
        .map_err(|error| {
            anyhow::anyhow!(
                "remote worktree at {canonical_root} was created but its child project registration failed; original session {} was left unchanged: {error}",
                req.session_id
            )
        })?;
    let mut events = service.subscribe_events();
    let grant = service
        .request_worktree_grant(
            new_session_id.clone(),
            &source_binding,
            canonical_root.clone(),
            approval_client_id,
        )
        .await
        .map_err(|error| {
            anyhow::anyhow!(
                "remote worktree at {canonical_root} was created but the new-root approval request failed; original session {} was left unchanged: {error}",
                req.session_id
            )
        })?;
    let (approved, approved_binding) = tokio::time::timeout(
        std::time::Duration::from_secs(300),
        async {
            loop {
                match events.recv().await {
                    Ok(crate::ssh::SshEvent::GrantResolved {
                        request_id,
                        approved,
                        binding,
                    }) if request_id == grant.id => return Ok((approved, binding)),
                    Ok(crate::ssh::SshEvent::GrantCancelled { request_id, .. })
                        if request_id == grant.id =>
                    {
                        anyhow::bail!("SSH approval was cancelled")
                    }
                    Ok(crate::ssh::SshEvent::GrantFailed {
                        request_id, error, ..
                    }) if request_id == grant.id => {
                        anyhow::bail!("SSH approval failed: {error}")
                    }
                    Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        anyhow::bail!("SSH grant approval stream closed")
                    }
                }
            }
        },
    )
    .await
    .map_err(|_| {
        anyhow::anyhow!(
            "remote worktree at {canonical_root} was created and left in place because approval for its new root timed out; original session {} was left unchanged",
            req.session_id
        )
    })?
    .map_err(|error| {
        anyhow::anyhow!(
            "remote worktree at {canonical_root} was created and left in place because its new-root approval did not complete; original session {} was left unchanged: {error}",
            req.session_id
        )
    })?;
    if !approved {
        anyhow::bail!(
            "remote worktree at {canonical_root} was created and left in place because its new-root approval was declined; original session {} was left unchanged",
            req.session_id
        );
    }
    let approved_binding = approved_binding.ok_or_else(|| {
        anyhow::anyhow!(
            "remote worktree at {canonical_root} was created and left in place because approval returned no binding; original session {} was left unchanged",
            req.session_id
        )
    })?;
    if approved_binding.target_id != *source_target_id || approved_binding.root != canonical_root {
        anyhow::bail!(
            "remote worktree at {canonical_root} was created and left in place because approval did not grant its exact new root; original session {} was left unchanged",
            req.session_id
        );
    }
    service
        .use_binding(&new_session_id, &approved_binding.id)
        .await
        .map_err(|error| {
            anyhow::anyhow!(
                "remote worktree at {canonical_root} was created and approved but its child binding could not be selected; original session {} was left unchanged: {error}",
                req.session_id
            )
        })?;
    let mut restore = crate::session::worktree::WorktreeRestoreDecision {
        code_restored: false,
        restore_summary: None,
        restore_degree: None,
    };
    if req.restore_code.unwrap_or(agent.restore_code())
        && let Some(target_sha) = source_summary.head_commit.as_deref()
    {
        let child_client = service
            .project_workspace_client(&new_session_id, &approved_binding.id, Some(approval_client_id))
            .await
            .map_err(|error| anyhow::anyhow!("opening SSH worktree for code restore failed: {error}"))?;
        let child_ops = xai_grok_workspace::WorkspaceOps::ssh(child_client);
        let outcome = child_ops
            .checkout_session_commit(target_sha, &new_session_id)
            .await
            .map_err(|error| {
                anyhow::anyhow!(
                    "remote worktree at {canonical_root} was created and approved but code restore failed; it was left in place and original session {} was left unchanged: {error}",
                    req.session_id
                )
            })?;
        let kind = if outcome.checked_out {
            xai_grok_workspace::session::git::RestoreKind::RegistryOff
        } else {
            xai_grok_workspace::session::git::RestoreKind::CheckoutFailed
        };
        restore = crate::session::worktree::build_worktree_restore_outcome(
            Some(target_sha),
            &outcome,
            kind,
        );
    }

    let fork = crate::session::fork::fork_session(
        crate::session::fork::ForkSessionRequest {
            source_session_id: req.session_id.clone(),
            source_cwd: source_root.clone(),
            new_cwd: canonical_root.clone(),
            new_session_id: Some(new_session_id.clone()),
            session_kind: Some("worktree".to_owned()),
            source_workspace_dir: Some(source_root.clone()),
            source_project_location: Some(source_location.clone()),
            new_project_location: Some(child_location.clone()),
            ..Default::default()
        },
        agent_id,
        Some(agent.auth_manager().clone()),
    )
    .await
    .map_err(|error| {
        anyhow::anyhow!(
            "remote worktree at {canonical_root} was created and approved but the session fork failed; it was left in place and original session {} was left unchanged: {error}",
            req.session_id
        )
    })?;
    let child_info = xai_grok_shared::session::info_for_location(
        acp::SessionId::new(fork.new_session_id.clone()),
        &child_location,
    );
    service
        .register_project_location(&fork.new_session_id, Some(child_info.clone()), &child_location)
        .await
        .map_err(|error| anyhow::anyhow!("registering SSH worktree session failed: {error}"))?;
    persist_ssh_state(
        &child_info,
        service.snapshot_session(&fork.new_session_id).await,
    )
    .await
    .map_err(|error| anyhow::anyhow!("persisting SSH worktree session state failed: {error}"))?;

    Ok(xai_grok_workspace::worktree::ResumeSessionInWorktreeResponse {
        session_id: fork.new_session_id,
        worktree_path: canonical_root.clone(),
        effective_cwd: canonical_root,
        project_location: Some(child_location),
        remote_restored: false,
        parent_session_id: req.session_id.clone(),
        chat_messages_copied: fork.chat_messages_copied,
        updates_copied: fork.updates_copied,
        code_restored: restore.code_restored,
        restore_summary: restore.restore_summary,
        restore_degree: restore.restore_degree,
        strategy: created.strategy,
    })
}

// ── ACP request types for worktree management ──────────────────────────────────────────────────

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListWorktreeRequest {
    #[serde(default)]
    pub repo: Option<String>,
    #[serde(default)]
    pub r#type: Vec<String>,
    #[serde(default)]
    pub include_all: bool,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ShowWorktreeRequest {
    pub id_or_path: String,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GcWorktreeRequest {
    #[serde(default)]
    pub dry_run: bool,
    /// Duration string like "7d", "24h", "30m", "60s".
    #[serde(default)]
    pub max_age: Option<String>,
    #[serde(default)]
    pub force: bool,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorktreeDbPathResponse {
    pub path: String,
}

/// `create_from_worktree_sync` response plus the optional branch step.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SeededForkResponse {
    #[serde(flatten)]
    pub created: xai_grok_workspace::worktree::CreateWorktreeFromWorktreeResponse,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branch: Option<worktree_seed::BranchOutcome>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ResolveLocalForWorktreeResumeRequest {
    pub session_id: String,
    pub cwd: String,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ResolveLocalForWorktreeResumeResponse {
    pub found: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_cwd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolution_kind: Option<LocalSessionResolutionKind>,
}
fn parse_duration(s: &str) -> Result<i64, acp::Error> {
    let s = s.trim();
    let (num, mult) = if let Some(n) = s.strip_suffix('d') {
        (n, 86400i64)
    } else if let Some(n) = s.strip_suffix('h') {
        (n, 3600)
    } else if let Some(n) = s.strip_suffix('m') {
        (n, 60)
    } else if let Some(n) = s.strip_suffix('s') {
        (n, 1)
    } else {
        return Err(acp::Error::invalid_params().data(format!(
            "invalid duration: {s} (expected e.g. 7d, 24h, 30m, 60s)"
        )));
    };
    num.parse::<i64>()
        .map(|v| v * mult)
        .map_err(|_| acp::Error::invalid_params().data(format!("invalid number in duration: {s}")))
}

fn log_effective_worktree_type(
    method: &str,
    request_worktree_type: Option<WorktreeType>,
    agent_default_worktree_type: crate::util::config::WorktreeType,
    effective_worktree_type: WorktreeType,
) {
    tracing::info!(
        target: WORKTREE_EXT_LOG,
        method,
        request_worktree_type = ?request_worktree_type,
        agent_default_worktree_type = ?agent_default_worktree_type,
        effective_worktree_type = ?effective_worktree_type,
        "WORKTREE_REQUEST_SHELL: resolved effective worktree type"
    );
}
#[tracing::instrument(name = "ext.worktree", skip_all, fields(method = %args.method))]
pub async fn handle(
    agent: &dyn AgentRuntime,
    ops: &xai_grok_workspace::WorkspaceOps,
    args: &acp::ExtRequest,
) -> ExtResult {
    let worktree_type_default = agent.worktree_type();
    let restore_code_default = agent.restore_code();

    match args.method.as_ref() {
        "x.ai/git/worktree/create" => {
            let mut req = serde_json::from_str::<CreateWorktreeRequest>(args.params.get())?;
            // Pre-dispatch: apply worktree_type default
            let request_worktree_type = req.worktree_type;
            if req.worktree_type.is_none() {
                req.worktree_type = Some(worktree_type_default.into());
            }
            req.grove_gate_source =
                Some(apply_grove_worktree_flag(agent, &mut req.grove_worktree).into());
            log_effective_worktree_type(
                "x.ai/git/worktree/create",
                request_worktree_type,
                worktree_type_default,
                req.worktree_type.unwrap_or(worktree_type_default.into()),
            );
            let result = ops
                .dispatch(&req, None)
                .await
                .map_err(|e| acp::Error::internal_error().data(e.to_string()))?;
            if !ops.is_ssh()
                && let Ok(resp) = serde_json::from_value::<CreateWorktreeResponse>(result.clone())
                && let Some((path, source_git_root)) = extract_creating(&resp)
            {
                req.worktree_path = Some(path);
                req.resolved_source_git_root = source_git_root;
                let notifier = GatewayWorktreeNotifier {
                    gateway: agent.gateway().clone(),
                };
                let copy_context = agent.background_copy_context();
                spawn_local_in_session_ctx(instrument_task!(
                    "worktree.create",
                    Parent::Root,
                    async move {
                        create_worktree_async(req, notifier, copy_context).await;
                    }
                ));
            }
            to_response(Ok(result))
        }
        "x.ai/git/worktree/remove" => {
            let req = serde_json::from_str::<RemoveWorktreeRequest>(args.params.get())?;
            let result = ops
                .dispatch(&req, None)
                .await
                .map_err(|e| acp::Error::internal_error().data(e.to_string()))?;
            to_response(Ok(result))
        }
        "x.ai/git/worktree/apply" => {
            let req = serde_json::from_str::<ApplyWorktreeRequest>(args.params.get())?;
            let result = ops
                .dispatch(&req, None)
                .await
                .map_err(|e| acp::Error::internal_error().data(e.to_string()))?;
            to_response(Ok(result))
        }
        // Create a worktree from an existing worktree (used during session fork)
        "x.ai/git/worktree/create_from_worktree" => {
            let mut req =
                serde_json::from_str::<CreateWorktreeFromWorktreeRequest>(args.params.get())?;
            let request_worktree_type = req.worktree_type;
            if req.worktree_type.is_none() {
                req.worktree_type = Some(worktree_type_default.into());
            }
            req.grove_gate_source =
                Some(apply_grove_worktree_flag(agent, &mut req.grove_worktree).into());
            log_effective_worktree_type(
                "x.ai/git/worktree/create_from_worktree",
                request_worktree_type,
                worktree_type_default,
                req.worktree_type.unwrap_or(worktree_type_default.into()),
            );
            if ops.is_ssh() {
                let response = ops
                    .dispatch(
                        &xai_grok_workspace::workspace_ops::CreateWorktreeFromWorktreeSyncReq {
                            inner: req.into_wire(),
                        },
                        None,
                    )
                    .await
                    .map_err(|e| acp::Error::internal_error().data(e.to_string()))?;
                return to_response(Ok(response));
            }
            let result = ops
                .dispatch(
                    &xai_grok_workspace::workspace_ops::PrepareWorktreeFromWorktreeReq {
                        inner: req.clone(),
                    },
                    None,
                )
                .await
                .map_err(|e| acp::Error::internal_error().data(e.to_string()))?;

            // Convert the serialized response back
            if let Some(err) = result.error {
                return Err(acp::Error::internal_error().data(err));
            }
            let response_value = result.response.unwrap_or(serde_json::Value::Null);
            let response: CreateWorktreeResponse =
                serde_json::from_value(response_value).map_err(|e| {
                    acp::Error::internal_error()
                        .data(format!("failed to deserialize response: {e}"))
                })?;

            if result.spawn_task {
                if let Some((path, source_git_root)) = extract_creating(&response) {
                    req.resolved_dest_path = Some(path);
                    req.resolved_source_git_root = source_git_root;
                }
                let notifier = GatewayWorktreeNotifier {
                    gateway: agent.gateway().clone(),
                };
                spawn_local_in_session_ctx(instrument_task!(
                    "worktree.create",
                    Parent::Root,
                    async move {
                        create_worktree_from_worktree_async(req, notifier).await;
                    }
                ));
            }

            to_response(Ok(response))
        }
        // Synchronous variant: waits for worktree creation to complete
        "x.ai/git/worktree/create_from_worktree_sync" => {
            let mut req =
                serde_json::from_str::<CreateWorktreeFromWorktreeRequest>(args.params.get())?;
            let seed = serde_json::from_str::<worktree_seed::SeedOptions>(args.params.get())?;
            seed.validate()
                .map_err(|e| acp::Error::invalid_params().data(e))?;

            let request_worktree_type = req.worktree_type;
            if req.worktree_type.is_none() {
                req.worktree_type = Some(worktree_type_default.into());
            }
            req.grove_gate_source =
                Some(apply_grove_worktree_flag(agent, &mut req.grove_worktree).into());
            if ops.is_ssh() {
                let created = ops
                    .dispatch(
                        &xai_grok_workspace::workspace_ops::CreateWorktreeFromWorktreeSyncReq {
                            inner: req.into_wire(),
                        },
                        None,
                    )
                    .await
                    .map_err(|e| acp::Error::internal_error().data(e.to_string()))?;
                return to_response(Ok(SeededForkResponse {
                    created,
                    branch: None,
                }));
            }

            // Nested clones keep libgit2; Grove dest is the fallback on partialclone.
            let source_path = std::path::Path::new(&req.source_worktree_path);
            if xai_grok_workspace::worktree::git_or_grove_is_jj_async(
                source_path,
                req.grove_worktree == Some(true),
            )
            .await
            {
                tracing::info!("using jj workspace for subagent isolation");
                return to_response(create_jj_workspace(&req).await);
            }

            log_effective_worktree_type(
                "x.ai/git/worktree/create_from_worktree_sync",
                request_worktree_type,
                worktree_type_default,
                req.worktree_type.unwrap_or(worktree_type_default.into()),
            );
            // Fetch in the source so linked and standalone copies both see the ref.
            if let Some(base_ref) = seed.base_ref.as_deref() {
                worktree_seed::fetch_base_ref(source_path, base_ref).await;
            }
            let mut result = ops
                .dispatch(
                    &xai_grok_workspace::workspace_ops::CreateWorktreeFromWorktreeSyncReq {
                        inner: req.into_wire(),
                    },
                    None,
                )
                .await
                .map_err(|e| acp::Error::internal_error().data(e.to_string()))?;
            // `checkout -B` on a `status: exists` tree would reset work already there.
            let branch = match seed.branch.as_deref() {
                Some(branch) if result.status == "created" => {
                    worktree_seed::checkout_branch(
                        std::path::Path::new(&result.worktree_path),
                        branch,
                        seed.base_ref.as_deref(),
                    )
                    .await
                }
                Some(branch) => {
                    tracing::info!(
                        target: WORKTREE_EXT_LOG,
                        branch,
                        status = %result.status,
                        worktree = %result.worktree_path,
                        "worktree seed: branch step skipped, worktree was not created by this call"
                    );
                    None
                }
                None => None,
            };
            if let Some(branch) = &branch {
                result.commit = Some(branch.commit.clone());
            }
            to_response(Ok(SeededForkResponse {
                created: result,
                branch,
            }))
        }
        // Resume a session in a fresh worktree.
        "x.ai/git/worktree/resume_session" => {
            let req = serde_json::from_str::<ResumeSessionInWorktreeRequest>(args.params.get())?;
            log_effective_worktree_type(
                "x.ai/git/worktree/resume_session",
                req.worktree_type,
                worktree_type_default,
                req.worktree_type.unwrap_or(worktree_type_default.into()),
            );
            let mut grove_worktree = None;
            let grove_gate_source = apply_grove_worktree_flag(agent, &mut grove_worktree);
            let grove_worktree = grove_worktree.unwrap_or(false);
            let registry_client = agent.session_registry_client();
            let agent_id = xai_grok_telemetry::id::agent_id();

            let source_ops = agent
                .workspace_ops_for_session(&acp::SessionId::new(req.session_id.clone()))
                .unwrap_or_else(|_| ops.clone());
            let source_is_ssh = source_ops.is_ssh()
                || find_summary_by_session_id(&req.session_id).is_some_and(|summary| {
                    matches!(summary.project_location, Some(ProjectLocation::Ssh { .. }))
                });
            if source_is_ssh {
                return to_response(
                    resume_ssh_session_in_worktree(
                        agent,
                        &source_ops,
                        &req,
                        worktree_type_default,
                        grove_worktree,
                        grove_gate_source,
                        &agent_id,
                    )
                    .await,
                );
            }
            to_response(
                resume_session_in_worktree(
                    &req,
                    ops,
                    worktree_type_default,
                    restore_code_default,
                    registry_client.as_ref(),
                    Some(agent.auth_manager().clone()),
                    &agent_id,
                    grove_worktree,
                    grove_gate_source,
                )
                .await,
            )
        }
        // ── Repo-wide session resolution ─────────────────────────────────
        "x.ai/session/resolve_local_for_worktree_resume" => {
            if ops.is_ssh() {
                return Err(acp::Error::invalid_params().data(
                    "local worktree-session resolution is unavailable for an SSH project",
                ));
            }
            let req =
                serde_json::from_str::<ResolveLocalForWorktreeResumeRequest>(args.params.get())?;
            let result = resolve_session_repo_wide(&req.session_id, std::path::Path::new(&req.cwd));
            match result {
                Ok(Some(resolved)) => to_response(Ok(ResolveLocalForWorktreeResumeResponse {
                    found: true,
                    resolved_session_id: Some(resolved.session_id),
                    resolved_cwd: Some(resolved.cwd),
                    resolution_kind: Some(resolved.resolution_kind),
                })),
                Ok(None) => to_response(Ok(ResolveLocalForWorktreeResumeResponse {
                    found: false,
                    resolved_session_id: None,
                    resolved_cwd: None,
                    resolution_kind: None,
                })),
                Err(e) => {
                    Err(acp::Error::internal_error()
                        .data(format!("repo-wide resolution failed: {e}")))
                }
            }
        }
        // ── Session rehydration (devbox recovery) ─────────────────────────
        "x.ai/session/rehydrate" => {
            let req = serde_json::from_str::<RehydrateSessionRequest>(args.params.get())?;
            let registry_client = agent.session_registry_client();
            let (grove_worktree, grove_gate_source) =
                crate::util::config::grove_worktree_gate(agent.remote_settings().as_ref());

            to_response(
                rehydrate_session_in_worktree(
                    &req,
                    ops,
                    registry_client.as_ref(),
                    grove_worktree,
                    grove_gate_source,
                )
                .await,
            )
        }
        // ── Worktree management methods ──────────────────────────────────
        "x.ai/git/worktree/list" => {
            let req: xai_grok_workspace::workspace_ops::WorktreeListReq =
                serde_json::from_str(args.params.get())
                    .map_err(|e| acp::Error::internal_error().data(e.to_string()))?;
            let result = ops
                .dispatch(&req, None)
                .await
                .map_err(|e| acp::Error::internal_error().data(e.to_string()))?;
            to_response(Ok(result))
        }
        "x.ai/git/worktree/show" => {
            let req = serde_json::from_str::<ShowWorktreeRequest>(args.params.get())?;
            let op = xai_grok_workspace::workspace_ops::WorktreeShowReq {
                id_or_path: req.id_or_path,
            };
            let result = ops
                .dispatch(&op, None)
                .await
                .map_err(|e| acp::Error::internal_error().data(e.to_string()))?;
            to_response(Ok(result))
        }
        "x.ai/git/worktree/gc" => {
            let req = serde_json::from_str::<GcWorktreeRequest>(args.params.get())?;
            let max_age_secs = req.max_age.as_deref().map(parse_duration).transpose()?;
            let op = xai_grok_workspace::workspace_ops::WorktreeGcReq {
                dry_run: req.dry_run,
                max_age_secs,
                force: req.force,
            };
            let result = ops
                .dispatch(&op, None)
                .await
                .map_err(|e| acp::Error::internal_error().data(e.to_string()))?;
            to_response(Ok(result))
        }
        "x.ai/git/worktree/db/stats" => {
            let result = ops
                .dispatch(
                    &xai_grok_workspace::workspace_ops::WorktreeDbStatsReq {},
                    None,
                )
                .await
                .map_err(|e| acp::Error::internal_error().data(e.to_string()))?;
            to_response(Ok(result))
        }
        "x.ai/git/worktree/db/rebuild" => {
            let result = ops
                .dispatch(
                    &xai_grok_workspace::workspace_ops::WorktreeDbRebuildReq {},
                    None,
                )
                .await
                .map_err(|e| acp::Error::internal_error().data(e.to_string()))?;
            to_response(Ok(result))
        }
        "x.ai/git/worktree/db/path" => {
            let result = ops
                .dispatch(
                    &xai_grok_workspace::workspace_ops::WorktreeDbPathReq {},
                    None,
                )
                .await
                .map_err(|e| acp::Error::internal_error().data(e.to_string()))?;
            to_response(Ok(result))
        }
        "x.ai/git/worktree/detach" => {
            #[derive(serde::Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct DetachReq {
                id_or_path: String,
                #[serde(default)]
                allow_copy: bool,
            }
            let req = serde_json::from_str::<DetachReq>(args.params.get())?;
            let result = ops
                .dispatch(
                    &xai_grok_workspace::workspace_ops::WorktreeDetachReq {
                        id_or_path: req.id_or_path,
                        allow_copy: req.allow_copy,
                    },
                    None,
                )
                .await
                .map_err(|e| acp::Error::internal_error().data(e.to_string()))?;
            to_response(Ok(result))
        }
        "x.ai/git/worktree/salvage" => {
            #[derive(serde::Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct SalvageReq {
                id_or_path: String,
                out: String,
            }
            let req = serde_json::from_str::<SalvageReq>(args.params.get())?;
            let result = ops
                .dispatch(
                    &xai_grok_workspace::workspace_ops::WorktreeSalvageReq {
                        id_or_path: req.id_or_path,
                        out: req.out,
                    },
                    None,
                )
                .await
                .map_err(|e| acp::Error::internal_error().data(e.to_string()))?;
            to_response(Ok(result))
        }
        "x.ai/git/worktree/clean-artifacts" => {
            #[derive(serde::Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct CleanReq {
                id_or_path: String,
            }
            let req = serde_json::from_str::<CleanReq>(args.params.get())?;
            let result = ops
                .dispatch(
                    &xai_grok_workspace::workspace_ops::WorktreeCleanArtifactsReq {
                        id_or_path: req.id_or_path,
                    },
                    None,
                )
                .await
                .map_err(|e| acp::Error::internal_error().data(e.to_string()))?;
            to_response(Ok(result))
        }
        _ => Err(acp::Error::method_not_found()),
    }
}

fn apply_grove_worktree_flag(agent: &dyn AgentRuntime, slot: &mut Option<bool>) -> &'static str {
    let root = crate::config::load_effective_config()
        .unwrap_or_else(|_| toml::Value::Table(toml::map::Map::new()));
    apply_grove_worktree_gate(slot, &root, agent.remote_settings().as_ref())
}

/// Always run the grove gate, even when `slot` is already `Some`; the kill switch applies last.
pub(crate) fn apply_grove_worktree_gate(
    slot: &mut Option<bool>,
    root: &toml::Value,
    remote: Option<&crate::util::config::RemoteSettings>,
) -> &'static str {
    let (enabled, src) = crate::util::config::gate_grove_worktree(*slot, root, remote);
    tracing::info!(
        target: WORKTREE_EXT_LOG,
        grove_worktree = enabled,
        source = src,
        "WORKTREE_REQUEST_SHELL: resolved grove materialize strategy"
    );
    *slot = Some(enabled);
    src
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[test]
    fn list_request_all_defaults() {
        let req: ListWorktreeRequest = serde_json::from_str("{}").unwrap();
        assert!(req.repo.is_none());
        assert!(req.r#type.is_empty());
        assert!(!req.include_all);
    }

    #[test]
    fn list_request_with_filters() {
        let json = r#"{"repo": "xai", "type": ["session", "fork"], "includeAll": true}"#;
        let req: ListWorktreeRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.repo.as_deref(), Some("xai"));
        assert_eq!(req.r#type, vec!["session", "fork"]);
        assert!(req.include_all);
    }

    #[test]
    fn show_request_deserializes() {
        let json = r#"{"idOrPath": "wt-abc"}"#;
        let req: ShowWorktreeRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.id_or_path, "wt-abc");
    }

    #[test]
    fn gc_request_all_defaults() {
        let req: GcWorktreeRequest = serde_json::from_str("{}").unwrap();
        assert!(!req.dry_run);
        assert!(req.max_age.is_none());
        assert!(!req.force);
    }

    #[test]
    fn gc_rejects_a_malformed_max_age() {
        let err = parse_duration("7x").unwrap_err().to_string();
        assert!(err.contains("invalid duration: 7x"), "{err}");
        assert_eq!(parse_duration("7d").unwrap(), 7 * 86_400);
    }

    #[test]
    fn gc_request_with_all_fields() {
        let json = r#"{"dryRun": true, "maxAge": "7d", "force": true}"#;
        let req: GcWorktreeRequest = serde_json::from_str(json).unwrap();
        assert!(req.dry_run);
        assert_eq!(req.max_age.as_deref(), Some("7d"));
        assert!(req.force);
    }

    #[test]
    fn apply_grove_worktree_gate_runs_when_slot_already_some() {
        let root: toml::Value = toml::from_str("[cli]\ngrove_worktree = true").unwrap();
        let remote = crate::util::config::RemoteSettings {
            grove_worktree: Some(false),
            ..Default::default()
        };
        let mut slot = Some(true);
        apply_grove_worktree_gate(&mut slot, &root, Some(&remote));
        assert_eq!(
            slot,
            Some(false),
            "ACP wrapper must re-run the gate when the client already set Some(true)"
        );
        let mut slot = Some(true);
        apply_grove_worktree_gate(&mut slot, &root, None);
        assert_eq!(
            slot,
            Some(true),
            "ACP wrapper must keep request Grove when remote settings are unavailable"
        );
    }

    fn clear_grove_env() {
        // SAFETY: callers are `#[serial]`; no concurrent env mutation.
        unsafe {
            std::env::remove_var(crate::util::config::ENV_WORKTREE_TYPE);
            std::env::remove_var(crate::util::config::ENV_GROVE);
        }
    }

    #[test]
    #[serial]
    fn inherit_grove_gate_attaches_opts_when_local_toml_is_on() {
        clear_grove_env();
        let root: toml::Value = toml::from_str("[cli]\ngrove_worktree = true").unwrap();
        let mut slot = None;
        let src = apply_grove_worktree_gate(&mut slot, &root, None);
        assert_eq!(src, "local");
        assert_eq!(slot, Some(true));
        assert!(
            crate::util::config::grove_worktree_opts_if_enabled(slot.unwrap_or(false))
                .is_some_and(|opts| opts.enabled)
        );
    }

    #[test]
    #[serial]
    fn inherit_grove_gate_skips_opts_when_default_off() {
        clear_grove_env();
        let root = toml::Value::Table(toml::map::Map::new());
        let mut slot = None;
        let src = apply_grove_worktree_gate(&mut slot, &root, None);
        assert_eq!(src, "default");
        assert_eq!(slot, Some(false));
        assert!(
            crate::util::config::grove_worktree_opts_if_enabled(slot.unwrap_or(false)).is_none()
        );
    }

    #[test]
    #[serial]
    fn inherit_grove_gate_skips_opts_on_remote_kill() {
        clear_grove_env();
        let root: toml::Value = toml::from_str("[cli]\ngrove_worktree = true").unwrap();
        let remote = crate::util::config::RemoteSettings {
            grove_worktree: Some(false),
            ..crate::util::config::RemoteSettings::default()
        };
        let mut slot = None;
        let src = apply_grove_worktree_gate(&mut slot, &root, Some(&remote));
        assert_eq!(src, "remote_kill");
        assert_eq!(slot, Some(false));
        assert!(
            crate::util::config::grove_worktree_opts_if_enabled(slot.unwrap_or(false)).is_none()
        );
    }

    #[test]
    fn parse_duration_valid_values() {
        assert_eq!(parse_duration("7d").unwrap(), 7 * 86400);
        assert_eq!(parse_duration("24h").unwrap(), 24 * 3600);
        assert_eq!(parse_duration("30m").unwrap(), 30 * 60);
        assert_eq!(parse_duration("60s").unwrap(), 60);
    }

    #[test]
    fn parse_duration_rejects_invalid() {
        assert!(parse_duration("bad").is_err());
        assert!(parse_duration("").is_err());
        assert!(parse_duration("7x").is_err());
        assert!(parse_duration("abcd").is_err());
    }

    #[test]
    fn db_path_response_serializes() {
        let resp = WorktreeDbPathResponse {
            path: "/home/user/.grok/worktrees.db".into(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"path\":\"/home/user/.grok/worktrees.db\""));
    }

    #[test]
    fn remove_request_rejects_both_fields_set() {
        use crate::session::worktree::{
            BackgroundCopyContext, RemoveWorktreeRequest, remove_worktree,
        };

        let req = RemoveWorktreeRequest {
            worktree_path: Some("/a".into()),
            id_or_path: Some("b".into()),
            force: false,
            dry_run: false,
        };
        let ctx = BackgroundCopyContext::new();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = rt.block_on(remove_worktree(&req, &ctx));
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("exactly one"), "unexpected error: {msg}");
    }

    #[test]
    fn remove_request_rejects_neither_field_set() {
        use crate::session::worktree::{
            BackgroundCopyContext, RemoveWorktreeRequest, remove_worktree,
        };

        let req = RemoveWorktreeRequest {
            worktree_path: None,
            id_or_path: None,
            force: false,
            dry_run: false,
        };
        let ctx = BackgroundCopyContext::new();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = rt.block_on(remove_worktree(&req, &ctx));
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("either worktreePath or idOrPath"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn db_rebuild_response_carries_report_not_null() {
        // Regression: forwarding `()` instead of the report yields `result: null`, which the CLI rejects with "ACP response missing result field"
        let report = serde_json::json!({
            "discovered": 5,
            "registered": 3,
            "already_tracked": 2,
        });
        let resp = to_response(Ok(report)).expect("rebuild response should serialize");
        let wire: serde_json::Value = serde_json::from_str(resp.0.get()).unwrap();

        let result = wire
            .get("result")
            .expect("envelope must carry a result field");
        assert!(!result.is_null(), "rebuild result must not be null");
        assert_eq!(result.get("discovered"), Some(&serde_json::json!(5)));
        assert_eq!(result.get("registered"), Some(&serde_json::json!(3)));
        assert_eq!(result.get("already_tracked"), Some(&serde_json::json!(2)));
        assert!(wire.get("error").is_none_or(|e| e.is_null()));
    }

    // === Tests for repo-wide session resolution ACP types ===

    #[test]
    fn resolve_local_request_deserializes() {
        let json = r#"{"sessionId": "sess-abc", "cwd": "/repo/main"}"#;
        let req: ResolveLocalForWorktreeResumeRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.session_id, "sess-abc");
        assert_eq!(req.cwd, "/repo/main");
    }

    #[test]
    fn resolve_local_response_found_serializes() {
        use crate::session::persistence::LocalSessionResolutionKind;
        let resp = ResolveLocalForWorktreeResumeResponse {
            found: true,
            resolved_session_id: Some("sess-123".into()),
            resolved_cwd: Some("/repo/wt-1".into()),
            resolution_kind: Some(LocalSessionResolutionKind::SameRepoDifferentCwd),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"found\":true"));
        assert!(json.contains("\"resolvedSessionId\":\"sess-123\""));
        assert!(json.contains("\"resolvedCwd\":\"/repo/wt-1\""));
        assert!(json.contains("\"resolutionKind\":"));
    }

    #[test]
    fn resolve_local_response_not_found_omits_optional_fields() {
        let resp = ResolveLocalForWorktreeResumeResponse {
            found: false,
            resolved_session_id: None,
            resolved_cwd: None,
            resolution_kind: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"found\":false"));
        assert!(!json.contains("resolvedSessionId"));
        assert!(!json.contains("resolvedCwd"));
        assert!(!json.contains("resolutionKind"));
    }

    #[test]
    fn remote_worktree_command_quotes_each_path_without_local_path_resolution() {
        assert_eq!(
            shell_quote_remote_arg("/srv/a b/'quoted'").unwrap(),
            "'/srv/a b/'\"'\"'quoted'\"'\"''"
        );
        assert!(shell_quote_remote_arg("/srv/\0bad").is_err());
    }

    #[test]
    fn remote_worktree_resume_accepts_only_remote_absolute_canonical_output() {
        assert_eq!(
            canonical_remote_worktree_root(b"remote diagnostic\n/srv/worktrees/fork\n").unwrap(),
            "/srv/worktrees/fork"
        );
        assert!(canonical_remote_worktree_root(b"relative/path\n").is_err());
    }
}
