use std::sync::OnceLock;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use xai_grok_workspace_types::ssh::{SshCapabilities, SshOperation};
use xai_tool_runtime::Tool;

use super::{SessionSshResource, SshDispatchRequest};

/// Register the explicit SSH tools once before a `ToolRegistryBuilder` is
/// created. Registration is intentionally explicit rather than a static
/// initializer so shell startup order remains deterministic.
pub fn register_tool_pack() {
    static REGISTERED: OnceLock<()> = OnceLock::new();
    REGISTERED.get_or_init(|| {
        xai_grok_tools::registry::types::register_tool_pack(register_tools);
    });
}

fn register_tools(builder: &mut xai_grok_tools::registry::types::ToolRegistryBuilder) {
    builder.register::<SshTargetsTool>();
    builder.register::<SshRequestAccessTool>();
    builder.register::<SshReadTool>();
    builder.register::<SshWriteTool>();
    builder.register::<SshEditTool>();
    builder.register::<SshSearchTool>();
    builder.register::<SshRunTool>();
    builder.register::<SshTaskQueryTool>();
    builder.register::<SshTaskCancelTool>();
}

pub(crate) fn configure_default_tools(definition: &mut xai_grok_agent::AgentDefinition) {
    register_tool_pack();
    if !definition.inject_default_tools {
        return;
    }
    let tools: [xai_grok_tools::registry::types::ToolConfig; 9] = [
        (&SshTargetsTool).into(),
        (&SshRequestAccessTool).into(),
        (&SshReadTool).into(),
        (&SshWriteTool).into(),
        (&SshEditTool).into(),
        (&SshSearchTool).into(),
        (&SshRunTool).into(),
        (&SshTaskQueryTool).into(),
        (&SshTaskCancelTool).into(),
    ];
    for tool in tools {
        if !definition
            .tool_config
            .tools
            .iter()
            .any(|existing| existing.id == tool.id)
        {
            definition.tool_config.tools.push(tool);
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
pub(super) struct SshTargetsInput {}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub(super) struct SshRequestAccessInput {
    /// Prefer the exact target_id returned by ssh_targets. A unique exact
    /// configured label, host, or imported alias is accepted; missing and
    /// ambiguous values fail before user approval is requested.
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub root: Option<String>,
    pub capabilities: SshCapabilityInput,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub(super) struct SshCapabilityInput {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl From<SshCapabilityInput> for SshCapabilities {
    fn from(value: SshCapabilityInput) -> Self {
        Self {
            read: value.read,
            write: value.write,
            execute: value.execute,
        }
    }
}

/// Common SSH routing fields are composed with the exact remote tool schemas.
/// `remote` is flattened, so the model receives the normal remote tool's
/// documented fields rather than an untyped JSON escape hatch.
trait SshForwardInput {
    fn target(&self) -> Option<&str>;
    fn cwd(&self) -> Option<&str>;
    fn into_remote_args(self) -> Result<serde_json::Value, serde_json::Error>;
}

macro_rules! remote_input {
    ($name:ident, $remote:path) => {
        #[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
        pub(super) struct $name {
            #[serde(default)]
            pub target: Option<String>,
            #[serde(default)]
            pub cwd: Option<String>,
            #[serde(flatten)]
            #[schemars(flatten)]
            pub remote: $remote,
        }

        impl SshForwardInput for $name {
            fn target(&self) -> Option<&str> {
                self.target.as_deref()
            }

            fn cwd(&self) -> Option<&str> {
                self.cwd.as_deref()
            }

            fn into_remote_args(self) -> Result<serde_json::Value, serde_json::Error> {
                serde_json::to_value(self.remote)
            }
        }
    };
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub(super) struct SshTextReadArgs {
    /// Remote UTF-8 text file, absolute or relative to the granted cwd.
    pub target_file: String,
    /// One-based starting line; a negative value reads relative to the end.
    #[serde(
        default,
        deserialize_with = "xai_grok_tools::types::schema::deserialize_lenient_i64"
    )]
    pub offset: Option<i64>,
    /// Maximum number of lines returned.
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub(super) struct SshCommandArgs {
    /// Shell command executed as the SSH user. The cwd is not a sandbox.
    pub command: String,
    pub description: String,
    /// Foreground execution timeout in milliseconds, at most 300000.
    /// Zero starts a background task. Default: 120000.
    #[serde(
        default,
        deserialize_with = "xai_grok_tools::types::schema::deserialize_lenient_u64"
    )]
    pub timeout: Option<u64>,
    /// Return a task id immediately. Query or cancel on the same binding.
    /// State is held by this local service, not a remote daemon.
    #[serde(
        default,
        deserialize_with = "xai_grok_tools::types::schema::deserialize_lenient_bool"
    )]
    pub is_background: bool,
    /// Wait this many milliseconds before returning a background task id.
    /// Overrides is_background/timeout; does not impose an execution deadline.
    #[serde(
        default,
        deserialize_with = "xai_grok_tools::types::schema::deserialize_lenient_u64"
    )]
    pub block_until_ms: Option<u64>,
}

remote_input!(SshReadInput, SshTextReadArgs);
remote_input!(
    SshWriteInput,
    xai_grok_tools::implementations::opencode::write::WriteInput
);
remote_input!(
    SshEditInput,
    xai_grok_tools::implementations::opencode::edit::EditInput
);
remote_input!(
    SshSearchInput,
    xai_grok_tools::implementations::grok_build::grep::GrepSearchInput
);
remote_input!(SshRunInput, SshCommandArgs);

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub(super) struct SshTaskQueryInput {
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub operation_id: Option<String>,
    /// Retrieve one remote background task's actual output. Mutually exclusive
    /// with `operation_id`.
    #[serde(default)]
    pub task_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub(super) struct SshTaskCancelInput {
    #[serde(default)]
    pub target: Option<String>,
    pub task_id: String,
}

macro_rules! dynamic_input {
    ($($input:ty),+ $(,)?) => {$(
        impl From<$input> for xai_grok_tools::types::ToolInput {
            fn from(input: $input) -> Self {
                Self::Dynamic(serde_json::to_value(input).expect("SSH arguments serialize to JSON"))
            }
        }
    )+};
}

dynamic_input!(
    SshTargetsInput,
    SshRequestAccessInput,
    SshReadInput,
    SshWriteInput,
    SshEditInput,
    SshSearchInput,
    SshRunInput,
    SshTaskQueryInput,
    SshTaskCancelInput,
);

macro_rules! metadata {
    ($tool:ident, $kind:expr, $description:literal) => {
        impl xai_grok_tools::types::tool_metadata::ToolMetadata for $tool {
            fn kind(&self) -> xai_grok_tools::types::tool::ToolKind {
                $kind
            }

            fn tool_namespace(&self) -> xai_grok_tools::types::tool::ToolNamespace {
                xai_grok_tools::types::tool::ToolNamespace::GrokBuild
            }

            fn description_template(&self) -> &str {
                $description
            }
        }
    };
}

fn dispatch_output(
    result: super::SshDispatchResult,
) -> xai_grok_tools::types::output::DynamicOutput {
    xai_grok_tools::types::output::DynamicOutput {
        value: result.output,
        prompt_text: Some(result.prompt_text),
    }
}

macro_rules! forwarding_tool {
    ($tool:ident, $input:ty, $id:literal, $kind:expr, $operation:expr, $remote_tool:literal, $read_only:expr, $description:literal) => {
        #[derive(Debug, Default)]
        pub(super) struct $tool;

        metadata!($tool, $kind, $description);

        impl Tool for $tool {
            type Args = $input;
            type Output = xai_grok_tools::types::output::DynamicOutput;
            fn id(&self) -> xai_tool_protocol::ToolId {
                xai_tool_protocol::ToolId::new($id).expect("static SSH tool ID is valid")
            }

            fn description(
                &self,
                _ctx: &xai_tool_runtime::ListToolsContext,
            ) -> xai_tool_types::ToolDescription {
                xai_tool_types::ToolDescription::new(
                    $id,
                    xai_grok_tools::types::tool_metadata::ToolMetadata::sanitized_description_template(self),
                )
            }

            fn capabilities(&self) -> xai_tool_protocol::ToolCapabilities {
                xai_tool_protocol::ToolCapabilities {
                    is_read_only: $read_only,
                    tool_scope: Some(if $read_only {
                        xai_tool_protocol::ToolScope::Read
                    } else {
                        xai_tool_protocol::ToolScope::Write
                    }),
                    streaming: matches!($operation, SshOperation::Execute).then(|| xai_tool_protocol::StreamingSpec {
                        subkind: "bash_output_chunk".into(),
                        max_delta_bytes: Some(64 * 1024),
                    }),
                    ..Default::default()
                }
            }

            async fn execute(
                &self,
                ctx: xai_tool_runtime::ToolCallContext,
                input: $input,
            ) -> xai_tool_runtime::ToolStream<Self::Output> {
                if !matches!($operation, SshOperation::Execute) {
                    return xai_tool_runtime::terminal_only(self.run(ctx, input).await);
                }
                let resource = match session_resource(&ctx).await {
                    Ok(resource) => resource,
                    Err(error) => return xai_tool_runtime::terminal_only(Err(error)),
                };
                let events = resource.service.subscribe_session_events(&resource.session_id).await;
                let call_id = ctx.call_id.to_string();
                let notifications = match xai_grok_tools::types::tool_metadata::shared_resources(&ctx) {
                    Ok(resources) => resources.lock().await
                        .get::<xai_grok_tools::types::resources::NotificationHandle>()
                        .map(|handle| handle.0.clone()),
                    Err(_) => None,
                };
                command_stream(async move { $tool.run(ctx, input).await }, events, call_id, notifications)
            }

            async fn run(
                &self,
                ctx: xai_tool_runtime::ToolCallContext,
                input: $input,
            ) -> Result<Self::Output, xai_tool_runtime::ToolError> {
                let resource = session_resource(&ctx).await?;
                let invocation = resource
                    .service
                    .resolve_invocation(
                        &resource.session_id,
                        input.target(),
                        input.cwd(),
                        $operation,
                        ctx.call_id.as_str(),
                    )
                    .await
                    .map_err(service_error)?;
                let mutation_id = match $operation {
                    SshOperation::Read => None,
                    SshOperation::Write | SshOperation::Execute => Some(ctx.call_id.as_str().to_owned()),
                };
                let result = resource
                    .service
                    .dispatch(
                        SshDispatchRequest {
                            invocation,
                            tool_name: $remote_tool.to_owned(),
                            args: input.into_remote_args().map_err(|error| {
                                xai_tool_runtime::ToolError::custom("ssh", error.to_string())
                            })?,
                            mutation_id,
                        },
                        resource.client_id,
                    )
                    .await
                    .map_err(service_error)?;
                Ok(dispatch_output(result))
            }
        }
    };
}

forwarding_tool!(
    SshReadTool,
    SshReadInput,
    "ssh_read",
    xai_grok_tools::types::tool::ToolKind::Read,
    SshOperation::Read,
    "GrokBuild:read_file",
    true,
    "Read a remote UTF-8 text file over SFTP, without a remote groky worker. The target must already be granted for this session. Paths and symlinks must remain inside the granted root. Use an SSH project for document/image decoding."
);
forwarding_tool!(
    SshWriteTool,
    SshWriteInput,
    "ssh_write",
    xai_grok_tools::types::tool::ToolKind::Write,
    SshOperation::Write,
    "OpenCode:write",
    false,
    "Write a remote UTF-8 file over SFTP without a worker. SSH access is a capability ceiling; this operation still requires user approval. The destination must remain inside the granted root."
);
forwarding_tool!(
    SshEditTool,
    SshEditInput,
    "ssh_edit",
    xai_grok_tools::types::tool::ToolKind::Edit,
    SshOperation::Write,
    "OpenCode:edit",
    false,
    "Edit a remote UTF-8 file over SFTP without a worker. Requires user approval, an unambiguous text match unless replaceAll is set, and an unchanged file before committing the replacement."
);
forwarding_tool!(
    SshSearchTool,
    SshSearchInput,
    "ssh_search",
    xai_grok_tools::types::tool::ToolKind::Search,
    SshOperation::Read,
    "GrokBuild:grep",
    true,
    "Search remote files using ripgrep through SSH without a worker. Requires read authorization and rg installed remotely. Search does not follow symlinks outside the granted root."
);
forwarding_tool!(
    SshRunTool,
    SshRunInput,
    "ssh_run",
    xai_grok_tools::types::tool::ToolKind::Execute,
    SshOperation::Execute,
    "GrokBuild:run_terminal_cmd",
    false,
    "Run a command through native SSH exec without a worker. Requires execution authorization and per-command user approval. Streams stdout/stderr and records the exit status. Background tasks are tracked by this local service; after connection loss the remote outcome is unknown, not automatically retried. The cwd is not a sandbox."
);

#[derive(Debug, Default)]
pub(super) struct SshTargetsTool;

metadata!(
    SshTargetsTool,
    xai_grok_tools::types::tool::ToolKind::Read,
    "Discover safe metadata for every configured SSH target and this session's existing access only. Each candidate has target_id, label, host, source, and current-session access. Discovery never connects or grants authority; use target_id for a later ssh_request_access call."
);

impl Tool for SshTargetsTool {
    type Args = SshTargetsInput;
    type Output = xai_grok_tools::types::output::DynamicOutput;

    fn id(&self) -> xai_tool_protocol::ToolId {
        xai_tool_protocol::ToolId::new("ssh_targets").expect("static SSH tool ID is valid")
    }

    fn description(
        &self,
        _ctx: &xai_tool_runtime::ListToolsContext,
    ) -> xai_tool_types::ToolDescription {
        xai_tool_types::ToolDescription::new(
            "ssh_targets",
            xai_grok_tools::types::tool_metadata::ToolMetadata::sanitized_description_template(
                self,
            ),
        )
    }

    fn capabilities(&self) -> xai_tool_protocol::ToolCapabilities {
        xai_tool_protocol::ToolCapabilities {
            is_read_only: true,
            tool_scope: Some(xai_tool_protocol::ToolScope::Read),
            ..Default::default()
        }
    }

    async fn run(
        &self,
        ctx: xai_tool_runtime::ToolCallContext,
        _input: SshTargetsInput,
    ) -> Result<Self::Output, xai_tool_runtime::ToolError> {
        let resource = session_resource(&ctx).await?;
        let discovery = resource
            .service
            .discover_targets(&resource.session_id)
            .await
            .map_err(service_error)?;
        serde_json::to_value(discovery)
            .map(Into::into)
            .map_err(|error| xai_tool_runtime::ToolError::custom("ssh", error.to_string()))
    }
}

#[derive(Debug, Default)]
pub(super) struct SshRequestAccessTool;

metadata!(
    SshRequestAccessTool,
    xai_grok_tools::types::tool::ToolKind::Other,
    "Request human approval for a session-scoped SSH target and root. Use an exact target_id returned by ssh_targets; an exact unique label, host, or imported alias is also resolved before any approval UI opens. Missing or ambiguous names return target_not_found or ambiguous_target without selecting another target. If approved, this returns the exact narrowed binding target, root, and capabilities, and never grants access by itself. Omit target and root to let the local user choose."
);

impl Tool for SshRequestAccessTool {
    type Args = SshRequestAccessInput;
    type Output = xai_grok_tools::types::output::DynamicOutput;

    fn id(&self) -> xai_tool_protocol::ToolId {
        xai_tool_protocol::ToolId::new("ssh_request_access").expect("static SSH tool ID is valid")
    }

    fn description(
        &self,
        _ctx: &xai_tool_runtime::ListToolsContext,
    ) -> xai_tool_types::ToolDescription {
        xai_tool_types::ToolDescription::new(
            "ssh_request_access",
            xai_grok_tools::types::tool_metadata::ToolMetadata::sanitized_description_template(
                self,
            ),
        )
    }

    fn capabilities(&self) -> xai_tool_protocol::ToolCapabilities {
        xai_tool_protocol::ToolCapabilities {
            is_read_only: true,
            tool_scope: Some(xai_tool_protocol::ToolScope::Read),
            ..Default::default()
        }
    }

    async fn run(
        &self,
        ctx: xai_tool_runtime::ToolCallContext,
        input: SshRequestAccessInput,
    ) -> Result<Self::Output, xai_tool_runtime::ToolError> {
        let resource = session_resource(&ctx).await?;
        let cancellation = ctx
            .get::<xai_tool_runtime::Cancellation>()
            .map(|cancellation| cancellation.0.clone());
        let binding = resource
            .service
            .request_tool_grant(
                resource.session_id,
                input.target,
                input.root,
                input.capabilities.into(),
                input.reason,
                resource.client_id,
                cancellation,
            )
            .await
            .map_err(service_error)?;
        Ok(serde_json::json!({
            "granted": true,
            "binding_id": binding.id,
            "target_id": binding.target_id,
            "root": binding.root,
            "cwd": binding.cwd,
            "capabilities": binding.capabilities,
            "identity": binding.identity,
            "epoch": binding.epoch,
        })
        .into())
}
}

#[derive(Debug, Default)]
pub(super) struct SshTaskQueryTool;

metadata!(
    SshTaskQueryTool,
    xai_grok_tools::types::tool::ToolKind::Read,
    "Query a remote operation, list remote tasks, or retrieve one remote task's output for the selected SSH binding and current session. Set exactly one of operation_id or task_id to inspect it; cross-target task lookup is rejected."
);

impl Tool for SshTaskQueryTool {
    type Args = SshTaskQueryInput;
    type Output = xai_grok_tools::types::output::DynamicOutput;

    fn id(&self) -> xai_tool_protocol::ToolId {
        xai_tool_protocol::ToolId::new("ssh_task_query").expect("static SSH tool ID is valid")
    }

    fn description(
        &self,
        _ctx: &xai_tool_runtime::ListToolsContext,
    ) -> xai_tool_types::ToolDescription {
        xai_tool_types::ToolDescription::new(
            "ssh_task_query",
            xai_grok_tools::types::tool_metadata::ToolMetadata::sanitized_description_template(
                self,
            ),
        )
    }

    fn capabilities(&self) -> xai_tool_protocol::ToolCapabilities {
        xai_tool_protocol::ToolCapabilities {
            is_read_only: true,
            tool_scope: Some(xai_tool_protocol::ToolScope::Read),
            ..Default::default()
        }
    }

    async fn run(
        &self,
        ctx: xai_tool_runtime::ToolCallContext,
        input: SshTaskQueryInput,
    ) -> Result<Self::Output, xai_tool_runtime::ToolError> {
        let resource = session_resource(&ctx).await?;
        let SshTaskQueryInput {
            target,
            operation_id,
            task_id,
        } = input;
        match (operation_id, task_id) {
            (Some(_), Some(_)) => Err(xai_tool_runtime::ToolError::invalid_arguments(
                "Provide operation_id or task_id, not both.",
            )),
            (Some(operation_id), None) => {
                let result = resource
                    .service
                    .query_task(
                        &resource.session_id,
                        target.as_deref(),
                        &operation_id,
                        ctx.call_id.as_str(),
                        resource.client_id,
                    )
                    .await
                    .map_err(service_error)?;
                Ok(match result {
                    Some(result) => dispatch_output(result),
                    None => serde_json::json!({
                        "operation_id": operation_id,
                        "found": false,
                    })
                    .into(),
                })
            }
            (None, Some(task_id)) => resource
                .service
                .query_task_output(
                    &resource.session_id,
                    target.as_deref(),
                    task_id,
                    ctx.call_id.as_str(),
                    resource.client_id,
                )
                .await
                .map(dispatch_output)
                .map_err(service_error),
            (None, None) => resource
                .service
                .list_tasks(&resource.session_id, target.as_deref(), resource.client_id)
                .await
                .map_err(service_error)
                .and_then(|tasks| {
                    serde_json::to_value(tasks)
                        .map(Into::into)
                        .map_err(|error| {
                            xai_tool_runtime::ToolError::custom("ssh", error.to_string())
                        })
                }),
        }
    }
}

#[derive(Debug, Default)]
pub(super) struct SshTaskCancelTool;

metadata!(
    SshTaskCancelTool,
    xai_grok_tools::types::tool::ToolKind::KillTaskAction,
    "Request cancellation of a task owned by the selected SSH binding and session. Native tasks receive an SSH signal; cancellation is confirmed only by a remote exit, otherwise remains pending or unknown. Never closes other tasks or a shared SSH connection."
);

impl Tool for SshTaskCancelTool {
    type Args = SshTaskCancelInput;
    type Output = xai_grok_tools::types::output::DynamicOutput;

    fn id(&self) -> xai_tool_protocol::ToolId {
        xai_tool_protocol::ToolId::new("ssh_task_cancel").expect("static SSH tool ID is valid")
    }

    fn description(
        &self,
        _ctx: &xai_tool_runtime::ListToolsContext,
    ) -> xai_tool_types::ToolDescription {
        xai_tool_types::ToolDescription::new(
            "ssh_task_cancel",
            xai_grok_tools::types::tool_metadata::ToolMetadata::sanitized_description_template(
                self,
            ),
        )
    }

    fn capabilities(&self) -> xai_tool_protocol::ToolCapabilities {
        xai_tool_protocol::ToolCapabilities {
            is_read_only: false,
            tool_scope: Some(xai_tool_protocol::ToolScope::Write),
            ..Default::default()
        }
    }

    async fn run(
        &self,
        ctx: xai_tool_runtime::ToolCallContext,
        input: SshTaskCancelInput,
    ) -> Result<Self::Output, xai_tool_runtime::ToolError> {
        let resource = session_resource(&ctx).await?;
        let result = resource
            .service
            .cancel_task(
                &resource.session_id,
                input.target.as_deref(),
                input.task_id,
                ctx.call_id.as_str(),
                resource.client_id,
            )
            .await
            .map_err(service_error)?;
        serde_json::to_value(result)
            .map(Into::into)
            .map_err(|error| xai_tool_runtime::ToolError::custom("ssh", error.to_string()))
    }
}

async fn session_resource(
    ctx: &xai_tool_runtime::ToolCallContext,
) -> Result<SessionSshResource, xai_tool_runtime::ToolError> {
    let resources = xai_grok_tools::types::tool_metadata::shared_resources(ctx)?;
    let resources = resources.lock().await;
    resources.require::<SessionSshResource>().cloned()
}

fn service_error(error: super::SshServiceError) -> xai_tool_runtime::ToolError {
    match error {
        super::SshServiceError::GrantCancelled => xai_tool_runtime::ToolError::cancelled(
            xai_tool_protocol::ToolId::new("ssh_request_access")
                .expect("static SSH tool ID is valid"),
            "SSH access request was cancelled before a human decision granted authority.",
        ),
        super::SshServiceError::WorkerHook { message, outcome } => {
            xai_tool_runtime::ToolError::custom(
                "ssh",
                super::service::render_remote_hook_prompt(message, &outcome),
            )
        }
        error => xai_tool_runtime::ToolError::custom("ssh", error.to_string()),
    }
}

struct CommandProgress<F> {
    terminal: std::pin::Pin<Box<F>>,
    events: tokio::sync::broadcast::Receiver<super::SshSessionWorkerEvent>,
    call_id: String,
    operation: Option<String>,
    total: usize,
    gap: bool,
    truncated: bool,
    done: bool,
    notifications: Option<xai_grok_tools::notification::types::ToolNotificationHandle>,
    output: Vec<u8>,
    command: String,
    cwd: std::path::PathBuf,
}

impl<F> CommandProgress<F> {
    fn notification_base(&self) -> xai_grok_tools::notification::types::BashNotificationBase {
        xai_grok_tools::notification::types::BashNotificationBase {
            tool_call_id: self.call_id.clone(),
            command: self.command.clone(),
            output: self.output.clone(),
            total_bytes: self.total,
            truncated: self.truncated || self.gap,
            cwd: self.cwd.clone(),
        }
    }

    fn finish(
        &mut self,
        result: &Result<xai_grok_tools::types::output::DynamicOutput, xai_tool_runtime::ToolError>,
    ) {
        self.done = true;
        let Some(exit_code) = result
            .as_ref()
            .ok()
            .and_then(|output| output.value.get("exit_code"))
            .and_then(|value| value.as_i64())
            .and_then(|code| i32::try_from(code).ok())
        else {
            return;
        };
        if let Some(notifications) = &self.notifications {
            notifications.send_complete(
                xai_grok_tools::notification::types::BashExecutionComplete {
                    base: self.notification_base(),
                    exit_code: Some(exit_code),
                    signal: None,
                },
            );
        }
    }
}

fn command_stream<F>(
    terminal: F,
    events: tokio::sync::broadcast::Receiver<super::SshSessionWorkerEvent>,
    call_id: String,
    notifications: Option<xai_grok_tools::notification::types::ToolNotificationHandle>,
) -> xai_tool_runtime::ToolStream<xai_grok_tools::types::output::DynamicOutput>
where
    F: Future<
            Output = Result<
                xai_grok_tools::types::output::DynamicOutput,
                xai_tool_runtime::ToolError,
            >,
        > + Send
        + 'static,
{
    let state = CommandProgress {
        terminal: Box::pin(terminal),
        events,
        call_id,
        operation: None,
        total: 0,
        gap: false,
        truncated: false,
        done: false,
        notifications,
        output: Vec::new(),
        command: String::new(),
        cwd: Default::default(),
    };
    Box::pin(futures::stream::unfold(state, |mut state| async move {
        if state.done {
            return None;
        }
        loop {
            tokio::select! {
                biased;
                // A noisy background process must not starve its task handle.
                result = &mut state.terminal => {
                    state.finish(&result);
                    return Some((xai_tool_runtime::ToolStreamItem::Terminal(result), state));
                }
                event = state.events.recv() => {
                    use xai_grok_workspace_types::ssh_wire::SshWorkerEvent;
                    match event {
                        Ok(event) => match event.event {
                            SshWorkerEvent::Operation(record) if record.mutation_id.as_deref() == Some(state.call_id.as_str()) => {
                                state.operation = Some(record.operation_id);
                            }
                            SshWorkerEvent::ToolProgress { operation_id, progress }
                                if state.operation.as_deref() == Some(operation_id.as_str()) => {
                                if let Some(text) = progress.body.get("text").and_then(|value| value.as_str()) {
                                    state.total = state.total.saturating_add(text.len());
                                    let available = (64 * 1024usize).saturating_sub(state.output.len());
                                    state.output.extend(text.as_bytes().iter().take(available));
                                    state.truncated |= text.len() > available;
                                    if state.command.is_empty() {
                                        state.command = progress.body.get("command").and_then(|v| v.as_str()).unwrap_or("ssh_run").to_owned();
                                        state.cwd = progress.body.get("cwd").and_then(|v| v.as_str()).unwrap_or_default().into();
                                    }
                                    if let Some(notifications) = &state.notifications {
                                        notifications.send_output_chunk(xai_grok_tools::notification::types::BashOutputChunk {
                                            base: state.notification_base(),
                                        });
                                    }
                                    let progress = xai_tool_runtime::ToolProgress::Custom {
                                        subkind: "bash_output_chunk".into(),
                                        payload: serde_json::json!({
                                            "delta": text, "total_bytes": state.total,
                                            "truncated": state.truncated || state.gap, "gap": state.gap,
                                        }),
                                    };
                                    return Some((xai_tool_runtime::ToolStreamItem::Progress(progress), state));
                                }
                            }
                            _ => {}
                        },
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => { state.gap = true; },
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                            let result = (&mut state.terminal).await;
                            state.finish(&result);
                            return Some((xai_tool_runtime::ToolStreamItem::Terminal(result), state));
                        }
                    }
                }
            }
        }
    }))
}
