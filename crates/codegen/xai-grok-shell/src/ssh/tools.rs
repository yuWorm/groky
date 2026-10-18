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
        if !definition.tool_config.tools.iter().any(|existing| existing.id == tool.id) {
            definition.tool_config.tools.push(tool);
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
pub(super) struct SshTargetsInput {}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub(super) struct SshRequestAccessInput {
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

remote_input!(
    SshReadInput,
    xai_grok_tools::implementations::grok_build::read_file::ReadFileInput
);
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
remote_input!(
    SshRunInput,
    xai_grok_tools::implementations::grok_build::bash::BashToolInput
);

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
                    ..Default::default()
                }
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
    "Read a remote file using the complete workspace read schema. The target must already be granted for this SSH session."
);
forwarding_tool!(
    SshWriteTool,
    SshWriteInput,
    "ssh_write",
    xai_grok_tools::types::tool::ToolKind::Write,
    SshOperation::Write,
    "OpenCode:write",
    false,
    "Write a remote file using the complete workspace write schema. SSH grant access is only a capability ceiling; the remote operation still requests ordinary user approval."
);
forwarding_tool!(
    SshEditTool,
    SshEditInput,
    "ssh_edit",
    xai_grok_tools::types::tool::ToolKind::Edit,
    SshOperation::Write,
    "OpenCode:edit",
    false,
    "Edit a remote file using the complete workspace edit schema. SSH grant access does not bypass normal remote operation approval."
);
forwarding_tool!(
    SshSearchTool,
    SshSearchInput,
    "ssh_search",
    xai_grok_tools::types::tool::ToolKind::Search,
    SshOperation::Read,
    "GrokBuild:grep",
    true,
    "Search remote workspace content using the complete remote grep schema."
);
forwarding_tool!(
    SshRunTool,
    SshRunInput,
    "ssh_run",
    xai_grok_tools::types::tool::ToolKind::Execute,
    SshOperation::Execute,
    "GrokBuild:run_terminal_cmd",
    false,
    "Run a remote command through the complete workspace command schema. SSH execution grants do not bypass per-command approval."
);

#[derive(Debug, Default)]
pub(super) struct SshTargetsTool;

metadata!(
    SshTargetsTool,
    xai_grok_tools::types::tool::ToolKind::Read,
    "List only the SSH targets currently granted to this session, including each granted root, capability ceiling, default selection, and connection status. Configured but ungranted targets are never shown."
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
        serde_json::to_value(resource.service.list_targets(&resource.session_id).await)
            .map(Into::into)
            .map_err(|error| xai_tool_runtime::ToolError::custom("ssh", error.to_string()))
    }
}

#[derive(Debug, Default)]
pub(super) struct SshRequestAccessTool;

metadata!(
    SshRequestAccessTool,
    xai_grok_tools::types::tool::ToolKind::Other,
    "Request human approval for a session-scoped SSH target and root. This never grants access by itself, even when ordinary operations are configured for automatic approval. Omit target and root to let the local user choose without exposing configured targets."
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
        let request = resource
            .service
            .request_grant(
                resource.session_id,
                input.target,
                input.root,
                input.capabilities.into(),
                input.reason,
                resource.client_id,
            )
            .await
            .map_err(service_error)?;
        serde_json::to_value(request)
            .map(Into::into)
            .map_err(|error| xai_tool_runtime::ToolError::custom("ssh", error.to_string()))
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
    "Cancel a remote task by its task_id from ssh_task_query on the selected SSH binding and session. Terminal tasks are confirmed only after remote termination; non-task operation references report pending cancellation and never close a shared SSH connection."
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
        super::SshServiceError::WorkerHook { message, outcome } => {
            xai_tool_runtime::ToolError::custom(
                "ssh",
                super::service::render_remote_hook_prompt(message, &outcome),
            )
        }
        error => xai_tool_runtime::ToolError::custom("ssh", error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_ssh_read_uses_remote_post_hook_prompt_without_leaking_clean_output() {
        let output = dispatch_output(super::super::SshDispatchResult {
            output: serde_json::json!({
                "type": "read_file",
                "content": "ORIGINAL_REMOTE_CONTENT_20261016",
            }),
            prompt_text: "REMOTE_POST_REPLACEMENT_20261016".into(),
        });
        let prompt =
            xai_grok_tools::types::output::ToolOutput::Dynamic(output.clone()).to_prompt_format();

        assert_eq!(prompt, "REMOTE_POST_REPLACEMENT_20261016");
        assert!(
            !prompt.contains("ORIGINAL_REMOTE_CONTENT_20261016"),
            "the model-facing explicit SSH output must not retain the replaced raw content"
        );
        assert_eq!(
            output.value["content"], "ORIGINAL_REMOTE_CONTENT_20261016",
            "clean remote output remains available to UI consumers"
        );
    }
}
