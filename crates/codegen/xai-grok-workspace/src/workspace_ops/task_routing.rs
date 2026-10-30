use super::*;
use std::sync::atomic::Ordering;
use xai_grok_tools::implementations::grok_build::task_output::routed::{
    RemoteTaskExecutor, RoutedTaskControl,
};
use xai_grok_tools::registry::types::ToolConfig;

pub(super) struct CancelRemoteRead;

struct RemoteControl {
    name: String,
    params: HashMap<String, String>,
    operation: SshOperation,
    served: AtomicBool,
}

/// The original finalized tools keep their metadata and local coordinator.
/// This adapter supplies only their remote-command half, never a local terminal.
pub(super) struct SshTaskExecutor {
    workspace: WorkspaceOps,
    session_id: String,
    controls: HashMap<RoutedTaskControl, RemoteControl>,
}

impl SshTaskExecutor {
    pub(super) fn new(workspace: WorkspaceOps, session_id: String, tools: &[ToolConfig]) -> Self {
        let controls = tools
            .iter()
            .filter_map(|tool| {
                let control = RoutedTaskControl::from_registry_id(&tool.id)?;
                let default_name = tool.id.rsplit_once(':')?.1;
                Some((
                    control,
                    RemoteControl {
                        name: tool.resolve_client_name(default_name),
                        params: tool.params_name_overrides.clone().unwrap_or_default(),
                        operation: ssh_operation_for_tool_kind(
                            tool.kind.unwrap_or(ToolKind::Other),
                        ),
                        served: AtomicBool::new(false),
                    },
                ))
            })
            .collect();
        Self {
            workspace,
            session_id,
            controls,
        }
    }

    pub(super) fn contains_name(&self, name: &str) -> bool {
        self.controls.values().any(|control| control.name == name)
    }

    pub(super) fn enable(&self, name: &str) -> bool {
        let Some(control) = self.controls.values().find(|control| control.name == name) else {
            return false;
        };
        control.served.store(true, Ordering::Release);
        true
    }
}

pub(super) fn has_remote_background_commands(tools: &[ToolConfig]) -> bool {
    tools.iter().any(|tool| {
        if !ssh_worker_tool_operations().contains_key(&tool.id) {
            return false;
        }
        match tool.id.as_str() {
            "OpenCode:bash" => true,
            "GrokBuild:run_terminal_cmd" | "GrokBuildConcise:run_terminal_cmd" => tool
                .params
                .as_ref()
                .and_then(|params| params.get("enabled_background"))
                .and_then(Value::as_bool)
                .unwrap_or(true),
            _ => false,
        }
    })
}

#[async_trait]
impl RemoteTaskExecutor for SshTaskExecutor {
    async fn call(
        &self,
        control: RoutedTaskControl,
        args: Value,
        mut ctx: xai_tool_runtime::ToolCallContext,
    ) -> Result<ToolOutput, xai_tool_runtime::ToolError> {
        let remote = self.controls.get(&control)
            .filter(|control| control.served.load(Ordering::Acquire))
            .ok_or_else(|| xai_tool_runtime::ToolError::custom(
                "ssh_task_tool_unavailable",
                "This session did not delegate this task control to the SSH worker; local commands are never consulted.",
            ))?;
        if remote.operation == SshOperation::Read
            && args
                .get("timeout_ms")
                .and_then(Value::as_u64)
                .is_some_and(|ms| ms > 0)
        {
            ctx.insert(CancelRemoteRead);
        }
        let args = if remote.params.is_empty() {
            args
        } else {
            xai_grok_tools::util::remap::remap_json_keys_checked(args, &remote.params)
                .map_err(xai_tool_runtime::ToolError::invalid_arguments)?
        };
        self.workspace
            .call_tool_with_operation(
                &remote.name,
                args,
                Some(&self.session_id),
                ctx,
                Some(remote.operation),
            )
            .await
            .map(|result| result.output)
    }
}
