//! OS and shell of an SSH project's remote host for the `<user_info>` prompt.

use xai_grok_agent::PromptHost;
use xai_grok_workspace_types::rpc::workspace::WorkspaceInfo;

/// Ask the bound worker which machine the session's tools run on.
pub(crate) async fn remote_prompt_host(
    workspace: &xai_grok_workspace::WorkspaceOps,
) -> Result<PromptHost, String> {
    let info = workspace
        .workspace_info()
        .await
        .map_err(|error| format!("remote workspace info: {error}"))?;
    let WorkspaceInfo { os, shell, .. } = serde_json::from_value(info)
        .map_err(|error| format!("remote workspace info is malformed: {error}"))?;
    Ok(PromptHost { os, shell })
}
