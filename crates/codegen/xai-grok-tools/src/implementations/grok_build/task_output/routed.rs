//! Task controls for a local subagent coordinator plus a remote command executor.
//! Presence of this resource forbids consulting the client's terminal backend.

use std::sync::Arc;
use std::time::Duration;

use futures_util::{StreamExt, stream::FuturesUnordered};
use xai_tool_runtime::{ToolCallContext, ToolError};
use xai_tool_types::{
    KillTaskOutput, KillTaskResult, KillTaskToolInput, MultiTaskOutputResult, TaskOutputOutput,
    TaskOutputResult, WaitMode, WaitTasksToolInput,
};

use super::{
    WaitHint, capped_wait_timeout, format_subagent_snapshot, max_wait_block, not_found_result,
};
use crate::implementations::grok_build::task::backend::SubagentBackendResource;
use crate::implementations::grok_build::task::types::{SubagentCancelOutcome, SubagentSnapshot};
use crate::types::output::ToolOutput;
use crate::types::tool_metadata::shared_resources;

/// Canonical task controls; the remote adapter owns names, parameter mappings and authorization.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RoutedTaskControl {
    Output,
    Wait,
    Kill,
}

impl RoutedTaskControl {
    pub fn from_registry_id(id: &str) -> Option<Self> {
        match id {
            "GrokBuild:get_task_output" => Some(Self::Output),
            "GrokBuild:wait_tasks" => Some(Self::Wait),
            "GrokBuild:kill_task" => Some(Self::Kill),
            _ => None,
        }
    }
}

/// Calls only explicitly delegated remote tools. Dropping a call must cancel its
/// wait, not the command being observed. Transport errors must remain errors.
#[async_trait::async_trait]
pub trait RemoteTaskExecutor: Send + Sync {
    async fn call(
        &self,
        control: RoutedTaskControl,
        args: serde_json::Value,
        ctx: ToolCallContext,
    ) -> Result<ToolOutput, ToolError>;
}

#[derive(Clone)]
pub struct RemoteTaskExecutorResource(pub Arc<dyn RemoteTaskExecutor>);

pub(super) async fn output(
    remote: &RemoteTaskExecutorResource,
    ctx: ToolCallContext,
    ids: Vec<String>,
    timeout_ms: Option<u64>,
) -> Result<TaskOutputOutput, ToolError> {
    let timeout = Duration::from_millis(timeout_ms.unwrap_or(0));
    run(
        remote,
        ctx,
        ids,
        RoutedTaskControl::Output,
        WaitMode::WaitAll,
        timeout,
    )
    .await
}

pub(super) async fn wait(
    remote: &RemoteTaskExecutorResource,
    ctx: ToolCallContext,
    input: WaitTasksToolInput,
) -> Result<TaskOutputOutput, ToolError> {
    // Match the legacy tool: wait_all treats zero as the default budget;
    // wait_any with zero is a nonblocking snapshot.
    let timeout_ms = if input.mode == WaitMode::WaitAll {
        input.timeout_ms.filter(|ms| *ms > 0)
    } else {
        input.timeout_ms
    };
    let timeout = timeout_ms
        .map(Duration::from_millis)
        .unwrap_or(super::DEFAULT_WAIT_TIMEOUT);
    run(
        remote,
        ctx,
        input.task_ids,
        RoutedTaskControl::Wait,
        input.mode,
        timeout,
    )
    .await
}

pub(crate) async fn kill(
    remote: &RemoteTaskExecutorResource,
    ctx: ToolCallContext,
    input: KillTaskToolInput,
) -> Result<KillTaskOutput, ToolError> {
    let backend = shared_resources(&ctx)?
        .lock()
        .await
        .get::<SubagentBackendResource>()
        .cloned();
    if let Some(backend) = backend
        && backend
            .backend()
            .query(&input.task_id, false, None)
            .await
            .is_some()
    {
        // Ownership is pinned by the query. A child disappearing during cancel
        // must not redirect the same ID to a command (or to the local terminal).
        return Ok(match backend.backend().cancel(&input.task_id).await {
            SubagentCancelOutcome::Cancelled => KillTaskOutput::Result(KillTaskResult {
                task_id: input.task_id,
                outcome: "killed".into(),
                message: "Subagent cancellation initiated".into(),
            }),
            SubagentCancelOutcome::AlreadyFinished { status } => {
                KillTaskOutput::Result(KillTaskResult {
                    task_id: input.task_id,
                    outcome: "already_exited".into(),
                    message: format!("Subagent already {status}"),
                })
            }
            SubagentCancelOutcome::NotFound => {
                KillTaskOutput::TaskNotFound(format!("Subagent {} not found.", input.task_id))
            }
        });
    }
    match remote
        .0
        .call(
            RoutedTaskControl::Kill,
            serde_json::json!({"task_id": input.task_id}),
            ctx,
        )
        .await?
    {
        ToolOutput::KillTask(output) => Ok(output),
        _ => Err(unexpected_output()),
    }
}

fn unexpected_output() -> ToolError {
    ToolError::custom(
        "remote_task_output",
        "remote task control returned an unexpected result",
    )
}

fn args(
    ids: &[String],
    control: RoutedTaskControl,
    mode: WaitMode,
    timeout: Duration,
) -> serde_json::Value {
    let mut value = serde_json::json!({
        "task_ids": ids,
        "timeout_ms": timeout.as_millis() as u64,
    });
    if control == RoutedTaskControl::Wait {
        value["mode"] = serde_json::json!(if timeout.is_zero() {
            WaitMode::WaitAny
        } else {
            mode
        });
    }
    value
}

async fn remote_output(
    remote: &RemoteTaskExecutorResource,
    ctx: ToolCallContext,
    control: RoutedTaskControl,
    ids: &[String],
    mode: WaitMode,
    timeout: Duration,
) -> Result<TaskOutputOutput, ToolError> {
    match remote
        .0
        .call(control, args(ids, control, mode, timeout), ctx)
        .await?
    {
        ToolOutput::TaskOutput(output) => Ok(output),
        _ => Err(unexpected_output()),
    }
}

fn merge_remote(
    results: &mut [TaskOutputResult],
    remote_ids: &[String],
    output: TaskOutputOutput,
) -> Result<(), ToolError> {
    let rows = match output {
        TaskOutputOutput::Result(result) => vec![result],
        TaskOutputOutput::MultiResult(result) => result.results,
        TaskOutputOutput::TaskNotFound(message) if remote_ids.len() == 1 => {
            let Some(id) = remote_ids.first() else {
                return Err(unexpected_output());
            };
            let mut result = not_found_result(id);
            result.output = message;
            vec![result]
        }
        _ => return Err(unexpected_output()),
    };
    // Never let an unexpected worker row overwrite a local subagent's result.
    if rows.len() != remote_ids.len()
        || remote_ids
            .iter()
            .any(|id| rows.iter().filter(|row| row.task_id == *id).count() != 1)
    {
        return Err(unexpected_output());
    }
    for row in rows {
        let mut slots = results
            .iter_mut()
            .filter(|slot| slot.task_id == row.task_id);
        let first = slots.next().ok_or_else(unexpected_output)?;
        for slot in slots {
            *slot = row.clone();
        }
        *first = row;
    }
    Ok(())
}

fn local_result(snapshot: &SubagentSnapshot, hint: WaitHint) -> TaskOutputResult {
    match format_subagent_snapshot(snapshot, hint) {
        TaskOutputOutput::Result(result) => result,
        _ => unreachable!("subagent snapshots always render one result"),
    }
}

async fn run(
    remote: &RemoteTaskExecutorResource,
    ctx: ToolCallContext,
    ids: Vec<String>,
    control: RoutedTaskControl,
    mode: WaitMode,
    requested: Duration,
) -> Result<TaskOutputOutput, ToolError> {
    let timeout = capped_wait_timeout(Some(requested.as_millis() as u64), max_wait_block());
    let deadline = tokio::time::Instant::now() + timeout;
    let backend = shared_resources(&ctx)?
        .lock()
        .await
        .get::<SubagentBackendResource>()
        .cloned();
    let mut local = Vec::new();
    let mut remote_ids = Vec::new();
    let mut results = Vec::with_capacity(ids.len());
    for id in &ids {
        let snapshot = match &backend {
            Some(backend) => backend.backend().query(id, false, None).await,
            None => None,
        };
        if let Some(snapshot) = snapshot {
            results.push(local_result(&snapshot, WaitHint::NotRequested));
            local.push(snapshot);
        } else {
            results.push(not_found_result(id));
            if !remote_ids.contains(id) {
                remote_ids.push(id.clone());
            }
        }
    }
    if local.is_empty() && control == RoutedTaskControl::Output {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        return remote_output(remote, ctx, control, &ids, mode, remaining).await;
    }
    if !remote_ids.is_empty() {
        let output = remote_output(
            remote,
            ctx.clone(),
            control,
            &remote_ids,
            mode,
            Duration::ZERO,
        )
        .await?;
        merge_remote(&mut results, &remote_ids, output)?;
    }
    let wait_satisfied =
        mode == WaitMode::WaitAny && results.iter().any(TaskOutputResult::is_terminal);
    let pending_remote: Vec<String> = remote_ids
        .iter()
        .filter(|id| {
            results.iter().any(|result| {
                result.task_id == **id
                    && matches!(result.status.as_str(), "running" | "initializing")
            })
        })
        .cloned()
        .collect();
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    let mut remote_needs_snapshot = false;
    if !timeout.is_zero() && !wait_satisfied && !remaining.is_zero() {
        // Futures are owned by this call, not detached tasks: losing wait_any
        // branches and caller cancellation drop all coordinator waiters.
        let mut local_waits: FuturesUnordered<_> = local
            .iter()
            .filter(|snapshot| !snapshot.status.is_terminal())
            .map(|snapshot| async {
                let backend = backend.as_ref().expect("local snapshots require a backend");
                let id = &snapshot.subagent_id;
                (
                    id,
                    backend
                        .backend()
                        .query(id, true, Some(remaining.as_millis() as u64))
                        .await,
                )
            })
            .collect();
        let remote_wait = remote_output(
            remote,
            ctx.clone(),
            control,
            &pending_remote,
            mode,
            remaining,
        );
        tokio::pin!(remote_wait);
        let mut remote_pending = !pending_remote.is_empty();
        while remote_pending || !local_waits.is_empty() {
            tokio::select! {
                result = local_waits.next(), if !local_waits.is_empty() => {
                    if let Some((id, snapshot)) = result {
                        let completed = snapshot.as_ref().is_some_and(|snapshot| snapshot.status.is_terminal());
                        for slot in results.iter_mut().filter(|slot| slot.task_id == *id) {
                            *slot = snapshot.as_ref().map(|snapshot| local_result(snapshot, WaitHint::ReturnedEarly))
                                .unwrap_or_else(|| not_found_result(id));
                        }
                        if mode == WaitMode::WaitAny && completed { break; }
                    }
                }
                output = &mut remote_wait, if remote_pending => {
                    remote_pending = false;
                    merge_remote(&mut results, &pending_remote, output?)?;
                    if mode == WaitMode::WaitAny && results.iter().any(TaskOutputResult::is_terminal) { break; }
                }
                _ = tokio::time::sleep_until(deadline) => break,
            }
        }
        remote_needs_snapshot = remote_pending;
        // remote_wait is dropped here before the final snapshot; its adapter
        // cancels only the outstanding tool invocation, never the task itself.
    }
    let hint = if timeout.is_zero() {
        WaitHint::NotRequested
    } else if tokio::time::Instant::now() >= deadline {
        WaitHint::Elapsed {
            requested,
            waited: timeout,
        }
    } else {
        WaitHint::ReturnedEarly
    };
    if let Some(backend) = &backend {
        for snapshot in local {
            let id = snapshot.subagent_id;
            let latest = backend.backend().query(&id, false, None).await;
            for slot in results.iter_mut().filter(|slot| slot.task_id == id) {
                *slot = latest
                    .as_ref()
                    .map(|snapshot| local_result(snapshot, hint))
                    .unwrap_or_else(|| not_found_result(&id));
            }
        }
    }
    if remote_needs_snapshot {
        let output =
            remote_output(remote, ctx, control, &pending_remote, mode, Duration::ZERO).await?;
        merge_remote(&mut results, &pending_remote, output)?;
    }
    if control == RoutedTaskControl::Output && results.len() == 1 {
        return Ok(TaskOutputOutput::Result(results.remove(0)));
    }
    let mode = if timeout.is_zero() && control == RoutedTaskControl::Output {
        "poll"
    } else if mode == WaitMode::WaitAny {
        "wait_any"
    } else {
        "wait_all"
    };
    let completed = results.iter().filter(|result| result.is_terminal()).count();
    Ok(TaskOutputOutput::MultiResult(MultiTaskOutputResult {
        mode: mode.into(),
        summary: format!("{completed}/{} tasks completed ({mode})", results.len()),
        results,
    }))
}
