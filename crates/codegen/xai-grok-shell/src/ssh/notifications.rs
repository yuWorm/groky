//! Live worker task notifications enter the session's existing notification bridge.
//! The bridge resource owns the sink; the SSH service keeps only a weak reference.

use std::collections::HashMap;
use std::sync::{Arc, Weak};

use serde::Deserialize;
use xai_grok_tools::bridge::ToolBridge;
use xai_grok_tools::notification::{ToolNotification, ToolNotificationHandle};
use xai_grok_tools::types::resources::NotificationHandle;
use xai_grok_workspace_types::ssh::SshBinding;

use super::SshServiceError;

struct NotificationTarget {
    binding_id: String,
    handle: ToolNotificationHandle,
}

/// Copied to a replacement bridge before the old bridge is released. Keeping
/// this resource, rather than spawning another relay, preserves exactly one sink.
#[derive(Clone)]
pub(crate) struct RemoteNotifications(Arc<NotificationTarget>);

#[derive(Default)]
pub(super) struct NotificationTargets {
    sessions: parking_lot::Mutex<HashMap<String, Weak<NotificationTarget>>>,
}

impl NotificationTargets {
    pub(super) async fn attach(
        &self,
        bridge: &ToolBridge,
        binding: &SshBinding,
    ) -> Result<(), SshServiceError> {
        let handle = bridge
            .read_resource::<NotificationHandle>()
            .await
            .ok_or_else(|| {
                SshServiceError::Worker(
                    "SSH project has no session tool notification handle".into(),
                )
            })?;
        let target = RemoteNotifications(Arc::new(NotificationTarget {
            binding_id: binding.id.clone(),
            handle: handle.0,
        }));
        self.sessions
            .lock()
            .insert(binding.session_id.clone(), Arc::downgrade(&target.0));
        bridge.update_resource(target).await;
        Ok(())
    }

    pub(super) fn forget(&self, session_id: &str) {
        self.sessions.lock().remove(session_id);
    }

    pub(super) fn forward(&self, binding: &SshBinding, payload: &serde_json::Value) {
        // Operation-state diagnostics share this wire event. Session/UI state
        // and file snapshots are client/worker-owned respectively, not remotely
        // injectable notifications. Only command/monitor lifecycle crosses here.
        if !matches!(
            payload.get("type").and_then(serde_json::Value::as_str),
            Some(
                "BashOutputChunk"
                    | "BashExecutionComplete"
                    | "BashExecutionTimeout"
                    | "BashExecutionBackgrounded"
                    | "BashExecutionFailed"
                    | "TaskCompleted"
                    | "MonitorEvent"
            )
        ) {
            return;
        }
        let target = self
            .sessions
            .lock()
            .get(&binding.session_id)
            .and_then(Weak::upgrade);
        let Some(target) = target.filter(|target| target.binding_id == binding.id) else {
            return;
        };
        let notification = match ToolNotification::deserialize(payload) {
            Ok(notification) => notification,
            Err(error) => {
                tracing::warn!(session_id = %binding.session_id, %error, "Invalid SSH tool notification");
                return;
            }
        };
        let owner = match &notification {
            ToolNotification::MonitorEvent(event) => Some(event.owner_session_id.as_deref()),
            ToolNotification::TaskCompleted(task) => Some(task.owner_session_id.as_deref()),
            _ => None,
        };
        if owner.is_some_and(|owner| owner != Some(binding.session_id.as_str())) {
            tracing::warn!(session_id = %binding.session_id, "Dropped SSH task notification with mismatched owner");
            return;
        }
        target.handle.send(notification);
    }
}
