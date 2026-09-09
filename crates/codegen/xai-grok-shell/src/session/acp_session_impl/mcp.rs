use super::mcp_failed_reminder::{classify_failed_servers, render_failed_section};
use super::*;
use crate::session::mcp_servers::McpOauthDiscovery;
use xai_grok_telemetry::instrument_task;
use xai_grok_telemetry::region::Parent;
/// Wire the session's elicitation inbox into a freshly built client so its `elicitation/create` requests reach the coordinator.
/// Takes the already-locked `McpState` so each caller keeps its own lock scope.
fn attach_elicitation_tx(
    state: &crate::session::mcp_servers::McpState,
    client: &crate::session::mcp_servers::McpClient,
) {
    if let Some(tx) = state.elicitation_tx() {
        client.set_elicitation_tx(Some(tx));
    }
}
pub(super) fn unregister_dropped_server_tools(
    tool_bridge: &crate::tools::bridge::ToolBridge,
    state: &crate::session::mcp_servers::McpState,
    registered_servers: &[String],
) {
    for server in registered_servers {
        let still_claimed = state
            .configs
            .iter()
            .any(|c| crate::session::mcp_servers::mcp_server_name(c) == server)
            || state.is_acp_server(server);
        if still_claimed
            || state.owned_clients.contains_key(server)
            || state.shared_clients.contains_key(server)
        {
            continue;
        }
        let prefix = format!(
            "{}{}",
            server,
            crate::session::mcp_servers::MCP_TOOL_NAME_DELIMITER
        );
        let removed = tool_bridge.unregister_tools_by_prefix(&prefix);
        tracing::info!(
            server = %server,
            tools_removed = removed,
            "Unregistered tools from a superseded MCP init"
        );
    }
}
struct SnapshotRefresher {
    tool_bridge: Arc<crate::tools::bridge::ToolBridge>,
    mcp_state: Arc<TokioMutex<crate::session::mcp_servers::McpState>>,
    refresh_gate: Arc<TokioMutex<()>>,
    managed_mcp_handle: crate::session::managed_mcp::ManagedMcpStateHandle,
    tool_snapshot: Arc<std::sync::Mutex<crate::session::tool_index::ToolMetadataSnapshot>>,
    mcp_reminder_dirty: Arc<std::sync::atomic::AtomicBool>,
    disabled_gateway_tools: std::collections::HashMap<String, std::collections::HashSet<String>>,
    mcps_root: Option<std::path::PathBuf>,
}
impl SnapshotRefresher {
    async fn refresh(&self) {
        refresh_mcp_snapshot_and_schedule_reminder_with(
            self.tool_bridge.clone(),
            Arc::clone(&self.mcp_state),
            Arc::clone(&self.refresh_gate),
            self.managed_mcp_handle.clone(),
            Arc::clone(&self.tool_snapshot),
            Arc::clone(&self.mcp_reminder_dirty),
            &self.disabled_gateway_tools,
            self.mcps_root.clone(),
        )
        .await;
    }
}
/// Owns the per-init snapshot refresher: every pass exit drains it through `finish`, and drop aborts the task so a cancelled pass cannot leave it running detached.
struct RefreshQueue {
    tx: tokio::sync::mpsc::UnboundedSender<()>,
    task: crate::util::AbortOnDrop,
}
impl RefreshQueue {
    fn start(refresher: SnapshotRefresher) -> Self {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<()>();
        let task = crate::util::AbortOnDrop(tokio::task::spawn_local(async move {
            while rx.recv().await.is_some() {
                while rx.try_recv().is_ok() {}
                refresher.refresh().await;
            }
        }));
        Self { tx, task }
    }
    fn request(&self) {
        let _ = self.tx.send(());
    }
    /// Queue one last refresh, close the channel, and wait for the drain.
    async fn finish(self) {
        let Self { tx, mut task } = self;
        let _ = tx.send(());
        drop(tx);
        let _ = (&mut task.0).await;
    }
}
/// Bounds a server's handshake plus its first `tools/list`; `startup_timeout_sec` bounds the connect alone.
fn handshake_budget(client: &crate::session::mcp_servers::McpClient) -> std::time::Duration {
    std::time::Duration::from_secs(
        client
            .startup_timeout_sec()
            .saturating_mul(2)
            .saturating_add(5),
    )
}
async fn abort_superseded_init(
    tool_bridge: &Arc<crate::tools::bridge::ToolBridge>,
    state: tokio::sync::MutexGuard<'_, crate::session::mcp_servers::McpState>,
    registered_servers: &[String],
    event_writer: &xai_grok_session_events::EventWriter,
    refresh_queue: RefreshQueue,
) {
    unregister_dropped_server_tools(tool_bridge, &state, registered_servers);
    event_writer.emit(xai_grok_session_events::Event::McpInitCancelled {
        reason: MCP_INIT_CANCELLED_CONFIG_CHANGED.to_string(),
    });
    state.notify_init_waiters();
    drop(state);
    refresh_queue.finish().await;
}
impl SessionActor {
    /// If initialization is in progress by another task, this parks on the init-wait signal until complete.
    /// Concludes only once every handshake is complete, on every path, including when this call starts init itself.
    /// A spurious notify is safe: every iteration re-reads the state before waiting again.
    pub(super) async fn wait_for_mcp_initialized(&self) {
        let signal = self.mcp_state.lock().await.init_wait_signal();
        loop {
            let notified = signal.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let (initialized, initializing) = {
                let mcp_state = self.mcp_state.lock().await;
                (mcp_state.is_initialized(), mcp_state.is_initializing())
            };
            if initialized {
                return;
            }
            if !initializing {
                self.ensure_mcp_tools_initialized().await;
                continue;
            }
            notified.await;
        }
    }
    /// Register tools from shared (inherited) MCP clients on this session's ToolBridge.
    /// Shared clients are already connected (Arc-shared from parent).
    /// `get_tool_registrations` reuses the existing transport with no new handshake.
    async fn register_shared_client_tools(&self) {
        let shared_clients: Vec<(
            String,
            std::sync::Arc<crate::session::mcp_servers::McpClient>,
        )> = {
            let st = self.mcp_state.lock().await;
            if st.shared_clients.is_empty() {
                return;
            }
            st.shared_clients
                .iter()
                .map(|(n, c)| (n.clone(), std::sync::Arc::clone(c)))
                .collect()
        };
        tracing::info!(
            session_id = %self.session_info.id.0,
            count = shared_clients.len(),
            "Registering tools from shared MCP clients"
        );
        let mcp_state_arc = std::sync::Arc::clone(&self.mcp_state);
        let mut ui_tools: std::collections::HashMap<
            String,
            Vec<crate::extensions::mcp::McpToolEntry>,
        > = std::collections::HashMap::new();
        for (server_name, client) in &shared_clients {
            let regs = match tokio::time::timeout(
                handshake_budget(client),
                client.get_tool_registrations(std::sync::Arc::clone(&mcp_state_arc)),
            )
            .await
            {
                Ok(Ok(r)) => r,
                Ok(Err(e)) => {
                    tracing::warn!(
                        server = %server_name,
                        error = %e,
                        "Failed to list tools from shared MCP client, skipping"
                    );
                    continue;
                }
                Err(_) => {
                    tracing::warn!(
                        server = %server_name,
                        "Timed out listing tools from shared MCP client, skipping"
                    );
                    continue;
                }
            };
            let mut mcp_state = self.mcp_state.lock().await;
            for reg in regs {
                self.register_mcp_tool(server_name, reg, &mut mcp_state, &mut ui_tools);
            }
        }
        self.refresh_mcp_snapshot_and_schedule_reminder().await;
        if !ui_tools.is_empty() {
            self.emit_mcp_tools_changed_notifications(ui_tools);
        }
    }
    pub(super) fn register_mcp_tool(
        &self,
        server_name: &str,
        reg: crate::session::mcp_servers::McpToolRegistration,
        mcp_state: &mut crate::session::mcp_servers::McpState,
        ui_tools_by_server: &mut std::collections::HashMap<
            String,
            Vec<crate::extensions::mcp::McpToolEntry>,
        >,
    ) {
        register_mcp_tool(
            self.agent.borrow().tool_bridge(),
            &self.events.writer(),
            server_name,
            reg,
            mcp_state,
            ui_tools_by_server,
        );
    }
    /// Emit per-server `x.ai/mcp/tools_changed` notifications.
    /// Each emission carries the owning `sessionId` so the pager can route via `find_session_match` instead of falling back to `app.active_view`.
    /// Without that field, a background agent's push would silently land on the foregrounded agent's modal.
    pub(super) fn emit_mcp_tools_changed_notifications(
        &self,
        ui_tools_by_server: std::collections::HashMap<
            String,
            Vec<crate::extensions::mcp::McpToolEntry>,
        >,
    ) {
        let session_id = self.session_id_string();
        for (server_name, tools) in ui_tools_by_server {
            let payload = crate::extensions::mcp::McpToolsChanged {
                session_id: session_id.clone(),
                server_name,
                tools,
            };
            if let Ok(params) = serde_json::value::to_raw_value(&payload) {
                self.notifications
                    .gateway
                    .forward_fire_and_forget(acp::ExtNotification::new(
                        crate::extensions::mcp::mcp_methods::TOOLS_CHANGED,
                        params.into(),
                    ));
            }
        }
    }
    /// Handle explicit auth trigger from the client (x.ai/mcp/auth_trigger).
    ///
    /// Runs force_reauth (browser flow), then re-initializes the server and registers its tools.
    pub(super) async fn handle_mcp_auth_trigger(&self, server_name: &str) -> Result<(), String> {
        let existing_client = {
            let state = self.mcp_state.lock().await;
            state.get_client(server_name).cloned()
        };
        let client = match existing_client {
            Some(c) if c.has_auth() => c,
            _ => {
                self.rebuild_http_client_with_oauth(server_name, McpOauthDiscovery::Network)
                    .await?
            }
        };
        if !client.force_reauth(true).await {
            return Err(format!(
                "Authentication failed for MCP server '{}'",
                server_name
            ));
        }
        let mcp_state_arc = self.mcp_state.clone();
        let registrations = client
            .get_tool_registrations(mcp_state_arc)
            .await
            .map_err(|e| format!("Failed to get tools after auth: {}", e))?;
        let mut mcp_state = self.mcp_state.lock().await;
        mcp_state.auth_required.remove(server_name);
        mcp_state.clear_init_failed(server_name);
        let mut ui_tools: std::collections::HashMap<
            String,
            Vec<crate::extensions::mcp::McpToolEntry>,
        > = std::collections::HashMap::new();
        for reg in registrations {
            self.register_mcp_tool(server_name, reg, &mut mcp_state, &mut ui_tools);
        }
        drop(mcp_state);
        self.refresh_mcp_snapshot_and_schedule_reminder().await;
        self.emit_mcp_tools_changed_notifications(ui_tools);
        self.refresh_goal_harness_enabled().await;
        tracing::info!(
            server = server_name,
            "MCP server authenticated and tools registered via auth_trigger"
        );
        Ok(())
    }
    async fn rebuild_http_client_with_oauth(
        &self,
        server_name: &str,
        discovery: McpOauthDiscovery,
    ) -> Result<std::sync::Arc<crate::session::mcp_servers::McpClient>, String> {
        let (server_config, meta_config, event_tx) = {
            let mcp_state = self.mcp_state.lock().await;
            let server_config = mcp_state
                .configs
                .iter()
                .find(|c| crate::session::mcp_servers::mcp_server_name(c) == server_name)
                .cloned()
                .ok_or_else(|| format!("MCP server '{}' not found in config", server_name))?;
            match &server_config {
                acp::McpServer::Http(_) | acp::McpServer::Sse(_) => {}
                _ => {
                    return Err(format!("MCP server '{}' does not use OAuth", server_name));
                }
            }
            let meta_config = mcp_state.meta_config_map.get(server_name).cloned();
            let event_tx = mcp_state.client_event_tx();
            (server_config, meta_config, event_tx)
        };
        let cwd = std::path::Path::new(&self.session_info.cwd);
        let session_id = self.session_info.id.0.as_ref();
        let (_, oauth_config_map) =
            crate::util::config::load_mcp_servers_with_oauth(cwd, &self.rebuild_spec.compat);
        let byo_config = oauth_config_map.get(server_name).cloned();
        let event_writer = self.events.writer();
        let ctx = crate::session::mcp_servers::McpSpawnCtx::for_session(
            session_id,
            &event_writer,
            crate::session::mcp_servers::OauthInteractivity::Interactive,
            self.tool_context.process_scope.as_ref(),
        )
        .with_oauth_discovery(discovery);
        let new_client = crate::session::mcp_servers::start_mcp_server(
            server_config,
            Some(cwd),
            meta_config.as_ref(),
            byo_config.as_ref(),
            &ctx,
        )
        .await
        .map_err(|e| format!("Failed to prepare OAuth for '{}': {}", server_name, e))?;
        if !new_client.has_auth() {
            return Err(match discovery {
                McpOauthDiscovery::Network => {
                    format!(
                        "MCP server '{}' does not support OAuth (discovery found no authorization support)",
                        server_name
                    )
                }
                McpOauthDiscovery::Disk => {
                    format!(
                        "MCP server '{}' has no stored OAuth credentials",
                        server_name
                    )
                }
            });
        }
        if let Some(tx) = event_tx {
            new_client.set_event_tx(Some(tx));
        }
        attach_elicitation_tx(&*self.mcp_state.lock().await, &new_client);
        let arc = std::sync::Arc::new(new_client);
        {
            let mut mcp_state = self.mcp_state.lock().await;
            mcp_state
                .owned_clients
                .insert(server_name.to_string(), arc.clone());
            mcp_state.auth_required.insert(server_name.to_string());
            mcp_state.clear_init_failed(server_name);
        }
        tracing::info!(
            server = server_name,
            discovery = ?discovery,
            "Rebuilt MCP HTTP client with OAuth manager"
        );
        Ok(arc)
    }
    pub(super) async fn retry_auth_required_servers(&self) {
        let servers_to_retry: Vec<String> = {
            let state = self.mcp_state.lock().await;
            state.auth_required.iter().cloned().collect()
        };
        if servers_to_retry.is_empty() {
            return;
        }
        let mut recovered = false;
        let mut all_ui_tools: std::collections::HashMap<
            String,
            Vec<crate::extensions::mcp::McpToolEntry>,
        > = std::collections::HashMap::new();
        for server_name in &servers_to_retry {
            let existing = {
                let state = self.mcp_state.lock().await;
                state.get_client(server_name).cloned()
            };
            let client = match existing {
                Some(c) if c.has_auth() => {
                    if !c.try_reauth_from_disk().await {
                        continue;
                    }
                    c
                }
                _ => {
                    match self
                        .rebuild_http_client_with_oauth(server_name, McpOauthDiscovery::Disk)
                        .await
                    {
                        Ok(c) => c,
                        Err(e) => {
                            tracing::debug!(
                                server = server_name.as_str(),
                                %e,
                                "retry_auth_required: no stored-credential rebuild"
                            );
                            continue;
                        }
                    }
                }
            };
            let init_budget = handshake_budget(&client);
            let mcp_state_arc = self.mcp_state.clone();
            let registrations = match tokio::time::timeout(
                init_budget,
                client.get_tool_registrations(mcp_state_arc),
            )
            .await
            .unwrap_or_else(|_| {
                Err(crate::session::mcp_servers::McpError::Timeout {
                    server: server_name.clone(),
                    timeout_secs: init_budget.as_secs(),
                })
            }) {
                Ok(r) => r,
                Err(e) => {
                    tracing::debug!(
                        server = server_name.as_str(),
                        %e,
                        "retry_auth_required: handshake still failing"
                    );
                    continue;
                }
            };
            let mut mcp_state = self.mcp_state.lock().await;
            mcp_state.auth_required.remove(server_name);
            let mut ui_tools: std::collections::HashMap<
                String,
                Vec<crate::extensions::mcp::McpToolEntry>,
            > = std::collections::HashMap::new();
            for reg in registrations {
                self.register_mcp_tool(server_name, reg, &mut mcp_state, &mut ui_tools);
            }
            drop(mcp_state);
            all_ui_tools.extend(ui_tools);
            tracing::info!(
                server = server_name.as_str(),
                "MCP server recovered via retry_auth_required (tokens found on disk)"
            );
            recovered = true;
        }
        if recovered {
            self.refresh_mcp_snapshot_and_schedule_reminder().await;
            self.emit_mcp_tools_changed_notifications(all_ui_tools);
        }
    }
    /// The OAuth config map every spawn path must use.
    /// It merges the config file's own OAuth settings with plugin-provided OAuth (client IDs, callbacks) for plugin MCP servers.
    /// Both initial init and the unreachable respawn share it, so a recovered plugin server keeps its OAuth identity.
    pub(super) fn spawn_oauth_config_map(
        &self,
        cwd: &std::path::Path,
    ) -> crate::util::config::McpOAuthConfigMap {
        let (_, mut oauth_config_map) =
            crate::util::config::load_mcp_servers_with_oauth(cwd, &self.rebuild_spec.compat);
        let plugin_registry_snapshot = self.plugin_registry.borrow().clone();
        let plugin_oauth = crate::session::managed_mcp::collect_plugin_oauth_configs(
            plugin_registry_snapshot.as_deref(),
        );
        let toml_mcp_names = crate::util::config::all_toml_mcp_server_names(cwd);
        crate::session::managed_mcp::merge_plugin_oauth_into(
            &mut oauth_config_map,
            plugin_oauth,
            &toml_mcp_names,
        );
        oauth_config_map
    }
    /// Attempt to respawn MCP servers whose last spawn failed as unreachable ([`xai_grok_mcp::servers::McpError::Unreachable`]).
    /// A transient connectivity loss during one startup probe must not strip the session of the server's tools for its remaining lifetime.
    /// Parallel triggers therefore cannot double-spawn, and a stale attempt cannot overwrite a newer client or re-pollute cleaned records.
    pub(super) async fn retry_unreachable_servers(&self) {
        let (attempts, meta_config_map, configs) = {
            let mut state = self.mcp_state.lock().await;
            let attempts = state.take_unreachable_retry_candidates();
            let configs: Vec<acp::McpServer> = state
                .configs
                .iter()
                .filter(|c| attempts.iter().any(|(n, _)| n == mcp_server_name(c)))
                .cloned()
                .collect();
            (attempts, state.meta_config_map.clone(), configs)
        };
        if attempts.is_empty() || configs.is_empty() {
            return;
        }
        let attempt_tokens: std::collections::HashMap<String, u64> = attempts.into_iter().collect();
        let mut unsettled: std::collections::HashMap<String, u64> = attempt_tokens.clone();
        tracing::info!(
            servers = ?attempt_tokens.keys().collect::<Vec<_>>(),
            "Retrying spawn of unreachable MCP servers"
        );
        let cwd = std::path::Path::new(&self.session_info.cwd);
        let oauth_config_map = self.spawn_oauth_config_map(cwd);
        let spawn_writer = self.events.writer();
        let ctx = crate::session::mcp_servers::McpSpawnCtx::for_session(
            self.session_info.id.0.as_ref(),
            &spawn_writer,
            OauthInteractivity::from_non_interactive(self.attach_non_interactive.get()),
            self.tool_context.process_scope.as_ref(),
        );
        let results = crate::session::mcp_servers::start_mcp_servers(
            configs,
            Some(cwd),
            &meta_config_map,
            &oauth_config_map,
            &ctx,
        )
        .await;
        let mut recovered = false;
        let mut all_ui_tools: std::collections::HashMap<
            String,
            Vec<crate::extensions::mcp::McpToolEntry>,
        > = std::collections::HashMap::new();
        for result in results {
            match result {
                Ok(client) => {
                    let server_name = client.server_name().to_string();
                    let Some(&token) = attempt_tokens.get(&server_name) else {
                        continue;
                    };
                    unsettled.remove(&server_name);
                    {
                        let state = self.mcp_state.lock().await;
                        if let Some(tx) = state.client_event_tx() {
                            client.set_event_tx(Some(tx));
                        }
                        attach_elicitation_tx(&state, &client);
                    }
                    let arc = std::sync::Arc::new(client);
                    let init_budget = handshake_budget(&arc);
                    let registrations = match tokio::time::timeout(
                        init_budget,
                        arc.get_tool_registrations(self.mcp_state.clone()),
                    )
                    .await
                    .unwrap_or_else(|_| {
                        Err(crate::session::mcp_servers::McpError::Timeout {
                            server: server_name.clone(),
                            timeout_secs: init_budget.as_secs(),
                        })
                    }) {
                        Ok(r) => r,
                        Err(e) => {
                            tracing::debug!(
                                server = server_name.as_str(),
                                %e,
                                "retry_unreachable: handshake still failing"
                            );
                            self.settle_failed_unreachable_attempt(
                                &server_name,
                                token,
                                &e,
                                Some(arc.clone()),
                            )
                            .await;
                            continue;
                        }
                    };
                    let _ = arc
                        .arm_liveness_watcher(xai_grok_mcp::liveness::DEFAULT_POLL_INTERVAL)
                        .await;
                    let mut mcp_state = self.mcp_state.lock().await;
                    if !mcp_state.finish_unreachable_attempt(&server_name, token) {
                        tracing::info!(
                            server = server_name.as_str(),
                            "retry_unreachable: attempt token stale; discarding client"
                        );
                        continue;
                    }
                    mcp_state
                        .owned_clients
                        .insert(server_name.clone(), arc.clone());
                    let mut ui_tools: std::collections::HashMap<
                        String,
                        Vec<crate::extensions::mcp::McpToolEntry>,
                    > = std::collections::HashMap::new();
                    for reg in registrations {
                        self.register_mcp_tool(&server_name, reg, &mut mcp_state, &mut ui_tools);
                    }
                    drop(mcp_state);
                    all_ui_tools.extend(ui_tools);
                    tracing::info!(
                        server = server_name.as_str(),
                        "MCP server recovered via retry_unreachable (respawn succeeded)"
                    );
                    recovered = true;
                }
                Err(e) => {
                    let Some(sname) = e.server_name().map(str::to_string) else {
                        continue;
                    };
                    let Some(&token) = attempt_tokens.get(&sname) else {
                        continue;
                    };
                    unsettled.remove(&sname);
                    tracing::debug!(
                        server = sname.as_str(),
                        %e,
                        "retry_unreachable: spawn still failing"
                    );
                    self.settle_failed_unreachable_attempt(&sname, token, &e, None)
                        .await;
                }
            }
        }
        for (name, token) in unsettled {
            tracing::debug!(
                server = name.as_str(),
                "retry_unreachable: spawn produced no attributable result"
            );
            self.mcp_state
                .lock()
                .await
                .settle_unreachable_attempt_failed(
                    &name,
                    token,
                    "respawn attempt produced no attributable result".to_string(),
                );
        }
        if recovered {
            self.refresh_mcp_snapshot_and_schedule_reminder().await;
            self.emit_mcp_tools_changed_notifications(all_ui_tools);
        }
    }
    /// Settle a failed respawn attempt by error class.
    /// An auth rejection hands off to the auth-required flow, keeping the fresh client (when one exists) for its recovery paths.
    /// Anything else (protocol rejection, malformed `tools/list`, redirect loops) is a terminal init failure.
    async fn settle_failed_unreachable_attempt(
        &self,
        server_name: &str,
        token: u64,
        error: &crate::session::mcp_servers::McpError,
        client_for_auth: Option<std::sync::Arc<crate::session::mcp_servers::McpClient>>,
    ) {
        let detail =
            || xai_grok_tools::util::truncate_str_with_marker(&error.to_string(), 200).into_owned();
        let mut state = self.mcp_state.lock().await;
        if error.is_auth_rejection() {
            if !state.settle_unreachable_attempt_unretryable(server_name, token) {
                return;
            }
            if let Some(client) = client_for_auth {
                state.owned_clients.insert(server_name.to_string(), client);
            }
            state.clear_init_failed(server_name);
            let generation = state.generation();
            state.record_init_failure(generation, server_name, true, None);
        } else if error.is_transient_connectivity() {
            state.settle_unreachable_attempt_failed(server_name, token, detail());
        } else {
            if !state.settle_unreachable_attempt_unretryable(server_name, token) {
                return;
            }
            let generation = state.generation();
            state.record_init_failure(generation, server_name, false, Some(detail()));
        }
    }
    /// Refresh the MCP tool/search snapshot from current tool bridge state.
    /// `maybe_inject_mcp_reminder` can then inject the next `<system-reminder>` at a turn boundary.
    /// The `search_tool` description itself stays static (cacheable).
    pub(super) async fn refresh_mcp_snapshot_and_schedule_reminder(&self) {
        let disabled_gateway_tools = crate::util::config::get_all_mcp_disabled_tools(
            std::path::Path::new(&self.session_info.cwd),
        );
        self.refresh_mcp_snapshot_and_schedule_reminder_with_disabled(&disabled_gateway_tools)
            .await;
    }
    pub(super) async fn refresh_mcp_snapshot_and_schedule_reminder_with_disabled(
        &self,
        disabled_gateway_tools: &std::collections::HashMap<
            String,
            std::collections::HashSet<String>,
        >,
    ) {
        refresh_mcp_snapshot_and_schedule_reminder_with(
            self.agent.borrow().tool_bridge().clone(),
            Arc::clone(&self.mcp_state),
            Arc::clone(&self.mcp_refresh_gate),
            self.managed_mcp_handle.clone(),
            self.tool_metadata_snapshot.clone(),
            Arc::clone(&self.mcp_reminder_dirty),
            disabled_gateway_tools,
            self.cursor_mcps_root(),
        )
        .await;
    }
    /// This build never writes descriptor files, so this is always `None`.
    fn cursor_mcps_root(&self) -> Option<std::path::PathBuf> {
        None
    }
    /// Snapshot both MCP and skill announcement tracking state and send it to the persistence channel for atomic write to `announcement_state.json`.
    ///
    /// Called after MCP fingerprint changes, skill update effects, and compaction so that resumed sessions start with accurate tracking state.
    pub(super) async fn persist_announcement_state(&self) {
        let skill_names = self.tool_bridge_handle().get_announced_skill_names().await;
        let (mcp_server_fingerprints, announced_failed) = {
            let announced = self.mcp_announcements.lock();
            (
                crate::session::announcement_state::to_persisted_fingerprints(
                    &announced.fingerprints,
                ),
                announced.persisted_failed(),
            )
        };
        let state = crate::session::announcement_state::AnnouncementState {
            mcp_server_fingerprints,
            announced_skill_names: skill_names,
            announced_failed_servers: announced_failed,
        };
        let _ = self
            .notifications
            .persistence_tx
            .send(PersistenceMsg::AnnouncementState(state));
    }
    /// Inject an MCP server system-reminder if the set changed since the last announcement.
    /// Skips if not dirty.
    /// The dirty flag is cleared up front so a cancelled run degrades to a missed (re-triggerable) injection, never an in-session duplicate.
    pub(super) async fn maybe_inject_mcp_reminder(&self) {
        if !self
            .mcp_reminder_dirty
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            return;
        }
        use xai_grok_tools::implementations::search_tool::fingerprint_servers;
        self.mcp_reminder_dirty
            .store(false, std::sync::atomic::Ordering::Relaxed);
        struct RearmOnDrop<'a>(Option<&'a std::sync::atomic::AtomicBool>);
        impl Drop for RearmOnDrop<'_> {
            fn drop(&mut self) {
                if let Some(dirty) = self.0.take() {
                    dirty.store(true, std::sync::atomic::Ordering::Relaxed);
                }
            }
        }
        let mut rearm_on_drop = RearmOnDrop(Some(&self.mcp_reminder_dirty));
        let server_summaries = self.connected_server_summaries();
        let new_fingerprints = fingerprint_servers(&server_summaries);
        let clients: Vec<(
            String,
            std::sync::Arc<crate::session::mcp_servers::McpClient>,
        )> = {
            let mcp_state = self.mcp_state.lock().await;
            mcp_state
                .all_clients()
                .map(|(n, c)| (n.clone(), std::sync::Arc::clone(c)))
                .collect()
        };
        let mut connected_names: std::collections::HashSet<String> =
            server_summaries.iter().map(|s| s.name.clone()).collect();
        for (name, client) in clients {
            if client.is_ready().await {
                connected_names.insert(name);
            }
        }
        let (currently_failed, unconnected_configured) = {
            let mcp_state = self.mcp_state.lock().await;
            connected_names.retain(|name| !mcp_state.has_failure_record(name));
            classify_failed_servers(&mcp_state, &connected_names)
        };
        let hint = self.rendered_mcp_hint().await;
        let announcements_changed = self.latch_and_push_mcp_reminder(
            &server_summaries,
            new_fingerprints,
            currently_failed,
            &unconnected_configured,
            hint.as_deref(),
        );
        rearm_on_drop.0 = None;
        if announcements_changed {
            self.persist_announcement_state().await;
        }
    }
    /// Latch fingerprints and failure episodes under one lock and push the resulting reminder, if any.
    /// The single lock scope means a concurrent persist cannot snapshot half an update.
    /// A future dropped there by a turn cancel would swallow the announcement for good.
    fn latch_and_push_mcp_reminder(
        &self,
        server_summaries: &[xai_grok_tools::types::tool_index::ServerSummary],
        new_fingerprints: std::collections::HashMap<
            String,
            xai_grok_tools::implementations::search_tool::ServerFingerprint,
        >,
        currently_failed: Vec<crate::session::announcement_state::FailedServer>,
        unconnected_configured: &std::collections::HashSet<String>,
        hint: Option<&str>,
    ) -> bool {
        use xai_grok_tools::implementations::search_tool::{
            build_delta_reminder, build_server_reminder,
        };
        let (mut reminder_text, announcements_changed, to_announce) = {
            let mut announced = self.mcp_announcements.lock();
            let text = match self.mcp_reminder_mode {
                McpReminderMode::Delta => {
                    build_delta_reminder(&announced.fingerprints, server_summaries)
                }
                McpReminderMode::Full => {
                    if announced.fingerprints == new_fingerprints {
                        None
                    } else if server_summaries.is_empty() {
                        Some("All MCP servers have disconnected.".to_string())
                    } else {
                        build_server_reminder(server_summaries)
                    }
                }
            };
            let fingerprints_changed = announced.fingerprints != new_fingerprints;
            if fingerprints_changed {
                announced.fingerprints = new_fingerprints;
            }
            let (to_announce, failed_changed) =
                announced.note_failures(currently_failed, unconnected_configured);
            (text, fingerprints_changed || failed_changed, to_announce)
        };
        let has_failed = !to_announce.is_empty();
        if has_failed {
            reminder_text
                .get_or_insert_with(String::new)
                .push_str(&render_failed_section(&to_announce));
        }
        if let (Some(text), Some(hint)) = (reminder_text.as_mut(), hint) {
            text.push_str(hint);
        }
        if let Some(text) = reminder_text {
            self.push_system_reminder_with_tag(&text, self.reminder_wrapper_tag());
            tracing::info!(
                servers = server_summaries.len(),
                has_failed,
                mode = ?self.mcp_reminder_mode,
                "Injected MCP server system-reminder"
            );
        } else {
            tracing::debug!(
                servers = server_summaries.len(),
                "MCP servers unchanged, skipping reminder injection"
            );
        }
        announcements_changed
    }
    /// Clears the announced episodes and marks the reminder dirty so the next injection re-announces servers that are still down.
    /// Persists the cleared tracking so a resume starts from it.
    /// A rewind's kept prefix usually retains the initial listing, so clearing would inject a duplicate.
    pub(crate) async fn rearm_failed_server_announcements(&self) {
        self.mcp_announcements.lock().rearm_failed();
        self.mcp_reminder_dirty
            .store(true, std::sync::atomic::Ordering::Relaxed);
        self.persist_announcement_state().await;
    }
    /// Returns `true` iff `server` has a `Stdio` entry in [`McpState::configs`] and is not on the per-cwd disabled list.
    /// HTTP / HttpAuth entries always return `false` here, which is what the auto-restart task wants.
    /// Performs one synchronous read of the per-cwd disabled-MCP list (`crate::util::config::disabled_mcp_server_names`, which parses `~/.grok/config.toml` + the project `.grok/config.toml`) on every call.
    pub(crate) async fn is_stdio_server_configured(&self, server: &str) -> bool {
        let mcp_state = self.mcp_state.lock().await;
        let is_stdio_in_configs = mcp_state
            .configs
            .iter()
            .any(|c| {
                matches!(c, acp::McpServer::Stdio(acp::McpServerStdio { name, .. }) if name == server)
            });
        if !is_stdio_in_configs {
            return false;
        }
        drop(mcp_state);
        let cwd = std::path::Path::new(&self.session_info.cwd);
        let disabled = crate::util::config::disabled_mcp_server_names(cwd);
        !disabled.contains(server)
    }
    /// HTTP analog of [`Self::is_stdio_server_configured`]: `true` iff `server` has an enabled `Http` / `Sse` config entry.
    /// Gates [`crate::session::mcp_restart::maybe_schedule_http_recovery`].
    pub(crate) async fn is_http_server_configured(&self, server: &str) -> bool {
        let mcp_state = self.mcp_state.lock().await;
        let is_http_in_configs = mcp_state
            .configs
            .iter()
            .any(|c| {
                matches!(
                c,
                acp::McpServer::Http(acp::McpServerHttp { name, .. }) | acp::McpServer::Sse(acp::McpServerSse { name, .. }) if name == server
            )
            });
        if !is_http_in_configs {
            return false;
        }
        drop(mcp_state);
        let cwd = std::path::Path::new(&self.session_info.cwd);
        let disabled = crate::util::config::disabled_mcp_server_names(cwd);
        !disabled.contains(server)
    }
    /// Recover a dead HTTP client in place via [`McpClient::recover`] (reset, re-handshake, restart the liveness watcher).
    /// Unlike [`Self::respawn_stdio`] the existing `Arc<McpClient>` is kept, so its tools stay valid.
    /// Report the race instead of a false success on a detached client.
    pub(crate) async fn reset_http_client(&self, server: &str) -> Result<(), String> {
        let client = {
            let mcp_state = self.mcp_state.lock().await;
            mcp_state.get_client(server).cloned()
        };
        let Some(client) = client else {
            return Err(format!("no client for server '{server}'"));
        };
        if !client.is_http() {
            return Err(format!("server '{server}' is not an HTTP client"));
        }
        client.recover().await.map_err(|e| e.to_string())?;
        let still_current = {
            let mcp_state = self.mcp_state.lock().await;
            mcp_state
                .get_client(server)
                .is_some_and(|c| std::sync::Arc::ptr_eq(c, &client))
        };
        if !still_current || !self.is_http_server_configured(server).await {
            client.set_liveness_handle(None);
            return Err(format!(
                "server '{server}' was removed or disabled during HTTP recovery"
            ));
        }
        Ok(())
    }
    /// Unregister `server`'s tools from the bridge after stdio restart exhaustion, so the model stops calling a now-absent client.
    pub(crate) fn unregister_server_tools(&self, server: &str) {
        let prefix = format!(
            "{}{}",
            server,
            crate::session::mcp_servers::MCP_TOOL_NAME_DELIMITER
        );
        let removed = self
            .agent
            .borrow()
            .tool_bridge()
            .unregister_tools_by_prefix(&prefix);
        if removed > 0 {
            tracing::info!(
                server = %server,
                tools_removed = removed,
                "unregistered tools for MCP server after auto-restart exhaustion",
            );
        }
    }
    /// Stdio-only restart: handshake, start the liveness watcher, then atomically install the new `Arc<McpClient>`.
    /// Wire `set_event_tx` after `ensure_initialized` so a restart emits only `RestartSucceeded`, not a second `Initialized` from `Ready`.
    /// Re-check `is_stdio_server_configured` before insert; a disable during the long start must drop the new client (`kill_on_drop`) instead of installing it.
    pub(crate) async fn respawn_stdio(&self, server: &str) -> Result<(), String> {
        let (server_config, meta_config, event_tx) = {
            let mcp_state = self.mcp_state.lock().await;
            let server_config = mcp_state
                .configs
                .iter()
                .find(|c| {
                    matches!(c, acp::McpServer::Stdio(acp::McpServerStdio { name, .. }) if name == server)
                })
                .cloned()
                .ok_or_else(|| format!("no stdio config entry for server '{server}'"))?;
            let meta_config = mcp_state.meta_config_map.get(server).cloned();
            let event_tx = mcp_state.client_event_tx();
            (server_config, meta_config, event_tx)
        };
        let cwd = std::path::Path::new(&self.session_info.cwd);
        let session_id = self.session_info.id.0.as_ref();
        let (_, oauth_config_map) =
            crate::util::config::load_mcp_servers_with_oauth(cwd, &self.rebuild_spec.compat);
        let byo_config = oauth_config_map.get(server).cloned();
        let event_writer = self.events.writer();
        let ctx = crate::session::mcp_servers::McpSpawnCtx::for_session(
            session_id,
            &event_writer,
            OauthInteractivity::from_non_interactive(self.attach_non_interactive.get()),
            self.tool_context.process_scope.as_ref(),
        );
        let new_client = crate::session::mcp_servers::start_mcp_server(
            server_config.clone(),
            Some(cwd),
            meta_config.as_ref(),
            byo_config.as_ref(),
            &ctx,
        )
        .await
        .map_err(|e| e.to_string())?;
        attach_elicitation_tx(&*self.mcp_state.lock().await, &new_client);
        new_client
            .ensure_initialized()
            .await
            .map_err(|e| e.to_string())?;
        if !self.is_stdio_server_configured(server).await {
            drop(new_client);
            return Err(format!(
                "server '{server}' was disabled or removed during respawn"
            ));
        }
        let current_config = {
            let mcp_state = self.mcp_state.lock().await;
            mcp_state
                .configs
                .iter()
                .find(|c| {
                    matches!(c, acp::McpServer::Stdio(acp::McpServerStdio { name, .. }) if name == server)
                })
                .cloned()
        };
        let config_unchanged = match (
            serde_json::to_string(&server_config),
            current_config.as_ref().map(serde_json::to_string),
        ) {
            (Ok(snapshot), Some(Ok(current))) => snapshot == current,
            _ => false,
        };
        if !config_unchanged {
            drop(new_client);
            return Err(format!(
                "config for server '{server}' changed during respawn"
            ));
        }
        if let Some(tx) = event_tx {
            new_client.set_event_tx(Some(tx.clone()));
            let _ = tx.send(xai_grok_mcp::servers::McpClientEvent::ToolsChanged {
                server: server.to_string(),
            });
        }
        let arc_client = std::sync::Arc::new(new_client);
        let _ = arc_client
            .arm_liveness_watcher(xai_grok_mcp::liveness::DEFAULT_POLL_INTERVAL)
            .await;
        {
            let mut mcp_state = self.mcp_state.lock().await;
            mcp_state
                .owned_clients
                .insert(server.to_string(), arc_client);
        }
        Ok(())
    }
    pub(super) async fn maybe_inject_mcp_connecting_reminder(&self) {
        if self.mcp_connecting_reminder_injected.get() {
            return;
        }
        let connecting: Vec<String> = {
            let mcp_state = self.mcp_state.lock().await;
            let mut names: Vec<String> = mcp_state.handshaking_servers_iter().cloned().collect();
            names.sort_unstable();
            names
        };
        if connecting.is_empty() {
            return;
        }
        self.mcp_connecting_reminder_injected.set(true);
        let delivery_tools = self.delivery_tools.borrow().clone();
        let text = format_mcp_connecting_reminder(&connecting, &delivery_tools);
        self.push_system_reminder(&text);
        tracing::info!(
            servers = ?connecting,
            ?delivery_tools,
            "Injected MCP connecting system-reminder"
        );
    }
    /// `deliveryTools` sessions emit user-visible output only through MCP tools, so both gates hold full waits for them, under either strategy.
    pub(super) fn requires_full_mcp_wait(&self) -> bool {
        !self.delivery_tools.borrow().is_empty()
    }
    /// Re-apply the attaching client's per-attachment policy.
    /// The resident `session/load` rail sends this when the request carries explicit `startupHints`.
    /// Only policy fields are touched; structural spawn-time hints (subagent identity, inherited prefix, preserved system head) stay frozen.
    pub(super) fn apply_attach_policy(&self, hints: &crate::session::StartupHints) {
        let strategy = hints.resolve_mcp_strategy();
        let changed = self.mcp_strategy.get() != strategy
            || self.attach_non_interactive.get() != hints.non_interactive
            || *self.delivery_tools.borrow() != hints.delivery_tools;
        self.mcp_strategy.set(strategy);
        self.attach_non_interactive.set(hints.non_interactive);
        *self.delivery_tools.borrow_mut() = hints.delivery_tools.clone();
        if changed {
            self.mcp_connecting_reminder_injected.set(false);
        }
        tracing::info!(
            ?strategy,
            non_interactive = hints.non_interactive,
            delivery_tools = ?hints.delivery_tools,
            changed,
            "apply_attach_policy: updated per-attachment policy from session request startupHints"
        );
    }
    /// Finishes the pass when `generation` is still current; otherwise cancels it and reports the cancel. Consumes the guard.
    fn finish_or_cancel_init(
        &self,
        mcp_state: &mut McpState,
        generation: u64,
        init_claim: crate::session::mcp_servers::InitClaimGuard,
    ) {
        if mcp_state.generation() == generation {
            mcp_state.finish_init(generation);
        } else if mcp_state.cancel_init(&init_claim) {
            self.events
                .emit(xai_grok_session_events::Event::McpInitCancelled {
                    reason: MCP_INIT_CANCELLED_CONFIG_CHANGED.to_string(),
                });
        }
    }
    /// Concludes a pass with nothing to handshake.
    async fn finish_init_without_handshakes(
        &self,
        generation: u64,
        init_claim: crate::session::mcp_servers::InitClaimGuard,
    ) {
        {
            let mut mcp_state = self.mcp_state.lock().await;
            self.finish_or_cancel_init(&mut mcp_state, generation, init_claim);
        }
        self.refresh_mcp_snapshot_and_schedule_reminder().await;
        if let Ok(params) = serde_json::value::to_raw_value(&serde_json::json!({
            "sessionId": self.session_info.id.0.as_ref(),
            "mcpToolCount": 0_u32,
            "elapsedMs": 0_u64,
        })) {
            self.notifications
                .gateway
                .forward_fire_and_forget(acp::ExtNotification::new(
                    "x.ai/mcp_initialized",
                    params.into(),
                ));
        }
    }
    /// Ensure MCP tools are initialized (spawns processes and performs handshakes on first call)
    pub(super) async fn ensure_mcp_tools_initialized(&self) {
        use tracing::Instrument;
        match self.mcp_startup_reroot_span() {
            Some(span) => {
                self.ensure_mcp_tools_initialized_inner(true)
                    .instrument(span)
                    .await
            }
            None => self.ensure_mcp_tools_initialized_inner(false).await,
        }
    }
    fn mcp_startup_reroot_span(&self) -> Option<tracing::Span> {
        let tp = self.startup_hints.take_mcp_reroot_traceparent()?;
        let span = tracing::info_span!("session.mcp_startup", session_id = %self.session_info.id.0);
        xai_grok_otel::link_span_to_meta(&span, &serde_json::json!({ "traceparent": tp }))
            .then_some(span)
    }
    async fn ensure_mcp_tools_initialized_inner(&self, reroot_active: bool) {
        let (
            mcp_server_configs,
            meta_config_map,
            generation,
            existing_client_names,
            has_servers_to_spawn,
            init_claim,
        ) = {
            let mut mcp_state = self.mcp_state.lock().await;
            let Some(init_claim) = mcp_state.try_start_init() else {
                tracing::debug!(
                    session_id = %self.session_info.id.0,
                    "ensure_mcp_tools_initialized: skipped (already initialized or in progress)"
                );
                return;
            };
            tracing::info!(
                session_id = %self.session_info.id.0,
                config_count = mcp_state.configs.len(),
                config_names = ?mcp_state.configs.iter().map(crate::session::mcp_servers::mcp_server_name).collect::<Vec<_>>(),
                existing_client_count = mcp_state.owned_clients.len() + mcp_state.shared_clients.len(),
                generation = mcp_state.generation(),
                "ensure_mcp_tools_initialized: starting MCP init"
            );
            mcp_state.set_event_writer(self.events.writer());
            if mcp_state.disabled_tools.is_empty() {
                let cwd = std::path::Path::new(&self.session_info.cwd);
                let dt = crate::util::config::get_all_mcp_disabled_tools(cwd);
                if !dt.is_empty() {
                    tracing::info!(servers = dt.len(), "Loaded disabled_tools from config");
                    mcp_state.disabled_tools = dt;
                }
            }
            let existing: std::collections::HashSet<String> =
                mcp_state.owned_clients.keys().cloned().collect();
            (
                mcp_state.configs.clone(),
                mcp_state.meta_config_map.clone(),
                mcp_state.generation(),
                existing,
                !mcp_state.configs.is_empty() || mcp_state.has_acp_servers(),
                init_claim,
            )
        };
        self.register_shared_client_tools().await;
        if !has_servers_to_spawn {
            self.finish_init_without_handshakes(generation, init_claim)
                .await;
            return;
        }
        {
            let cwd = std::path::Path::new(&self.session_info.cwd);
            self.events
                .emit(crate::session::mcp_servers::build_config_resolved_event(
                    &mcp_server_configs,
                    cwd,
                ));
        }
        let configs_to_start: Vec<_> = mcp_server_configs
            .iter()
            .filter(|c| !existing_client_names.contains(mcp_server_name(c)))
            .cloned()
            .collect();
        let acp_pending_names = {
            let mcp_state = self.mcp_state.lock().await;
            mcp_state.pending_acp_server_names()
        };
        {
            let mut mcp_state = self.mcp_state.lock().await;
            let names: Vec<String> = configs_to_start
                .iter()
                .map(|c| mcp_server_name(c).to_string())
                .chain(acp_pending_names.iter().cloned())
                .collect();
            for name in &names {
                tracing::info!(server = %name, "Added server to handshaking set");
            }
            mcp_state.mark_servers_initializing(generation, names);
        }
        self.mcp_connecting_reminder_injected.set(false);
        let init_total = (configs_to_start.len() + acp_pending_names.len()) as u32;
        if let Ok(params) = serde_json::value::to_raw_value(&serde_json::json!({
            "total": init_total,
            "connected": 0,
            "sessionId": self.session_info.id.0.as_ref(),
        })) {
            self.notifications
                .gateway
                .forward_fire_and_forget(acp::ExtNotification::new(
                    crate::extensions::mcp::mcp_methods::INIT_PROGRESS,
                    params.into(),
                ));
        }
        if configs_to_start.is_empty() && acp_pending_names.is_empty() {
            self.finish_init_without_handshakes(generation, init_claim)
                .await;
            return;
        }
        let mcp_init_start = std::time::Instant::now();
        let mut timer = crate::instrumentation_timer!("session.mcp_init");
        timer.with_field("session_id", self.session_info.id.0.as_ref());
        timer.with_field("server_count", configs_to_start.len() as u64);
        tracing::info!(
            "Starting MCP initialization ({} new servers, {} already initialized, strategy: {:?})",
            configs_to_start.len(),
            existing_client_names.len(),
            self.mcp_strategy.get()
        );
        let session_id = self.session_info.id.0.as_ref();
        tokio::task::yield_now().await;
        let cwd = std::path::Path::new(&self.session_info.cwd);
        let oauth_config_map = self.spawn_oauth_config_map(cwd);
        let spawn_writer = self.events.writer();
        let ctx = crate::session::mcp_servers::McpSpawnCtx::for_session(
            session_id,
            &spawn_writer,
            OauthInteractivity::from_non_interactive(self.attach_non_interactive.get()),
            self.tool_context.process_scope.as_ref(),
        );
        let mcp_results = build_pending_clients(
            &self.mcp_state,
            configs_to_start,
            Some(cwd),
            &meta_config_map,
            &oauth_config_map,
            &ctx,
        )
        .await;
        tokio::task::yield_now().await;
        let mut spawn_auth_failures: Vec<String> = Vec::new();
        let mut spawn_unreachable_failures: Vec<(String, String)> = Vec::new();
        let mcp_clients: Vec<_> = mcp_results
            .into_iter()
            .filter_map(|result| match result {
                Ok(client) => {
                    tracing::debug!("MCP server '{}' spawned", client.server_name());
                    Some(client)
                }
                Err(e) => {
                    tracing::warn!("Failed to spawn MCP server: {}", e);
                    let sname = e.server_name().unwrap_or("unknown").to_string();
                    if e.is_auth_rejection() && sname != "unknown" {
                        spawn_auth_failures.push(sname.clone());
                    } else if e.is_unreachable() && sname != "unknown" {
                        spawn_unreachable_failures.push((sname.clone(), e.to_string()));
                    }
                    let cfg = mcp_server_configs
                        .iter()
                        .find(|c| mcp_server_name(c) == sname.as_str());
                    self.events
                        .emit(xai_grok_session_events::Event::McpServerFailed {
                            server_name: sname,
                            transport: cfg.map(|c| mcp_transport_str(c).to_string()),
                            target: cfg.map(mcp_target_str),
                            error_type: e.error_category(),
                            error_message: e.to_string(),
                            duration_ms: None,
                            timeout_sec: None,
                        });
                    None
                }
            })
            .collect();
        let spawned_names: std::collections::HashSet<String> = mcp_clients
            .iter()
            .map(|c| c.server_name().to_string())
            .collect();
        {
            let mut mcp_state = self.mcp_state.lock().await;
            if mcp_state.generation() != generation {
                self.finish_or_cancel_init(&mut mcp_state, generation, init_claim);
                return;
            }
            let failed_spawns: Vec<String> = mcp_state
                .handshaking_servers_iter()
                .filter(|name| !spawned_names.contains(name.as_str()))
                .cloned()
                .collect();
            for name in &failed_spawns {
                tracing::warn!(
                    server = name.as_str(),
                    "MCP server spawn failed, removing from initializing set"
                );
                if spawn_auth_failures.iter().any(|n| n == name) {
                    mcp_state.record_init_failure(generation, name, true, None);
                } else if let Some((_, detail)) =
                    spawn_unreachable_failures.iter().find(|(n, _)| n == name)
                {
                    mcp_state.record_unreachable_failure(generation, name, detail.clone());
                }
                mcp_state.mark_server_ready(generation, name);
            }
            mcp_state.finish_init(generation);
        }
        let scope_cwd = std::path::Path::new(self.session_info.cwd.as_str());
        let servers = mcp_server_configs
            .iter()
            .map(|c| {
                let name = mcp_server_name(c);
                (
                    name.to_string(),
                    ServerInfo {
                        transport: mcp_transport_str(c),
                        target: mcp_target_str(c),
                        scope: crate::util::config::mcp_server_scope(name, scope_cwd),
                    },
                )
            })
            .collect();
        let clients = mcp_clients
            .into_iter()
            .map(|c| (c.server_name().to_string(), std::sync::Arc::new(c)))
            .collect();
        let tool_bridge = self.agent.borrow().tool_bridge().clone();
        let refresher = SnapshotRefresher {
            tool_bridge: tool_bridge.clone(),
            mcp_state: std::sync::Arc::clone(&self.mcp_state),
            refresh_gate: Arc::clone(&self.mcp_refresh_gate),
            managed_mcp_handle: self.managed_mcp_handle.clone(),
            tool_snapshot: self.tool_metadata_snapshot.clone(),
            mcp_reminder_dirty: Arc::clone(&self.mcp_reminder_dirty),
            disabled_gateway_tools: crate::util::config::get_all_mcp_disabled_tools(
                std::path::Path::new(&self.session_info.cwd),
            ),
            mcps_root: self.cursor_mcps_root(),
        };
        let pass = InitPass {
            generation,
            mcp_init_start,
            mcp_state: std::sync::Arc::clone(&self.mcp_state),
            tool_bridge,
            events: self.events.writer(),
            gateway: self.notifications.gateway.clone(),
            session_id: self.session_info.id.0.to_string(),
            servers,
            clients,
            server_count: (mcp_server_configs.len() + acp_pending_names.len()) as u32,
            handshake_count: init_total,
            strategy: self.mcp_strategy.get(),
            is_reinit: !existing_client_names.is_empty(),
            registered_servers: Vec::new(),
            inserted_servers: Vec::new(),
            failed_servers: Vec::new(),
            ui_tools_by_server: std::collections::HashMap::new(),
            succeeded: 0,
            failed: 0,
            auth_required: 0,
            tools_registered: 0,
        };
        let mcp_init_task_parent = if reroot_active {
            Parent::Inherit
        } else {
            Parent::Root
        };
        let mut init_tasks = self.mcp_init_tasks.borrow_mut();
        while init_tasks.try_join_next().is_some() {}
        init_tasks.spawn_local(instrument_task!(
            "session.mcp_init_task",
            mcp_init_task_parent,
            pass.run(refresher)
        ));
        drop(init_tasks);
    }
    /// Summaries of the currently connected MCP servers, from the live tool-metadata snapshot.
    /// The single source for every consumer of the server list.
    pub(crate) fn connected_server_summaries(
        &self,
    ) -> Vec<xai_grok_tools::types::tool_index::ServerSummary> {
        use xai_grok_tools::types::tool_index::ToolSearchIndex;
        crate::session::tool_index::Bm25ToolSearchIndex::new(self.tool_metadata_snapshot.clone())
            .list_server_summaries()
    }
    /// Render the tool usage hint appended to every injected MCP reminder body, with the session's tool names substituted.
    /// Shared by the injector and the `/context` estimate.
    /// `None` when the template fails to render.
    async fn rendered_mcp_hint(&self) -> Option<String> {
        let hint_template = "\nTo use MCP tools, you MUST call `${{ tools.by_kind.search_tool }}` first to retrieve the tool's input schema before calling `${{ tools.by_kind.use_tool }}`. NEVER guess parameter names — always use the exact schema returned by `${{ tools.by_kind.search_tool }}`.";
        self.tool_bridge_handle()
            .render_prompt(hint_template, &serde_json::json!({}))
            .await
    }
    /// The full MCP announcement for the current server set, for `/context` accounting.
    /// Returns `None` when no servers are connected, or when the active template carries MCP in its first user message rather than in reminders.
    /// Known approximations: the default reminder mode is `Delta`, which injects incremental texts rather than this full listing.
    pub(super) async fn mcp_announcement_snapshot(&self) -> Option<McpAnnouncementSnapshot> {
        let server_summaries = self.connected_server_summaries();
        let mut text =
            xai_grok_tools::implementations::search_tool::build_server_reminder(&server_summaries)?;
        if let Some(hint) = self.rendered_mcp_hint().await {
            text.push_str(&hint);
        }
        Some(McpAnnouncementSnapshot {
            text,
            server_count: server_summaries.len(),
        })
    }
}
/// The MCP server announcement as rendered by `mcp_announcement_snapshot`.
/// The MCP counterpart of `SkillListingSnapshot`.
pub(super) struct McpAnnouncementSnapshot {
    /// The announcement body: server listing plus the tool usage hint.
    pub(super) text: String,
    pub(super) server_count: usize,
}
/// On surfaces that declare delivery tools the user sees output only through those MCP tools.
/// Keying on the explicit opt-in rather than on `nonInteractive` keeps the default for every other client.
/// The right guidance there is to keep working and deliver through the tool, not to skip it.
pub(super) fn format_mcp_connecting_reminder(
    connecting: &[String],
    delivery_tools: &[String],
) -> String {
    let mut text =
        "MCP servers currently connecting (tools will become available shortly):\n".to_string();
    for name in connecting {
        text.push_str(&format!("- {name}\n"));
    }
    if delivery_tools.is_empty() {
        text.push_str(
            "\nDo not attempt to use tools from these servers yet. \
             If the user's request likely requires one of these servers, \
             mention that the server is still connecting and proceed with \
             what you can do in the meantime.",
        );
    } else {
        text.push_str(&format!(
            "\nThese servers are being awaited and their tools are expected \
             to become available as you work — use them normally, and if a \
             call reports the tool as unavailable, retry it after your other \
             work rather than giving up. User-visible output from this \
             session is delivered ONLY through: {}. Do NOT end the turn \
             without delivering your answer through the appropriate \
             delivery tool.",
            delivery_tools.join(", ")
        ));
    }
    text
}
/// Per-server config facts reported with each handshake outcome.
struct ServerInfo {
    transport: &'static str,
    target: String,
    scope: &'static str,
}
struct HandshakeSuccess {
    server: String,
    registrations: Vec<crate::session::mcp_servers::McpToolRegistration>,
    elapsed: std::time::Duration,
    timeout_sec: u64,
}
struct HandshakeFailure {
    server: String,
    error: crate::session::mcp_servers::McpError,
    needs_auth: bool,
    elapsed: std::time::Duration,
    timeout_sec: u64,
}
type HandshakeOutcome = Result<HandshakeSuccess, HandshakeFailure>;
/// One background init pass: runs the handshakes in parallel, records each outcome as it arrives, and reports completion.
/// Every outcome is recorded in one generation-checked section (tools registered, client inserted, server marked ready), and telemetry is emitted only for recorded outcomes, so a superseded pass leaves no half-applied.
struct InitPass {
    generation: u64,
    mcp_init_start: std::time::Instant,
    mcp_state: Arc<TokioMutex<crate::session::mcp_servers::McpState>>,
    tool_bridge: Arc<crate::tools::bridge::ToolBridge>,
    events: xai_grok_session_events::EventWriter,
    gateway: xai_acp_lib::AcpAgentGatewaySender,
    session_id: String,
    servers: std::collections::HashMap<String, ServerInfo>,
    clients: std::collections::HashMap<String, Arc<crate::session::mcp_servers::McpClient>>,
    /// Configured plus SDK servers; the completion event's denominator.
    server_count: u32,
    /// Servers this pass handshakes; the pager's progress denominator.
    handshake_count: u32,
    strategy: McpInitStrategy,
    is_reinit: bool,
    /// Servers whose tools this pass wrote to the bridge; the abort path strips exactly these.
    registered_servers: Vec<String>,
    inserted_servers: Vec<String>,
    failed_servers: Vec<String>,
    ui_tools_by_server:
        std::collections::HashMap<String, Vec<crate::extensions::mcp::McpToolEntry>>,
    succeeded: u32,
    failed: u32,
    auth_required: u32,
    tools_registered: u32,
}
impl InitPass {
    async fn run(mut self, refresher: SnapshotRefresher) {
        let started = std::time::Instant::now();
        let event_tx = self.mcp_state.lock().await.client_event_tx();
        let mut handshakes = tokio::task::JoinSet::new();
        let mut servers_by_task: std::collections::HashMap<tokio::task::Id, String> =
            std::collections::HashMap::new();
        for (server, client) in &self.clients {
            let (transport, target) = self
                .servers
                .get(server)
                .map(|info| (info.transport.to_string(), info.target.clone()))
                .unwrap_or_else(|| ("unknown".to_string(), String::new()));
            let handle = handshakes.spawn_local(run_handshake(
                Arc::clone(client),
                Arc::clone(&self.mcp_state),
                self.events.clone(),
                event_tx.clone(),
                transport,
                target,
            ));
            servers_by_task.insert(handle.id(), server.clone());
        }
        let refresh_queue = RefreshQueue::start(refresher);
        let mut completed: u32 = 0;
        while let Some(joined) = handshakes.join_next_with_id().await {
            completed += 1;
            if self.superseded("during background handshakes").await {
                self.abort(refresh_queue).await;
                return;
            }
            self.notify_progress(completed);
            let outcome = match joined {
                Ok((_task_id, outcome)) => outcome,
                Err(join_err) => {
                    tracing::warn!(error = %join_err, "MCP handshake task failed to join");
                    let Some(server) = servers_by_task.get(&join_err.id()).cloned() else {
                        continue;
                    };
                    Err(HandshakeFailure {
                        server,
                        error: crate::session::mcp_servers::McpError::ClientError(format!(
                            "handshake task failed: {join_err}"
                        )),
                        needs_auth: false,
                        elapsed: std::time::Duration::ZERO,
                        timeout_sec: 0,
                    })
                }
            };
            let recorded = match outcome {
                Ok(success) => self.record_connected(success).await,
                Err(failure) => self.record_failed(failure).await,
            };
            if recorded {
                refresh_queue.request();
            }
        }
        drop(handshakes);
        if self.superseded("after background handshakes").await {
            self.abort(refresh_queue).await;
            return;
        }
        self.finish(started).await;
        refresh_queue.finish().await;
        self.notify_tools_changed();
        self.notify_initialized(started.elapsed()).await;
    }
    async fn superseded(&self, when: &str) -> bool {
        let current = self.mcp_state.lock().await.generation();
        if current == self.generation {
            return false;
        }
        tracing::info!(
            "MCP configs changed {when} (gen {} -> {}), discarding",
            self.generation,
            current
        );
        true
    }
    async fn abort(&self, refresh_queue: RefreshQueue) {
        let mcp_state = self.mcp_state.lock().await;
        abort_superseded_init(
            &self.tool_bridge,
            mcp_state,
            &self.registered_servers,
            &self.events,
            refresh_queue,
        )
        .await;
    }
    /// Armed before the outcome is recorded so the watcher exists by the time the client is reachable; it holds a
    /// strong `Arc`, so a discarded outcome must cancel it or the client would outlive its eviction.
    async fn arm_liveness_watcher(
        &self,
        server: &str,
    ) -> Option<Arc<crate::session::mcp_servers::McpClient>> {
        let client = self.clients.get(server).cloned()?;
        let _ = client
            .arm_liveness_watcher(xai_grok_mcp::liveness::DEFAULT_POLL_INTERVAL)
            .await;
        Some(client)
    }
    /// Drops an outcome the pass may no longer record: the watcher armed for it is cancelled with it.
    fn discard(client: Option<Arc<crate::session::mcp_servers::McpClient>>) {
        if let Some(client) = client {
            client.set_liveness_handle(None);
        }
    }
    /// Runs `record` under the state lock, only while this pass still owns the generation.
    async fn record_if_current(
        &mut self,
        record: impl FnOnce(&mut Self, &mut crate::session::mcp_servers::McpState),
    ) -> bool {
        let mcp_state = Arc::clone(&self.mcp_state);
        let mut mcp_state = mcp_state.lock().await;
        if mcp_state.generation() != self.generation {
            return false;
        }
        record(self, &mut mcp_state);
        true
    }
    fn insert_client(
        &mut self,
        mcp_state: &mut crate::session::mcp_servers::McpState,
        server: &str,
        client: Option<Arc<crate::session::mcp_servers::McpClient>>,
    ) {
        if let Some(client) = client {
            mcp_state.owned_clients.insert(server.to_string(), client);
            self.inserted_servers.push(server.to_string());
        }
        mcp_state.mark_server_ready(self.generation, server);
    }
    fn transport(&self, server: &str) -> &'static str {
        self.servers
            .get(server)
            .map_or("unknown", |info| info.transport)
    }
    fn scope(&self, server: &str) -> &'static str {
        self.servers
            .get(server)
            .map_or("unknown", |info| info.scope)
    }
    /// True when the outcome was recorded; false when the pass was superseded, which the next generation check aborts.
    async fn record_connected(&mut self, success: HandshakeSuccess) -> bool {
        let HandshakeSuccess {
            server,
            registrations,
            elapsed,
            timeout_sec,
        } = success;
        tracing::info!(
            server = %server,
            elapsed_ms = elapsed.as_millis() as u64,
            timeout_sec,
            tool_count = registrations.len(),
            "MCP handshake succeeded",
        );
        let client = self.arm_liveness_watcher(&server).await;
        let tool_count = registrations.len() as u32;
        let tool_prefix = format!(
            "{}{}",
            server,
            crate::session::mcp_servers::MCP_TOOL_NAME_DELIMITER
        );
        let tool_names: Vec<String> = registrations
            .iter()
            .map(|r| {
                r.name
                    .strip_prefix(&tool_prefix)
                    .unwrap_or(&r.name)
                    .to_string()
            })
            .collect();
        let recorded = self
            .record_if_current(|pass, mcp_state| {
                pass.tool_bridge.unregister_tools_by_prefix(&tool_prefix);
                for reg in registrations {
                    register_mcp_tool(
                        &pass.tool_bridge,
                        &pass.events,
                        &server,
                        reg,
                        mcp_state,
                        &mut pass.ui_tools_by_server,
                    );
                }
                pass.registered_servers.push(server.clone());
                pass.insert_client(mcp_state, &server, client.clone());
            })
            .await;
        if !recorded {
            Self::discard(client);
            return false;
        }
        let transport = self.transport(&server);
        let transport_kind = match transport {
            "stdio" => xai_grok_telemetry::events::McpTransport::Stdio,
            "sse" => xai_grok_telemetry::events::McpTransport::Sse,
            _ => xai_grok_telemetry::events::McpTransport::Http,
        };
        debug_assert!(
            xai_grok_telemetry::activity::gauge_value(
                xai_grok_telemetry::activity::MCP_SERVERS_CONNECTED_KEY
            ) >= 1,
            "McpServerConnected must stamp a self-inclusive count"
        );
        xai_grok_telemetry::session_ctx::log_event(
            xai_grok_telemetry::events::McpServerConnected {
                server_name: server.clone(),
                tool_count,
                transport: transport_kind,
                duration_ms: elapsed.as_millis() as u64,
            },
        );
        self.events
            .emit(xai_grok_session_events::Event::McpServerConnected {
                server_name: server.clone(),
                transport: transport.to_string(),
                tool_count,
                duration_ms: elapsed.as_millis() as u64,
                tools: tool_names,
            });
        crate::session::telemetry::emit_mcp_connection_span(
            "connected",
            &server,
            transport,
            self.scope(&server),
            Some(elapsed.as_millis() as i64),
            Some(tool_count as i64),
            None,
        );
        self.succeeded += 1;
        self.tools_registered += tool_count;
        true
    }
    async fn record_failed(&mut self, failure: HandshakeFailure) -> bool {
        let HandshakeFailure {
            server,
            error,
            needs_auth,
            elapsed,
            timeout_sec,
        } = failure;
        let client = self.arm_liveness_watcher(&server).await;
        let detail = (!needs_auth).then(|| {
            xai_grok_tools::util::truncate_str_with_marker(&error.to_string(), 200).into_owned()
        });
        let unreachable = !needs_auth && error.is_connect_failure();
        let recorded = self
            .record_if_current(|pass, mcp_state| {
                if unreachable {
                    mcp_state.record_unreachable_failure(
                        pass.generation,
                        &server,
                        detail.unwrap_or_default(),
                    );
                } else {
                    mcp_state.record_init_failure(pass.generation, &server, needs_auth, detail);
                }
                pass.insert_client(mcp_state, &server, client.clone());
            })
            .await;
        if !recorded {
            Self::discard(client);
            return false;
        }
        let error_category = if needs_auth {
            xai_grok_session_events::McpErrorCategory::AuthRequired
        } else {
            error.error_category()
        };
        let error_type = match error_category {
            xai_grok_session_events::McpErrorCategory::AuthRequired => {
                xai_grok_telemetry::events::McpErrorType::Auth
            }
            xai_grok_session_events::McpErrorCategory::Timeout => {
                xai_grok_telemetry::events::McpErrorType::Timeout
            }
            _ => xai_grok_telemetry::events::McpErrorType::HandshakeFailed,
        };
        let transport = self.transport(&server);
        xai_grok_telemetry::session_ctx::log_event(xai_grok_telemetry::events::McpServerFailed {
            server_name: server.clone(),
            error_type,
            duration_ms: elapsed.as_millis() as u64,
            timeout_sec,
            error_message: Some(error.to_string()),
        });
        crate::session::telemetry::emit_mcp_connection_span(
            "failed",
            &server,
            transport,
            self.scope(&server),
            Some(elapsed.as_millis() as i64),
            None,
            Some(error_type.as_ref()),
        );
        self.events
            .emit(xai_grok_session_events::Event::McpServerFailed {
                server_name: server.clone(),
                transport: Some(transport.to_string()),
                target: self.servers.get(&server).map(|info| info.target.clone()),
                error_type: error_category,
                error_message: error.to_string(),
                duration_ms: Some(elapsed.as_millis() as u64),
                timeout_sec: Some(timeout_sec),
            });
        self.failed += 1;
        self.failed_servers.push(server);
        if needs_auth {
            self.auth_required += 1;
        }
        true
    }
    async fn finish(&mut self, started: std::time::Instant) {
        let mut mcp_state = self.mcp_state.lock().await;
        mcp_state.mark_all_servers_ready(self.generation);
        tracing::info!(
            session_id = %self.session_id,
            inserted = ?self.inserted_servers,
            total_clients = mcp_state.owned_clients.len() + mcp_state.shared_clients.len(),
            elapsed_ms = started.elapsed().as_millis() as u64,
            "mcp_bg_handshake: clients inserted, waking init waiters"
        );
        mcp_state.notify_init_waiters();
        xai_grok_telemetry::session_ctx::log_event(xai_grok_telemetry::events::McpInitCompleted {
            total_duration_ms: started.elapsed().as_millis() as u64,
            spawn_duration_ms: started.duration_since(self.mcp_init_start).as_millis() as u64,
            server_count: self.server_count,
            servers_succeeded: self.succeeded,
            servers_failed: self.failed,
            servers_auth_required: self.auth_required,
            total_tools_registered: self.tools_registered,
            strategy: self.strategy,
            is_reinit: self.is_reinit,
        });
        self.events
            .emit(xai_grok_session_events::Event::McpInitCompleted {
                total_servers: self.server_count,
                succeeded: self.succeeded,
                failed: self.failed,
                auth_required: self.auth_required,
                total_tools: self.tools_registered,
                duration_ms: started.elapsed().as_millis() as u64,
                is_reinit: self.is_reinit,
                failed_servers: std::mem::take(&mut self.failed_servers),
            });
    }
    fn notify_progress(&self, connected: u32) {
        if let Ok(params) = serde_json::value::to_raw_value(&serde_json::json!({
            "total": self.handshake_count,
            "connected": connected,
            "sessionId": self.session_id,
        })) {
            self.gateway
                .forward_fire_and_forget(acp::ExtNotification::new(
                    crate::extensions::mcp::mcp_methods::INIT_PROGRESS,
                    params.into(),
                ));
        }
    }
    /// Each payload carries `sessionId` so the pager routes via `find_session_match` rather than falling back to `app.active_view`.
    fn notify_tools_changed(&mut self) {
        for (server_name, tools) in std::mem::take(&mut self.ui_tools_by_server) {
            let payload = crate::extensions::mcp::McpToolsChanged {
                session_id: self.session_id.clone(),
                server_name,
                tools,
            };
            if let Ok(params) = serde_json::value::to_raw_value(&payload) {
                self.gateway
                    .forward_fire_and_forget(acp::ExtNotification::new(
                        crate::extensions::mcp::mcp_methods::TOOLS_CHANGED,
                        params.into(),
                    ));
            }
        }
    }
    async fn notify_initialized(&self, elapsed: std::time::Duration) {
        tracing::info!(
            target: crate::instrumentation::TARGET,
            event = "timing",
            name = "session.mcp_handshakes_bg",
            elapsed_us = elapsed.as_micros() as u64,
        );
        tracing::info!("MCP background handshakes completed in {:?}", elapsed);
        let mcp_tool_count = self
            .tool_bridge
            .tool_definitions()
            .await
            .iter()
            .filter(|t| t.function.name.contains("__"))
            .count();
        if let Ok(params) = serde_json::value::to_raw_value(&serde_json::json!({
            "sessionId": self.session_id,
            "mcpToolCount": mcp_tool_count,
            "elapsedMs": elapsed.as_millis() as u64,
        })) {
            self.gateway
                .forward_fire_and_forget(acp::ExtNotification::new(
                    "x.ai/mcp_initialized",
                    params.into(),
                ));
        }
    }
}
/// One server's handshake plus first `tools/list`, bounded by [`handshake_budget`] so a server that connects and then
/// stalls cannot hold the pass's completion signal.
async fn run_handshake(
    client: Arc<crate::session::mcp_servers::McpClient>,
    mcp_state: Arc<TokioMutex<crate::session::mcp_servers::McpState>>,
    events: xai_grok_session_events::EventWriter,
    event_tx: Option<tokio::sync::mpsc::UnboundedSender<xai_grok_mcp::servers::McpClientEvent>>,
    transport: String,
    target: String,
) -> HandshakeOutcome {
    let server = client.server_name().to_string();
    let start = std::time::Instant::now();
    let timeout_sec = client.startup_timeout_sec();
    events.emit(xai_grok_session_events::Event::McpServerStarting {
        server_name: server.clone(),
        transport,
        target,
        timeout_sec,
    });
    if let Some(tx) = event_tx {
        client.set_event_tx(Some(tx));
    }
    attach_elicitation_tx(&*mcp_state.lock().await, &client);
    let budget = handshake_budget(&client);
    let registrations =
        match tokio::time::timeout(budget, client.get_tool_registrations(mcp_state)).await {
            Ok(result) => result,
            Err(_) => Err(crate::session::mcp_servers::McpError::Timeout {
                server: server.clone(),
                timeout_secs: budget.as_secs(),
            }),
        };
    match registrations {
        Ok(registrations) => Ok(HandshakeSuccess {
            server,
            registrations,
            elapsed: start.elapsed(),
            timeout_sec,
        }),
        Err(error) => {
            let needs_auth = client.has_auth()
                || (client.is_http()
                    && !client.has_configured_auth_header()
                    && error.is_auth_rejection());
            tracing::warn!(
                server = server.as_str(),
                elapsed_ms = start.elapsed().as_millis() as u64,
                timeout_sec,
                error = %error,
                needs_auth,
                "MCP server failed to initialize"
            );
            Err(HandshakeFailure {
                server,
                error,
                needs_auth,
                elapsed: start.elapsed(),
                timeout_sec,
            })
        }
    }
}
fn register_mcp_tool(
    tool_bridge: &crate::tools::bridge::ToolBridge,
    events: &xai_grok_session_events::EventWriter,
    server_name: &str,
    reg: crate::session::mcp_servers::McpToolRegistration,
    mcp_state: &mut McpState,
    ui_tools_by_server: &mut std::collections::HashMap<
        String,
        Vec<crate::extensions::mcp::McpToolEntry>,
    >,
) {
    let qualified_name = reg.name.clone();
    let prefix = format!(
        "{}{}",
        server_name,
        crate::session::mcp_servers::MCP_TOOL_NAME_DELIMITER
    );
    let unqualified = qualified_name
        .strip_prefix(&prefix)
        .unwrap_or(&qualified_name)
        .to_string();
    mcp_state.record_tool_icons(qualified_name.clone(), reg.icons.clone());
    if let Some(meta) = reg.meta.as_ref() {
        mcp_state
            .mcp_tool_meta
            .insert(qualified_name.clone(), meta.clone());
        if meta
            .get("ui")
            .and_then(|ui| ui.get("resourceUri"))
            .is_some()
        {
            ui_tools_by_server
                .entry(server_name.to_string())
                .or_default()
                .push(crate::extensions::mcp::McpToolEntry {
                    name: unqualified.clone(),
                    display_name: None,
                    description: Some(reg.description.clone()),
                    meta: Some(meta.clone()),
                    icons: reg.icons.clone(),
                    enabled: !mcp_state.is_tool_disabled(server_name, &unqualified),
                });
        }
    }
    if mcp_state.is_tool_disabled(server_name, &unqualified) {
        tracing::info!(
            "Stashing disabled MCP tool '{}' from '{}'",
            qualified_name,
            server_name
        );
        mcp_state
            .disabled_tool_registrations
            .insert(qualified_name, reg);
        return;
    }
    if !reg.model_visible {
        tracing::debug!(
            "Skipping app-only MCP tool '{}' from '{}'",
            qualified_name,
            server_name
        );
        return;
    }
    if let Err(e) = tool_bridge.register_mcp_tools(reg.name, reg.tool, Some(reg.input_schema)) {
        tracing::warn!(
            "Failed to register tool '{}' from MCP server '{}': {}",
            qualified_name,
            server_name,
            e
        );
        events.emit(xai_grok_session_events::Event::McpToolRegistrationFailed {
            server_name: server_name.to_string(),
            tool_name: qualified_name,
            error: e.to_string(),
        });
    } else {
        tracing::debug!(
            "Registered MCP tool '{}' from server '{}'",
            qualified_name,
            server_name
        );
    }
}
