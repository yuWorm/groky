//! MCP snapshot refresh, reminder scheduling, and the bounded handshake gates.

use super::*;

pub(super) const MCP_INIT_CANCELLED_CONFIG_CHANGED: &str = "config_changed";
pub(super) const MCP_STARTUP_GRACE: std::time::Duration = std::time::Duration::from_secs(2);
pub(super) const DELIVERY_TOOLS_DEFAULT_PREFIX_WAIT: std::time::Duration =
    std::time::Duration::from_secs(15);
pub(super) const DELIVERY_TOOLS_TEMPLATED_PREFIX_WAIT: std::time::Duration =
    std::time::Duration::from_secs(60);
pub(super) const MCP_INIT_WAIT_BOUND: std::time::Duration = std::time::Duration::from_secs(120);

/// Outcome of [`SessionActor::wait_for_mcp_handshakes_until`]; `GenerationChanged` tells the caller to restart against the current generation's deadline.
#[derive(Debug, Clone, Copy)]
pub(super) enum McpHandshakeWait {
    Complete,
    DeadlineExpired,
    GenerationChanged,
}

/// The single MCP dispatch predicate. A server with a failure record or a handshake still in flight is not
/// dispatched to; as in the reference, a call to a still-connecting server is rejected rather than waited on.
/// Auth-required and "init finished, no ready client" both dispatch, so the bridge surfaces the real error.
pub(super) async fn mcp_server_dispatchable(
    mcp_state: &TokioMutex<McpState>,
    server_name: &str,
) -> bool {
    let (failed, auth_required, client, settled) = {
        let mcp_state = mcp_state.lock().await;
        (
            mcp_state.init_failed.contains_key(server_name),
            mcp_state.auth_required.contains(server_name),
            mcp_state.get_client(server_name).cloned(),
            mcp_state.has_finished_init() && !mcp_state.is_server_handshaking(server_name),
        )
    };
    if failed {
        return false;
    }
    let ready = match client {
        Some(client) => client.is_ready().await,
        None => false,
    };
    ready || auth_required || settled
}

impl McpReminderMode {
    pub(super) fn from_env() -> Self {
        match std::env::var("MCP_REMINDER_MODE")
            .unwrap_or_default()
            .to_lowercase()
            .as_str()
        {
            "full" => Self::Full,
            _ => Self::Delta,
        }
    }
}

pub(super) fn gateway_tool_is_disabled(
    tool: &crate::session::managed_mcp::GatewayTool,
    disabled_gateway_tools: &std::collections::HashMap<String, std::collections::HashSet<String>>,
) -> bool {
    let qualified_name = tool.qualified_name();
    disabled_gateway_tools
        .get(crate::util::config::MANAGED_GATEWAY_DISABLED_CONNECTORS_KEY)
        .is_some_and(|set| set.contains(&tool.connector_id))
        || disabled_gateway_tools
            .get(&tool.connector_id)
            .is_some_and(|set| set.contains(&qualified_name))
}

pub(super) async fn refresh_mcp_snapshot_and_schedule_reminder_with(
    tool_bridge: Arc<crate::tools::bridge::ToolBridge>,
    mcp_state: Arc<TokioMutex<McpState>>,
    refresh_gate: Arc<TokioMutex<()>>,
    managed_mcp_handle: crate::session::managed_mcp::ManagedMcpStateHandle,
    tool_metadata_snapshot: Arc<std::sync::Mutex<crate::session::tool_index::ToolMetadataSnapshot>>,
    mcp_reminder_dirty: Arc<std::sync::atomic::AtomicBool>,
    disabled_gateway_tools: &std::collections::HashMap<String, std::collections::HashSet<String>>,
    // External harness only: the per-workspace `mcps/` descriptor root
    // `Some` makes this refresh also update the on-disk descriptor mirror so servers that connect late become discoverable
    // `None` for other agent types (no-op)
    mcps_root: Option<std::path::PathBuf>,
) {
    // Refreshes serialize end-to-end on this gate (last write is the latest read); `mcp_state` itself is only locked for short sync scopes below.
    let _refresh_serialized = refresh_gate.lock().await;

    let (gateway_catalog, mut gateway_connectors) = {
        let state = managed_mcp_handle.lock().await;
        let catalog = if state.gateway_tools_active {
            match &state.gateway_tool_cache {
                crate::session::managed_mcp::GatewayToolCatalogCache::Ready(catalog) => {
                    Some(catalog.clone())
                }
                _ => None,
            }
        } else {
            None
        };
        let connectors: Vec<String> = state.gateway_tool_connectors_seen.iter().cloned().collect();
        (catalog, connectors)
    };

    if let Some(catalog) = gateway_catalog.as_ref() {
        gateway_connectors.extend(catalog.tools.iter().map(|tool| tool.connector_id.clone()));
    }
    gateway_connectors.sort_unstable();
    gateway_connectors.dedup();
    // Mirror before dirty: a reminder never announces a server whose descriptor files do not exist yet.
    if let Some(mcps_root) = mcps_root.as_ref() {
        let clients: Vec<(String, Arc<crate::session::mcp_servers::McpClient>)> = {
            let state = mcp_state.lock().await;
            state
                .all_clients()
                .map(|(n, c)| (n.clone(), Arc::clone(c)))
                .collect()
        };
        let protected_connectors = clients.iter().map(|(name, _)| name.clone()).collect();
        let mut gateway_descriptors = Vec::new();
        if let Some(catalog) = gateway_catalog.as_ref() {
            for tool in &catalog.tools {
                if gateway_tool_is_disabled(tool, disabled_gateway_tools) {
                    continue;
                }
                gateway_descriptors.push(crate::session::mcp_descriptors::GatewayToolDescriptor {
                    connector_id: tool.connector_id.clone(),
                    tool_id: tool.tool_id.clone(),
                    description: tool.description.clone(),
                    json_schema: tool.json_schema.clone(),
                });
            }
        }
        crate::session::mcp_descriptors::materialize_descriptors_for_clients(mcps_root, clients)
            .await;
        crate::session::mcp_descriptors::materialize_descriptors_for_gateway_tools(
            mcps_root,
            gateway_descriptors,
            gateway_connectors,
            protected_connectors,
        )
        .await;
    }

    // A config change while the catalog is built can unregister tools it still lists; rebuild rather than publish them.
    const MAX_REBUILDS: usize = 3;
    for _ in 0..MAX_REBUILDS {
        let generation = mcp_state.lock().await.generation();
        let catalog = build_mcp_catalog(
            &tool_bridge,
            &mcp_state,
            gateway_catalog.as_ref(),
            disabled_gateway_tools,
        )
        .await;
        {
            let mcp_state = mcp_state.lock().await;
            if mcp_state.generation() != generation {
                continue;
            }
            // Write and dirty mark in one non-await scope, so a dropped future cannot split them; `mcp_initialized` is re-read fresh under the lock.
            let mut snapshot = tool_metadata_snapshot.lock().unwrap();
            snapshot.tools = catalog.tools;
            snapshot.servers = catalog.servers;
            snapshot.mcp_initialized = mcp_state.is_initialized();
            mcp_reminder_dirty.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        tool_bridge
            .update_resource(xai_grok_tools::types::resources::ManagedGatewayToolCatalog(
                catalog.gateway_resource_entries.into_iter().collect(),
            ))
            .await;
        tracing::debug!("MCP snapshot updated, reminder marked dirty");
        return;
    }
    tracing::warn!("MCP snapshot refresh skipped: configs kept changing while it was built");
}

struct McpCatalog {
    tools: Vec<crate::session::tool_index::ToolMetadata>,
    servers: Vec<crate::session::tool_index::ServerMetadata>,
    gateway_resource_entries: Vec<(
        String,
        xai_grok_tools::types::resources::ManagedGatewayToolSource,
    )>,
}

/// Reads the bridge and the connected clients; the caller publishes only if the generation held throughout.
async fn build_mcp_catalog(
    tool_bridge: &crate::tools::bridge::ToolBridge,
    mcp_state: &TokioMutex<McpState>,
    gateway_catalog: Option<&crate::session::managed_mcp::GatewayToolCatalog>,
    disabled_gateway_tools: &std::collections::HashMap<String, std::collections::HashSet<String>>,
) -> McpCatalog {
    use crate::session::tool_index::{
        ServerMetadata, ToolMetadata, extract_parameter_names, split_qualified_name,
    };

    let all_defs = tool_bridge.tool_definitions().await;
    let mut seen_tools = std::collections::HashSet::new();
    let mut tools: Vec<ToolMetadata> = all_defs
        .iter()
        .filter(|d| d.function.name.contains("__"))
        .filter(|d| seen_tools.insert(d.function.name.clone()))
        .map(|d| {
            let (server, tool) = split_qualified_name(&d.function.name);
            ToolMetadata {
                qualified_name: d.function.name.clone(),
                server_name: server.to_string(),
                tool_name: tool.to_string(),
                description: d.function.description.clone().unwrap_or_default(),
                parameters: extract_parameter_names(&d.function.parameters),
                input_schema: d.function.parameters.clone(),
            }
        })
        .collect();

    let mut gateway_resource_entries = Vec::new();
    if let Some(catalog) = gateway_catalog {
        for tool in &catalog.tools {
            let qualified_name = tool.qualified_name();
            if gateway_tool_is_disabled(tool, disabled_gateway_tools) {
                continue;
            }
            if !seen_tools.insert(qualified_name.clone()) {
                continue;
            }
            gateway_resource_entries.push((
                qualified_name.clone(),
                xai_grok_tools::types::resources::ManagedGatewayToolSource {
                    connector_id: tool.connector_id.clone(),
                    connector_name: tool.connector_name.clone(),
                    tool_id: tool.tool_id.clone(),
                    tool_name: tool.tool_name.clone(),
                    call_id: tool.call_id.clone(),
                },
            ));
            tools.push(ToolMetadata {
                qualified_name,
                server_name: tool.connector_id.clone(),
                tool_name: tool.tool_id.clone(),
                description: tool.description.clone(),
                parameters: extract_parameter_names(&tool.json_schema),
                input_schema: tool.json_schema.clone(),
            });
        }
    }

    let servers_with_tools: std::collections::HashSet<&str> =
        tools.iter().map(|t| t.server_name.as_str()).collect();
    let clients_with_tools: Vec<(String, Arc<crate::session::mcp_servers::McpClient>)> = {
        let mcp_state = mcp_state.lock().await;
        mcp_state
            .all_clients()
            .filter(|(name, _)| servers_with_tools.contains(name.as_str()))
            .map(|(n, c)| (n.clone(), Arc::clone(c)))
            .collect()
    };
    let mut servers = Vec::new();
    for (name, client) in clients_with_tools {
        servers.push(ServerMetadata {
            description: client.server_instructions().await,
            name,
        });
    }

    McpCatalog {
        tools,
        servers,
        gateway_resource_entries,
    }
}

#[cfg(test)]
pub(crate) async fn refresh_mcp_snapshot_for_test(
    tool_bridge: Arc<crate::tools::bridge::ToolBridge>,
    mcp_state: Arc<TokioMutex<McpState>>,
    managed_mcp_handle: crate::session::managed_mcp::ManagedMcpStateHandle,
    tool_metadata_snapshot: Arc<std::sync::Mutex<crate::session::tool_index::ToolMetadataSnapshot>>,
) {
    refresh_mcp_snapshot_for_test_with_disabled(
        tool_bridge,
        mcp_state,
        managed_mcp_handle,
        tool_metadata_snapshot,
        &Default::default(),
    )
    .await;
}

#[cfg(test)]
pub(crate) async fn refresh_mcp_snapshot_for_test_with_disabled(
    tool_bridge: Arc<crate::tools::bridge::ToolBridge>,
    mcp_state: Arc<TokioMutex<McpState>>,
    managed_mcp_handle: crate::session::managed_mcp::ManagedMcpStateHandle,
    tool_metadata_snapshot: Arc<std::sync::Mutex<crate::session::tool_index::ToolMetadataSnapshot>>,
    disabled_gateway_tools: &std::collections::HashMap<String, std::collections::HashSet<String>>,
) {
    refresh_mcp_snapshot_and_schedule_reminder_with(
        tool_bridge,
        mcp_state,
        Arc::new(TokioMutex::new(())),
        managed_mcp_handle,
        tool_metadata_snapshot,
        Arc::new(std::sync::atomic::AtomicBool::new(false)),
        disabled_gateway_tools,
        None,
    )
    .await;
}

/// The prompt gates' per-generation waits: the startup grace is armed once, and a bounded full wait times out at most once.
/// Keyed by `McpState` generation, so a config change starts both over.
#[derive(Default)]
pub(crate) struct McpStartupWaits {
    grace: std::cell::Cell<Option<(u64, tokio::time::Instant)>>,
    full_wait_timed_out: std::cell::Cell<Option<u64>>,
}

impl McpStartupWaits {
    fn grace_deadline(&self, generation: u64, grace: std::time::Duration) -> tokio::time::Instant {
        match self.grace.get() {
            Some((armed_for, deadline)) if armed_for == generation => deadline,
            _ => {
                let deadline = tokio::time::Instant::now() + grace;
                self.grace.set(Some((generation, deadline)));
                deadline
            }
        }
    }

    pub(crate) fn full_wait_timed_out(&self, generation: u64) -> bool {
        self.full_wait_timed_out.get() == Some(generation)
    }

    fn mark_full_wait_timed_out(&self, generation: u64) {
        self.full_wait_timed_out.set(Some(generation));
    }
}

impl SessionActor {
    #[cfg(test)]
    pub(crate) async fn full_mcp_wait_timed_out(&self) -> bool {
        let generation = self.mcp_state.lock().await.generation();
        self.mcp_startup_waits.full_wait_timed_out(generation)
    }

    pub(super) async fn wait_for_mcp_initialized_bounded_once(&self) {
        let generation = self.mcp_state.lock().await.generation();
        if self.mcp_startup_waits.full_wait_timed_out(generation) {
            return;
        }
        let timed_out = tokio::time::timeout(MCP_INIT_WAIT_BOUND, self.wait_for_mcp_initialized())
            .await
            .is_err();
        if timed_out {
            self.mcp_startup_waits.mark_full_wait_timed_out(generation);
            tracing::warn!(
                "MCP initialization did not settle within {MCP_INIT_WAIT_BOUND:?}; proceeding"
            );
        }
    }

    /// One deadline armed at first use, so a session pays the grace at most once; `deliveryTools` sessions keep full waits.
    /// A config change mid-grace restarts the wait against the new generation's freshly armed deadline.
    pub(super) async fn wait_for_mcp_startup_grace(&self) {
        loop {
            let generation = self.mcp_state.lock().await.generation();
            let deadline = self
                .mcp_startup_waits
                .grace_deadline(generation, MCP_STARTUP_GRACE);
            if !matches!(
                self.wait_for_mcp_handshakes_until(deadline).await,
                McpHandshakeWait::GenerationChanged
            ) {
                return;
            }
        }
    }
    #[tracing::instrument(skip_all)]
    pub(super) async fn wait_for_mcp_handshakes_until(
        &self,
        deadline: tokio::time::Instant,
    ) -> McpHandshakeWait {
        let start = std::time::Instant::now();
        let signal = self.mcp_state.lock().await.init_wait_signal();
        let mut first_pass = true;
        let mut observed_generation = None;
        let outcome = loop {
            // Subscribe (and enable) BEFORE reading state: `notify_waiters` stores no permit, so a notify landing between read and await would otherwise be lost.
            let notified = signal.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let (generation, no_servers, settled) = {
                let s = self.mcp_state.lock().await;
                (
                    s.generation(),
                    !s.has_mcp_servers(),
                    s.handshakes_complete(),
                )
            };
            // No notify may conclude against a generation other than the one this wait started observing.
            if *observed_generation.get_or_insert(generation) != generation {
                return McpHandshakeWait::GenerationChanged;
            }
            // Complete is the state machine's own fact: a pre-seed empty set is not it,
            // so a superseded pass's notify cannot conclude a fresh generation's grace.
            if no_servers || settled {
                if first_pass {
                    return McpHandshakeWait::Complete;
                }
                break McpHandshakeWait::Complete;
            }
            first_pass = false;
            tokio::select! {
                () = &mut notified => {},
                () = tokio::time::sleep_until(deadline) => break McpHandshakeWait::DeadlineExpired,
            }
        };

        // Only acquire the post-wait snapshot when INFO tracing is active; in production the extra lock and string cloning is unnecessary
        if tracing::enabled!(tracing::Level::INFO) {
            let s = self.mcp_state.lock().await;
            tracing::info!(
                session_id = %self.session_info.id.0,
                outcome = ?outcome,
                elapsed_ms = start.elapsed().as_millis() as u64,
                final_initializing_names = ?s.handshaking_servers_iter().cloned().collect::<Vec<_>>(),
                final_client_names = ?s.all_clients().map(|(n, _)| n.as_str()).collect::<Vec<_>>(),
                "wait_for_mcp_handshakes_until: done"
            );
        }
        outcome
    }

    /// Re-register MCP tools from the existing clients onto a freshly built `ToolBridge` after a zero-turn harness rebuild.
    /// Per-server `list_tools` failures are logged and skipped.
    /// Afterwards the tool metadata snapshot is refreshed so `search_tool` stays accurate.
    pub(super) async fn re_register_mcp_tools_on_rebuilt_bridge(&self) {
        // Snapshot server names and client Arcs to avoid holding the lock across async list_tools calls
        let clients: Vec<(
            String,
            std::sync::Arc<crate::session::mcp_servers::McpClient>,
        )> = {
            let st = self.mcp_state.lock().await;
            st.all_clients()
                .map(|(name, client)| (name.clone(), std::sync::Arc::clone(client)))
                .collect()
        };

        if clients.is_empty() {
            self.refresh_mcp_snapshot_and_schedule_reminder().await;
            return;
        }

        tracing::info!(
            session_id = %self.session_info.id.0,
            server_count = clients.len(),
            "re_register_mcp_tools_on_rebuilt_bridge: re-registering MCP tools from existing clients"
        );

        let mcp_state_arc = std::sync::Arc::clone(&self.mcp_state);
        let mut all_ui_tools: std::collections::HashMap<
            String,
            Vec<crate::extensions::mcp::McpToolEntry>,
        > = std::collections::HashMap::new();

        for (server_name, client) in &clients {
            let registrations = match client
                .get_tool_registrations(std::sync::Arc::clone(&mcp_state_arc))
                .await
            {
                Ok(regs) => regs,
                Err(e) => {
                    tracing::warn!(
                        session_id = %self.session_info.id.0,
                        server = %server_name,
                        error = %e,
                        "re_register_mcp_tools_on_rebuilt_bridge: failed to list tools, skipping server"
                    );
                    continue;
                }
            };

            let tool_count = registrations.len();
            let mut mcp_state = self.mcp_state.lock().await;

            for reg in registrations {
                self.register_mcp_tool(server_name, reg, &mut mcp_state, &mut all_ui_tools);
            }
            drop(mcp_state);

            tracing::info!(
                session_id = %self.session_info.id.0,
                server = %server_name,
                tool_count,
                "re_register_mcp_tools_on_rebuilt_bridge: re-registered tools"
            );
        }

        // Refresh the snapshot so search_tool returns accurate results against the newly-registered tools
        self.refresh_mcp_snapshot_and_schedule_reminder().await;
        self.emit_mcp_tools_changed_notifications(all_ui_tools);
    }
}
