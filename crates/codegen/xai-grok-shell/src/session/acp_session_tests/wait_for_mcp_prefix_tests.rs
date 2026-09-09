use super::support::*;
use super::*;
use std::time::Duration;
use xai_grok_mcp::servers::McpInitStrategy;

async fn timed<F: Future>(f: F) -> (F::Output, Duration) {
    let start = tokio::time::Instant::now();
    let out = f.await;
    (out, start.elapsed())
}

async fn pending_linear_actor(strategy: McpInitStrategy) -> SessionActor {
    let a = actor_with_mcp(vec![stdio("linear", "true")], false, vec!["linear".into()]).await;
    a.mcp_strategy.set(strategy);
    a
}

async fn prepare(a: &SessionActor, id: &str, tool: &str) -> Result<PreparedToolCall, ToolLoop> {
    let call = crate::sampling::types::ToolCallResponse {
        id: id.to_string(),
        kind: "function".to_string(),
        function: crate::sampling::types::ToolCallFunction::new(tool, "{}".to_string()),
    };
    let mut deferred = Vec::new();
    a.prepare_tool_call(call, &mut deferred)
        .await
        .expect("prepare")
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn first_prompt_proceeds_at_grace_expiry_not_the_slowest_server() {
    tokio::task::LocalSet::new().run_until(grace_body()).await;
}

async fn grace_body() {
    let no_configs = actor_with_mcp(vec![], false, vec![]).await;
    let ready = actor_with_mcp(vec![stdio("linear", "true")], true, vec![]).await;
    let (_, fast) = timed(async {
        no_configs.wait_for_mcp_startup_grace().await;
        ready.wait_for_mcp_startup_grace().await;
    })
    .await;
    assert!(
        fast < ms(50),
        "no configs / already ready skip the grace, took {fast:?}"
    );

    struct NoopInvoker;
    #[async_trait::async_trait]
    impl xai_grok_mcp::acp_transport::AcpReverseInvoker for NoopInvoker {
        async fn invoke(
            &self,
            _server_id: &str,
            _message: serde_json::Value,
            _timeout: Duration,
        ) -> Result<serde_json::Value, String> {
            Err("unused".to_string())
        }
    }
    let acp_only = actor_with_mcp(vec![], false, vec!["sdk".into()]).await;
    acp_only.mcp_state.lock().await.set_acp_servers(
        vec![xai_grok_mcp::servers::AcpServerEntry {
            name: "sdk".to_string(),
            server_id: "sdk-1".to_string(),
        }],
        Arc::new(NoopInvoker),
    );
    let (_, acp_wait) = timed(acp_only.wait_for_mcp_startup_grace()).await;
    assert!(
        acp_wait >= MCP_STARTUP_GRACE,
        "ACP-only pays the grace, got {acp_wait:?}"
    );

    let restarted = pending_linear_actor(McpInitStrategy::Blocking).await;
    let state = Arc::clone(&restarted.mcp_state);
    tokio::task::spawn_local(async move {
        tokio::time::sleep(MCP_STARTUP_GRACE / 2).await;
        assert!(
            state
                .lock()
                .await
                .update_configs(vec![stdio("other", "true")])
        );
        tokio::time::sleep(ms(10)).await;
        let mut st = state.lock().await;
        std::mem::forget(st.try_start_init().expect("reclaim after bump"));
        let generation = st.generation();
        st.mark_servers_initializing(generation, vec!["other".to_string()]);
    });
    let (_, restart_wait) = timed(restarted.wait_for_mcp_startup_grace()).await;
    assert!(
        restart_wait >= MCP_STARTUP_GRACE + MCP_STARTUP_GRACE / 2,
        "a bump mid-grace must wake the waiter and re-pay the fresh grace, got {restart_wait:?}"
    );
    assert!(
        restart_wait < MCP_STARTUP_GRACE * 2,
        "restarted grace stays bounded"
    );

    let a = pending_linear_actor(McpInitStrategy::Blocking).await;
    let (prefix, prefix_wait) =
        timed(a.build_prefix_after_mcp_wait(a.requires_full_mcp_wait())).await;
    assert!(
        prefix_wait < ms(1900),
        "Default prefix skips MCP waits, took {prefix_wait:?}"
    );
    assert!(
        !prefix.contains("linear"),
        "Default prefix carries no MCP content"
    );

    let ((_defs, first_ms), gate) = timed(a.prepare_tool_definitions_timed()).await;
    assert!(
        gate >= MCP_STARTUP_GRACE,
        "pending handshakes get the grace, got {gate:?}"
    );
    assert!(
        gate < MCP_STARTUP_GRACE + Duration::from_secs(3),
        "the gate is bounded"
    );
    assert!(first_ms >= MCP_STARTUP_GRACE.as_millis() as u64);

    let (_defs, second_ms) = a.prepare_tool_definitions_timed().await;
    assert!(
        second_ms < 200,
        "a later gate must not restart the grace, got {second_ms}ms"
    );

    a.mcp_state
        .lock()
        .await
        .update_configs(vec![stdio("other", "true")]);
    let (_defs, third_ms) = a.prepare_tool_definitions_timed().await;
    assert!(
        third_ms >= MCP_STARTUP_GRACE.as_millis() as u64,
        "a new generation gets a fresh grace, got {third_ms}ms"
    );
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn delivery_tool_sessions_wait_fully_under_progressive_strategy() {
    tokio::task::LocalSet::new()
        .run_until(progressive_body())
        .await;
}

async fn progressive_body() {
    let a = pending_linear_actor(McpInitStrategy::Progressive).await;
    *a.delivery_tools.borrow_mut() = vec!["linear__post".to_string()];

    let state = Arc::clone(&a.mcp_state);
    tokio::task::spawn_local(async move {
        tokio::time::sleep(ms(300)).await;
        let mut st = state.lock().await;
        let generation = st.generation();
        st.mark_all_servers_ready(generation);
        st.notify_init_waiters();
    });
    let (_prefix, prefix_wait) =
        timed(a.build_prefix_after_mcp_wait(a.requires_full_mcp_wait())).await;
    assert!(
        prefix_wait >= ms(300),
        "prefix gate waits under Progressive"
    );
    assert!(
        prefix_wait < Duration::from_secs(10),
        "settle wakes the gate"
    );

    let state = Arc::clone(&a.mcp_state);
    tokio::task::spawn_local(async move {
        tokio::time::sleep(ms(300)).await;
        let mut st = state.lock().await;
        let generation = st.generation();
        st.finish_init(generation);
    });
    let ((_defs, wait_ms), gate) = timed(a.prepare_tool_definitions_timed()).await;
    assert!(
        gate >= ms(300),
        "definitions gate waits for full init under Progressive"
    );
    assert!(wait_ms >= 300, "the timed wait attributes the init wait");

    // `sleep` never speaks MCP, so the successor pass a rebuild starts below cannot settle early.
    let wedged = Arc::new(
        actor_with_mcp(vec![stdio("linear", "sleep")], false, vec!["linear".into()]).await,
    );
    wedged.mcp_strategy.set(McpInitStrategy::Progressive);
    *wedged.delivery_tools.borrow_mut() = vec!["linear__post".to_string()];
    let bg = Arc::clone(&wedged);
    let full_wait = wedged.requires_full_mcp_wait();
    wedged.deferred_prefix.arm(
        tokio::task::spawn_local(async move { bg.build_prefix_after_mcp_wait(full_wait).await }),
        full_wait,
    );
    let (_, deferred_wait) = timed(wedged.ensure_prefix_ready()).await;
    assert!(
        deferred_wait >= DELIVERY_TOOLS_DEFAULT_PREFIX_WAIT,
        "the deferred prefix runs the full delivery wait, got {deferred_wait:?}"
    );
    assert!(!wedged.chat_state_handle.get_conversation().await.is_empty());

    // A zero-turn rebuild rebuilds the prefix through the same policy, so a delivery-tools session still holds the wait.
    let (_, rebuild_wait) =
        timed(wedged.handle_rebuild_agent_for_definition(
            xai_grok_agent::AgentDefinition::default_grok_build(),
        ))
        .await;
    assert!(
        rebuild_wait >= DELIVERY_TOOLS_DEFAULT_PREFIX_WAIT,
        "the rebuilt prefix runs the full delivery wait, got {rebuild_wait:?}"
    );
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn delivery_wait_is_paid_once_per_generation_when_init_wedges() {
    tokio::task::LocalSet::new().run_until(budget_body()).await;
}

async fn budget_body() {
    let owner = actor_with_mcp(vec![stdio("linear", "true")], false, vec![]).await;
    {
        let init = owner.ensure_mcp_tools_initialized();
        tokio::pin!(init);
        assert!(futures::poll!(init.as_mut()).is_pending());
        assert!(
            owner.mcp_state.lock().await.is_initializing(),
            "owner holds the claim"
        );
    }
    assert!(
        !owner.mcp_state.lock().await.is_initializing(),
        "a dropped init owner must release the claim, not wedge Starting"
    );
    tokio::time::timeout(Duration::from_secs(600), owner.wait_for_mcp_initialized())
        .await
        .expect("the next waiter must be able to re-initiate and settle init");

    let starter = actor_with_mcp(vec![stdio("slow", "sleep")], false, vec![]).await;
    starter.mcp_strategy.set(McpInitStrategy::Blocking);
    *starter.delivery_tools.borrow_mut() = vec!["slow__post".to_string()];
    let (_defs, starter_ms) = starter.prepare_tool_definitions_timed().await;
    assert!(
        starter_ms >= 5_000,
        "a self-started wait must not conclude at finish_init"
    );

    let superseded = actor_with_mcp(vec![stdio("slow2", "sleep")], false, vec![]).await;
    let stale_claim = superseded
        .mcp_state
        .lock()
        .await
        .try_start_init()
        .expect("stale pass claims");
    let wait = superseded.wait_for_mcp_initialized_bounded_once();
    tokio::pin!(wait);
    assert!(
        tokio::time::timeout(Duration::from_secs(5), &mut wait)
            .await
            .is_err()
    );
    assert!(
        superseded
            .mcp_state
            .lock()
            .await
            .update_configs(vec![stdio("slow3", "sleep")])
    );
    assert!(
        tokio::time::timeout(Duration::from_secs(5), &mut wait)
            .await
            .is_err(),
        "supersession must not conclude the wait"
    );
    {
        let mut st = superseded.mcp_state.lock().await;
        assert!(
            !st.cancel_init(&stale_claim),
            "a stale cancel must not release the successor's init"
        );
        assert!(
            st.is_initializing(),
            "init stays live across a stale cancel"
        );
        assert!(
            st.try_start_init().is_none(),
            "a stale cancel must not free the claim"
        );
    }
    drop(stale_claim);
    assert!(!superseded.full_mcp_wait_timed_out().await);
    tokio::time::timeout(Duration::from_secs(200), &mut wait)
        .await
        .expect("the wait concludes at the new generation's settle");
    assert!(!superseded.full_mcp_wait_timed_out().await);

    let a = pending_linear_actor(McpInitStrategy::Blocking).await;
    *a.delivery_tools.borrow_mut() = vec!["linear__post".to_string()];
    {
        let wait = a.wait_for_mcp_initialized_bounded_once();
        tokio::pin!(wait);
        assert!(
            tokio::time::timeout(Duration::from_secs(10), &mut wait)
                .await
                .is_err(),
            "the wedged wait must still be pending when dropped"
        );
    }
    let (_defs, first_ms) = a.prepare_tool_definitions_timed().await;
    assert!(
        first_ms >= 120_000,
        "the first concluded wait pays the full bound"
    );
    let (_defs, second_ms) = a.prepare_tool_definitions_timed().await;
    assert!(
        second_ms < 1_000,
        "a spent budget is not paid again, got {second_ms}ms"
    );
    {
        let mut st = a.mcp_state.lock().await;
        assert!(st.update_configs(vec![stdio("other", "true")]));
        std::mem::forget(st.try_start_init().expect("fresh generation claims"));
        let generation = st.generation();
        st.mark_servers_initializing(generation, vec!["other".to_string()]);
    }
    let (_defs, third_ms) = a.prepare_tool_definitions_timed().await;
    assert!(
        third_ms >= 120_000,
        "a fresh generation pays the bound again"
    );
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn tool_dispatch_gates_on_its_own_server_not_the_slowest_handshake() {
    tokio::task::LocalSet::new()
        .run_until(dispatch_body())
        .await;
}

async fn dispatch_body() {
    struct ReadySdkServer;
    #[async_trait::async_trait]
    impl xai_grok_mcp::acp_transport::AcpReverseInvoker for ReadySdkServer {
        async fn invoke(
            &self,
            _server_id: &str,
            message: serde_json::Value,
            _timeout: Duration,
        ) -> Result<serde_json::Value, String> {
            let id = message
                .get("id")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let result = match message.get("method").and_then(|m| m.as_str()) {
                Some("initialize") => serde_json::json!({
                    "protocolVersion": message["params"]["protocolVersion"],
                    "capabilities": { "tools": {} },
                    "serverInfo": { "name": "ready", "version": "0.0.0" },
                }),
                Some("tools/list") => serde_json::json!({ "tools": [] }),
                other => return Err(format!("unexpected method {other:?}")),
            };
            Ok(serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": result }))
        }
    }

    let a = actor_with_mcp(
        vec![stdio("wedged", "true"), stdio("flaky", "true")],
        false,
        vec!["wedged".to_string(), "flaky".to_string()],
    )
    .await;
    a.mcp_strategy.set(McpInitStrategy::Blocking);

    let ready_client = Arc::new(crate::session::mcp_servers::McpClient::new_acp(
        "ready".to_string(),
        "ready-1".to_string(),
        Arc::new(ReadySdkServer),
        None,
        None,
    ));
    ready_client.ensure_initialized().await.expect("handshake");
    assert!(ready_client.is_ready().await);
    a.mcp_state
        .lock()
        .await
        .owned_clients
        .insert("ready".to_string(), ready_client);
    let bridge = a.agent.borrow().tool_bridge().clone();
    register_stub(&bridge, "ready__echo").await;

    let (prepared, took) = timed(prepare(&a, "call-ready", "ready__echo")).await;
    assert!(
        prepared.is_ok(),
        "a ready server's tool must dispatch, got {prepared:?}"
    );
    assert!(
        took < ms(100),
        "ready must not wait on the wedged handshake, took {took:?}"
    );
    assert!(!a.full_mcp_wait_timed_out().await);

    // Auth-required is recoverable, not terminal: the call must still dispatch so the surfaced auth error can drive re-auth.
    {
        let mut st = a.mcp_state.lock().await;
        let generation = st.generation();
        st.record_init_failure(generation, "ready", true, None);
    }
    let (auth_gated, took) = timed(prepare(&a, "call-auth", "ready__echo")).await;
    assert!(
        auth_gated.is_ok(),
        "an auth-required server's call must dispatch, not reject, got {auth_gated:?}"
    );
    assert!(
        took < ms(100),
        "auth-required must not park the wait, took {took:?}"
    );
    a.mcp_state.lock().await.auth_required.remove("ready");

    let (pending, took) = timed(prepare(&a, "call-wedged", "wedged__do")).await;
    assert!(
        matches!(pending, Err(ToolLoop::NonExistingTool)),
        "a still-connecting server's call rejects rather than waits, got {pending:?}"
    );
    assert!(took < ms(100), "rejecting must not park, took {took:?}");

    {
        let mut st = a.mcp_state.lock().await;
        let generation = st.generation();
        st.record_init_failure(generation, "flaky", false, Some("boom".to_string()));
        st.mark_server_ready(generation, "flaky");
    }
    let flaky = prepare(&a, "call-flaky", "flaky__do").await;
    assert!(
        matches!(flaky, Err(ToolLoop::NonExistingTool)),
        "a failed server's call rejects, got {flaky:?}"
    );
}

/// The abort path strips only namespaces with no live claimant: a still-configured or SDK-registered server belongs to the successor, even before its client lands in owned_clients.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn superseded_abort_strips_only_unclaimed_server_tools() {
    struct NoopInvoker;
    #[async_trait::async_trait]
    impl xai_grok_mcp::acp_transport::AcpReverseInvoker for NoopInvoker {
        async fn invoke(
            &self,
            _server_id: &str,
            _message: serde_json::Value,
            _timeout: Duration,
        ) -> Result<serde_json::Value, String> {
            Err("unused".to_string())
        }
    }

    let bridge = crate::tools::bridge::ToolBridge::for_test();
    register_stub(&bridge, "kept__post").await;
    register_stub(&bridge, "sdk__post").await;
    register_stub(&bridge, "gone__post").await;

    let mut state = crate::session::mcp_servers::McpState::new(vec![stdio("kept", "true")]);
    state.set_acp_servers(
        vec![xai_grok_mcp::servers::AcpServerEntry {
            name: "sdk".to_string(),
            server_id: "sdk-1".to_string(),
        }],
        Arc::new(NoopInvoker),
    );
    super::mcp::unregister_dropped_server_tools(
        &bridge,
        &state,
        &["kept".to_string(), "sdk".to_string(), "gone".to_string()],
    );

    let names: Vec<String> = bridge
        .tool_definitions()
        .await
        .iter()
        .map(|d| d.function.name.clone())
        .collect();
    assert!(
        names.contains(&"kept__post".to_string()),
        "a still-configured server's tools must survive a stale pass's abort"
    );
    assert!(
        names.contains(&"sdk__post".to_string()),
        "an SDK-registered server's tools must survive: its registry outlives config bumps"
    );
    assert!(
        !names.contains(&"gone__post".to_string()),
        "a dropped server's tools must not survive the abort"
    );
}
#[tokio::test(flavor = "current_thread")]
async fn resolved_repo_status_prefetch_builds_first_prefix_with_zero_wait() {
    use crate::session::repo_status_prefix::{
        RepoStatusInputs, RepoStatusPlan, RepoStatusPrefetch, RepoStatusPrefetchState,
        RepoStatusSnapshot,
    };
    use xai_grok_workspace::session::git::VcsKind;

    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (gw_tx, _gw_rx) = tokio::sync::mpsc::unbounded_channel();
            let (persist_tx, _persist_rx) = tokio::sync::mpsc::unbounded_channel();
            let mut actor = create_test_actor(100, 256_000, 80, gw_tx, persist_tx).await;

            let (snapshot_tx, snapshot_rx) = tokio::sync::watch::channel(None);
            snapshot_tx
                .send(Some(RepoStatusSnapshot {
                    root: None,
                    raw_status: Some("## main\n M src/lib.rs\n".to_string()),
                    vcs_kind: VcsKind::Git,
                }))
                .unwrap();
            actor.repo_status_prefetch = RepoStatusPrefetchState::new(RepoStatusPlan::Gather {
                inputs: RepoStatusInputs {
                    cwd: std::path::PathBuf::from("."),
                    vcs_kind: VcsKind::Git,
                    root: None,
                },
                prefetch: std::cell::RefCell::new(Some(RepoStatusPrefetch::from_snapshot_rx(
                    snapshot_rx,
                ))),
            });

            let prefix = actor.build_user_message_prefix().await;

            assert!(
                prefix.contains("<git_status>") && prefix.contains(" M src/lib.rs"),
                "prefix must render the prefetched status, got: {prefix}"
            );
            assert!(
                actor
                    .repo_status_prefetch
                    .take_wait_ms()
                    .is_some_and(|ms| ms < 100),
                "resolved prefetch must not consume the wait budget"
            );
            assert!(
                matches!(
                    actor.repo_status_prefetch.plan(),
                    RepoStatusPlan::Gather { prefetch, .. } if prefetch.borrow().is_none()
                ),
                "prefetch handle is consumed exactly once"
            );
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn absent_inputs_omit_the_status_block() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (gw_tx, _gw_rx) = tokio::sync::mpsc::unbounded_channel();
            let (persist_tx, _persist_rx) = tokio::sync::mpsc::unbounded_channel();
            let actor = create_test_actor(100, 256_000, 80, gw_tx, persist_tx).await;

            let prefix = actor.build_user_message_prefix().await;

            assert!(
                !prefix.contains("<git_status>") && !prefix.contains("<jj_status>"),
                "absent inputs must omit the status block, got: {prefix}"
            );
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn resumed_session_gathers_status_inline_without_a_prefetch() {
    use crate::session::repo_status_prefix::{
        RepoStatusInputs, RepoStatusPlan, RepoStatusPrefetchState,
    };
    use xai_grok_workspace::session::git::VcsKind;

    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            crate::test_support::ensure_hermetic_git_on_path();
            let repo = tempfile::tempdir().unwrap();
            let init = std::process::Command::new("git")
                .args(["init", "--quiet"])
                .current_dir(repo.path())
                .status()
                .expect("spawn git init");
            assert!(init.success(), "git init failed");
            std::fs::write(repo.path().join("untracked.txt"), b"x").unwrap();

            let (gw_tx, _gw_rx) = tokio::sync::mpsc::unbounded_channel();
            let (persist_tx, _persist_rx) = tokio::sync::mpsc::unbounded_channel();
            let mut actor = create_test_actor(100, 256_000, 80, gw_tx, persist_tx).await;
            actor.repo_status_prefetch = RepoStatusPrefetchState::new(RepoStatusPlan::Gather {
                inputs: RepoStatusInputs {
                    cwd: repo.path().to_path_buf(),
                    vcs_kind: VcsKind::Git,
                    root: Some(repo.path().to_path_buf()),
                },
                prefetch: std::cell::RefCell::new(None),
            });

            let prefix = actor.build_user_message_prefix().await;

            assert!(
                prefix.contains("<git_status>") && prefix.contains("untracked.txt"),
                "inline gather (no prefetch) must render the status block, got: {prefix}"
            );
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn suppressed_status_omits_the_body_but_keeps_the_repo_root() {
    use crate::session::repo_status_prefix::{
        RepoStatusPlan, RepoStatusPrefetchState, discover_vcs_root,
    };
    use xai_grok_workspace::session::git::VcsKind;

    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            crate::test_support::ensure_hermetic_git_on_path();
            let repo = tempfile::tempdir().unwrap();
            let init = std::process::Command::new("git")
                .args(["init", "--quiet"])
                .current_dir(repo.path())
                .status()
                .expect("spawn git init");
            assert!(init.success(), "git init failed");

            let (gw_tx, _gw_rx) = tokio::sync::mpsc::unbounded_channel();
            let (persist_tx, _persist_rx) = tokio::sync::mpsc::unbounded_channel();
            let mut actor = create_test_actor(100, 256_000, 80, gw_tx, persist_tx).await;
            actor.repo_status_prefetch = RepoStatusPrefetchState::new(RepoStatusPlan::RootOnly {
                root: discover_vcs_root(repo.path()),
                vcs_kind: VcsKind::Git,
            });

            let prefix = actor.build_user_message_prefix().await;

            assert!(
                !prefix.contains("<git_status>"),
                "suppressed status must omit the body, got: {prefix}"
            );
            assert!(
                matches!(
                    actor.repo_status_prefetch.plan(),
                    RepoStatusPlan::RootOnly { root: Some(_), .. }
                ),
                "suppressed status must keep the discovered repo root"
            );
        })
        .await;
}
