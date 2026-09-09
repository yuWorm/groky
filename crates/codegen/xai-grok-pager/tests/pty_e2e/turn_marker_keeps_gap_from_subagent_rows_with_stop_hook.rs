//! PTY: with a Stop hook configured, the parent's `Worked for` marker must keep its blank-row gap from the
//! background subagent's completion row that lands under it after the turn already ended.
//! A Stop hook batch collapses the marker so its summary rides the same line; the gap rule must not then stack it
//! against the next collapsed row like tool chrome.
//!
//! Set `GROK_PTY_CAST_DIR` to dump the final screen (`.txt`/`.html`) and an asciinema cast for visual review.
#[allow(unused_imports)]
use super::common::*;

/// Identifies the child's requests in the mock log.
#[cfg(unix)]
const CHILD_PROMPT_MARKER: &str = "CHILD_PROMPT_MARKER_XYZ";

/// The pager keys the background flag on `task_id`; only a background child gets its own completion row.
#[cfg(unix)]
const CHILD_TASK_ID: &str = "0192f1a0-7c3d-7e4b-8f9a-1b2c3d4e5f60";

#[cfg(unix)]
const CHILD_DONE: &str = "CHILD_TURN_DONE_XYZ";

#[cfg(unix)]
const PARENT_DONE: &str = "PARENT_TURN_DONE_XYZ";

#[cfg(unix)]
const WAKE_DONE: &str = "WAKE_TURN_DONE_XYZ";

#[cfg(unix)]
fn seed_stop_hook(content: &ContentController) {
    let spec = json!({
        "hooks": {
            "Stop": [{
                "hooks": [{ "type": "command", "command": "true", "timeout": 5 }]
            }]
        }
    });
    seed_hook_spec(content, "stop.json", &spec);
}

/// Zero-based screen rows of every line containing `needle`.
#[cfg(unix)]
fn rows_containing(screen: &str, needle: &str) -> Vec<usize> {
    screen
        .lines()
        .enumerate()
        .filter_map(|(row, line)| line.contains(needle).then_some(row))
        .collect()
}

/// Whether `screen` has at least one blank row between rows `above` and `below`.
#[cfg(unix)]
fn has_blank_row_between(screen: &str, above: usize, below: usize) -> bool {
    let lines: Vec<&str> = screen.lines().collect();
    (above + 1..below).any(|row| lines.get(row).is_some_and(|line| line.trim().is_empty()))
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "PTY e2e; run the owning pty_e2e_* Cargo test with --ignored (see Cargo.toml)"]
async fn turn_marker_keeps_gap_from_subagent_rows_with_stop_hook() {
    let content = ContentController::start().await.expect("start content");
    seed_stop_hook(&content);
    // Disable the shell's 15 s auto-background budget so the hold below runs to its own 60 s bound.
    std::fs::write(
        content.home().join(".grok").join("config.toml"),
        "[toolset.bash]\nforeground_block_budget_ms = 0\n",
    )
    .expect("write config.toml");

    let spawn_args = json!({
        "description": "spacing probe",
        "prompt": format!("{CHILD_PROMPT_MARKER} reply with the word done"),
        "subagent_type": "general-purpose",
        "background": true,
        "task_id": CHILD_TASK_ID
    })
    .to_string();
    // Flag-gated foreground hold: released after the child claims the blocked turn so the parent
    // follow-up cannot steal it. Capped at 60 s (300 × 0.2 s), the same budget the child-turn wait
    // below gets, and under the bash tool's 120 s default timeout.
    let flag = content.home().join("turn_marker_gap_hold_flag");
    let hold_args = json!({
        "command": format!(
            "for _ in $(seq 1 300); do [ -e {} ] && break; /bin/sleep 0.2; done",
            flag.display()
        ),
        "description": "hold turn"
    })
    .to_string();
    let calls = [
        ("call_spawn_probe", "spawn_subagent", spawn_args),
        ("call_hold_turn", "run_terminal_command", hold_args),
    ];
    let _spawn_turn = content.expect_agent_turn_with_responses(
        "spawn and hold",
        ScriptedResponse::sse(responses_api_parallel_tool_call_events(&calls)),
        ScriptedResponse::sse(chat_completions_parallel_tool_call_events(&calls)),
    );
    let mut child_turn = content.expect_agent_turn_blocked("child turn", CHILD_DONE);
    content.set_response(PARENT_DONE);

    let binary = pager_binary().expect("resolve pager binary");
    // --yolo skips the bash and spawn permission prompts; --trust skips the folder-trust gate.
    let mut harness = PtyHarness::spawn_with_content_in_dir(
        &binary,
        DEFAULT_ROWS,
        DEFAULT_COLS,
        &content,
        &["--yolo", "--trust"],
        Some(content.home()),
    )
    .expect("spawn pager");

    harness
        .wait_for_text(WELCOME_SCREEN_SENTINEL, WELCOME_TIMEOUT)
        .expect("welcome");
    harness
        .inject_keys(format!("{PROMPT}\r").as_bytes())
        .expect("submit prompt");

    tokio::time::timeout(Duration::from_secs(60), child_turn.wait_received())
        .await
        .unwrap_or_else(|_| {
            panic!(
                "no request claimed the blocked child turn\n--- non-system messages ---\n{}\n--- screen ---\n{}",
                dump_non_system_messages(&content.request_bodies()),
                harness.screen_contents()
            )
        });
    let bodies = content.request_bodies();
    assert!(
        bodies
            .iter()
            .any(|body| body.to_string().contains(CHILD_PROMPT_MARKER)),
        "the child's request never reached the mock\n--- non-system messages ---\n{}",
        dump_non_system_messages(&bodies)
    );
    // Compact JSON. The parent follow-up is the only request that carries a tool result for
    // call_hold_turn (Responses: function_call_output + call_id; Chat Completions: role=tool +
    // tool_call_id). It cannot exist until the hold flag is written — unless the 60 s bound elapsed.
    assert!(
        !bodies.iter().any(|body| {
            let serialized = body.to_string();
            serialized.contains("call_hold_turn")
                && (serialized.contains("function_call_output")
                    || serialized.contains("\"role\":\"tool\""))
        }),
        "the parent's follow-up claimed the child's blocked turn: the hold ended before the child bootstrapped\n--- non-system messages ---\n{}",
        dump_non_system_messages(&bodies)
    );

    std::fs::write(&flag, b"done").expect("release hold");
    harness
        .wait_for_text(PARENT_DONE, Duration::from_secs(60))
        .unwrap_or_else(|_| {
            panic!(
                "parent turn never settled; screen:\n{}",
                harness.screen_contents()
            )
        });
    let parent_marker_shown = wait_until(Duration::from_secs(30), || {
        harness.update(Duration::from_millis(100));
        harness
            .screen_contents()
            .lines()
            .any(|line| line.contains("Worked for") && line.contains("stop"))
    });
    assert!(
        parent_marker_shown,
        "the parent marker never carried the stop-hook summary; screen:\n{}",
        harness.screen_contents()
    );
    write_screen_dump_if_requested(&harness, "turn_marker_gap_stop_hook_parent_settled");

    content.set_response(WAKE_DONE);
    child_turn.release();
    let wake_closed = wait_until(Duration::from_secs(60), || {
        harness.update(Duration::from_millis(100));
        let screen = harness.screen_contents();
        screen.contains(WAKE_DONE) && screen.matches("Worked for").count() == 2
    });
    assert!(
        wake_closed,
        "expected the wake reply and the wake's closing marker; screen:\n{}\n--- non-system messages ---\n{}",
        harness.screen_contents(),
        dump_non_system_messages(&content.request_bodies())
    );
    harness.update(Duration::from_secs(1));

    write_screen_dump_if_requested(&harness, "turn_marker_gap_stop_hook");
    write_cast_if_requested(&harness, "turn_marker_gap_stop_hook.cast");

    let screen = harness.screen_contents();
    assert!(
        !screen.contains("panicked"),
        "pager panicked\nscreen:\n{screen}"
    );

    let markers = rows_containing(&screen, "Worked for");
    let [parent_marker, _wake_marker] = markers[..] else {
        panic!("expected exactly two markers, got {markers:?}; screen:\n{screen}");
    };
    // The child's started row inside the parent turn also reads "Ran 1 subagent" once it finishes
    let completion_row = rows_containing(&screen, "Ran 1 subagent")
        .into_iter()
        .find(|&row| row > parent_marker)
        .unwrap_or_else(|| {
            panic!("no child completion row under the parent marker; screen:\n{screen}")
        });
    assert!(
        has_blank_row_between(&screen, parent_marker, completion_row),
        "the child's completion row is butted against the collapsed parent marker (rows {parent_marker} and {completion_row}); screen:\n{screen}"
    );

    harness.quit().expect("clean quit");
}
