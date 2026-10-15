//! End-to-end regression for custom providers that intentionally share an endpoint and wire model.
//!
//! This is a standalone integration-test binary: custom-provider discovery is disabled for the
//! shell's unit-test build, while this dependency build exercises the production discovery path.

mod acp_harness;

use acp_harness::{
    AutoApproveClient, RPC_TIMEOUT, connect_and_auth_with_config, prompt_turn, run_agent_test,
};
use agent_client_protocol::{self as acp, Agent as _};
use serde_json::json;
use xai_grok_shell::compat::{
    VendorAuthStore,
    custom::{CustomModel, CustomProvider, save_custom_provider},
};
use xai_grok_test_support::mock_server::LogEntry;
use xai_grok_test_support::{
    InferenceEndpoint, InferenceRequestMatcher, MockInferenceServer, ScriptedResponse,
};

const WIRE_MODEL: &str = "gpt-5.6";
const FIRST_PROVIDER: &str = "a-first";
const SECOND_PROVIDER: &str = "b-selected";
const FIRST_KEY: &str = "a-first-fixture-key";
const SECOND_KEY: &str = "b-selected-fixture-key";
const OVERRIDE_PROVIDER: &str = "override-provider";
const OVERRIDE_STORED_KEY: &str = "override-provider-secret";
const EXPLICIT_MODEL_KEY: &str = "model-override-secret";
fn install_provider(id: &str, key: &str, base_url: &str, wire_model: &str) {
    save_custom_provider(
        CustomProvider {
            id: id.to_owned(),
            name: id.to_owned(),
            base_url: base_url.to_owned(),
            platform: Default::default(),
            usage_base_url: None,
            api_backend: "chat_completions".to_owned(),
            auth_scheme: "bearer".to_owned(),
            anthropic_version: None,
            models: vec![CustomModel {
                api_model: wire_model.to_owned(),
                name: wire_model.to_owned(),
                context_window: 128_000,
                advertised_context_window: None,
                supports_reasoning_effort: false,
                enabled: true,
                auto_compact_threshold_percent: None,
            }],
        },
        key,
    )
    .unwrap_or_else(|error| panic!("save {id} custom provider: {error}"));
}

fn write_model_api_key_override(model_id: &str, base_url: &str) {
    let home = std::env::var_os("GROK_HOME").expect("test fixture sets GROK_HOME");
    std::fs::write(
        std::path::PathBuf::from(home).join("config.toml"),
        format!(
            r#"[model."{model_id}"]
model = "{WIRE_MODEL}"
model_family = "{OVERRIDE_PROVIDER}"
base_url = "{base_url}"
api_backend = "chat_completions"
api_key = "{EXPLICIT_MODEL_KEY}"
context_window = 128000
"#,
        ),
    )
    .expect("write explicit model credential override");
}

fn catalog_model(provider: &str) -> String {
    format!("{provider}/{WIRE_MODEL}")
}

fn inference_requests(server: &MockInferenceServer) -> Vec<LogEntry> {
    server
        .requests()
        .into_iter()
        .filter(|request| request.path == "/v1/chat/completions")
        .collect()
}

fn assert_prompt_authentication(
    server: &MockInferenceServer,
    before: usize,
    prompt: &str,
    expected_key: Option<&str>,
) {
    let requests = inference_requests(server);
    let request = requests[before..]
        .iter()
        .find(|request| {
            request
                .body
                .as_ref()
                .is_some_and(|body| body.to_string().contains(prompt))
        })
        .unwrap_or_else(|| {
            panic!(
                "prompt `{prompt}` never reached the inference endpoint; new requests: {:#?}",
                &requests[before..]
            )
        });

    assert_eq!(
        request
            .body
            .as_ref()
            .and_then(|body| body.get("model"))
            .and_then(serde_json::Value::as_str),
        Some(WIRE_MODEL),
        "each provider owns a catalog model but sends the shared wire model"
    );
    let expected_authorization = expected_key.map(|key| format!("Bearer {key}"));
    assert_eq!(
        request.authorization.as_deref(),
        expected_authorization.as_deref(),
        "the request must retain the selected provider's bearer despite the shared URL/model"
    );
}

async fn new_session_with_model(
    conn: &acp::ClientSideConnection,
    cwd: &std::path::Path,
    model_id: &str,
) -> acp::SessionId {
    tokio::time::timeout(
        RPC_TIMEOUT,
        conn.new_session(
            acp::NewSessionRequest::new(cwd.to_path_buf())
                .meta(json!({ "modelId": model_id }).as_object().cloned()),
        ),
    )
    .await
    .expect("session/new timed out")
    .expect("session/new failed")
    .session_id
}

async fn switch_model(
    conn: &acp::ClientSideConnection,
    session_id: &acp::SessionId,
    model_id: &str,
) {
    tokio::time::timeout(
        RPC_TIMEOUT,
        conn.set_session_model(acp::SetSessionModelRequest::new(
            session_id.clone(),
            acp::ModelId::new(model_id),
        )),
    )
    .await
    .expect("session/setModel timed out")
    .expect("session/setModel failed");
}

async fn close_and_resume(
    conn: &acp::ClientSideConnection,
    session_id: &acp::SessionId,
    cwd: &std::path::Path,
) {
    tokio::time::timeout(
        RPC_TIMEOUT,
        conn.close_session(acp::CloseSessionRequest::new(session_id.clone())),
    )
    .await
    .expect("session/close timed out")
    .expect("session/close failed");

    tokio::time::timeout(
        RPC_TIMEOUT,
        conn.resume_session(acp::ResumeSessionRequest::new(
            session_id.clone(),
            cwd.to_path_buf(),
        )),
    )
    .await
    .expect("session/resume timed out")
    .expect("session/resume failed");
}

async fn prompt_expect_error(
    conn: &acp::ClientSideConnection,
    session_id: &acp::SessionId,
    text: &str,
) -> acp::Error {
    tokio::time::timeout(
        RPC_TIMEOUT,
        conn.prompt(acp::PromptRequest::new(
            session_id.clone(),
            vec![acp::ContentBlock::Text(acp::TextContent::new(
                text.to_owned(),
            ))],
        )),
    )
    .await
    .expect("prompt timed out")
    .expect_err("a rejected selected-provider credential must fail the turn")
}

#[test]
fn same_url_custom_provider_credentials_follow_catalog_model_through_switch_and_resume() {
    // `run_agent_test` owns a process-global environment lock and a temporary GROK_HOME. This
    // file is its own test binary because `grok_home()` is memoized by production code.
    run_agent_test(|cwd, server| async move {
        // The BTree-backed provider store sorts a-first before b-selected. Both rows deliberately
        // have the same endpoint, wire slug, and bearer scheme, so URL/model inference would
        // select a-first even when b-selected is the catalog model the session selected.
        install_provider(FIRST_PROVIDER, FIRST_KEY, &server.url(), WIRE_MODEL);
        install_provider(
            OVERRIDE_PROVIDER,
            OVERRIDE_STORED_KEY,
            &server.url(),
            WIRE_MODEL,
        );
        install_provider(SECOND_PROVIDER, SECOND_KEY, &server.url(), WIRE_MODEL);
        // A relay's wire name can equal another provider's complete catalog ID.
        // Losing the selected key must not reinterpret that ID as this relay's alias.
        install_provider(
            "namespace-collision",
            "namespace-collision-fixture-key",
            &server.url(),
            &catalog_model(SECOND_PROVIDER),
        );
        let override_model = catalog_model(OVERRIDE_PROVIDER);
        write_model_api_key_override(&override_model, &server.url());
        let raw_config =
            xai_grok_shell::config::load_effective_config().expect("load fixture config");
        let config = xai_grok_shell::agent::config::Config::new_from_toml_cfg(&raw_config)
            .expect("parse fixture config");
        let (conn, _init) =
            connect_and_auth_with_config(AutoApproveClient, "custom-provider-isolation", config)
                .await;

        let second_model = catalog_model(SECOND_PROVIDER);
        let first_model = catalog_model(FIRST_PROVIDER);
        let session_id = new_session_with_model(&conn, &cwd, &second_model).await;

        let before = inference_requests(&server).len();
        prompt_turn(&conn, &session_id, "provider-isolation-initial").await;
        assert_prompt_authentication(
            &server,
            before,
            "provider-isolation-initial",
            Some(SECOND_KEY),
        );

        switch_model(&conn, &session_id, &first_model).await;
        let before = inference_requests(&server).len();
        prompt_turn(&conn, &session_id, "provider-isolation-after-first-switch").await;
        assert_prompt_authentication(
            &server,
            before,
            "provider-isolation-after-first-switch",
            Some(FIRST_KEY),
        );

        switch_model(&conn, &session_id, &override_model).await;
        let before = inference_requests(&server).len();
        prompt_turn(&conn, &session_id, "provider-isolation-explicit-model-key").await;
        assert_prompt_authentication(
            &server,
            before,
            "provider-isolation-explicit-model-key",
            Some(EXPLICIT_MODEL_KEY),
        );

        switch_model(&conn, &session_id, &second_model).await;
        let before = inference_requests(&server).len();
        prompt_turn(&conn, &session_id, "provider-isolation-after-second-switch").await;
        assert_prompt_authentication(
            &server,
            before,
            "provider-isolation-after-second-switch",
            Some(SECOND_KEY),
        );

        close_and_resume(&conn, &session_id, &cwd).await;
        let before = inference_requests(&server).len();
        prompt_turn(&conn, &session_id, "provider-isolation-after-resume").await;
        assert_prompt_authentication(
            &server,
            before,
            "provider-isolation-after-resume",
            Some(SECOND_KEY),
        );

        // Its first turn happens after logout, so auth resolution cannot depend on
        // a previously warmed per-session model-auth memo.
        let cold_session = new_session_with_model(&conn, &cwd, &second_model).await;
        let removed = VendorAuthStore::default_store()
            .expect("open isolated vendor credential store")
            .remove(SECOND_PROVIDER)
            .expect("remove selected provider credential");
        assert!(
            removed,
            "the selected provider credential must exist before removal"
        );
        for (session, prompt) in [
            (&session_id, "provider-isolation-after-key-removal"),
            (&cold_session, "provider-isolation-cold-after-key-removal"),
        ] {
            let rejection = server.expect_response(
                prompt,
                InferenceRequestMatcher::foreground_containing(
                    InferenceEndpoint::ChatCompletions,
                    prompt,
                ),
                ScriptedResponse::json(401, json!({ "error": "selected credential rejected" })),
            );
            let before = inference_requests(&server).len();
            let error = prompt_expect_error(&conn, session, prompt).await;
            assert_prompt_authentication(&server, before, prompt, None);
            rejection.assert_satisfied();
            let data = error.data.as_ref().expect("failed turn explains itself");
            let message = data
                .get("message")
                .unwrap_or(data)
                .as_str()
                .expect("provider-auth failure message is a string");
            assert!(
                message.contains(SECOND_PROVIDER),
                "the 401 must name the selected provider, not a same-URL neighbor: {message}"
            );
            assert!(
                !message.contains(FIRST_PROVIDER),
                "the 401 attribution must not select the first same-URL provider: {message}"
            );
        }
    });
}
