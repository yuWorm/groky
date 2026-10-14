//! Checks provider endpoint resolution, query parameters, and environment headers over HTTP.

mod support;

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::http::{HeaderMap, Uri};
use axum::routing::post;
use tokio::net::TcpListener;
use xai_grok_sampler::SamplingClient;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn request_carries_query_params_and_env_http_headers() {
    // A unique name avoids clashing with other tests that read the process environment; the surrounding whitespace exercises value trimming
    let env_var = "XAI_SAMPLER_TEST_TENANT_TOKEN";
    unsafe { std::env::set_var(env_var, "  tenant-secret\n") };

    let captured: Arc<Mutex<Option<(String, HeaderMap)>>> = Arc::new(Mutex::new(None));
    let sink = Arc::clone(&captured);
    let app = Router::new().route(
        "/v1/chat/completions",
        post(move |uri: Uri, headers: HeaderMap| {
            let sink = Arc::clone(&sink);
            async move {
                *sink.lock().unwrap() =
                    Some((uri.query().unwrap_or_default().to_string(), headers));
                "{}"
            }
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    // The base URL already carries `api-version`; a configured value must replace it (not duplicate), keep unrelated keys, and percent-encode
    let base_url = format!("http://{addr}/v1?api-version=old&keep=1");
    let mut cfg = support::test_config(&base_url, "test-key");
    cfg.query_params
        .insert("api-version".into(), "2026-07-22".into());
    cfg.query_params.insert("tenant".into(), "a b".into());
    cfg.env_http_headers
        .insert("x-tenant-token".into(), env_var.into());

    let client = SamplingClient::new(cfg).expect("client builds");
    support::send_one(&client).await;
    unsafe { std::env::remove_var(env_var) };

    let (query, headers) = captured.lock().unwrap().take().expect("request captured");
    assert_eq!(query.matches("api-version=").count(), 1, "query: {query}");
    assert!(query.contains("api-version=2026-07-22"), "query: {query}");
    assert!(!query.contains("api-version=old"), "query: {query}");
    assert!(query.contains("keep=1"), "query: {query}");
    assert!(
        query.contains("tenant=a%20b") || query.contains("tenant=a+b"),
        "query: {query}"
    );
    assert_eq!(headers.get("x-tenant-token").unwrap(), "tenant-secret");
}

#[tokio::test]
async fn messages_accepts_sdk_and_versioned_base_urls() {
    use axum::Json;
    use axum::response::IntoResponse;
    use serde_json::{Value, json};
    use xai_grok_sampler::{ApiBackend, AuthScheme};
    use xai_grok_sampling_types::messages::ContentBlock;
    use xai_grok_sampling_types::{ConversationItem, ConversationRequest};

    let handler = post(|uri: Uri, Json(body): Json<Value>| async move {
        assert!(matches!(uri.query(), None | Some("tenant=messages")));
        if body["stream"] == true {
            let events = [
                json!({"type":"message_start","message":{"id":"msg_test","type":"message",
                    "role":"assistant","model":"test-model","content":[],
                    "usage":{"input_tokens":1,"output_tokens":0}}}),
                json!({"type":"content_block_start","index":0,
                    "content_block":{"type":"text","text":""}}),
                json!({"type":"content_block_delta","index":0,
                    "delta":{"type":"text_delta","text":"MESSAGES_OK"}}),
                json!({"type":"content_block_stop","index":0}),
                json!({"type":"message_delta","delta":{"stop_reason":"end_turn"},
                    "usage":{"output_tokens":1}}),
                json!({"type":"message_stop"}),
            ];
            let sse: String = events
                .iter()
                .map(|event| format!("data: {event}\n\n"))
                .collect();
            ([("content-type", "text/event-stream")], sse).into_response()
        } else {
            Json(json!({"id":"msg_test","type":"message","role":"assistant",
                "model":"test-model","content":[{"type":"text","text":"MESSAGES_OK"}],
                "stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}))
            .into_response()
        }
    });
    let app = Router::new()
        .route("/v1/messages", handler.clone())
        .route("/api/anthropic/v1/messages", handler)
        // The GLM gateway answers a missing /v1 with HTTP 200 and a JSON 404.
        .fallback(|| async { Json(json!({"code":500,"msg":"404 NOT_FOUND","success":false})) });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    for path in [
        "/api/anthropic",
        "",
        "/v1/",
        "/api/anthropic/v1/",
        "/api/anthropic?tenant=messages",
        "/api/anthropic/v1/?tenant=messages",
    ] {
        let mut cfg = support::test_config(&format!("http://{addr}{path}"), "test-key");
        cfg.api_backend = ApiBackend::Messages;
        cfg.auth_scheme = AuthScheme::XApiKey;
        if path.is_empty() {
            cfg.query_params.insert("tenant".into(), "messages".into());
        }
        let client = SamplingClient::new(cfg).unwrap();
        let request = ConversationRequest {
            items: vec![ConversationItem::user("Reply with MESSAGES_OK")],
            max_output_tokens: Some(128),
            ..Default::default()
        };
        let streamed = client.conversation_collect(request.clone()).await.unwrap();
        assert_eq!(
            streamed.assistant_text(),
            "MESSAGES_OK",
            "base path: {path}"
        );
        let response = client.conversation_messages(request).await.unwrap();
        assert!(
            matches!(response.content.as_slice(), [ContentBlock::Text { text, .. }] if text == "MESSAGES_OK"),
            "base path: {path}; response: {response:?}"
        );
    }
    server.abort();
}
