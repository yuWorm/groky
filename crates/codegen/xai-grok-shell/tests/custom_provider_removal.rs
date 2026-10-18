//! Production discovery and persistence paths, isolated from the user's provider stores.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use xai_grok_shell::compat::{
    VendorAuthStore,
    custom::{self, CustomModel, CustomProvider, CustomProviderStore},
};

fn provider(id: &str, base_url: &str) -> CustomProvider {
    CustomProvider {
        id: id.into(),
        name: id.into(),
        base_url: base_url.into(),
        platform: Default::default(),
        usage_base_url: None,
        api_backend: "chat_completions".into(),
        auth_scheme: "bearer".into(),
        anthropic_version: None,
        models: vec![CustomModel {
            api_model: "fixture-model".into(),
            name: "Fixture model".into(),
            context_window: 128_000,
            advertised_context_window: None,
            supports_reasoning_effort: false,
            enabled: true,
            auto_compact_threshold_percent: None,
        }],
    }
}

// grok_home() is memoized; all scenarios share one isolated, current-thread test.
#[tokio::test(flavor = "current_thread")]
async fn removal_clears_only_custom_provider_and_refresh_cannot_restore_it() {
    let home = tempfile::tempdir().unwrap();
    // SAFETY: this test binary has one current-thread test; set before starting tasks.
    unsafe { std::env::set_var("GROK_HOME", home.path()) };
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}/v1", listener.local_addr().unwrap());
        custom::save_custom_provider(provider("remove-me", &base_url), "fixture-key").unwrap();
        custom::save_custom_provider(provider("keep-me", &base_url), "other-key").unwrap();
        let mut auth = VendorAuthStore::default_store().unwrap();
        auth.set_api_key("openai", "builtin-key".into()).unwrap();
        assert!(custom::is_custom_provider("remove-me"));
        assert!(xai_grok_shell::compat::acp_models_for_provider("remove-me")
            .contains_key(&agent_client_protocol::ModelId::new("remove-me/fixture-model")));

        let (requested_tx, requested_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut chunk = [0; 1024];
            while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                let count = stream.read(&mut chunk).await.unwrap();
                assert_ne!(count, 0);
                request.extend_from_slice(&chunk[..count]);
            }
            requested_tx.send(()).unwrap();
            release_rx.await.unwrap();
            let body = r#"{"data":[{"id":"new-model"}]}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });
        let refresh = tokio::spawn(custom::refresh("remove-me"));
        requested_rx.await.unwrap();
        assert!(custom::remove_custom_provider("remove-me").unwrap());
        release_tx.send(()).unwrap();
        assert_eq!(refresh.await.unwrap().unwrap(), 0);
        server.await.unwrap();

        assert!(!CustomProviderStore::default_store().unwrap().has("remove-me"));
        assert!(!VendorAuthStore::default_store().unwrap().has_provider("remove-me"));
        assert!(xai_grok_shell::compat::acp_models_for_provider("remove-me").is_empty());
        assert!(!xai_grok_shell::compat::arg_items().iter().any(|(id, _, _)| id == "remove-me"));
        assert!(!custom::remove_custom_provider("remove-me").unwrap());
        assert!(custom::remove_custom_provider("openai").is_err());
        let auth = VendorAuthStore::default_store().unwrap();
        assert_eq!(auth.api_key("openai").as_deref(), Some("builtin-key"));
        assert_eq!(auth.api_key("keep-me").as_deref(), Some("other-key"));
        assert!(CustomProviderStore::default_store().unwrap().has("keep-me"));
        assert!(xai_grok_shell::compat::acp_models_for_provider("keep-me")
            .contains_key(&agent_client_protocol::ModelId::new("keep-me/fixture-model")));

        // Signed-out and keyless providers are removable too.
        custom::save_custom_provider(provider("signed-out", &base_url), "old-key").unwrap();
        xai_grok_shell::compat::logout_provider("signed-out").unwrap();
        assert!(custom::remove_custom_provider("signed-out").unwrap());
        assert!(!custom::is_custom_provider("signed-out"));
        custom::save_custom_provider(provider("keyless", &base_url), "").unwrap();
        assert!(custom::remove_custom_provider("keyless").unwrap());
        assert!(!custom::is_custom_provider("keyless"));
        assert!(!VendorAuthStore::default_store().unwrap().has_provider("keyless"));
    })
    .await
    .expect("provider removal scenario timed out");
}
