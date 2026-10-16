//! OpenRouter PKCE — port of Pi `auth/oauth/openrouter.ts`.
//!
//! Authorization mints a user-controlled API key billed from OpenRouter
//! credits. The key is stored as an OAuth slot (`access`) with no expiry.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::mpsc;
use uuid::Uuid;

use super::callback::{error_html, read_http_request, success_html, write_html};
use super::pkce::generate_pkce;
use super::{OAuthPending, parse_authorization_input};
use crate::compat::auth_store::VendorAuthStore;
use crate::compat::probe::{VendorLoginError, probe_api_key};

const AUTHORIZE_URL: &str = "https://openrouter.ai/auth";
const TOKEN_URL: &str = "https://openrouter.ai/api/v1/auth/keys";
const PROVIDER_ID: &str = "openrouter";
const LOGIN_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const TOKEN_TIMEOUT: Duration = Duration::from_secs(30);

struct InFlight {
    verifier: String,
    callback_path: String,
    manual_tx: mpsc::Sender<String>,
    manual_rx: Mutex<Option<mpsc::Receiver<String>>>,
    cancel_tx: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    cancel_rx: Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
    listener: Mutex<Option<TcpListener>>,
}

static INFLIGHT: OnceLock<Mutex<HashMap<String, InFlight>>> = OnceLock::new();

fn inflight_map() -> std::sync::MutexGuard<'static, HashMap<String, InFlight>> {
    INFLIGHT
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

pub fn login_label() -> &'static str {
    "Sign in with OpenRouter"
}

pub async fn begin() -> Result<OAuthPending, VendorLoginError> {
    cancel(PROVIDER_ID);

    let pkce = generate_pkce();
    let callback_path = format!("/oauth/callback/{}", Uuid::new_v4());
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| VendorLoginError::Probe(format!("couldn't bind OAuth callback: {e}")))?;
    let port = listener
        .local_addr()
        .map_err(|e| VendorLoginError::Probe(e.to_string()))?
        .port();
    let callback_url = format!("http://127.0.0.1:{port}{callback_path}");

    let mut authorize =
        reqwest::Url::parse(AUTHORIZE_URL).map_err(|e| VendorLoginError::Probe(e.to_string()))?;
    authorize
        .query_pairs_mut()
        .append_pair("callback_url", &callback_url)
        .append_pair("code_challenge", &pkce.challenge)
        .append_pair("code_challenge_method", "S256");

    let (manual_tx, manual_rx) = mpsc::channel::<String>(1);
    let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel();
    inflight_map().insert(
        PROVIDER_ID.to_owned(),
        InFlight {
            verifier: pkce.verifier,
            callback_path,
            manual_tx,
            manual_rx: Mutex::new(Some(manual_rx)),
            cancel_tx: Mutex::new(Some(cancel_tx)),
            cancel_rx: Mutex::new(Some(cancel_rx)),
            listener: Mutex::new(Some(listener)),
        },
    );

    let authorize_url = authorize.to_string();
    let _ = webbrowser::open(&authorize_url);

    Ok(OAuthPending {
        provider_id: PROVIDER_ID.to_owned(),
        authorize_url,
        instructions:
            "Complete sign-in in your browser. If the browser is on another machine, paste the final redirect URL or authorization code."
                .into(),
    })
}

pub(super) fn submit_manual(provider_id: &str, input: String) -> Result<(), VendorLoginError> {
    let map = inflight_map();
    let Some(session) = map.get(provider_id) else {
        return Err(VendorLoginError::Probe("no in-flight OAuth login".into()));
    };
    session
        .manual_tx
        .try_send(input)
        .map_err(|_| VendorLoginError::Probe("OAuth login is no longer waiting".into()))?;
    Ok(())
}

pub(super) fn cancel(provider_id: &str) {
    let mut map = inflight_map();
    if let Some(session) = map.remove(provider_id)
        && let Ok(mut tx) = session.cancel_tx.lock()
        && let Some(tx) = tx.take()
    {
        let _ = tx.send(());
    }
}

pub(super) async fn wait_completion(provider_id: &str) -> Result<(), VendorLoginError> {
    if provider_id != PROVIDER_ID {
        return Err(VendorLoginError::UnknownProvider(provider_id.to_owned()));
    }

    let (verifier, callback_path, listener, mut manual_rx, mut cancel_rx) = {
        let map = inflight_map();
        let session = map
            .get(provider_id)
            .ok_or_else(|| VendorLoginError::Probe("no in-flight OAuth login".into()))?;
        let listener = session
            .listener
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .ok_or_else(|| VendorLoginError::Probe("OAuth callback already running".into()))?;
        let manual_rx = session
            .manual_rx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .ok_or_else(|| VendorLoginError::Probe("OAuth callback already running".into()))?;
        let cancel_rx = session
            .cancel_rx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .ok_or_else(|| VendorLoginError::Probe("OAuth callback already running".into()))?;
        (
            session.verifier.clone(),
            session.callback_path.clone(),
            listener,
            manual_rx,
            cancel_rx,
        )
    };

    let outcome = tokio::select! {
        biased;
        _ = &mut cancel_rx => Err(VendorLoginError::Probe("OAuth login cancelled".into())),
        _ = tokio::time::sleep(LOGIN_TIMEOUT) => {
            Err(VendorLoginError::Probe("OpenRouter OAuth login timed out".into()))
        }
        manual = manual_rx.recv() => {
            let Some(input) = manual else {
                return finish_err(provider_id, VendorLoginError::Probe("OAuth login cancelled".into()));
            };
            let Some(code) = parse_authorization_input(&input) else {
                return finish_err(provider_id, VendorLoginError::Probe("Missing authorization code".into()));
            };
            exchange_and_store(&verifier, &code).await
        }
        accepted = listener.accept() => {
            match accepted {
                Ok((mut stream, _)) => {
                    let req = read_http_request(&mut stream).await.unwrap_or_default();
                    match callback_code(&req, &callback_path) {
                        Ok(code) => {
                            match exchange_and_store(&verifier, &code).await {
                                Ok(()) => {
                                    let _ = write_html(
                                        &mut stream,
                                        200,
                                        success_html("Signed in to OpenRouter"),
                                    )
                                    .await;
                                    Ok(())
                                }
                                Err(e) => {
                                    let _ = write_html(
                                        &mut stream,
                                        502,
                                        error_html("OpenRouter key exchange failed.", &e.to_string()),
                                    ).await;
                                    Err(e)
                                }
                            }
                        }
                        Err(msg) => {
                            let _ = write_html(&mut stream, 400, error_html(&msg, "")).await;
                            Err(VendorLoginError::Probe(msg))
                        }
                    }
                }
                Err(e) => Err(VendorLoginError::Probe(format!("OAuth callback accept failed: {e}"))),
            }
        }
    };

    inflight_map().remove(provider_id);
    outcome
}

fn finish_err(provider_id: &str, err: VendorLoginError) -> Result<(), VendorLoginError> {
    inflight_map().remove(provider_id);
    Err(err)
}

async fn exchange_and_store(verifier: &str, code: &str) -> Result<(), VendorLoginError> {
    let access = exchange_authorization_code(code, verifier).await?;
    probe_api_key(PROVIDER_ID, &access).await?;
    let mut store = VendorAuthStore::default_store()?;
    store.set_oauth(PROVIDER_ID, access, None, Some(i64::MAX), None, None)?;
    Ok(())
}

async fn exchange_authorization_code(
    code: &str,
    verifier: &str,
) -> Result<String, VendorLoginError> {
    let client = reqwest::Client::builder()
        .timeout(TOKEN_TIMEOUT)
        .build()
        .map_err(|e| VendorLoginError::Probe(e.to_string()))?;
    let resp = client
        .post(TOKEN_URL)
        .header("accept", "application/json")
        .header("content-type", "application/json")
        .json(&serde_json::json!({
            "code": code,
            "code_verifier": verifier,
            "code_challenge_method": "S256",
        }))
        .send()
        .await
        .map_err(|e| VendorLoginError::Probe(format!("OpenRouter token exchange: {e}")))?;
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
    if !status.is_success() {
        let detail = body
            .get("error_description")
            .or_else(|| body.get("message"))
            .or_else(|| body.get("error"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        return Err(VendorLoginError::Probe(format!(
            "OpenRouter OAuth key exchange failed (HTTP {status}){extra}",
            extra = if detail.is_empty() {
                String::new()
            } else {
                format!(": {detail}")
            }
        )));
    }
    body.get("key")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            VendorLoginError::Probe("OpenRouter OAuth response carries no \"key\"".into())
        })
}

fn callback_code(request: &str, expected_path: &str) -> Result<String, String> {
    let first = request
        .lines()
        .next()
        .ok_or_else(|| "empty OAuth callback".to_string())?;
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    if method != "GET" {
        return Err("OAuth callback route not found.".into());
    }
    let url = reqwest::Url::parse(&format!("http://127.0.0.1{target}"))
        .map_err(|_| "OAuth callback route not found.".to_string())?;
    if url.path() != expected_path {
        return Err("OAuth callback route not found.".into());
    }
    if let Some(err) = url.query_pairs().find(|(k, _)| k == "error") {
        let desc = url
            .query_pairs()
            .find(|(k, _)| k == "error_description")
            .map(|(_, v)| v.into_owned())
            .unwrap_or_else(|| err.1.into_owned());
        return Err(format!("OpenRouter authorization failed: {desc}"));
    }
    url.query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.into_owned())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "OpenRouter returned no authorization code.".into())
}
