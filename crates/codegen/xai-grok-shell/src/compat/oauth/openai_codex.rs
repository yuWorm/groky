//! OpenAI Codex (ChatGPT Plus/Pro) PKCE — port of Pi `auth/oauth/openai-codex.ts`.
//!
//! Browser login on the Codex CLI public client. Tokens go to
//! `vendor-auth.json`. Device-code login is deferred.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use serde_json::Value;
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use super::callback::{error_html, read_http_request, success_html, write_html};
use super::pkce::generate_pkce;
use super::{OAuthPending, parse_authorization_input};
use crate::compat::auth_store::{VendorAuthStore, VendorCredential};
use crate::compat::probe::VendorLoginError;

pub(super) const PROVIDER_ID: &str = "openai-codex";
const CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
const AUTHORIZE_URL: &str = "https://auth.openai.com/oauth/authorize";
const TOKEN_URL: &str = "https://auth.openai.com/oauth/token";
const REDIRECT_URI: &str = "http://localhost:1455/auth/callback";
const CALLBACK_PATH: &str = "/auth/callback";
const BIND_ADDR: &str = "127.0.0.1:1455";
const SCOPE: &str = "openid profile email offline_access";
const ORIGINATOR: &str = "grok-build";
const JWT_AUTH_CLAIM: &str = "https://api.openai.com/auth";
const LOGIN_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const TOKEN_TIMEOUT: Duration = Duration::from_secs(30);
pub(super) const REFRESH_SKEW_SECS: i64 = 60;

struct InFlight {
    verifier: String,
    state: String,
    manual_tx: mpsc::Sender<String>,
    manual_rx: Mutex<Option<mpsc::Receiver<String>>>,
    cancel_tx: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    cancel_rx: Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
    listener: Mutex<Option<TcpListener>>,
}

static INFLIGHT: LazyLock<Mutex<HashMap<String, InFlight>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static REFRESH_LOCKS: LazyLock<Mutex<HashMap<String, Arc<Mutex<()>>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn inflight_map() -> std::sync::MutexGuard<'static, HashMap<String, InFlight>> {
    INFLIGHT.lock().unwrap_or_else(|e| e.into_inner())
}

fn refresh_lock(account_id: &str) -> Arc<Mutex<()>> {
    let mut locks = REFRESH_LOCKS.lock().unwrap_or_else(|e| e.into_inner());
    locks
        .entry(account_id.to_owned())
        .or_insert_with(|| Arc::new(Mutex::new(())))
        .clone()
}

pub(super) fn login_label() -> &'static str {
    "Sign in with ChatGPT Plus/Pro (Codex)"
}

pub(super) async fn begin() -> Result<OAuthPending, VendorLoginError> {
    cancel(PROVIDER_ID);

    let pkce = generate_pkce();
    let state = random_state();
    let listener = match TcpListener::bind(BIND_ADDR).await {
        Ok(listener) => Some(listener),
        Err(error) => {
            tracing::warn!(
                error = %error,
                "Codex OAuth port 1455 is busy; paste the redirect URL after sign-in"
            );
            None
        }
    };
    let listening = listener.is_some();

    let mut authorize =
        reqwest::Url::parse(AUTHORIZE_URL).map_err(|e| VendorLoginError::Probe(e.to_string()))?;
    authorize
        .query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", CLIENT_ID)
        .append_pair("redirect_uri", REDIRECT_URI)
        .append_pair("scope", SCOPE)
        .append_pair("code_challenge", &pkce.challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("state", &state)
        // OpenID Connect's standard `prompt=login` forces the browser to
        // offer authentication rather than silently reusing its current
        // session, allowing a user to select another ChatGPT account.
        .append_pair("prompt", "login")
        .append_pair("id_token_add_organizations", "true")
        .append_pair("codex_cli_simplified_flow", "true")
        .append_pair("originator", ORIGINATOR);

    let (manual_tx, manual_rx) = mpsc::channel::<String>(1);
    let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel();
    inflight_map().insert(
        PROVIDER_ID.to_owned(),
        InFlight {
            verifier: pkce.verifier,
            state,
            manual_tx,
            manual_rx: Mutex::new(Some(manual_rx)),
            cancel_tx: Mutex::new(Some(cancel_tx)),
            cancel_rx: Mutex::new(Some(cancel_rx)),
            listener: Mutex::new(listener),
        },
    );

    let authorize_url = authorize.to_string();
    let _ = webbrowser::open(&authorize_url);

    let instructions = if listening {
        "Complete ChatGPT sign-in in the browser. If it opened on another machine, paste the localhost:1455 redirect URL."
    } else {
        "Port 1455 is in use (often Codex CLI). Sign in in the browser, then paste the localhost:1455 redirect URL."
    };

    Ok(OAuthPending {
        provider_id: PROVIDER_ID.to_owned(),
        authorize_url,
        instructions: instructions.into(),
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

    let (verifier, expected_state, listener, mut manual_rx, mut cancel_rx) = {
        let map = inflight_map();
        let session = map
            .get(provider_id)
            .ok_or_else(|| VendorLoginError::Probe("no in-flight OAuth login".into()))?;
        let listener = session
            .listener
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
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
            session.state.clone(),
            listener,
            manual_rx,
            cancel_rx,
        )
    };

    let outcome = tokio::select! {
        biased;
        _ = &mut cancel_rx => Err(VendorLoginError::Probe("OAuth login cancelled".into())),
        _ = tokio::time::sleep(LOGIN_TIMEOUT) => {
            Err(VendorLoginError::Probe("ChatGPT Codex OAuth login timed out".into()))
        }
        manual = manual_rx.recv() => {
            let Some(input) = manual else {
                return finish_err(provider_id, VendorLoginError::Probe("OAuth login cancelled".into()));
            };
            match parse_codex_input(&input) {
                Ok((code, state)) => {
                    if let Some(state) = state
                        && state != expected_state
                    {
                        return finish_err(
                            provider_id,
                            VendorLoginError::Probe("OAuth state mismatch".into()),
                        );
                    }
                    exchange_and_store(&verifier, &code).await
                }
                Err(msg) => finish_err(provider_id, VendorLoginError::Probe(msg)),
            }
        }
        accepted = async {
            match listener.as_ref() {
                Some(listener) => Some(listener.accept().await),
                None => std::future::pending().await,
            }
        } => {
            match accepted {
                Some(Ok((mut stream, _))) => {
                    let req = read_http_request(&mut stream).await.unwrap_or_default();
                    match callback_code(&req, &expected_state) {
                        Ok(code) => {
                            match exchange_and_store(&verifier, &code).await {
                                Ok(()) => {
                                    let _ = write_html(
                                        &mut stream,
                                        200,
                                        success_html("Signed in to ChatGPT Codex"),
                                    )
                                    .await;
                                    Ok(())
                                }
                                Err(e) => {
                                    let _ = write_html(
                                        &mut stream,
                                        502,
                                        error_html("ChatGPT token exchange failed.", &e.to_string()),
                                    )
                                    .await;
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
                Some(Err(e)) => Err(VendorLoginError::Probe(format!("OAuth callback accept failed: {e}"))),
                None => Err(VendorLoginError::Probe("OAuth callback is not listening".into())),
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
    let token = exchange_authorization_code(code, verifier).await?;
    persist_token(token)
}

struct CodexToken {
    access: String,
    refresh: String,
    expires: i64,
    account_id: String,
}

async fn exchange_authorization_code(
    code: &str,
    verifier: &str,
) -> Result<CodexToken, VendorLoginError> {
    let client = reqwest::Client::builder()
        .timeout(TOKEN_TIMEOUT)
        .build()
        .map_err(|e| VendorLoginError::Probe(e.to_string()))?;
    let resp = client
        .post(TOKEN_URL)
        .form(&[
            ("grant_type", "authorization_code"),
            ("client_id", CLIENT_ID),
            ("code", code),
            ("code_verifier", verifier),
            ("redirect_uri", REDIRECT_URI),
        ])
        .send()
        .await
        .map_err(|e| VendorLoginError::Probe(format!("ChatGPT token exchange: {e}")))?;
    read_token_response(resp, "exchange").await
}

async fn read_token_response(
    resp: reqwest::Response,
    operation: &str,
) -> Result<CodexToken, VendorLoginError> {
    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or(Value::Null);
    if !status.is_success() {
        let detail = body
            .get("error_description")
            .or_else(|| body.get("error"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        return Err(VendorLoginError::Probe(format!(
            "ChatGPT Codex token {operation} failed (HTTP {status}){extra}",
            extra = if detail.is_empty() {
                String::new()
            } else {
                format!(": {detail}")
            }
        )));
    }
    token_from_json(&body, operation)
}

fn token_from_json(body: &Value, operation: &str) -> Result<CodexToken, VendorLoginError> {
    let access = body
        .get("access_token")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            VendorLoginError::Probe(format!(
                "ChatGPT Codex token {operation} response missing access_token"
            ))
        })?;
    let refresh = body
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            VendorLoginError::Probe(format!(
                "ChatGPT Codex token {operation} response missing refresh_token"
            ))
        })?;
    let expires_in = body
        .get("expires_in")
        .and_then(|v| v.as_i64().or_else(|| v.as_u64().map(|n| n as i64)))
        .unwrap_or(3600);
    let account_id = account_id_from_access(access).ok_or_else(|| {
        VendorLoginError::Probe("Failed to extract ChatGPT account id from token".into())
    })?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    Ok(CodexToken {
        access: access.to_owned(),
        refresh: refresh.to_owned(),
        expires: now.saturating_add(expires_in.max(0)),
        account_id,
    })
}

fn persist_token(token: CodexToken) -> Result<(), VendorLoginError> {
    let mut store = VendorAuthStore::default_store()?;
    store.set_oauth(
        PROVIDER_ID,
        token.access,
        Some(token.refresh),
        Some(token.expires),
        Some(token.account_id),
    )?;
    Ok(())
}

/// Refresh the selected Codex account only when its current snapshot is
/// expiring. A file lock is acquired only while persisting the result, never
/// while the token endpoint is contacted.
pub(super) fn refresh_if_needed(account_id: &str) -> Result<(), VendorLoginError> {
    let lock = refresh_lock(account_id);
    let _guard = lock.lock().unwrap_or_else(|e| e.into_inner());
    let mut store = VendorAuthStore::default_store()?;
    refresh_if_needed_in(&mut store, account_id)
}

fn refresh_if_needed_in(
    store: &mut VendorAuthStore,
    account_id: &str,
) -> Result<(), VendorLoginError> {
    let Some(credential) = store.account_credential(PROVIDER_ID, account_id).cloned() else {
        return Ok(());
    };
    if credential.kind != "oauth" || !credential.expires_soon(REFRESH_SKEW_SECS) {
        return Ok(());
    }
    let Some(refresh) = credential.refresh.as_deref().filter(|refresh| !refresh.trim().is_empty())
    else {
        return Err(VendorLoginError::Probe(
            "ChatGPT Codex session expired; run /provider-login openai-codex".into(),
        ));
    };
    let token = refresh_access_token_blocking(refresh)?;
    if token.account_id != account_id {
        return Err(VendorLoginError::Probe(
            "ChatGPT Codex refresh returned a different account".into(),
        ));
    }
    let replacement = VendorCredential::oauth_slot(
        token.access,
        Some(token.refresh),
        Some(token.expires),
        Some(token.account_id),
    );
    let _ = store.replace_account_credential_if_matches(
        PROVIDER_ID,
        account_id,
        &credential,
        replacement,
    )?;
    Ok(())
}

fn refresh_access_token_blocking(refresh: &str) -> Result<CodexToken, VendorLoginError> {
    let client = reqwest::blocking::Client::builder()
        .timeout(TOKEN_TIMEOUT)
        .build()
        .map_err(|e| VendorLoginError::Probe(e.to_string()))?;
    let resp = client
        .post(TOKEN_URL)
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh),
            ("client_id", CLIENT_ID),
        ])
        .send()
        .map_err(|e| VendorLoginError::Probe(format!("ChatGPT token refresh: {e}")))?;
    let status = resp.status();
    let body: Value = resp.json().unwrap_or(Value::Null);
    if !status.is_success() {
        let detail = body
            .get("error_description")
            .or_else(|| body.get("error"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        return Err(VendorLoginError::Probe(format!(
            "ChatGPT Codex token refresh failed (HTTP {status}){extra}",
            extra = if detail.is_empty() {
                String::new()
            } else {
                format!(": {detail}")
            }
        )));
    }
    token_from_json(&body, "refresh")
}

pub(super) fn inject_request_headers(
    credential: Option<&VendorCredential>,
    headers: &mut indexmap::IndexMap<String, String>,
) {
    // A session may have changed model/provider since this map was assembled.
    // Never let a header from an earlier Codex snapshot ride with this request.
    headers.shift_remove("chatgpt-account-id");
    if let Some(id) = credential
        .and_then(|credential| credential.account_id.as_deref())
        .filter(|id| !id.trim().is_empty())
    {
        headers.insert("chatgpt-account-id".into(), id.to_owned());
    }
    headers
        .entry("originator".into())
        .or_insert_with(|| ORIGINATOR.to_owned());
    headers
        .entry("OpenAI-Beta".into())
        .or_insert_with(|| "responses=experimental".into());
}

fn random_state() -> String {
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    bytes.iter().fold(String::new(), |mut out, b| {
        use std::fmt::Write;
        let _ = write!(&mut out, "{b:02x}");
        out
    })
}

fn parse_codex_input(input: &str) -> Result<(String, Option<String>), String> {
    let value = input.trim();
    if value.is_empty() {
        return Err("Missing authorization code".into());
    }
    if let Ok(url) = reqwest::Url::parse(value) {
        let code = url
            .query_pairs()
            .find(|(k, _)| k == "code")
            .map(|(_, v)| v.into_owned())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| "ChatGPT returned no authorization code.".to_string())?;
        let state = url
            .query_pairs()
            .find(|(k, _)| k == "state")
            .map(|(_, v)| v.into_owned());
        return Ok((code, state));
    }
    if let Some((code, state)) = value.split_once('#')
        && !code.is_empty()
    {
        return Ok((code.to_owned(), Some(state.to_owned())));
    }
    let code = parse_authorization_input(value).filter(|s| !s.is_empty());
    code.map(|c| (c, None))
        .ok_or_else(|| "Missing authorization code".into())
}

fn callback_code(request: &str, expected_state: &str) -> Result<String, String> {
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
    if url.path() != CALLBACK_PATH {
        return Err("OAuth callback route not found.".into());
    }
    if let Some(err) = url.query_pairs().find(|(k, _)| k == "error") {
        let desc = url
            .query_pairs()
            .find(|(k, _)| k == "error_description")
            .map(|(_, v)| v.into_owned())
            .unwrap_or_else(|| err.1.into_owned());
        return Err(format!("ChatGPT authorization failed: {desc}"));
    }
    if let Some(state) = url
        .query_pairs()
        .find(|(k, _)| k == "state")
        .map(|(_, v)| v.into_owned())
        && state != expected_state
    {
        return Err("OAuth state mismatch".into());
    }
    url.query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.into_owned())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "ChatGPT returned no authorization code.".into())
}

fn decode_jwt_segment(segment: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(segment).ok().or_else(|| {
        let mut padded = segment.replace('-', "+").replace('_', "/");
        while padded.len() % 4 != 0 {
            padded.push('=');
        }
        base64::engine::general_purpose::STANDARD
            .decode(padded)
            .ok()
    })
}

pub(super) fn account_id_from_access(access: &str) -> Option<String> {
    let payload = access.split('.').nth(1)?;
    let bytes = decode_jwt_segment(payload)?;
    let json: Value = serde_json::from_slice(&bytes).ok()?;
    json.get(JWT_AUTH_CLAIM)?
        .get("chatgpt_account_id")?
        .as_str()
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::{account_id_from_access, inject_request_headers, parse_codex_input};
    use crate::compat::auth_store::VendorCredential;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    fn jwt_with_account(account: &str) -> String {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
        let payload = URL_SAFE_NO_PAD.encode(
            format!(r#"{{"https://api.openai.com/auth":{{"chatgpt_account_id":"{account}"}}}}"#)
                .as_bytes(),
        );
        format!("{header}.{payload}.sig")
    }

    #[test]
    fn extracts_chatgpt_account_id() {
        let token = jwt_with_account("acct-99");
        assert_eq!(account_id_from_access(&token).as_deref(), Some("acct-99"));
        assert!(account_id_from_access("not-a-jwt").is_none());
    }

    #[test]
    fn parses_redirect_and_hash_code() {
        let (code, state) =
            parse_codex_input("http://localhost:1455/auth/callback?code=abc&state=st").unwrap();
        assert_eq!(code, "abc");
        assert_eq!(state.as_deref(), Some("st"));
        let (code, state) = parse_codex_input("rawcode#st2").unwrap();
        assert_eq!(code, "rawcode");
        assert_eq!(state.as_deref(), Some("st2"));
    }

    #[test]
    fn account_header_uses_the_supplied_credential_snapshot() {
        let mut headers = indexmap::IndexMap::new();
        headers.insert("chatgpt-account-id".into(), "stale-account".into());
        inject_request_headers(None, &mut headers);
        assert!(!headers.contains_key("chatgpt-account-id"));

        let credential = VendorCredential::oauth_slot(
            "token".into(),
            Some("refresh".into()),
            Some(i64::MAX),
            Some("acct-42".into()),
        );
        inject_request_headers(Some(&credential), &mut headers);
        assert_eq!(headers["chatgpt-account-id"], "acct-42");
    }
}
