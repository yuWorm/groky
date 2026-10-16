//! Account-scoped provider quota compatibility.
//!
//! This module deliberately treats every saved credential slot as an independent
//! account. It never selects a provider default while fetching a row, and every
//! completed report carries opaque snapshots so a late network response cannot
//! be displayed after its account or provider configuration changed.

use std::sync::LazyLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::StreamExt;
use serde_json::Value;

use super::auth_store::{VendorAccountInfo, VendorAuthStore, VendorCredential};
use super::custom::{CustomPlatform, CustomProviderStore};
use super::oauth;

const CODEX_PROVIDER_ID: &str = "openai-codex";
const CLAUDE_PROVIDER_ID: &str = "anthropic-claude";
const CODEX_USAGE_URL: &str = "https://chatgpt.com/backend-api/wham/usage";
const CLAUDE_USAGE_URL: &str = "https://claude.ai/settings/usage";
const USAGE_TIMEOUT: Duration = Duration::from_secs(12);
const USAGE_BODY_LIMIT: usize = 1024 * 1024;
const ONE_API_UNLIMITED_SENTINEL: f64 = 100_000_000.0;

static USAGE_NETWORK_CONCURRENCY: LazyLock<tokio::sync::Semaphore> =
    LazyLock::new(|| tokio::sync::Semaphore::new(4));

/// A saved credential slot whose provider may expose usage information.
///
/// Credential material is intentionally absent: this type is safe to retain in
/// UI state or display in diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VendorUsageTarget {
    pub provider_id: String,
    pub account_id: String,
    pub provider_name: String,
    pub account_label: String,
    pub is_default: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VendorUsageStatus {
    Available,
    Unavailable,
    NeedsLogin,
    Unsupported,
}

/// One provider-reported usage quantity or usage window.
///
/// Amounts are deliberately optional. Missing data is unknown, never zero.
#[derive(Debug, Clone)]
pub struct VendorUsageLimit {
    pub label: String,
    pub scope: String,
    pub used: Option<f64>,
    pub limit: Option<f64>,
    pub remaining: Option<f64>,
    pub unit: String,
    pub used_percent: Option<f64>,
    pub resets_at: Option<i64>,
    pub expires_at: Option<i64>,
    pub unlimited: bool,
}

impl Default for VendorUsageLimit {
    fn default() -> Self {
        Self {
            label: String::new(),
            scope: String::new(),
            used: None,
            limit: None,
            remaining: None,
            unit: String::new(),
            used_percent: None,
            resets_at: None,
            expires_at: None,
            unlimited: false,
        }
    }
}

/// A point-in-time, account-scoped usage result.
///
/// The private fingerprints are hashes only. They allow callers to reject a
/// result that completed after credentials, account membership, or provider
/// configuration changed without retaining raw credential material.
#[derive(Debug, Clone)]
pub struct VendorUsageReport {
    pub target: VendorUsageTarget,
    pub status: VendorUsageStatus,
    pub checked_at: u64,
    pub limits: Vec<VendorUsageLimit>,
    pub notes: Vec<String>,
    pub manage_url: Option<String>,
    credential_fingerprint: Option<String>,
    provider_fingerprint: Option<String>,
}

#[derive(Clone)]
enum UsageKind {
    Codex,
    Claude,
    Generic,
    InvalidConfiguration,
    Sub2Api { service_root: String },
    NewApi { service_root: String },
    OneApi { service_root: String },
}

struct TargetContext {
    kind: UsageKind,
    credential_fingerprint: Option<String>,
    provider_fingerprint: String,
}

enum ContextLookup {
    Found(TargetContext),
    Missing,
    InvalidConfiguration,
}

#[derive(Debug, Clone, Copy)]
enum FetchError {
    Authentication,
    RateLimited,
    Http(u16),
    Network,
    TooLarge,
    InvalidJson,
    InvalidResponse,
}

struct ParsedUsage {
    limits: Vec<VendorUsageLimit>,
    notes: Vec<String>,
}

struct NewApiDisplay {
    unit: String,
    divisor: Option<f64>,
    multiplier: f64,
}

impl Default for NewApiDisplay {
    fn default() -> Self {
        Self {
            unit: "quota".into(),
            divisor: None,
            multiplier: 1.0,
        }
    }
}

/// List every saved account independently. Custom providers remain distinct
/// even when they share an endpoint, because the credential slot is the usage
/// authority rather than a host name.
pub fn usage_targets() -> Result<Vec<VendorUsageTarget>, String> {
    let auth = VendorAuthStore::default_store()
        .map_err(|_| "Could not read saved provider accounts.".to_owned())?;
    let custom = CustomProviderStore::default_store()
        .map_err(|_| "Could not read configured providers.".to_owned())?;

    let mut targets = Vec::new();
    append_targets(
        &mut targets,
        CODEX_PROVIDER_ID,
        "OpenAI Codex (ChatGPT)",
        auth.accounts(CODEX_PROVIDER_ID),
    );
    append_targets(
        &mut targets,
        CLAUDE_PROVIDER_ID,
        "Claude Pro/Max",
        auth.accounts(CLAUDE_PROVIDER_ID),
    );
    for provider in custom.list() {
        append_targets(
            &mut targets,
            &provider.id,
            &provider.name,
            auth.accounts(&provider.id),
        );
    }
    Ok(targets)
}

/// Fetch usage for exactly `target.account_id`.
///
/// The explicit account id is passed into `request_credential`; it is never
/// replaced by a provider default if the requested slot disappeared. Claude
/// and generic providers intentionally make no usage request.
pub async fn fetch_vendor_usage(target: VendorUsageTarget) -> VendorUsageReport {
    let initial = match load_context(target.clone()).await {
        Ok(ContextLookup::Found(context)) => context,
        Ok(ContextLookup::Missing) => {
            return report(
                target,
                VendorUsageStatus::Unavailable,
                Vec::new(),
                vec!["This saved account is no longer configured. Refresh provider quotas.".into()],
                None,
                None,
            );
        }
        Ok(ContextLookup::InvalidConfiguration) => {
            return report(
                target,
                VendorUsageStatus::Unavailable,
                Vec::new(),
                vec!["This provider's usage configuration is invalid. Edit the provider and try again.".into()],
                None,
                None,
            );
        }
        Err(()) => {
            return report(
                target,
                VendorUsageStatus::Unavailable,
                Vec::new(),
                vec!["Could not read the saved provider configuration.".into()],
                None,
                None,
            );
        }
    };

    match &initial.kind {
        UsageKind::Claude => {
            return report(
                target,
                VendorUsageStatus::Unsupported,
                Vec::new(),
                vec![
                    "Claude subscription quota lookup is not supported here. Open Claude Settings → Usage."
                        .into(),
                ],
                Some(CLAUDE_USAGE_URL.into()),
                Some(&initial),
            );
        }
        UsageKind::Generic => {
            return report(
                target,
                VendorUsageStatus::Unsupported,
                Vec::new(),
                vec!["This provider does not publish a compatible quota endpoint.".into()],
                None,
                Some(&initial),
            );
        }
        UsageKind::InvalidConfiguration => {
            return report(
                target,
                VendorUsageStatus::Unavailable,
                Vec::new(),
                vec!["This provider's usage configuration is invalid. Edit the provider and try again.".into()],
                None,
                Some(&initial),
            );
        }

        UsageKind::Codex
        | UsageKind::Sub2Api { .. }
        | UsageKind::NewApi { .. }
        | UsageKind::OneApi { .. } => {}
    }

    let _network_permit = match USAGE_NETWORK_CONCURRENCY.acquire().await {
        Ok(permit) => permit,
        Err(_) => {
            return report(
                target,
                VendorUsageStatus::Unavailable,
                Vec::new(),
                vec!["The usage request could not be scheduled. Try again shortly.".into()],
                None,
                Some(&initial),
            );
        }
    };

    let credential = match resolve_exact_credential(&target).await {
        Ok(Some(credential)) => credential,
        Ok(None) => {
            return report(
                target,
                VendorUsageStatus::NeedsLogin,
                Vec::new(),
                vec!["This saved account needs a valid provider credential. Sign in again and refresh.".into()],
                None,
                Some(&initial),
            );
        }
        Err(()) => {
            return report(
                target,
                VendorUsageStatus::NeedsLogin,
                Vec::new(),
                vec!["This saved account could not refresh its credential. Sign in again and refresh.".into()],
                None,
                Some(&initial),
            );
        }
    };
    let Some(secret) = credential.request_secret() else {
        return report(
            target,
            VendorUsageStatus::NeedsLogin,
            Vec::new(),
            vec![
                "This saved account needs a valid provider credential. Sign in again and refresh."
                    .into(),
            ],
            None,
            Some(&initial),
        );
    };

    let mut context = initial;
    // request_credential may have refreshed this exact slot. Use the refreshed
    // snapshot, not the snapshot observed before the blocking request.
    context.credential_fingerprint = Some(credential_fingerprint(&credential));
    // A provider edit may have happened while this query waited for a permit or
    // refreshed OAuth. Never combine a new key with the old provider endpoint.
    let still_current = matches!(load_context(target.clone()).await,
        Ok(ContextLookup::Found(current))
            if current.provider_fingerprint == context.provider_fingerprint
                && current.credential_fingerprint == context.credential_fingerprint);
    if !still_current {
        return report(
            target,
            VendorUsageStatus::Unavailable,
            Vec::new(),
            vec![
                "Account or provider changed before the query started. Refresh provider quotas."
                    .into(),
            ],
            None,
            Some(&context),
        );
    }

    let client = match usage_client() {
        Ok(client) => client,
        Err(()) => {
            return report(
                target,
                VendorUsageStatus::Unavailable,
                Vec::new(),
                vec!["Could not start the usage request.".into()],
                None,
                Some(&context),
            );
        }
    };

    let fetched = match &context.kind {
        UsageKind::Codex => fetch_codex_usage(&client, &target, &credential, secret).await,
        UsageKind::Sub2Api { service_root } => {
            fetch_sub2api_usage(&client, service_root, secret).await
        }
        UsageKind::NewApi { service_root } => {
            fetch_newapi_usage(&client, service_root, secret).await
        }
        UsageKind::OneApi { service_root } => {
            fetch_oneapi_usage(&client, service_root, secret).await
        }
        UsageKind::Claude | UsageKind::Generic | UsageKind::InvalidConfiguration => {
            unreachable!("non-network kinds returned early")
        }
    };

    match fetched {
        Ok(parsed) => report(
            target,
            VendorUsageStatus::Available,
            parsed.limits,
            parsed.notes,
            None,
            Some(&context),
        ),
        Err(error) => report_from_fetch_error(target, error, &context),
    }
}

/// Return whether the exact saved account and usage-provider configuration that
/// produced `report` still exist. This is intentionally fail-closed: a store
/// read failure or a changed/deleted account makes a late result stale.
pub fn report_is_current(report: &VendorUsageReport) -> bool {
    context_from_default(&report.target)
        .is_ok_and(|current| report_matches_context(report, current))
}

fn report_matches_context(report: &VendorUsageReport, current: ContextLookup) -> bool {
    match current {
        ContextLookup::Found(current) => {
            current.credential_fingerprint == report.credential_fingerprint
                && Some(current.provider_fingerprint.as_str())
                    == report.provider_fingerprint.as_deref()
        }
        ContextLookup::Missing | ContextLookup::InvalidConfiguration => false,
    }
}

fn append_targets(
    out: &mut Vec<VendorUsageTarget>,
    provider_id: &str,
    provider_name: &str,
    accounts: Vec<VendorAccountInfo>,
) {
    out.extend(accounts.into_iter().map(|account| VendorUsageTarget {
        provider_id: provider_id.to_owned(),
        account_label: if account.label.trim().is_empty() {
            account.id.clone()
        } else {
            account.label
        },
        account_id: account.id,
        provider_name: provider_name.to_owned(),
        is_default: account.is_default,
    }));
}

async fn load_context(target: VendorUsageTarget) -> Result<ContextLookup, ()> {
    tokio::task::spawn_blocking(move || context_from_default(&target))
        .await
        .map_err(|_| ())?
}

async fn resolve_exact_credential(
    target: &VendorUsageTarget,
) -> Result<Option<VendorCredential>, ()> {
    let provider_id = target.provider_id.clone();
    let account_id = target.account_id.clone();
    tokio::task::spawn_blocking(move || {
        oauth::request_credential(&provider_id, Some(&account_id)).map_err(|_| ())
    })
    .await
    .map_err(|_| ())?
}

fn context_from_default(target: &VendorUsageTarget) -> Result<ContextLookup, ()> {
    let auth = VendorAuthStore::default_store().map_err(|_| ())?;
    match target.provider_id.as_str() {
        CODEX_PROVIDER_ID | CLAUDE_PROVIDER_ID => Ok(context_from_stores(target, &auth, None)),
        _ => {
            let custom = CustomProviderStore::default_store().map_err(|_| ())?;
            Ok(context_from_stores(target, &auth, Some(&custom)))
        }
    }
}

fn context_from_stores(
    target: &VendorUsageTarget,
    auth: &VendorAuthStore,
    custom: Option<&CustomProviderStore>,
) -> ContextLookup {
    let Some(credential) = auth.account_credential(&target.provider_id, &target.account_id) else {
        return ContextLookup::Missing;
    };
    let credential_fingerprint = Some(credential_fingerprint(credential));

    match target.provider_id.as_str() {
        CODEX_PROVIDER_ID => ContextLookup::Found(TargetContext {
            kind: UsageKind::Codex,
            credential_fingerprint,
            provider_fingerprint: fingerprint("built-in:openai-codex".as_bytes()),
        }),
        CLAUDE_PROVIDER_ID => ContextLookup::Found(TargetContext {
            kind: UsageKind::Claude,
            credential_fingerprint,
            provider_fingerprint: fingerprint("built-in:anthropic-claude".as_bytes()),
        }),
        _ => {
            let Some(provider) = custom.and_then(|store| store.get(&target.provider_id)) else {
                return ContextLookup::Missing;
            };
            let provider_fingerprint = match serde_json::to_vec(provider) {
                Ok(encoded) => fingerprint(&encoded),
                Err(_) => return ContextLookup::InvalidConfiguration,
            };
            let kind = match provider.platform {
                CustomPlatform::Generic => UsageKind::Generic,
                CustomPlatform::Sub2Api => provider
                    .usage_service_root()
                    .map(|service_root| UsageKind::Sub2Api { service_root })
                    .unwrap_or(UsageKind::InvalidConfiguration),
                CustomPlatform::NewApi => provider
                    .usage_service_root()
                    .map(|service_root| UsageKind::NewApi { service_root })
                    .unwrap_or(UsageKind::InvalidConfiguration),
                CustomPlatform::OneApi => provider
                    .usage_service_root()
                    .map(|service_root| UsageKind::OneApi { service_root })
                    .unwrap_or(UsageKind::InvalidConfiguration),
            };
            ContextLookup::Found(TargetContext {
                kind,
                credential_fingerprint,
                provider_fingerprint,
            })
        }
    }
}

fn report(
    target: VendorUsageTarget,
    status: VendorUsageStatus,
    limits: Vec<VendorUsageLimit>,
    notes: Vec<String>,
    manage_url: Option<String>,
    context: Option<&TargetContext>,
) -> VendorUsageReport {
    VendorUsageReport {
        target,
        status,
        checked_at: now_unix(),
        limits,
        notes,
        manage_url,
        credential_fingerprint: context.and_then(|context| context.credential_fingerprint.clone()),
        provider_fingerprint: context.map(|context| context.provider_fingerprint.clone()),
    }
}

fn report_from_fetch_error(
    target: VendorUsageTarget,
    error: FetchError,
    context: &TargetContext,
) -> VendorUsageReport {
    let (status, note) = match error {
        FetchError::Authentication => (
            VendorUsageStatus::NeedsLogin,
            "The provider rejected this account's credential. Sign in again and refresh.".into(),
        ),
        FetchError::RateLimited => (
            VendorUsageStatus::Unavailable,
            "The usage service is rate-limiting requests. Quota state is unknown; try again later."
                .into(),
        ),
        FetchError::Http(code) => (
            VendorUsageStatus::Unavailable,
            format!("The usage service returned HTTP {code}."),
        ),
        FetchError::Network => (
            VendorUsageStatus::Unavailable,
            "Could not reach the usage service. Check the provider endpoint and try again.".into(),
        ),
        FetchError::TooLarge => (
            VendorUsageStatus::Unavailable,
            "The usage service returned an unexpectedly large response.".into(),
        ),
        FetchError::InvalidJson | FetchError::InvalidResponse => (
            VendorUsageStatus::Unavailable,
            "The usage service returned an unrecognized response.".into(),
        ),
    };
    report(target, status, Vec::new(), vec![note], None, Some(context))
}

fn usage_client() -> Result<reqwest::Client, ()> {
    reqwest::Client::builder()
        .timeout(USAGE_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| ())
}

async fn fetch_codex_usage(
    client: &reqwest::Client,
    target: &VendorUsageTarget,
    credential: &VendorCredential,
    secret: &str,
) -> Result<ParsedUsage, FetchError> {
    // Production Codex usage always uses this fixed ChatGPT origin. The
    // endpoint parameter on the private helper below exists solely for the
    // deterministic local-server regression test.
    let url = reqwest::Url::parse(CODEX_USAGE_URL).map_err(|_| FetchError::InvalidResponse)?;
    fetch_codex_usage_at(client, url, target, credential, secret).await
}

async fn fetch_codex_usage_at(
    client: &reqwest::Client,
    url: reqwest::Url,
    target: &VendorUsageTarget,
    credential: &VendorCredential,
    secret: &str,
) -> Result<ParsedUsage, FetchError> {
    if credential.kind != "oauth"
        || credential
            .account_id
            .as_deref()
            .filter(|account_id| *account_id == target.account_id.as_str())
            .is_none()
    {
        return Err(FetchError::Authentication);
    }

    let response = client
        .get(url)
        .bearer_auth(secret.trim())
        .header("chatgpt-account-id", &target.account_id)
        .header("originator", "grok-build")
        .send()
        .await
        .map_err(|_| FetchError::Network)?;
    let body = read_json_response(response).await?;
    if body
        .get("account_id")
        .and_then(Value::as_str)
        .is_some_and(|account_id| {
            !account_id.trim().is_empty() && account_id != target.account_id.as_str()
        })
    {
        return Err(FetchError::InvalidResponse);
    }
    let mut parsed = parse_codex_usage(&body, now_unix() as i64)?;
    parsed.notes.push(
        "ChatGPT quota data uses an internal compatibility endpoint and may change without notice."
            .into(),
    );
    Ok(parsed)
}

async fn fetch_sub2api_usage(
    client: &reqwest::Client,
    service_root: &str,
    secret: &str,
) -> Result<ParsedUsage, FetchError> {
    let url = usage_endpoint(service_root, "v1/usage").map_err(|_| FetchError::InvalidResponse)?;
    let body = fetch_json(client, url, Some(secret)).await?;
    parse_sub2api_usage(&body)
}

async fn fetch_newapi_usage(
    client: &reqwest::Client,
    service_root: &str,
    secret: &str,
) -> Result<ParsedUsage, FetchError> {
    let usage_url = usage_endpoint(service_root, "api/usage/token/")
        .map_err(|_| FetchError::InvalidResponse)?;
    let body = fetch_json(client, usage_url, Some(secret)).await?;

    // Display metadata is public and optional. An unavailable or invalid status
    // document must not erase a successful, account-scoped token response.
    let display = match usage_endpoint(service_root, "api/status") {
        Ok(status_url) => match fetch_json(client, status_url, None).await {
            Ok(status) => newapi_display_from_status(&status),
            Err(_) => NewApiDisplay::default(),
        },
        Err(_) => NewApiDisplay::default(),
    };
    parse_newapi_usage(&body, &display)
}

async fn fetch_oneapi_usage(
    client: &reqwest::Client,
    service_root: &str,
    secret: &str,
) -> Result<ParsedUsage, FetchError> {
    let subscription_url = usage_endpoint(service_root, "v1/dashboard/billing/subscription")
        .map_err(|_| FetchError::InvalidResponse)?;
    let usage_url = usage_endpoint(service_root, "v1/dashboard/billing/usage")
        .map_err(|_| FetchError::InvalidResponse)?;
    let subscription = fetch_json(client, subscription_url, Some(secret)).await?;
    let usage = fetch_json(client, usage_url, Some(secret)).await?;

    let unit = match usage_endpoint(service_root, "api/status") {
        Ok(status_url) => match fetch_json(client, status_url, None).await {
            Ok(status) => oneapi_unit_from_status(&status),
            Err(_) => "gateway-reported units".into(),
        },
        Err(_) => "gateway-reported units".into(),
    };
    parse_oneapi_usage(&subscription, &usage, &unit)
}

fn usage_endpoint(service_root: &str, endpoint: &str) -> Result<reqwest::Url, ()> {
    let root = service_root.trim().trim_end_matches('/');
    if root.is_empty() {
        return Err(());
    }
    let url = reqwest::Url::parse(&format!("{root}/{}", endpoint.trim_start_matches('/')))
        .map_err(|_| ())?;
    if !matches!(url.scheme(), "http" | "https") || url.username() != "" || url.password().is_some()
    {
        return Err(());
    }
    Ok(url)
}

async fn fetch_json(
    client: &reqwest::Client,
    url: reqwest::Url,
    bearer: Option<&str>,
) -> Result<Value, FetchError> {
    let mut request = client.get(url);
    if let Some(secret) = bearer {
        request = request.bearer_auth(secret.trim());
    }
    let response = request.send().await.map_err(|_| FetchError::Network)?;
    read_json_response(response).await
}

async fn read_json_response(response: reqwest::Response) -> Result<Value, FetchError> {
    let status = response.status();
    if !status.is_success() {
        return Err(match status.as_u16() {
            401 | 403 => FetchError::Authentication,
            429 => FetchError::RateLimited,
            code => FetchError::Http(code),
        });
    }
    if response
        .content_length()
        .is_some_and(|length| length > USAGE_BODY_LIMIT as u64)
    {
        return Err(FetchError::TooLarge);
    }
    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| FetchError::Network)?;
        if bytes.len().saturating_add(chunk.len()) > USAGE_BODY_LIMIT {
            return Err(FetchError::TooLarge);
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| FetchError::InvalidJson)
}

fn parse_codex_usage(value: &Value, checked_at: i64) -> Result<ParsedUsage, FetchError> {
    let root = value.as_object().ok_or(FetchError::InvalidResponse)?;
    let mut limits = Vec::new();
    let mut notes = Vec::new();
    let mut recognized = false;

    if let Some(rate_limit) = root.get("rate_limit").and_then(Value::as_object) {
        recognized = true;
        add_codex_rate_limit(&mut limits, &mut notes, rate_limit, None, checked_at);
    }

    if let Some(additional) = root.get("additional_rate_limits").and_then(Value::as_array) {
        for entry in additional {
            let Some(entry) = entry.as_object() else {
                continue;
            };
            let Some(rate_limit) = entry.get("rate_limit").and_then(Value::as_object) else {
                continue;
            };
            recognized = true;
            let name = entry
                .get("limit_name")
                .and_then(Value::as_str)
                .filter(|name| !name.trim().is_empty())
                .or_else(|| {
                    entry
                        .get("metered_feature")
                        .and_then(Value::as_str)
                        .filter(|name| !name.trim().is_empty())
                })
                .unwrap_or("Additional limit");
            add_codex_rate_limit(&mut limits, &mut notes, rate_limit, Some(name), checked_at);
        }
    }

    add_codex_credits(&mut limits, root);
    if !recognized {
        return Err(FetchError::InvalidResponse);
    }
    if limits.is_empty() {
        notes.push("The service returned no quota windows for this account.".into());
    }
    Ok(ParsedUsage { limits, notes })
}

fn add_codex_rate_limit(
    limits: &mut Vec<VendorUsageLimit>,
    notes: &mut Vec<String>,
    rate_limit: &serde_json::Map<String, Value>,
    prefix: Option<&str>,
    checked_at: i64,
) {
    for (field, title) in [
        ("primary_window", "Primary window"),
        ("secondary_window", "Secondary window"),
    ] {
        let Some(window) = rate_limit.get(field).and_then(Value::as_object) else {
            continue;
        };
        let used_percent = number_field(window, "used_percent");
        let duration = number_field(window, "limit_window_seconds");
        let reset_at = integer_field(window, "reset_at").or_else(|| {
            integer_field(window, "reset_after_seconds")
                .filter(|seconds| *seconds >= 0)
                .map(|seconds| checked_at.saturating_add(seconds))
        });
        if used_percent.is_none() && duration.is_none() && reset_at.is_none() {
            continue;
        }
        let label = match (prefix, duration) {
            (Some(prefix), Some(seconds)) => format!("{prefix} · {title} ({seconds} s)"),
            (Some(prefix), None) => format!("{prefix} · {title}"),
            (None, Some(seconds)) => format!("{title} ({seconds} s)"),
            (None, None) => title.into(),
        };
        let remaining = used_percent
            .filter(|value| (0.0..=100.0).contains(value))
            .map(|value| 100.0 - value);
        limits.push(VendorUsageLimit {
            label,
            scope: "subscription".into(),
            used: used_percent,
            limit: used_percent.map(|_| 100.0),
            remaining,
            unit: "%".into(),
            used_percent,
            resets_at: reset_at,
            ..VendorUsageLimit::default()
        });
    }

    if rate_limit.get("limit_reached").and_then(Value::as_bool) == Some(true) {
        notes.push(match prefix {
            Some(prefix) => format!("{prefix} is currently reported as reached."),
            None => "A Codex quota limit is currently reported as reached.".into(),
        });
    } else if rate_limit.get("allowed").and_then(Value::as_bool) == Some(false) {
        notes.push(match prefix {
            Some(prefix) => format!("{prefix} is not currently allowed by the service."),
            None => "Codex included usage is not currently allowed by the service.".into(),
        });
    }
}

fn add_codex_credits(limits: &mut Vec<VendorUsageLimit>, root: &serde_json::Map<String, Value>) {
    let credits = root.get("credits").and_then(Value::as_object).or_else(|| {
        root.get("rate_limit_reset_credits")
            .and_then(Value::as_object)
    });
    let Some(credits) = credits else {
        return;
    };
    let remaining =
        number_field(credits, "balance").or_else(|| number_field(credits, "available_count"));
    let unlimited = credits
        .get("unlimited")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if remaining.is_none() && !unlimited {
        return;
    }
    limits.push(VendorUsageLimit {
        label: "Credits".into(),
        scope: "subscription".into(),
        remaining: (!unlimited).then_some(remaining).flatten(),
        unit: "credits".into(),
        unlimited,
        ..VendorUsageLimit::default()
    });
}

fn parse_sub2api_usage(value: &Value) -> Result<ParsedUsage, FetchError> {
    let root = value.as_object().ok_or(FetchError::InvalidResponse)?;
    let mode = root
        .get("mode")
        .and_then(Value::as_str)
        .ok_or(FetchError::InvalidResponse)?;
    let unit = string_field(root, "unit").unwrap_or_else(|| "USD".into());
    let mut limits = Vec::new();
    let mut notes =
        vec!["Amounts are Sub2API gateway accounting, not upstream provider token quotas.".into()];

    if root.get("isValid").and_then(Value::as_bool) == Some(false) {
        notes.push("The gateway reports that this key is not currently usable.".into());
    }

    match mode {
        "quota_limited" => {
            if let Some(quota) = root.get("quota").and_then(Value::as_object) {
                let raw_limit = number_field(quota, "limit");
                let unlimited = raw_limit == Some(-1.0);
                let limit = raw_limit.filter(|value| *value > 0.0);
                let row = VendorUsageLimit {
                    label: "Key quota".into(),
                    scope: "key".into(),
                    used: number_field(quota, "used"),
                    limit,
                    remaining: (!unlimited)
                        .then_some(number_field(quota, "remaining"))
                        .flatten(),
                    unit: string_field(quota, "unit").unwrap_or_else(|| unit.clone()),
                    expires_at: timestamp_field(root, "expires_at"),
                    unlimited,
                    ..VendorUsageLimit::default()
                };
                if row.used.is_some()
                    || row.limit.is_some()
                    || row.remaining.is_some()
                    || row.unlimited
                {
                    limits.push(row);
                }
            }
            if let Some(rate_limits) = root.get("rate_limits").and_then(Value::as_array) {
                for rate_limit in rate_limits {
                    let Some(rate_limit) = rate_limit.as_object() else {
                        continue;
                    };
                    let raw_limit = number_field(rate_limit, "limit");
                    // Sub2API uses zero to mean an unconfigured/unlimited key
                    // rate limit. A zero quota object is not given that meaning.
                    let unlimited = raw_limit.is_some_and(|value| value <= 0.0);
                    let label = string_field(rate_limit, "window")
                        .map(|window| format!("Key rate limit ({window})"))
                        .unwrap_or_else(|| "Key rate limit".into());
                    let row = VendorUsageLimit {
                        label,
                        scope: "key".into(),
                        used: number_field(rate_limit, "used"),
                        limit: (!unlimited).then_some(raw_limit).flatten(),
                        remaining: (!unlimited)
                            .then_some(number_field(rate_limit, "remaining"))
                            .flatten(),
                        unit: string_field(rate_limit, "unit").unwrap_or_else(|| unit.clone()),
                        resets_at: timestamp_field(rate_limit, "reset_at"),
                        expires_at: timestamp_field(root, "expires_at"),
                        unlimited,
                        ..VendorUsageLimit::default()
                    };
                    if row.used.is_some()
                        || row.limit.is_some()
                        || row.remaining.is_some()
                        || row.unlimited
                    {
                        limits.push(row);
                    }
                }
            }
        }
        "unrestricted" => {
            if let Some(subscription) = root.get("subscription").and_then(Value::as_object) {
                for (label, usage_key, limit_key) in [
                    ("Daily subscription", "daily_usage_usd", "daily_limit_usd"),
                    (
                        "Weekly subscription",
                        "weekly_usage_usd",
                        "weekly_limit_usd",
                    ),
                    (
                        "Monthly subscription",
                        "monthly_usage_usd",
                        "monthly_limit_usd",
                    ),
                ] {
                    let used = number_field(subscription, usage_key);
                    let raw_limit = number_field(subscription, limit_key);
                    let unlimited = raw_limit.is_some_and(|value| value <= 0.0);
                    let limit = (!unlimited).then_some(raw_limit).flatten();
                    let remaining = match (used, limit) {
                        (Some(used), Some(limit)) => Some((limit - used).max(0.0)),
                        _ => None,
                    };
                    if used.is_some() || limit.is_some() || unlimited {
                        limits.push(VendorUsageLimit {
                            label: label.into(),
                            scope: "subscription".into(),
                            used,
                            limit,
                            remaining,
                            unit: unit.clone(),
                            expires_at: timestamp_field(subscription, "expires_at"),
                            unlimited,
                            ..VendorUsageLimit::default()
                        });
                    }
                }
            }
            if let Some(balance) = number_field(root, "balance") {
                limits.push(VendorUsageLimit {
                    label: "Wallet balance".into(),
                    scope: "account".into(),
                    remaining: Some(balance),
                    unit: unit.clone(),
                    ..VendorUsageLimit::default()
                });
            }
            if root.get("balance").is_none()
                && let Some(remaining) = number_field(root, "remaining")
            {
                limits.push(VendorUsageLimit {
                    label: "Reported remaining".into(),
                    scope: if root.get("subscription").is_some() {
                        "subscription"
                    } else {
                        "unknown"
                    }
                    .into(),
                    remaining: (remaining != -1.0).then_some(remaining),
                    unit: unit.clone(),
                    unlimited: remaining == -1.0,
                    ..VendorUsageLimit::default()
                });
            }
        }
        _ => return Err(FetchError::InvalidResponse),
    }

    Ok(ParsedUsage { limits, notes })
}

fn parse_newapi_usage(value: &Value, display: &NewApiDisplay) -> Result<ParsedUsage, FetchError> {
    let root = value.as_object().ok_or(FetchError::InvalidResponse)?;
    if root.get("code").and_then(Value::as_bool) != Some(true) {
        return Err(FetchError::InvalidResponse);
    }
    let data = root
        .get("data")
        .and_then(Value::as_object)
        .ok_or(FetchError::InvalidResponse)?;
    if data.get("object").and_then(Value::as_str) != Some("token_usage") {
        return Err(FetchError::InvalidResponse);
    }

    let unlimited = data
        .get("unlimited_quota")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let used = convert_newapi_amount(number_field(data, "total_used"), display);
    let limit = (!unlimited)
        .then_some(convert_newapi_amount(
            number_field(data, "total_granted"),
            display,
        ))
        .flatten();
    let remaining = (!unlimited)
        .then_some(convert_newapi_amount(
            number_field(data, "total_available"),
            display,
        ))
        .flatten();
    let mut limits = Vec::new();
    if used.is_some() || limit.is_some() || remaining.is_some() || unlimited {
        limits.push(VendorUsageLimit {
            label: "Key token allowance".into(),
            scope: "key".into(),
            used,
            limit,
            remaining,
            unit: display.unit.clone(),
            expires_at: positive_timestamp_field(data, "expires_at"),
            unlimited,
            ..VendorUsageLimit::default()
        });
    }

    if let Some(user_quota) = data.get("user_quota").and_then(Value::as_object) {
        let used = convert_newapi_amount(number_field(user_quota, "total_used"), display);
        let remaining = convert_newapi_amount(number_field(user_quota, "total_available"), display);
        let limit = match (used, remaining) {
            (Some(used), Some(remaining)) => Some(used + remaining),
            _ => None,
        };
        if used.is_some() || remaining.is_some() {
            limits.push(VendorUsageLimit {
                label: "Account quota".into(),
                scope: "account".into(),
                used,
                limit,
                remaining,
                unit: display.unit.clone(),
                ..VendorUsageLimit::default()
            });
        }
    }

    Ok(ParsedUsage {
        limits,
        notes: vec![
            "This is a New API gateway token allowance, not an upstream provider account balance."
                .into(),
            "An unlimited key does not establish a numeric remaining spendable balance.".into(),
        ],
    })
}

fn newapi_display_from_status(value: &Value) -> NewApiDisplay {
    let root = match value.as_object() {
        Some(root) if root.get("success").and_then(Value::as_bool) == Some(true) => root,
        _ => return NewApiDisplay::default(),
    };
    let Some(data) = root.get("data").and_then(Value::as_object) else {
        return NewApiDisplay::default();
    };
    let Some(display_type) = string_field(data, "quota_display_type") else {
        return NewApiDisplay::default();
    };
    let divisor = number_field(data, "quota_per_unit").filter(|value| *value > 0.0);
    let mut display = NewApiDisplay::default();
    match display_type.to_ascii_uppercase().as_str() {
        "USD" => {
            if divisor.is_some() {
                display.unit = "USD".into();
                display.divisor = divisor;
                display.multiplier = 1.0;
            }
        }
        "CNY" => {
            if let (Some(divisor), Some(exchange)) = (
                divisor,
                number_field(data, "usd_exchange_rate").filter(|value| *value > 0.0),
            ) {
                display.unit = "CNY".into();
                display.divisor = Some(divisor);
                display.multiplier = exchange;
            }
        }
        "CUSTOM" => {
            if let (Some(divisor), Some(exchange)) = (
                divisor,
                number_field(data, "custom_currency_exchange_rate").filter(|value| *value > 0.0),
            ) {
                display.unit = "custom gateway currency".into();
                display.divisor = Some(divisor);
                display.multiplier = exchange;
            }
        }
        "TOKENS" => {
            display.unit = "gateway tokens".into();
            display.multiplier = 1.0;
        }
        _ => {}
    }
    display
}

fn convert_newapi_amount(raw: Option<f64>, display: &NewApiDisplay) -> Option<f64> {
    raw.map(|raw| match display.divisor {
        Some(divisor) => raw / divisor * display.multiplier,
        None => raw,
    })
}

fn parse_oneapi_usage(
    subscription: &Value,
    usage: &Value,
    unit: &str,
) -> Result<ParsedUsage, FetchError> {
    let subscription = subscription
        .as_object()
        .ok_or(FetchError::InvalidResponse)?;
    let usage = usage.as_object().ok_or(FetchError::InvalidResponse)?;
    if subscription.get("object").and_then(Value::as_str) != Some("billing_subscription")
        || usage.get("object").and_then(Value::as_str) != Some("list")
        || is_error_envelope(subscription)
        || is_error_envelope(usage)
    {
        return Err(FetchError::InvalidResponse);
    }

    let reported_limit = number_field(subscription, "hard_limit_usd")
        .or_else(|| number_field(subscription, "soft_limit_usd"))
        .or_else(|| number_field(subscription, "system_hard_limit_usd"));
    let unlimited = reported_limit == Some(ONE_API_UNLIMITED_SENTINEL);
    let mut limits = Vec::new();
    if reported_limit.is_some() {
        limits.push(VendorUsageLimit {
            label: "Reported gateway limit".into(),
            scope: "unknown".into(),
            limit: (!unlimited).then_some(reported_limit).flatten(),
            unit: unit.into(),
            expires_at: positive_timestamp_field(subscription, "access_until"),
            unlimited,
            ..VendorUsageLimit::default()
        });
    }
    if let Some(total_usage) = number_field(usage, "total_usage") {
        limits.push(VendorUsageLimit {
            label: "Reported gateway usage".into(),
            scope: "unknown".into(),
            used: Some(total_usage / 100.0),
            unit: unit.into(),
            ..VendorUsageLimit::default()
        });
    }
    if limits.is_empty() {
        return Err(FetchError::InvalidResponse);
    }

    Ok(ParsedUsage {
        limits,
        notes: vec![
            "One API does not publicly reveal whether these figures are key- or account-scoped."
                .into(),
            "Reported limit and usage are shown separately; remaining balance is intentionally unknown."
                .into(),
            "A 100,000,000 gateway value is treated as an unlimited sentinel, not a real balance."
                .into(),
        ],
    })
}

fn is_error_envelope(value: &serde_json::Map<String, Value>) -> bool {
    value.get("error").is_some()
        || value.get("success").and_then(Value::as_bool) == Some(false)
        || value.get("code").and_then(Value::as_bool) == Some(false)
        || value
            .get("code")
            .and_then(Value::as_i64)
            .is_some_and(|code| code != 0)
}

fn oneapi_unit_from_status(value: &Value) -> String {
    let Some(root) = value.as_object() else {
        return "gateway-reported units".into();
    };
    if root.get("success").and_then(Value::as_bool) != Some(true) {
        return "gateway-reported units".into();
    }
    let Some(data) = root.get("data").and_then(Value::as_object) else {
        return "gateway-reported units".into();
    };
    match data.get("display_in_currency").and_then(Value::as_bool) {
        Some(true) => "gateway currency".into(),
        Some(false) => "gateway quota".into(),
        None => "gateway-reported units".into(),
    }
}

fn number_field(object: &serde_json::Map<String, Value>, key: &str) -> Option<f64> {
    number_value(object.get(key)?)
}

fn number_value(value: &Value) -> Option<f64> {
    let number = match value {
        Value::Number(number) => number.as_f64(),
        Value::String(string) => string.trim().parse().ok(),
        _ => None,
    }?;
    number.is_finite().then_some(number)
}

fn integer_field(object: &serde_json::Map<String, Value>, key: &str) -> Option<i64> {
    integer_value(object.get(key)?)
}

fn integer_value(value: &Value) -> Option<i64> {
    let number = number_value(value)?;
    (number.fract() == 0.0 && number >= i64::MIN as f64 && number <= i64::MAX as f64)
        .then_some(number as i64)
}

fn string_field(object: &serde_json::Map<String, Value>, key: &str) -> Option<String> {
    object
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn timestamp_field(object: &serde_json::Map<String, Value>, key: &str) -> Option<i64> {
    object.get(key).and_then(|value| {
        integer_value(value).or_else(|| {
            value
                .as_str()
                .and_then(|timestamp| chrono::DateTime::parse_from_rfc3339(timestamp).ok())
                .map(|timestamp| timestamp.timestamp())
        })
    })
}

fn positive_timestamp_field(object: &serde_json::Map<String, Value>, key: &str) -> Option<i64> {
    timestamp_field(object, key).filter(|timestamp| *timestamp > 0)
}

fn credential_fingerprint(credential: &VendorCredential) -> String {
    let mut hasher = blake3::Hasher::new();
    hash_component(&mut hasher, credential.kind.as_bytes());
    hash_option(&mut hasher, credential.api_key.as_deref());
    hash_option(&mut hasher, credential.access.as_deref());
    hash_option(&mut hasher, credential.refresh.as_deref());
    match credential.expires {
        Some(expires) => {
            hasher.update(&[1]);
            hasher.update(&expires.to_le_bytes());
        }
        None => {
            hasher.update(&[0]);
        }
    }
    hash_option(&mut hasher, credential.account_id.as_deref());
    hasher.finalize().to_hex().to_string()
}

fn fingerprint(value: &[u8]) -> String {
    blake3::hash(value).to_hex().to_string()
}

fn hash_option(hasher: &mut blake3::Hasher, value: Option<&str>) {
    match value {
        Some(value) => {
            hasher.update(&[1]);
            hash_component(hasher, value.as_bytes());
        }
        None => {
            hasher.update(&[0]);
        }
    }
}

fn hash_component(hasher: &mut blake3::Hasher, value: &[u8]) {
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value);
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(provider_id: &str, account_id: &str) -> VendorUsageTarget {
        VendorUsageTarget {
            provider_id: provider_id.into(),
            account_id: account_id.into(),
            provider_name: provider_id.into(),
            account_label: account_id.into(),
            is_default: false,
        }
    }

    #[test]
    fn codex_parser_keeps_server_window_durations_and_additional_buckets() {
        let value = serde_json::json!({
            "rate_limit": {
                "allowed": true,
                "primary_window": {
                    "used_percent": 4,
                    "limit_window_seconds": 17940,
                    "reset_at": 2_000_000_000i64
                },
                "secondary_window": null
            },
            "additional_rate_limits": [{
                "limit_name": "GPT-5.3-Codex-Spark",
                "metered_feature": "codex_bengalfox",
                "rate_limit": {
                    "limit_reached": true,
                    "primary_window": {
                        "used_percent": 17,
                        "limit_window_seconds": 18000,
                        "reset_at": 2_000_001_000i64
                    },
                    "secondary_window": {
                        "used_percent": 61,
                        "limit_window_seconds": 604800,
                        "reset_at": 2_000_600_000i64
                    }
                }
            }],
            "rate_limit_reset_credits": {"available_count": 2}
        });

        let parsed = parse_codex_usage(&value, 1_999_999_000).unwrap();
        assert_eq!(parsed.limits.len(), 4);
        assert_eq!(parsed.limits[0].used_percent, Some(4.0));
        assert!(parsed.limits[0].label.contains("17940 s"));
        assert_eq!(
            parsed.limits[1].label,
            "GPT-5.3-Codex-Spark · Primary window (18000 s)"
        );
        assert_eq!(parsed.limits[2].used_percent, Some(61.0));
        assert_eq!(parsed.limits[3].unit, "credits");
        assert_eq!(parsed.limits[3].remaining, Some(2.0));
        assert!(parsed.notes.iter().any(|note| note.contains("reached")));
    }

    #[test]
    fn sub2api_parser_distinguishes_unlimited_rate_limits_from_unknown_zero_quota() {
        let value = serde_json::json!({
            "mode": "quota_limited",
            "unit": "USD",
            "quota": {"limit": 0, "used": null, "remaining": null},
            "rate_limits": [
                {"window": "5h", "limit": 0, "used": 2, "remaining": 0},
                {"window": "7d", "limit": -1, "used": null, "remaining": -1}
            ]
        });

        let parsed = parse_sub2api_usage(&value).unwrap();
        assert_eq!(parsed.limits.len(), 2);
        assert!(parsed.limits.iter().all(|limit| limit.unlimited));
        assert!(parsed.limits.iter().all(|limit| limit.limit.is_none()));
        assert!(parsed.limits.iter().all(|limit| limit.remaining.is_none()));
    }

    #[test]
    fn newapi_parser_uses_public_conversion_only_when_present() {
        let value = serde_json::json!({
            "code": true,
            "message": "ok",
            "data": {
                "object": "token_usage",
                "total_granted": 1000000,
                "total_used": 12345,
                "total_available": 987655,
                "unlimited_quota": false,
                "expires_at": 0,
                "user_quota": {"total_used": 10, "total_available": 30}
            }
        });
        let raw = parse_newapi_usage(&value, &NewApiDisplay::default()).unwrap();
        assert_eq!(raw.limits[0].unit, "quota");
        assert_eq!(raw.limits[0].limit, Some(1_000_000.0));
        assert_eq!(raw.limits[0].expires_at, None);

        let status = serde_json::json!({
            "success": true,
            "data": {"quota_display_type": "CNY", "quota_per_unit": 500000, "usd_exchange_rate": 7.2}
        });
        let parsed = parse_newapi_usage(&value, &newapi_display_from_status(&status)).unwrap();
        assert_eq!(parsed.limits[0].unit, "CNY");
        assert!((parsed.limits[0].limit.unwrap() - 14.4).abs() < 1e-12);
        assert_eq!(parsed.limits[1].scope, "account");
        assert!((parsed.limits[1].limit.unwrap() - 0.000576).abs() < 1e-12);
    }

    #[test]
    fn oneapi_parser_never_derives_remaining_from_ambiguous_scope() {
        let subscription = serde_json::json!({
            "object": "billing_subscription",
            "hard_limit_usd": 100000000,
            "access_until": 0
        });
        let usage = serde_json::json!({"object": "list", "total_usage": 1250});
        let parsed = parse_oneapi_usage(&subscription, &usage, "gateway currency").unwrap();
        assert!(parsed.limits[0].unlimited);
        assert_eq!(parsed.limits[0].limit, None);
        assert_eq!(parsed.limits[0].remaining, None);
        assert_eq!(parsed.limits[1].used, Some(12.5));
        assert_eq!(parsed.limits[1].scope, "unknown");
        let failed_subscription = serde_json::json!({
            "success": false,
            "object": "billing_subscription",
            "hard_limit_usd": 20
        });
        assert!(parse_oneapi_usage(&failed_subscription, &usage, "gateway currency").is_err());
    }

    #[test]
    fn usage_endpoint_preserves_operator_prefix() {
        let url = usage_endpoint(
            "https://gateway.example/operator/prefix/v1",
            "api/usage/token/",
        )
        .unwrap();
        assert_eq!(
            url.as_str(),
            "https://gateway.example/operator/prefix/v1/api/usage/token/"
        );
    }

    #[tokio::test]
    async fn codex_private_fetch_seam_keeps_bearer_and_account_pairs_isolated() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let mut requests = Vec::new();
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut bytes = [0_u8; 4096];
                let count = stream.read(&mut bytes).unwrap();
                let request = String::from_utf8_lossy(&bytes[..count]).into_owned();
                let lower = request.to_ascii_lowercase();
                let used_percent = if lower.contains("authorization: bearer token-a")
                    && lower.contains("chatgpt-account-id: account-a")
                {
                    11
                } else if lower.contains("authorization: bearer token-b")
                    && lower.contains("chatgpt-account-id: account-b")
                {
                    22
                } else {
                    panic!("Codex request used a mismatched account credential");
                };
                let body = format!(
                    r#"{{"rate_limit":{{"primary_window":{{"used_percent":{used_percent},"limit_window_seconds":60,"reset_at":2000000000}}}}}}"#
                );
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).unwrap();
                requests.push(request);
            }
            requests
        });

        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(2))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let url = reqwest::Url::parse(&format!("http://{address}/backend-api/wham/usage")).unwrap();
        let account_a = target(CODEX_PROVIDER_ID, "account-a");
        let account_b = target(CODEX_PROVIDER_ID, "account-b");
        let credential_a = VendorCredential::oauth_slot(
            "access-a".into(),
            None,
            Some(i64::MAX),
            Some("account-a".into()),
        );
        let credential_b = VendorCredential::oauth_slot(
            "access-b".into(),
            None,
            Some(i64::MAX),
            Some("account-b".into()),
        );

        let report_a =
            fetch_codex_usage_at(&client, url.clone(), &account_a, &credential_a, "token-a")
                .await
                .unwrap();
        let report_b = fetch_codex_usage_at(&client, url, &account_b, &credential_b, "token-b")
            .await
            .unwrap();
        assert_eq!(report_a.limits[0].used_percent, Some(11.0));
        assert_eq!(report_b.limits[0].used_percent, Some(22.0));

        let requests = server.join().unwrap();
        let first = requests[0].to_ascii_lowercase();
        let second = requests[1].to_ascii_lowercase();
        assert!(first.contains("authorization: bearer token-a"));
        assert!(first.contains("chatgpt-account-id: account-a"));
        assert!(second.contains("authorization: bearer token-b"));
        assert!(second.contains("chatgpt-account-id: account-b"));
    }

    #[test]
    fn report_snapshot_is_account_specific_and_rejects_replaced_or_deleted_credentials() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vendor-auth.json");
        let mut auth = VendorAuthStore::load_from(path).unwrap();
        auth.set_oauth(
            CODEX_PROVIDER_ID,
            "access-a".into(),
            Some("refresh-a".into()),
            Some(i64::MAX),
            Some("account-a".into()),
            None,
        )
        .unwrap();
        auth.set_oauth(
            CODEX_PROVIDER_ID,
            "access-b".into(),
            Some("refresh-b".into()),
            Some(i64::MAX),
            Some("account-b".into()),
            None,
        )
        .unwrap();
        auth.set_default_account(CODEX_PROVIDER_ID, "account-b")
            .unwrap();

        let target = target(CODEX_PROVIDER_ID, "account-a");
        let ContextLookup::Found(context) = context_from_stores(&target, &auth, None) else {
            panic!("account-a must have an exact snapshot");
        };
        let report = report(
            target.clone(),
            VendorUsageStatus::Available,
            Vec::new(),
            Vec::new(),
            None,
            Some(&context),
        );
        assert!(report_is_current_in(&report, &auth, None));

        // Changing the provider default cannot substitute account-b for an
        // account-a report.
        auth.set_default_account(CODEX_PROVIDER_ID, "account-a")
            .unwrap();
        assert!(report_is_current_in(&report, &auth, None));

        auth.set_oauth(
            CODEX_PROVIDER_ID,
            "replacement-a".into(),
            Some("replacement-refresh-a".into()),
            Some(i64::MAX),
            Some("account-a".into()),
            None,
        )
        .unwrap();
        assert!(!report_is_current_in(&report, &auth, None));

        auth.remove_account(CODEX_PROVIDER_ID, "account-a").unwrap();
        assert!(!report_is_current_in(&report, &auth, None));
        assert!(
            auth.account_credential(CODEX_PROVIDER_ID, "account-b")
                .is_some()
        );
    }

    #[test]
    fn custom_provider_reconfiguration_invalidates_a_late_report() {
        let directory = tempfile::tempdir().unwrap();
        let mut auth =
            VendorAuthStore::load_from(directory.path().join("vendor-auth.json")).unwrap();
        auth.set_api_key("relay", "key-a".into()).unwrap();

        let mut providers =
            CustomProviderStore::load_from(directory.path().join("vendor-providers.json")).unwrap();
        let provider = crate::compat::custom::CustomProvider {
            id: "relay".into(),
            name: "Relay".into(),
            base_url: "https://gateway.example/prefix/v1".into(),
            platform: CustomPlatform::Sub2Api,
            usage_base_url: None,
            api_backend: "chat_completions".into(),
            auth_scheme: "bearer".into(),
            anthropic_version: None,
            models: Vec::new(),
        };
        providers.upsert(provider.clone()).unwrap();

        let target = target("relay", "default");
        let ContextLookup::Found(context) = context_from_stores(&target, &auth, Some(&providers))
        else {
            panic!("custom provider must have a snapshot");
        };
        let report = report(
            target,
            VendorUsageStatus::Available,
            Vec::new(),
            Vec::new(),
            None,
            Some(&context),
        );
        assert!(report_is_current_in(&report, &auth, Some(&providers)));

        let mut reconfigured = provider;
        reconfigured.usage_base_url = Some("https://gateway.example/prefix/usage".into());
        providers.upsert(reconfigured).unwrap();
        assert!(!report_is_current_in(&report, &auth, Some(&providers)));
    }

    #[test]
    fn sub2api_rate_window_keeps_server_reset_and_key_expiry() {
        let parsed = parse_sub2api_usage(&serde_json::json!({
            "mode": "quota_limited",
            "expires_at": "2030-01-02T00:00:00Z",
            "rate_limits": [{
                "window": "5h", "limit": 10, "used": 3, "remaining": 7,
                "reset_at": "2030-01-01T00:00:00Z"
            }]
        }))
        .unwrap();
        let limit = &parsed.limits[0];
        assert_eq!(limit.resets_at, Some(1_893_456_000));
        assert_eq!(limit.expires_at, Some(1_893_542_400));
        assert_eq!(limit.remaining, Some(7.0));
        assert_eq!(limit.unit, "USD");
    }

    #[test]
    fn sub2api_zero_subscription_limit_is_not_exhaustion() {
        let parsed = parse_sub2api_usage(&serde_json::json!({
            "mode": "unrestricted", "unit": "USD",
            "subscription": {
                "daily_usage_usd": 12, "daily_limit_usd": 0,
                "weekly_usage_usd": 20, "weekly_limit_usd": 50,
                "monthly_usage_usd": 30, "monthly_limit_usd": null
            }
        }))
        .unwrap();
        assert!(parsed.limits[0].unlimited);
        assert_eq!(parsed.limits[0].remaining, None);
        assert_eq!(parsed.limits[1].remaining, Some(30.0));
        assert_eq!(parsed.limits[2].limit, None);
        assert_eq!(parsed.limits[2].remaining, None);
        assert!(parsed.limits.iter().all(|limit| limit.resets_at.is_none()));
    }

    fn report_is_current_in(
        report: &VendorUsageReport,
        auth: &VendorAuthStore,
        custom: Option<&CustomProviderStore>,
    ) -> bool {
        report_matches_context(report, context_from_stores(&report.target, auth, custom))
    }
}
