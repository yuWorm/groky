//! Probe a vendor API key, then persist it.

use super::auth_store::VendorAuthStore;
use super::catalog::provider_by_id;

#[derive(Debug, thiserror::Error)]
pub enum VendorLoginError {
    #[error("unknown provider '{0}'")]
    UnknownProvider(String),
    #[error("empty API key")]
    EmptyKey,
    #[error("{0}")]
    Probe(String),
    #[error("couldn't save credentials: {0}")]
    Store(#[from] std::io::Error),
}

pub async fn probe_api_key(provider_id: &str, api_key: &str) -> Result<(), VendorLoginError> {
    let Some(provider) = provider_by_id(provider_id) else {
        return crate::compat::custom::probe_existing(provider_id, api_key).await;
    };
    if provider.requires_auth && api_key.trim().is_empty() {
        return Err(VendorLoginError::EmptyKey);
    }

    // Codex model discovery is account-scoped. OAuth proves the account and
    // refreshes its product catalog; a manually supplied PAT is accepted here.
    if provider.id == "openai-codex" {
        return Ok(());
    }

    let url = format!("{}/models", provider.base_url.trim_end_matches('/'));
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| VendorLoginError::Probe(e.to_string()))?;

    let mut req = client.get(&url);
    if provider.requires_auth {
        match provider.auth_scheme {
            xai_grok_sampler::AuthScheme::XApiKey => {
                req = req.header("x-api-key", api_key.trim());
            }
            xai_grok_sampler::AuthScheme::Bearer => {
                req = req.bearer_auth(api_key.trim());
            }
        }
    }
    if let Some(version) = provider.anthropic_version {
        req = req.header("anthropic-version", version);
    }

    let resp = req.send().await.map_err(|e| {
        VendorLoginError::Probe(format!("couldn't reach {}: {e}", provider.base_url))
    })?;
    let status = resp.status();
    if status.is_success() {
        return Ok(());
    }
    let body = resp.text().await.unwrap_or_default();
    let snippet: String = body.chars().take(180).collect();
    Err(VendorLoginError::Probe(format!(
        "{status} from {url}{}",
        if snippet.is_empty() {
            String::new()
        } else {
            format!(": {snippet}")
        }
    )))
}

pub async fn login_with_api_key(provider_id: &str, api_key: &str) -> Result<(), VendorLoginError> {
    let key = api_key.trim();
    if provider_by_id(provider_id).is_none() {
        return crate::compat::custom::login_existing(provider_id, key).await;
    }
    probe_api_key(provider_id, key).await?;
    let provider = provider_by_id(provider_id)
        .ok_or_else(|| VendorLoginError::UnknownProvider(provider_id.to_owned()))?;
    let mut store = VendorAuthStore::default_store()?;
    if provider.requires_auth {
        store.set_api_key(provider_id, key.to_owned())?;
    } else {
        store.mark_connected(provider_id)?;
    }
    if let Err(error) = crate::compat::vendor_models::refresh(provider_id).await {
        tracing::warn!(
            provider_id,
            error = %error,
            "vendor model list refresh failed after login"
        );
    }
    Ok(())
}

pub fn logout_provider(provider_id: &str) -> Result<bool, VendorLoginError> {
    if provider_by_id(provider_id).is_none()
        && !crate::compat::custom::is_custom_provider(provider_id)
    {
        return Err(VendorLoginError::UnknownProvider(provider_id.to_owned()));
    }
    let mut store = VendorAuthStore::default_store()?;
    Ok(store.remove(provider_id)?)
}
