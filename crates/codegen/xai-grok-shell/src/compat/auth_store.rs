//! `$GROK_HOME/vendor-auth.json` (default `~/.groky/vendor-auth.json`) —
//! credentials keyed by provider id.
//!
//! Shape matches Pi's `auth.json` enough to store API keys and OAuth
//! tokens. First-party xAI `auth.json` is never read or written here.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::util::grok_home::grok_home;

const FILE_NAME: &str = "vendor-auth.json";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct FileShape {
    #[serde(default)]
    providers: BTreeMap<String, VendorCredential>,
}

/// One provider slot. Legacy `{ "api_key": "…" }` still deserializes
/// (`type` defaults to `api_key`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VendorCredential {
    #[serde(rename = "type", default = "default_kind")]
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<i64>,
    /// ChatGPT account id (Codex). Pi stores this as `accountId`.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "accountId")]
    pub account_id: Option<String>,
}

fn default_kind() -> String {
    "api_key".into()
}

impl VendorCredential {
    pub fn api_key_slot(key: String) -> Self {
        Self {
            kind: "api_key".into(),
            api_key: Some(key),
            access: None,
            refresh: None,
            expires: None,
            account_id: None,
        }
    }

    pub fn oauth_slot(
        access: String,
        refresh: Option<String>,
        expires: Option<i64>,
        account_id: Option<String>,
    ) -> Self {
        Self {
            kind: "oauth".into(),
            api_key: None,
            access: Some(access),
            refresh,
            expires,
            account_id,
        }
    }

    pub fn connected_slot() -> Self {
        Self {
            kind: "connected".into(),
            api_key: None,
            access: None,
            refresh: None,
            expires: None,
            account_id: None,
        }
    }

    fn now_unix() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }

    pub fn is_expired(&self) -> bool {
        let Some(exp) = self.expires else {
            return false;
        };
        exp < Self::now_unix()
    }

    /// True when the access token is missing an expiry buffer (refresh now).
    pub fn expires_soon(&self, skew_secs: i64) -> bool {
        let Some(exp) = self.expires else {
            return false;
        };
        exp < Self::now_unix().saturating_add(skew_secs.max(0))
    }

    /// Bearer / x-api-key material for a live request.
    pub fn request_secret(&self) -> Option<&str> {
        match self.kind.as_str() {
            "oauth" => {
                if self.is_expired() {
                    return None;
                }
                self.access
                    .as_deref()
                    .filter(|s| !s.trim().is_empty())
                    .or_else(|| self.api_key.as_deref().filter(|s| !s.trim().is_empty()))
            }
            "connected" => None,
            _ => self.api_key.as_deref().filter(|s| !s.trim().is_empty()),
        }
    }
}

pub struct VendorAuthStore {
    path: PathBuf,
    data: FileShape,
}

impl VendorAuthStore {
    pub fn default_path() -> PathBuf {
        grok_home().join(FILE_NAME)
    }

    pub fn default_store() -> io::Result<Self> {
        Self::load_from(Self::default_path())
    }

    pub fn load_from(path: PathBuf) -> io::Result<Self> {
        let data = if path.exists() {
            let raw = fs::read_to_string(&path)?;
            serde_json::from_str(&raw).unwrap_or_default()
        } else {
            FileShape::default()
        };
        Ok(Self { path, data })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn credential(&self, provider_id: &str) -> Option<&VendorCredential> {
        self.data.providers.get(provider_id)
    }

    pub fn api_key(&self, provider_id: &str) -> Option<String> {
        self.data
            .providers
            .get(provider_id)
            .and_then(|c| c.request_secret().map(str::to_owned))
    }

    /// True if a slot exists, including a no-key local connect (Ollama).
    pub fn has_provider(&self, provider_id: &str) -> bool {
        self.data.providers.contains_key(provider_id)
    }

    /// Any configured vendor slot that can actually be used.
    pub fn has_any_configured_provider(&self) -> bool {
        self.data
            .providers
            .values()
            .any(|cred| match cred.kind.as_str() {
                "connected" => true,
                "oauth" => {
                    cred.request_secret().is_some()
                        || cred
                            .refresh
                            .as_deref()
                            .is_some_and(|s| !s.trim().is_empty())
                }
                _ => cred.request_secret().is_some(),
            })
    }

    pub fn set_api_key(&mut self, provider_id: &str, key: String) -> io::Result<()> {
        self.data
            .providers
            .insert(provider_id.to_owned(), VendorCredential::api_key_slot(key));
        self.save()
    }

    pub fn set_oauth(
        &mut self,
        provider_id: &str,
        access: String,
        refresh: Option<String>,
        expires: Option<i64>,
        account_id: Option<String>,
    ) -> io::Result<()> {
        self.data.providers.insert(
            provider_id.to_owned(),
            VendorCredential::oauth_slot(access, refresh, expires, account_id),
        );
        self.save()
    }

    /// Persist a connected marker without an API key (local providers).
    pub fn mark_connected(&mut self, provider_id: &str) -> io::Result<()> {
        self.data
            .providers
            .entry(provider_id.to_owned())
            .or_insert_with(VendorCredential::connected_slot);
        self.save()
    }

    pub fn remove(&mut self, provider_id: &str) -> io::Result<bool> {
        let existed = self.data.providers.remove(provider_id).is_some();
        if existed {
            self.save()?;
        }
        Ok(existed)
    }

    fn save(&self) -> io::Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(&self.data)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let mut file = fs::File::create(&self.path)?;
        file.write_all(json.as_bytes())?;
        file.sync_all()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{VendorAuthStore, VendorCredential};

    #[test]
    fn roundtrip_api_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vendor-auth.json");
        let mut store = VendorAuthStore::load_from(path.clone()).unwrap();
        assert!(store.api_key("openai").is_none());
        store.set_api_key("openai", "sk-test".into()).unwrap();
        drop(store);
        let store = VendorAuthStore::load_from(path).unwrap();
        assert_eq!(store.api_key("openai").as_deref(), Some("sk-test"));
        assert!(store.has_provider("openai"));
        assert_eq!(
            store.credential("openai").map(|c| c.kind.as_str()),
            Some("api_key")
        );
    }

    #[test]
    fn legacy_json_without_type_still_loads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vendor-auth.json");
        std::fs::write(&path, r#"{"providers":{"openai":{"api_key":"sk-legacy"}}}"#).unwrap();
        let store = VendorAuthStore::load_from(path).unwrap();
        assert_eq!(store.api_key("openai").as_deref(), Some("sk-legacy"));
    }

    #[test]
    fn oauth_secret_and_expiry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vendor-auth.json");
        let mut store = VendorAuthStore::load_from(path.clone()).unwrap();
        store
            .set_oauth("openrouter", "or-key".into(), None, Some(i64::MAX), None)
            .unwrap();
        assert_eq!(store.api_key("openrouter").as_deref(), Some("or-key"));

        store
            .set_oauth("openrouter", "or-key".into(), None, Some(1), None)
            .unwrap();
        assert!(store.api_key("openrouter").is_none());
        assert!(store.has_provider("openrouter"));
    }

    #[test]
    fn mark_connected_without_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vendor-auth.json");
        let mut store = VendorAuthStore::load_from(path.clone()).unwrap();
        store.mark_connected("ollama").unwrap();
        drop(store);
        let store = VendorAuthStore::load_from(path).unwrap();
        assert!(store.has_provider("ollama"));
        assert!(store.api_key("ollama").is_none());
        assert!(store.has_any_configured_provider());
        let _ = VendorCredential::connected_slot();
    }

    #[test]
    fn empty_store_has_no_configured_provider() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vendor-auth.json");
        let store = VendorAuthStore::load_from(path).unwrap();
        assert!(!store.has_any_configured_provider());
    }

    #[test]
    fn oauth_roundtrip_account_id() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vendor-auth.json");
        let mut store = VendorAuthStore::load_from(path.clone()).unwrap();
        store
            .set_oauth(
                "openai-codex",
                "tok".into(),
                Some("ref".into()),
                Some(i64::MAX),
                Some("acct-1".into()),
            )
            .unwrap();
        drop(store);
        let store = VendorAuthStore::load_from(path).unwrap();
        let cred = store.credential("openai-codex").unwrap();
        assert_eq!(cred.account_id.as_deref(), Some("acct-1"));
        assert_eq!(cred.refresh.as_deref(), Some("ref"));
        assert_eq!(store.api_key("openai-codex").as_deref(), Some("tok"));
    }
}
