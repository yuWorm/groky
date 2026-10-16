//! `$GROK_HOME/vendor-auth.json` (default `~/.groky/vendor-auth.json`) —
//! credentials keyed by provider and account id.
//!
//! Shape matches Pi's `auth.json` enough to store API keys and OAuth
//! tokens. First-party xAI `auth.json` is never read or written here.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use fs2::FileExt;
use serde::{Deserialize, Serialize};

use crate::util::grok_home::grok_home;

const FILE_NAME: &str = "vendor-auth.json";
const DEFAULT_ACCOUNT_ID: &str = "default";
const CODEX_PROVIDER_ID: &str = "openai-codex";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct FileShape {
    #[serde(default)]
    providers: BTreeMap<String, ProviderAuth>,
}

impl FileShape {
    fn normalize(&mut self) {
        for (provider_id, provider) in &mut self.providers {
            if let ProviderAuth::Legacy(credential) = provider {
                *provider = ProviderAuth::Accounts(ProviderAccounts::from_legacy(
                    provider_id,
                    credential.clone(),
                ));
            }
            if let ProviderAuth::Accounts(accounts) = provider {
                accounts.normalize();
            }
        }
    }

    fn provider_accounts(&self, provider_id: &str) -> Option<&ProviderAccounts> {
        match self.providers.get(provider_id) {
            Some(ProviderAuth::Accounts(accounts)) => Some(accounts),
            Some(ProviderAuth::Legacy(_)) | None => None,
        }
    }

    fn provider_accounts_mut(&mut self, provider_id: &str) -> &mut ProviderAccounts {
        let provider = self
            .providers
            .entry(provider_id.to_owned())
            .or_insert_with(|| ProviderAuth::Accounts(ProviderAccounts::default()));
        if let ProviderAuth::Legacy(credential) = provider {
            *provider = ProviderAuth::Accounts(ProviderAccounts::from_legacy(
                provider_id,
                credential.clone(),
            ));
        }
        match provider {
            ProviderAuth::Accounts(accounts) => accounts,
            ProviderAuth::Legacy(_) => unreachable!("legacy providers are normalized"),
        }
    }
}

/// The pre-multi-account shape was a credential directly under its provider
/// id. It remains accepted on read and is written back as `Accounts` by the
/// next mutation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
enum ProviderAuth {
    Accounts(ProviderAccounts),
    Legacy(VendorCredential),
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ProviderAccounts {
    accounts: BTreeMap<String, AccountSlot>,
    #[serde(
        default,
        rename = "defaultAccountId",
        skip_serializing_if = "Option::is_none"
    )]
    default_account_id: Option<String>,
}

impl ProviderAccounts {
    fn from_legacy(provider_id: &str, credential: VendorCredential) -> Self {
        let account_id = account_slot_id(provider_id, credential.account_id.as_deref());
        let mut accounts = BTreeMap::new();
        accounts.insert(
            account_id.clone(),
            AccountSlot {
                label: account_id.clone(),
                label_is_custom: false,
                credential,
            },
        );
        Self {
            accounts,
            default_account_id: Some(account_id),
        }
    }

    fn normalize(&mut self) {
        for (account_id, account) in &mut self.accounts {
            if account.label.trim().is_empty() {
                account.label = account_id.clone();
            }
        }
        if self
            .default_account_id
            .as_deref()
            .is_some_and(|id| !self.accounts.contains_key(id))
        {
            self.default_account_id = None;
        }
    }

    fn credential(&self) -> Option<&VendorCredential> {
        self.default_account_id
            .as_deref()
            .and_then(|id| self.accounts.get(id))
            .map(|account| &account.credential)
    }

    fn upsert(
        &mut self,
        account_id: String,
        credential: VendorCredential,
        suggested_label: Option<String>,
    ) {
        let suggested_label = suggested_label.filter(|label| !label.trim().is_empty());
        let was_empty = self.accounts.is_empty();
        match self.accounts.get_mut(&account_id) {
            Some(account) => {
                account.credential = credential;
                if !account.label_is_custom && account.label == account_id
                    && let Some(label) = suggested_label
                {
                    account.label = label;
                }
            }
            None => {
                self.accounts.insert(
                    account_id.clone(),
                    AccountSlot {
                        label: suggested_label.unwrap_or_else(|| account_id.clone()),
                        label_is_custom: false,
                        credential,
                    },
                );
                if was_empty {
                    self.default_account_id = Some(account_id);
                }
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AccountSlot {
    #[serde(default)]
    label: String,
    /// Explicit renames stay pinned even when the chosen label is the account id.
    #[serde(default)]
    label_is_custom: bool,
    credential: VendorCredential,
}

/// One provider account without credential material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VendorAccountInfo {
    pub id: String,
    pub label: String,
    pub is_default: bool,
    pub needs_login: bool,
}

/// One provider credential. Legacy `{ "api_key": "…" }` still deserializes
/// (`type` defaults to `api_key`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

    fn needs_login(&self) -> bool {
        match self.kind.as_str() {
            "connected" => false,
            "oauth" => {
                self.request_secret().is_none()
                    && self
                        .refresh
                        .as_deref()
                        .is_none_or(|refresh| refresh.trim().is_empty())
            }
            _ => self.request_secret().is_none(),
        }
    }
}

#[derive(Debug)]
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
        let data = load_file_shape(&path)?;
        Ok(Self { path, data })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The currently selected credential. This preserves the legacy
    /// provider-level accessor while selecting exactly one account.
    pub fn credential(&self, provider_id: &str) -> Option<&VendorCredential> {
        self.data
            .provider_accounts(provider_id)
            .and_then(ProviderAccounts::credential)
    }

    /// The credential for this exact account. It never falls back to default.
    pub fn account_credential(
        &self,
        provider_id: &str,
        account_id: &str,
    ) -> Option<&VendorCredential> {
        self.data
            .provider_accounts(provider_id)
            .and_then(|accounts| accounts.accounts.get(account_id))
            .map(|account| &account.credential)
    }

    pub fn accounts(&self, provider_id: &str) -> Vec<VendorAccountInfo> {
        let Some(accounts) = self.data.provider_accounts(provider_id) else {
            return Vec::new();
        };
        accounts
            .accounts
            .iter()
            .map(|(id, account)| VendorAccountInfo {
                id: id.clone(),
                label: account.label.clone(),
                is_default: accounts.default_account_id.as_deref() == Some(id),
                needs_login: account.credential.needs_login(),
            })
            .collect()
    }

    pub fn default_account_id(&self, provider_id: &str) -> Option<&str> {
        self.data
            .provider_accounts(provider_id)
            .and_then(|accounts| accounts.default_account_id.as_deref())
    }

    pub fn api_key(&self, provider_id: &str) -> Option<String> {
        self.credential(provider_id)
            .and_then(|credential| credential.request_secret().map(str::to_owned))
    }

    /// True if at least one account exists, including a no-key local connect
    /// (Ollama) or an account whose default was deliberately cleared.
    pub fn has_provider(&self, provider_id: &str) -> bool {
        self.data
            .provider_accounts(provider_id)
            .is_some_and(|accounts| !accounts.accounts.is_empty())
    }

    /// Any configured vendor slot that can actually be used.
    pub fn has_any_configured_provider(&self) -> bool {
        self.data
            .providers
            .values()
            .filter_map(|provider| match provider {
                ProviderAuth::Accounts(accounts) => Some(accounts),
                ProviderAuth::Legacy(_) => None,
            })
            .flat_map(|accounts| accounts.accounts.values())
            .any(|account| match account.credential.kind.as_str() {
                "connected" => true,
                "oauth" => {
                    account.credential.request_secret().is_some()
                        || account
                            .credential
                            .refresh
                            .as_deref()
                            .is_some_and(|refresh| !refresh.trim().is_empty())
                }
                _ => account.credential.request_secret().is_some(),
            })
    }

    pub fn set_api_key(&mut self, provider_id: &str, key: String) -> io::Result<()> {
        self.mutate(|data| {
            data.provider_accounts_mut(provider_id).upsert(
                DEFAULT_ACCOUNT_ID.to_owned(),
                VendorCredential::api_key_slot(key),
                None,
            );
            Ok(((), true))
        })
    }

    /// Store a provider OAuth token. Codex uses its stable ChatGPT account id
    /// as the slot; all legacy providers remain a `default` singleton.
    /// A suggested label only fills an untouched account-id label, under the same file lock.
    pub fn set_oauth(
        &mut self,
        provider_id: &str,
        access: String,
        refresh: Option<String>,
        expires: Option<i64>,
        account_id: Option<String>,
        suggested_label: Option<String>,
    ) -> io::Result<()> {
        let slot_id = account_slot_id(provider_id, account_id.as_deref());
        self.mutate(|data| {
            data.provider_accounts_mut(provider_id).upsert(
                slot_id,
                VendorCredential::oauth_slot(access, refresh, expires, account_id),
                suggested_label,
            );
            Ok(((), true))
        })
    }

    /// Persist a connected marker without an API key (local providers).
    pub fn mark_connected(&mut self, provider_id: &str) -> io::Result<()> {
        self.mutate(|data| {
            let accounts = data.provider_accounts_mut(provider_id);
            if accounts.accounts.contains_key(DEFAULT_ACCOUNT_ID) {
                return Ok(((), false));
            }
            accounts.upsert(
                DEFAULT_ACCOUNT_ID.to_owned(),
                VendorCredential::connected_slot(),
                None,
            );
            Ok(((), true))
        })
    }

    /// Remove every account for this provider (legacy provider logout).
    pub fn remove(&mut self, provider_id: &str) -> io::Result<bool> {
        self.mutate(|data| {
            let existed = data.providers.remove(provider_id).is_some();
            Ok((existed, existed))
        })
    }

    pub fn set_default_account(&mut self, provider_id: &str, account_id: &str) -> io::Result<()> {
        self.mutate(|data| {
            let Some(ProviderAuth::Accounts(accounts)) = data.providers.get_mut(provider_id)
            else {
                return Err(account_not_found(provider_id, account_id));
            };
            if !accounts.accounts.contains_key(account_id) {
                return Err(account_not_found(provider_id, account_id));
            }
            let changed = accounts.default_account_id.as_deref() != Some(account_id);
            if changed {
                accounts.default_account_id = Some(account_id.to_owned());
            }
            Ok(((), changed))
        })
    }

    pub fn rename_account(
        &mut self,
        provider_id: &str,
        account_id: &str,
        label: &str,
    ) -> io::Result<()> {
        if label.trim().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "account label cannot be empty",
            ));
        }
        self.mutate(|data| {
            let Some(ProviderAuth::Accounts(accounts)) = data.providers.get_mut(provider_id)
            else {
                return Err(account_not_found(provider_id, account_id));
            };
            let Some(account) = accounts.accounts.get_mut(account_id) else {
                return Err(account_not_found(provider_id, account_id));
            };
            let changed = account.label != label || !account.label_is_custom;
            if account.label != label {
                account.label = label.to_owned();
            }
            account.label_is_custom = true;
            Ok(((), changed))
        })
    }

    /// Remove one account. Removing the selected account deliberately leaves
    /// no selection; another account is never chosen implicitly.
    pub fn remove_account(&mut self, provider_id: &str, account_id: &str) -> io::Result<bool> {
        self.mutate(|data| {
            let Some(ProviderAuth::Accounts(accounts)) = data.providers.get_mut(provider_id)
            else {
                return Ok((false, false));
            };
            let existed = accounts.accounts.remove(account_id).is_some();
            if !existed {
                return Ok((false, false));
            }
            if accounts.default_account_id.as_deref() == Some(account_id) {
                accounts.default_account_id = None;
            }
            if accounts.accounts.is_empty() {
                data.providers.remove(provider_id);
            }
            Ok((true, true))
        })
    }

    /// Replace a credential only when the account still holds the exact
    /// snapshot that initiated the refresh. This protects a newer login or
    /// refresh and never recreates an account that was deleted in-flight.
    pub(crate) fn replace_account_credential_if_matches(
        &mut self,
        provider_id: &str,
        account_id: &str,
        expected: &VendorCredential,
        replacement: VendorCredential,
    ) -> io::Result<bool> {
        self.mutate(|data| {
            let Some(ProviderAuth::Accounts(accounts)) = data.providers.get_mut(provider_id)
            else {
                return Ok((false, false));
            };
            let Some(account) = accounts.accounts.get_mut(account_id) else {
                return Ok((false, false));
            };
            if account.credential != *expected {
                return Ok((false, false));
            }
            account.credential = replacement;
            Ok((true, true))
        })
    }

    fn mutate<T>(
        &mut self,
        mutation: impl FnOnce(&mut FileShape) -> io::Result<(T, bool)>,
    ) -> io::Result<T> {
        let parent = parent_dir(&self.path)?;
        fs::create_dir_all(parent)?;
        let lock_path = parent.join(format!(
            ".{}.lock",
            self.path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid auth path"))?
        ));
        let lock_file = open_owner_only_lock(&lock_path)?;
        lock_file.lock_exclusive()?;

        let mut data = load_file_shape(&self.path)?;
        let (result, changed) = mutation(&mut data)?;
        if changed {
            write_file_shape(&self.path, &data)?;
        }
        self.data = data;
        Ok(result)
    }
}

fn account_slot_id(provider_id: &str, account_id: Option<&str>) -> String {
    if provider_id == CODEX_PROVIDER_ID {
        return account_id
            .filter(|id| !id.trim().is_empty())
            .unwrap_or(DEFAULT_ACCOUNT_ID)
            .to_owned();
    }
    DEFAULT_ACCOUNT_ID.to_owned()
}

fn account_not_found(provider_id: &str, account_id: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        format!("account '{account_id}' is not configured for provider '{provider_id}'"),
    )
}

fn parent_dir(path: &Path) -> io::Result<&Path> {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "auth path has no parent"))
}

fn load_file_shape(path: &Path) -> io::Result<FileShape> {
    if !path.exists() {
        return Ok(FileShape::default());
    }
    let raw = fs::read_to_string(path)?;
    let mut data = serde_json::from_str::<FileShape>(&raw).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid vendor auth file '{}': {error}", path.display()),
        )
    })?;
    data.normalize();
    Ok(data)
}

fn open_owner_only_lock(path: &Path) -> io::Result<fs::File> {
    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
}

fn write_file_shape(path: &Path, data: &FileShape) -> io::Result<()> {
    let parent = parent_dir(path)?;
    let json = serde_json::to_string_pretty(data)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o600))?;
    }
    temporary.write_all(json.as_bytes())?;
    temporary.as_file_mut().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(unix)]
    {
        let directory = fs::File::open(parent)?;
        directory.sync_all()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{VendorAuthStore, VendorCredential};

    fn oauth(access: &str, refresh: &str, account_id: &str) -> VendorCredential {
        VendorCredential::oauth_slot(
            access.into(),
            Some(refresh.into()),
            Some(i64::MAX),
            Some(account_id.into()),
        )
    }

    #[test]
    fn login_backfills_legacy_default_labels_but_preserves_existing_labels() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vendor-auth.json");
        std::fs::write(&path, r#"{"providers":{"openai-codex":{
            "defaultAccountId":"acct-a","accounts":{
                "acct-a":{"label":"acct-a","credential":{"type":"oauth","access":"old-a","accountId":"acct-a"}},
                "acct-b":{"label":"Team","credential":{"type":"oauth","access":"old-b","accountId":"acct-b"}}
            }
        }}}"#).unwrap();
        let mut store = VendorAuthStore::load_from(path.clone()).unwrap();
        for account_id in ["acct-a", "acct-b"] {
            store.set_oauth(
                "openai-codex",
                "new-access".into(),
                None,
                None,
                Some(account_id.into()),
                Some("person@example.com".into()),
            ).unwrap();
        }
        let mut store = VendorAuthStore::load_from(path.clone()).unwrap();
        assert_eq!(store.accounts("openai-codex")[0].label, "person@example.com");
        assert_eq!(store.accounts("openai-codex")[1].label, "Team");
        store.set_oauth(
            "openai-codex",
            "next-access".into(),
            None,
            None,
            Some("acct-a".into()),
            None,
        ).unwrap();
        let store = VendorAuthStore::load_from(path).unwrap();
        assert_eq!(store.accounts("openai-codex")[0].label, "person@example.com");
        assert_eq!(store.default_account_id("openai-codex"), Some("acct-a"));
    }

    #[test]
    fn explicit_default_label_survives_stale_login_and_refresh() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vendor-auth.json");
        let mut store = VendorAuthStore::load_from(path.clone()).unwrap();
        store.set_oauth(
            "openai-codex",
            "access".into(),
            None,
            None,
            Some("acct-a".into()),
            None,
        ).unwrap();
        let mut stale_login = VendorAuthStore::load_from(path.clone()).unwrap();
        store.rename_account("openai-codex", "acct-a", "acct-a").unwrap();
        stale_login.set_oauth(
            "openai-codex",
            "new-access".into(),
            None,
            None,
            Some("acct-a".into()),
            Some("person@example.com".into()),
        ).unwrap();
        let mut store = VendorAuthStore::load_from(path.clone()).unwrap();
        assert_eq!(store.accounts("openai-codex")[0].label, "acct-a");
        let expected = store.account_credential("openai-codex", "acct-a").unwrap().clone();
        store.rename_account("openai-codex", "acct-a", "Work").unwrap();
        assert!(store.replace_account_credential_if_matches(
            "openai-codex", "acct-a", &expected, oauth("refreshed", "next-refresh", "acct-a"),
        ).unwrap());
        let store = VendorAuthStore::load_from(path).unwrap();
        assert_eq!(store.accounts("openai-codex")[0].label, "Work");
        assert_eq!(
            store.account_credential("openai-codex", "acct-a").unwrap().access.as_deref(),
            Some("refreshed")
        );
    }

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
            store.credential("openai").map(|credential| credential.kind.as_str()),
            Some("api_key")
        );
        assert_eq!(store.default_account_id("openai"), Some("default"));
    }

    #[test]
    fn legacy_json_migrates_without_losing_credential() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vendor-auth.json");
        std::fs::write(
            &path,
            r#"{"providers":{"openai-codex":{"type":"oauth","access":"old","refresh":"refresh","expires":9223372036854775807,"accountId":"acct-1"}}}"#,
        )
        .unwrap();

        let mut store = VendorAuthStore::load_from(path.clone()).unwrap();
        assert_eq!(store.default_account_id("openai-codex"), Some("acct-1"));
        assert_eq!(
            store
                .account_credential("openai-codex", "acct-1")
                .and_then(|credential| credential.access.as_deref()),
            Some("old")
        );
        store.rename_account("openai-codex", "acct-1", "Primary").unwrap();

        let persisted = std::fs::read_to_string(&path).unwrap();
        assert!(persisted.contains("\"accounts\""));
        let store = VendorAuthStore::load_from(path).unwrap();
        assert_eq!(store.accounts("openai-codex")[0].label, "Primary");
    }

    #[test]
    fn malformed_json_returns_invalid_data_instead_of_resetting_credentials() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vendor-auth.json");
        std::fs::write(&path, "{ definitely not json").unwrap();
        let error = VendorAuthStore::load_from(path).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn oauth_secret_and_expiry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vendor-auth.json");
        let mut store = VendorAuthStore::load_from(path).unwrap();
        store.set_oauth(
            "openrouter",
            "or-key".into(),
            None,
            Some(i64::MAX),
            None,
            None,
        )
            .unwrap();
        assert_eq!(store.api_key("openrouter").as_deref(), Some("or-key"));

        store.set_oauth(
            "openrouter",
            "or-key".into(),
            None,
            Some(1),
            None,
            None,
        )
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
    }

    #[test]
    fn empty_store_has_no_configured_provider() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vendor-auth.json");
        let store = VendorAuthStore::load_from(path).unwrap();
        assert!(!store.has_any_configured_provider());
    }

    #[test]
    fn codex_login_adds_and_updates_only_its_account() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vendor-auth.json");
        let mut store = VendorAuthStore::load_from(path).unwrap();
        store.set_oauth(
            "openai-codex",
            "token-a".into(),
            Some("refresh-a".into()),
            Some(i64::MAX),
            Some("acct-a".into()),
            None,
        )
            .unwrap();
        store.set_oauth(
            "openai-codex",
            "token-b".into(),
            Some("refresh-b".into()),
            Some(i64::MAX),
            Some("acct-b".into()),
            None,
        )
            .unwrap();
        store.set_oauth(
            "openai-codex",
            "new-token-a".into(),
            Some("new-refresh-a".into()),
            Some(i64::MAX),
            Some("acct-a".into()),
            None,
        )
            .unwrap();

        assert_eq!(store.default_account_id("openai-codex"), Some("acct-a"));
        assert_eq!(
            store
                .account_credential("openai-codex", "acct-a")
                .and_then(|credential| credential.access.as_deref()),
            Some("new-token-a")
        );
        assert_eq!(
            store
                .account_credential("openai-codex", "acct-b")
                .and_then(|credential| credential.access.as_deref()),
            Some("token-b")
        );
        assert_eq!(store.accounts("openai-codex").len(), 2);
    }

    #[test]
    fn selection_and_removal_never_pick_another_account() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vendor-auth.json");
        let mut store = VendorAuthStore::load_from(path).unwrap();
        store.set_oauth(
            "openai-codex",
            "token-a".into(),
            Some("refresh-a".into()),
            Some(i64::MAX),
            Some("acct-a".into()),
            None,
        )
            .unwrap();
        store.set_oauth(
            "openai-codex",
            "token-b".into(),
            Some("refresh-b".into()),
            Some(i64::MAX),
            Some("acct-b".into()),
            None,
        )
            .unwrap();
        store
            .set_default_account("openai-codex", "acct-b")
            .unwrap();
        store
            .rename_account("openai-codex", "acct-b", "Work")
            .unwrap();
        assert!(store.remove_account("openai-codex", "acct-b").unwrap());

        assert_eq!(store.default_account_id("openai-codex"), None);
        assert!(store.credential("openai-codex").is_none());
        assert!(store.account_credential("openai-codex", "acct-a").is_some());
        assert_eq!(
            store
                .set_default_account("openai-codex", "missing")
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::NotFound
        );
    }

    #[test]
    fn stale_store_writers_merge_accounts_under_the_file_lock() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vendor-auth.json");
        let mut first = VendorAuthStore::load_from(path.clone()).unwrap();
        let mut second = VendorAuthStore::load_from(path.clone()).unwrap();

        first.set_oauth(
            "openai-codex",
            "token-a".into(),
            Some("refresh-a".into()),
            Some(i64::MAX),
            Some("acct-a".into()),
            None,
        )
            .unwrap();
        second.set_oauth(
            "openai-codex",
            "token-b".into(),
            Some("refresh-b".into()),
            Some(i64::MAX),
            Some("acct-b".into()),
            None,
        )
            .unwrap();

        let store = VendorAuthStore::load_from(path).unwrap();
        assert_eq!(store.accounts("openai-codex").len(), 2);
        assert_eq!(store.default_account_id("openai-codex"), Some("acct-a"));
    }

    #[test]
    fn refresh_updates_exact_account_without_overwriting_newer_or_removed_credential() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vendor-auth.json");
        let mut store = VendorAuthStore::load_from(path).unwrap();
        store.set_oauth(
            "openai-codex",
            "token-a".into(),
            Some("refresh-a".into()),
            Some(i64::MAX),
            Some("acct-a".into()),
            None,
        )
            .unwrap();
        store.set_oauth(
            "openai-codex",
            "token-b".into(),
            Some("refresh-b".into()),
            Some(i64::MAX),
            Some("acct-b".into()),
            None,
        )
            .unwrap();
        let expected_a = store
            .account_credential("openai-codex", "acct-a")
            .cloned()
            .unwrap();

        assert!(
            store
                .replace_account_credential_if_matches(
                    "openai-codex",
                    "acct-a",
                    &expected_a,
                    oauth("refreshed-a", "next-a", "acct-a"),
                )
                .unwrap()
        );
        assert_eq!(
            store
                .account_credential("openai-codex", "acct-b")
                .and_then(|credential| credential.access.as_deref()),
            Some("token-b")
        );

        let stale_a = store
            .account_credential("openai-codex", "acct-a")
            .cloned()
            .unwrap();
        store.set_oauth(
            "openai-codex",
            "newer-a".into(),
            Some("newer-refresh-a".into()),
            Some(i64::MAX),
            Some("acct-a".into()),
            None,
        )
            .unwrap();
        assert!(
            !store
                .replace_account_credential_if_matches(
                    "openai-codex",
                    "acct-a",
                    &stale_a,
                    oauth("stale-refresh", "stale-next", "acct-a"),
                )
                .unwrap()
        );
        assert_eq!(
            store
                .account_credential("openai-codex", "acct-a")
                .and_then(|credential| credential.access.as_deref()),
            Some("newer-a")
        );

        let expected_b = store
            .account_credential("openai-codex", "acct-b")
            .cloned()
            .unwrap();
        assert!(store.remove_account("openai-codex", "acct-b").unwrap());
        assert!(
            !store
                .replace_account_credential_if_matches(
                    "openai-codex",
                    "acct-b",
                    &expected_b,
                    oauth("recreated", "never", "acct-b"),
                )
                .unwrap()
        );
        assert!(store.account_credential("openai-codex", "acct-b").is_none());
    }
}
