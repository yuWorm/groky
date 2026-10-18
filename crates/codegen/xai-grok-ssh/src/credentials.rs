use crate::auth::{Secret, SshError};
use keyring::Entry;

const SERVICE: &str = "com.xai.groky.ssh";

/// Thin adapter over the platform credential service. It intentionally has no
/// file-based fallback: a machine without a usable store simply cannot remember
/// an SSH secret.
#[derive(Debug, Default)]
pub(crate) struct CredentialStore;

impl CredentialStore {
    pub(crate) fn load(&self, credential_id: &str) -> Result<Option<Secret>, SshError> {
        let entry =
            Entry::new(SERVICE, credential_id).map_err(|_| SshError::CredentialStoreUnavailable)?;
        match entry.get_secret() {
            Ok(secret) => Ok(Some(Secret::from_owned(secret))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(_) => Err(SshError::CredentialStoreUnavailable),
        }
    }

    pub(crate) fn save(&self, credential_id: &str, secret: &Secret) -> Result<(), SshError> {
        let entry =
            Entry::new(SERVICE, credential_id).map_err(|_| SshError::CredentialStoreUnavailable)?;
        entry
            .set_secret(secret.bytes())
            .map_err(|_| SshError::CredentialStoreUnavailable)
    }

    pub(crate) fn forget(&self, credential_id: &str) -> Result<(), SshError> {
        let entry =
            Entry::new(SERVICE, credential_id).map_err(|_| SshError::CredentialStoreUnavailable)?;
        match entry.delete_credential() {
            Ok(()) => Ok(()),
            // A missing entry is distinct from an inaccessible credential store.
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(_) => Err(SshError::CredentialStoreUnavailable),
        }
    }
}
