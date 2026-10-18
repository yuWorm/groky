use crate::auth::{HostKeyDecision, HostKeyPrompt, HostKeyStatus, Interaction, SshError};
use crate::config::{HostKeyPolicy, KnownHostsConfig};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac};
use russh::keys::{
    HashAlg, PublicKey,
    ssh_key::known_hosts::{HostPatterns, KnownHosts, Marker},
};
use sha1::Sha1;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HostKeyCheck {
    Trusted,
    Unknown,
    Changed,
    Revoked,
}

pub(crate) fn fingerprint(key: &PublicKey) -> String {
    key.fingerprint(HashAlg::Sha256).to_string()
}

pub(crate) fn check(
    known_hosts: &KnownHostsConfig,
    hostname: &str,
    port: u16,
    server_key: &PublicKey,
) -> Result<HostKeyCheck, SshError> {
    let mut found_trusted_key = false;
    let mut found_different_key = false;

    for path in known_hosts
        .user_files
        .iter()
        .chain(known_hosts.global_files.iter())
    {
        let entries = read_entries(path)?;
        for entry in entries {
            if !entry_matches_host(entry.host_patterns(), hostname, port) {
                continue;
            }

            if entry.marker() == Some(&Marker::Revoked) && entry.public_key() == server_key {
                return Ok(HostKeyCheck::Revoked);
            }

            if entry.marker().is_none() && entry.public_key() == server_key {
                found_trusted_key = true;
                continue;
            }

            // A matching host record with any non-CA key is a conflicting host
            // identity. Do not allow `Ask`, `AcceptNew`, or `Off` to weaken it.
            if entry.marker() != Some(&Marker::CertAuthority) {
                found_different_key = true;
            }
        }
    }

    Ok(if found_different_key {
        HostKeyCheck::Changed
    } else if found_trusted_key {
        HostKeyCheck::Trusted
    } else {
        HostKeyCheck::Unknown
    })
}

pub(crate) async fn verify_or_prompt(
    known_hosts: &KnownHostsConfig,
    policy: HostKeyPolicy,
    target_id: &str,
    hostname: &str,
    port: u16,
    generation: u64,
    server_key: &PublicKey,
    interaction: &Arc<dyn Interaction>,
) -> Result<(), SshError> {
    match check(known_hosts, hostname, port, server_key)? {
        HostKeyCheck::Trusted => Ok(()),
        HostKeyCheck::Changed => Err(SshError::ChangedHostKey),
        HostKeyCheck::Revoked => Err(SshError::RevokedHostKey),
        HostKeyCheck::Unknown => match policy {
            HostKeyPolicy::Off => Ok(()),
            HostKeyPolicy::Require => Err(SshError::UnknownHostKey),
            HostKeyPolicy::AcceptNew => store_trusted_key(known_hosts, hostname, port, server_key),
            HostKeyPolicy::Ask => {
                let decision = interaction
                    .confirm_host_key(HostKeyPrompt {
                        challenge_id: Uuid::new_v4(),
                        connection_generation: generation,
                        target_id: target_id.to_owned(),
                        hostname: hostname.to_owned(),
                        port,
                        algorithm: server_key.algorithm().to_string(),
                        fingerprint: fingerprint(server_key),
                        status: HostKeyStatus::Unknown,
                    })
                    .await?;
                match decision {
                    HostKeyDecision::Reject => Err(SshError::HostKeyRejected),
                    HostKeyDecision::TrustOnce => Ok(()),
                    HostKeyDecision::TrustAndStore => {
                        store_trusted_key(known_hosts, hostname, port, server_key)
                    }
                }
            }
        },
    }
}

fn read_entries(path: &Path) -> Result<Vec<russh::keys::ssh_key::known_hosts::Entry>, SshError> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err(SshError::Configuration),
    };

    KnownHosts::new(&contents)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| SshError::Configuration)
}

fn entry_matches_host(patterns: &HostPatterns, hostname: &str, port: u16) -> bool {
    let port_host = format!("[{hostname}]:{port}");
    match patterns {
        HostPatterns::Patterns(patterns) => {
            let mut positive = false;
            for pattern in patterns {
                let (negated, pattern) = pattern
                    .strip_prefix('!')
                    .map_or((false, pattern.as_str()), |value| (true, value));
                let matches = glob_matches(pattern, hostname) || glob_matches(pattern, &port_host);
                if matches && negated {
                    return false;
                }
                positive |= matches;
            }
            positive
        }
        HostPatterns::HashedName { salt, hash } => {
            host_hash_matches(salt, hash, hostname) || host_hash_matches(salt, hash, &port_host)
        }
    }
}

fn host_hash_matches(salt: &[u8], hash: &[u8], hostname: &str) -> bool {
    let Ok(mut mac) = Hmac::<Sha1>::new_from_slice(salt) else {
        return false;
    };
    mac.update(hostname.as_bytes());
    mac.verify_slice(hash).is_ok()
}

fn glob_matches(pattern: &str, value: &str) -> bool {
    glob_matches_bytes(pattern.as_bytes(), value.as_bytes(), 0, 0)
}

fn glob_matches_bytes(
    pattern: &[u8],
    value: &[u8],
    mut pattern_index: usize,
    mut value_index: usize,
) -> bool {
    let mut wildcard = None;
    let mut retry_value = 0;

    while let Some(&pattern_byte) = pattern.get(pattern_index) {
        match pattern_byte {
            b'*' => {
                wildcard = Some(pattern_index);
                pattern_index += 1;
                retry_value = value_index;
            }
            b'?' if value.get(value_index).is_some() => {
                pattern_index += 1;
                value_index += 1;
            }
            byte if value
                .get(value_index)
                .is_some_and(|value_byte| byte.eq_ignore_ascii_case(value_byte)) =>
            {
                pattern_index += 1;
                value_index += 1;
            }
            _ => match wildcard {
                Some(wildcard_index) if value.get(retry_value).is_some() => {
                    pattern_index = wildcard_index + 1;
                    retry_value += 1;
                    value_index = retry_value;
                }
                _ => return false,
            },
        }
    }

    while pattern.get(pattern_index) == Some(&b'*') {
        pattern_index += 1;
    }
    value.get(value_index).is_none()
}

fn store_trusted_key(
    known_hosts: &KnownHostsConfig,
    hostname: &str,
    port: u16,
    server_key: &PublicKey,
) -> Result<(), SshError> {
    let path = writable_user_known_hosts(known_hosts)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|_| SshError::Configuration)?;
    }

    let host = stored_hostname(known_hosts, hostname, port)?;
    let line = format!(
        "{host} {}\n",
        server_key
            .to_openssh()
            .map_err(|_| SshError::Configuration)?
    );

    let mut options = OpenOptions::new();
    options.create(true).append(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|_| SshError::Configuration)?;
    file.write_all(line.as_bytes())
        .and_then(|()| file.sync_data())
        .map_err(|_| SshError::Configuration)
}

fn stored_hostname(
    known_hosts: &KnownHostsConfig,
    hostname: &str,
    port: u16,
) -> Result<String, SshError> {
    let hostname = if port == 22 {
        hostname.to_owned()
    } else {
        format!("[{hostname}]:{port}")
    };

    if known_hosts.hash_known_hosts != Some(true) {
        return Ok(hostname);
    }

    let mut salt = [0_u8; 20];
    getrandom::fill(&mut salt).map_err(|_| SshError::Configuration)?;
    let mut mac = Hmac::<Sha1>::new_from_slice(&salt).map_err(|_| SshError::Configuration)?;
    mac.update(hostname.as_bytes());
    let digest = mac.finalize().into_bytes();
    Ok(format!(
        "|1|{}|{}",
        STANDARD.encode(salt),
        STANDARD.encode(digest)
    ))
}

fn writable_user_known_hosts(known_hosts: &KnownHostsConfig) -> Result<&Path, SshError> {
    known_hosts
        .user_files
        .first()
        .map(|path| path.as_path())
        .ok_or(SshError::Configuration)
}

#[cfg(test)]
mod tests {
    use super::{entry_matches_host, glob_matches};
    use russh::keys::ssh_key::known_hosts::HostPatterns;

    #[test]
    fn glob_matching_handles_negation_and_ports() {
        assert!(glob_matches("*.example.test", "ssh.example.test"));
        assert!(!glob_matches("*.example.test", "ssh.example.org"));
        let patterns: HostPatterns = "*.example.test,!blocked.example.test".parse().unwrap();
        assert!(entry_matches_host(&patterns, "ssh.example.test", 22));
        assert!(!entry_matches_host(&patterns, "blocked.example.test", 22));
        let port: HostPatterns = "[ssh.example.test]:22486".parse().unwrap();
        assert!(entry_matches_host(&port, "ssh.example.test", 22486));
    }
}
