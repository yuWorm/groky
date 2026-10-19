use crate::auth::{HostKeyDecision, HostKeyPrompt, HostKeyStatus, Interaction, SshError};
use crate::config::{HostKeyPolicy, KnownHostsConfig};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac};
use russh::keys::{
    HashAlg, PublicKey,
    ssh_key::known_hosts::{Entry, HostPatterns, KnownHosts, Marker},
};
use sha1::Sha1;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use uuid::Uuid;
use xai_grok_config::fs_atomic::{self, BoundDest};

#[derive(Debug)]
pub(crate) enum HostKeyCheck {
    Trusted,
    Unknown,
    Changed(ChangedHostKey),
    Revoked,
}

#[derive(Debug)]
pub(crate) struct ChangedHostKey {
    previous_keys: Vec<String>,
    replacement: Option<ReplacementSnapshot>,
}

#[derive(Clone, Debug)]
struct ReplacementSnapshot {
    configured_path: PathBuf,
    destination: BoundDest,
    contents: Arc<String>,
    line: usize,
    aliases: Option<(String, String)>,
}

#[derive(Debug)]
struct KnownHostFile {
    destination: BoundDest,
    contents: Arc<String>,
    entries: Vec<KnownHostEntry>,
}

#[derive(Debug)]
struct KnownHostEntry {
    line: usize,
    entry: Entry,
}

#[derive(Debug)]
struct ChangedCandidate {
    previous_key: String,
    replacement: Option<ReplacementSnapshot>,
}

pub(crate) fn fingerprint(key: &PublicKey) -> String {
    key.fingerprint(HashAlg::Sha256).to_string()
}

fn keys_equal(left: &PublicKey, right: &PublicKey) -> bool {
    left.key_data() == right.key_data()
}

pub(crate) fn check(
    known_hosts: &KnownHostsConfig,
    hostname: &str,
    port: u16,
    server_key: &PublicKey,
) -> Result<HostKeyCheck, SshError> {
    let mut found_trusted_key = false;
    let mut changed = Vec::new();

    for (is_user_file, path) in known_hosts
        .user_files
        .iter()
        .map(|path| (true, path))
        .chain(known_hosts.global_files.iter().map(|path| (false, path)))
    {
        let file = read_entries(path)?;
        for known_host in &file.entries {
            let entry = &known_host.entry;
            if !entry_matches_host(entry.host_patterns(), hostname, port) {
                continue;
            }

            if entry.marker() == Some(&Marker::Revoked)
                && keys_equal(entry.public_key(), server_key)
            {
                return Ok(HostKeyCheck::Revoked);
            }

            if entry.marker().is_none() && keys_equal(entry.public_key(), server_key) {
                found_trusted_key = true;
                continue;
            }

            if entry.marker() != Some(&Marker::CertAuthority)
                && entry.public_key().algorithm() == server_key.algorithm()
            {
                changed.push(ChangedCandidate {
                    previous_key: previous_key_description(
                        path,
                        known_host.line,
                        entry.public_key(),
                    ),
                    replacement: (is_user_file && entry.marker().is_none())
                        .then(|| {
                            replacement_snapshot(path, &file, known_host, hostname, port, entry)
                        })
                        .flatten(),
                });
            }
        }
    }

    if found_trusted_key {
        return Ok(HostKeyCheck::Trusted);
    }
    if changed.is_empty() {
        return Ok(HostKeyCheck::Unknown);
    }

    let replacement = if changed.len() == 1 {
        changed
            .first_mut()
            .and_then(|candidate| candidate.replacement.take())
    } else {
        None
    };
    Ok(HostKeyCheck::Changed(ChangedHostKey {
        previous_keys: changed
            .into_iter()
            .map(|candidate| candidate.previous_key)
            .collect(),
        replacement,
    }))
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
        HostKeyCheck::Revoked => Err(SshError::RevokedHostKey),
        HostKeyCheck::Changed(changed) => {
            if policy != HostKeyPolicy::Ask {
                return Err(SshError::ChangedHostKey);
            }

            let ChangedHostKey {
                previous_keys,
                replacement,
            } = changed;
            let can_replace = replacement.is_some();
            let decision = interaction
                .confirm_host_key(HostKeyPrompt {
                    challenge_id: Uuid::new_v4(),
                    connection_generation: generation,
                    target_id: target_id.to_owned(),
                    hostname: hostname.to_owned(),
                    port,
                    algorithm: server_key.algorithm().to_string(),
                    fingerprint: fingerprint(server_key),
                    status: HostKeyStatus::Changed,
                    previous_keys,
                    can_replace,
                })
                .await?;
            match decision {
                HostKeyDecision::Reject => Err(SshError::HostKeyRejected),
                HostKeyDecision::ReplaceAndStore => match replacement {
                    Some(replacement) => replace_trusted_key(replacement, server_key),
                    None => Err(SshError::HostKeyReplacement(
                        "the matching records are not one exact user-owned endpoint entry; update the listed known_hosts entries manually"
                            .to_owned(),
                    )),
                },
                HostKeyDecision::TrustOnce | HostKeyDecision::TrustAndStore => {
                    Err(SshError::ChangedHostKey)
                }
            }
        }
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
                        previous_keys: Vec::new(),
                        can_replace: false,
                    })
                    .await?;
                match decision {
                    HostKeyDecision::Reject | HostKeyDecision::ReplaceAndStore => {
                        Err(SshError::HostKeyRejected)
                    }
                    HostKeyDecision::TrustOnce => Ok(()),
                    HostKeyDecision::TrustAndStore => {
                        store_trusted_key(known_hosts, hostname, port, server_key)
                    }
                }
            }
        },
    }
}

fn previous_key_description(path: &Path, line: usize, key: &PublicKey) -> String {
    format!(
        "{} {} at {}:{}",
        fingerprint(key),
        key.algorithm(),
        path.display(),
        line
    )
}

fn replacement_snapshot(
    path: &Path,
    file: &KnownHostFile,
    known_host: &KnownHostEntry,
    hostname: &str,
    port: u16,
    entry: &Entry,
) -> Option<ReplacementSnapshot> {
    let aliases = replacement_host_patterns(entry.host_patterns(), hostname, port)?;
    Some(ReplacementSnapshot {
        configured_path: path.to_path_buf(),
        destination: file.destination.clone(),
        contents: Arc::clone(&file.contents),
        line: known_host.line,
        aliases,
    })
}

fn replacement_host_patterns(
    patterns: &HostPatterns,
    hostname: &str,
    port: u16,
) -> Option<Option<(String, String)>> {
    match patterns {
        HostPatterns::HashedName { .. } => Some(None),
        HostPatterns::Patterns(patterns) => {
            if patterns.iter().any(|pattern| {
                pattern.starts_with('!')
                    || pattern
                        .as_bytes()
                        .iter()
                        .any(|byte| matches!(byte, b'*' | b'?'))
            }) {
                return None;
            }

            let endpoint = stored_endpoint(hostname, port);
            let mut matching = None;
            for (index, pattern) in patterns.iter().enumerate() {
                if pattern.eq_ignore_ascii_case(&endpoint) {
                    if matching.replace(index).is_some() {
                        return None;
                    }
                }
            }
            let matching = matching?;
            if patterns.len() == 1 {
                return Some(None);
            }

            let aliases_capacity = patterns
                .iter()
                .enumerate()
                .filter(|(index, _)| *index != matching)
                .map(|(_, pattern)| pattern.len())
                .sum::<usize>()
                .saturating_add(patterns.len().saturating_sub(2));
            let mut aliases = String::with_capacity(aliases_capacity);
            for (index, pattern) in patterns.iter().enumerate() {
                if index == matching {
                    continue;
                }
                if !aliases.is_empty() {
                    aliases.push(',');
                }
                aliases.push_str(pattern);
            }
            Some(Some((patterns.get(matching)?.clone(), aliases)))
        }
    }
}

fn read_entries(path: &Path) -> Result<KnownHostFile, SshError> {
    let destination =
        fs_atomic::bind_follow_destination(path).map_err(|_| SshError::Configuration)?;
    let contents = match fs::read_to_string(destination.as_path()) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(_) => return Err(SshError::Configuration),
    };
    let destination = fs_atomic::require_same_bound_destination(path, &destination)
        .map_err(|_| SshError::Configuration)?;
    let contents = Arc::new(contents);
    let mut entries = Vec::new();
    for (index, line) in contents.lines().enumerate() {
        let Some(entry) = KnownHosts::new(line).next() else {
            continue;
        };
        entries.push(KnownHostEntry {
            line: index + 1,
            entry: entry.map_err(|_| SshError::Configuration)?,
        });
    }
    Ok(KnownHostFile {
        destination,
        contents,
        entries,
    })
}

fn entry_matches_host(patterns: &HostPatterns, hostname: &str, port: u16) -> bool {
    let port_host = (port != 22).then(|| format!("[{hostname}]:{port}"));
    let endpoint = port_host.as_deref().unwrap_or(hostname);
    match patterns {
        HostPatterns::Patterns(patterns) => {
            let mut positive = false;
            for pattern in patterns {
                let (negated, pattern) = pattern
                    .strip_prefix('!')
                    .map_or((false, pattern.as_str()), |value| (true, value));
                let matches = glob_matches(pattern, endpoint);
                if matches && negated {
                    return false;
                }
                positive |= matches;
            }
            positive
        }
        HostPatterns::HashedName { salt, hash } => host_hash_matches(salt, hash, endpoint),
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

fn replace_trusted_key(
    replacement: ReplacementSnapshot,
    server_key: &PublicKey,
) -> Result<(), SshError> {
    let destination = fs_atomic::require_same_bound_destination(
        &replacement.configured_path,
        &replacement.destination,
    )
    .map_err(|_| {
        SshError::HostKeyReplacement(
            "known_hosts changed while confirmation was pending; review the listed entries and reconnect"
                .to_owned(),
        )
    })?;
    let contents = fs::read_to_string(destination.as_path()).map_err(|error| {
        SshError::HostKeyReplacement(format!(
            "could not read {} before updating it: {error}",
            destination.as_path().display()
        ))
    })?;
    if contents != replacement.contents.as_str() {
        return Err(SshError::HostKeyReplacement(
            "known_hosts changed while confirmation was pending; review the listed entries and reconnect"
                .to_owned(),
        ));
    }

    let updated = replacement_contents(&replacement, server_key)?;
    save_backup(destination.as_path(), &contents)?;

    let destination = fs_atomic::require_same_bound_destination(
        &replacement.configured_path,
        &destination,
    )
    .map_err(|_| {
        SshError::HostKeyReplacement(
            "known_hosts changed while its backup was being saved; review the listed entries and reconnect"
                .to_owned(),
        )
    })?;
    let current = fs::read_to_string(destination.as_path()).map_err(|error| {
        SshError::HostKeyReplacement(format!(
            "could not re-read {} before updating it: {error}",
            destination.as_path().display()
        ))
    })?;
    if current != contents {
        return Err(SshError::HostKeyReplacement(
            "known_hosts changed while its backup was being saved; review the listed entries and reconnect"
                .to_owned(),
        ));
    }

    fs_atomic::write_atomically_bound(&destination, &updated, None).map_err(|error| {
        SshError::HostKeyReplacement(format!(
            "could not atomically update {}: {error}",
            destination.as_path().display()
        ))
    })
}

fn replacement_contents(
    replacement: &ReplacementSnapshot,
    server_key: &PublicKey,
) -> Result<String, SshError> {
    let contents = replacement.contents.as_str();
    let (start, end) = line_range(contents, replacement.line).ok_or_else(|| {
        SshError::HostKeyReplacement(
            "the matching known_hosts line could not be safely located; update it manually"
                .to_owned(),
        )
    })?;
    let line = &contents[start..end];
    let (body, line_ending) = if let Some(body) = line.strip_suffix("\r\n") {
        (body, "\r\n")
    } else if let Some(body) = line.strip_suffix('\n') {
        (body, "\n")
    } else {
        (line, "")
    };
    let fields = field_ranges(body);
    let host_index = fields
        .first()
        .is_some_and(|field| body[field.0..field.1].starts_with('@'))
        .then_some(1)
        .unwrap_or(0);
    let (Some(host), Some(algorithm), Some(key_data)) = (
        fields.get(host_index),
        fields.get(host_index + 1),
        fields.get(host_index + 2),
    ) else {
        return Err(SshError::HostKeyReplacement(
            "the matching known_hosts line is no longer a plain host-key record; update it manually"
                .to_owned(),
        ));
    };
    let encoded = server_key.to_openssh().map_err(|_| {
        SshError::HostKeyReplacement(
            "the replacement host key could not be encoded for known_hosts".to_owned(),
        )
    })?;
    let mut key_fields = encoded.split_ascii_whitespace();
    let (Some(new_algorithm), Some(new_key_data)) = (key_fields.next(), key_fields.next()) else {
        return Err(SshError::HostKeyReplacement(
            "the replacement host key could not be encoded for known_hosts".to_owned(),
        ));
    };

    let replacement_line = match &replacement.aliases {
        None => {
            let mut updated =
                replace_key_fields(body, *algorithm, *key_data, new_algorithm, new_key_data);
            updated.push_str(line_ending);
            updated
        }
        Some((replacement_host, aliases)) => {
            let retained = replace_field(body, *host, aliases);
            let terminator = if line_ending.is_empty() {
                "\n"
            } else {
                line_ending
            };
            format!(
                "{retained}{terminator}{replacement_host} {new_algorithm} {new_key_data}{terminator}"
            )
        }
    };

    let mut updated = String::with_capacity(
        contents
            .len()
            .saturating_sub(line.len())
            .saturating_add(replacement_line.len()),
    );
    updated.push_str(&contents[..start]);
    updated.push_str(&replacement_line);
    updated.push_str(&contents[end..]);
    Ok(updated)
}

fn line_range(contents: &str, line: usize) -> Option<(usize, usize)> {
    let mut start = 0;
    for index in 1..=line {
        let end = contents[start..]
            .find('\n')
            .map(|offset| start + offset + 1)
            .unwrap_or(contents.len());
        if index == line {
            return (start != end).then_some((start, end));
        }
        start = end;
    }
    None
}

fn field_ranges(line: &str) -> Vec<(usize, usize)> {
    let mut fields = Vec::new();
    let bytes = line.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        while bytes.get(index).is_some_and(u8::is_ascii_whitespace) {
            index += 1;
        }
        let start = index;
        while bytes
            .get(index)
            .is_some_and(|byte| !byte.is_ascii_whitespace())
        {
            index += 1;
        }
        if start != index {
            fields.push((start, index));
        }
    }
    fields
}

fn replace_key_fields(
    line: &str,
    algorithm: (usize, usize),
    key_data: (usize, usize),
    new_algorithm: &str,
    new_key_data: &str,
) -> String {
    let mut updated = String::with_capacity(
        line.len()
            .saturating_sub(algorithm.1 - algorithm.0)
            .saturating_sub(key_data.1 - key_data.0)
            .saturating_add(new_algorithm.len())
            .saturating_add(new_key_data.len()),
    );
    updated.push_str(&line[..algorithm.0]);
    updated.push_str(new_algorithm);
    updated.push_str(&line[algorithm.1..key_data.0]);
    updated.push_str(new_key_data);
    updated.push_str(&line[key_data.1..]);
    updated
}

fn replace_field(line: &str, field: (usize, usize), replacement: &str) -> String {
    let mut updated =
        String::with_capacity(line.len().saturating_sub(field.1 - field.0) + replacement.len());
    updated.push_str(&line[..field.0]);
    updated.push_str(replacement);
    updated.push_str(&line[field.1..]);
    updated
}

fn save_backup(path: &Path, contents: &str) -> Result<(), SshError> {
    let mode = fs_atomic::unix_file_mode(path);
    for suffix in 0..1000 {
        let mut backup = path.as_os_str().to_os_string();
        backup.push(".old");
        if suffix != 0 {
            backup.push(format!(".{suffix}"));
        }
        let backup = PathBuf::from(backup);
        match fs_atomic::write_atomically_if_absent(&backup, contents, mode) {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(SshError::HostKeyReplacement(format!(
                    "could not save a backup at {}: {error}",
                    backup.display()
                )));
            }
        }
    }
    Err(SshError::HostKeyReplacement(
        "could not save a unique known_hosts backup; update the listed entries manually".to_owned(),
    ))
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
    let hostname = stored_endpoint(hostname, port);

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

fn stored_endpoint(hostname: &str, port: u16) -> String {
    if port == 22 {
        hostname.to_owned()
    } else {
        format!("[{hostname}]:{port}")
    }
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
    use super::{
        HostKeyCheck, check, entry_matches_host, fingerprint, glob_matches, verify_or_prompt,
    };
    use crate::auth::{
        HostKeyDecision, HostKeyPrompt, HostKeyStatus, Interaction, InteractionError,
        KeyboardInteractivePrompt, Secret, SecretPrompt, SshError,
    };
    use crate::config::{HostKeyPolicy, KnownHostsConfig};
    use async_trait::async_trait;
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use hmac::{Hmac, Mac};
    use russh::keys::{PublicKey, ssh_key::known_hosts::HostPatterns};
    use sha1::Sha1;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use tempfile::tempdir;

    const ED25519_A: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti";
    const ED25519_B: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB9dG4kjRhQTtWTVzd2t27+t0DEHBPW7iOD23TUiYLio";
    const ECDSA: &str = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHwf2HMM5TRXvo2SQJjsNkiDD5KqiiNjrGVv3UUh+mMT5RHxiRtOnlqvjhQtBq0VpmpCV/PwUdhOig4vkbqAcEc=";

    struct TestInteraction {
        response: Result<HostKeyDecision, InteractionError>,
        prompts: Arc<Mutex<Vec<HostKeyPrompt>>>,
        mutation: Option<(PathBuf, String)>,
    }

    #[async_trait]
    impl Interaction for TestInteraction {
        async fn confirm_host_key(
            &self,
            prompt: HostKeyPrompt,
        ) -> Result<HostKeyDecision, InteractionError> {
            if let Some((path, contents)) = &self.mutation {
                fs::write(path, contents).expect("concurrent known_hosts fixture update");
            }
            self.prompts.lock().expect("prompt mutex").push(prompt);
            self.response
        }

        async fn request_secret(&self, _prompt: SecretPrompt) -> Result<Secret, InteractionError> {
            Err(InteractionError::Unavailable)
        }

        async fn request_keyboard_interactive(
            &self,
            _prompt: KeyboardInteractivePrompt,
        ) -> Result<Vec<Secret>, InteractionError> {
            Err(InteractionError::Unavailable)
        }
    }

    fn scripted_interaction(
        response: Result<HostKeyDecision, InteractionError>,
        mutation: Option<(PathBuf, String)>,
    ) -> (Arc<dyn Interaction>, Arc<Mutex<Vec<HostKeyPrompt>>>) {
        let prompts = Arc::new(Mutex::new(Vec::new()));
        (
            Arc::new(TestInteraction {
                response,
                prompts: Arc::clone(&prompts),
                mutation,
            }),
            prompts,
        )
    }

    fn key(value: &str) -> PublicKey {
        PublicKey::from_openssh(value).expect("valid public-key fixture")
    }

    fn known_host_line(host: &str, key: &PublicKey) -> String {
        format!(
            "{host} {}\n",
            key.to_openssh().expect("serializable public-key fixture")
        )
    }

    fn known_hosts(user_files: Vec<PathBuf>, global_files: Vec<PathBuf>) -> KnownHostsConfig {
        KnownHostsConfig {
            user_files,
            global_files,
            hash_known_hosts: None,
        }
    }

    fn hashed_hostname(hostname: &str) -> String {
        let salt = [0x5a_u8; 20];
        let mut mac = Hmac::<Sha1>::new_from_slice(&salt).expect("valid HMAC salt");
        mac.update(hostname.as_bytes());
        format!(
            "|1|{}|{}",
            STANDARD.encode(salt),
            STANDARD.encode(mac.finalize().into_bytes())
        )
    }

    #[tokio::test]
    async fn endpoint_matching_separates_default_nondefault_and_hashed_hosts() {
        let bare: HostPatterns = "ssh.example.test".parse().expect("host pattern");
        let nondefault: HostPatterns = "[ssh.example.test]:22486".parse().expect("host pattern");
        assert!(entry_matches_host(&bare, "ssh.example.test", 22));
        assert!(!entry_matches_host(&bare, "ssh.example.test", 22486));
        assert!(!entry_matches_host(&nondefault, "ssh.example.test", 22));
        assert!(entry_matches_host(&nondefault, "ssh.example.test", 22486));

        assert!(glob_matches("*.example.test", "ssh.example.test"));
        assert!(!glob_matches("*.example.test", "ssh.example.org"));
        let negated: HostPatterns = "*.example.test,!blocked.example.test"
            .parse()
            .expect("host patterns");
        assert!(entry_matches_host(&negated, "ssh.example.test", 22));
        assert!(!entry_matches_host(&negated, "blocked.example.test", 22));

        let directory = tempdir().expect("temporary directory");
        let file = directory.path().join("known_hosts");
        let ed25519_a = key(ED25519_A);
        let ed25519_b = key(ED25519_B);
        let ecdsa = key(ECDSA);
        fs::write(
            &file,
            format!(
                "{}{}{}{}",
                known_host_line("bare.example.test", &ed25519_a),
                known_host_line("[port.example.test]:22486", &ed25519_b),
                known_host_line(&hashed_hostname("hash.example.test"), &ecdsa),
                known_host_line(&hashed_hostname("[hash.example.test]:22486"), &ed25519_a),
            ),
        )
        .expect("known_hosts fixture");
        let config = known_hosts(vec![file], Vec::new());

        assert!(matches!(
            check(&config, "bare.example.test", 22, &ed25519_a),
            Ok(HostKeyCheck::Trusted)
        ));
        assert!(matches!(
            check(&config, "bare.example.test", 22486, &ed25519_a),
            Ok(HostKeyCheck::Unknown)
        ));
        assert!(matches!(
            check(&config, "port.example.test", 22, &ed25519_b),
            Ok(HostKeyCheck::Unknown)
        ));
        assert!(matches!(
            check(&config, "port.example.test", 22486, &ed25519_b),
            Ok(HostKeyCheck::Trusted)
        ));
        assert!(matches!(
            check(&config, "hash.example.test", 22, &ecdsa),
            Ok(HostKeyCheck::Trusted)
        ));
        assert!(matches!(
            check(&config, "hash.example.test", 22486, &ed25519_a),
            Ok(HostKeyCheck::Trusted)
        ));
        assert!(matches!(
            check(&config, "hash.example.test", 22, &ed25519_a),
            Ok(HostKeyCheck::Unknown)
        ));

        let (interaction, prompts) = scripted_interaction(Ok(HostKeyDecision::Reject), None);
        verify_or_prompt(
            &config,
            HostKeyPolicy::Ask,
            "target",
            "port.example.test",
            22486,
            1,
            &ed25519_b,
            &interaction,
        )
        .await
        .expect("stored nondefault-port key must connect without a prompt");
        assert!(prompts.lock().expect("prompt mutex").is_empty());
    }

    #[tokio::test]
    async fn exact_unmarked_key_wins_over_other_algorithms_and_stale_keys() {
        let directory = tempdir().expect("temporary directory");
        let file = directory.path().join("known_hosts");
        let ed25519_a = key(ED25519_A);
        let ed25519_b = key(ED25519_B);
        let ecdsa = key(ECDSA);
        fs::write(
            &file,
            format!(
                "{} {} stale key comment\n{}{}",
                "ssh.example.test",
                ed25519_b.to_openssh().expect("serializable fixture"),
                known_host_line("ssh.example.test", &ecdsa),
                known_host_line("ssh.example.test", &ed25519_a),
            ),
        )
        .expect("known_hosts fixture");
        let config = known_hosts(vec![file], Vec::new());

        assert!(matches!(
            check(&config, "ssh.example.test", 22, &ed25519_a),
            Ok(HostKeyCheck::Trusted)
        ));
        let (interaction, prompts) = scripted_interaction(Ok(HostKeyDecision::Reject), None);
        verify_or_prompt(
            &config,
            HostKeyPolicy::Ask,
            "target",
            "ssh.example.test",
            22,
            1,
            &ed25519_a,
            &interaction,
        )
        .await
        .expect("an exact stored key must connect without a prompt");
        assert!(prompts.lock().expect("prompt mutex").is_empty());
    }

    #[tokio::test]
    async fn changed_keys_reject_invalid_decisions_and_non_ask_policies() {
        let directory = tempdir().expect("temporary directory");
        let file = directory.path().join("known_hosts");
        let ed25519_a = key(ED25519_A);
        let ed25519_b = key(ED25519_B);
        let contents = known_host_line("ssh.example.test", &ed25519_a);
        fs::write(&file, &contents).expect("known_hosts fixture");
        let config = known_hosts(vec![file.clone()], Vec::new());

        for decision in [HostKeyDecision::TrustOnce, HostKeyDecision::TrustAndStore] {
            let (interaction, prompts) = scripted_interaction(Ok(decision), None);
            assert!(matches!(
                verify_or_prompt(
                    &config,
                    HostKeyPolicy::Ask,
                    "target",
                    "ssh.example.test",
                    22,
                    1,
                    &ed25519_b,
                    &interaction,
                )
                .await,
                Err(SshError::ChangedHostKey)
            ));
            assert_eq!(prompts.lock().expect("prompt mutex").len(), 1);
            assert_eq!(fs::read_to_string(&file).expect("known_hosts"), contents);
        }

        let (interaction, prompts) = scripted_interaction(Ok(HostKeyDecision::Reject), None);
        assert!(matches!(
            verify_or_prompt(
                &config,
                HostKeyPolicy::Ask,
                "target",
                "ssh.example.test",
                22,
                1,
                &ed25519_b,
                &interaction,
            )
            .await,
            Err(SshError::HostKeyRejected)
        ));
        assert_eq!(prompts.lock().expect("prompt mutex").len(), 1);
        assert_eq!(fs::read_to_string(&file).expect("known_hosts"), contents);

        let (interaction, prompts) = scripted_interaction(Err(InteractionError::Cancelled), None);
        assert!(matches!(
            verify_or_prompt(
                &config,
                HostKeyPolicy::Ask,
                "target",
                "ssh.example.test",
                22,
                1,
                &ed25519_b,
                &interaction,
            )
            .await,
            Err(SshError::Interaction(InteractionError::Cancelled))
        ));
        assert_eq!(prompts.lock().expect("prompt mutex").len(), 1);

        for policy in [
            HostKeyPolicy::AcceptNew,
            HostKeyPolicy::Require,
            HostKeyPolicy::Off,
        ] {
            let (interaction, prompts) =
                scripted_interaction(Ok(HostKeyDecision::ReplaceAndStore), None);
            assert!(matches!(
                verify_or_prompt(
                    &config,
                    policy,
                    "target",
                    "ssh.example.test",
                    22,
                    1,
                    &ed25519_b,
                    &interaction,
                )
                .await,
                Err(SshError::ChangedHostKey)
            ));
            assert!(prompts.lock().expect("prompt mutex").is_empty());
            assert_eq!(fs::read_to_string(&file).expect("known_hosts"), contents);
        }

        let (interaction, prompts) = scripted_interaction(Ok(HostKeyDecision::TrustOnce), None);
        assert!(matches!(
            verify_or_prompt(
                &config,
                HostKeyPolicy::Require,
                "target",
                "new.example.test",
                22,
                1,
                &ed25519_b,
                &interaction,
            )
            .await,
            Err(SshError::UnknownHostKey)
        ));
        assert!(prompts.lock().expect("prompt mutex").is_empty());

        let (interaction, prompts) = scripted_interaction(Ok(HostKeyDecision::TrustOnce), None);
        verify_or_prompt(
            &config,
            HostKeyPolicy::Ask,
            "target",
            "unknown.example.test",
            22,
            1,
            &ed25519_b,
            &interaction,
        )
        .await
        .expect("unknown key trusted once");
        let unknown_prompt = prompts
            .lock()
            .expect("prompt mutex")
            .first()
            .cloned()
            .expect("unknown-key prompt");
        assert_eq!(unknown_prompt.status, HostKeyStatus::Unknown);
        assert!(unknown_prompt.previous_keys.is_empty());
        assert!(!unknown_prompt.can_replace);
    }

    #[tokio::test]
    async fn replace_and_store_updates_only_one_exact_user_record() {
        let directory = tempdir().expect("temporary directory");
        let file = directory.path().join("known_hosts");
        let ed25519_a = key(ED25519_A);
        let ed25519_b = key(ED25519_B);
        let ecdsa = key(ECDSA);
        let old_key = ed25519_a.to_openssh().expect("serializable fixture");
        let contents = format!(
            "# preserved comment\nssh.example.test,alias.example.test {old_key} stale key comment\n{}",
            known_host_line("other.example.test", &ecdsa),
        );
        fs::write(&file, &contents).expect("known_hosts fixture");
        let config = known_hosts(vec![file.clone()], Vec::new());
        let (interaction, prompts) =
            scripted_interaction(Ok(HostKeyDecision::ReplaceAndStore), None);

        verify_or_prompt(
            &config,
            HostKeyPolicy::Ask,
            "target",
            "ssh.example.test",
            22,
            7,
            &ed25519_b,
            &interaction,
        )
        .await
        .expect("safe exact host key replacement");

        let prompt = prompts
            .lock()
            .expect("prompt mutex")
            .first()
            .cloned()
            .expect("changed-key prompt");
        assert_eq!(prompt.status, HostKeyStatus::Changed);
        assert!(prompt.can_replace);
        assert_eq!(prompt.fingerprint, fingerprint(&ed25519_b));
        assert_eq!(prompt.previous_keys.len(), 1);
        assert!(prompt.previous_keys[0].contains(&fingerprint(&ed25519_a)));
        assert!(prompt.previous_keys[0].contains("ssh-ed25519"));
        assert!(prompt.previous_keys[0].contains(&format!("{}:2", file.display())));

        let updated = fs::read_to_string(&file).expect("updated known_hosts");
        assert!(updated.contains("# preserved comment\n"));
        assert!(updated.contains(&format!("alias.example.test {old_key} stale key comment\n")));
        assert!(updated.contains(&known_host_line("other.example.test", &ecdsa)));
        assert!(updated.contains(&known_host_line("ssh.example.test", &ed25519_b)));
        assert_eq!(
            fs::read_to_string(PathBuf::from(format!("{}.old", file.display())))
                .expect("known_hosts backup"),
            contents
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(&file)
                    .expect("updated metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                fs::metadata(PathBuf::from(format!("{}.old", file.display())))
                    .expect("backup metadata")
                    .permissions()
                    .mode()
                    & 0o777
            );
        }
        assert!(matches!(
            check(&config, "ssh.example.test", 22, &ed25519_b),
            Ok(HostKeyCheck::Trusted)
        ));

        let single = directory.path().join("single");
        let single_contents = format!(
            "{}{}",
            known_host_line("single.example.test", &ed25519_a),
            known_host_line("unrelated.example.test", &ecdsa),
        );
        fs::write(&single, &single_contents).expect("single-record fixture");
        let single_config = known_hosts(vec![single.clone()], Vec::new());
        let (interaction, _) = scripted_interaction(Ok(HostKeyDecision::ReplaceAndStore), None);
        verify_or_prompt(
            &single_config,
            HostKeyPolicy::Ask,
            "target",
            "single.example.test",
            22,
            7,
            &ed25519_b,
            &interaction,
        )
        .await
        .expect("single exact host key replacement");
        assert_eq!(
            fs::read_to_string(&single).expect("single updated known_hosts"),
            format!(
                "{}{}",
                known_host_line("single.example.test", &ed25519_b),
                known_host_line("unrelated.example.test", &ecdsa),
            )
        );
    }

    #[tokio::test]
    async fn unsafe_or_stale_changed_records_are_never_overwritten() {
        let directory = tempdir().expect("temporary directory");
        let ed25519_a = key(ED25519_A);
        let ed25519_b = key(ED25519_B);

        let wildcard = directory.path().join("wildcard");
        let wildcard_contents = known_host_line("*.example.test,!blocked.example.test", &ed25519_a);
        fs::write(&wildcard, &wildcard_contents).expect("wildcard fixture");
        let wildcard_config = known_hosts(vec![wildcard.clone()], Vec::new());
        let (interaction, prompts) =
            scripted_interaction(Ok(HostKeyDecision::ReplaceAndStore), None);
        assert!(matches!(
            verify_or_prompt(
                &wildcard_config,
                HostKeyPolicy::Ask,
                "target",
                "ssh.example.test",
                22,
                1,
                &ed25519_b,
                &interaction,
            )
            .await,
            Err(SshError::HostKeyReplacement(_))
        ));
        assert!(
            !prompts
                .lock()
                .expect("prompt mutex")
                .first()
                .expect("changed prompt")
                .can_replace
        );
        assert_eq!(
            fs::read_to_string(&wildcard).expect("wildcard known_hosts"),
            wildcard_contents
        );

        let global = directory.path().join("global");
        let global_contents = known_host_line("global.example.test", &ed25519_a);
        fs::write(&global, &global_contents).expect("global fixture");
        let global_config = known_hosts(
            vec![directory.path().join("user-known-hosts")],
            vec![global.clone()],
        );
        let (interaction, prompts) =
            scripted_interaction(Ok(HostKeyDecision::ReplaceAndStore), None);
        assert!(matches!(
            verify_or_prompt(
                &global_config,
                HostKeyPolicy::Ask,
                "target",
                "global.example.test",
                22,
                1,
                &ed25519_b,
                &interaction,
            )
            .await,
            Err(SshError::HostKeyReplacement(_))
        ));
        assert!(
            !prompts
                .lock()
                .expect("prompt mutex")
                .first()
                .expect("changed prompt")
                .can_replace
        );
        assert_eq!(
            fs::read_to_string(&global).expect("global known_hosts"),
            global_contents
        );

        let authority = directory.path().join("authority");
        let authority_contents = format!(
            "@cert-authority {}",
            known_host_line("ca.example.test", &ed25519_a)
        );
        fs::write(&authority, &authority_contents).expect("CA fixture");
        let authority_config = known_hosts(vec![authority.clone()], Vec::new());
        let (interaction, prompts) =
            scripted_interaction(Ok(HostKeyDecision::ReplaceAndStore), None);
        assert!(matches!(
            verify_or_prompt(
                &authority_config,
                HostKeyPolicy::Ask,
                "target",
                "ca.example.test",
                22,
                1,
                &ed25519_b,
                &interaction,
            )
            .await,
            Err(SshError::HostKeyRejected)
        ));
        let authority_prompt = prompts
            .lock()
            .expect("prompt mutex")
            .first()
            .cloned()
            .expect("unknown-key prompt");
        assert_eq!(authority_prompt.status, HostKeyStatus::Unknown);
        assert!(!authority_prompt.can_replace);
        assert_eq!(
            fs::read_to_string(&authority).expect("CA known_hosts"),
            authority_contents
        );

        let revoked = directory.path().join("revoked");
        let revoked_contents = format!(
            "@revoked {}",
            known_host_line("revoked.example.test", &ed25519_a)
        );
        fs::write(&revoked, &revoked_contents).expect("revoked fixture");
        let revoked_config = known_hosts(vec![revoked.clone()], Vec::new());
        let (interaction, prompts) =
            scripted_interaction(Ok(HostKeyDecision::ReplaceAndStore), None);
        assert!(matches!(
            verify_or_prompt(
                &revoked_config,
                HostKeyPolicy::Ask,
                "target",
                "revoked.example.test",
                22,
                1,
                &ed25519_a,
                &interaction,
            )
            .await,
            Err(SshError::RevokedHostKey)
        ));
        assert!(prompts.lock().expect("prompt mutex").is_empty());
        assert_eq!(
            fs::read_to_string(&revoked).expect("revoked known_hosts"),
            revoked_contents
        );

        let first = directory.path().join("first");
        let second = directory.path().join("second");
        let multi_contents = known_host_line("multi.example.test", &ed25519_a);
        fs::write(&first, &multi_contents).expect("first fixture");
        fs::write(&second, &multi_contents).expect("second fixture");
        let multi_config = known_hosts(vec![first.clone(), second.clone()], Vec::new());
        let (interaction, prompts) =
            scripted_interaction(Ok(HostKeyDecision::ReplaceAndStore), None);
        assert!(matches!(
            verify_or_prompt(
                &multi_config,
                HostKeyPolicy::Ask,
                "target",
                "multi.example.test",
                22,
                1,
                &ed25519_b,
                &interaction,
            )
            .await,
            Err(SshError::HostKeyReplacement(_))
        ));
        assert!(
            !prompts
                .lock()
                .expect("prompt mutex")
                .first()
                .expect("changed prompt")
                .can_replace
        );
        assert_eq!(
            fs::read_to_string(&first).expect("first known_hosts"),
            multi_contents
        );
        assert_eq!(
            fs::read_to_string(&second).expect("second known_hosts"),
            multi_contents
        );

        let stale = directory.path().join("stale");
        let stale_contents = known_host_line("stale.example.test", &ed25519_a);
        let concurrent_contents = format!("{stale_contents}# concurrent update\n");
        fs::write(&stale, &stale_contents).expect("stale fixture");
        let stale_config = known_hosts(vec![stale.clone()], Vec::new());
        let (interaction, prompts) = scripted_interaction(
            Ok(HostKeyDecision::ReplaceAndStore),
            Some((stale.clone(), concurrent_contents.clone())),
        );
        assert!(matches!(
            verify_or_prompt(
                &stale_config,
                HostKeyPolicy::Ask,
                "target",
                "stale.example.test",
                22,
                1,
                &ed25519_b,
                &interaction,
            )
            .await,
            Err(SshError::HostKeyReplacement(_))
        ));
        assert!(
            prompts
                .lock()
                .expect("prompt mutex")
                .first()
                .expect("changed prompt")
                .can_replace
        );
        assert_eq!(
            fs::read_to_string(&stale).expect("stale known_hosts"),
            concurrent_contents
        );
        assert!(!PathBuf::from(format!("{}.old", stale.display())).exists());
    }
}
