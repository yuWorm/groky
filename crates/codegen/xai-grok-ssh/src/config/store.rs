use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::time::Duration;

use fs2::FileExt;
use toml::Value;
use toml::map::Map;

use super::parser::{self, ImportedAlias};
use super::{ConfigError, SshTarget, TargetSource, default_worker_command};

const CONFIG_INIT_LOCK: &str = ".config-init.lock";
const USER_CONFIG: &str = "config.toml";

/// User-global target persistence plus SSH configuration discovery. It never
/// accepts a workspace path, preventing repository configuration from changing
/// a target's host, user, credential reference, or route.
#[derive(Debug, Clone)]
pub struct TargetStore {
    home: PathBuf,
    ssh_home: PathBuf,
    user_ssh_config: PathBuf,
    system_ssh_config: PathBuf,
}

impl TargetStore {
    /// Construct a store rooted at the process's global Groky home directory.
    #[must_use]
    pub fn new(home: PathBuf) -> Self {
        let ssh_home = user_home_dir().unwrap_or_else(|| home.join(".ssh-home-unavailable"));
        let user_ssh_config = ssh_home.join(".ssh").join("config");
        let system_ssh_config = default_system_ssh_config();
        Self {
            home,
            ssh_home,
            user_ssh_config,
            system_ssh_config,
        }
    }

    /// Construct a store with explicit global OpenSSH locations. This is useful
    /// for embedders with a nonstandard OS SSH layout and deterministic tests.
    #[must_use]
    pub fn with_ssh_config_paths(
        home: PathBuf,
        ssh_home: PathBuf,
        user_ssh_config: PathBuf,
        system_ssh_config: PathBuf,
    ) -> Self {
        Self {
            home,
            ssh_home,
            user_ssh_config,
            system_ssh_config,
        }
    }

    /// List manually saved targets followed by literal aliases imported from
    /// user/system SSH configuration. This operation never executes commands.
    pub fn list(&self) -> Result<Vec<SshTarget>, ConfigError> {
        let mut targets = self.load_user_targets()?;
        targets.sort_by(|left, right| left.id.cmp(&right.id));
        let imported = parser::imported_aliases(
            &self.user_ssh_config,
            &self.system_ssh_config,
            &self.ssh_home,
        )?;
        targets.extend(imported.into_iter().map(imported_target));
        Ok(targets)
    }

    /// Resolve a target reference without ever choosing a matching target by
    /// position. Stable IDs take precedence, followed by imported OpenSSH
    /// aliases, then an exact unique display label or host. This parsing-only
    /// lookup never opens a connection.
    pub fn resolve_reference(&self, reference: &str) -> Result<Option<SshTarget>, ConfigError> {
        Ok(Self::resolve_configured_reference(reference, self.list()?.iter())?.cloned())
    }

    /// Resolve against a loaded configuration snapshot, including repeated grant rows.
    /// Matching precedence is identical to [`Self::resolve_reference`].
    pub fn resolve_configured_reference<'a>(
        reference: &str,
        targets: impl Iterator<Item = &'a SshTarget> + Clone,
    ) -> Result<Option<&'a SshTarget>, ConfigError> {
        if let Some(target) = unique_target_reference(
            reference,
            targets.clone().filter(|target| target.id == reference),
        )? {
            return Ok(Some(target));
        }
        if let Some(target) = unique_target_reference(
            reference,
            targets.clone().filter(|target| {
                matches!(&target.source, TargetSource::Imported { .. })
                    && target.host == reference
            }),
        )? {
            return Ok(Some(target));
        }
        unique_target_reference(
            reference,
            targets
                .filter(|target| target.label == reference || target.host == reference),
        )
    }

    /// Return the stable target ID selected by [`Self::resolve_reference`].
    /// Authority-bearing callers must persist and compare this ID, never the
    /// caller-supplied label or host spelling.
    pub fn canonical_id(&self, reference: &str) -> Result<String, ConfigError> {
        self.resolve_reference(reference)?
            .map(|target| target.id)
            .ok_or_else(|| ConfigError::TargetNotFound(reference.to_owned()))
    }

    /// Compatibility lookup for callers that need the full configured target.
    /// It has the same exact and ambiguity-safe semantics as
    /// [`Self::resolve_reference`].
    pub fn get(&self, reference: &str) -> Result<Option<SshTarget>, ConfigError> {
        self.resolve_reference(reference)
    }

    /// Insert or replace a persisted user target. Imported aliases are a view
    /// over ssh_config and cannot be edited in-place.
    pub fn upsert(&self, mut target: SshTarget) -> Result<SshTarget, ConfigError> {
        if matches!(&target.source, TargetSource::Imported { .. }) {
            return Err(ConfigError::ImmutableImportedTarget(target.id));
        }
        validate_target(&target)?;
        target.source = TargetSource::User;
        let target_for_write = target.clone();
        self.mutate_config(move |root| {
            let target_table = ensure_targets_table(root)?;
            let existing = target_table.get(&target_for_write.id);
            let next = merge_target_value(existing, &target_for_write)?;
            if existing == Some(&next) {
                return Ok(false);
            }
            target_table.insert(target_for_write.id.clone(), next);
            Ok(true)
        })?;
        Ok(target)
    }

    /// Replace an existing manual target only when it still equals the caller's
    /// original snapshot. The check and write share the configuration lock so
    /// stale editors cannot overwrite another editor's changes.
    pub fn update(
        &self,
        expected: SshTarget,
        mut replacement: SshTarget,
    ) -> Result<SshTarget, ConfigError> {
        if matches!(&expected.source, TargetSource::Imported { .. })
            || matches!(&replacement.source, TargetSource::Imported { .. })
        {
            return Err(ConfigError::ImmutableImportedTarget(expected.id));
        }
        if replacement.id != expected.id {
            return Err(ConfigError::InvalidTarget(
                "target id cannot change during an update".to_owned(),
            ));
        }
        validate_target(&replacement)?;
        replacement.source = TargetSource::User;
        let id = expected.id.clone();
        let replacement_for_write = replacement.clone();
        self.mutate_config(move |root| {
            let Some(targets) = targets_table_mut(root)? else {
                return Err(ConfigError::StaleTarget(id.clone()));
            };
            let Some(existing) = targets.get(&id) else {
                return Err(ConfigError::StaleTarget(id.clone()));
            };
            let current = parse_stored_target(&id, existing, &self.config_path())?;
            if current != expected {
                return Err(ConfigError::StaleTarget(id.clone()));
            }
            let next = merge_target_value(Some(existing), &replacement_for_write)?;
            if existing == &next {
                return Ok(false);
            }
            targets.insert(id.clone(), next);
            Ok(true)
        })?;
        Ok(replacement)
    }

    /// Remove an existing manual target only when it still equals the caller's
    /// original snapshot. Imported aliases remain a read-only configuration view.
    pub fn remove_expected(&self, expected: SshTarget) -> Result<SshTarget, ConfigError> {
        if matches!(&expected.source, TargetSource::Imported { .. }) {
            return Err(ConfigError::ImmutableImportedTarget(expected.id));
        }
        let id = expected.id.clone();
        let mut removed = None;
        self.mutate_config(|root| {
            let Some(targets) = targets_table_mut(root)? else {
                return Err(ConfigError::StaleTarget(id.clone()));
            };
            let Some(existing) = targets.get(&id) else {
                return Err(ConfigError::StaleTarget(id.clone()));
            };
            let current = parse_stored_target(&id, existing, &self.config_path())?;
            if current != expected {
                return Err(ConfigError::StaleTarget(id.clone()));
            }
            removed = Some(current);
            targets.remove(&id);
            Ok(true)
        })?;
        Ok(removed.expect("the checked target was removed under the write lock"))
    }

    /// Remove one manually persisted target. Imported aliases are derived from
    /// SSH files and deliberately remain read-only.
    pub fn remove(&self, id: &str) -> Result<Option<SshTarget>, ConfigError> {
        let id = id.to_owned();
        let has_user_target = self
            .load_user_targets()?
            .iter()
            .any(|target| target.id == id);
        if !has_user_target {
            let imported = parser::imported_aliases(
                &self.user_ssh_config,
                &self.system_ssh_config,
                &self.ssh_home,
            )?;
            if imported
                .iter()
                .any(|target| target.id == id || target.host == id)
            {
                return Err(ConfigError::ImmutableImportedTarget(id));
            }
            return Ok(None);
        }
        let mut removed = None;
        self.mutate_config(|root| {
            let Some(targets) = targets_table_mut(root)? else {
                return Ok(false);
            };
            let Some(value) = targets.get(&id) else {
                return Ok(false);
            };
            removed = Some(parse_stored_target(&id, value, &self.config_path())?);
            targets.remove(&id);
            Ok(true)
        })?;
        Ok(removed)
    }

    /// Resolve an id or host alias into the exact native connection settings.
    /// The resolver parses configuration only; it never starts a ProxyCommand,
    /// Match exec command, or network operation.
    pub fn resolve(&self, id_or_alias: &str) -> Result<super::ResolvedSshConfig, ConfigError> {
        let target = self
            .get(id_or_alias)?
            .ok_or_else(|| ConfigError::TargetNotFound(id_or_alias.to_owned()))?;
        parser::resolve(
            target,
            &self.config_path(),
            &self.user_ssh_config,
            &self.system_ssh_config,
            self.ssh_home.clone(),
        )
    }

    fn config_path(&self) -> PathBuf {
        self.home.join(USER_CONFIG)
    }

    fn load_user_targets(&self) -> Result<Vec<SshTarget>, ConfigError> {
        let root = self.read_config()?;
        let Some(targets) = targets_table(&root)? else {
            return Ok(Vec::new());
        };
        targets
            .iter()
            .map(|(id, value)| parse_stored_target(id, value, &self.config_path()))
            .collect()
    }

    fn read_config(&self) -> Result<Value, ConfigError> {
        match fs::metadata(&self.home) {
            Ok(_) => {}
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Value::Table(Map::new()));
            }
            Err(source) => {
                return Err(ConfigError::Io {
                    path: self.home.clone(),
                    source,
                });
            }
        }
        let config_path = self.config_path();
        let destination = xai_grok_config::fs_atomic::bind_follow_destination(&config_path)
            .map_err(|source| ConfigError::Io {
                path: config_path.clone(),
                source,
            })?;
        let text = match fs::read_to_string(destination.as_path()) {
            Ok(text) => text,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(source) => {
                return Err(ConfigError::Io {
                    path: destination.as_path().to_path_buf(),
                    source,
                });
            }
        };
        parse_config(&config_path, &text)
    }

    fn mutate_config(
        &self,
        mutate: impl FnOnce(&mut Value) -> Result<bool, ConfigError>,
    ) -> Result<(), ConfigError> {
        fs::create_dir_all(&self.home).map_err(|source| ConfigError::Io {
            path: self.home.clone(),
            source,
        })?;
        let _lock = lock_config(&self.home)?;
        let config_path = self.config_path();
        let destination = xai_grok_config::fs_atomic::bind_follow_destination(&config_path)
            .map_err(|source| ConfigError::Io {
                path: config_path.clone(),
                source,
            })?;
        let text = match fs::read_to_string(destination.as_path()) {
            Ok(text) => text,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(source) => {
                return Err(ConfigError::Io {
                    path: destination.as_path().to_path_buf(),
                    source,
                });
            }
        };
        let mut root = parse_config(&config_path, &text)?;
        if !mutate(&mut root)? {
            return Ok(());
        }
        let content = toml::to_string_pretty(&root).map_err(|error| ConfigError::GrokyToml {
            path: config_path.clone(),
            message: error.to_string(),
        })?;
        let destination =
            xai_grok_config::fs_atomic::require_same_bound_destination(&config_path, &destination)
                .map_err(|source| ConfigError::Io {
                    path: config_path.clone(),
                    source,
                })?;
        xai_grok_config::fs_atomic::write_atomically_bound(&destination, &content, None).map_err(
            |source| ConfigError::Io {
                path: destination.as_path().to_path_buf(),
                source,
            },
        )
    }
}

fn unique_target_reference<'a>(
    reference: &str,
    candidates: impl Iterator<Item = &'a SshTarget>,
) -> Result<Option<&'a SshTarget>, ConfigError> {
    let mut candidates = candidates;
    let Some(first) = candidates.next() else {
        return Ok(None);
    };
    let mut candidates = candidates.filter(|target| target.id != first.id);
    let Some(second) = candidates.next() else {
        return Ok(Some(first));
    };
    let mut candidate_ids = vec![first.id.clone(), second.id.clone()];
    candidate_ids.extend(candidates.map(|target| target.id.clone()));
    candidate_ids.sort();
    candidate_ids.dedup();
    Err(ConfigError::AmbiguousTarget {
        reference: reference.to_owned(),
        candidate_ids,
    })
}

/// Parse a shell-like worker argv without invoking a shell. Quotes group an
/// argument; a backslash quotes the next character. Empty quoted words remain
/// arguments, unlike whitespace-only input.
pub fn parse_worker_command(input: &str) -> Result<Vec<String>, ConfigError> {
    let mut arguments = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    let mut escaped = false;
    let mut argument_started = false;
    for character in input.chars() {
        if escaped {
            current.push(character);
            argument_started = true;
            escaped = false;
            continue;
        }
        if character == '\\' {
            escaped = true;
            argument_started = true;
            continue;
        }
        match quote {
            Some(quote_character) if quote_character == character => quote = None,
            Some(_) => {
                current.push(character);
                argument_started = true;
            }
            None if matches!(character, '\'' | '"') => {
                quote = Some(character);
                argument_started = true;
            }
            None if character.is_ascii_whitespace() => {
                if argument_started {
                    arguments.push(std::mem::take(&mut current));
                    argument_started = false;
                }
            }
            None => {
                current.push(character);
                argument_started = true;
            }
        }
    }
    if quote.is_some() || escaped {
        return Err(ConfigError::InvalidTarget(
            "worker command has an unterminated quote or escape".to_owned(),
        ));
    }
    if argument_started {
        arguments.push(current);
    }
    if !matches!(arguments.first(), Some(executable) if !executable.is_empty()) {
        return Err(ConfigError::InvalidTarget(
            "worker command must have an executable".to_owned(),
        ));
    }
    Ok(arguments)
}

fn imported_target(alias: ImportedAlias) -> SshTarget {
    SshTarget {
        id: alias.id,
        label: alias.label,
        host: alias.host,
        user: None,
        port: None,
        identity_files: Vec::new(),
        credential_ref: None,
        worker_command: default_worker_command(),
        source: alias.source,
    }
}

fn parse_config(path: &Path, text: &str) -> Result<Value, ConfigError> {
    if text.trim().is_empty() {
        return Ok(Value::Table(Map::new()));
    }
    let value: Value =
        toml::from_str(text).map_err(|error: toml::de::Error| ConfigError::GrokyToml {
            path: path.to_path_buf(),
            message: error.to_string(),
        })?;
    if !value.is_table() {
        return Err(ConfigError::GrokyToml {
            path: path.to_path_buf(),
            message: "the root must be a table".to_owned(),
        });
    }
    Ok(value)
}

fn targets_table(root: &Value) -> Result<Option<&Map<String, Value>>, ConfigError> {
    let Some(ssh) = root.get("ssh") else {
        return Ok(None);
    };
    let ssh = ssh.as_table().ok_or_else(|| {
        ConfigError::InvalidTarget(
            "[ssh] must be a TOML table in the user-global config".to_owned(),
        )
    })?;
    let Some(targets) = ssh.get("targets") else {
        return Ok(None);
    };
    targets
        .as_table()
        .map(Some)
        .ok_or_else(|| ConfigError::InvalidTarget("[ssh.targets] must be a TOML table".to_owned()))
}

fn targets_table_mut(root: &mut Value) -> Result<Option<&mut Map<String, Value>>, ConfigError> {
    let root = root.as_table_mut().expect("root verified as table");
    let Some(ssh) = root.get_mut("ssh") else {
        return Ok(None);
    };
    let ssh = ssh.as_table_mut().ok_or_else(|| {
        ConfigError::InvalidTarget(
            "[ssh] must be a TOML table in the user-global config".to_owned(),
        )
    })?;
    let Some(targets) = ssh.get_mut("targets") else {
        return Ok(None);
    };
    targets
        .as_table_mut()
        .map(Some)
        .ok_or_else(|| ConfigError::InvalidTarget("[ssh.targets] must be a TOML table".to_owned()))
}

fn ensure_targets_table(root: &mut Value) -> Result<&mut Map<String, Value>, ConfigError> {
    let root = root.as_table_mut().expect("root verified as table");
    let ssh = root
        .entry("ssh".to_owned())
        .or_insert_with(|| Value::Table(Map::new()))
        .as_table_mut()
        .ok_or_else(|| ConfigError::InvalidTarget("[ssh] must be a TOML table".to_owned()))?;
    ssh.entry("targets".to_owned())
        .or_insert_with(|| Value::Table(Map::new()))
        .as_table_mut()
        .ok_or_else(|| ConfigError::InvalidTarget("[ssh.targets] must be a TOML table".to_owned()))
}

fn parse_stored_target(id: &str, value: &Value, path: &Path) -> Result<SshTarget, ConfigError> {
    let table = value.as_table().ok_or_else(|| ConfigError::GrokyToml {
        path: path.to_path_buf(),
        message: format!("[ssh.targets.{id}] must be a table"),
    })?;
    let host = required_string(table, "host", id, path)?;
    let label = optional_string(table, "label", id, path)?.unwrap_or_else(|| host.clone());
    let user = optional_string(table, "user", id, path)?;
    let port = optional_port(table, id, path)?;
    let identity_files = optional_string_array(table, "identity_files", id, path)?
        .unwrap_or_default()
        .into_iter()
        .map(PathBuf::from)
        .collect();
    let credential_ref = optional_string(table, "credential_ref", id, path)?;
    let worker_command = match table.get("worker_command") {
        Some(Value::String(command)) => parse_worker_command(command)?,
        Some(Value::Array(values)) => values
            .iter()
            .map(Value::as_str)
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| ConfigError::GrokyToml {
                path: path.to_path_buf(),
                message: format!("worker_command for target `{id}` must be a string array"),
            })?
            .into_iter()
            .map(ToOwned::to_owned)
            .collect(),
        Some(_) => {
            return Err(ConfigError::GrokyToml {
                path: path.to_path_buf(),
                message: format!(
                    "worker_command for target `{id}` must be a string or string array"
                ),
            });
        }
        None => default_worker_command(),
    };
    let target = SshTarget {
        id: id.to_owned(),
        label,
        host,
        user,
        port,
        identity_files,
        credential_ref,
        worker_command,
        source: TargetSource::User,
    };
    validate_target(&target)?;
    Ok(target)
}

fn merge_target_value(existing: Option<&Value>, target: &SshTarget) -> Result<Value, ConfigError> {
    let mut table = match existing {
        Some(Value::Table(table)) => table.clone(),
        Some(_) => {
            return Err(ConfigError::InvalidTarget(format!(
                "[ssh.targets.{}] must be a TOML table",
                target.id
            )));
        }
        None => Map::new(),
    };
    for key in [
        "host",
        "label",
        "user",
        "port",
        "identity_files",
        "credential_ref",
        "worker_command",
        "source",
    ] {
        table.remove(key);
    }
    table.insert("host".to_owned(), Value::String(target.host.clone()));
    table.insert("label".to_owned(), Value::String(target.label.clone()));
    if let Some(user) = target.user.as_ref() {
        table.insert("user".to_owned(), Value::String(user.clone()));
    }
    if let Some(port) = target.port {
        table.insert("port".to_owned(), Value::Integer(i64::from(port)));
    }
    if !target.identity_files.is_empty() {
        table.insert(
            "identity_files".to_owned(),
            Value::Array(
                target
                    .identity_files
                    .iter()
                    .map(|path| Value::String(path.to_string_lossy().into_owned()))
                    .collect(),
            ),
        );
    }
    if let Some(credential_ref) = target.credential_ref.as_ref() {
        table.insert(
            "credential_ref".to_owned(),
            Value::String(credential_ref.clone()),
        );
    }
    table.insert(
        "worker_command".to_owned(),
        Value::Array(
            target
                .worker_command
                .iter()
                .cloned()
                .map(Value::String)
                .collect(),
        ),
    );
    Ok(Value::Table(table))
}

fn required_string(
    table: &Map<String, Value>,
    key: &str,
    id: &str,
    path: &Path,
) -> Result<String, ConfigError> {
    optional_string(table, key, id, path)?.ok_or_else(|| ConfigError::GrokyToml {
        path: path.to_path_buf(),
        message: format!("target `{id}` requires `{key}`"),
    })
}

fn optional_string(
    table: &Map<String, Value>,
    key: &str,
    id: &str,
    path: &Path,
) -> Result<Option<String>, ConfigError> {
    match table.get(key) {
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(ConfigError::GrokyToml {
            path: path.to_path_buf(),
            message: format!("target `{id}` field `{key}` must be a string"),
        }),
        None => Ok(None),
    }
}

fn optional_port(
    table: &Map<String, Value>,
    id: &str,
    path: &Path,
) -> Result<Option<u16>, ConfigError> {
    match table.get("port") {
        Some(Value::Integer(value)) if (1..=i64::from(u16::MAX)).contains(value) => {
            Ok(Some(*value as u16))
        }
        Some(_) => Err(ConfigError::GrokyToml {
            path: path.to_path_buf(),
            message: format!("target `{id}` field `port` must be an SSH port"),
        }),
        None => Ok(None),
    }
}

fn optional_string_array(
    table: &Map<String, Value>,
    key: &str,
    id: &str,
    path: &Path,
) -> Result<Option<Vec<String>>, ConfigError> {
    match table.get(key) {
        Some(Value::Array(values)) => values
            .iter()
            .map(Value::as_str)
            .collect::<Option<Vec<_>>>()
            .map(|values| Some(values.into_iter().map(ToOwned::to_owned).collect()))
            .ok_or_else(|| ConfigError::GrokyToml {
                path: path.to_path_buf(),
                message: format!("target `{id}` field `{key}` must be a string array"),
            }),
        Some(_) => Err(ConfigError::GrokyToml {
            path: path.to_path_buf(),
            message: format!("target `{id}` field `{key}` must be a string array"),
        }),
        None => Ok(None),
    }
}

fn validate_target(target: &SshTarget) -> Result<(), ConfigError> {
    if target.id.trim().is_empty() {
        return Err(ConfigError::InvalidTarget(
            "id must not be empty".to_owned(),
        ));
    }
    if target.id.starts_with("imported:") {
        return Err(ConfigError::InvalidTarget(
            "ids beginning with `imported:` are reserved for read-only SSH aliases".to_owned(),
        ));
    }
    for (name, value) in [
        ("id", target.id.as_str()),
        ("label", target.label.as_str()),
        ("host", target.host.as_str()),
    ] {
        if value.trim().is_empty() || value.chars().any(char::is_control) {
            return Err(ConfigError::InvalidTarget(format!(
                "{name} must be non-empty and contain no control characters"
            )));
        }
    }
    if let Some(user) = target.user.as_ref()
        && (user.trim().is_empty() || user.chars().any(char::is_control))
    {
        return Err(ConfigError::InvalidTarget(
            "user must be non-empty and contain no control characters".to_owned(),
        ));
    }
    if target.port == Some(0) {
        return Err(ConfigError::InvalidTarget(
            "port must be a valid SSH port".to_owned(),
        ));
    }
    if target
        .identity_files
        .iter()
        .any(|path| path.as_os_str().is_empty())
    {
        return Err(ConfigError::InvalidTarget(
            "identity_files must not contain an empty path".to_owned(),
        ));
    }
    if let Some(credential_ref) = target.credential_ref.as_ref()
        && (credential_ref.trim().is_empty() || credential_ref.chars().any(char::is_control))
    {
        return Err(ConfigError::InvalidTarget(
            "credential_ref must be non-empty and contain no control characters".to_owned(),
        ));
    }
    if !matches!(
        target.worker_command.first(),
        Some(executable) if !executable.trim().is_empty()
    ) {
        return Err(ConfigError::InvalidTarget(
            "worker_command must contain an executable".to_owned(),
        ));
    }
    if target
        .worker_command
        .iter()
        .any(|argument| argument.chars().any(char::is_control))
    {
        return Err(ConfigError::InvalidTarget(
            "worker_command arguments must not contain control characters".to_owned(),
        ));
    }
    Ok(())
}

fn lock_config(home: &Path) -> Result<File, ConfigError> {
    let path = home.join(CONFIG_INIT_LOCK);
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&path)
        .map_err(|source| ConfigError::Io {
            path: path.clone(),
            source,
        })?;
    for _ in 0..50 {
        match file.try_lock_exclusive() {
            Ok(()) => return Ok(file),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(source) => return Err(ConfigError::Io { path, source }),
        }
    }
    Err(ConfigError::Io {
        path,
        source: std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "timed out waiting for the Groky configuration write lock",
        ),
    })
}

fn user_home_dir() -> Option<PathBuf> {
    #[allow(deprecated)]
    {
        std::env::home_dir()
    }
}

fn default_system_ssh_config() -> PathBuf {
    #[cfg(windows)]
    {
        return std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\\ProgramData"))
            .join("ssh")
            .join("ssh_config");
    }
    #[cfg(not(windows))]
    {
        PathBuf::from("/etc/ssh/ssh_config")
    }
}
