use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

use super::{
    AgentConfig, AlgorithmRequirements, AuthMethod, ConfigError, ConfigValueSource,
    DurationSetting, HostKeyPolicy, JumpHost, KeepAliveConfig, KnownHostsConfig, ProxyRoute,
    ResolvedConfigProvenance, ResolvedSshConfig, SshConfigSource, SshTarget, TargetSource,
};

const MAX_INCLUDE_DEPTH: usize = 32;

#[derive(Debug, Clone)]
pub(super) struct ImportedAlias {
    pub id: String,
    pub label: String,
    pub host: String,
    pub source: TargetSource,
}

#[derive(Debug)]
struct ResolutionContext {
    original_host: String,
    local_user: String,
    home: PathBuf,
}

#[derive(Debug)]
struct ExpansionContext<'a> {
    original_host: &'a str,
    hostname: &'a str,
    username: &'a str,
    port: u16,
    local_user: &'a str,
    home: &'a Path,
}

#[derive(Debug, Clone)]
struct Sourced<T> {
    value: T,
    source: ConfigValueSource,
}

#[derive(Debug, Default)]
struct ResolutionState {
    hostname: Option<Sourced<String>>,
    username: Option<Sourced<String>>,
    port: Option<Sourced<u16>>,
    identity_files: Vec<Sourced<String>>,
    identity_agent: Option<Sourced<Option<String>>>,
    identities_only: Option<Sourced<bool>>,
    user_known_hosts: Option<Sourced<Vec<String>>>,
    global_known_hosts: Option<Sourced<Vec<String>>>,
    hash_known_hosts: Option<Sourced<bool>>,
    host_key_policy: Option<Sourced<HostKeyPolicy>>,
    pubkey_auth: Option<Sourced<bool>>,
    password_auth: Option<Sourced<bool>>,
    keyboard_interactive_auth: Option<Sourced<bool>>,
    preferred_auth: Option<Sourced<Vec<AuthMethod>>>,
    proxy: Option<Sourced<Option<ProxyRoute>>>,
    connect_timeout: Option<Sourced<u64>>,
    server_alive_interval: Option<Sourced<u64>>,
    server_alive_count_max: Option<Sourced<u32>>,
    tcp_keep_alive: Option<Sourced<bool>>,
    send_env: Vec<Sourced<String>>,
    host_key_algorithms: Option<Sourced<Vec<String>>>,
    public_key_algorithms: Option<Sourced<Vec<String>>>,
    kex_algorithms: Option<Sourced<Vec<String>>>,
    ciphers: Option<Sourced<Vec<String>>>,
    macs: Option<Sourced<Vec<String>>>,
    provenance: BTreeMap<String, ConfigValueSource>,
}

impl ResolutionState {
    fn set_first<T>(
        slot: &mut Option<Sourced<T>>,
        value: T,
        source: ConfigValueSource,
        field: &str,
        provenance: &mut BTreeMap<String, ConfigValueSource>,
    ) {
        if slot.is_none() {
            provenance.insert(field.to_owned(), source.clone());
            *slot = Some(Sourced { value, source });
        }
    }

    fn push_identity(&mut self, value: String, source: ConfigValueSource) {
        let index = self.identity_files.len();
        self.provenance
            .insert(format!("identity_files.{index}"), source.clone());
        self.identity_files.push(Sourced { value, source });
    }

    fn apply_send_env(
        &mut self,
        names: &[String],
        source: ConfigValueSource,
    ) -> Result<(), ConfigError> {
        if names.is_empty() {
            return Err(ConfigError::InvalidSshConfig {
                path: source.path,
                line: source.line,
                message: "SendEnv requires at least one environment-variable name".to_owned(),
            });
        }
        for name in names {
            if name.is_empty() || name.contains('=') {
                return Err(ConfigError::InvalidSshConfig {
                    path: source.path.clone(),
                    line: source.line,
                    message: "SendEnv names must be non-empty and not contain `=`".to_owned(),
                });
            }
            let pattern = name.strip_prefix('-').unwrap_or(name);
            if name.starts_with('-') {
                self.send_env
                    .retain(|entry| !send_env_pattern_matches(&entry.value, pattern));
            } else {
                self.send_env.push(Sourced {
                    value: name.clone(),
                    source: source.clone(),
                });
            }
        }
        self.provenance
            .retain(|field, _| !field.starts_with("send_env."));
        for (index, entry) in self.send_env.iter().enumerate() {
            self.provenance
                .insert(format!("send_env.{index}"), entry.source.clone());
        }
        Ok(())
    }
}

/// Evaluate user configuration before system configuration, preserving OpenSSH's
/// first-value-wins behavior and its special accumulating `IdentityFile` rule.
pub(super) fn resolve(
    target: SshTarget,
    groky_config_path: &Path,
    user_config: &Path,
    system_config: &Path,
    home: PathBuf,
) -> Result<ResolvedSshConfig, ConfigError> {
    let local_user = local_user()?;
    let context = ResolutionContext {
        original_host: target.host.clone(),
        local_user,
        home,
    };
    let mut state = ResolutionState::default();
    let target_source = ConfigValueSource {
        source: SshConfigSource::Target,
        path: groky_config_path.to_path_buf(),
        line: 0,
    };

    if let Some(user) = target.user.as_ref() {
        ResolutionState::set_first(
            &mut state.username,
            user.clone(),
            target_source.clone(),
            "username",
            &mut state.provenance,
        );
    }
    if let Some(port) = target.port {
        ResolutionState::set_first(
            &mut state.port,
            port,
            target_source.clone(),
            "port",
            &mut state.provenance,
        );
    }
    for identity in &target.identity_files {
        state.push_identity(
            identity.to_string_lossy().into_owned(),
            target_source.clone(),
        );
    }

    let mut include_stack = Vec::new();
    let _ = evaluate_file(
        user_config,
        SshConfigSource::UserSsh,
        &context,
        &mut state,
        &mut include_stack,
        true,
        true,
    )?;
    let _ = evaluate_file(
        system_config,
        SshConfigSource::SystemSsh,
        &context,
        &mut state,
        &mut include_stack,
        true,
        true,
    )?;

    finalize(target, groky_config_path, &context, state)
}

pub(super) fn imported_aliases(
    user_config: &Path,
    system_config: &Path,
    home: &Path,
) -> Result<Vec<ImportedAlias>, ConfigError> {
    let mut aliases = Vec::new();
    let mut seen = HashSet::new();
    let mut stack = Vec::new();
    collect_aliases_file(user_config, home, &mut stack, &mut seen, &mut aliases, true)?;
    collect_aliases_file(
        system_config,
        home,
        &mut stack,
        &mut seen,
        &mut aliases,
        true,
    )?;
    Ok(aliases)
}

fn finalize(
    target: SshTarget,
    groky_config_path: &Path,
    context: &ResolutionContext,
    state: ResolutionState,
) -> Result<ResolvedSshConfig, ConfigError> {
    let mut provenance = ResolvedConfigProvenance {
        fields: state.provenance,
    };
    let default_path = PathBuf::from("<default>");
    let default_source = |_field: &str| ConfigValueSource {
        source: SshConfigSource::Default,
        path: default_path.clone(),
        line: 0,
    };
    let target_source = || ConfigValueSource {
        source: SshConfigSource::Target,
        path: groky_config_path.to_path_buf(),
        line: 0,
    };

    let initial_user = state
        .username
        .as_ref()
        .map(|value| value.value.as_str())
        .unwrap_or(context.local_user.as_str());
    let initial_port = state.port.as_ref().map(|value| value.value).unwrap_or(22);
    let hostname = match state.hostname.as_ref() {
        Some(value) => expand_value(
            &value.value,
            &ExpansionContext {
                original_host: &context.original_host,
                hostname: &context.original_host,
                username: initial_user,
                port: initial_port,
                local_user: &context.local_user,
                home: &context.home,
            },
            &value.source,
            false,
        )?,
        None => {
            provenance
                .fields
                .entry("hostname".to_owned())
                .or_insert_with(target_source);
            context.original_host.clone()
        }
    };
    let username = match state.username.as_ref() {
        Some(value) => expand_value(
            &value.value,
            &ExpansionContext {
                original_host: &context.original_host,
                hostname: &hostname,
                username: &context.local_user,
                port: initial_port,
                local_user: &context.local_user,
                home: &context.home,
            },
            &value.source,
            false,
        )?,
        None => {
            provenance
                .fields
                .entry("username".to_owned())
                .or_insert_with(|| default_source("username"));
            context.local_user.clone()
        }
    };
    let port = state
        .port
        .as_ref()
        .map(|value| value.value)
        .unwrap_or_else(|| {
            provenance
                .fields
                .entry("port".to_owned())
                .or_insert_with(|| default_source("port"));
            22
        });
    let expansion = ExpansionContext {
        original_host: &context.original_host,
        hostname: &hostname,
        username: &username,
        port,
        local_user: &context.local_user,
        home: &context.home,
    };

    let identity_files = state
        .identity_files
        .iter()
        .map(|value| expand_path(&value.value, &expansion, &value.source))
        .collect::<Result<Vec<_>, _>>()?;
    if identity_files.is_empty() {
        provenance
            .fields
            .entry("identity_files".to_owned())
            .or_insert_with(|| default_source("identity_files"));
    }

    let identity_agent = match state.identity_agent.as_ref() {
        Some(value) if value.value.as_deref() == Some("SSH_AUTH_SOCK") => {
            std::env::var_os("SSH_AUTH_SOCK").map(PathBuf::from)
        }
        Some(value) => value
            .value
            .as_deref()
            .map(|socket| expand_path(socket, &expansion, &value.source))
            .transpose()?,
        None => std::env::var_os("SSH_AUTH_SOCK").map(PathBuf::from),
    };
    let pubkey_enabled = state
        .pubkey_auth
        .as_ref()
        .map(|value| value.value)
        .unwrap_or(true);
    let agent = AgentConfig {
        enabled: pubkey_enabled && identity_agent.is_some(),
        socket: identity_agent,
        identities_only: state
            .identities_only
            .as_ref()
            .map(|value| value.value)
            .unwrap_or(false),
    };
    provenance
        .fields
        .entry("agent".to_owned())
        .or_insert_with(|| default_source("agent"));

    let user_files = match state.user_known_hosts.as_ref() {
        Some(value) => value
            .value
            .iter()
            .map(|path| expand_path(path, &expansion, &value.source))
            .collect::<Result<Vec<_>, _>>()?,
        None => vec![
            context.home.join(".ssh").join("known_hosts"),
            context.home.join(".ssh").join("known_hosts2"),
        ],
    };
    let global_files = match state.global_known_hosts.as_ref() {
        Some(value) => value
            .value
            .iter()
            .map(|path| expand_path(path, &expansion, &value.source))
            .collect::<Result<Vec<_>, _>>()?,
        None => default_global_known_hosts(),
    };
    let known_hosts = KnownHostsConfig {
        user_files,
        global_files,
        hash_known_hosts: state.hash_known_hosts.as_ref().map(|value| value.value),
    };
    provenance
        .fields
        .entry("known_hosts".to_owned())
        .or_insert_with(|| default_source("known_hosts"));

    let host_key_policy = state
        .host_key_policy
        .as_ref()
        .map(|value| value.value)
        .unwrap_or(HostKeyPolicy::Ask);
    provenance
        .fields
        .entry("host_key_policy".to_owned())
        .or_insert_with(|| default_source("host_key_policy"));

    let preferred_auth = match state.preferred_auth.as_ref() {
        Some(value) => value.value.clone(),
        None => vec![
            AuthMethod::PublicKey,
            AuthMethod::KeyboardInteractive,
            AuthMethod::Password,
        ],
    }
    .into_iter()
    .filter(|method| match method {
        AuthMethod::PublicKey => pubkey_enabled,
        AuthMethod::KeyboardInteractive => state
            .keyboard_interactive_auth
            .as_ref()
            .map(|value| value.value)
            .unwrap_or(true),
        AuthMethod::Password => state
            .password_auth
            .as_ref()
            .map(|value| value.value)
            .unwrap_or(true),
    })
    .collect();
    provenance
        .fields
        .entry("preferred_auth".to_owned())
        .or_insert_with(|| default_source("preferred_auth"));

    let proxy = match state.proxy.as_ref() {
        Some(value) => match value.value.as_ref() {
            Some(ProxyRoute::Command(command)) => Some(ProxyRoute::Command(expand_value(
                command,
                &expansion,
                &value.source,
                false,
            )?)),
            Some(ProxyRoute::Jump(jumps)) => Some(ProxyRoute::Jump(
                jumps
                    .iter()
                    .map(|jump| {
                        Ok(JumpHost {
                            hostname: expand_value(
                                &jump.hostname,
                                &expansion,
                                &value.source,
                                false,
                            )?,
                            username: jump
                                .username
                                .as_deref()
                                .map(|username| {
                                    expand_value(username, &expansion, &value.source, false)
                                })
                                .transpose()?,
                            port: jump.port,
                        })
                    })
                    .collect::<Result<Vec<_>, ConfigError>>()?,
            )),
            None => None,
        },
        None => None,
    };
    if proxy.is_none() {
        provenance
            .fields
            .entry("proxy".to_owned())
            .or_insert_with(|| default_source("proxy"));
    }

    let connect_timeout = state.connect_timeout.as_ref().and_then(|value| {
        (value.value > 0).then_some(DurationSetting {
            seconds: value.value,
        })
    });
    let server_alive = if state.server_alive_interval.is_some()
        || state.server_alive_count_max.is_some()
        || state.tcp_keep_alive.is_some()
    {
        Some(KeepAliveConfig {
            interval: DurationSetting {
                seconds: state
                    .server_alive_interval
                    .as_ref()
                    .map(|value| value.value)
                    .unwrap_or(0),
            },
            count_max: state
                .server_alive_count_max
                .as_ref()
                .map(|value| value.value)
                .unwrap_or(3),
            tcp_keep_alive: state.tcp_keep_alive.as_ref().map(|value| value.value),
        })
    } else {
        None
    };

    let send_env = state
        .send_env
        .into_iter()
        .map(|entry| entry.value)
        .collect();

    let algorithms = AlgorithmRequirements {
        host_key: state.host_key_algorithms.map(|value| value.value),
        public_key: state.public_key_algorithms.map(|value| value.value),
        kex: state.kex_algorithms.map(|value| value.value),
        ciphers: state.ciphers.map(|value| value.value),
        macs: state.macs.map(|value| value.value),
    };

    Ok(ResolvedSshConfig {
        target,
        hostname,
        username,
        port,
        identity_files,
        agent,
        known_hosts,
        host_key_policy,
        preferred_auth,
        send_env,
        proxy,
        connect_timeout,
        server_alive,
        algorithms,
        provenance,
    })
}

fn evaluate_file(
    path: &Path,
    source_kind: SshConfigSource,
    context: &ResolutionContext,
    state: &mut ResolutionState,
    include_stack: &mut Vec<PathBuf>,
    active: bool,
    missing_is_empty: bool,
) -> Result<bool, ConfigError> {
    let canonical = match fs::canonicalize(path) {
        Ok(path) => path,
        Err(error) if missing_is_empty && error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(active);
        }
        Err(source) => {
            return Err(ConfigError::Io {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    if include_stack.len() >= MAX_INCLUDE_DEPTH {
        return Err(ConfigError::IncludeDepth {
            path: canonical,
            limit: MAX_INCLUDE_DEPTH,
        });
    }
    if include_stack.iter().any(|ancestor| ancestor == &canonical) {
        return Err(ConfigError::IncludeRecursion { path: canonical });
    }
    let content = fs::read_to_string(&canonical).map_err(|source| ConfigError::Io {
        path: canonical.clone(),
        source,
    })?;
    include_stack.push(canonical.clone());
    let result = evaluate_lines(
        &canonical,
        source_kind,
        &content,
        context,
        state,
        include_stack,
        active,
    );
    include_stack.pop();
    result
}

fn evaluate_lines(
    path: &Path,
    source_kind: SshConfigSource,
    content: &str,
    context: &ResolutionContext,
    state: &mut ResolutionState,
    include_stack: &mut Vec<PathBuf>,
    mut active: bool,
) -> Result<bool, ConfigError> {
    for (index, raw_line) in content.lines().enumerate() {
        let line = index + 1;
        let Some((key, value, words)) = split_directive(raw_line, path, line)? else {
            continue;
        };
        let key_lower = key.to_ascii_lowercase();
        match key_lower.as_str() {
            "host" => {
                if words.is_empty() {
                    return Err(ConfigError::InvalidSshConfig {
                        path: path.to_path_buf(),
                        line,
                        message: "Host requires at least one pattern".to_owned(),
                    });
                }
                active = host_patterns_match(&words, &context.original_host);
            }
            "match" => {
                let remote_user = state
                    .username
                    .as_ref()
                    .map(|value| value.value.as_str())
                    .unwrap_or(&context.local_user);
                active = match_conditions(&words, context, remote_user, path, line)?;
            }
            "include" if active => {
                let source = ConfigValueSource {
                    source: source_kind,
                    path: path.to_path_buf(),
                    line,
                };
                for pattern in &words {
                    let expansion = ExpansionContext {
                        original_host: &context.original_host,
                        hostname: &context.original_host,
                        username: state
                            .username
                            .as_ref()
                            .map(|value| value.value.as_str())
                            .unwrap_or(&context.local_user),
                        port: state.port.as_ref().map(|value| value.value).unwrap_or(22),
                        local_user: &context.local_user,
                        home: &context.home,
                    };
                    let pattern = expand_path(pattern, &expansion, &source)?;
                    for included in expand_include_pattern(&pattern, path)? {
                        active = evaluate_file(
                            &included,
                            source_kind,
                            context,
                            state,
                            include_stack,
                            active,
                            false,
                        )?;
                    }
                }
            }
            "include" => {}
            _ if active => {
                let source = ConfigValueSource {
                    source: source_kind,
                    path: path.to_path_buf(),
                    line,
                };
                apply_directive(&key_lower, &value, &words, source, state)?;
            }
            _ => {}
        }
    }
    Ok(active)
}

fn apply_directive(
    key: &str,
    raw_value: &str,
    words: &[String],
    source: ConfigValueSource,
    state: &mut ResolutionState,
) -> Result<(), ConfigError> {
    macro_rules! one {
        () => {
            exactly_one(key, words, &source)?
        };
    }
    match key {
        "hostname" => {
            ResolutionState::set_first(
                &mut state.hostname,
                one!(),
                source,
                "hostname",
                &mut state.provenance,
            );
        }
        "user" => {
            ResolutionState::set_first(
                &mut state.username,
                one!(),
                source,
                "username",
                &mut state.provenance,
            );
        }
        "port" => {
            let value = parse_port(&one!(), &source)?;
            ResolutionState::set_first(
                &mut state.port,
                value,
                source,
                "port",
                &mut state.provenance,
            );
        }
        "identityfile" => state.push_identity(one!(), source),
        "identityagent" => {
            let value = one!();
            let value = if value.eq_ignore_ascii_case("none") {
                None
            } else {
                Some(value)
            };
            ResolutionState::set_first(
                &mut state.identity_agent,
                value,
                source,
                "agent",
                &mut state.provenance,
            );
        }
        "identitiesonly" => {
            let value = parse_bool(&one!(), &source)?;
            ResolutionState::set_first(
                &mut state.identities_only,
                value,
                source,
                "agent",
                &mut state.provenance,
            );
        }
        "userknownhostsfile" => {
            let value = parse_known_hosts_paths(words, &source)?;
            ResolutionState::set_first(
                &mut state.user_known_hosts,
                value,
                source,
                "known_hosts",
                &mut state.provenance,
            );
        }
        "globalknownhostsfile" => {
            let value = parse_known_hosts_paths(words, &source)?;
            ResolutionState::set_first(
                &mut state.global_known_hosts,
                value,
                source,
                "known_hosts",
                &mut state.provenance,
            );
        }
        "hashknownhosts" => {
            let value = parse_bool(&one!(), &source)?;
            ResolutionState::set_first(
                &mut state.hash_known_hosts,
                value,
                source,
                "known_hosts",
                &mut state.provenance,
            );
        }
        "stricthostkeychecking" => {
            let value = match one!().to_ascii_lowercase().as_str() {
                "ask" => HostKeyPolicy::Ask,
                "accept-new" => HostKeyPolicy::AcceptNew,
                "yes" => HostKeyPolicy::Require,
                "no" | "off" => HostKeyPolicy::Off,
                _ => return invalid_value("StrictHostKeyChecking", &source),
            };
            ResolutionState::set_first(
                &mut state.host_key_policy,
                value,
                source,
                "host_key_policy",
                &mut state.provenance,
            );
        }
        "pubkeyauthentication" => {
            let value = parse_bool(&one!(), &source)?;
            ResolutionState::set_first(
                &mut state.pubkey_auth,
                value,
                source,
                "preferred_auth",
                &mut state.provenance,
            );
        }
        "passwordauthentication" => {
            let value = parse_bool(&one!(), &source)?;
            ResolutionState::set_first(
                &mut state.password_auth,
                value,
                source,
                "preferred_auth",
                &mut state.provenance,
            );
        }
        "kbdinteractiveauthentication" | "challengeresponseauthentication" => {
            let value = parse_bool(&one!(), &source)?;
            ResolutionState::set_first(
                &mut state.keyboard_interactive_auth,
                value,
                source,
                "preferred_auth",
                &mut state.provenance,
            );
        }
        "preferredauthentications" => {
            let value = parse_auth_methods(&one!(), &source)?;
            ResolutionState::set_first(
                &mut state.preferred_auth,
                value,
                source,
                "preferred_auth",
                &mut state.provenance,
            );
        }
        "proxyjump" => {
            let value = parse_proxy_jump(&one!(), &source)?;
            ResolutionState::set_first(
                &mut state.proxy,
                value.map(ProxyRoute::Jump),
                source,
                "proxy",
                &mut state.provenance,
            );
        }
        "proxycommand" => {
            let command = raw_value.trim();
            if command.is_empty() {
                return Err(ConfigError::InvalidSshConfig {
                    path: source.path,
                    line: source.line,
                    message: "ProxyCommand requires a command".to_owned(),
                });
            }
            let value = if command.eq_ignore_ascii_case("none") {
                None
            } else {
                Some(ProxyRoute::Command(command.to_owned()))
            };
            ResolutionState::set_first(
                &mut state.proxy,
                value,
                source,
                "proxy",
                &mut state.provenance,
            );
        }
        "connecttimeout" => {
            let value = parse_u64("ConnectTimeout", &one!(), &source)?;
            ResolutionState::set_first(
                &mut state.connect_timeout,
                value,
                source,
                "connect_timeout",
                &mut state.provenance,
            );
        }
        "serveraliveinterval" => {
            let value = parse_u64("ServerAliveInterval", &one!(), &source)?;
            ResolutionState::set_first(
                &mut state.server_alive_interval,
                value,
                source,
                "server_alive",
                &mut state.provenance,
            );
        }
        "serveralivecountmax" => {
            let value = parse_u32("ServerAliveCountMax", &one!(), &source)?;
            ResolutionState::set_first(
                &mut state.server_alive_count_max,
                value,
                source,
                "server_alive",
                &mut state.provenance,
            );
        }
        "tcpkeepalive" => {
            let value = parse_bool(&one!(), &source)?;
            ResolutionState::set_first(
                &mut state.tcp_keep_alive,
                value,
                source,
                "server_alive",
                &mut state.provenance,
            );
        }
        "sendenv" => state.apply_send_env(words, source)?,
        "hostkeyalgorithms" => {
            let value = parse_algorithm_list(&one!(), &source)?;
            ResolutionState::set_first(
                &mut state.host_key_algorithms,
                value,
                source,
                "algorithms.host_key",
                &mut state.provenance,
            );
        }
        "pubkeyacceptedalgorithms" => {
            let value = parse_algorithm_list(&one!(), &source)?;
            ResolutionState::set_first(
                &mut state.public_key_algorithms,
                value,
                source,
                "algorithms.public_key",
                &mut state.provenance,
            );
        }
        "kexalgorithms" => {
            let value = parse_algorithm_list(&one!(), &source)?;
            ResolutionState::set_first(
                &mut state.kex_algorithms,
                value,
                source,
                "algorithms.kex",
                &mut state.provenance,
            );
        }
        "ciphers" => {
            let value = parse_algorithm_list(&one!(), &source)?;
            ResolutionState::set_first(
                &mut state.ciphers,
                value,
                source,
                "algorithms.ciphers",
                &mut state.provenance,
            );
        }
        "macs" => {
            let value = parse_algorithm_list(&one!(), &source)?;
            ResolutionState::set_first(
                &mut state.macs,
                value,
                source,
                "algorithms.macs",
                &mut state.provenance,
            );
        }
        // XAuthLocation only supplies the local helper for X11 forwarding.
        // Forwarding itself is unsupported and rejected, so this value cannot
        // affect a native connection.
        "xauthlocation" => {
            let _ = one!();
        }
        // These options alter authentication, routing, connection behavior, or
        // host-verification policy. Refuse them until the native transport can
        // implement their OpenSSH semantics exactly.
        "batchmode"
        | "updatehostkeys"
        | "verifyhostkeydns"
        | "canonicalizehostname"
        | "controlmaster"
        | "controlpath"
        | "controlpersist"
        | "proxyusefdpass"
        | "gssapiauthentication"
        | "hostbasedauthentication"
        | "forwardagent"
        | "permitlocalcommand"
        | "localcommand"
        | "remotecommand"
        | "requesttty"
        | "escapechar"
        | "ipqos"
        | "addressfamily"
        | "bindaddress"
        | "bindinterface"
        | "compression"
        | "rekeylimit"
        | "numberofpasswordprompts"
        | "kbdinteractivedevices"
        | "securitykeyprovider"
        | "pkcs11provider"
        | "revokedhostkeys"
        | "trustedusercakeys"
        | "hostcertificate"
        | "certificatefile"
        | "casignaturealgorithms"
        | "requiredrsasize"
        | "loglevel"
        | "userknownhostsfile2" => {
            return Err(ConfigError::UnsupportedDirective {
                path: source.path,
                line: source.line,
                directive: key.to_owned(),
                reason: "the native SSH transport does not implement this active setting"
                    .to_owned(),
            });
        }
        _ => {
            return Err(ConfigError::UnsupportedDirective {
                path: source.path,
                line: source.line,
                directive: key.to_owned(),
                reason: "Groky does not support this active OpenSSH directive".to_owned(),
            });
        }
    }
    Ok(())
}

fn collect_aliases_file(
    path: &Path,
    home: &Path,
    include_stack: &mut Vec<PathBuf>,
    seen: &mut HashSet<String>,
    aliases: &mut Vec<ImportedAlias>,
    missing_is_empty: bool,
) -> Result<(), ConfigError> {
    let canonical = match fs::canonicalize(path) {
        Ok(path) => path,
        Err(error) if missing_is_empty && error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(());
        }
        Err(source) => {
            return Err(ConfigError::Io {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    if include_stack.len() >= MAX_INCLUDE_DEPTH {
        return Err(ConfigError::IncludeDepth {
            path: canonical,
            limit: MAX_INCLUDE_DEPTH,
        });
    }
    if include_stack.iter().any(|ancestor| ancestor == &canonical) {
        return Err(ConfigError::IncludeRecursion { path: canonical });
    }
    let content = fs::read_to_string(&canonical).map_err(|source| ConfigError::Io {
        path: canonical.clone(),
        source,
    })?;
    include_stack.push(canonical.clone());
    let result = (|| {
        for (index, raw_line) in content.lines().enumerate() {
            let line = index + 1;
            let Some((key, _, words)) = split_directive(raw_line, &canonical, line)? else {
                continue;
            };
            match key.to_ascii_lowercase().as_str() {
                "host" => {
                    for alias in literal_host_aliases(&words) {
                        if seen.insert(alias.clone()) {
                            aliases.push(ImportedAlias {
                                id: format!("imported:{alias}"),
                                label: alias.clone(),
                                host: alias,
                                source: TargetSource::Imported {
                                    path: canonical.clone(),
                                    line,
                                },
                            });
                        }
                    }
                }
                "include" => {
                    let source = ConfigValueSource {
                        source: SshConfigSource::UserSsh,
                        path: canonical.clone(),
                        line,
                    };
                    let context = ExpansionContext {
                        original_host: "",
                        hostname: "",
                        username: "",
                        port: 22,
                        local_user: "",
                        home,
                    };
                    for pattern in words {
                        let pattern = expand_path(&pattern, &context, &source)?;
                        for included in expand_include_pattern(&pattern, &canonical)? {
                            collect_aliases_file(
                                &included,
                                home,
                                include_stack,
                                seen,
                                aliases,
                                false,
                            )?;
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(())
    })();
    include_stack.pop();
    result
}

fn exactly_one(
    directive: &str,
    words: &[String],
    source: &ConfigValueSource,
) -> Result<String, ConfigError> {
    match words {
        [word] => Ok(word.clone()),
        _ => Err(ConfigError::InvalidSshConfig {
            path: source.path.clone(),
            line: source.line,
            message: format!("{directive} requires exactly one value"),
        }),
    }
}

fn parse_port(value: &str, source: &ConfigValueSource) -> Result<u16, ConfigError> {
    let port = value
        .parse::<u16>()
        .map_err(|_| ConfigError::InvalidSshConfig {
            path: source.path.clone(),
            line: source.line,
            message: format!("invalid SSH port `{value}`"),
        })?;
    if port == 0 {
        return invalid_value("Port", source);
    }
    Ok(port)
}

fn parse_u64(directive: &str, value: &str, source: &ConfigValueSource) -> Result<u64, ConfigError> {
    value
        .parse::<u64>()
        .map_err(|_| ConfigError::InvalidSshConfig {
            path: source.path.clone(),
            line: source.line,
            message: format!("{directive} must be a non-negative integer"),
        })
}

fn parse_u32(directive: &str, value: &str, source: &ConfigValueSource) -> Result<u32, ConfigError> {
    value
        .parse::<u32>()
        .map_err(|_| ConfigError::InvalidSshConfig {
            path: source.path.clone(),
            line: source.line,
            message: format!("{directive} must be a non-negative integer"),
        })
}

fn parse_bool(value: &str, source: &ConfigValueSource) -> Result<bool, ConfigError> {
    match value.to_ascii_lowercase().as_str() {
        "yes" | "true" => Ok(true),
        "no" | "false" => Ok(false),
        _ => invalid_value("boolean", source),
    }
}

fn invalid_value<T>(directive: &str, source: &ConfigValueSource) -> Result<T, ConfigError> {
    Err(ConfigError::InvalidSshConfig {
        path: source.path.clone(),
        line: source.line,
        message: format!("invalid {directive} value"),
    })
}

fn parse_known_hosts_paths(
    words: &[String],
    source: &ConfigValueSource,
) -> Result<Vec<String>, ConfigError> {
    if words.is_empty() {
        return Err(ConfigError::InvalidSshConfig {
            path: source.path.clone(),
            line: source.line,
            message: "known-hosts file setting requires a value".to_owned(),
        });
    }
    if words.iter().any(|value| value.eq_ignore_ascii_case("none")) {
        if words.len() != 1 {
            return Err(ConfigError::InvalidSshConfig {
                path: source.path.clone(),
                line: source.line,
                message: "`none` cannot be combined with known-hosts file paths".to_owned(),
            });
        }
        return Ok(Vec::new());
    }
    Ok(words.to_vec())
}

fn parse_auth_methods(
    value: &str,
    source: &ConfigValueSource,
) -> Result<Vec<AuthMethod>, ConfigError> {
    let mut result = Vec::new();
    for method in value.split(',').map(str::trim) {
        let method = match method.to_ascii_lowercase().as_str() {
            "publickey" => AuthMethod::PublicKey,
            "keyboard-interactive" => AuthMethod::KeyboardInteractive,
            "password" => AuthMethod::Password,
            unsupported => {
                return Err(ConfigError::UnsupportedDirective {
                    path: source.path.clone(),
                    line: source.line,
                    directive: "PreferredAuthentications".to_owned(),
                    reason: format!("authentication method `{unsupported}` is unsupported"),
                });
            }
        };
        if !result.contains(&method) {
            result.push(method);
        }
    }
    if result.is_empty() {
        return invalid_value("PreferredAuthentications", source);
    }
    Ok(result)
}

fn parse_proxy_jump(
    value: &str,
    source: &ConfigValueSource,
) -> Result<Option<Vec<JumpHost>>, ConfigError> {
    if value.eq_ignore_ascii_case("none") {
        return Ok(None);
    }
    let mut hops = Vec::new();
    for item in value.split(',') {
        if item.is_empty() {
            return invalid_value("ProxyJump", source);
        }
        let (user, destination) = match item.rsplit_once('@') {
            Some((user, destination)) if !user.is_empty() && !destination.is_empty() => {
                (Some(user.to_owned()), destination)
            }
            Some(_) => return invalid_value("ProxyJump", source),
            None => (None, item),
        };
        let (hostname, port) = if destination.starts_with('[') {
            let Some(end) = destination.find(']') else {
                return invalid_value("ProxyJump", source);
            };
            let Some(hostname) = destination.get(1..end) else {
                return invalid_value("ProxyJump", source);
            };
            let Some(rest) = destination.get(end + 1..) else {
                return invalid_value("ProxyJump", source);
            };
            let port = if rest.is_empty() {
                None
            } else if let Some(port) = rest.strip_prefix(':') {
                Some(parse_port(port, source)?)
            } else {
                return invalid_value("ProxyJump", source);
            };
            (hostname, port)
        } else {
            match destination.rsplit_once(':') {
                Some((hostname, port)) if !hostname.contains(':') => {
                    (hostname, Some(parse_port(port, source)?))
                }
                _ => (destination, None),
            }
        };
        if hostname.is_empty() {
            return invalid_value("ProxyJump", source);
        }
        hops.push(JumpHost {
            hostname: hostname.to_owned(),
            username: user,
            port,
        });
    }
    Ok(Some(hops))
}

fn parse_algorithm_list(
    value: &str,
    source: &ConfigValueSource,
) -> Result<Vec<String>, ConfigError> {
    let values = value.split(',').collect::<Vec<_>>();
    if values.is_empty()
        || values.iter().any(|value| value.is_empty())
        || values.first().is_some_and(|value| {
            matches!(value.as_bytes().first(), Some(b'+' | b'-' | b'^')) && value.len() == 1
        })
    {
        return invalid_value("algorithm list", source);
    }
    Ok(values.into_iter().map(ToOwned::to_owned).collect())
}

fn match_conditions(
    words: &[String],
    context: &ResolutionContext,
    remote_user: &str,
    path: &Path,
    line: usize,
) -> Result<bool, ConfigError> {
    if words.is_empty() {
        return Err(ConfigError::InvalidSshConfig {
            path: path.to_path_buf(),
            line,
            message: "Match requires conditions".to_owned(),
        });
    }
    let mut index = 0;
    let mut matches = true;
    while let Some(word) = words.get(index) {
        let criterion = word.to_ascii_lowercase();
        if criterion == "all" {
            if words.len() != 1 {
                return Err(ConfigError::InvalidSshConfig {
                    path: path.to_path_buf(),
                    line,
                    message: "Match all cannot be combined with other conditions".to_owned(),
                });
            }
            return Ok(true);
        }
        if matches!(
            criterion.as_str(),
            "exec" | "canonical" | "final" | "localnetwork" | "address" | "raddress" | "tagged"
        ) {
            return Err(ConfigError::UnsupportedDirective {
                path: path.to_path_buf(),
                line,
                directive: format!("Match {criterion}"),
                reason: "evaluating this Match condition is unsupported; no command or network probe was run"
                    .to_owned(),
            });
        }
        if !matches!(
            criterion.as_str(),
            "host" | "originalhost" | "user" | "localuser"
        ) {
            return Err(ConfigError::InvalidSshConfig {
                path: path.to_path_buf(),
                line,
                message: format!("unknown Match criterion `{word}`"),
            });
        }
        index += 1;
        let start = index;
        while words.get(index).is_some_and(|word| {
            !matches!(
                word.to_ascii_lowercase().as_str(),
                "all"
                    | "host"
                    | "originalhost"
                    | "user"
                    | "localuser"
                    | "exec"
                    | "canonical"
                    | "final"
                    | "localnetwork"
                    | "address"
                    | "raddress"
                    | "tagged"
            )
        }) {
            index += 1;
        }
        if start == index {
            return Err(ConfigError::InvalidSshConfig {
                path: path.to_path_buf(),
                line,
                message: format!("Match {criterion} requires a pattern"),
            });
        }
        let Some(pattern_words) = words.get(start..index) else {
            return Err(ConfigError::InvalidSshConfig {
                path: path.to_path_buf(),
                line,
                message: "Match has invalid pattern bounds".to_owned(),
            });
        };
        let patterns = pattern_words
            .iter()
            .flat_map(|word| word.split(','))
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
        let value = match criterion.as_str() {
            "host" | "originalhost" => &context.original_host,
            "user" => remote_user,
            "localuser" => &context.local_user,
            _ => unreachable!("criterion checked above"),
        };
        matches &= host_patterns_match(&patterns, value);
    }
    Ok(matches)
}

fn host_patterns_match(patterns: &[String], hostname: &str) -> bool {
    let mut positive = false;
    for pattern in patterns {
        let (negated, pattern) = pattern
            .strip_prefix('!')
            .map_or((false, pattern.as_str()), |pattern| (true, pattern));
        if glob_matches(pattern, hostname) {
            if negated {
                return false;
            }
            positive = true;
        }
    }
    positive
}

fn literal_host_aliases(patterns: &[String]) -> Vec<String> {
    patterns
        .iter()
        .filter(|pattern| !pattern.starts_with('!'))
        .filter(|pattern| !pattern.contains('*') && !pattern.contains('?'))
        .filter(|pattern| !pattern.is_empty())
        .cloned()
        .collect()
}

fn glob_matches(pattern: &str, candidate: &str) -> bool {
    let pattern = pattern.as_bytes();
    let candidate = candidate.as_bytes();
    let mut pattern_index = 0;
    let mut candidate_index = 0;
    let mut star = None;
    let mut retry = 0;
    while let Some(candidate_char) = candidate.get(candidate_index) {
        match pattern.get(pattern_index).copied() {
            Some(b'?') => {
                pattern_index += 1;
                candidate_index += 1;
            }
            Some(pattern_char) if pattern_char.eq_ignore_ascii_case(candidate_char) => {
                pattern_index += 1;
                candidate_index += 1;
            }
            Some(b'*') => {
                star = Some(pattern_index);
                pattern_index += 1;
                retry = candidate_index;
            }
            _ if star.is_some() => {
                let Some(star_index) = star else {
                    unreachable!("star checked above");
                };
                pattern_index = star_index + 1;
                retry += 1;
                candidate_index = retry;
            }
            _ => return false,
        }
    }
    while pattern.get(pattern_index) == Some(&b'*') {
        pattern_index += 1;
    }
    pattern_index == pattern.len()
}

/// OpenSSH `SendEnv` uses case-sensitive wildcard matching, unlike `Host`.
pub(super) fn send_env_pattern_matches(pattern: &str, variable: &str) -> bool {
    let pattern = pattern.as_bytes();
    let variable = variable.as_bytes();
    let mut pattern_index = 0;
    let mut variable_index = 0;
    let mut star = None;
    let mut retry = 0;
    while let Some(variable_char) = variable.get(variable_index) {
        match pattern.get(pattern_index).copied() {
            Some(b'?') => {
                pattern_index += 1;
                variable_index += 1;
            }
            Some(pattern_char) if pattern_char == *variable_char => {
                pattern_index += 1;
                variable_index += 1;
            }
            Some(b'*') => {
                star = Some(pattern_index);
                pattern_index += 1;
                retry = variable_index;
            }
            _ if star.is_some() => {
                let Some(star_index) = star else {
                    unreachable!("star checked above");
                };
                pattern_index = star_index + 1;
                retry += 1;
                variable_index = retry;
            }
            _ => return false,
        }
    }
    while pattern.get(pattern_index) == Some(&b'*') {
        pattern_index += 1;
    }
    pattern_index == pattern.len()
}

fn split_directive(
    raw_line: &str,
    path: &Path,
    line: usize,
) -> Result<Option<(String, String, Vec<String>)>, ConfigError> {
    let line_without_comment = strip_comment(raw_line, path, line)?;
    let trimmed = line_without_comment.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let key_end = trimmed
        .find(|character: char| character.is_ascii_whitespace() || character == '=')
        .unwrap_or(trimmed.len());
    let Some(key) = trimmed.get(..key_end) else {
        return Err(ConfigError::InvalidSshConfig {
            path: path.to_path_buf(),
            line,
            message: "invalid SSH option boundary".to_owned(),
        });
    };
    if key.is_empty() {
        return Ok(None);
    }
    let Some(rest_after_key) = trimmed.get(key_end..) else {
        return Err(ConfigError::InvalidSshConfig {
            path: path.to_path_buf(),
            line,
            message: "invalid SSH option boundary".to_owned(),
        });
    };
    let mut rest = rest_after_key.trim_start();
    if let Some(rest_after_equals) = rest.strip_prefix('=') {
        rest = rest_after_equals.trim_start();
    }
    let words = lex_words(rest, path, line)?;
    Ok(Some((key.to_owned(), rest.to_owned(), words)))
}

fn strip_comment<'a>(line: &'a str, path: &Path, number: usize) -> Result<&'a str, ConfigError> {
    let mut quote = None;
    let mut escaped = false;
    for (index, character) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if character == '\\' {
            escaped = true;
            continue;
        }
        match (quote, character) {
            (Some(quote_char), character) if quote_char == character => quote = None,
            (None, '\'' | '"') => quote = Some(character),
            (None, '#') => {
                return line
                    .get(..index)
                    .ok_or_else(|| ConfigError::InvalidSshConfig {
                        path: path.to_path_buf(),
                        line: number,
                        message: "invalid SSH comment boundary".to_owned(),
                    });
            }
            _ => {}
        }
    }
    if quote.is_some() || escaped {
        return Err(ConfigError::InvalidSshConfig {
            path: path.to_path_buf(),
            line: number,
            message: "unterminated quote or escape".to_owned(),
        });
    }
    Ok(line)
}

fn lex_words(value: &str, path: &Path, line: usize) -> Result<Vec<String>, ConfigError> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    let mut escaped = false;
    for character in value.chars() {
        if escaped {
            current.push(character);
            escaped = false;
            continue;
        }
        if character == '\\' {
            escaped = true;
            continue;
        }
        match quote {
            Some(quote_char) if quote_char == character => quote = None,
            Some(_) => current.push(character),
            None if matches!(character, '\'' | '"') => quote = Some(character),
            None if character.is_ascii_whitespace() => {
                if !current.is_empty() {
                    words.push(std::mem::take(&mut current));
                }
            }
            None => current.push(character),
        }
    }
    if quote.is_some() || escaped {
        return Err(ConfigError::InvalidSshConfig {
            path: path.to_path_buf(),
            line,
            message: "unterminated quote or escape".to_owned(),
        });
    }
    if !current.is_empty() {
        words.push(current);
    }
    Ok(words)
}

fn expand_value(
    value: &str,
    context: &ExpansionContext<'_>,
    source: &ConfigValueSource,
    expand_tilde: bool,
) -> Result<String, ConfigError> {
    let mut expanded = expand_environment(value, source)?;
    let mut output = String::with_capacity(expanded.len());
    let mut chars = expanded.chars();
    while let Some(character) = chars.next() {
        if character != '%' {
            output.push(character);
            continue;
        }
        let Some(token) = chars.next() else {
            return Err(ConfigError::InvalidSshConfig {
                path: source.path.clone(),
                line: source.line,
                message: "trailing percent token".to_owned(),
            });
        };
        match token {
            '%' => output.push('%'),
            'h' => output.push_str(context.hostname),
            'n' => output.push_str(context.original_host),
            'p' => output.push_str(&context.port.to_string()),
            'r' => output.push_str(context.username),
            'u' => output.push_str(context.local_user),
            'd' => output.push_str(&context.home.to_string_lossy()),
            unsupported => {
                return Err(ConfigError::UnsupportedDirective {
                    path: source.path.clone(),
                    line: source.line,
                    directive: format!("token %{unsupported}"),
                    reason: "this OpenSSH token is not supported by Groky".to_owned(),
                });
            }
        }
    }
    if expand_tilde {
        expanded = output;
        if expanded == "~" {
            return Ok(context.home.to_string_lossy().into_owned());
        }
        if let Some(rest) = expanded.strip_prefix("~/") {
            return Ok(context.home.join(rest).to_string_lossy().into_owned());
        }
        if expanded.starts_with('~') {
            return Err(ConfigError::UnsupportedDirective {
                path: source.path.clone(),
                line: source.line,
                directive: "tilde expansion".to_owned(),
                reason: "only the current user's `~` path is supported".to_owned(),
            });
        }
        return Ok(expanded);
    }
    Ok(output)
}

fn expand_path(
    value: &str,
    context: &ExpansionContext<'_>,
    source: &ConfigValueSource,
) -> Result<PathBuf, ConfigError> {
    Ok(PathBuf::from(expand_value(value, context, source, true)?))
}

fn expand_environment(value: &str, source: &ConfigValueSource) -> Result<String, ConfigError> {
    let mut output = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();
    while let Some(character) = chars.next() {
        if character != '$' {
            output.push(character);
            continue;
        }
        if chars.peek().is_some_and(|character| *character == '$') {
            chars.next();
            output.push('$');
            continue;
        }
        let variable = if chars.peek().is_some_and(|character| *character == '{') {
            chars.next();
            let mut variable = String::new();
            let mut closed = false;
            for character in chars.by_ref() {
                if character == '}' {
                    closed = true;
                    break;
                }
                variable.push(character);
            }
            if !closed || variable.is_empty() {
                return Err(ConfigError::InvalidSshConfig {
                    path: source.path.clone(),
                    line: source.line,
                    message: "invalid environment variable expansion".to_owned(),
                });
            }
            variable
        } else {
            let mut variable = String::new();
            while chars
                .peek()
                .is_some_and(|character| character.is_ascii_alphanumeric() || *character == '_')
            {
                variable.push(chars.next().expect("peeked character exists"));
            }
            if variable.is_empty() {
                output.push('$');
                continue;
            }
            variable
        };
        let value = std::env::var(&variable).map_err(|_| ConfigError::MissingEnvironment {
            path: source.path.clone(),
            line: source.line,
            variable: variable.clone(),
        })?;
        output.push_str(&value);
    }
    Ok(output)
}

fn expand_include_pattern(pattern: &Path, including: &Path) -> Result<Vec<PathBuf>, ConfigError> {
    let path = if pattern.is_absolute() {
        pattern.to_path_buf()
    } else {
        including
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(pattern)
    };
    let paths = expand_glob_path(&path)?;
    Ok(paths)
}

fn expand_glob_path(pattern: &Path) -> Result<Vec<PathBuf>, ConfigError> {
    if !pattern.components().any(|component| {
        let component = component.as_os_str().to_string_lossy();
        component.contains('*') || component.contains('?')
    }) {
        return Ok(pattern
            .exists()
            .then_some(pattern.to_path_buf())
            .into_iter()
            .collect());
    }
    let mut candidates = if pattern.is_absolute() {
        vec![PathBuf::from(std::path::MAIN_SEPARATOR.to_string())]
    } else {
        vec![PathBuf::new()]
    };
    for component in pattern.components() {
        match component {
            Component::Prefix(prefix) => {
                candidates = vec![PathBuf::from(prefix.as_os_str())];
            }
            Component::RootDir => {}
            Component::CurDir => {}
            Component::ParentDir => {
                for candidate in &mut candidates {
                    candidate.push("..");
                }
            }
            Component::Normal(component) => {
                let component_text = component.to_string_lossy();
                if !component_text.contains('*') && !component_text.contains('?') {
                    for candidate in &mut candidates {
                        candidate.push(component);
                    }
                    continue;
                }
                let mut next = Vec::new();
                for candidate in candidates {
                    let entries = match fs::read_dir(&candidate) {
                        Ok(entries) => entries,
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                        Err(source) => {
                            return Err(ConfigError::Io {
                                path: candidate,
                                source,
                            });
                        }
                    };
                    let mut matches = entries
                        .map(|entry| entry.map(|entry| entry.path()))
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(|source| ConfigError::Io {
                            path: candidate.clone(),
                            source,
                        })?
                        .into_iter()
                        .filter(|entry| {
                            entry.file_name().is_some_and(|name| {
                                glob_matches(&component_text, &name.to_string_lossy())
                            })
                        })
                        .collect::<Vec<_>>();
                    matches.sort();
                    next.extend(matches);
                }
                candidates = next;
            }
        }
    }
    Ok(candidates)
}

fn local_user() -> Result<String, ConfigError> {
    local_user_from(
        |key| std::env::var_os(key).map(|value| value.to_string_lossy().into_owned()),
        || whoami::fallible::username().ok(),
    )
}

pub(super) fn local_user_from(
    mut environment: impl FnMut(&str) -> Option<String>,
    fallback: impl FnOnce() -> Option<String>,
) -> Result<String, ConfigError> {
    for key in ["USER", "USERNAME"] {
        if let Some(value) = environment(key)
            && !value.is_empty()
        {
            return Ok(value);
        }
    }
    fallback().filter(|value| !value.is_empty()).ok_or_else(|| {
        ConfigError::InvalidTarget(
            "could not determine the local user for SSH configuration resolution".to_owned(),
        )
    })
}

fn default_global_known_hosts() -> Vec<PathBuf> {
    #[cfg(windows)]
    {
        return std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .map(|base| vec![base.join("ssh").join("ssh_known_hosts")])
            .unwrap_or_default();
    }
    #[cfg(not(windows))]
    {
        vec![
            PathBuf::from("/etc/ssh/ssh_known_hosts"),
            PathBuf::from("/etc/ssh/ssh_known_hosts2"),
        ]
    }
}
