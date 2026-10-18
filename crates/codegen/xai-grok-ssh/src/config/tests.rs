use std::fs;
use std::path::PathBuf;

use tempfile::TempDir;

use super::{
    AuthMethod, ConfigError, HostKeyPolicy, ProxyRoute, SshConfigSource, SshTarget, TargetSource,
    TargetStore,
};

struct Fixture {
    _temp: TempDir,
    home: PathBuf,
    ssh_home: PathBuf,
    user_config: PathBuf,
    store: TargetStore,
}

impl Fixture {
    fn new(user_config_text: &str, system_config_text: &str) -> Self {
        let temp = tempfile::tempdir().expect("create temp directory");
        let root = temp
            .path()
            .canonicalize()
            .expect("canonical temp directory");
        let home = root.join("groky-home");
        let ssh_home = root.join("user-home");
        let user_config = ssh_home.join(".ssh").join("config");
        let system_config = root.join("system-ssh-config");
        fs::create_dir_all(user_config.parent().expect("config parent")).expect("create .ssh");
        fs::create_dir_all(&home).expect("create Groky home");
        fs::write(&user_config, user_config_text).expect("write user config");
        fs::write(&system_config, system_config_text).expect("write system config");
        let store = TargetStore::with_ssh_config_paths(
            home.clone(),
            ssh_home.clone(),
            user_config.clone(),
            system_config,
        );
        Self {
            _temp: temp,
            home,
            ssh_home,
            user_config,
            store,
        }
    }

    fn target(&self, id: &str, host: &str) -> SshTarget {
        let mut target = SshTarget::new(host);
        target.id = id.to_owned();
        target
    }
}

#[test]
fn resolver_honors_target_user_port_overrides_and_ssh_precedence() {
    let fixture = Fixture::new(
        r#"
            Host prod
                HostName user.example.test
                User config-user
                Port 2200
                IdentityFile ~/.ssh/id_user_%r
                UserKnownHostsFile ~/.ssh/known_%r
                StrictHostKeyChecking accept-new
                PreferredAuthentications publickey,password
                ProxyJump jump-user@bastion.example.test:2222
                ConnectTimeout 0
                ServerAliveInterval 15
                ServerAliveCountMax 4
                TCPKeepAlive no
                HostKeyAlgorithms ssh-ed25519
        "#,
        r#"
            Host prod
                HostName system.example.test
                User system-user
                Port 2201
                IdentityFile ~/.ssh/id_system_%r
        "#,
    );
    let mut target = fixture.target("prod-target", "prod");
    target.user = Some("target-user".to_owned());
    target.port = Some(2022);
    target.identity_files.push(PathBuf::from("manual-identity"));
    fixture.store.upsert(target).expect("persist target");

    let resolved = fixture
        .store
        .resolve("prod-target")
        .expect("resolve target");

    assert_eq!(resolved.hostname, "user.example.test");
    assert_eq!(resolved.username, "target-user");
    assert_eq!(resolved.port, 2022);
    assert_eq!(
        resolved.identity_files,
        vec![
            PathBuf::from("manual-identity"),
            fixture.ssh_home.join(".ssh").join("id_user_target-user"),
            fixture.ssh_home.join(".ssh").join("id_system_target-user"),
        ]
    );
    assert_eq!(
        resolved.known_hosts.user_files,
        vec![fixture.ssh_home.join(".ssh").join("known_target-user")]
    );
    assert_eq!(resolved.host_key_policy, HostKeyPolicy::AcceptNew);
    assert_eq!(
        resolved.preferred_auth,
        vec![AuthMethod::PublicKey, AuthMethod::Password]
    );
    assert_eq!(
        resolved.proxy,
        Some(ProxyRoute::Jump(vec![super::JumpHost {
            hostname: "bastion.example.test".to_owned(),
            username: Some("jump-user".to_owned()),
            port: Some(2222),
        }]))
    );
    assert_eq!(resolved.connect_timeout, None);
    let keepalive = resolved.server_alive.expect("configured keepalive");
    assert_eq!(keepalive.interval.seconds, 15);
    assert_eq!(keepalive.tcp_keep_alive, Some(false));
    assert_eq!(
        resolved.algorithms.host_key,
        Some(vec!["ssh-ed25519".to_owned()])
    );
    let hostname_source = resolved
        .provenance
        .fields
        .get("hostname")
        .expect("hostname source");
    assert_eq!(hostname_source.source, SshConfigSource::UserSsh);
    assert_eq!(hostname_source.path, fixture.user_config);
}

#[test]
fn resolver_accumulates_and_removes_send_env_patterns_case_sensitively() {
    let fixture = Fixture::new(
        r#"
            Host env
                SendEnv LANG LC_* DISPLAY
                SendEnv -LC_TIME lc_*
        "#,
        r#"
            Host env
                SendEnv -LANG TERM
        "#,
    );
    fixture
        .store
        .upsert(fixture.target("env", "env"))
        .expect("save target");

    let resolved = fixture.store.resolve("env").expect("resolve target");

    assert_eq!(
        resolved.send_env,
        vec!["DISPLAY".to_owned(), "lc_*".to_owned(), "TERM".to_owned()]
    );
    assert!(super::send_env_pattern_matches("LC_*", "LC_TIME"));
    assert!(!super::send_env_pattern_matches("LC_*", "lc_time"));
    assert_eq!(
        resolved
            .provenance
            .fields
            .get("send_env.0")
            .expect("DISPLAY source")
            .source,
        SshConfigSource::UserSsh
    );
    assert_eq!(
        resolved
            .provenance
            .fields
            .get("send_env.2")
            .expect("TERM source")
            .source,
        SshConfigSource::SystemSsh
    );
}

#[test]
fn resolver_applies_host_globs_negation_and_supported_match_conditions() {
    let fixture = Fixture::new(
        r#"
            Host * !skip
                HostName wildcard.example.test
            Host skip
                HostName skip.example.test
            Match host matched user deploy
                Port 2201
        "#,
        "",
    );
    let mut matched = fixture.target("matched", "matched");
    matched.user = Some("deploy".to_owned());
    let skip = fixture.target("skip", "skip");
    fixture.store.upsert(matched).expect("save matched target");
    fixture.store.upsert(skip).expect("save skip target");

    let matched = fixture.store.resolve("matched").expect("resolve matched");
    let skip = fixture.store.resolve("skip").expect("resolve skip");

    assert_eq!(matched.hostname, "wildcard.example.test");
    assert_eq!(matched.port, 2201);
    assert_eq!(skip.hostname, "skip.example.test");
    assert_eq!(skip.port, 22);
}

#[test]
fn include_is_inline_sorted_and_first_value_wins() {
    let fixture = Fixture::new(
        r#"
            Include conf.d/*.conf
            Host prod
                User later-user
        "#,
        "",
    );
    let include_dir = fixture.user_config.parent().expect("parent").join("conf.d");
    fs::create_dir_all(&include_dir).expect("create include directory");
    fs::write(
        include_dir.join("10-target.conf"),
        "Host prod\n    User included-user\n",
    )
    .expect("write include");
    fs::write(
        include_dir.join("20-ignored.conf"),
        "Host prod\n    User ignored-user\n",
    )
    .expect("write include");
    fixture
        .store
        .upsert(fixture.target("prod", "prod"))
        .expect("save target");

    let resolved = fixture.store.resolve("prod").expect("resolve target");

    assert_eq!(resolved.username, "included-user");
}

#[test]
fn include_preserves_its_terminal_host_context_inline() {
    let fixture = Fixture::new("Include scope.conf\n    Port 2200\n", "");
    fs::write(
        fixture
            .user_config
            .parent()
            .expect("parent")
            .join("scope.conf"),
        "Host other\n",
    )
    .expect("write include");
    fixture
        .store
        .upsert(fixture.target("prod", "prod"))
        .expect("save target");

    let resolved = fixture.store.resolve("prod").expect("resolve target");

    assert_eq!(resolved.port, 22);
}

#[test]
fn recursive_includes_fail_with_a_specific_error() {
    let fixture = Fixture::new("Include loop.conf\n", "");
    fs::write(
        fixture
            .user_config
            .parent()
            .expect("parent")
            .join("loop.conf"),
        "Include config\n",
    )
    .expect("write recursive include");
    fixture
        .store
        .upsert(fixture.target("loop", "loop"))
        .expect("save target");

    let error = fixture
        .store
        .resolve("loop")
        .expect_err("recursive include fails");

    assert!(matches!(error, ConfigError::IncludeRecursion { .. }));
}

#[test]
fn listing_imports_literal_aliases_without_evaluating_match_exec() {
    let fixture = Fixture::new("", "");
    let marker = fixture.home.join("match-exec-must-not-run");
    fs::write(
        &fixture.user_config,
        format!(
            "Host literal another *.wild !excluded\n    User configured\nMatch exec \"touch {}\"\n    Port 2022\n",
            marker.display()
        ),
    )
    .expect("write SSH config");
    fs::remove_dir_all(&fixture.home).expect("remove absent Groky home");

    let targets = fixture.store.list().expect("list aliases");
    assert!(!marker.exists(), "listing must not execute Match exec");

    let aliases = targets
        .into_iter()
        .filter(|target| matches!(&target.source, TargetSource::Imported { .. }))
        .collect::<Vec<_>>();
    assert_eq!(
        aliases
            .iter()
            .map(|target| target.host.as_str())
            .collect::<Vec<_>>(),
        vec!["literal", "another"]
    );
    assert!(aliases.iter().all(|target| {
        matches!(
            &target.source,
            TargetSource::Imported {
                path,
                line: 1
            } if path == &fixture.user_config
        )
    }));
    let error = fixture
        .store
        .resolve("literal")
        .expect_err("Match exec is refused, never run");
    assert!(!marker.exists(), "resolution must not execute Match exec");
    assert!(matches!(
        error,
        ConfigError::UnsupportedDirective { directive, .. } if directive == "Match exec"
    ));
}

#[test]
fn proxy_command_expands_tokens_without_executing() {
    let fixture = Fixture::new("", "");
    let marker = fixture.home.join("proxy-command-must-not-run");
    fs::write(
        &fixture.user_config,
        format!(
            "Host proxy\n    HostName endpoint.example.test\n    ProxyCommand touch {} --host %h --port %p --origin %n --user %r\n",
            marker.display()
        ),
    )
    .expect("write SSH config");
    let mut target = fixture.target("proxy", "proxy");
    target.user = Some("remote-user".to_owned());
    fixture.store.upsert(target).expect("save target");

    let resolved = fixture.store.resolve("proxy").expect("resolve proxy route");

    assert_eq!(
        resolved.proxy,
        Some(ProxyRoute::Command(format!(
            "touch {} --host endpoint.example.test --port 22 --origin proxy --user remote-user",
            marker.display()
        )))
    );
    assert!(!marker.exists(), "resolver must not execute ProxyCommand");
}

#[test]
fn unsupported_active_security_directive_is_not_silently_ignored() {
    let fixture = Fixture::new(
        r#"
            Host secure
                VerifyHostKeyDNS yes
        "#,
        "",
    );
    fixture
        .store
        .upsert(fixture.target("secure", "secure"))
        .expect("save target");

    let error = fixture
        .store
        .resolve("secure")
        .expect_err("unsupported security directive fails closed");

    assert!(matches!(
        error,
        ConfigError::UnsupportedDirective { directive, .. } if directive == "verifyhostkeydns"
    ));
}

#[test]
fn invalid_active_option_value_is_reported() {
    let fixture = Fixture::new(
        r#"
            Host invalid
                Port 0
        "#,
        "",
    );
    fixture
        .store
        .upsert(fixture.target("invalid", "invalid"))
        .expect("save target");

    let error = fixture
        .store
        .resolve("invalid")
        .expect_err("invalid port is reported");

    assert!(matches!(error, ConfigError::InvalidSshConfig { .. }));
}

#[test]
fn target_persistence_preserves_unrelated_and_target_extension_keys() {
    let fixture = Fixture::new("", "");
    fs::write(
        fixture.home.join("config.toml"),
        r#"
            [unrelated]
            keep = "yes"

            [ssh]
            extra = true

            [ssh.targets.persisted]
            host = "old.example.test"
            extra = 42
        "#,
    )
    .expect("write existing global config");
    let mut target = fixture.target("persisted", "new.example.test");
    target.label = "Updated target".to_owned();
    target.credential_ref = Some("keychain:ssh/persisted".to_owned());
    target.worker_command = vec![
        "groky".to_owned(),
        "worker".to_owned(),
        "--stdio".to_owned(),
    ];

    fixture.store.upsert(target).expect("update target");

    let value: toml::Value = toml::from_str(
        &fs::read_to_string(fixture.home.join("config.toml")).expect("read persisted config"),
    )
    .expect("parse persisted config");
    let root = value.as_table().expect("global config is a table");
    let ssh = root
        .get("ssh")
        .and_then(toml::Value::as_table)
        .expect("ssh is a table");
    let targets = ssh
        .get("targets")
        .and_then(toml::Value::as_table)
        .expect("ssh targets is a table");
    let persisted = targets
        .get("persisted")
        .and_then(toml::Value::as_table)
        .expect("persisted target is a table");
    assert_eq!(
        root.get("unrelated")
            .and_then(toml::Value::as_table)
            .and_then(|unrelated| unrelated.get("keep"))
            .and_then(toml::Value::as_str),
        Some("yes")
    );
    assert_eq!(ssh.get("extra").and_then(toml::Value::as_bool), Some(true));
    assert_eq!(
        persisted.get("extra").and_then(toml::Value::as_integer),
        Some(42)
    );
    assert_eq!(
        persisted.get("host").and_then(toml::Value::as_str),
        Some("new.example.test")
    );
}

#[test]
fn user_target_crud_uses_stable_ids_and_never_edits_imported_aliases() {
    let fixture = Fixture::new("Host imported\n    HostName imported.example.test\n", "");
    let mut target = fixture.target("stable-target", "manual.example.test");
    target.label = "Editable target".to_owned();
    let saved = fixture.store.upsert(target).expect("save target");

    assert_eq!(saved.id, "stable-target");
    assert_eq!(
        fixture.store.get("stable-target").expect("get target"),
        Some(saved.clone())
    );
    assert_eq!(
        fixture
            .store
            .get("manual.example.test")
            .expect("get target by host alias"),
        Some(saved.clone())
    );
    assert!(
        fixture
            .store
            .list()
            .expect("list targets")
            .iter()
            .any(|target| target.id == "imported:imported")
    );
    assert!(matches!(
        fixture
            .store
            .remove("imported")
            .expect_err("imported alias is read-only"),
        ConfigError::ImmutableImportedTarget(_)
    ));
    assert_eq!(
        fixture
            .store
            .remove("stable-target")
            .expect("remove target"),
        Some(saved)
    );
    assert_eq!(
        fixture
            .store
            .get("stable-target")
            .expect("get deleted target"),
        None
    );
}

#[test]
fn worker_command_parser_preserves_quoted_arguments_without_a_shell() {
    assert_eq!(
        super::parse_worker_command(r#"groky worker --socket "a path/socket""#)
            .expect("parse worker command"),
        vec!["groky", "worker", "--socket", "a path/socket"]
    );
    assert!(super::parse_worker_command("groky 'unterminated").is_err());
}

#[test]
fn resolver_preserves_open_ssh_algorithm_list_modifiers() {
    let fixture = Fixture::new(
        "",
        r#"
            Host *
                Ciphers ^aes128-gcm@openssh.com,aes256-gcm@openssh.com
                KexAlgorithms +ecdh-sha2-nistp256
                MACs -hmac-sha1
        "#,
    );
    fixture
        .store
        .upsert(fixture.target("modified-algorithms", "fixture.test"))
        .expect("save target");

    let resolved = fixture
        .store
        .resolve("modified-algorithms")
        .expect("resolve modifiers");

    assert_eq!(
        resolved.algorithms.ciphers,
        Some(vec![
            "^aes128-gcm@openssh.com".to_owned(),
            "aes256-gcm@openssh.com".to_owned()
        ])
    );
    assert_eq!(
        resolved.algorithms.kex,
        Some(vec!["+ecdh-sha2-nistp256".to_owned()])
    );
    assert_eq!(
        resolved.algorithms.macs,
        Some(vec!["-hmac-sha1".to_owned()])
    );
}

#[test]
fn resolver_falls_back_to_os_user_when_pty_clears_environment() {
    let username = super::parser::local_user_from(|_| None, || Some("pty-user".to_owned()))
        .expect("OS username fallback");

    assert_eq!(username, "pty-user");
}
