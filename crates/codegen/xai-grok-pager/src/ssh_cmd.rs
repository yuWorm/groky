//! Local-only SSH target commands.
//!
//! These commands never authenticate an xAI provider or choose a model. Connection state lives
//! in the leader-held SSH service, so a short-lived CLI process cannot accidentally release it.

use anyhow::{Context, Result, bail};

use crate::{
    app::{SshAddArgs, SshArgs, SshCommand, SshProjectOpen},
    ssh_tui::SshTuiStart,
};

/// Run one SSH command. A selected remote directory is returned for the normal pager startup
/// path; a completed management interaction without a selected project returns `None`.
pub async fn run(args: SshArgs) -> Result<Option<SshProjectOpen>> {
    match args.command {
        None => run_interactive(SshTuiStart::Manager, "`groky ssh`").await,
        Some(SshCommand::List { json }) => {
            list(json).await?;
            Ok(None)
        }
        Some(SshCommand::Add(args)) if args.host.is_some() => {
            add(args)?;
            Ok(None)
        }
        Some(SshCommand::Add(args)) => {
            reject_add_flags_without_host(&args)?;
            run_interactive(SshTuiStart::Add, "`groky ssh add`").await
        }
        Some(SshCommand::Connect {
            target,
            json,
            interactive: false,
        }) => {
            connect(&target, false, json).await?;
            Ok(None)
        }
        Some(SshCommand::Connect {
            target,
            interactive: true,
            ..
        }) => {
            let command = "`groky ssh connect TARGET --interactive`";
            require_interactive_terminal(command)?;
            let target_id = target_by_id_or_alias(&target)?.id;
            crate::ssh_tui::run(SshTuiStart::Connect { target_id }).await
        }
        Some(SshCommand::Disconnect { target, json }) => {
            connect(&target, true, json).await?;
            Ok(None)
        }
        Some(SshCommand::Open {
            target: Some(target),
            root: Some(root),
        }) => {
            require_interactive_terminal("`groky ssh open TARGET REMOTE_ROOT`")?;
            Ok(Some(prepare_open(target, root)?))
        }
        Some(SshCommand::Open {
            target: Some(target),
            root: None,
        }) => {
            let command = "`groky ssh open [TARGET] [REMOTE_ROOT]`";
            require_interactive_terminal(command)?;
            let target_id = target_by_id_or_alias(&target)?.id;
            crate::ssh_tui::run(SshTuiStart::Open {
                target_id: Some(target_id),
            })
            .await
        }
        Some(SshCommand::Open {
            target: None,
            root: None,
        }) => run_interactive(
            SshTuiStart::Open { target_id: None },
            "`groky ssh open [TARGET] [REMOTE_ROOT]`",
        )
        .await,
        Some(SshCommand::Open {
            target: None,
            root: Some(_),
        }) => bail!("`REMOTE_ROOT` requires a configured SSH target"),
    }
}

fn reject_add_flags_without_host(args: &SshAddArgs) -> Result<()> {
    if args.id.is_some()
        || args.label.is_some()
        || args.user.is_some()
        || args.port.is_some()
        || !args.identity_files.is_empty()
        || args.credential_ref.is_some()
        || args.worker_command.is_some()
        || args.json
    {
        bail!("SSH target fields require HOST; omit them to open the interactive add form");
    }
    Ok(())
}

async fn run_interactive(
    start: SshTuiStart,
    command: &'static str,
) -> Result<Option<SshProjectOpen>> {
    require_interactive_terminal(command)?;
    crate::ssh_tui::run(start).await
}

fn require_interactive_terminal(command: &str) -> Result<()> {
    use std::io::IsTerminal;

    if std::io::stdin().is_terminal() && std::io::stdout().is_terminal() {
        return Ok(());
    }
    bail!(
        "{command} requires an interactive terminal with both stdin and stdout attached; \
         provide HOST for noninteractive target saving or use an existing noninteractive SSH command"
    );
}

/// Validate the target before the normal pager startup path pre-mints a session id for consent.
pub fn prepare_open(target: String, root: String) -> Result<SshProjectOpen> {
    let target = target_by_id_or_alias(&target)?;
    if root.trim().is_empty() {
        bail!("remote project root must not be empty");
    }
    Ok(SshProjectOpen {
        target_id: target.id,
        root,
        project_session_id: uuid::Uuid::now_v7().to_string(),
        expected_identity: None,
    })
}

pub fn target_by_id_or_alias(id_or_alias: &str) -> Result<xai_grok_ssh::SshTarget> {
    xai_grok_ssh::TargetStore::new(xai_grok_shell::util::grok_home::grok_home())
        .get(id_or_alias)
        .context("could not read SSH target configuration")?
        .ok_or_else(|| anyhow::anyhow!("SSH target '{id_or_alias}' was not found"))
}

async fn list(json: bool) -> Result<()> {
    let store = xai_grok_ssh::TargetStore::new(xai_grok_shell::util::grok_home::grok_home());
    let targets = store
        .list()
        .context("could not read SSH target configuration")?;
    let mut rows = Vec::with_capacity(targets.len());
    for target in targets {
        let effective = match store.resolve(&target.id) {
            Ok(resolved) => serde_json::json!({
                "address": format!("{}@{}:{}", resolved.username, resolved.hostname, resolved.port),
                "error": serde_json::Value::Null,
            }),
            Err(error) => serde_json::json!({
                "address": serde_json::Value::Null,
                "error": error.to_string(),
            }),
        };
        let status = target_status(&target.id).await.unwrap_or_else(
            |error| serde_json::json!({"state": "unavailable", "detail": error.to_string()}),
        );
        rows.push(serde_json::json!({
            "id": target.id,
            "label": target.label,
            "host": target.host,
            "source": target.source,
            "effective": effective,
            "connection": status,
        }));
    }
    if json {
        println!("{}", serde_json::to_string(&rows)?);
    } else if rows.is_empty() {
        println!("No SSH targets configured.");
    } else {
        for row in rows {
            let id = row
                .get("id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("?");
            let label = row
                .get("label")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("?");
            let source = row
                .get("source")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let effective = row
                .get("effective")
                .and_then(|value| value.get("address"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unresolved");
            let state = row
                .get("connection")
                .and_then(|value| value.get("state"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unavailable");
            println!("{label} ({id})\n  {effective} · {state} · {source}");
        }
    }
    Ok(())
}

fn add(args: SshAddArgs) -> Result<()> {
    let host = args
        .host
        .ok_or_else(|| anyhow::anyhow!("SSH target saving requires HOST"))?;
    let mut target = xai_grok_ssh::SshTarget::new(host);
    if let Some(id) = args.id {
        target.id = id;
    }
    if let Some(label) = args.label {
        target.label = label;
    }
    target.user = args.user;
    target.port = args.port;
    target.identity_files = args.identity_files;
    target.credential_ref = args.credential_ref;
    if let Some(worker_command) = args.worker_command {
        target.worker_command = xai_grok_ssh::parse_worker_command(&worker_command)
            .context("invalid --worker-command")?;
    }
    let target = xai_grok_ssh::TargetStore::new(xai_grok_shell::util::grok_home::grok_home())
        .upsert(target)
        .context("could not save SSH target")?;
    if args.json {
        println!("{}", serde_json::to_string(&target)?);
    } else {
        println!("Saved SSH target {} ({})", target.label, target.id);
    }
    Ok(())
}

async fn connect(id_or_alias: &str, disconnect: bool, json: bool) -> Result<()> {
    let target = target_by_id_or_alias(id_or_alias)?;
    let command = if disconnect {
        xai_grok_shell::ssh::SshControlCommand::Disconnect {
            target_id: target.id.clone(),
        }
    } else {
        xai_grok_shell::ssh::SshControlCommand::Connect {
            target_id: target.id.clone(),
            interactive: false,
        }
    };
    let (_, reply) = control(command).await?;
    let xai_grok_shell::ssh::SshControlReply::TargetStatus(status) = reply else {
        bail!("SSH local service returned an unexpected connection response");
    };
    let payload = serde_json::json!({
        "targetId": status.target_id,
        "state": status.connection,
        "detail": status.detail,
    });
    if json {
        println!("{}", serde_json::to_string(&payload)?);
    } else {
        let action = if disconnect {
            "Disconnected"
        } else {
            "Connected"
        };
        println!(
            "{action} SSH target {}: {}",
            target.label,
            serde_json::to_string(&payload["state"])?
        );
        if let Some(detail) = payload["detail"].as_str() {
            println!("  {detail}");
        }
    }
    Ok(())
}

async fn target_status(target_id: &str) -> Result<serde_json::Value> {
    let (_, reply) = control(xai_grok_shell::ssh::SshControlCommand::ConnectionStatus {
        target_id: target_id.to_owned(),
    })
    .await?;
    let xai_grok_shell::ssh::SshControlReply::TargetStatus(status) = reply else {
        bail!("SSH local service returned an unexpected status response");
    };
    Ok(serde_json::json!({
        "state": status.connection,
        "detail": status.detail,
    }))
}

async fn control(
    command: xai_grok_shell::ssh::SshControlCommand,
) -> Result<(u64, xai_grok_shell::ssh::SshControlReply)> {
    crate::app::ssh_control::request(command).await
}
