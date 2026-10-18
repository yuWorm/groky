//! Local-only SSH target commands.
//!
//! These commands never authenticate an xAI provider or choose a model. Connection state lives
//! in the leader-held SSH service, so a short-lived CLI process cannot accidentally release it.

use anyhow::{Context, Result, bail};

use crate::app::{SshAddArgs, SshArgs, SshCommand, SshProjectOpen};

pub async fn run(args: SshArgs) -> Result<()> {
    match args.command {
        SshCommand::List { json } => list(json).await,
        SshCommand::Add(args) => add(args),
        SshCommand::Connect { target, json } => connect(&target, false, json).await,
        SshCommand::Disconnect { target, json } => connect(&target, true, json).await,
        SshCommand::Open { .. } => {
            bail!("SSH project opening must be started by the interactive pager")
        }
    }
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
    let mut target = xai_grok_ssh::SshTarget::new(args.host);
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
