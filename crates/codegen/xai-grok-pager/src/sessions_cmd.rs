use anyhow::{Result, bail};
use clap::Subcommand;
use xai_grok_login::{AuthManager, try_ensure_fresh_auth};
use xai_grok_shell::agent::config::Config as AgentConfig;
use xai_grok_shell::session::merge::MergedSession;
use xai_grok_shell::util::grok_home::grok_home;
#[derive(Debug, clap::Args, Clone)]
pub struct SessionsArgs {
    #[command(subcommand)]
    command: SessionsCommand,
}

#[derive(Debug, Subcommand, Clone)]
enum SessionsCommand {
    /// List recent sessions (same as search with no query)
    List {
        /// Maximum number of sessions to show
        #[arg(short = 'n', long, default_value = "20")]
        limit: usize,
    },
    /// Search sessions by keyword
    Search {
        /// Search query (searches summaries and first prompts).
        query: String,
        /// Maximum number of sessions to show
        #[arg(short = 'n', long, default_value = "20")]
        limit: usize,
    },
    /// Permanently delete a session from history
    Delete {
        /// Session id to delete.
        id: String,
    },
    /// Discover and import a foreign agent transcript as a native Groky session.
    Import {
        /// A discovered session ID or an explicit transcript, store, or database path.
        #[arg(value_name = "ID_OR_PATH")]
        target: Option<String>,
        /// Session ID within a discovered or explicit multi-session store.
        #[arg(long, value_name = "ID")]
        id: Option<String>,
        /// Foreign session source for an explicit path, or to filter discovery.
        #[arg(long = "from", value_name = "SOURCE")]
        source: Option<xai_grok_foreign_sessions::import::ImportSource>,
        /// Search every project instead of only the current directory.
        #[arg(long)]
        all: bool,
        /// Print candidates without importing one.
        #[arg(long)]
        list: bool,
        /// Emit machine-readable candidate or import output.
        #[arg(long)]
        json: bool,
    },
}

pub async fn run(args: SessionsArgs, agent_config: &AgentConfig) -> Result<()> {
    let cwd = std::env::current_dir().unwrap_or_else(|_| ".".into());

    // Import is local-only. It must not refresh auth or construct a network registry client.
    if let SessionsCommand::Import {
        target,
        id,
        source,
        all,
        list,
        json,
    } = &args.command
    {
        return run_import(
            target.as_deref(),
            id.as_deref(),
            *source,
            *all,
            *list,
            *json,
            &cwd,
            agent_config,
        )
        .await;
    }

    // Best-effort only: never force an interactive public login here. Enterprise deployments may configure only a
    // deployment_key and a custom xai_api_base_url. Otherwise we still proceed so the SessionRegistryClient can use
    // the deployment_key when talking to the custom proxy.
    let auth = try_ensure_fresh_auth(
        &agent_config.grok_com_config,
        agent_config.endpoints.proxy_url(),
    )
    .await;

    let auth_manager = std::sync::Arc::new(AuthManager::new_with_proxy_base_url(
        &grok_home(),
        agent_config.grok_com_config.clone(),
        agent_config.endpoints.proxy_url(),
    ));

    let client = xai_grok_shell::agent::session_registry_client::SessionRegistryClient::new(
        agent_config.endpoints.proxy_url(),
        String::new(),
    )
    .with_deployment_key(agent_config.endpoints.deployment_key.clone())
    .with_alpha_test_key(agent_config.endpoints.alpha_test_key.clone())
    .with_auth(auth_manager.clone());


    match args.command {
        SessionsCommand::List { limit } => {
            let sessions = xai_grok_shell::session::merge::fetch_merged(
                Some(&client),
                cwd.to_str(),
                xai_grok_shell::session::merge::CwdScope::WithSiblings,
                None,
                limit,
                // The CLI listing is an inventory, not the resume picker.
                xai_grok_shell::session::visibility::HeadlessPolicy::Include,
            )
            .await;
            print_sessions_grouped(&sessions);
        }
        SessionsCommand::Search { query, limit } => {
            use std::collections::HashSet;
            use xai_grok_shell::session::merge::REMOTE_TIMEOUT;
            use xai_grok_shell::session::storage::search::{
                IndexDecision, SessionSearchRequest, execute_search,
            };

            // Search is the only subcommand that reads the index, so it is the only one to start one
            let search = xai_grok_shell::session::storage::search::start_if_enabled(agent_config);

            let req = SessionSearchRequest {
                query,
                cwd: Some(cwd.to_string_lossy().to_string()),
                limit,
                offset: 0,
                include_content: true,
            };
            let root = grok_home();

            let remote_limit = (limit * 3).max(100) as i64;
            let (local_resp, remote_results) = tokio::join!(
                execute_search(IndexDecision::settled(&search), &root, &req),
                async {
                    tokio::time::timeout(
                        REMOTE_TIMEOUT,
                        client.search(Some(&req.query), remote_limit),
                    )
                    .await
                    .unwrap_or_else(|_| {
                        eprintln!("warning: remote session search timed out");
                        Ok(Vec::new())
                    })
                    .unwrap_or_else(|e| {
                        eprintln!("warning: remote session search failed: {e}");
                        Vec::new()
                    })
                }
            );

            let resp = local_resp?;
            if let Some(by) = search.off_reason() {
                eprintln!(
                    "warning: local session search is off ({by}); searched remote sessions only."
                );
            }
            let local_ids: HashSet<&str> =
                resp.results.iter().map(|r| r.session_id.as_str()).collect();

            for hit in &resp.results {
                let title = summary_or_untitled(&hit.title);
                let time = chrono::DateTime::from_timestamp(hit.updated_at_unix, 0)
                    .map(|dt| {
                        dt.with_timezone(&chrono::Local)
                            .format("%b %d, %l:%M%P")
                            .to_string()
                    })
                    .unwrap_or_default();
                println!(
                    "{} (score: {:.2})  {}\n  {}\n  {}",
                    hit.session_id,
                    hit.score,
                    time,
                    title,
                    hit.snippet.as_deref().unwrap_or("")
                );
            }

            let remaining = limit.saturating_sub(resp.results.len());
            let mut remote_shown = 0usize;
            for r in &remote_results {
                if remote_shown >= remaining {
                    break;
                }
                if local_ids.contains(r.session_id.as_str()) {
                    continue;
                }
                let title = summary_or_untitled(&r.summary);
                let time = chrono::DateTime::parse_from_rfc3339(&r.updated_at)
                    .map(|dt| {
                        dt.with_timezone(&chrono::Local)
                            .format("%b %d, %l:%M%P")
                            .to_string()
                    })
                    .unwrap_or_default();
                let snippet: String = r
                    .first_prompt
                    .as_deref()
                    .unwrap_or("")
                    .chars()
                    .take(80)
                    .collect();
                println!(
                    "{} (remote)  {}\n  {}\n  {}",
                    r.session_id, time, title, snippet
                );
                remote_shown += 1;
            }

            println!("\nTotal: {}", resp.results.len() + remote_shown);
        }
        SessionsCommand::Delete { id } => {
            // Always attempt the remote delete when authenticated and not ZDR; `list` and `search` likewise query remote
            // unconditionally. Gating on storage mode is impossible here: the CLI builds config without remote settings. ZDR
            // teams never upload, so there is nothing remote to delete.
            let needs_remote = auth.as_ref().is_some_and(|a| !a.is_zdr_team());

            // Pass `cwd = None` so the session is found by id regardless of which workspace it was created in
            // The local delete still uses the resolved per-session cwd
            // No search handle: the eviction inside prunes the row from another process's index, so a delete never needs one of its own
            let deletion = xai_grok_shell::session::persistence::delete_session_history(
                &id,
                None,
                needs_remote,
                auth_manager.clone(),
                None,
            )
            .await?;

            if deletion.any_removed() {
                println!("Deleted session {id}");
            } else {
                println!("No session found with id {id}.");
            }
        }
        SessionsCommand::Import { .. } => unreachable!("local import returns before auth setup"),
    }

    Ok(())
}
fn safe_cli_display(value: &str) -> String {
    crate::views::session_title::sanitize_display_text(value)
        .trim()
        .chars()
        .take(240)
        .collect()
}

fn print_import_candidates(
    candidates: &[xai_grok_foreign_sessions::import::ImportCandidate],
    warnings: &[String],
    json: bool,
) -> Result<()> {
    if json {
        let sessions: Vec<serde_json::Value> = candidates
            .iter()
            .map(|candidate| {
                serde_json::json!({
                    "source": candidate.source.as_str(),
                    "id": &candidate.id,
                    "path": &candidate.path,
                    "cwd": &candidate.cwd,
                    "title": &candidate.title,
                    "modified": chrono::DateTime::<chrono::Utc>::from(candidate.modified).to_rfc3339(),
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "sessions": sessions,
                "warnings": warnings,
            }))?
        );
        return Ok(());
    }

    let warnings: Vec<String> = warnings
        .iter()
        .map(|warning| safe_cli_display(warning))
        .filter(|warning| !warning.is_empty())
        .collect();

    for warning in &warnings {
        eprintln!("warning: {warning}");
    }
    if candidates.is_empty() {
        println!("No importable foreign sessions found.");
        return Ok(());
    }
    for candidate in candidates {
        let modified = chrono::DateTime::<chrono::Utc>::from(candidate.modified)
            .with_timezone(&chrono::Local)
            .format("%b %d, %l:%M%P");
        let id = safe_cli_display(&candidate.id);
        let title = safe_cli_display(&candidate.title);
        let cwd = safe_cli_display(&candidate.cwd.to_string_lossy());
        println!(
            "{} {}  {}\n  {}\n  {}",
            candidate.source.as_str(),
            id,
            modified,
            summary_or_untitled(&title),
            cwd,
        );
    }
    Ok(())
}

async fn run_import(
    target: Option<&str>,
    id: Option<&str>,
    source: Option<xai_grok_foreign_sessions::import::ImportSource>,
    all: bool,
    list: bool,
    json: bool,
    cwd: &std::path::Path,
    agent_config: &AgentConfig,
) -> Result<()> {
    let explicit_path = target
        .map(|target| std::path::Path::new(target))
        .filter(|path| path.exists());
    let discovered_id = if explicit_path.is_some() {
        id
    } else {
        id.or(target)
    };
    if explicit_path.is_some() && all {
        bail!("--all applies to discovery and cannot be combined with an explicit PATH");
    }

    let (mut candidates, warnings) = if let Some(path) = explicit_path {
        let source = source.ok_or_else(|| anyhow::anyhow!("--from is required with PATH"))?;
        (
            vec![xai_grok_foreign_sessions::import::inspect(
                source,
                path,
                discovered_id,
            )
            .map_err(|error| anyhow::anyhow!(safe_cli_display(&error.to_string())))?],
            Vec::new(),
        )
    } else {
        let discovery = xai_grok_foreign_sessions::import::discover((!all).then_some(cwd));
        (discovery.sessions, discovery.warnings)
    };

    candidates.retain(|candidate| {
        source.is_none_or(|source| candidate.source == source)
            && discovered_id.is_none_or(|id| candidate.id == id)
    });

    // No target always lists. It must never implicitly import every current-directory match.
    if list || (explicit_path.is_none() && discovered_id.is_none()) {
        return print_import_candidates(&candidates, &warnings, json);
    }

    let candidate = match candidates.as_slice() {
        [candidate] => candidate.clone(),
        [] => bail!("No matching foreign session found; use --list or --all to inspect candidates."),
        _ => bail!("More than one foreign session matched; pass --from or an explicit PATH."),
    };
    let model_id = agent_config
        .default_model_override
        .clone()
        .or_else(|| std::env::var("GROK_DEFAULT_MODEL").ok().filter(|id| !id.trim().is_empty()))
        .or_else(|| agent_config.models.default.clone())
        .or_else(|| {
            // Match ModelsManager's offline fallback: external model catalogues
            // must not silently inherit a bundled xAI model.
            (agent_config.grok_com_config.auth_provider_command.is_none()
                || !agent_config.endpoints.has_custom_endpoint())
                .then(|| xai_grok_shell::models::default_model().to_owned())
        })
        .ok_or_else(|| anyhow::anyhow!("No Groky default model is configured."))?;
    let imported = xai_grok_shell::session::import::import_session(
        candidate,
        cwd.to_path_buf(),
        model_id,
    )
    .await
    .map_err(|error| anyhow::anyhow!(safe_cli_display(&error.to_string())))?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "sessionId": &imported.session_id,
                "cwd": &imported.cwd,
                "messageCount": imported.message_count,
                "warnings": &imported.warnings,
                "resume": format!("groky --resume {}", imported.session_id),
            }))?
        );
        return Ok(());
    }

    let warnings: Vec<String> = imported
        .warnings
        .iter()
        .map(|warning| safe_cli_display(warning))
        .filter(|warning| !warning.is_empty())
        .collect();

    for warning in &warnings {
        eprintln!("warning: {warning}");
    }
    println!(
        "Imported {} messages as native session {}.",
        imported.message_count, imported.session_id
    );
    println!("Resume with:\n  groky --resume {}", imported.session_id);
    Ok(())
}


/// The placeholder every session listing shows for a blank title
pub(crate) fn summary_or_untitled(title: &str) -> &str {
    if title.trim().is_empty() {
        "(untitled)"
    } else {
        title
    }
}

/// Print sessions grouped by worktree label, preserving the original table format with a `Label: <label>` header before each group.
fn print_sessions_grouped(sessions: &[MergedSession]) {
    if sessions.is_empty() {
        println!("No sessions found.");
        return;
    }

    // Group by worktree_label, sort alphabetically, None last.
    let mut groups: std::collections::BTreeMap<Option<&str>, Vec<&MergedSession>> =
        std::collections::BTreeMap::new();
    for s in sessions {
        groups
            .entry(s.worktree_label.as_deref())
            .or_default()
            .push(s);
    }

    let header = format!(
        "{:<36}  {:<10}  {:<10}  {:<10}  {}",
        "SESSION ID", "CREATED", "UPDATED", "STATUS", "SUMMARY"
    );

    // Labeled groups first (alphabetical), then unlabeled last.
    let none_group = groups.remove(&None);
    let print_group = |label_line: &str, members: &[&MergedSession]| {
        println!("\n{label_line}");
        println!("{header}");
        for s in members {
            let first_line;
            let summary: &str = if !s.summary.is_empty() {
                &s.summary
            } else if let Some(ref fp) = s.first_prompt
                && let Some(line) = fp.lines().find(|l| !l.trim().is_empty())
            {
                first_line = line.trim().to_string();
                &first_line
            } else {
                "(no summary)"
            };
            let truncated: String = summary.chars().take(50).collect();
            let created = s
                .created_at
                .get(..s.created_at.len().min(10))
                .unwrap_or(s.created_at.as_str());
            let updated = s
                .updated_at
                .get(..s.updated_at.len().min(10))
                .unwrap_or(s.updated_at.as_str());
            println!(
                "{}  {}  {}  {}  {}",
                s.session_id, created, updated, s.source, truncated
            );
        }
    };

    for (label, members) in &groups {
        let line = format!("Label: {}", label.unwrap_or(""));
        print_group(&line, members);
    }
    if let Some(members) = &none_group {
        print_group("(no label)", members);
    }
}
