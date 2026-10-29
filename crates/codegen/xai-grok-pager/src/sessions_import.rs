//! `groky sessions import`: discover foreign agent transcripts and persist them as native sessions.
//!
//! Discovery is scoped to one project directory (the launch cwd unless `--dir` or a directory
//! argument names another). A session ID imports one transcript, `--all` imports every candidate,
//! and an interactive terminal without either opens a multi-select picker. Batches show a progress
//! bar, skip transcripts already imported into the same directory, and stop cleanly on Ctrl-C.

use std::collections::HashMap;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use xai_grok_foreign_sessions::import::{ImportCandidate, ImportSource};
use xai_grok_shell::agent::config::Config as AgentConfig;

use crate::sessions_cmd::summary_or_untitled;

/// Parsed `groky sessions import` flags.
#[derive(Debug, Clone)]
pub(crate) struct ImportOptions {
    pub target: Option<String>,
    pub dir: Option<PathBuf>,
    pub id: Option<String>,
    pub source: Option<ImportSource>,
    pub all: bool,
    pub all_projects: bool,
    pub force: bool,
    pub list: bool,
    pub json: bool,
    pub yes: bool,
}

/// One candidate paired with the native directory it would be imported into.
struct Planned {
    candidate: ImportCandidate,
    target_cwd: PathBuf,
    /// Native session ID of a previous import of the same transcript into `target_cwd`.
    existing: Option<String>,
}

pub(crate) fn safe_cli_display(value: &str) -> String {
    crate::views::session_title::sanitize_display_text(value)
        .trim()
        .chars()
        .take(240)
        .collect()
}

pub(crate) async fn run(opts: ImportOptions, agent_config: &AgentConfig) -> Result<()> {
    let launch_cwd = std::env::current_dir().unwrap_or_else(|_| ".".into());
    let interactive = !opts.json && std::io::stdin().is_terminal() && std::io::stderr().is_terminal();

    // A bare directory argument names the project to scan; explicit store paths still need `--from`.
    let positional_dir = opts
        .target
        .as_deref()
        .filter(|target| opts.source.is_none() && Path::new(target).is_dir())
        .map(PathBuf::from);
    if positional_dir.is_some() && opts.dir.is_some() {
        bail!("Pass the project directory either as DIR or with --dir, not both.");
    }
    let target = if positional_dir.is_some() {
        None
    } else {
        opts.target.as_deref()
    };
    let project_dir = resolve_project_dir(opts.dir.clone().or(positional_dir), &launch_cwd)?;

    let explicit_path = target.map(Path::new).filter(|path| path.exists());
    let wanted_id = if explicit_path.is_some() {
        opts.id.as_deref()
    } else {
        opts.id.as_deref().or(target)
    };
    if explicit_path.is_some() && (opts.all || opts.all_projects) {
        bail!("--all and --all-projects apply to discovery and cannot be combined with an explicit PATH.");
    }
    if opts.all && wanted_id.is_some() {
        bail!("--all imports every discovered session; drop the session ID or drop --all.");
    }

    let (mut candidates, warnings) = if let Some(path) = explicit_path {
        let source = opts
            .source
            .ok_or_else(|| anyhow::anyhow!("--from is required with PATH"))?;
        let candidate = xai_grok_foreign_sessions::import::inspect(source, path, wanted_id)
            .map_err(|error| anyhow::anyhow!(safe_cli_display(&error.to_string())))?;
        (vec![candidate], Vec::new())
    } else {
        discover(&project_dir, opts.all_projects, interactive).await?
    };
    for warning in warnings.iter().map(|warning| safe_cli_display(warning)) {
        if !warning.is_empty() && !opts.json {
            eprintln!("warning: {warning}");
        }
    }

    candidates.retain(|candidate| opts.source.is_none_or(|source| candidate.source == source));
    if explicit_path.is_none()
        && let Some(id) = wanted_id
    {
        candidates = xai_grok_foreign_sessions::import::match_id(candidates, id);
    }

    // Only "migrate everything" sends each transcript home; every other path imports into the chosen project.
    let route_to_source_cwd = opts.all && opts.all_projects;
    let plan = plan_imports(candidates, &project_dir, route_to_source_cwd);

    if opts.list || (wanted_id.is_none() && explicit_path.is_none() && !opts.all && !interactive) {
        return print_candidates(&plan, &warnings, &project_dir, opts.json);
    }

    let selected: Vec<Planned> = if opts.all {
        plan
    } else if wanted_id.is_some() || explicit_path.is_some() {
        match plan.len() {
            1 => plan,
            0 => bail!(
                "No matching foreign session found in {}; use --list or --all-projects to inspect candidates.",
                project_dir.display()
            ),
            _ => {
                print_candidates(&plan, &[], &project_dir, false)?;
                bail!("More than one foreign session matched; pass a longer ID, --from, or an explicit PATH.");
            }
        }
    } else {
        if plan.is_empty() {
            println!(
                "No importable foreign sessions found in {}.\nTry --all-projects to search every project.",
                project_dir.display()
            );
            return Ok(());
        }
        let rows: Vec<picker::Row> = plan.iter().map(picker::Row::from_planned).collect();
        let header = format!("Import sessions into {}", project_dir.display());
        let Some(indices) = tokio::task::spawn_blocking(move || picker::select(&header, &rows))
            .await
            .context("session picker panicked")??
        else {
            eprintln!("Import cancelled.");
            return Ok(());
        };
        let mut plan: Vec<Option<Planned>> = plan.into_iter().map(Some).collect();
        indices
            .into_iter()
            .filter_map(|index| plan.get_mut(index).and_then(Option::take))
            // Picking an already-imported row is an explicit request to import it again.
            .map(|mut item| {
                item.existing = None;
                item
            })
            .collect()
    };

    let (pending, skipped): (Vec<Planned>, Vec<Planned>) = selected
        .into_iter()
        .partition(|item| opts.force || item.existing.is_none());

    if pending.is_empty() {
        if opts.json {
            print_batch_json(&[], &skipped, &[])?;
        } else if skipped.is_empty() {
            println!("No importable foreign sessions found in {}.", project_dir.display());
        } else {
            for item in &skipped {
                println!(
                    "Already imported {} {} as {}; pass --force to import again.",
                    item.candidate.source,
                    safe_cli_display(&item.candidate.id),
                    item.existing.as_deref().unwrap_or_default()
                );
            }
        }
        return Ok(());
    }

    if opts.all && interactive && !opts.yes {
        let skipped_note = if skipped.is_empty() {
            String::new()
        } else {
            format!(" ({} already imported, skipped)", skipped.len())
        };
        let destination = if route_to_source_cwd {
            "their original projects".to_owned()
        } else {
            project_dir.display().to_string()
        };
        if !confirm(&format!(
            "Import {} sessions into {destination}{skipped_note}?",
            pending.len()
        ))? {
            eprintln!("Import cancelled.");
            return Ok(());
        }
    }

    let model_id = configured_model_id(agent_config)?;
    let single_explicit = !opts.all && pending.len() == 1 && skipped.is_empty();
    let report = import_batch(pending, &model_id, interactive, opts.json).await;

    if opts.json {
        if single_explicit && let [(_, imported)] = report.imported.as_slice() {
            // Keep the single-import shape stable for scripts written against earlier releases.
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
        } else {
            print_batch_json(&report.imported, &skipped, &report.failed)?;
        }
    } else {
        print_summary(&report, &skipped, &project_dir);
    }

    match report.failed.len() {
        0 if report.interrupted => bail!("Import interrupted."),
        0 => Ok(()),
        1 if report.imported.is_empty() && skipped.is_empty() => {
            bail!("{}", report.failed[0].1)
        }
        failed => bail!("{failed} sessions failed to import."),
    }
}

fn resolve_project_dir(dir: Option<PathBuf>, launch_cwd: &Path) -> Result<PathBuf> {
    let dir = match dir {
        Some(dir) if dir.is_relative() => launch_cwd.join(dir),
        Some(dir) => dir,
        None => launch_cwd.to_path_buf(),
    };
    let canonical = dunce::canonicalize(&dir)
        .with_context(|| format!("project directory {} does not exist", dir.display()))?;
    if !canonical.is_dir() {
        bail!("{} is not a directory", canonical.display());
    }
    Ok(canonical)
}

async fn discover(
    project_dir: &Path,
    all_projects: bool,
    interactive: bool,
) -> Result<(Vec<ImportCandidate>, Vec<String>)> {
    let spinner = if interactive {
        let spinner = ProgressBar::with_draw_target(None, ProgressDrawTarget::stderr());
        spinner.set_style(
            ProgressStyle::with_template("{spinner:.cyan} {msg}")
                .expect("valid discovery spinner template"),
        );
        spinner.set_message(if all_projects {
            "Scanning omp, pi, Claude Code, Codex and OpenCode sessions in every project…".to_owned()
        } else {
            format!(
                "Scanning omp, pi, Claude Code, Codex and OpenCode sessions for {}…",
                project_dir.display()
            )
        });
        spinner.enable_steady_tick(Duration::from_millis(80));
        spinner
    } else {
        ProgressBar::hidden()
    };
    let scope = (!all_projects).then(|| project_dir.to_path_buf());
    let discovery = tokio::task::spawn_blocking(move || {
        xai_grok_foreign_sessions::import::discover(scope.as_deref())
    })
    .await
    .context("foreign session discovery panicked")?;
    spinner.finish_and_clear();
    Ok((discovery.sessions, discovery.warnings))
}

fn plan_imports(
    candidates: Vec<ImportCandidate>,
    project_dir: &Path,
    route_to_source_cwd: bool,
) -> Vec<Planned> {
    let mut imported_by_dir: HashMap<PathBuf, HashMap<(String, String), String>> = HashMap::new();
    candidates
        .into_iter()
        .map(|candidate| {
            let target_cwd = if route_to_source_cwd {
                dunce::canonicalize(&candidate.cwd)
                    .ok()
                    .filter(|cwd| cwd.is_dir())
                    .unwrap_or_else(|| project_dir.to_path_buf())
            } else {
                project_dir.to_path_buf()
            };
            let existing = imported_by_dir
                .entry(target_cwd.clone())
                .or_insert_with(|| xai_grok_shell::session::import::imported_sources(&target_cwd))
                .get(&(candidate.source.as_str().to_owned(), candidate.id.clone()))
                .cloned();
            Planned {
                candidate,
                target_cwd,
                existing,
            }
        })
        .collect()
}

fn configured_model_id(agent_config: &AgentConfig) -> Result<String> {
    agent_config
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
        .ok_or_else(|| anyhow::anyhow!("No Groky default model is configured."))
}

#[derive(Default)]
struct BatchReport {
    imported: Vec<(ImportCandidate, xai_grok_shell::session::import::ImportResult)>,
    failed: Vec<(ImportCandidate, String)>,
    interrupted: bool,
}

/// Imports sequentially so Ctrl-C can stop between sessions without abandoning a half-written stage.
async fn import_batch(
    items: Vec<Planned>,
    model_id: &str,
    interactive: bool,
    json: bool,
) -> BatchReport {
    let total = items.len() as u64;
    let bar = if interactive && total > 0 {
        let bar = ProgressBar::with_draw_target(Some(total), ProgressDrawTarget::stderr());
        bar.set_style(
            ProgressStyle::with_template(
                "{spinner:.cyan} [{bar:28.cyan/dim}] {pos}/{len} {elapsed:>4} {wide_msg}",
            )
            .expect("valid import progress template")
            .progress_chars("=>-"),
        );
        bar.enable_steady_tick(Duration::from_millis(100));
        bar
    } else {
        ProgressBar::hidden()
    };
    let say = |line: String| {
        if interactive {
            bar.println(line);
        } else if !json {
            println!("{line}");
        }
    };

    let stop = Arc::new(AtomicBool::new(false));
    let listener = {
        let stop = stop.clone();
        let bar = bar.clone();
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                stop.store(true, Ordering::SeqCst);
                bar.set_message("Stopping after the current session… (Ctrl-C again to force quit)");
                if tokio::signal::ctrl_c().await.is_ok() {
                    std::process::exit(130);
                }
            }
        })
    };

    let mut report = BatchReport::default();
    for item in items {
        if stop.load(Ordering::SeqCst) {
            report.interrupted = true;
            break;
        }
        let title = safe_cli_display(&item.candidate.title);
        let label = format!(
            "{:<8} {}",
            item.candidate.source.as_str(),
            summary_or_untitled(&title)
        );
        if !stop.load(Ordering::SeqCst) {
            bar.set_message(label.clone());
        }
        match xai_grok_shell::session::import::import_session(
            item.candidate.clone(),
            item.target_cwd.clone(),
            model_id.to_owned(),
        )
        .await
        {
            Ok(imported) => {
                let warnings = if imported.warnings.is_empty() {
                    String::new()
                } else {
                    format!(", {} warnings", imported.warnings.len())
                };
                say(format!(
                    "  \u{2713} {label}  \u{2192} {} ({} messages{warnings})",
                    imported.session_id, imported.message_count
                ));
                report.imported.push((item.candidate, imported));
            }
            Err(error) => {
                let error = safe_cli_display(&error.to_string());
                say(format!("  \u{2717} {label}  {error}"));
                report.failed.push((item.candidate, error));
            }
        }
        bar.inc(1);
    }
    listener.abort();
    bar.finish_and_clear();
    report
}

fn print_summary(report: &BatchReport, skipped: &[Planned], project_dir: &Path) {
    for (_, imported) in &report.imported {
        for warning in &imported.warnings {
            let warning = safe_cli_display(warning);
            if !warning.is_empty() {
                eprintln!("warning: {} {warning}", imported.session_id);
            }
        }
    }
    let mut parts = vec![format!(
        "Imported {} session{}",
        report.imported.len(),
        if report.imported.len() == 1 { "" } else { "s" }
    )];
    if !skipped.is_empty() {
        parts.push(format!("{} already imported", skipped.len()));
    }
    if !report.failed.is_empty() {
        parts.push(format!("{} failed", report.failed.len()));
    }
    if report.interrupted {
        parts.push("interrupted".to_owned());
    }
    println!("{}.", parts.join(", "));
    if !skipped.is_empty() && report.imported.is_empty() {
        println!("Pass --force to import already-imported sessions again.");
    }
    match report.imported.as_slice() {
        [] => {}
        [(_, imported)] => {
            println!("Resume with:\n  groky --resume {}", imported.session_id);
        }
        _ => println!(
            "Open groky in {} and run /resume to pick one.",
            project_dir.display()
        ),
    }
}

fn candidate_json(candidate: &ImportCandidate) -> serde_json::Value {
    serde_json::json!({
        "source": candidate.source.as_str(),
        "id": &candidate.id,
        "path": &candidate.path,
        "cwd": &candidate.cwd,
        "title": &candidate.title,
        "modified": chrono::DateTime::<chrono::Utc>::from(candidate.modified).to_rfc3339(),
    })
}

fn print_batch_json(
    imported: &[(ImportCandidate, xai_grok_shell::session::import::ImportResult)],
    skipped: &[Planned],
    failed: &[(ImportCandidate, String)],
) -> Result<()> {
    let imported: Vec<_> = imported
        .iter()
        .map(|(candidate, result)| {
            serde_json::json!({
                "source": candidate.source.as_str(),
                "id": &candidate.id,
                "sessionId": &result.session_id,
                "cwd": &result.cwd,
                "messageCount": result.message_count,
                "warnings": &result.warnings,
            })
        })
        .collect();
    let skipped: Vec<_> = skipped
        .iter()
        .map(|item| {
            serde_json::json!({
                "source": item.candidate.source.as_str(),
                "id": &item.candidate.id,
                "sessionId": &item.existing,
                "reason": "already imported",
            })
        })
        .collect();
    let failed: Vec<_> = failed
        .iter()
        .map(|(candidate, error)| {
            serde_json::json!({
                "source": candidate.source.as_str(),
                "id": &candidate.id,
                "error": error,
            })
        })
        .collect();
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "imported": imported,
            "skipped": skipped,
            "failed": failed,
        }))?
    );
    Ok(())
}

fn print_candidates(
    plan: &[Planned],
    warnings: &[String],
    project_dir: &Path,
    json: bool,
) -> Result<()> {
    if json {
        let sessions: Vec<serde_json::Value> = plan
            .iter()
            .map(|item| {
                let mut value = candidate_json(&item.candidate);
                value["importedAs"] = serde_json::json!(item.existing);
                value
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "projectDir": project_dir,
                "sessions": sessions,
                "warnings": warnings,
            }))?
        );
        return Ok(());
    }
    if plan.is_empty() {
        println!(
            "No importable foreign sessions found in {}.",
            project_dir.display()
        );
        return Ok(());
    }
    for item in plan {
        let candidate = &item.candidate;
        let modified = chrono::DateTime::<chrono::Utc>::from(candidate.modified)
            .with_timezone(&chrono::Local)
            .format("%b %d, %l:%M%P");
        let imported = item
            .existing
            .as_deref()
            .map(|id| format!("  (imported as {id})"))
            .unwrap_or_default();
        println!(
            "{} {}  {}{imported}\n  {}\n  {}",
            candidate.source.as_str(),
            safe_cli_display(&candidate.id),
            modified,
            summary_or_untitled(&safe_cli_display(&candidate.title)),
            safe_cli_display(&candidate.cwd.to_string_lossy()),
        );
    }
    Ok(())
}

fn confirm(question: &str) -> Result<bool> {
    let mut stderr = std::io::stderr();
    write!(stderr, "{question} [Y/n] ")?;
    stderr.flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    let answer = answer.trim();
    Ok(answer.is_empty() || answer.eq_ignore_ascii_case("y") || answer.eq_ignore_ascii_case("yes"))
}

/// Full-screen multi-select drawn on stderr so stdout stays clean for the final summary.
mod picker {
    use std::io::{self, Write};

    use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
    use crossterm::style::{Attribute, Color, Print, ResetColor, SetAttribute, SetForegroundColor};
    use crossterm::{cursor, execute, queue, terminal};
    use unicode_width::UnicodeWidthChar;

    use super::{Planned, safe_cli_display, summary_or_untitled};

    pub(super) struct Row {
        source: &'static str,
        when: String,
        title: String,
        cwd: String,
        imported: bool,
    }

    impl Row {
        pub(super) fn from_planned(item: &Planned) -> Self {
            let candidate = &item.candidate;
            Self {
                source: candidate.source.as_str(),
                when: chrono::DateTime::<chrono::Utc>::from(candidate.modified)
                    .with_timezone(&chrono::Local)
                    .format("%b %d %H:%M")
                    .to_string(),
                title: summary_or_untitled(&safe_cli_display(&candidate.title)).to_owned(),
                cwd: safe_cli_display(&candidate.cwd.to_string_lossy()),
                imported: item.existing.is_some(),
            }
        }
    }

    /// Restores the terminal even when drawing fails or the picker panics.
    struct Screen;

    impl Screen {
        fn enter() -> io::Result<Self> {
            terminal::enable_raw_mode()?;
            if let Err(error) = execute!(io::stderr(), terminal::EnterAlternateScreen, cursor::Hide) {
                let _ = terminal::disable_raw_mode();
                return Err(error);
            }
            Ok(Self)
        }
    }

    impl Drop for Screen {
        fn drop(&mut self) {
            let _ = execute!(io::stderr(), cursor::Show, terminal::LeaveAlternateScreen);
            let _ = terminal::disable_raw_mode();
        }
    }

    struct State {
        cursor: usize,
        offset: usize,
        selected: Vec<bool>,
    }

    /// Returns the chosen row indices, or `None` when the user cancels.
    /// Enter with nothing ticked imports the highlighted row.
    pub(super) fn select(header: &str, rows: &[Row]) -> io::Result<Option<Vec<usize>>> {
        let _screen = Screen::enter()?;
        let mut state = State {
            cursor: 0,
            offset: 0,
            selected: vec![false; rows.len()],
        };
        loop {
            draw(header, rows, &mut state)?;
            let Event::Key(key) = event::read()? else {
                continue;
            };
            if key.kind != KeyEventKind::Press {
                continue;
            }
            let last = rows.len().saturating_sub(1);
            match key.code {
                KeyCode::Esc | KeyCode::Char('q') => return Ok(None),
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    return Ok(None);
                }
                KeyCode::Up | KeyCode::Char('k') => state.cursor = state.cursor.saturating_sub(1),
                KeyCode::Down | KeyCode::Char('j') => state.cursor = (state.cursor + 1).min(last),
                KeyCode::PageUp => state.cursor = state.cursor.saturating_sub(page_rows()),
                KeyCode::PageDown => state.cursor = (state.cursor + page_rows()).min(last),
                KeyCode::Home | KeyCode::Char('g') => state.cursor = 0,
                KeyCode::End | KeyCode::Char('G') => state.cursor = last,
                KeyCode::Char(' ') => {
                    if let Some(selected) = state.selected.get_mut(state.cursor) {
                        *selected = !*selected;
                    }
                    state.cursor = (state.cursor + 1).min(last);
                }
                KeyCode::Char('a') => {
                    // Toggle every row that is not already imported; a second press clears.
                    let any_unselected = rows
                        .iter()
                        .zip(&state.selected)
                        .any(|(row, selected)| !row.imported && !selected);
                    for (row, selected) in rows.iter().zip(state.selected.iter_mut()) {
                        *selected = any_unselected && !row.imported;
                    }
                }
                KeyCode::Enter => {
                    let chosen: Vec<usize> = state
                        .selected
                        .iter()
                        .enumerate()
                        .filter_map(|(index, selected)| selected.then_some(index))
                        .collect();
                    return Ok(Some(if chosen.is_empty() {
                        vec![state.cursor]
                    } else {
                        chosen
                    }));
                }
                _ => {}
            }
        }
    }

    const CHROME_ROWS: usize = 5;

    fn page_rows() -> usize {
        terminal::size()
            .map(|(_, height)| usize::from(height).saturating_sub(CHROME_ROWS).max(1))
            .unwrap_or(10)
    }

    fn draw(header: &str, rows: &[Row], state: &mut State) -> io::Result<()> {
        let (width, _) = terminal::size()?;
        let width = usize::from(width);
        let visible = page_rows();
        if state.cursor < state.offset {
            state.offset = state.cursor;
        } else if state.cursor >= state.offset + visible {
            state.offset = state.cursor + 1 - visible;
        }

        let mut out = io::stderr();
        queue!(out, cursor::MoveTo(0, 0), terminal::Clear(terminal::ClearType::All))?;
        let imported = rows.iter().filter(|row| row.imported).count();
        let counts = if imported == 0 {
            format!("  {} found", rows.len())
        } else {
            format!("  {} found · {imported} already imported", rows.len())
        };
        queue!(
            out,
            SetAttribute(Attribute::Bold),
            Print(fit(header, width.saturating_sub(counts.chars().count()))),
            SetAttribute(Attribute::Reset),
            SetForegroundColor(Color::DarkGrey),
            Print(counts),
            ResetColor,
            cursor::MoveToNextLine(1),
            SetForegroundColor(Color::DarkGrey),
            Print(fit(
                "↑↓ move  space select  a select all  enter import  esc cancel",
                width
            )),
            ResetColor,
            cursor::MoveToNextLine(2),
        )?;

        for (index, row) in rows.iter().enumerate().skip(state.offset).take(visible) {
            let focused = index == state.cursor;
            let mark = if state.selected[index] { "[x]" } else { "[ ]" };
            let prefix = format!(
                "{} {mark} {:<8} {}  ",
                if focused { '›' } else { ' ' },
                row.source,
                row.when
            );
            let suffix = if row.imported { "  (imported)" } else { "" };
            let room = width.saturating_sub(prefix.chars().count() + suffix.len());
            let detail = if room > 24 && !row.cwd.is_empty() {
                format!("{}  {}", row.title, row.cwd)
            } else {
                row.title.clone()
            };
            if focused {
                queue!(out, SetForegroundColor(Color::Cyan), SetAttribute(Attribute::Bold))?;
            } else if row.imported {
                queue!(out, SetForegroundColor(Color::DarkGrey))?;
            }
            queue!(
                out,
                Print(&prefix),
                Print(fit(&detail, room)),
                Print(suffix),
                SetAttribute(Attribute::Reset),
                ResetColor,
                cursor::MoveToNextLine(1),
            )?;
        }

        let chosen = state.selected.iter().filter(|selected| **selected).count();
        let footer = if chosen == 0 {
            "Enter imports the highlighted session".to_owned()
        } else {
            format!("{chosen} selected")
        };
        let more = if rows.len() > visible {
            format!("  {}–{} of {}", state.offset + 1, (state.offset + visible).min(rows.len()), rows.len())
        } else {
            String::new()
        };
        queue!(
            out,
            cursor::MoveToNextLine(1),
            SetForegroundColor(Color::DarkGrey),
            Print(fit(&format!("{footer}{more}"), width)),
            ResetColor,
        )?;
        out.flush()
    }

    /// Truncates to a display width, appending an ellipsis when text is cut.
    fn fit(text: &str, width: usize) -> String {
        let char_width = |ch: char| ch.width().unwrap_or(0);
        if text.chars().map(char_width).sum::<usize>() <= width {
            return text.to_owned();
        }
        let mut used = 0;
        let mut out = String::new();
        for ch in text.chars() {
            if used + char_width(ch) + 1 > width {
                break;
            }
            used += char_width(ch);
            out.push(ch);
        }
        if width > 0 {
            out.push('…');
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_project_dir_resolves_against_launch_cwd() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir(temp.path().join("child")).unwrap();
        let resolved = resolve_project_dir(Some(PathBuf::from("child")), temp.path()).unwrap();
        assert_eq!(
            resolved,
            dunce::canonicalize(temp.path().join("child")).unwrap()
        );
        assert!(resolve_project_dir(Some(PathBuf::from("missing")), temp.path()).is_err());
    }
}
