//! `/import-session` discovers foreign agent transcripts and imports them into the active project.
//!
//! Arguments mirror `groky sessions import`: a session ID (or unique prefix) jumps straight to its
//! import preview, a path or `--dir` scans another project, and `--all` imports every new session.

use std::path::PathBuf;

use crate::app::actions::Action;
use crate::slash::command::{CommandExecCtx, CommandResult, SlashCommand, slash_meta};
use crate::views::session_picker::ImportSessionRequest;

const USAGE: &str =
    "/import-session [ID] [DIR | --dir DIR] [--from SOURCE] [--all] [--all-projects]";

/// Opens the native foreign-session import picker.
pub struct ImportSessionCommand;

impl SlashCommand for ImportSessionCommand {
    slash_meta! {
        name: "import-session",
        description: "Import sessions from omp, pi, Claude Code, Codex, or OpenCode",
        usage: "/import-session [ID] [DIR | --dir DIR] [--from SOURCE] [--all] [--all-projects]",
        takes_args: true,
        arg_placeholder: "[id] [--dir path] [--all]",
    }

    fn run(&self, _ctx: &mut CommandExecCtx, args: &str) -> CommandResult {
        match parse_args(args) {
            Ok(request) => CommandResult::Action(Action::ShowImportSessionPicker { request }),
            Err(error) => CommandResult::Error(format!("{error}\nUsage: {USAGE}")),
        }
    }
}

fn looks_like_path(token: &str) -> bool {
    token.starts_with(['/', '.', '~']) || token.contains('/') || token.contains('\\')
}

fn expand_tilde(input: &str) -> PathBuf {
    match input.strip_prefix('~') {
        Some(rest) if rest.is_empty() || rest.starts_with('/') => xai_dirs::home_dir()
            .map(|home| home.join(rest.trim_start_matches('/')))
            .unwrap_or_else(|| PathBuf::from(input)),
        _ => PathBuf::from(input),
    }
}

fn parse_args(args: &str) -> Result<ImportSessionRequest, String> {
    let tokens = shlex::split(args).ok_or_else(|| "Unbalanced quotes in arguments.".to_owned())?;
    let mut request = ImportSessionRequest::default();
    let mut tokens = tokens.into_iter();
    let set_dir = |request: &mut ImportSessionRequest, dir: &str| {
        if request.dir.is_some() {
            return Err("Pass only one project directory.".to_owned());
        }
        request.dir = Some(expand_tilde(dir));
        Ok(())
    };
    while let Some(token) = tokens.next() {
        let (flag, inline) = match token.split_once('=') {
            Some((flag, value)) if flag.starts_with("--") => (flag.to_owned(), Some(value.to_owned())),
            _ => (token.clone(), None),
        };
        let mut value = |name: &str| {
            inline
                .clone()
                .or_else(|| tokens.next())
                .filter(|value| !value.is_empty())
                .ok_or_else(|| format!("{name} needs a value."))
        };
        match flag.as_str() {
            "--all" | "-a" => request.all = true,
            "--all-projects" => request.all_projects = true,
            "--dir" | "-C" => set_dir(&mut request, &value("--dir")?)?,
            "--from" => {
                request.source = Some(value("--from")?.parse()?);
            }
            "--id" => {
                if request.id.replace(value("--id")?).is_some() {
                    return Err("Pass only one session ID.".to_owned());
                }
            }
            other if other.starts_with('-') => return Err(format!("Unknown option {other}.")),
            _ if looks_like_path(&token) => set_dir(&mut request, &token)?,
            _ => {
                if request.id.replace(token).is_some() {
                    return Err("Pass only one session ID.".to_owned());
                }
            }
        }
    }
    if request.all && request.id.is_some() {
        return Err("--all imports every session; drop the session ID or drop --all.".to_owned());
    }
    if request.all && request.all_projects {
        return Err(
            "--all imports into this project only; use `groky sessions import --all --all-projects` to migrate every project."
                .to_owned(),
        );
    }
    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use xai_grok_foreign_sessions::import::ImportSource;

    #[test]
    fn no_arguments_open_the_current_project_picker() {
        assert_eq!(parse_args("  ").unwrap(), ImportSessionRequest::default());
    }

    #[test]
    fn positional_id_and_directory_are_distinguished() {
        let request = parse_args("0199abcd ../other").unwrap();
        assert_eq!(request.id.as_deref(), Some("0199abcd"));
        assert_eq!(request.dir, Some(PathBuf::from("../other")));
    }

    #[test]
    fn flags_accept_separate_and_inline_values() {
        let request = parse_args("--dir='/tmp/my project' --from claude --all").unwrap();
        assert_eq!(request.dir, Some(PathBuf::from("/tmp/my project")));
        assert_eq!(request.source, Some(ImportSource::Claude));
        assert!(request.all);
    }

    #[test]
    fn conflicting_or_unknown_arguments_are_rejected() {
        assert!(parse_args("--all abc123").is_err());
        assert!(parse_args("--all --all-projects").is_err());
        assert!(parse_args("--dir").is_err());
        assert!(parse_args("--from nope").is_err());
        assert!(parse_args("--bogus").is_err());
        assert!(parse_args("one two").is_err());
        assert!(parse_args("./a --dir ./b").is_err());
    }
}
