//! `/import-session` discovers foreign agent transcripts for the active project.

use crate::app::actions::Action;
use crate::slash::command::{CommandExecCtx, CommandResult, SlashCommand, slash_meta};

/// Opens the native foreign-session import picker.
pub struct ImportSessionCommand;

impl SlashCommand for ImportSessionCommand {
    slash_meta! {
        name: "import-session",
        description: "Import a session from omp, pi, Claude Code, Codex, or OpenCode",
        usage: "/import-session",
    }

    fn run(&self, _ctx: &mut CommandExecCtx, args: &str) -> CommandResult {
        if !args.trim().is_empty() {
            return CommandResult::Error("/import-session does not accept arguments.".to_owned());
        }
        CommandResult::Action(Action::ShowImportSessionPicker)
    }
}
