//! `/ssh`: open the local SSH target manager.

use crate::app::actions::Action;
use crate::slash::command::{CommandExecCtx, CommandResult, SlashCommand, slash_meta};

pub struct SshCommand;

impl SlashCommand for SshCommand {
    slash_meta! {
        name: "ssh",
        aliases: ["remote"],
        description: "Manage SSH targets and session access",
        usage: "/ssh",
    }

    fn run(&self, _ctx: &mut CommandExecCtx, args: &str) -> CommandResult {
        if args.trim().is_empty() {
            CommandResult::Action(Action::OpenSshManager)
        } else {
            CommandResult::Error(
                "/ssh takes no arguments. Use /ssh to manage targets and access.".into(),
            )
        }
    }
}
