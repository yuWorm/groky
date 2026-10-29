//! `/remote`: open or resume a remembered remote SSH project.

use crate::app::actions::Action;
use crate::slash::command::{CommandExecCtx, CommandResult, SlashCommand, slash_meta};

pub struct RemoteCommand;

impl SlashCommand for RemoteCommand {
    slash_meta! {
        name: "remote",
        description: "Open or resume a remote SSH project",
        usage: "/remote",
    }

    fn run(&self, _ctx: &mut CommandExecCtx, _args: &str) -> CommandResult {
        CommandResult::Action(Action::ShowRemoteProjects)
    }
}
