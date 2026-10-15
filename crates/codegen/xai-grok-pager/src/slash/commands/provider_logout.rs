//! `/provider-logout` — sign out of every stored account for a provider.

use crate::app::actions::Action;
use crate::slash::command::{AppCtx, ArgItem, CommandExecCtx, CommandResult, SlashCommand};

pub struct ProviderLogoutCommand;

impl SlashCommand for ProviderLogoutCommand {
    fn name(&self) -> &str {
        "provider-logout"
    }

    fn aliases(&self) -> &[&str] {
        &["plogout"]
    }

    fn description(&self) -> &str {
        "Sign out of every stored account for a provider"
    }

    fn usage(&self) -> &str {
        "/provider-logout <provider>"
    }

    fn takes_args(&self) -> bool {
        true
    }

    fn args_required(&self) -> bool {
        true
    }

    fn arg_placeholder(&self) -> Option<&str> {
        Some("<provider>")
    }

    fn suggest_args(&self, _ctx: &AppCtx, _args_query: &str) -> Option<Vec<ArgItem>> {
        Some(
            xai_grok_shell::compat::arg_items()
                .into_iter()
                .map(|(id, name, desc)| ArgItem {
                    display: name.clone(),
                    match_text: format!("{id} {name}"),
                    insert_text: id,
                    description: desc,
                })
                .collect(),
        )
    }

    fn run(&self, _ctx: &mut CommandExecCtx, args: &str) -> CommandResult {
        let id = args.trim();
        if id.is_empty() {
            return CommandResult::Error("Usage: /provider-logout <provider>".into());
        }
        if !xai_grok_shell::compat::is_known_vendor(id) {
            return CommandResult::Error(format!("Unknown provider '{id}'"));
        }
        CommandResult::Action(Action::VendorLogout {
            provider_id: id.to_owned(),
        })
    }
}
