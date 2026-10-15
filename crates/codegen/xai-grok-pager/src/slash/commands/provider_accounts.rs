//! `/provider-accounts` — manage ChatGPT Codex subscription accounts.

use crate::app::actions::Action;
use crate::slash::command::{AppCtx, ArgItem, CommandExecCtx, CommandResult, SlashCommand};

pub struct ProviderAccountsCommand;

impl SlashCommand for ProviderAccountsCommand {
    fn name(&self) -> &str {
        "provider-accounts"
    }

    fn aliases(&self) -> &[&str] {
        &["paccounts"]
    }

    fn description(&self) -> &str {
        "Manage ChatGPT Codex accounts"
    }

    fn usage(&self) -> &str {
        "/provider-accounts [openai-codex]"
    }

    fn takes_args(&self) -> bool {
        true
    }

    fn args_required(&self) -> bool {
        false
    }

    fn arg_placeholder(&self) -> Option<&str> {
        Some("<provider>")
    }

    fn suggest_args(&self, _ctx: &AppCtx, _args_query: &str) -> Option<Vec<ArgItem>> {
        Some(vec![ArgItem {
            display: "OpenAI Codex (ChatGPT)".into(),
            match_text: "openai-codex chatgpt codex accounts".into(),
            insert_text: "openai-codex".into(),
            description: "Select, add, label, or remove an individual ChatGPT account.".into(),
        }])
    }

    fn run(&self, _ctx: &mut CommandExecCtx, args: &str) -> CommandResult {
        let provider = args.trim();
        if provider.is_empty() || provider == "openai-codex" {
            return CommandResult::Action(Action::OpenVendorLogin {
                provider_id: Some("openai-codex".into()),
            });
        }
        CommandResult::Error(format!(
            "Account management is available for openai-codex; use /provider-login {provider} to sign in."
        ))
    }
}
