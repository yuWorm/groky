//! `/usage` shows session totals, Grok billing, or account-scoped provider quotas.
//! External-auth deployments may query vendor quotas but never grok.com billing.

use crate::app::actions::Action;
use crate::slash::command::{
    AppCtx, ArgItem, CommandExecCtx, CommandResult, SlashCommand, slash_meta,
};
use agent_client_protocol as acp;

pub struct UsageCommand;

/// Detect external-auth installs once at pager startup.
pub(crate) fn detect_external_auth_provider(auth_methods: &[acp::AuthMethod]) -> bool {
    auth_methods.iter().any(auth_method_is_external_provider)
        || auth_provider_env_set()
        || auth_provider_config_set()
}

fn auth_method_is_external_provider(method: &acp::AuthMethod) -> bool {
    method
        .meta()
        .as_ref()
        .and_then(|v| v.get("external_provider"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

fn auth_provider_env_set() -> bool {
    std::env::var("GROK_AUTH_PROVIDER_COMMAND")
        .ok()
        .is_some_and(|s| !s.trim().is_empty())
}

fn auth_provider_config_set() -> bool {
    let Ok(raw) = xai_grok_shell::config::load_effective_config() else {
        return false;
    };
    let Ok(cfg) = xai_grok_shell::agent::config::Config::new_from_toml_cfg(&raw) else {
        return false;
    };
    cfg.grok_com_config
        .auth_provider_command
        .as_deref()
        .is_some_and(|s| !s.trim().is_empty())
}

impl SlashCommand for UsageCommand {
    slash_meta! {
        name: "usage",
        aliases: ["cost"],
        description: "View usage and provider quotas",
        usage: "/usage [show|providers|manage]",
        takes_args: true,
    }

    fn suggest_args(&self, ctx: &AppCtx, _args_query: &str) -> Option<Vec<ArgItem>> {
        let mut items = vec![ArgItem {
            display: "providers".into(),
            match_text: "providers".into(),
            insert_text: "providers".into(),
            description: "View quotas for saved provider accounts".into(),
        }];
        if ctx.usage_command_visible {
            items.push(ArgItem {
                display: "show".into(),
                match_text: "show".into(),
                insert_text: "show".into(),
                description: "View session usage".into(),
            });
            if ctx.billing_surface_visible {
                items.push(ArgItem {
                    display: "manage".into(),
                    match_text: "manage".into(),
                    insert_text: "manage".into(),
                    description: "Manage Grok billing".into(),
                });
            }
        }
        Some(items)
    }

    fn run(&self, ctx: &mut CommandExecCtx, args: &str) -> CommandResult {
        match args.trim() {
            "providers" => CommandResult::Action(Action::ShowProviderUsage),
            "" if !ctx.usage_command_visible => CommandResult::Action(Action::ShowProviderUsage),
            "" | "show" if ctx.usage_command_visible => CommandResult::Action(Action::ShowUsage),
            "manage" if ctx.usage_command_visible && ctx.billing_surface_visible => {
                CommandResult::Action(Action::ManageBilling)
            }
            _ => CommandResult::Error(
                "Use /usage providers, /usage show, or /usage manage (Grok billing only).".into(),
            ),
        }
    }
}

pub struct ProviderUsageCommand;

impl SlashCommand for ProviderUsageCommand {
    slash_meta! {
        name: "provider-usage",
        aliases: ["pusage"],
        description: "View quotas for all saved provider accounts",
        usage: "/provider-usage",
    }

    fn run(&self, _ctx: &mut CommandExecCtx, args: &str) -> CommandResult {
        if args.trim().is_empty() {
            CommandResult::Action(Action::ShowProviderUsage)
        } else {
            CommandResult::Error("Use /provider-usage without arguments.".into())
        }
    }
}
