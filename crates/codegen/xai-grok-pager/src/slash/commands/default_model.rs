//! `/default`: show or persist the default model for new sessions without switching this one.

use crate::app::actions::Action;
use crate::slash::command::{
    AppCtx, ArgItem, CommandExecCtx, CommandResult, SlashCommand, slash_meta,
};

/// Persist the model used for new sessions (`[models].default`).
pub struct DefaultModelCommand;

impl SlashCommand for DefaultModelCommand {
    slash_meta! {
        name: "default",
        aliases: ["default-model"],
        description: "Show or set the default model for new sessions",
        usage: "/default [name|clear]",
        takes_args: true,
        args_required: false,
        offered_when_session_less: true,
        arg_placeholder: "[model|clear]",
    }

    fn suggest_args(&self, ctx: &AppCtx, _args_query: &str) -> Option<Vec<ArgItem>> {
        let mut items = vec![clear_item()];
        for info in ctx.models.available.values() {
            items.push(ArgItem {
                display: info.name.clone(),
                match_text: info.name.clone(),
                insert_text: info.name.clone(),
                description: info.description.clone().unwrap_or_default(),
            });
        }
        Some(items)
    }

    fn run(&self, ctx: &mut CommandExecCtx, args: &str) -> CommandResult {
        let trimmed = args.trim();
        if trimmed.is_empty() {
            return CommandResult::Message(current_default_message(ctx));
        }
        if is_clear_token(trimmed) {
            return CommandResult::Action(Action::ClearDefaultModel);
        }
        if let Some(id) = ctx.models.resolve_by_name_or_id(trimmed) {
            return CommandResult::Action(Action::PersistDefaultModel(id));
        }
        CommandResult::Error(format!("Unknown model: {trimmed}"))
    }
}

fn clear_item() -> ArgItem {
    ArgItem {
        display: "clear".to_string(),
        match_text: "clear no override".to_string(),
        insert_text: "clear".to_string(),
        description: "Remove the override; new sessions use the remote or built-in default"
            .to_string(),
    }
}

fn is_clear_token(args: &str) -> bool {
    matches!(
        args.to_ascii_lowercase().as_str(),
        "clear" | "--clear" | "(no override)" | "no-override" | "none"
    )
}

fn current_default_message(ctx: &CommandExecCtx<'_>) -> String {
    let Some(id) = ctx
        .pager_state
        .persisted_default_model_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        return "No default model override. New sessions use the remote or built-in default."
            .to_string();
    };
    let display = ctx
        .models
        .display_name_for(&agent_client_protocol::ModelId::new(id.to_string()));
    if display == id {
        format!("Default model: {id}")
    } else {
        format!("Default model: {display} ({id})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acp::model_state::ModelState;
    use agent_client_protocol as acp;
    use std::sync::Arc;

    static EMPTY_BUNDLE: crate::app::bundle::BundleState = crate::app::bundle::BundleState {
        has_cache: false,
        version: String::new(),
        personas: Vec::new(),
        roles: Vec::new(),
        agents: Vec::new(),
        skills: Vec::new(),
        persona_details: Vec::new(),
        role_details: Vec::new(),
    };

    fn dummy_exec_ctx<'a>(models: &'a ModelState, persisted: Option<String>) -> CommandExecCtx<'a> {
        CommandExecCtx {
            models,
            session_id: None,
            bundle_state: &EMPTY_BUNDLE,
            screen_mode: crate::app::ScreenMode::Inline,
            billing_surface_visible: true,
            usage_command_visible: true,
            pager_state: crate::settings::PagerLocalSnapshot {
                persisted_default_model_id: persisted,
                ..crate::settings::PagerLocalSnapshot::default()
            },
        }
    }

    fn catalog() -> ModelState {
        let mut state = ModelState::default();
        let id = acp::ModelId::new(Arc::from("grok-4.6"));
        state
            .available
            .insert(id.clone(), acp::ModelInfo::new(id, "Grok 4.6"));
        state
    }

    #[test]
    fn empty_args_reports_no_override() {
        let models = catalog();
        let mut ctx = dummy_exec_ctx(&models, None);
        match DefaultModelCommand.run(&mut ctx, "") {
            CommandResult::Message(msg) => {
                assert!(msg.contains("No default model override"), "{msg}");
            }
            other => panic!("expected Message, got {other:?}"),
        }
    }

    #[test]
    fn empty_args_reports_persisted_id() {
        let models = catalog();
        let mut ctx = dummy_exec_ctx(&models, Some("grok-4.6".into()));
        match DefaultModelCommand.run(&mut ctx, "") {
            CommandResult::Message(msg) => {
                assert!(msg.contains("Grok 4.6"), "{msg}");
                assert!(msg.contains("grok-4.6"), "{msg}");
            }
            other => panic!("expected Message, got {other:?}"),
        }
    }

    #[test]
    fn named_model_persists_without_switching() {
        let models = catalog();
        let mut ctx = dummy_exec_ctx(&models, None);
        match DefaultModelCommand.run(&mut ctx, "Grok 4.6") {
            CommandResult::Action(Action::PersistDefaultModel(id)) => {
                assert_eq!(id.0.as_ref(), "grok-4.6");
            }
            other => panic!("expected PersistDefaultModel, got {other:?}"),
        }
    }

    #[test]
    fn clear_token_clears_override() {
        let models = catalog();
        let mut ctx = dummy_exec_ctx(&models, Some("grok-4.6".into()));
        assert!(matches!(
            DefaultModelCommand.run(&mut ctx, "clear"),
            CommandResult::Action(Action::ClearDefaultModel)
        ));
    }
}
