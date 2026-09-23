//! `/window`: pick a session context-window gear.

use xai_grok_shell::context_window::{
    format_window, gears_for_max, parse_window_arg, snap_to_gear,
};

use crate::slash::command::{
    AppCtx, ArgItem, CommandExecCtx, CommandResult, SlashCommand, slash_meta,
};

/// Set the live session context window without changing the model.
pub struct WindowCommand;

impl SlashCommand for WindowCommand {
    slash_meta! {
        name: "window",
        description: "Set this session's context-window gear",
        usage: "/window 256k",
        takes_args: true,
        args_required: false,
        session_scoped: true,
        arg_placeholder: "256k|512k|max",
    }

    fn suggest_args(&self, ctx: &AppCtx, _args_query: &str) -> Option<Vec<ArgItem>> {
        let max = ctx.models.catalog_context_window()?;
        let gears = gears_for_max(max);
        if gears.is_empty() {
            return None;
        }
        let current = ctx.models.get_context_window().unwrap_or(max);
        Some(
            gears
                .into_iter()
                .map(|gear| {
                    let label = format_window(gear);
                    let display = if gear == current {
                        format!("{label} (current)")
                    } else if gear == max {
                        format!("{label} (max)")
                    } else {
                        label.clone()
                    };
                    ArgItem {
                        display,
                        match_text: label.clone(),
                        insert_text: label,
                        description: format!("{gear} tokens"),
                    }
                })
                .collect(),
        )
    }

    fn run(&self, ctx: &mut CommandExecCtx, args: &str) -> CommandResult {
        if ctx.session_id.is_none() {
            return CommandResult::Error("No active session".to_string());
        }
        let trimmed = args.trim();
        if trimmed.is_empty() {
            return CommandResult::PassThrough("/window".to_string());
        }
        let max = ctx
            .models
            .catalog_context_window()
            .or_else(|| ctx.models.get_context_window())
            .unwrap_or(0);
        let Some(parsed) = parse_window_arg(trimmed, max) else {
            return CommandResult::Error(format!(
                "Unknown window '{trimmed}'. Try 256k, 1M, 1.05M, or max."
            ));
        };
        let dest = snap_to_gear(parsed, max.max(1)).unwrap_or(parsed);
        CommandResult::PassThrough(format!("/window {}", format_window(dest)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acp::model_state::ModelState;
    use agent_client_protocol as acp;
    use std::sync::Arc;

    fn state_with_window(tokens: u64) -> ModelState {
        let mut state = ModelState::default();
        let id = acp::ModelId::new(Arc::from("wide"));
        let info = acp::ModelInfo::new(id.clone(), "Wide".to_string()).meta(
            serde_json::json!({ "totalContextTokens": tokens })
                .as_object()
                .cloned(),
        );
        state.available.insert(id.clone(), info);
        state.set_current(id, None);
        state
    }

    #[test]
    fn suggest_args_lists_gears_for_large_window() {
        let state = state_with_window(1_050_000);
        let cmd = WindowCommand;
        let ctx = AppCtx {
            models: &state,
            cwd: std::path::Path::new("."),
            has_session_announcements: false,
            billing_surface_visible: true,
            usage_command_visible: true,
            workflows_available: true,
            saved_workflows: &[],
            workflow_runs: &[],
            screen_mode: crate::app::ScreenMode::Fullscreen,
            current_title: None,
        };
        let items = cmd.suggest_args(&ctx, "").unwrap();
        let labels: Vec<_> = items.iter().map(|i| i.insert_text.as_str()).collect();
        assert_eq!(labels, ["256k", "512k", "1024k", "1050k"]);
        assert!(
            items.last().unwrap().display.contains("current"),
            "catalog max is the live window in this fixture: {:?}",
            items.last().unwrap().display
        );
    }

    #[test]
    fn run_queues_snapped_gear() {
        let state = state_with_window(1_050_000);
        let session_id = acp::SessionId::new("s");
        let mut ctx = CommandExecCtx {
            models: &state,
            session_id: Some(&session_id),
            bundle_state: &crate::app::bundle::BundleState {
                has_cache: false,
                version: String::new(),
                personas: Vec::new(),
                roles: Vec::new(),
                agents: Vec::new(),
                skills: Vec::new(),
                persona_details: Vec::new(),
                role_details: Vec::new(),
            },
            screen_mode: crate::app::ScreenMode::Fullscreen,
            billing_surface_visible: true,
            usage_command_visible: true,
            pager_state: crate::settings::PagerLocalSnapshot::default(),
        };
        match WindowCommand.run(&mut ctx, "256k") {
            CommandResult::PassThrough(text) => assert_eq!(text, "/window 256k"),
            other => panic!("expected QueueCommand, got {other:?}"),
        }
        match WindowCommand.run(&mut ctx, "1M") {
            CommandResult::PassThrough(text) => assert_eq!(text, "/window 1024k"),
            other => panic!("expected PassThrough, got {other:?}"),
        }
        match WindowCommand.run(&mut ctx, "1.05M") {
            CommandResult::PassThrough(text) => assert_eq!(text, "/window 1050k"),
            other => panic!("expected PassThrough, got {other:?}"),
        }
    }
}
