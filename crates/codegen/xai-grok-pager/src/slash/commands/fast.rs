//! `/fast`: toggle OpenAI-compatible priority service tier for this session.
//!
//! Official `openai` / `openai-codex`, and any GPT wire id (`gpt-4o`,
//! `acme/gpt-5`) including custom OpenAI-compatible relays. Off by default;
//! not written to `config.toml`. Claude `-fast` models are unrelated.

use crate::app::actions::Action;
use crate::slash::command::{
    AppCtx, ArgItem, CommandExecCtx, CommandResult, SlashCommand, slash_meta,
};
use xai_grok_shell::compat::model_supports_openai_fast;

const UNAVAILABLE: &str = "Fast mode is only available on GPT models.";

pub struct FastCommand;

impl SlashCommand for FastCommand {
    slash_meta! {
        name: "fast",
        description: "Toggle Fast mode (GPT priority service_tier)",
        usage: "/fast [on|off]",
        takes_args: true,
        session_scoped: true,
        arg_placeholder: "[on|off]",
    }

    fn visible(&self, ctx: &AppCtx) -> bool {
        ctx.models
            .current_model_id_str()
            .is_some_and(model_supports_openai_fast)
    }

    fn suggest_args(&self, ctx: &AppCtx, _args_query: &str) -> Option<Vec<ArgItem>> {
        if !self.visible(ctx) {
            return None;
        }
        Some(vec![
            ArgItem {
                display: "on".into(),
                match_text: "on".into(),
                insert_text: "on".into(),
                description: "Enable Fast (service_tier=priority)".into(),
            },
            ArgItem {
                display: "off".into(),
                match_text: "off".into(),
                insert_text: "off".into(),
                description: "Disable Fast (omit service_tier)".into(),
            },
        ])
    }

    fn run(&self, ctx: &mut CommandExecCtx, args: &str) -> CommandResult {
        if ctx.session_id.is_none() {
            return CommandResult::Error("No active session".into());
        }
        let supported = ctx
            .models
            .current_model_id_str()
            .is_some_and(model_supports_openai_fast);
        let trimmed = args.trim().to_ascii_lowercase();
        let currently_on = ctx.pager_state.fast_mode;
        let new = match trimmed.as_str() {
            "" => {
                if currently_on {
                    false
                } else if supported {
                    true
                } else {
                    return CommandResult::Error(UNAVAILABLE.into());
                }
            }
            "on" => {
                if !supported {
                    return CommandResult::Error(UNAVAILABLE.into());
                }
                true
            }
            "off" => false,
            _ => {
                return CommandResult::Error("Usage: /fast [on|off]".into());
            }
        };
        CommandResult::Action(Action::SetFastMode(new))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acp::model_state::ModelState;
    use crate::app::bundle::BundleState;
    use crate::settings::PagerLocalSnapshot;
    use agent_client_protocol as acp;
    use std::sync::Arc;

    fn openai_models() -> ModelState {
        let id = acp::ModelId::new(Arc::from("openai/gpt-4o"));
        let info = acp::ModelInfo::new(id.clone(), "GPT-4o".to_string());
        let mut models = ModelState::default();
        models.available.insert(id.clone(), info);
        models.current = Some(id);
        models
    }

    fn grok_models() -> ModelState {
        let id = acp::ModelId::new(Arc::from("grok-4.5"));
        let info = acp::ModelInfo::new(id.clone(), "Grok 4.5".to_string());
        let mut models = ModelState::default();
        models.available.insert(id.clone(), info);
        models.current = Some(id);
        models
    }

    fn custom_gpt_models() -> ModelState {
        let id = acp::ModelId::new(Arc::from("acme/gpt-4o"));
        let info = acp::ModelInfo::new(id.clone(), "Acme · GPT-4o".to_string());
        let mut models = ModelState::default();
        models.available.insert(id.clone(), info);
        models.current = Some(id);
        models
    }

    fn exec<'a>(
        models: &'a ModelState,
        bundle: &'a BundleState,
        session_id: &'a acp::SessionId,
        fast: bool,
    ) -> CommandExecCtx<'a> {
        CommandExecCtx {
            models,
            session_id: Some(session_id),
            bundle_state: bundle,
            screen_mode: crate::app::ScreenMode::Inline,
            billing_surface_visible: true,
            usage_command_visible: true,
            pager_state: PagerLocalSnapshot {
                fast_mode: fast,
                ..PagerLocalSnapshot::default()
            },
        }
    }

    fn app_ctx<'a>(models: &'a ModelState) -> AppCtx<'a> {
        AppCtx {
            models,
            cwd: std::path::Path::new("."),
            has_session_announcements: false,
            billing_surface_visible: true,
            usage_command_visible: true,
            workflows_available: false,
            saved_workflows: &[],
            ssh_candidates: &[],
            workflow_runs: &[],
            screen_mode: crate::app::ScreenMode::Inline,
            current_title: None,
        }
    }

    #[test]
    fn hidden_on_grok_visible_on_openai() {
        let grok = grok_models();
        let openai = openai_models();
        let custom = custom_gpt_models();
        assert!(!FastCommand.visible(&app_ctx(&grok)));
        assert!(FastCommand.visible(&app_ctx(&openai)));
        assert!(FastCommand.visible(&app_ctx(&custom)));
    }

    #[test]
    fn toggle_on_openai() {
        let models = openai_models();
        let bundle = BundleState::default();
        let sid = acp::SessionId::new("s1");
        let mut ctx = exec(&models, &bundle, &sid, false);
        assert!(matches!(
            FastCommand.run(&mut ctx, ""),
            CommandResult::Action(Action::SetFastMode(true))
        ));
        let mut ctx = exec(&models, &bundle, &sid, true);
        assert!(matches!(
            FastCommand.run(&mut ctx, ""),
            CommandResult::Action(Action::SetFastMode(false))
        ));
    }

    #[test]
    fn toggle_on_custom_gpt() {
        let models = custom_gpt_models();
        let bundle = BundleState::default();
        let sid = acp::SessionId::new("s1");
        let mut ctx = exec(&models, &bundle, &sid, false);
        assert!(matches!(
            FastCommand.run(&mut ctx, ""),
            CommandResult::Action(Action::SetFastMode(true))
        ));
    }

    #[test]
    fn on_off_args() {
        let models = openai_models();
        let bundle = BundleState::default();
        let sid = acp::SessionId::new("s1");
        let mut ctx = exec(&models, &bundle, &sid, false);
        assert!(matches!(
            FastCommand.run(&mut ctx, "on"),
            CommandResult::Action(Action::SetFastMode(true))
        ));
        assert!(matches!(
            FastCommand.run(&mut ctx, "off"),
            CommandResult::Action(Action::SetFastMode(false))
        ));
        let CommandResult::Error(msg) = FastCommand.run(&mut ctx, "flex") else {
            panic!("expected usage error");
        };
        assert!(msg.contains("/fast"));
    }

    #[test]
    fn enable_rejected_on_grok() {
        let models = grok_models();
        let bundle = BundleState::default();
        let sid = acp::SessionId::new("s1");
        let mut ctx = exec(&models, &bundle, &sid, false);
        let CommandResult::Error(msg) = FastCommand.run(&mut ctx, "") else {
            panic!("expected unavailable");
        };
        assert!(msg.contains("GPT"));
        let CommandResult::Error(msg) = FastCommand.run(&mut ctx, "on") else {
            panic!("expected unavailable");
        };
        assert!(msg.contains("GPT"));
        assert!(matches!(
            FastCommand.run(&mut ctx, "off"),
            CommandResult::Action(Action::SetFastMode(false))
        ));
    }
}
