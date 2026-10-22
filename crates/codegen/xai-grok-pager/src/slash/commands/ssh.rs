//! `/ssh [target]`: choose a session SSH target or open its manager.

use std::collections::HashSet;

use crate::app::actions::Action;
use crate::slash::command::{AppCtx, ArgItem, CommandExecCtx, CommandResult, SlashCommand, slash_meta};

/// Convert configured SSH targets into terminal argument-completion rows.
///
/// Several session grants may produce views of the same target. Completion selects targets rather
/// than grants, so retain one row for each stable target ID while leaving distinct same-label
/// targets available to the user.
pub(crate) fn target_candidates(
    targets: Vec<crate::views::ssh_modal::SshTargetView>,
) -> Vec<crate::slash::command::ArgItem> {
    let mut seen_ids = HashSet::with_capacity(targets.len());
    let mut candidates = Vec::with_capacity(targets.len());
    for target in targets {
        if !seen_ids.insert(target.target_id.clone()) {
            continue;
        }

        let source = match &target.target.source {
            xai_grok_ssh::TargetSource::User => "Groky config",
            xai_grok_ssh::TargetSource::Imported { .. } => "OpenSSH",
        };
        let mut match_text = String::with_capacity(
            target.label.len()
                + target.target.host.len()
                + target.target_id.len()
                + target.effective_address.len()
                + 3,
        );
        for field in [
            target.label.as_str(),
            target.target.host.as_str(),
            target.target_id.as_str(),
            target.effective_address.as_str(),
        ] {
            if !match_text.is_empty() {
                match_text.push(' ');
            }
            match_text.push_str(field);
        }

        let description = format!(
            "{} · {source} · {}",
            target.effective_address, target.target_id
        );
        candidates.push(ArgItem {
            display: target.label,
            match_text,
            insert_text: target.target_id,
            description,
        });
    }
    candidates
}

pub struct SshCommand;

impl SlashCommand for SshCommand {
    slash_meta! {
        name: "ssh",
        aliases: ["remote"],
        description: "Choose an SSH server by name or manage session access",
        usage: "/ssh [server name or target ID]",
        takes_args: true,
    }

    fn suggest_args(&self, ctx: &AppCtx, _args_query: &str) -> Option<Vec<ArgItem>> {
        Some(ctx.ssh_candidates.to_vec())
    }

    fn run(&self, _ctx: &mut CommandExecCtx, args: &str) -> CommandResult {
        if args.trim().is_empty() {
            CommandResult::Action(Action::OpenSshManager)
        } else {
            CommandResult::Action(Action::SelectSshTarget {
                reference: args.trim().to_owned(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::acp::model_state::ModelState;
    use crate::app::bundle::BundleState;
    use crate::views::ssh_modal::{SshGrantView, SshTargetView};

    fn target_view(target_id: &str, label: &str, host: &str, address: &str) -> SshTargetView {
        let mut target = xai_grok_ssh::SshTarget::new(host);
        target.id = target_id.into();
        target.label = label.into();
        SshTargetView::from_target(
            target,
            address.into(),
            false,
            String::new(),
            SshGrantView::NotGranted,
        )
    }

    fn app_ctx<'a>(models: &'a ModelState, candidates: &'a [ArgItem]) -> AppCtx<'a> {
        AppCtx {
            models,
            cwd: std::path::Path::new("."),
            has_session_announcements: false,
            billing_surface_visible: true,
            usage_command_visible: true,
            workflows_available: true,
            saved_workflows: &[],
            ssh_candidates: candidates,
            workflow_runs: &[],
            screen_mode: crate::app::ScreenMode::Fullscreen,
            current_title: None,
        }
    }

    fn exec_ctx<'a>(models: &'a ModelState, bundle: &'a BundleState) -> CommandExecCtx<'a> {
        CommandExecCtx {
            models,
            session_id: None,
            bundle_state: bundle,
            screen_mode: crate::app::ScreenMode::Fullscreen,
            billing_surface_visible: true,
            usage_command_visible: true,
            pager_state: crate::settings::PagerLocalSnapshot::default(),
        }
    }

    #[test]
    fn target_candidates_deduplicate_grants_but_keep_same_label_targets() {
        let mut imported = target_view(
            "target-east",
            "Build Cache",
            "cache-east",
            "builder@cache-east.example.test:2222",
        );
        imported.target.source = xai_grok_ssh::TargetSource::Imported {
            path: PathBuf::from("/Users/test/.ssh/config"),
            line: 41,
        };
        let duplicate_grant_row = imported.clone();
        let distinct_same_label = target_view(
            "target-west",
            "Build Cache",
            "cache-west",
            "builder@cache-west.example.test:2222",
        );

        let candidates = target_candidates(vec![imported, duplicate_grant_row, distinct_same_label]);

        assert_eq!(candidates.len(), 2);
        assert_eq!(
            candidates
                .iter()
                .map(|candidate| (candidate.display.as_str(), candidate.insert_text.as_str()))
                .collect::<Vec<_>>(),
            vec![
                ("Build Cache", "target-east"),
                ("Build Cache", "target-west"),
            ]
        );
        let east = &candidates[0];
        for field in [
            "Build Cache",
            "cache-east",
            "target-east",
            "builder@cache-east.example.test:2222",
        ] {
            assert!(east.match_text.contains(field), "missing searchable field {field:?}");
        }
        for field in [
            "builder@cache-east.example.test:2222",
            "OpenSSH",
            "target-east",
        ] {
            assert!(east.description.contains(field), "missing row detail {field:?}");
        }
    }

    #[test]
    fn suggest_args_returns_the_injected_catalog_without_filtering_it() {
        let candidates = target_candidates(vec![target_view(
            "target-east",
            "Build Cache",
            "cache-east",
            "builder@cache-east.example.test:2222",
        )]);
        let models = ModelState::default();

        let suggestions = SshCommand
            .suggest_args(&app_ctx(&models, &candidates), "build")
            .expect("SSH completion catalog");

        assert_eq!(suggestions.len(), 1);
        assert_eq!(suggestions[0].insert_text, "target-east");
    }

    #[test]
    fn no_arg_opens_manager_and_direct_reference_remains_supported() {
        let models = ModelState::default();
        let bundle = BundleState::default();
        let mut ctx = exec_ctx(&models, &bundle);
        let command = SshCommand;

        assert!(command.takes_args());
        assert!(!command.args_required());
        assert!(matches!(
            command.run(&mut ctx, "  "),
            CommandResult::Action(Action::OpenSshManager)
        ));
        assert!(matches!(
            command.run(&mut ctx, " target-east "),
            CommandResult::Action(Action::SelectSshTarget { reference }) if reference == "target-east"
        ));
    }
}