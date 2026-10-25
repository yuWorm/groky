//! `/ssh [target]`: choose a server for the editable chat draft.

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
        description: "Choose an SSH server for this chat draft",
        usage: "/ssh [server name or target ID]",
        takes_args: true,
    }

    fn suggest_args(&self, ctx: &AppCtx, _args_query: &str) -> Option<Vec<ArgItem>> {
        Some(ctx.ssh_candidates.to_vec())
    }

    fn run(&self, _ctx: &mut CommandExecCtx, args: &str) -> CommandResult {
        if args.trim().is_empty() {
            CommandResult::Action(Action::OpenSshTargetPicker)
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
}