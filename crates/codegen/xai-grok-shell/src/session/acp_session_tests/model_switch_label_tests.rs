use agent_client_protocol as acp;
use xai_grok_sampling_types::conversation::ConversationItem;

use super::support::{build_actor, create_test_actor, running_task_stub};
use crate::session::SwitchContextWindow;
use crate::session::compaction_config::AsyncCompactionCache;

const SWITCH_TARGET_LABEL: &str = "Aurora";

fn head_text(conv: &[ConversationItem]) -> String {
    let Some(ConversationItem::System(sys)) = conv.first() else {
        panic!(
            "conversation must start with a System item, got {:?}",
            conv.first()
        );
    };
    sys.content.as_ref().to_owned()
}

#[tokio::test(flavor = "current_thread")]
async fn model_switch_relabels_live_agent_and_system_head() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let (actor, _gateway_rx) = build_actor().await;
            actor.chat_state_handle.replace_conversation(vec![
                ConversationItem::system("spawn-time prompt"),
                ConversationItem::user("hi"),
            ]);

            actor
                .handle_set_session_model(crate::session::SessionModelSwitch {
                    model_id: acp::ModelId::new("switch-target"),
                    sampling_config: xai_grok_sampler::SamplerConfig {
                        model: "switch-target".to_owned(),
                        context_window: 256_000,
                        ..xai_grok_sampler::SamplerConfig::default()
                    },
                    use_concise: false,
                    is_family_switch: false,
                    apply_prompt_override: true,
                    skip_prompt_rewrite: false,
                    auto_compact_threshold_percent: 85,
                    system_prompt_label: SWITCH_TARGET_LABEL.to_owned(),
                    context_window_selection: SwitchContextWindow::Set(None),
                    supported_context_windows: Vec::new(),
                })
                .await
                .expect("model switch succeeds");

            let conv = actor.chat_state_handle.get_conversation().await;
            let head = head_text(&conv);
            assert!(
                head.contains(SWITCH_TARGET_LABEL),
                "system head must render the new model's label, got: {head:.120}"
            );
            let agent = actor.agent.borrow();
            assert_eq!(
                SWITCH_TARGET_LABEL,
                agent.prompt_context().system_prompt_label
            );
            assert_eq!(agent.system_prompt(), head);
            assert_eq!(2, conv.len(), "the switch swaps only the head");
        })
        .await;
}
#[tokio::test(flavor = "current_thread")]
async fn effort_routing_persists_the_selected_catalog_model() {
    use crate::agent::config::{EndpointsConfig, ModelEntry, ModelVariant};
    use xai_grok_sampling_types::ReasoningEffort;

    tokio::task::LocalSet::new()
        .run_until(async {
            let (gateway_tx, _gateway_rx) = tokio::sync::mpsc::unbounded_channel();
            let (persistence_tx, mut persistence_rx) = tokio::sync::mpsc::unbounded_channel();
            let actor = std::sync::Arc::new(
                create_test_actor(0, 256_000, 85, gateway_tx, persistence_tx).await,
            );
            let provider = |low_model: &str| {
                let mut entry = ModelEntry::fallback("gpt-5.6-sol", &EndpointsConfig::default());
                entry.info.supports_reasoning_effort = true;
                entry.info.variants = vec![ModelVariant {
                    effort: ReasoningEffort::Low,
                    model_id: low_model.to_owned(),
                }];
                entry
            };
            actor
                .models_manager
                .insert_test_entry("claudeuy/gpt-5.6-sol", provider("claudeuy-low"));
            actor
                .models_manager
                .insert_test_entry("claudeuyplan/gpt-5.6-sol", provider("claudeuyplan-low"));
            let selected = acp::ModelId::new("claudeuy/gpt-5.6-sol");

            assert_eq!(
                actor
                    .handle_set_session_model(crate::session::SessionModelSwitch {
                        model_id: selected.clone(),
                        sampling_config: xai_grok_sampler::SamplerConfig {
                            model: "gpt-5.6-sol".to_owned(),
                            context_window: 256_000,
                            ..xai_grok_sampler::SamplerConfig::default()
                        },
                        use_concise: false,
                        is_family_switch: false,
                        apply_prompt_override: false,
                        skip_prompt_rewrite: true,
                        auto_compact_threshold_percent: 85,
                        system_prompt_label: xai_grok_agent::DEFAULT_SYSTEM_PROMPT_LABEL.to_owned(),
                        context_window_selection: SwitchContextWindow::Set(None),
                        supported_context_windows: Vec::new(),
                    })
                    .await
                    .expect("catalog model switch succeeds"),
                selected
            );
            assert_eq!(
                actor
                    .handle_set_reasoning_effort(ReasoningEffort::Low)
                    .await
                    .expect("effort switch succeeds"),
                selected
            );
            assert_eq!(
                actor
                    .chat_state_handle
                    .get_sampling_config()
                    .await
                    .expect("sampling config exists")
                    .model,
                "claudeuy-low",
                "effort routing uses the selected catalog entry, not the ambiguous wire slug"
            );
            assert_eq!(actor.catalog_model_id.borrow().clone(), selected);

            for _ in 0..2 {
                let crate::session::persistence::PersistenceMsg::CurrentModel { model_id, .. } =
                    persistence_rx
                        .try_recv()
                        .expect("switch writes the selected catalog model")
                else {
                    panic!("switch persistence must be CurrentModel");
                };
                assert_eq!(model_id, selected);
            }
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn relabel_skipped_mid_turn_keeps_prefire_cache() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let (actor, _gateway_rx) = build_actor().await;
            actor.compaction.prefire.store(AsyncCompactionCache {
                note1: "NOTE1".to_owned(),
                prefix_len: 1,
                fingerprint: 42,
                model_slug: "switch-target".to_owned(),
                pass1_latency_ms: 5,
            });
            actor.state.lock().await.running_task = Some(running_task_stub("running"));

            actor
                .relabel_agent_system_prompt(SWITCH_TARGET_LABEL.to_owned())
                .await;

            assert!(
                actor.compaction.prefire.has_cache(),
                "a skipped relabel must not drop a prefire built on the still-live prompt"
            );
            assert_eq!(
                xai_grok_agent::DEFAULT_SYSTEM_PROMPT_LABEL,
                actor.agent.borrow().prompt_context().system_prompt_label
            );
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn zero_turn_rebuild_renders_switch_target_label() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let (actor, _gateway_rx) = build_actor().await;

            actor
                .handle_rebuild_agent_for_definition(
                    xai_grok_agent::AgentDefinition::default_grok_build(),
                    SWITCH_TARGET_LABEL.to_owned(),
                )
                .await
                .expect("zero-turn rebuild succeeds");

            let conv = actor.chat_state_handle.get_conversation().await;
            let head = head_text(&conv);
            assert!(
                head.contains(SWITCH_TARGET_LABEL),
                "rebuilt head must render the new model's label, got: {head:.120}"
            );
            let agent = actor.agent.borrow();
            assert_eq!(
                SWITCH_TARGET_LABEL,
                agent.prompt_context().system_prompt_label
            );
            assert_eq!(agent.system_prompt(), head);
        })
        .await;
}
