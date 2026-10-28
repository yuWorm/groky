use super::test_support::*;
use super::*;

fn messages_test_request(reasoning_effort: Option<crate::ReasoningEffort>) -> ConversationRequest {
    ConversationRequest {
        items: vec![ConversationItem::user("Hello")],
        model: Some("test-model".to_string()),
        reasoning_effort,
        ..Default::default()
    }
}

#[test]
fn json_schema_and_reasoning_effort_are_orthogonal_in_output_config() {
    let schema = serde_json::json!({
        "type": "object",
        "properties": { "x": { "type": "string" } },
        "required": ["x"]
    });
    let mut req = ConversationRequest::from_items(vec![ConversationItem::user("go")])
        .with_json_schema(schema);
    req.reasoning_effort = Some(crate::ReasoningEffort::High);

    let msgs = build_messages_request(&req);
    let oc = msgs.output_config.expect("output_config present");
    assert_eq!(oc.effort.as_deref(), Some("high"));
    assert!(oc.format.is_some());
    assert!(
        msgs.thinking.is_some(),
        "thinking set when effort is present"
    );
}

#[test]
fn test_messages_request_wire_format_for_supported_variants() {
    for (variant, expected) in [
        (crate::ReasoningEffort::Low, "low"),
        (crate::ReasoningEffort::Medium, "medium"),
        (crate::ReasoningEffort::High, "high"),
        (crate::ReasoningEffort::Xhigh, "xhigh"),
        (crate::ReasoningEffort::Max, "max"),
    ] {
        let req = messages_test_request(Some(variant));
        let msgs = build_messages_request(&req);
        let json = serde_json::to_value(&msgs).unwrap();
        assert_eq!(
            json.pointer("/output_config/effort")
                .and_then(|v| v.as_str()),
            Some(expected),
            "{variant:?} should map to output_config.effort={expected:?}; got: {json:#}",
        );
        assert_eq!(
            json.pointer("/thinking/type").and_then(|v| v.as_str()),
            Some("adaptive"),
            "{variant:?} should auto-pair thinking.type=adaptive; got: {json:#}",
        );
    }
}

#[test]
fn test_messages_request_omits_output_config_when_no_supported_effort() {
    let none_or_unsupported = [
        None,
        Some(crate::ReasoningEffort::None),
        Some(crate::ReasoningEffort::Minimal),
    ];
    for input in none_or_unsupported {
        let req = messages_test_request(input);
        let msgs = build_messages_request(&req);
        assert!(
            msgs.output_config.is_none(),
            "input {input:?} must not produce output_config",
        );
        assert!(
            msgs.thinking.is_none(),
            "input {input:?} must not auto-pair thinking",
        );
    }
}

#[test]
fn test_messages_request_thinking_carries_summarized_display() {
    let req = ConversationRequest {
        reasoning_effort: Some(crate::ReasoningEffort::High),
        ..ConversationRequest::from_items(vec![ConversationItem::user("hi")])
            .with_model("messages-compatible-model")
    };
    let msg = build_messages_request(&req);
    let json = serde_json::to_value(&msg).unwrap();
    assert_eq!(
        json.pointer("/thinking/type").and_then(|v| v.as_str()),
        Some("adaptive"),
        "thinking.type should be 'adaptive'; got: {json:#}",
    );
    assert_eq!(
        json.pointer("/thinking/display").and_then(|v| v.as_str()),
        Some("summarized"),
        "thinking.display must be 'summarized' so 4.7+ surfaces thinking content; got: {json:#}",
    );
}

#[test]
fn test_messages_request_omits_thinking_when_effort_unset() {
    let req = ConversationRequest::from_items(vec![ConversationItem::user("hi")])
        .with_model("messages-compatible-model");
    let msg = build_messages_request(&req);
    let json = serde_json::to_value(&msg).unwrap();
    assert!(
        json.get("thinking").is_none()
            || json
                .pointer("/thinking")
                .map(|v| v.is_null())
                .unwrap_or(false),
        "thinking must be absent when reasoning_effort is unset; got: {json:#}",
    );
    assert!(
        json.get("output_config").is_none()
            || json
                .pointer("/output_config")
                .map(|v| v.is_null())
                .unwrap_or(false),
        "output_config must be absent when reasoning_effort is unset; got: {json:#}",
    );
}

#[test]
fn test_messages_request_previous_tip_skips_a_trailing_user_run() {
    let mut items = vec![
        ConversationItem::system("You are a helpful assistant."),
        ConversationItem::user("Fix the bug"),
    ];
    items.extend(agent_turn(0));
    items.extend(agent_turn(1));
    // The shape after a parallel batch: tool results, then followups.
    items.push(ConversationItem::user("[Image content]"));
    items.push(ConversationItem::user("<system-reminder>"));

    let json = serde_json::to_value(build_messages_request(
        &ConversationRequest::from_items(items).with_model("messages-compatible-model"),
    ))
    .unwrap();
    let Some(messages) = json.get("messages").and_then(|v| v.as_array()) else {
        panic!("expected messages array: {json:#}");
    };

    let marked: Vec<usize> = messages
        .iter()
        .enumerate()
        .filter(|(_, m)| marker_on_last_block(m).is_some())
        .map(|(i, _)| i)
        .collect();
    let last_assistant = messages
        .iter()
        .rposition(|m| m.get("role").and_then(|r| r.as_str()) == Some("assistant"))
        .unwrap();
    let [prev_tip, tip] = marked.as_slice() else {
        panic!("tip and previous tip only: {json:#}");
    };
    assert_eq!(*tip, messages.len() - 1, "tip: {json:#}");
    assert!(
        *prev_tip < last_assistant,
        "the previous tip must sit before the last assistant turn, not inside \
             the trailing user run; got {marked:?} in {json:#}",
    );
}

#[test]
fn test_messages_request_cache_breakpoint_marks_an_image_tip() {
    let req = ConversationRequest::from_items(vec![
        ConversationItem::system("You are a helpful assistant."),
        ConversationItem::User(UserItem {
            content: vec![
                ContentPart::Text {
                    text: "what is in this screenshot".into(),
                },
                ContentPart::Image {
                    url: "data:image/png;base64,iVBOR".into(),
                },
            ],
            ..Default::default()
        }),
    ])
    .with_model("messages-compatible-model");

    let json = serde_json::to_value(build_messages_request(&req)).unwrap();
    let Some(first_msg) = json
        .get("messages")
        .and_then(|v| v.as_array())
        .and_then(|m| m.first())
    else {
        panic!("expected first message: {json:#}");
    };
    let Some(blocks) = first_msg.get("content").and_then(|c| c.as_array()) else {
        panic!("expected content array: {json:#}");
    };

    assert_eq!(
        blocks
            .last()
            .and_then(|b| b.get("type"))
            .and_then(|t| t.as_str()),
        Some("image")
    );
    assert_eq!(
        marker_on_last_block(first_msg),
        Some("ephemeral"),
        "{json:#}",
    );
    assert!(
        blocks
            .first()
            .is_some_and(|b| b.get("cache_control").is_none()),
        "{json:#}"
    );
}

#[test]
fn test_messages_request_cache_breakpoint_skips_thinking() {
    let req = ConversationRequest::from_items(vec![
        ConversationItem::user("Fix the bug"),
        ConversationItem::Reasoning(rs::ReasoningItem {
            encrypted_content: Some("sig".to_string()),
            ..synthesized_reasoning_item("weighing options")
        }),
        ConversationItem::assistant("Fixed it."),
    ])
    .with_model("messages-compatible-model");

    let json = serde_json::to_value(build_messages_request(&req)).unwrap();
    let Some(asst) = json
        .get("messages")
        .and_then(|v| v.as_array())
        .and_then(|m| m.get(1))
    else {
        panic!("expected assistant message: {json:#}");
    };
    let Some(blocks) = asst.get("content").and_then(|c| c.as_array()) else {
        panic!("expected content array: {json:#}");
    };

    let thinking = blocks
        .iter()
        .find(|b| b.get("type").and_then(|t| t.as_str()) == Some("thinking"))
        .expect("reasoning should emit a thinking block");
    assert!(thinking.get("cache_control").is_none(), "{json:#}");
    assert_eq!(marker_on_last_block(asst), Some("ephemeral"), "{json:#}",);
}

#[test]
fn test_btw_cross_api_messages_no_regressions() {
    let items = btw_prepare_items(btw_mid_turn_conversation());
    let req = ConversationRequest::from_items(items);
    let msg = build_messages_request(&req);
    let json = serde_json::to_value(&msg).unwrap();

    let messages = json.get("messages").unwrap().as_array().unwrap();

    // No thinking blocks anywhere.
    for (i, m) in messages.iter().enumerate() {
        if let Some(content) = m.get("content").and_then(|c| c.as_array()) {
            for block in content {
                assert_ne!(
                    block.get("type").and_then(|t| t.as_str()),
                    Some("thinking"),
                    "messages[{i}] must not contain thinking blocks",
                );
            }
        }
    }

    // Last assistant message must not have unanswered tool_use.
    let last_assistant = messages
        .iter()
        .rev()
        .find(|m| m.get("role").and_then(|r| r.as_str()) == Some("assistant"))
        .expect("should have an assistant message");
    if let Some(content) = last_assistant.get("content").and_then(|c| c.as_array()) {
        for block in content {
            assert_ne!(
                block.get("type").and_then(|t| t.as_str()),
                Some("tool_use"),
                "last assistant in btw request must not have unanswered tool_use",
            );
        }
    }

    // Top-level thinking must be absent (no reasoning_effort set).
    assert!(
        json.get("thinking").is_none() || json.pointer("/thinking").is_some_and(|v| v.is_null()),
        "top-level thinking must be absent; got: {json:#}",
    );

    assert!(
        json.get("temperature").is_none()
            || json.pointer("/temperature").is_some_and(|v| v.is_null()),
        "temperature must be absent so proxy defaults can apply; got: {json:#}",
    );

    // The completed tool pair (call_1) must survive.
    let has_tool_use_call_1 = messages.iter().any(|m| {
        m.get("content")
            .and_then(|c| c.as_array())
            .is_some_and(|blocks| {
                blocks.iter().any(|b| {
                    b.get("type").and_then(|t| t.as_str()) == Some("tool_use")
                        && b.get("id").and_then(|id| id.as_str()) == Some("call_1")
                })
            })
    });
    assert!(
        has_tool_use_call_1,
        "completed tool_use call_1 must survive"
    );

    let has_tool_result_call_1 = messages.iter().any(|m| {
        m.get("content")
            .and_then(|c| c.as_array())
            .is_some_and(|blocks| {
                blocks.iter().any(|b| {
                    b.get("type").and_then(|t| t.as_str()) == Some("tool_result")
                        && b.get("tool_use_id").and_then(|id| id.as_str()) == Some("call_1")
                })
            })
    });
    assert!(
        has_tool_result_call_1,
        "completed tool_result for call_1 must survive"
    );
}

#[test]
fn test_tool_result_with_images_to_anthropic() {
    let req = ConversationRequest::from_items(vec![
        ConversationItem::user("Read this"),
        ConversationItem::Assistant(AssistantItem {
            content: String::new().into(),
            tool_calls: vec![ToolCall {
                id: "call_1".into(),
                name: "read_file".to_string(),
                arguments: "{}".into(),
            }],
            model_id: None,
            model_fingerprint: None,
            reasoning_effort: None,
        }),
        ConversationItem::tool_result_with_images(
            "call_1",
            "Read image file: photo.png",
            vec![ContentPart::Image {
                url: "data:image/png;base64,iVBOR".into(),
            }],
        ),
    ]);

    let messages_req = build_messages_request(&req);

    // Find the user message that contains the tool result (the Messages API wraps tool results in user messages)
    let tool_result_msg = messages_req
        .messages
        .iter()
        .find(|m| {
            if let crate::messages::MessageContent::Blocks(blocks) = &m.content {
                blocks
                    .iter()
                    .any(|b| matches!(b, crate::messages::ContentBlock::ToolResult { .. }))
            } else {
                false
            }
        })
        .expect("Expected a message with ToolResult block");

    let crate::messages::MessageContent::Blocks(blocks) = &tool_result_msg.content else {
        panic!("Expected Blocks");
    };
    let tool_result_block = blocks
        .iter()
        .find_map(|b| {
            if let crate::messages::ContentBlock::ToolResult { content, .. } = b {
                Some(content)
            } else {
                None
            }
        })
        .unwrap();

    let crate::messages::ToolResultContent::Blocks(inner) = tool_result_block else {
        panic!("Expected ToolResultContent::Blocks, got Text");
    };
    let [t0, t1] = inner.as_slice() else {
        panic!("expected two inner blocks: {inner:?}");
    };
    assert!(
        matches!(t0, crate::messages::ContentBlock::Text { text, .. } if text == "Read image file: photo.png")
    );
    assert!(
        matches!(t1, crate::messages::ContentBlock::Image { source: crate::messages::ImageSource::Base64 { media_type, data }, .. } if media_type == "image/png" && data == "iVBOR")
    );
}

#[test]
fn upgrade_legacy_reasoning_singular_anthropic_no_id() {
    // Messages streaming sets id = "" (see stream/messages.rs:340).
    // The upgrader must still emit a sibling carrying text and signature
    let raw = serde_json::json!({
        "type": "assistant",
        "content": "answer",
        "reasoning": {
            "text": "Let me think about this...",
            "encrypted": "signature-bytes-here",
            "id": ""
        },
        "model_id": "messages-compatible-model"
    });
    let mut seen = std::collections::HashSet::new();
    let siblings = upgrade_legacy_reasoning(&raw, &mut seen);
    assert_eq!(siblings.len(), 1);
    let Some(ConversationItem::Reasoning(r)) = siblings.first() else {
        panic!("expected Reasoning sibling: {siblings:?}");
    };
    assert_eq!(r.id, "");
    assert_eq!(r.encrypted_content.as_deref(), Some("signature-bytes-here"));
}

fn signed_reasoning(text: &str, signature: &str) -> ConversationItem {
    ConversationItem::Reasoning(rs::ReasoningItem {
        encrypted_content: Some(signature.to_string()),
        ..synthesized_reasoning_item(text)
    })
}

fn assistant_block_types(json: &serde_json::Value, index: usize) -> Vec<String> {
    json["messages"][index]["content"]
        .as_array()
        .unwrap_or_else(|| panic!("messages[{index}] content array: {json:#}"))
        .iter()
        .map(|b| b["type"].as_str().unwrap_or_default().to_string())
        .collect()
}

/// A signature only verifies on the model family that minted it; anything else must not reach the API as a thinking block.
#[test]
fn thinking_replays_natively_only_with_a_matching_signature() {
    let cases = [
        // (label, reasoning, owner model, expected assistant block types)
        (
            "same model",
            signed_reasoning("plan", "sig"),
            "claude-opus-5",
            vec!["thinking", "text"],
        ),
        (
            "dated snapshot",
            signed_reasoning("plan", "sig"),
            "claude-opus-5-20261001",
            vec!["thinking", "text"],
        ),
        (
            "foreign signature demotes",
            signed_reasoning("plan", "enc_grok"),
            "grok-4.6",
            vec!["text", "text"],
        ),
        (
            "foreign signature-only drops",
            signed_reasoning("", "enc_grok"),
            "grok-4.6",
            vec!["text"],
        ),
        (
            "unsigned demotes",
            ConversationItem::Reasoning(synthesized_reasoning_item("plan")),
            "claude-opus-5",
            vec!["text", "text"],
        ),
    ];
    for (label, reasoning, owner, expected) in cases {
        let req = ConversationRequest::from_items(vec![
            ConversationItem::user("go"),
            reasoning,
            ConversationItem::assistant_with_model("done", owner),
            ConversationItem::user("next"),
        ])
        .with_model("claude-opus-5");
        let json = serde_json::to_value(build_messages_request(&req)).unwrap();
        assert_eq!(
            assistant_block_types(&json, 1),
            expected,
            "{label}: {json:#}"
        );
    }
}

#[test]
fn demoted_thinking_is_bare_prose() {
    let req = ConversationRequest::from_items(vec![
        ConversationItem::user("go"),
        ConversationItem::Reasoning(synthesized_reasoning_item("weigh it")),
        ConversationItem::assistant_with_model("done", "grok-4.6"),
    ])
    .with_model("claude-opus-5");
    let json = serde_json::to_value(build_messages_request(&req)).unwrap();
    assert_eq!(
        json["messages"][1]["content"][0]["text"], "weigh it",
        "{json:#}"
    );
}

/// Responses call ids run to hundreds of chars with `|`; Anthropic allows `^[a-zA-Z0-9_-]{1,64}$` and the pair must still match.
#[test]
fn tool_call_ids_fit_anthropic_grammar_and_stay_paired() {
    let long_a = format!("call_{}|fc_{}", "a".repeat(200), "x".repeat(60));
    let long_b = format!("call_{}|fc_{}", "a".repeat(200), "y".repeat(60));
    let call = |id: &str| ToolCall {
        id: id.into(),
        name: "read".to_string(),
        arguments: "{}".into(),
    };
    let req = ConversationRequest::from_items(vec![
        ConversationItem::user("go"),
        ConversationItem::assistant_tool_calls(vec![call(&long_a), call(&long_b), call("")]),
        ConversationItem::tool_result(long_a.clone(), "a"),
        ConversationItem::tool_result(long_b.clone(), "b"),
        ConversationItem::tool_result("", "c"),
    ]);
    let json = serde_json::to_value(build_messages_request(&req)).unwrap();
    let ids = |index: usize, key: &str| -> Vec<String> {
        json["messages"][index]["content"]
            .as_array()
            .unwrap()
            .iter()
            .map(|b| b[key].as_str().unwrap().to_string())
            .collect()
    };
    let uses = ids(1, "id");
    assert_eq!(uses, ids(2, "tool_use_id"), "{json:#}");
    for id in &uses {
        assert!(
            (1..=64).contains(&id.len())
                && id
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'),
            "invalid id {id:?}"
        );
    }
    assert_ne!(uses[0], uses[1], "distinct long ids must not collide");
}

#[test]
fn tool_choice_mapping_and_forced_tool_drops_thinking() {
    let spec = ToolSpec {
        name: "read".to_string(),
        description: None,
        parameters: serde_json::json!({"type": "object"}),
    };
    let build = |choice: ConversationToolChoice, tools: Vec<ToolSpec>| {
        let mut req = messages_test_request(Some(crate::ReasoningEffort::High));
        req.tools = tools;
        req.tool_choice = Some(choice);
        serde_json::to_value(build_messages_request(&req)).unwrap()
    };

    let none = build(ConversationToolChoice::None, vec![spec.clone()]);
    assert_eq!(none["tool_choice"], serde_json::json!({"type": "none"}));
    assert!(none.get("thinking").is_some(), "{none:#}");

    for forced in [
        ConversationToolChoice::Required,
        ConversationToolChoice::Function("read".to_string()),
    ] {
        let json = build(forced, vec![spec.clone()]);
        assert!(json.get("thinking").is_none(), "{json:#}");
        assert!(json.get("output_config").is_none(), "{json:#}");
    }

    let toolless = build(ConversationToolChoice::None, Vec::new());
    assert!(toolless.get("tool_choice").is_none(), "{toolless:#}");
}

/// sub2api keys sticky account routing, and so prompt-cache reuse, on `metadata.user_id`; it needs both device_id and session_id.
#[test]
fn metadata_user_id_carries_stable_device_and_session() {
    let build = |agent: Option<&str>, session: Option<&str>| {
        let mut req = messages_test_request(None);
        req.x_grok_agent_id = agent.map(str::to_owned);
        req.x_grok_session_id = session.map(str::to_owned);
        build_messages_request(&req)
            .metadata
            .and_then(|m| m.user_id)
    };
    let user_id = build(Some("install-1"), Some("sess-1")).expect("user_id");
    let parsed: serde_json::Value = serde_json::from_str(&user_id).unwrap();
    assert_eq!(parsed["session_id"], "sess-1");
    let device_id = parsed["device_id"].as_str().unwrap();
    assert!(device_id.len() == 64 && device_id.bytes().all(|b| b.is_ascii_hexdigit()));
    assert!(
        !user_id.contains("install-1"),
        "raw install id must not leak"
    );
    assert_eq!(
        build(Some("install-1"), Some("sess-1")).as_deref(),
        Some(user_id.as_str())
    );
    assert_ne!(
        build(Some("install-2"), Some("sess-1")).as_deref(),
        Some(user_id.as_str())
    );
    assert_eq!(build(None, Some("sess-1")), None);
    assert_eq!(build(Some("install-1"), None), None);
}

#[test]
fn user_text_after_tool_results_joins_their_turn() {
    let req = ConversationRequest::from_items(vec![
        ConversationItem::user("go"),
        ConversationItem::assistant_tool_calls(vec![ToolCall {
            id: "t1".into(),
            name: "read".to_string(),
            arguments: "{}".into(),
        }]),
        ConversationItem::tool_result("t1", "ok"),
        ConversationItem::user("reminder"),
        ConversationItem::user(""),
    ]);
    let json = serde_json::to_value(build_messages_request(&req)).unwrap();
    assert_eq!(json["messages"].as_array().unwrap().len(), 3, "{json:#}");
    assert_eq!(assistant_block_types(&json, 2), vec!["tool_result", "text"]);
}
