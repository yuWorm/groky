use super::*;

/// Marks the last block that can carry one, scanning back past `Thinking`, which the API rejects a breakpoint on.
fn mark_message_cache_breakpoint(msg: &mut crate::messages::Message) -> bool {
    use crate::messages::{CacheControl, ContentBlock, MessageContent};

    match &mut msg.content {
        MessageContent::Blocks(blocks) => {
            for block in blocks.iter_mut().rev() {
                let cache_control = match block {
                    ContentBlock::Text { cache_control, .. }
                    | ContentBlock::ToolResult { cache_control, .. }
                    | ContentBlock::Image { cache_control, .. }
                    | ContentBlock::ToolUse { cache_control, .. } => cache_control,
                    ContentBlock::Thinking { .. } | ContentBlock::RedactedThinking { .. } => {
                        continue;
                    }
                };
                *cache_control = Some(CacheControl::ephemeral());
                return true;
            }
            false
        }
        // Plain text cannot carry a breakpoint, so promote it to block form.
        MessageContent::Text(text) => {
            let text = std::mem::take(text);
            msg.content = MessageContent::Blocks(vec![ContentBlock::Text {
                text,
                cache_control: Some(CacheControl::ephemeral()),
            }]);
            true
        }
    }
}

/// An entry is written only at a breakpoint, so marking the system prompt alone leaves the transcript uncached.
/// The third covers a turn that appends more than the API's 20 block lookback.
/// The fourth slot stays free: a gateway that turns on automatic caching takes it, and five is rejected outright.
fn apply_cache_breakpoints(
    system_blocks: &mut [crate::messages::TextBlock],
    messages: &mut [crate::messages::Message],
) {
    use crate::messages::{CacheControl, MessageRole};

    if let Some(last) = system_blocks.last_mut() {
        last.cache_control = Some(CacheControl::ephemeral());
    }

    let tip = (0..messages.len()).rev().find(|&i| {
        messages
            .get_mut(i)
            .is_some_and(mark_message_cache_breakpoint)
    });

    // Where the previous request ended
    // A turn can append several user messages in a row, so skip the whole trailing run rather than a neighbour of the tip
    if let Some(tip) = tip
        && let Some(before_tip) = messages.get(..tip)
        && let Some(prev) = before_tip
            .iter()
            .rposition(|m| matches!(m.role, MessageRole::Assistant))
            .and_then(|assistant| {
                before_tip.get(..assistant).and_then(|before_asst| {
                    before_asst
                        .iter()
                        .rposition(|m| matches!(m.role, MessageRole::User))
                })
            })
        && let Some(msg) = messages.get_mut(prev)
    {
        mark_message_cache_breakpoint(msg);
    }
}

/// Anthropic accepts tool ids matching `^[a-zA-Z0-9_-]+$`, at most 64 chars.
const MAX_TOOL_CALL_ID_LEN: usize = 64;

/// Maps any tool call id onto Anthropic's id grammar; tool_use and tool_result both go through here, so the pair stays matched.
/// Over-long ids (Responses ids run to hundreds of chars) keep a prefix plus a stable hash of the full id, so distinct ids stay distinct.
fn anthropic_tool_call_id(id: &str) -> String {
    let sanitized: String = id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if sanitized.is_empty() {
        return format!("toolu_{:016x}", fnv1a64(id.as_bytes()));
    }
    if sanitized.len() <= MAX_TOOL_CALL_ID_LEN {
        return sanitized;
    }
    // 47 + "_" + 16 hex = 64; `sanitized` is pure ASCII, so the byte slice is a char boundary
    format!("{}_{:016x}", &sanitized[..47], fnv1a64(id.as_bytes()))
}

/// Stable across processes and releases, unlike `DefaultHasher`, so a resumed session rebuilds byte-identical ids and keeps its prompt cache.
fn fnv1a64(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

/// For each item, the `model_id` of the assistant turn a `Reasoning` item belongs to.
/// Reasoning precedes its assistant item within one turn, so a reverse scan carries the model back until a turn boundary.
fn reasoning_owner_models(items: &[ConversationItem]) -> Vec<Option<&str>> {
    let mut owners = vec![None; items.len()];
    let mut next_model: Option<&str> = None;
    for (index, item) in items.iter().enumerate().rev() {
        match item {
            ConversationItem::Assistant(a) => next_model = a.model_id.as_deref(),
            ConversationItem::Reasoning(_) => owners[index] = next_model,
            ConversationItem::BackendToolCall(_) => {}
            ConversationItem::System(_)
            | ConversationItem::User(_)
            | ConversationItem::ToolResult(_) => next_model = None,
        }
    }
    owners
}

/// Whether a thinking block produced by `owner` can be replayed natively to `target`; otherwise its signature is foreign and the API rejects it.
/// Gateways echo dated snapshots (`claude-opus-4-8-20261001`) or remap Claude aliases, so any Claude pair counts; Anthropic checks signatures, not model names.
/// An unknown side keeps the native replay that sessions persisted before `model_id` relied on.
fn thinking_replays_natively(owner: Option<&str>, target: Option<&str>) -> bool {
    let (Some(owner), Some(target)) = (owner, target) else {
        return true;
    };
    let is_claude = |model: &str| model.to_ascii_lowercase().contains("claude");
    owner == target || (is_claude(owner) && is_claude(target))
}

/// `metadata.user_id` in the JSON shape Claude Code sends; Claude gateways (sub2api) key sticky account routing, and so prompt-cache reuse, on it.
/// `device_id` is a one-way hash of the install id so the raw id never leaves the machine.
fn messages_metadata(
    install_id: Option<&str>,
    session_id: Option<&str>,
) -> Option<crate::messages::Metadata> {
    use sha2::{Digest, Sha256};
    use std::fmt::Write as _;

    let install_id = install_id.filter(|id| !id.is_empty())?;
    let session_id = session_id.filter(|id| !id.is_empty())?;
    let digest = Sha256::new()
        .chain_update("groky-claude-device-id-v1:")
        .chain_update(install_id)
        .finalize();
    let device_id = digest
        .iter()
        .fold(String::with_capacity(64), |mut hex, byte| {
            let _ = write!(hex, "{byte:02x}");
            hex
        });
    let user_id = serde_json::json!({
        "device_id": device_id,
        "account_uuid": "",
        "session_id": session_id,
    });
    Some(crate::messages::Metadata {
        user_id: Some(user_id.to_string()),
    })
}

pub fn build_messages_request(req: &ConversationRequest) -> crate::messages::MessagesRequest {
    use crate::messages::{
        ContentBlock, ImageSource, Message, MessageContent, MessageRole, MessagesRequest,
        OutputConfig, SystemParam, TextBlock, ToolChoiceParam, ToolParam, ToolResultContent,
    };

    let mut system_blocks: Vec<TextBlock> = Vec::new();
    let mut messages: Vec<Message> = Vec::new();
    let mut pending_assistant: Vec<ContentBlock> = Vec::new();
    let mut pending_tool_results: Vec<ContentBlock> = Vec::new();

    let owner_models = reasoning_owner_models(&req.items);
    let target_model = req.model.as_deref();

    let content_parts_to_anthropic_blocks = |parts: &[ContentPart]| -> Vec<ContentBlock> {
        parts
            .iter()
            .map(|part| match part {
                ContentPart::Text { text } => ContentBlock::Text {
                    text: text.as_ref().to_owned(),
                    cache_control: None,
                },
                ContentPart::Image { url } => {
                    if url.starts_with("data:") {
                        if let Some((header, data)) = url.split_once(',') {
                            let media_type = header
                                .strip_prefix("data:")
                                .and_then(|h| h.strip_suffix(";base64"))
                                .unwrap_or("image/png")
                                .to_string();
                            ContentBlock::Image {
                                source: ImageSource::Base64 {
                                    media_type,
                                    data: data.to_string(),
                                },
                                cache_control: None,
                            }
                        } else {
                            // Malformed data URI, treat as text
                            ContentBlock::Text {
                                text: format!("[invalid image: {}]", url),
                                cache_control: None,
                            }
                        }
                    } else if url.starts_with("http://") || url.starts_with("https://") {
                        ContentBlock::Image {
                            source: ImageSource::Url {
                                url: url.as_ref().to_owned(),
                            },
                            cache_control: None,
                        }
                    } else {
                        // Unknown format, treat as text
                        ContentBlock::Text {
                            text: format!("[image: {}]", url),
                            cache_control: None,
                        }
                    }
                }
            })
            .collect()
    };

    let flush_assistant = |pending: &mut Vec<ContentBlock>, msgs: &mut Vec<Message>| {
        if !pending.is_empty() {
            msgs.push(Message {
                role: MessageRole::Assistant,
                content: MessageContent::Blocks(pending.clone()),
            });
            pending.clear();
        }
    };

    let flush_tool_results = |pending: &mut Vec<ContentBlock>, msgs: &mut Vec<Message>| {
        if !pending.is_empty() {
            msgs.push(Message {
                role: MessageRole::User,
                content: MessageContent::Blocks(pending.clone()),
            });
            pending.clear();
        }
    };

    for (index, item) in req.items.iter().enumerate() {
        match item {
            ConversationItem::System(s) => {
                flush_assistant(&mut pending_assistant, &mut messages);
                flush_tool_results(&mut pending_tool_results, &mut messages);
                system_blocks.push(TextBlock {
                    r#type: "text".to_string(),
                    text: s.content.as_ref().to_owned(),
                    cache_control: None,
                });
            }
            ConversationItem::User(u) => {
                flush_assistant(&mut pending_assistant, &mut messages);
                flush_tool_results(&mut pending_tool_results, &mut messages);
                // The API rejects empty text blocks, and an empty user turn with them
                let mut blocks = content_parts_to_anthropic_blocks(&u.content);
                blocks.retain(
                    |block| !matches!(block, ContentBlock::Text { text, .. } if text.is_empty()),
                );
                if blocks.is_empty() {
                    continue;
                }
                // Text after a tool run joins the tool_result turn, the shape the API documents, instead of a second user turn
                match messages.last_mut() {
                    Some(Message {
                        role: MessageRole::User,
                        content: MessageContent::Blocks(prev),
                    }) if prev
                        .iter()
                        .all(|block| matches!(block, ContentBlock::ToolResult { .. })) =>
                    {
                        prev.extend(blocks);
                    }
                    _ => messages.push(Message {
                        role: MessageRole::User,
                        content: MessageContent::Blocks(blocks),
                    }),
                }
            }
            ConversationItem::Assistant(a) => {
                flush_tool_results(&mut pending_tool_results, &mut messages);

                if !a.content.is_empty() {
                    pending_assistant.push(ContentBlock::Text {
                        text: a.content.as_ref().to_owned(),
                        cache_control: None,
                    });
                }

                for tc in &a.tool_calls {
                    let input =
                        serde_json::from_str(&tc.arguments).unwrap_or(serde_json::json!({}));
                    pending_assistant.push(ContentBlock::ToolUse {
                        id: anthropic_tool_call_id(&tc.id),
                        name: tc.name.clone(),
                        input,
                        cache_control: None,
                    });
                }
            }
            ConversationItem::ToolResult(t) => {
                flush_assistant(&mut pending_assistant, &mut messages);
                let content = if t.images.is_empty() {
                    ToolResultContent::Text(t.content.as_ref().to_owned())
                } else {
                    // The API rejects an empty text block; the images alone carry the result
                    let mut blocks = Vec::with_capacity(t.images.len() + 1);
                    if !t.content.is_empty() {
                        blocks.push(ContentBlock::Text {
                            text: t.content.as_ref().to_owned(),
                            cache_control: None,
                        });
                    }
                    for img in &t.images {
                        if let ContentPart::Image { url } = img {
                            let source = if let Some(rest) = url.strip_prefix("data:") {
                                if let Some((media_type, data)) = rest.split_once(";base64,") {
                                    ImageSource::Base64 {
                                        media_type: media_type.to_string(),
                                        data: data.to_string(),
                                    }
                                } else {
                                    ImageSource::Url {
                                        url: url.as_ref().to_owned(),
                                    }
                                }
                            } else {
                                ImageSource::Url {
                                    url: url.as_ref().to_owned(),
                                }
                            };
                            blocks.push(ContentBlock::Image {
                                source,
                                cache_control: None,
                            });
                        }
                    }
                    ToolResultContent::Blocks(blocks)
                };
                pending_tool_results.push(ContentBlock::ToolResult {
                    tool_use_id: anthropic_tool_call_id(&t.tool_call_id),
                    content,
                    cache_control: None,
                });
            }
            // No native equivalent, so emit synthetic text to retain context.
            ConversationItem::BackendToolCall(b) => {
                flush_tool_results(&mut pending_tool_results, &mut messages);
                pending_assistant.push(ContentBlock::Text {
                    text: b.text_summary(),
                    cache_control: None,
                });
            }
            // `tco_*` blobs carry only `signature`; real reasoning sets `thinking`
            ConversationItem::Reasoning(r) => {
                flush_tool_results(&mut pending_tool_results, &mut messages);
                let thinking = reasoning_item_text(r);
                let signature = r.encrypted_content.as_deref().unwrap_or_default();
                if !signature.is_empty()
                    && thinking_replays_natively(owner_models[index], target_model)
                {
                    pending_assistant.push(ContentBlock::Thinking {
                        thinking,
                        signature: signature.to_owned(),
                    });
                } else if !thinking.is_empty() {
                    // Unsigned or foreign-signed thinking is rejected as a thinking block, so it survives as prose.
                    // Bare text, no `<thinking>` wrapper: Claude's classifier refuses replayed tagged reasoning (omp `renderDemotedThinking`).
                    pending_assistant.push(ContentBlock::Text {
                        text: thinking,
                        cache_control: None,
                    });
                }
            }
        }
    }

    flush_assistant(&mut pending_assistant, &mut messages);
    flush_tool_results(&mut pending_tool_results, &mut messages);

    apply_cache_breakpoints(&mut system_blocks, &mut messages);

    let system: Option<SystemParam> = if system_blocks.is_empty() {
        None
    } else if let [block] = system_blocks.as_slice()
        && block.cache_control.is_none()
    {
        Some(SystemParam::Text(block.text.clone()))
    } else {
        Some(SystemParam::Blocks(system_blocks))
    };

    let tools: Option<Vec<ToolParam>> = if req.tools.is_empty() {
        None
    } else {
        Some(
            req.tools
                .iter()
                .map(|t| ToolParam {
                    name: t.name.clone(),
                    description: t.description.clone(),
                    input_schema: t.parameters.clone(),
                })
                .collect(),
        )
    };

    // The API rejects a `tool_choice` without `tools`
    let tool_choice: Option<ToolChoiceParam> =
        tools
            .as_ref()
            .and(req.tool_choice.as_ref())
            .map(|tc| match tc {
                ConversationToolChoice::Auto => ToolChoiceParam::Auto,
                ConversationToolChoice::Required => ToolChoiceParam::Any,
                ConversationToolChoice::Function(name) => {
                    ToolChoiceParam::Tool { name: name.clone() }
                }
                ConversationToolChoice::None => ToolChoiceParam::None,
            });
    // The API rejects thinking on a forced tool call, so that turn samples without it (omp `disableThinkingIfToolChoiceForced`)
    let forced_tool = matches!(
        tool_choice,
        Some(ToolChoiceParam::Any | ToolChoiceParam::Tool { .. })
    );

    let effort = req
        .reasoning_effort
        .filter(|_| !forced_tool)
        .and_then(|e| e.to_messages_api())
        .map(|s| s.to_string());

    // A wire schema here suppresses tool calls, so the agent routes structured output through the StructuredOutput tool instead
    let format = req
        .json_schema
        .as_ref()
        .map(|schema| crate::messages::OutputFormat::JsonSchema {
            schema: schema.clone(),
        });

    // thinking is driven by reasoning_effort only, not by json_schema.
    let thinking = effort
        .as_ref()
        .map(|_| crate::messages::ThinkingConfig::Adaptive {
            display: Some(crate::messages::ThinkingDisplay::Summarized),
        });

    let output_config = if effort.is_some() || format.is_some() {
        Some(OutputConfig { effort, format })
    } else {
        None
    };

    MessagesRequest {
        model: req.model.clone().unwrap_or_default(),
        messages,
        max_tokens: req.max_output_tokens.unwrap_or(0),
        system,
        tools,
        tool_choice,
        temperature: req.temperature,
        top_p: req.top_p,
        top_k: None,
        stream: None, // The caller sets this
        stop_sequences: None,
        thinking,
        output_config,
        metadata: messages_metadata(
            req.x_grok_agent_id.as_deref(),
            req.x_grok_session_id.as_deref(),
        ),
    }
}

/// `Thinking` is dropped because this `From` returns a single item; the streaming consumer emits the sibling `Reasoning` item instead.
impl From<crate::messages::MessagesResponse> for ConversationItem {
    fn from(resp: crate::messages::MessagesResponse) -> Self {
        use crate::messages::ContentBlock;

        let mut content = String::new();
        let mut tool_calls = Vec::new();

        for block in resp.content {
            match block {
                ContentBlock::Text { text, .. } => {
                    if !content.is_empty() {
                        content.push('\n');
                    }
                    content.push_str(&text);
                }
                ContentBlock::ToolUse {
                    id, name, input, ..
                } => {
                    tool_calls.push(ToolCall {
                        id: Arc::<str>::from(id),
                        name,
                        arguments: Arc::<str>::from(
                            serde_json::to_string(&input).unwrap_or_default(),
                        ),
                    });
                }
                // Thinking is dropped; see the doc comment above
                ContentBlock::Thinking { .. } => {}
                _ => {} // Image and ToolResult are not expected in assistant responses
            }
        }

        ConversationItem::Assistant(AssistantItem {
            content: Arc::<str>::from(content),
            tool_calls,
            model_id: Some(resp.model),
            model_fingerprint: None,
            reasoning_effort: None,
        })
    }
}
