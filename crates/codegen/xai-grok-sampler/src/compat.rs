//! Third-party request/response shims (Codex Responses + Claude OAuth).
//!
//! `async-openai`'s Responses types treat `output_text.annotations` and
//! output-item `id` as required. xAI always sends them; OpenAI and many
//! gateways omit empty `annotations` or item ids. This module fills those
//! holes on the deserialize-failure path so the typed parse can succeed.
//!
//! Invoked only after a first `from_str` fails, so a well-formed xAI event
//! never runs this code. Filling missing fields is additive: a payload that
//! already has `annotations` / `id` is left unchanged.
//!
//! Driver ids below are the Pi-style names for the three existing
//! [`crate::ApiBackend`]s. Sampling still uses [`SamplingClient`]; new
//! native protocols (Gemini, Bedrock) would plug in here later.

use std::collections::BTreeMap;

use indexmap::IndexMap;
use serde_json::{Map, Value};
use xai_grok_sampling_types::messages::{
    ContentBlock, MessageContent, MessageStreamEvent, MessagesRequest, MessagesResponse,
    SystemParam, TextBlock, ToolChoiceParam,
};
use xai_grok_sampling_types::{ApiBackend, ConversationItem, ConversationResponse, ToolCall, rs};

use crate::events::{SamplingChannel, SamplingEvent};

/// Pi-style driver id for a Grok `ApiBackend`.
#[allow(dead_code)]
pub fn driver_id_for_backend(backend: ApiBackend) -> &'static str {
    match backend {
        ApiBackend::ChatCompletions => "openai-completions",
        ApiBackend::Responses => "openai-responses",
        ApiBackend::Messages => "anthropic-messages",
    }
}

/// Output-item `type` values that the Responses schema requires an `id` on.
/// Deltas (`response.output_text.delta`, etc.) use other type strings and
/// are not touched.
const OUTPUT_ITEMS_REQUIRING_ID: &[&str] = &[
    "message",
    "reasoning",
    "function_call",
    "web_search_call",
    "file_search_call",
    "code_interpreter_call",
    "image_generation_call",
    "computer_call",
    "mcp_call",
    "mcp_list_tools",
    "custom_tool_call",
    "local_shell_call",
];

/// Patch a Responses SSE payload in place. Returns whether any field was
/// added.
pub(crate) fn sanitize_response_event_json(value: &mut Value) -> bool {
    let mut changed = false;
    let mut next_id = 0u64;
    walk(value, &mut changed, &mut next_id);
    changed
}

fn walk(value: &mut Value, changed: &mut bool, next_id: &mut u64) {
    match value {
        Value::Object(map) => {
            patch_object(map, changed, next_id);
            for child in map.values_mut() {
                walk(child, changed, next_id);
            }
        }
        Value::Array(arr) => {
            for child in arr {
                walk(child, changed, next_id);
            }
        }
        _ => {}
    }
}

fn patch_object(map: &mut Map<String, Value>, changed: &mut bool, next_id: &mut u64) {
    let Some(ty) = map.get("type").and_then(Value::as_str).map(str::to_owned) else {
        return;
    };
    if ty == "output_text" && !map.contains_key("annotations") {
        map.insert("annotations".into(), Value::Array(Vec::new()));
        *changed = true;
    }
    if OUTPUT_ITEMS_REQUIRING_ID.contains(&ty.as_str()) && !map.contains_key("id") {
        let id = format!("compat_{next_id}");
        *next_id += 1;
        map.insert("id".into(), Value::String(id));
        *changed = true;
    }
}

/// Fill Responses `usage` sub-objects Codex often omits so `response.completed`
/// can deserialize.
pub(crate) fn fill_response_usage_defaults(value: &mut Value) -> bool {
    let Some(usage) = value
        .pointer_mut("/response/usage")
        .and_then(Value::as_object_mut)
    else {
        return false;
    };
    let mut changed = false;
    if !usage.contains_key("input_tokens_details") {
        usage.insert(
            "input_tokens_details".into(),
            serde_json::json!({ "cached_tokens": 0 }),
        );
        changed = true;
    }
    if !usage.contains_key("output_tokens_details") {
        usage.insert(
            "output_tokens_details".into(),
            serde_json::json!({ "reasoning_tokens": 0 }),
        );
        changed = true;
    }
    changed
}

/// Extra-header key the shell uses to pass session Fast mode. Never forwarded HTTP.
pub(crate) const GROKY_SERVICE_TIER_HEADER: &str = "x-groky-service-tier";

/// ChatGPT Codex Responses (`chatgpt.com/backend-api/codex`).
pub(crate) fn is_codex_responses_url(base_url: &str) -> bool {
    base_url.contains("chatgpt.com/backend-api/codex")
}

pub(crate) fn allows_openai_service_tier(base_url: &str) -> bool {
    let lower = base_url.to_ascii_lowercase();
    !lower.contains("api.x.ai") && !lower.contains("api.anthropic.com")
}

/// GROK_COMPAT_HOOK: set `service_tier` on OpenAI-compatible JSON bodies.
/// Official hosts and OpenAI-compatible relays both get it; xAI / Anthropic
/// official APIs do not.
pub(crate) fn apply_service_tier_to_json(
    base_url: &str,
    service_tier: Option<&str>,
    body: &mut Value,
) {
    let Some(tier) = service_tier.filter(|s| !s.is_empty()) else {
        return;
    };
    if !allows_openai_service_tier(base_url) {
        return;
    }
    if let Some(obj) = body.as_object_mut() {
        obj.insert("service_tier".into(), Value::String(tier.to_owned()));
    }
}

/// GROK_COMPAT_HOOK: call after grok fills typed Responses defaults.
pub(crate) fn prepare_codex_create_response(base_url: &str, req: &mut rs::CreateResponse) {
    if is_codex_responses_url(base_url) {
        adapt_codex_create_response(req);
    }
}

/// GROK_COMPAT_HOOK: last mutation of a serialized Responses body.
pub(crate) fn prepare_codex_request_json(base_url: &str, body: &mut Value) {
    if is_codex_responses_url(base_url) {
        sanitize_codex_request_json(body);
    }
}

/// GROK_COMPAT_HOOK: xAI-only request extras (`stream_tool_calls`, doom-loop).
pub(crate) fn allows_xai_request_extensions(base_url: &str) -> bool {
    !is_codex_responses_url(base_url)
}

/// GROK_COMPAT_HOOK: ChatGPT Codex session-affinity headers (no `x-grok-*`).
pub(crate) fn apply_codex_session_headers(
    mut builder: reqwest::RequestBuilder,
    session_id: &str,
) -> reqwest::RequestBuilder {
    if !session_id.is_empty() {
        builder = builder
            .header("session-id", session_id)
            .header("session_id", session_id)
            .header("conversation_id", session_id)
            .header("x-client-request-id", session_id);
    }
    builder
}

/// GROK_COMPAT_HOOK: lenient JSON on the Responses deserialize-failure path.
///
/// Fill missing `id` / `annotations` first; only then drop items the typed
/// schema still cannot parse (encrypted reasoning, extra types).
pub(crate) fn prepare_lenient_response_json(event_name: &str, value: &mut Value) {
    if let Some(obj) = value.as_object_mut() {
        if !obj.contains_key("type") && event_name.starts_with("response.") {
            obj.insert("type".into(), Value::String(event_name.to_owned()));
        }
        // OpenAI-compatible gateways (vLLM/SGLang proxies) omit `sequence_number`,
        // which the typed schema requires; without it an `error` event is
        // dropped and the turn surfaces as a synthetic 500 instead.
        obj.entry("sequence_number").or_insert(Value::from(0u64));
    }
    sanitize_response_event_json(value);
    fill_response_usage_defaults(value);
    if let Some(output) = value
        .pointer_mut("/response/output")
        .and_then(|v| v.as_array_mut())
    {
        output.retain(|item| serde_json::from_value::<rs::OutputItem>(item.clone()).is_ok());
    }
}

/// Codex/OpenAI often stream `output_text.delta` but leave `response.output`
/// empty on the terminal snapshot. Fold streamed text into the assistant item
/// so the turn is not classified empty and retried.
pub(crate) fn inject_streaming_text_fallback(items: &mut Vec<ConversationItem>, text: &str) {
    if text.is_empty() {
        return;
    }
    if let Some(assistant) = items.iter_mut().rev().find_map(|item| match item {
        ConversationItem::Assistant(a) => Some(a),
        _ => None,
    }) {
        if assistant.content.is_empty() {
            assistant.content = std::sync::Arc::<str>::from(text);
        }
        return;
    }
    items.push(ConversationItem::assistant(text));
}

pub(crate) fn inject_streaming_tool_fallback(
    items: &mut Vec<ConversationItem>,
    streamed_tools: &BTreeMap<u32, (String, String, String)>,
) {
    if streamed_tools.is_empty() {
        return;
    }
    let tools: Vec<ToolCall> = streamed_tools
        .values()
        .map(|(id, name, arguments)| ToolCall {
            id: std::sync::Arc::<str>::from(id.as_str()),
            name: name.clone(),
            arguments: std::sync::Arc::<str>::from(arguments.as_str()),
        })
        .collect();
    if let Some(assistant) = items.iter_mut().rev().find_map(|item| match item {
        ConversationItem::Assistant(a) => Some(a),
        _ => None,
    }) {
        if assistant.tool_calls.is_empty() {
            assistant.tool_calls = tools;
        }
        return;
    }
    items.push(ConversationItem::assistant_tool_calls(tools));
}

pub(crate) fn has_streamed_visible_output(
    text: &str,
    streamed_tools: &BTreeMap<u32, (String, String, String)>,
) -> bool {
    !text.is_empty() || !streamed_tools.is_empty()
}

/// Visible assistant text / tool calls must not be resampled.
pub(crate) fn marks_replay_unsafe(event: &SamplingEvent) -> bool {
    matches!(
        event,
        SamplingEvent::ToolCallDelta { .. }
            | SamplingEvent::ChannelToken {
                channel: SamplingChannel::Text,
                ..
            }
    )
}

/// Streamed text that never landed in the terminal snapshot is still a reply.
pub(crate) fn accept_empty_snapshot(response: &ConversationResponse) -> bool {
    response.message_chunks_emitted > 0
}

/// Keys Pi's `openai-codex-responses` body is allowed to send. Everything
/// else (notably `max_output_tokens`, sampling knobs, xAI extras) 400s
/// on the ChatGPT Codex backend.
const CODEX_BODY_KEYS: &[&str] = &[
    "model",
    "store",
    "stream",
    "instructions",
    "input",
    "text",
    "include",
    "prompt_cache_key",
    "tool_choice",
    "parallel_tool_calls",
    "tools",
    "reasoning",
    "service_tier",
];

/// Pi-shaped typed request: hoist system → `instructions`, drop ChatGPT-
/// rejected sampling fields, keep reasoning only when an effort is set.
pub(crate) fn adapt_codex_create_response(req: &mut rs::CreateResponse) {
    let mut system_chunks = Vec::new();
    if let rs::InputParam::Items(items) = &mut req.input {
        items.retain(|item| {
            let Some(text) = system_message_text(item) else {
                return true;
            };
            if !text.is_empty() {
                system_chunks.push(text);
            }
            false
        });
    }
    req.instructions = Some(if system_chunks.is_empty() {
        "You are a helpful assistant.".to_owned()
    } else {
        system_chunks.join("\n\n")
    });
    req.store = Some(false);
    req.parallel_tool_calls = Some(true);
    if req.tool_choice.is_none() {
        req.tool_choice = Some(rs::ToolChoiceParam::Mode(rs::ToolChoiceOptions::Auto));
    }
    req.temperature = None;
    req.top_p = None;
    req.top_logprobs = None;
    req.max_output_tokens = None;
    req.max_tool_calls = None;
    req.truncation = None;
    req.background = None;
    req.conversation = None;
    req.metadata = None;
    req.previous_response_id = None;
    req.prompt = None;
    req.prompt_cache_retention = None;
    req.safety_identifier = None;
    req.stream_options = None;
    req.reasoning = match req.reasoning.take() {
        Some(reasoning) if reasoning.effort.is_some() => Some(rs::Reasoning {
            effort: reasoning.effort,
            summary: Some(rs::ReasoningSummary::Auto),
        }),
        _ => None,
    };
}

/// Last-line filter after serialize + extra-field splice. `apply_response_defaults`
/// and `stream_tool_calls` must not be able to put a rejected key back.
pub(crate) fn sanitize_codex_request_json(body: &mut Value) {
    let Some(obj) = body.as_object_mut() else {
        return;
    };
    obj.retain(|key, _| CODEX_BODY_KEYS.contains(&key.as_str()));
    if !obj.contains_key("instructions") {
        obj.insert(
            "instructions".into(),
            Value::String("You are a helpful assistant.".into()),
        );
    }
    obj.insert("store".into(), Value::Bool(false));
    obj.insert("parallel_tool_calls".into(), Value::Bool(true));

    match obj.get("text") {
        Some(text) if text.get("format").is_some() => {
            if let Some(text_obj) = obj.get_mut("text").and_then(Value::as_object_mut) {
                text_obj.retain(|key, _| key == "format" || key == "verbosity");
                text_obj
                    .entry("verbosity")
                    .or_insert_with(|| Value::String("low".into()));
            }
        }
        _ => {
            obj.insert("text".into(), serde_json::json!({ "verbosity": "low" }));
        }
    }

    let include = obj
        .entry("include")
        .or_insert_with(|| Value::Array(Vec::new()));
    if let Some(items) = include.as_array_mut() {
        items.retain(|v| v.as_str() == Some("reasoning.encrypted_content"));
        if !items
            .iter()
            .any(|v| v.as_str() == Some("reasoning.encrypted_content"))
        {
            items.push(Value::String("reasoning.encrypted_content".into()));
        }
    }

    let effort = obj
        .get("reasoning")
        .and_then(|r| r.get("effort"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    match effort {
        Some(effort) => {
            obj.insert(
                "reasoning".into(),
                serde_json::json!({ "effort": effort, "summary": "auto" }),
            );
        }
        None => {
            obj.remove("reasoning");
        }
    }

    if obj
        .get("tools")
        .and_then(Value::as_array)
        .is_some_and(Vec::is_empty)
    {
        obj.remove("tools");
    }

    if let Some(input) = obj.get_mut("input").and_then(Value::as_array_mut) {
        transform_codex_input_items(input);
    }
}

const CODEX_INTERRUPTED_TOOL_OUTPUT: &str =
    "[No tool output recorded: the tool call was interrupted before it produced a result.]";
const CODEX_ORPHAN_OUTPUT_LIMIT: usize = 16_000;

fn item_type(item: &Value) -> Option<&str> {
    item.get("type").and_then(Value::as_str)
}

fn item_call_id(item: &Value) -> Option<&str> {
    item.get("call_id").and_then(Value::as_str)
}

fn is_tool_call_type(ty: &str) -> bool {
    matches!(ty, "function_call" | "custom_tool_call")
}

fn is_tool_output_type(ty: &str) -> bool {
    matches!(ty, "function_call_output" | "custom_tool_call_output")
}

fn output_type_for_call(ty: &str) -> &'static str {
    match ty {
        "custom_tool_call" => "custom_tool_call_output",
        _ => "function_call_output",
    }
}

fn matching_output_type(call_ty: &str, output_ty: &str) -> bool {
    matches!(
        (call_ty, output_ty),
        ("function_call", "function_call_output") | ("custom_tool_call", "custom_tool_call_output")
    )
}

fn orphan_output_to_message(item: &Value, call_id: &str) -> Value {
    let tool_name = item.get("name").and_then(Value::as_str).unwrap_or("tool");
    let mut text = match item.get("output") {
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
        None => String::new(),
    };
    if text.len() > CODEX_ORPHAN_OUTPUT_LIMIT {
        text.truncate(CODEX_ORPHAN_OUTPUT_LIMIT);
        text.push_str("\n...[truncated]");
    }
    serde_json::json!({
        "type": "message",
        "role": "assistant",
        "content": format!("[Previous {tool_name} result; call_id={call_id}]: {text}")
    })
}

/// Oh My Pi `filterInput` + `repairToolCallPairs`: drop `item_reference`,
/// strip client item ids, and pair orphaned function calls/outputs so the
/// ChatGPT Codex backend does not 400 mid-turn.
fn transform_codex_input_items(input: &mut Vec<Value>) {
    input.retain(|item| item_type(item) != Some("item_reference"));
    for item in input.iter_mut() {
        if let Some(obj) = item.as_object_mut() {
            obj.remove("id");
        }
    }

    let mut call_types: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    let mut output_types: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    for item in input.iter() {
        let Some(call_id) = item_call_id(item).map(str::to_owned) else {
            continue;
        };
        let Some(ty) = item_type(item) else {
            continue;
        };
        if is_tool_call_type(ty) {
            call_types.insert(call_id.clone(), ty.to_owned());
        }
        if is_tool_output_type(ty) {
            output_types.insert(call_id, ty.to_owned());
        }
    }

    let mut repaired = Vec::with_capacity(input.len());
    for item in input.drain(..) {
        let call_id = item_call_id(&item).map(str::to_owned);
        let ty = item_type(&item).map(str::to_owned);
        if let (Some(call_id), Some(ty)) = (call_id.as_deref(), ty.as_deref()) {
            if is_tool_output_type(ty)
                && call_types
                    .get(call_id)
                    .is_none_or(|call_ty| !matching_output_type(call_ty, ty))
            {
                repaired.push(orphan_output_to_message(&item, call_id));
                continue;
            }
            if is_tool_call_type(ty)
                && output_types
                    .get(call_id)
                    .is_none_or(|out_ty| !matching_output_type(ty, out_ty))
            {
                repaired.push(item);
                repaired.push(serde_json::json!({
                    "type": output_type_for_call(ty),
                    "call_id": call_id,
                    "output": CODEX_INTERRUPTED_TOOL_OUTPUT,
                }));
                continue;
            }
        }
        repaired.push(item);
    }
    *input = repaired;
}

fn system_message_text(item: &rs::InputItem) -> Option<String> {
    let rs::InputItem::EasyMessage(msg) = item else {
        return None;
    };
    if !matches!(msg.role, rs::Role::System | rs::Role::Developer) {
        return None;
    }
    Some(match &msg.content {
        rs::EasyInputContent::Text(text) => text.clone(),
        rs::EasyInputContent::ContentList(parts) => parts
            .iter()
            .filter_map(|part| match part {
                rs::InputContent::InputText(t) => Some(t.text.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("\n"),
    })
}

// ---------------------------------------------------------------------------
// Claude Pro/Max OAuth (Oh My Pi `buildAnthropicHeaders` / tool prefix /
// `claudeCodeSystemInstruction`). `cch` billing attestation is intentionally
// not ported — send the SDK identity + Cowork tool prefix only.
// ---------------------------------------------------------------------------

/// Oh My Pi `claudeCodeSystemInstruction`. First system block on OAuth
/// Messages requests (OMP puts billing attestation in front of this; we skip
/// `cch`, so this is `system[0]`).
pub(crate) const CLAUDE_CODE_SYSTEM_INSTRUCTION: &str =
    "You are a Claude agent, built on Anthropic's Claude Agent SDK.";

/// Oh My Pi `claudeToolPrefix`. Applied once on the way out; stripped once
/// on the way back.
pub(crate) const CLAUDE_TOOL_PREFIX: &str = "_";

const ANTHROPIC_BUILTIN_TOOL_NAMES: &[&str] =
    &["web_search", "code_execution", "text_editor", "computer"];

pub(crate) fn is_anthropic_oauth_token(token: &str) -> bool {
    token.contains("sk-ant-oat")
}

fn header_value_ignore_case<'a>(
    extra_headers: &'a IndexMap<String, String>,
    name: &str,
) -> Option<&'a str> {
    extra_headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

/// True when this sampling client is the Claude Pro/Max OAuth slot.
pub(crate) fn is_claude_oauth_client(
    api_key: Option<&str>,
    extra_headers: &IndexMap<String, String>,
) -> bool {
    api_key.is_some_and(is_anthropic_oauth_token)
        || header_value_ignore_case(extra_headers, "anthropic-beta").is_some_and(|betas| {
            betas
                .split(',')
                .any(|token| token.trim() == "oauth-2025-04-20")
        })
}

/// Cowork `User-Agent` from extra_headers, if the session injected one.
pub(crate) fn claude_oauth_user_agent(extra_headers: &IndexMap<String, String>) -> Option<&str> {
    let ua = header_value_ignore_case(extra_headers, "user-agent")?;
    ua.to_ascii_lowercase()
        .starts_with("claude-cli")
        .then_some(ua)
}

/// Oh My Pi `applyClaudeToolPrefix`: always prepend (no already-prefixed
/// short-circuit) so a tool literally named `_foo` round-trips.
pub(crate) fn apply_claude_tool_prefix(name: &str) -> String {
    if ANTHROPIC_BUILTIN_TOOL_NAMES
        .iter()
        .any(|builtin| name.eq_ignore_ascii_case(builtin))
    {
        return name.to_owned();
    }
    format!("{CLAUDE_TOOL_PREFIX}{name}")
}

pub(crate) fn strip_claude_tool_prefix(name: &str) -> String {
    name.strip_prefix(CLAUDE_TOOL_PREFIX)
        .unwrap_or(name)
        .to_owned()
}

/// GROK_COMPAT_HOOK: Claude OAuth Messages body — SDK identity + `_` tool
/// names. Cache breakpoints on the caller's system prompt are left in place;
/// the identity block itself is never cached.
pub(crate) fn prepare_claude_oauth_messages(req: &mut MessagesRequest) {
    inject_claude_system_instruction(req);
    prefix_claude_oauth_tools(req);
}

fn inject_claude_system_instruction(req: &mut MessagesRequest) {
    let already_present = match &req.system {
        Some(SystemParam::Text(text)) => text == CLAUDE_CODE_SYSTEM_INSTRUCTION,
        Some(SystemParam::Blocks(blocks)) => blocks
            .iter()
            .any(|block| block.text == CLAUDE_CODE_SYSTEM_INSTRUCTION),
        None => false,
    };
    if already_present {
        return;
    }
    let instruction = TextBlock {
        r#type: "text".into(),
        text: CLAUDE_CODE_SYSTEM_INSTRUCTION.into(),
        cache_control: None,
    };
    req.system = Some(match req.system.take() {
        None => SystemParam::Blocks(vec![instruction]),
        Some(SystemParam::Text(text)) => SystemParam::Blocks(vec![
            instruction,
            TextBlock {
                r#type: "text".into(),
                text,
                cache_control: None,
            },
        ]),
        Some(SystemParam::Blocks(mut blocks)) => {
            blocks.insert(0, instruction);
            SystemParam::Blocks(blocks)
        }
    });
}

fn prefix_claude_oauth_tools(req: &mut MessagesRequest) {
    if let Some(tools) = &mut req.tools {
        for tool in tools {
            tool.name = apply_claude_tool_prefix(&tool.name);
        }
    }
    if let Some(ToolChoiceParam::Tool { name }) = &mut req.tool_choice {
        *name = apply_claude_tool_prefix(name);
    }
    for message in &mut req.messages {
        if let MessageContent::Blocks(blocks) = &mut message.content {
            for block in blocks {
                if let ContentBlock::ToolUse { name, .. } = block {
                    *name = apply_claude_tool_prefix(name);
                }
            }
        }
    }
}

pub(crate) fn strip_claude_oauth_response_tools(resp: &mut MessagesResponse) {
    for block in &mut resp.content {
        strip_tool_use_name(block);
    }
}

pub(crate) fn strip_claude_oauth_stream_event(event: &mut MessageStreamEvent) {
    match event {
        MessageStreamEvent::MessageStart { message } => {
            strip_claude_oauth_response_tools(message);
        }
        MessageStreamEvent::ContentBlockStart { content_block, .. } => {
            strip_tool_use_name(content_block);
        }
        _ => {}
    }
}

fn strip_tool_use_name(block: &mut ContentBlock) {
    if let ContentBlock::ToolUse { name, .. } = block {
        *name = strip_claude_tool_prefix(name);
    }
}

/// GROK_COMPAT_HOOK: Claude OAuth request headers (no `x-grok-*`).
pub(crate) fn apply_claude_oauth_request_headers(
    mut builder: reqwest::RequestBuilder,
    session_id: &str,
) -> reqwest::RequestBuilder {
    builder = builder.header("x-client-request-id", uuid::Uuid::new_v4().to_string());
    if !session_id.is_empty() {
        builder = builder.header("X-Claude-Code-Session-Id", session_id);
    }
    builder
}

#[cfg(test)]
mod tests {
    use super::sanitize_response_event_json;
    use serde_json::{Value, json};

    fn xai_completed() -> Value {
        json!({
            "type": "response.completed",
            "sequence_number": 0,
            "response": {
                "id": "resp_test",
                "object": "response",
                "created_at": 1234567890,
                "model": "grok-4.6",
                "status": "completed",
                "output": [{
                    "type": "message",
                    "id": "msg_test",
                    "role": "assistant",
                    "status": "completed",
                    "content": [{
                        "type": "output_text",
                        "text": "hello",
                        "annotations": []
                    }]
                }]
            }
        })
    }

    fn openai_completed_missing_fields() -> Value {
        json!({
            "type": "response.completed",
            "sequence_number": 0,
            "response": {
                "id": "resp_gpt",
                "object": "response",
                "created_at": 1234567890,
                "model": "gpt-5.6",
                "status": "completed",
                "output": [
                    {
                        "type": "reasoning",
                        "summary": [{ "type": "summary_text", "text": "think" }],
                        "status": "completed"
                    },
                    {
                        "type": "message",
                        "role": "assistant",
                        "status": "completed",
                        "content": [{
                            "type": "output_text",
                            "text": "Hi. What can I help you with?"
                        }]
                    }
                ]
            }
        })
    }

    #[test]
    fn xai_shaped_payload_is_unchanged() {
        let mut value = xai_completed();
        let before = value.clone();
        assert!(!sanitize_response_event_json(&mut value));
        assert_eq!(value, before);
    }

    #[test]
    fn is_codex_url_matches_chatgpt_backend() {
        assert!(super::is_codex_responses_url(
            "https://chatgpt.com/backend-api/codex"
        ));
        assert!(super::is_codex_responses_url(
            "https://chatgpt.com/backend-api/codex/"
        ));
        assert!(!super::is_codex_responses_url("https://api.openai.com/v1"));
        assert!(!super::is_codex_responses_url("https://api.x.ai/v1"));
    }

    #[test]
    fn codex_hoists_system_messages_out_of_input() {
        use xai_grok_sampling_types::{ConversationItem, ConversationRequest, rs};

        let req = ConversationRequest::from_items(vec![
            ConversationItem::system("You are Codex."),
            ConversationItem::user("hi"),
        ])
        .with_model("gpt-5.6-terra")
        .with_temperature(0.2)
        .with_max_output_tokens(128_000);
        let mut body: rs::CreateResponse = (&req).into();
        super::adapt_codex_create_response(&mut body);
        let rs::InputParam::Items(items) = body.input else {
            panic!("expected items");
        };
        assert_eq!(items.len(), 1, "system item must leave input");
        assert_eq!(body.instructions.as_deref(), Some("You are Codex."));
        assert!(body.temperature.is_none());
        assert!(body.top_p.is_none());
        assert!(body.max_output_tokens.is_none());
        assert_eq!(body.store, Some(false));
        assert_eq!(body.parallel_tool_calls, Some(true));
        assert!(body.reasoning.is_none());
    }

    #[test]
    fn codex_json_allowlist_drops_rejected_parameters() {
        let mut body = json!({
            "model": "gpt-5.6-terra",
            "max_output_tokens": 128000,
            "temperature": 0.7,
            "top_p": 1.0,
            "stream_tool_calls": true,
            "truncation": "auto",
            "stream_options": { "include_usage": true },
            "input": [{ "role": "user", "content": "hi" }],
            "stream": true,
            "reasoning": { "summary": "concise" }
        });
        super::sanitize_codex_request_json(&mut body);
        assert!(body.get("max_output_tokens").is_none());
        assert!(body.get("temperature").is_none());
        assert!(body.get("top_p").is_none());
        assert!(body.get("stream_tool_calls").is_none());
        assert!(body.get("truncation").is_none());
        assert!(body.get("stream_options").is_none());
        assert!(body.get("reasoning").is_none());
        assert_eq!(body["store"], false);
        assert_eq!(body["parallel_tool_calls"], true);
        assert_eq!(body["text"]["verbosity"], "low");
        assert_eq!(body["instructions"], "You are a helpful assistant.");
        assert_eq!(body["include"], json!(["reasoning.encrypted_content"]));
        assert_eq!(body["model"], "gpt-5.6-terra");
        assert_eq!(body["stream"], true);
    }

    #[test]
    fn codex_repairs_orphaned_tool_call_and_output() {
        let mut body = json!({
            "model": "gpt-5.6-terra",
            "input": [
                { "type": "function_call", "call_id": "c1", "name": "read_file", "arguments": "{}", "id": "fc_drop" },
                { "type": "function_call_output", "call_id": "c2", "output": "stale result" },
                { "type": "item_reference", "id": "msg_old" },
                { "type": "message", "role": "user", "content": "hi", "id": "msg_1" }
            ],
            "stream": true
        });
        super::sanitize_codex_request_json(&mut body);
        let input = body["input"].as_array().expect("input");
        assert!(
            input.iter().all(|item| item.get("id").is_none()
                && item.get("type") != Some(&json!("item_reference"))),
            "{input:?}"
        );
        assert!(
            input.iter().any(|item| {
                item.get("type") == Some(&json!("function_call_output"))
                    && item.get("call_id") == Some(&json!("c1"))
            }),
            "orphaned function_call must get a synthetic output: {input:?}"
        );
        assert!(
            input.iter().any(|item| {
                item.get("role") == Some(&json!("assistant"))
                    && item
                        .get("content")
                        .and_then(|v| v.as_str())
                        .is_some_and(|s| s.contains("call_id=c2"))
            }),
            "orphaned function_call_output must fold into an assistant note: {input:?}"
        );
    }

    #[test]
    fn fills_missing_annotations_and_ids() {
        let mut value = openai_completed_missing_fields();
        assert!(sanitize_response_event_json(&mut value));

        let reasoning = &value["response"]["output"][0];
        assert_eq!(reasoning["id"], "compat_0");

        let message = &value["response"]["output"][1];
        assert_eq!(message["id"], "compat_1");
        assert_eq!(message["content"][0]["annotations"], json!([]));
        assert_eq!(
            message["content"][0]["text"],
            "Hi. What can I help you with?"
        );
    }

    #[test]
    fn does_not_invent_id_on_delta_events() {
        let mut value = json!({
            "type": "response.output_text.delta",
            "sequence_number": 0,
            "item_id": "item_test",
            "output_index": 0,
            "content_index": 0,
            "delta": "hello"
        });
        let before = value.clone();
        assert!(!sanitize_response_event_json(&mut value));
        assert_eq!(value, before);
        assert!(value.get("id").is_none());
    }

    #[test]
    fn fills_annotations_on_content_part() {
        let mut value = json!({
            "type": "response.content_part.done",
            "sequence_number": 1,
            "item_id": "msg_1",
            "output_index": 0,
            "content_index": 0,
            "part": {
                "type": "output_text",
                "text": "done"
            }
        });
        assert!(sanitize_response_event_json(&mut value));
        assert_eq!(value["part"]["annotations"], json!([]));
        assert!(value.get("id").is_none());
    }

    #[test]
    fn claude_oauth_detected_from_oat_token_or_beta_header() {
        let mut headers = indexmap::IndexMap::new();
        assert!(super::is_claude_oauth_client(
            Some("sk-ant-oat-test"),
            &headers
        ));
        assert!(!super::is_claude_oauth_client(
            Some("sk-ant-api03-test"),
            &headers
        ));
        headers.insert(
            "anthropic-beta".into(),
            "oauth-2025-04-20,claude-code-20250219".into(),
        );
        assert!(super::is_claude_oauth_client(
            Some("sk-ant-api03-test"),
            &headers
        ));
    }

    #[test]
    fn claude_oauth_messages_inject_system_and_prefix_tools() {
        use xai_grok_sampling_types::messages::{
            ContentBlock, Message, MessageContent, MessageRole, MessagesRequest, SystemParam,
            ToolChoiceParam, ToolParam,
        };

        let mut req = MessagesRequest {
            model: "claude-opus-4-6".into(),
            messages: vec![Message {
                role: MessageRole::Assistant,
                content: MessageContent::Blocks(vec![ContentBlock::ToolUse {
                    id: "t1".into(),
                    name: "bash".into(),
                    input: json!({}),
                    cache_control: None,
                }]),
            }],
            max_tokens: 1024,
            system: Some(SystemParam::Text("Stay concise.".into())),
            tools: Some(vec![
                ToolParam {
                    name: "bash".into(),
                    description: Some("run".into()),
                    input_schema: json!({"type": "object"}),
                },
                ToolParam {
                    name: "web_search".into(),
                    description: None,
                    input_schema: json!({"type": "object"}),
                },
            ]),
            tool_choice: Some(ToolChoiceParam::Tool {
                name: "bash".into(),
            }),
            ..Default::default()
        };
        super::prepare_claude_oauth_messages(&mut req);

        let SystemParam::Blocks(blocks) = req.system.as_ref().expect("system") else {
            panic!("expected system blocks");
        };
        assert_eq!(blocks[0].text, super::CLAUDE_CODE_SYSTEM_INSTRUCTION);
        assert!(blocks[0].cache_control.is_none());
        assert_eq!(blocks[1].text, "Stay concise.");

        let tools = req.tools.as_ref().expect("tools");
        assert_eq!(tools[0].name, "_bash");
        assert_eq!(tools[1].name, "web_search");
        assert!(
            matches!(req.tool_choice, Some(ToolChoiceParam::Tool { ref name }) if name == "_bash")
        );
        let MessageContent::Blocks(history) = &req.messages[0].content else {
            panic!("expected history blocks");
        };
        assert!(matches!(&history[0], ContentBlock::ToolUse { name, .. } if name == "_bash"));

        super::prepare_claude_oauth_messages(&mut req);
        let SystemParam::Blocks(blocks) = req.system.as_ref().expect("system") else {
            panic!("expected system blocks");
        };
        assert_eq!(
            blocks
                .iter()
                .filter(|b| b.text == super::CLAUDE_CODE_SYSTEM_INSTRUCTION)
                .count(),
            1,
            "identity block must be idempotent"
        );
    }

    #[test]
    fn claude_tool_prefix_round_trip_preserves_literal_underscore_names() {
        assert_eq!(super::apply_claude_tool_prefix("bash"), "_bash");
        assert_eq!(super::strip_claude_tool_prefix("_bash"), "bash");
        assert_eq!(super::apply_claude_tool_prefix("_foo"), "__foo");
        assert_eq!(super::strip_claude_tool_prefix("__foo"), "_foo");
        assert_eq!(super::apply_claude_tool_prefix("web_search"), "web_search");
        assert_eq!(super::strip_claude_tool_prefix("bash"), "bash");
    }

    #[test]
    fn claude_oauth_stream_event_strips_tool_prefix() {
        use xai_grok_sampling_types::messages::{ContentBlock, MessageStreamEvent};

        let mut event = MessageStreamEvent::ContentBlockStart {
            index: 0,
            content_block: ContentBlock::ToolUse {
                id: "t1".into(),
                name: "_bash".into(),
                input: json!({}),
                cache_control: None,
            },
        };
        super::strip_claude_oauth_stream_event(&mut event);
        let MessageStreamEvent::ContentBlockStart { content_block, .. } = event else {
            panic!("expected content_block_start");
        };
        assert!(matches!(content_block, ContentBlock::ToolUse { name, .. } if name == "bash"));
    }

    #[test]
    fn service_tier_json_on_openai_compatible_hosts() {
        let mut openai = json!({"model": "gpt-4o"});
        super::apply_service_tier_to_json(
            "https://api.openai.com/v1",
            Some("priority"),
            &mut openai,
        );
        assert_eq!(openai["service_tier"], json!("priority"));

        let mut codex = json!({"model": "gpt-5.6-sol"});
        super::apply_service_tier_to_json(
            "https://chatgpt.com/backend-api/codex",
            Some("priority"),
            &mut codex,
        );
        assert_eq!(codex["service_tier"], json!("priority"));

        let mut proxy = json!({"model": "gpt-4o"});
        super::apply_service_tier_to_json("https://relay.example/v1", Some("priority"), &mut proxy);
        assert_eq!(proxy["service_tier"], json!("priority"));

        let mut grok = json!({"model": "grok-4.5"});
        super::apply_service_tier_to_json("https://api.x.ai/v1", Some("priority"), &mut grok);
        assert!(grok.get("service_tier").is_none());

        let mut anthropic = json!({"model": "claude-sonnet-4"});
        super::apply_service_tier_to_json(
            "https://api.anthropic.com/v1",
            Some("priority"),
            &mut anthropic,
        );
        assert!(anthropic.get("service_tier").is_none());

        let mut empty = json!({"model": "gpt-4o"});
        super::apply_service_tier_to_json("https://api.openai.com/v1", None, &mut empty);
        assert!(empty.get("service_tier").is_none());
    }
}
