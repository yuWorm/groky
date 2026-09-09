//! Wire names of the hub-synthesized Grok Bot harness tools.
//!
//! Single source of truth shared by the hub that registers the tools and
//! by agent hosts that gate the tools per agent config.

/// Handwritten v1 harness tool ids. The hub's registration specs are
/// tested against this list so the surface cannot drift silently.
pub const GROK_BOT_TOOL_IDS: &[&str] = &[
    "bot_create_agent",
    "bot_list_agents",
    "bot_send_prompt",
    "bot_get_agent_transcript",
    "bot_get_agent_transcript_page",
    "bot_get_agent_transcript_tail",
    "bot_get_agent_transcript_window",
    "bot_transcript_offbox",
    "bot_await_turn",
];

/// Whether `name` is a hub-synthesized Grok Bot harness tool.
pub fn is_grok_bot_tool(name: &str) -> bool {
    GROK_BOT_TOOL_IDS.contains(&name)
}

/// Model-facing descriptions, one per [`GROK_BOT_TOOL_IDS`] entry (same
/// order). The hub registers its tools with these strings, and agent hosts
/// use them to advertise opted-in bot tools before the hub connection is
/// live, so both surfaces render the same text.
pub const GROK_BOT_TOOL_DESCRIPTIONS: &[(&str, &str)] = &[
    (
        "bot_create_agent",
        "Create a Grok Bot agent. It greets the user itself; send no first \
         prompt, never quote its id. Cannot be deleted; check bot_list_agents \
         first.",
    ),
    (
        "bot_list_agents",
        "List Grok Bot agents on the user's box with id, name, description, \
         and status. Wakes the box.",
    ),
    (
        "bot_send_prompt",
        "Send a prompt to a Grok Bot agent. Returns once accepted unless mode \
         waits for the reply. on_busy is reject (default), queue, or supersede. \
         After a timeout or a missing notification, resume with bot_await_turn \
         and the returned handle; never re-send. Empty reply with \
         finished:true means no text. A <grok_bot agent_id> tag is that \
         agent's id.",
    ),
    (
        "bot_get_agent_transcript",
        "Read an agent's entire transcript. Wakes the box.",
    ),
    (
        "bot_get_agent_transcript_page",
        "Read a time-bounded page of an agent's transcript. Wakes the box.",
    ),
    (
        "bot_get_agent_transcript_tail",
        "Read the latest page of an agent's transcript, such as the reply after \
         a send. Wakes the box. Do not poll it to wait for a turn; use \
         bot_await_turn.",
    ),
    (
        "bot_get_agent_transcript_window",
        "Like bot_get_agent_transcript_tail, plus per-thread counts.",
    ),
    (
        "bot_transcript_offbox",
        "Read an agent's transcript without waking the box. Pass the previous \
         page's nextCursor to continue.",
    ),
    (
        "bot_await_turn",
        "Wait for an agent's turn to finish. Pass the handle from \
         bot_send_prompt to keep waiting after a timeout instead of re-sending. \
         Without a handle, waits for idle and returns the last message.",
    ),
];

/// The model-facing description for a Grok Bot tool id, if known.
pub fn grok_bot_tool_description(name: &str) -> Option<&'static str> {
    GROK_BOT_TOOL_DESCRIPTIONS
        .iter()
        .find(|(id, _)| *id == name)
        .map(|(_, desc)| *desc)
}

/// Flattened JSON Schema for a Grok Bot tool's arguments.
///
/// Same shape the hub advertises via `schema_for_kind`. Pre-bind synthesis
/// uses this so constrained decoding can emit required fields (`agent_id`,
/// `prompt`, …) instead of locking the call to `{}`.
pub fn grok_bot_tool_arguments_schema(name: &str) -> Option<serde_json::Value> {
    Some(match name {
        "bot_create_agent" => serde_json::json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["name"],
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Display name."
                },
                "description": {
                    "type": "string",
                    "description": "Optional persona or instructions."
                }
            }
        }),
        "bot_list_agents" => serde_json::json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {}
        }),
        "bot_send_prompt" => serde_json::json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["agent_id", "prompt"],
            "properties": {
                "agent_id": {
                    "type": "string",
                    "description": "Agent id."
                },
                "prompt": {
                    "type": "string",
                    "description": "Text to send."
                },
                "mode": {
                    "type": "string",
                    "enum": ["fire_and_forget", "blocking", "async"],
                    "description": "fire_and_forget (default) returns on accept; blocking waits and returns the reply; async returns a handle and notifies when the turn ends."
                },
                "timeout_ms": {
                    "type": "integer",
                    "description": "Wait limit in ms for blocking. Async uses the safety max. Out-of-range values are clamped."
                },
                "on_busy": {
                    "type": "string",
                    "enum": ["reject", "queue", "supersede"],
                    "description": "reject (default), queue after idle, or supersede the current wait."
                },
                "paths": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Up to 8 files, 25 MiB each. Workspace-relative paths such as attachments/note.pdf; absolute guest paths are rewritten. Without a connected workspace, artifacts/ and attachments/ paths fetch conversation files."
                }
            }
        }),
        "bot_get_agent_transcript" => serde_json::json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["agent_id"],
            "properties": {
                "agent_id": {
                    "type": "string",
                    "description": "Agent id."
                }
            }
        }),
        "bot_get_agent_transcript_page" => serde_json::json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["agent_id", "limit", "until_ms"],
            "properties": {
                "agent_id": {
                    "type": "string",
                    "description": "Agent id."
                },
                "limit": {
                    "type": "integer",
                    "description": "Max entries, at least 1."
                },
                "until_ms": {
                    "type": "integer",
                    "description": "Inclusive upper bound, unix ms."
                },
                "before_seq": {
                    "type": "integer",
                    "description": "Return entries before this seq."
                },
                "since_ms": {
                    "type": "integer",
                    "description": "Inclusive lower bound, unix ms."
                }
            }
        }),
        "bot_get_agent_transcript_tail" => serde_json::json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["agent_id", "limit"],
            "properties": {
                "agent_id": {
                    "type": "string",
                    "description": "Agent id."
                },
                "limit": {
                    "type": "integer",
                    "description": "Max entries, at least 1."
                },
                "before_seq": {
                    "type": "integer",
                    "description": "Return entries before this seq; omit for the latest page."
                }
            }
        }),
        "bot_get_agent_transcript_window" => serde_json::json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["agent_id", "limit"],
            "properties": {
                "agent_id": {
                    "type": "string",
                    "description": "Agent id."
                },
                "limit": {
                    "type": "integer",
                    "description": "Max entries, at least 1."
                },
                "before_seq": {
                    "type": "integer",
                    "description": "Return entries before this seq; omit for the latest page."
                }
            }
        }),
        "bot_transcript_offbox" => serde_json::json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["agent_id"],
            "properties": {
                "agent_id": {
                    "type": "string",
                    "description": "Agent id."
                },
                "cursor": {
                    "type": "string",
                    "description": "nextCursor from the previous page; omit on the first."
                }
            }
        }),
        "bot_await_turn" => serde_json::json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["agent_id"],
            "properties": {
                "agent_id": {
                    "type": "string",
                    "description": "Agent id; must match the handle's agent."
                },
                "handle": {
                    "type": "object",
                    "default": null,
                    "description": "From bot_send_prompt or a prior bot_await_turn, unchanged. Omit to wait for idle."
                },
                "timeout_ms": {
                    "type": "integer",
                    "description": "Wait limit in ms; on timeout, finished:false plus a handle to wait again."
                }
            }
        }),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptions_cover_every_id_in_order() {
        let desc_ids: Vec<&str> = GROK_BOT_TOOL_DESCRIPTIONS
            .iter()
            .map(|(id, _)| *id)
            .collect();
        assert_eq!(desc_ids, GROK_BOT_TOOL_IDS);
        assert!(
            GROK_BOT_TOOL_DESCRIPTIONS
                .iter()
                .all(|(_, desc)| !desc.trim().is_empty())
        );
    }

    #[test]
    fn arguments_schema_covers_every_id() {
        for id in GROK_BOT_TOOL_IDS {
            let schema = grok_bot_tool_arguments_schema(id)
                .unwrap_or_else(|| panic!("{id} must have an arguments schema"));
            assert_eq!(schema["type"], "object", "{id}");
        }
        assert!(grok_bot_tool_arguments_schema("bot_typo").is_none());
    }

    /// Every byte here is prompt context on every turn that carries the tools.
    #[test]
    fn surface_fits_budget() {
        let total: usize = GROK_BOT_TOOL_IDS
            .iter()
            .map(|id| {
                serde_json::json!({
                    "name": id,
                    "description": grok_bot_tool_description(id),
                    "parameters": grok_bot_tool_arguments_schema(id),
                })
                .to_string()
                .len()
            })
            .sum();
        assert!(
            total <= 5_000,
            "model-facing bot tool surface is {total} bytes; trim before raising the budget"
        );
    }
}
