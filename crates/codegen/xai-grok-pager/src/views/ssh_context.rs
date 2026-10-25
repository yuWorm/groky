//! Durable SSH target context: exact wire payloads and display-only labels.
//!
//! Sent messages and replay do not retain textarea elements. The typed envelope is the
//! durable identity; presentation must never replace the text used for sending or editing.

use std::borrow::Cow;
use std::ops::Range;

const PREFIX: &str = r#"{"type":"ssh_target","#;

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetContext<'a> {
    #[serde(rename = "type")]
    kind: TargetKind,
    #[serde(borrow)]
    target_id: Cow<'a, str>,
    #[serde(borrow)]
    label: Cow<'a, str>,
    #[serde(borrow)]
    address: Cow<'a, str>,
}

#[derive(serde::Serialize, serde::Deserialize)]
enum TargetKind {
    #[serde(rename = "ssh_target")]
    Ssh,
}

pub(crate) fn payload(target_id: &str, label: &str, address: &str) -> String {
    let payload = serde_json::to_string(&TargetContext {
        kind: TargetKind::Ssh,
        target_id: Cow::Borrowed(target_id),
        label: Cow::Borrowed(label),
        address: Cow::Borrowed(address),
    })
    .expect("serializing SSH target context strings cannot fail");
    escape_json_inline_separators(payload)
}

/// Chip label shared by the composer and durable message presentation.
pub(crate) fn label(label: &str, address: &str) -> String {
    let mut output = String::with_capacity("SSH:  · ".len() + label.len() + address.len());
    append_label(&mut output, label, address);
    output
}

fn append_label(output: &mut String, label: &str, address: &str) {
    output.push_str("SSH: ");
    push_terminal_safe(output, label);
    output.push_str(" · ");
    push_terminal_safe(output, address);
}

fn push_terminal_safe(output: &mut String, value: &str) {
    for character in value.chars() {
        if character.is_control() || matches!(character, '\u{2028}' | '\u{2029}') {
            output.push(' ');
        } else {
            output.push(character);
        }
    }
}

fn escape_json_inline_separators(payload: String) -> String {
    if !payload.chars().any(|character| {
        character.is_control() || matches!(character, '\u{2028}' | '\u{2029}')
    }) {
        return payload;
    }
    use std::fmt::Write;
    let mut escaped = String::with_capacity(payload.len());
    for character in payload.chars() {
        if character.is_control() || matches!(character, '\u{2028}' | '\u{2029}') {
            write!(escaped, "\\u{:04x}", character as u32)
                .expect("writing a JSON escape into a String cannot fail");
        } else {
            escaped.push(character);
        }
    }
    escaped
}

pub(crate) struct SshTargetChip {
    /// Byte range in the original prompt, before any presentation replacement.
    pub range: Range<usize>,
    pub display: String,
}

/// Recognize complete envelopes emitted by `payload`, including existing v0.1.28 history.
/// Ordinary JSON, incomplete envelopes and unknown fields remain literal text.
/// No collection or JSON parsing is needed for text without the exact type discriminator.
pub(crate) fn chips(text: &str) -> impl Iterator<Item = SshTargetChip> + '_ {
    let mut offset = 0;
    std::iter::from_fn(move || loop {
        let start = offset + text.get(offset..)?.find(PREFIX)?;
        offset = start + PREFIX.len();
        let mut stream = serde_json::Deserializer::from_str(&text[start..])
            .into_iter::<TargetContext<'_>>();
        let Some(Ok(target)) = stream.next() else {
            continue;
        };
        let end = start + stream.byte_offset();
        if target.target_id.is_empty()
            || target.address.is_empty()
            || text[start..end].contains('\n')
            || text[end..].chars().next().is_some_and(|character| !character.is_whitespace())
        {
            continue;
        }
        offset = end;
        let mut display = String::with_capacity("[SSH:  · ]".len() + target.label.len() + target.address.len());
        display.push('[');
        append_label(&mut display, &target.label, &target.address);
        display.push(']');
        return Some(SshTargetChip { range: start..end, display });
    })
}

/// Project a prompt for display, leaving the caller's authoritative original untouched.
pub(crate) fn display_text(text: &str) -> Cow<'_, str> {
    let mut chips = chips(text);
    let Some(first) = chips.next() else {
        return Cow::Borrowed(text);
    };
    let mut display = String::with_capacity(text.len());
    display.push_str(&text[..first.range.start]);
    display.push_str(&first.display);
    let mut end = first.range.end;
    for chip in chips {
        display.push_str(&text[end..chip.range.start]);
        display.push_str(&chip.display);
        end = chip.range.end;
    }
    display.push_str(&text[end..]);
    Cow::Owned(display)
}
