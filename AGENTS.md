# groky

Product fork of xAI grok-build. CLI is `groky`, home is `~/.groky`. Merge playbook: `crates/codegen/xai-grok-shell/src/compat/UPSTREAM.md`.

## Release changelog

Welcome Changelog, `/release-notes`, and the once-per-upgrade Release Notes prompt read the bundled files — not `x.ai/cli/changelogs`:

- `crates/codegen/xai-grok-shell/src/compat/changelogs/CHANGELOG.md`
- `crates/codegen/xai-grok-shell/src/compat/changelogs/CHANGELOG.json`

**Unreleased** below is the source of truth until the next groky tag. Do not invent a version section in those files until ship.

### Ship

1. Take every Unreleased bullet. Rewrite only if the user-facing behavior changed since it was filed.
2. Prepend a version section to `CHANGELOG.md`:
   `# {version} — {YYYY-MM-DD}` then `## Features` / `## Bug Fixes` (omit empty sections).
3. Prepend matching objects to `CHANGELOG.json`. Shape: `{ "category": "features"|"fixes", "description": "**Lead** rest.", "breaking_change": false }`. Array order is welcome-bullet order (first 3 show on Welcome).
4. Delete the shipped bullets from Unreleased. Done when Unreleased is empty or only holds work not in this tag.
5. GitHub Release body: paste the same markdown section. `.github/workflows/release.yml` writes a stub; replace the notes after the tag.

Voice: `**Lead** rest.` Lead is the noun the user already knows (`/default`, `Resume`, `Settings Default model`). One bullet per user-visible change.

### Unreleased

Next groky version after `v0.1.30`.

#### Bug Fixes

- **Messages backend** prompt cache now survives Claude gateways such as sub2api: requests send a stable `metadata.user_id` per session, so cache reads no longer drop to zero every few turns.
- **Messages backend** no longer fails after switching from another provider mid-session: foreign or unsigned reasoning replays as plain text, and long tool call ids are shortened to Anthropic's 64-char limit.
- **Messages backend** retries a stream that ends before `message_stop` instead of committing a truncated reply.
- **Messages backend** forced tool calls turn thinking off, and `tool_choice: none` is sent as `none` rather than `auto`.
- **Title refresh** reuses the conversation's prompt cache on Claude models instead of re-reading the whole session.
