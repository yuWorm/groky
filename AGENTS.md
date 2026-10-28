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

Next groky version after `v0.1.29`.

- **/import-session** discovers omp, pi, Claude Code, Codex, and OpenCode sessions for the current directory, previews migration warnings, and imports a new native session without changing the source or rerunning historical tools; `groky sessions import` provides the same local import from IDs or paths.
- **SSH approvals** preserve concurrent access, command, and authentication requests instead of overwriting dialogs; completion, cancellation, and expiry advance only the matching request, while sudo password prompts stay tied to their approved command.
- **SSH authorization listener** reports interruptions and restores valid pending prompts after recovery without replaying commands or approval decisions.
