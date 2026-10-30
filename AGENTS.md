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

Release recovery: manual `Release groky` runs require an existing `tag` and build that tag, not the selected workflow branch. Push workflow-only fixes to `main`, then dispatch from `main` for the original tag; keep the tag unchanged.

Voice: `**Lead** rest.` Lead is the noun the user already knows (`/default`, `Resume`, `Settings Default model`). One bullet per user-visible change.

### Unreleased

Next groky version after `v0.1.32`.

- **Session import** no longer lists Codex internal child threads (guardian approval reviews, `/review`, spawned agents), which imported as walls of `[N] tool … call` user messages.
- **Imported sessions** render tool history as native cards: commands with output and exit code, file reads, and per-file diffs (including Codex/OpenCode `apply_patch`, omp hashline edits, and Codex code-mode scripts) for Claude Code, Codex, omp, pi and OpenCode. Codex environment/AGENTS.md preambles no longer show as user messages.
- **`/import-session`** and **`groky sessions import`** can import upstream grok CLI sessions (`--from grok`), copied as-is under a new ID.
- **Session import** finds omp sessions in large stores (previously none were listed) and Codex sessions whose first 64 KB ends mid-character; never-used Codex sessions are hidden.
