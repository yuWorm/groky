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

Next groky version after `v0.1.26`.

- **SSH target management** supports editing and confirmed deletion of manual targets in both SSH managers, preserves IDs and untouched settings, and invalidates changed connections and grants; imported OpenSSH targets remain read-only with source-file guidance and external refresh.
- **SSH access** makes worker-free authorization the default in chat and connection-only the default without a session; remote projects have a separate explicit entry with worker requirements shown before approval.
- **SSH server selection** lists configured manual and OpenSSH candidates for tools, resolves exact names safely, and makes `/ssh` selections the session default after approval without installing a worker.
- **SSH access requests** distinguish cancellation, explicit denial and real connection or inspection failures, preserving the original error for the waiting tool and rejecting late approvals.
- **/ssh** accepts a server name or target ID directly, reuses an unambiguous session grant or opens worker-free authorization, and shows matching candidates instead of guessing duplicate names.
- **/ssh suggestions** automatically list configured servers while typing, filter by name or address, and support arrow selection, Tab completion and Enter confirmation using exact target IDs without connecting during discovery.
- **groky update** uses `https://gh-proxy.com` for GitHub release metadata and downloads by default; `--mirrors` (alias `--mirros`) overrides the mirror per invocation, and `--mirrors direct` bypasses it without exposing GitHub tokens to mirrors.
- **Update downloads** stream to disk with progress, speed and ETA (or downloaded bytes when size is unknown), replace the two-minute total deadline with connection/read timeouts, and remove partial binaries after interrupted transfers.
