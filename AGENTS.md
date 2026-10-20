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

Next groky version after `v0.1.25`.

- **SSH host trust** correctly isolates known_hosts ports and key algorithms, and offers explicit changed-key replacement with old/new fingerprints, backups and safeguards against ambiguous records.
- **SSH diagnostics** distinguish normal connection details from actual errors, with green connected status and wrapped, scrollable full errors that return to the retained folder or form.
- **SSH connection status** clears completed connect/disconnect progress without replacing newer errors or another target's progress.
- **SSH access grants** choose remote folders before permission confirmation, including requests without a directory; cancellation denies waiting requests without late popups, each active binding remains separately revocable, and default selection continues automatically after approval.
- **SSH task continuation** waits for access approval and resumes the original tool call automatically; cancellation, session closure and client disconnect prevent late approvals from restoring access.
- **SSH operation previews** show highlighted multiline commands and exact file changes, with mouse/keyboard scrolling, raw details and command copying.
- **SSH operation approvals** offer allow-once or current-session approval for the exact grant and operation kind; Advanced can restore per-operation prompts without revoking access.
- **SSH controls** offer server selection and remote folder browsing as the primary flow, with clickable rows, scrolling and keyboard-focusable permissions; grant/default/revocation controls live under Advanced.
- **SSH target saving** prevents duplicate submissions, preserves form fields after failure, and selects the saved target with a completed status message.
- **SSH project startup** no longer stalls on repeated pending guards, returns failures to the originating manager for retry, and isolates asynchronous results from other sessions or reopened managers.
- **SSH worker startup** uses a short private socket namespace for long home directories and retains early daemon startup diagnostics.
- **SSH worker installation** detects the remote platform and installs the exact local release automatically, with checksum validation and an explicit local-download/SSH-upload fallback when remote downloads fail.
- **SSH worker updates** prepare matching versions on project open or resume, keep existing versions intact, and isolate their daemons while preserving cross-version grant revocation.
- **SSH project resume** restores projects opened from non-default grants and keeps worker installation confirmations visible while the session loads, without reopening dismissed dialogs.
- **SSH projects** connect automatically, confirm the verified folder and permissions once, then prepare the matching worker and open the project without a separate grant/use/open sequence.
- **SSH project permissions** can optionally remember an exact remote project across sessions and local launch directories, reusing only matching host identity, canonical folder and approved capabilities without expanding access.
