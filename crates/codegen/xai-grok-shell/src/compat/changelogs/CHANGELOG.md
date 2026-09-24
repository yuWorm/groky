# Unreleased

# 0.1.20 — 2026-09-24

## Bug Fixes

- **`/window`** can set a gear during its own slash turn. It no longer fails with "Cannot change context window while a turn is running".

# 0.1.19 — 2026-09-24

## Features

- **`/window`** picks a session context-window gear cut from the model's max. Type `256k`, `1M`, `1.05M`, or `max`. Shrinking compact-fits at the current window first.
- **Custom provider models** can set max context (`c` to type `256k`/`1M`, `[]` to cycle) and compact threshold (`t`) in the model list and when adding a model.
- **Model switch** no longer auto-compacts across providers. Foreign encrypted reasoning and backend tool calls are stripped instead.

# 0.1.18 — 2026-09-23

## Features

- **`/default`** shows and sets the disk `[models].default` without switching the current session. `/model` still switches and persists.
- **Release Notes** open once on Welcome after an upgrade. `/release-notes` and the Welcome Changelog block use groky notes bundled in the binary.

## Bug Fixes

- **Default model** resolves with the vendor catalog overlay, so `[models].default` is not ignored.
- **Default fallback** uses the bundled default (`grok-4.6`) instead of the first catalog row (`grok-4.7`).
- **Resume** keeps a vanished model and blocks prompts instead of silently switching to the newest catalog model.
- **Settings Default model** reads and writes the disk `[models].default`, not the live session model.

# 0.1.17 — 2026-09-22

## Features

- **Default `$GROK_HOME`** is `~/.groky`, so `config.toml` and `vendor-auth.json` are no longer shared with official grok.
- **First launch** copies missing files from `~/.grok`; existing groky files are left alone.
- **Sessions, xAI login, memory, skills, and plugins** stay shared via `~/.grok/` (directory links + `GROK_AUTH_PATH`).
- **`GROK_HOME`** isolates the whole tree; `GROKY_SKIP_HOME_MIGRATE=1` skips copy/link. `GROK_HOME=~/.grok` restores the old fully-shared layout.

# 0.1.16 — 2026-09-21

## Features

- **`groky update --version`** downloads the GitHub asset directly and does not call `api.github.com`.
- **Pinned installer** (`bash -s 0.1.16`) uses the same direct download.
- **Unpinned `groky update`** still queries `/releases/latest` once, then downloads the asset directly.

# 0.1.15 — 2026-09-21

## Features

- **`/memory`** can delete entries, shows empty states, and carries over legacy `MEMORY.md`.
- **Post-turn plan review** offers Keep / Review / execute after a turn ends.
- **Workflows** can pause and stop; `/flush` and `/dream` report progress.

## Bug Fixes

- **Vendor catalog overlay** follows `ModelsManager` to `remote_config/manager` after the grok-build merge.
