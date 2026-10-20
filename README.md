# groky

[English](README.md) · [中文](README.zh.md)

**groky** is a product fork of [Grok Build](https://github.com/xai-org/grok-build) (`grok`).
It keeps the same agent, tools, MCP, ACP, and TUI — and adds third-party
models (OpenAI, Anthropic, OpenRouter, custom OpenAI-compatible endpoints)
plus ChatGPT Codex OAuth.

The CLI binary is **`groky`**. It can sit next to official `grok`.

Latest release: [v0.1.25](https://github.com/yuWorm/groky/releases/tag/v0.1.25)

## Install

macOS and Linux:

```sh
curl -fsSL https://raw.githubusercontent.com/yuWorm/groky/main/scripts/install-groky.sh | bash
groky --version
```

Windows x86_64 (PowerShell):

```powershell
irm https://raw.githubusercontent.com/yuWorm/groky/main/scripts/install-groky.ps1 | iex
groky --version
```

On Windows, the installer places `groky.exe` in `%USERPROFILE%\.groky\bin`
and adds that directory to your user `PATH`. If `groky` is not found,
open a new PowerShell window.


On macOS and Linux, the binary lands in `~/.groky/bin/groky`. groky's own config lives under
`~/.groky/` (`config.toml`, `vendor-auth.json`). On first launch (and any
later upgrade that is still missing a file) groky copies those from
`~/.grok/` if present, then **shares** sessions, xAI login, memory, skills,
and plugins with official `grok` via `~/.grok/` (directory links +
`GROK_AUTH_PATH`). Set `GROK_HOME` to isolate everything; set
`GROKY_SKIP_HOME_MIGRATE=1` to skip the copy/link step.

- Pin a version: see [INSTALL.md](INSTALL.md) for Bash and PowerShell commands
- Upgrade: run your platform's install command again
- **Do not** run `curl https://x.ai/cli/install.sh` — that installs official `grok`

Windows x86_64 binaries are available from v0.1.23. See
[INSTALL.md](INSTALL.md) for the release matrix and version-pinned installation.

## Usage

```sh
cd your-project
groky
```

| You want | Do this |
| --- | --- |
| xAI Grok | `/login` — same flow as official Grok Build |
| OpenAI / Anthropic / OpenRouter API key | `/provider-login` then pick the provider |
| ChatGPT Codex (Plus/Pro, not an `sk-` key) | `/provider-login openai-codex` |
| Manage multiple ChatGPT Codex accounts | `/provider-accounts` — add, label, select, or remove one account |
| Claude Pro/Max (not an `sk-ant-` key) | `/provider-login anthropic-claude` |
| Custom OpenAI-compatible endpoint | `/provider-login` → custom provider |
| Remove a custom provider | `/provider-login` → highlight it → `d` (or `Delete`) → `Enter` to confirm; `Esc` cancels |
| Check subscription / gateway quotas | `/provider-usage` (aliases `/pusage`, `/usage providers`) |
| Switch model | `/model` |
| Fast mode (GPT, including custom OpenAI-compatible relays) | `/fast` |
| Sign out a provider (all its accounts) | `/provider-logout` |
| Refresh vendor model lists | `/sync-models-dev` (alias `/refresh-models`); provider picker `r`; custom model list `Ctrl+R` |
| Update groky | `groky update` or `groky update --version 0.1.25` (Welcome: ctrl+u) |

xAI login is unchanged (`AuthManager`, `~/.grok/auth.json`, shared with
official `grok`). Third-party keys never go in `config.toml`; they live in
`~/.groky/vendor-auth.json`. A vendor 401 asks for `/provider-login`, not
`/login`.

Removing a custom provider deletes its configuration, models, and saved credentials,
and refreshes the provider and model pickers. Built-in providers cannot be removed.
`/provider-logout` only signs out; it keeps custom-provider configuration for later use.

Codex accounts keep separate credentials and model catalogs. In `/provider-accounts`
(also available through `/provider-login openai-codex`), use `a` to add a login,
`Enter` to select, `r` to label, and `d` to remove with confirmation. Selecting
an account sets the default for new sessions and changes only the current session;
a running turn finishes before the change takes effect. Other sessions keep their
selection, including on resume. Removing the default leaves no default until you
choose one. Existing single-account logins migrate automatically. Accounts do not
rotate automatically or combine subscription quotas.

New Codex logins use the returned email as the account label when available.
Signing in again fills an untouched account-ID label, but preserves existing
labels and manual renames; token refresh never changes the label. Missing or
unusable email metadata does not block login. Accounts with identical labels
show their account IDs separately in the account manager. Email is display
metadata only; credentials, model catalogs, and quotas remain keyed by account ID.

### Provider quotas

`/provider-usage` lists saved accounts separately, with default and current-session
markers. Press `r` to refresh. A failed refresh labels any retained snapshot as
stale; changing credentials or removing an account discards its in-flight results.
Checking quotas never switches accounts or combines their allowances. For multiple
keys on the same gateway, add a separate custom provider for each key.

Custom providers have an independent **Platform** choice: Generic, Sub2API, One API,
or New API. This does not change the inference protocol. Existing providers default
to Generic; edit them through `/provider-login` and press `Esc` from the model list
to reach the form. The optional **Usage base URL** is the gateway service root,
not a full usage endpoint, and must share the inference URL's origin. If omitted,
groky removes a trailing `/v1` while preserving any path prefix.

| Source | What is shown |
| --- | --- |
| Codex | Account-specific usage windows, reset times, and credits when returned. Uses an internal ChatGPT endpoint that may change. |
| Sub2API / New API | Gateway-reported key, subscription, or wallet allowances, not upstream subscription quotas or local token counts. Missing currency conversion stays in gateway quota units. |
| One API | Reported limit and usage separately. Public responses cannot establish key vs. account scope, so remaining balance stays unknown. |
| Claude subscription | Official Settings → Usage link (`o`); no direct OAuth quota query. The browser's signed-in account determines which account that page shows. |
| Generic | Unsupported until a compatible platform is selected. |

### SSH projects and explicit SSH tools

SSH targets reuse literal aliases from `~/.ssh/config` and the system SSH
configuration. A connection alone does **not** authorize an agent to use it.

```sh
groky ssh list
groky ssh add my-server --id dev --label "Development"
groky ssh open dev /srv/project
# With an existing noninteractive authentication method:
groky ssh connect dev
groky ssh disconnect dev
```

**Explicit SSH tools do not require remote groky or a worker.** They use the
authenticated native SSH connection, SFTP for files, and POSIX shell execution.
The SSH server must enable SFTP; search additionally requires remote `rg`.

**SSH projects manage their own matching remote worker.** On project open or
resume, groky checks the remote OS/architecture and the worker's product/protocol
version. A missing worker is installed automatically; after a local upgrade, the
next open/resume installs that exact release, never an unrelated `latest` build.
Supported worker platforms are Linux and macOS on x86_64 or aarch64.

Installation first downloads the release and its required SHA-256 checksum on
the remote host. If that fails, the TUI shows the full error and asks whether to
download through **this computer's network** and upload over the authenticated
SSH/SFTP connection. `Enter`/`y` or the footer button approves; `n`/`Esc` declines.
Downloads/uploads and identity checks finish before the worker is published under
`~/.groky/workers/<version>/<os>-<arch>/groky`. No sudo or system `PATH` change is
needed. Versions remain side by side, with separate daemons; failed installation
does not replace an existing worker or silently run an incompatible one.

Development builds have no release download: same-platform hosts can receive
the local executable after explicit approval, keyed by its SHA-256. For a different
remote platform, use a published release or supply a matching cross-built worker.
An explicit `--worker-command '/absolute/path/groky worker --stdio'` is user-managed:
groky checks compatibility but never overwrites or automatically updates it.
Git, ripgrep and the project's tools must still be available remotely. The worker
does not need an xAI login; model requests and provider credentials remain local.

Open `/ssh` in a session, or press `Ctrl+S` on Welcome. Select a server and press
`Enter` to connect and browse its remote folders; no worker or model access is
needed for browsing. Use arrows/`j`/`k`, `Enter` for a child folder, `Backspace`
for its parent, or `/` to enter a remote path. Press `o` to open the current folder.
The first confirmation shows the verified server identity, canonical folder and
read/write/run permissions. Approval automatically prepares the worker and opens
the project—there is no separate grant/use/open sequence.

**Remember this project** is optional and off by default. A saved permission applies
only to the same target, host identity and exact canonical remote folder, independently
of the local directory from which groky starts. Existing permissions are reused without
expansion; a different folder, identity or broader permission request needs fresh consent.
Without remembering, access lasts only for the authorized session.

`c` connects/disconnects, `a` adds a target, `d` shows connection details, and `m`
opens advanced grant/default/revocation controls. Advanced `g` requests a root-scoped
grant, `u` selects a default (continuing automatically after any required consent),
and `r` revokes only the selected grant. Each active grant has its own row.
Target rows and footer actions are clickable; the wheel scrolls lists. Permission
options support clicks and `Tab`/`Space`; `PgUp`/`PgDn` inspect wrapped details.
Passwords, encrypted private keys, ssh-agent and keyboard-interactive authentication are supported.
Host trust and access grants are separate confirmations. Passwords are masked and
remembered only by explicit opt-in to the OS credential store; if that store is
unavailable, remembering is disabled rather than falling back to a plaintext file.
`ssh connect` is noninteractive: use `/ssh` when authentication or host trust needs
an answer.

Known-host checks isolate each host/port and allow multiple key algorithms. If a
stored key changes and `StrictHostKeyChecking` permits prompting (`ask`), `/ssh`
shows the old and new fingerprints and record locations.
Verify the new fingerprint independently before pressing `r` to replace and save.
Replacement backs up the file to `.old` (or a numbered backup), preserves unrelated
records, and refuses stale confirmations or ambiguous/global/wildcard records.
Those records require manual review. In the target manager, `d` opens the selected
target's configuration, grant details and latest SSH error. Normal connection
details are not errors: connected status is green and only actual failures are red.
Long diagnostics and host-key details wrap and scroll. Unsupported forwarding directives are reported
explicitly, not silently ignored: use system OpenSSH for forwarding, or scope those
directives to a separate alias.
Folder selection and grant drafts can be cancelled with `Esc` or the close button.
Directory, grant and target-save failures open the full diagnostic automatically;
`Esc` returns to the retained folder or form. Failed navigation restores the last
valid folder, so the displayed path and the folder being opened cannot disagree.
Target saves and project opens ignore
repeated submissions while pending. Project startup failures return to the source
manager with a diagnostic and allow retry. The remote worker uses a short, private
per-user socket path so long home directories do not exceed Unix socket limits.

There are two execution modes:

- **SSH project:** ordinary file, edit, search, command and Git operations use the
  remote workspace. Remote project instructions, skills, hooks, MCP and LSP follow
  that workspace. The TUI, model requests, transcripts and provider credentials remain
  local. Remote hooks receive the verified remote cwd/root, not a local transcript path.
  Discovered instructions and skills stay within the authorized root: ancestor
  instructions and symlinks escaping that root are excluded. Skill bodies, including
  slash-command skills, are read on the remote worker, not from matching local paths.
- **Explicit SSH tools in any session:** `ssh_read`, `ssh_write`, `ssh_edit`,
  `ssh_search` and `ssh_run` take an optional `target`. An explicit target wins;
  otherwise a user-selected SSH default is required. This default never redirects
  ordinary local tools. `ssh_targets` lists only the current session's grants;
  `ssh_request_access` asks the user for a grant rather than granting itself access.
  These tools stay workerless even inside an SSH project; they do not load remote
  project instructions, skills or hooks. File reads support UTF-8 text and line
  ranges, not image/PDF decoding. Read output and existing-file write/edit
  snapshots are bounded. Replacing an existing file requires the SFTP
  `posix-rename@openssh.com` extension; unsupported servers fail before writing.
  Edits recheck the original bytes before atomic replacement, but this is not a
  cross-client compare-and-swap against concurrent writers.
  `ssh_task_query` and `ssh_task_cancel` operate within the selected binding.
  Query with `task_id` to read task output, with `operation_id` to inspect a
  recorded operation, or neither to list tasks; these IDs are not local task IDs.
  Agent/session tool allowlists, denylists and capability restrictions still apply;
  curated profiles that disable default tool injection keep their explicit toolset.

Grants specify a remote root and read/write/execute capabilities. They are
session-scoped unless the user explicitly saves a project rule; subagents inherit
only an authorized subset. A grant does not bypass operation approval. **A run
working directory is not a sandbox:** commands run with the remote SSH user's OS
permissions. Revocation blocks new calls locally immediately. A workerless-only
grant needs no remote acknowledgement; a grant used by a project worker remains
“remote confirmation pending” until that worker acknowledges revocation.
Already-running tasks require separate cancellation. Workerless tasks can still
be cancelled using their captured binding ID after its grant is revoked.

Headless resume can reuse an existing grant with noninteractive SSH authentication
and the normal tool permissions. Required SSH interaction fails promptly;
`--always-approve` does not answer remote operation approvals.

SSH resume restores conversation only unless `--restore-code` is set. With that
flag, groky requests approval to check out the session's saved Git HEAD in its
verified remote root. Current dirty tracked/untracked files are stashed before
changing HEAD; the result reports the stash reference or any preservation failure.
This is **HEAD-only restoration**, not recovery of historical staged, unstaged or
untracked file snapshots. No matching local checkout is touched.
With `--resume <session-id> --worktree --restore-code`, the original remote checkout
is left unchanged. The new worktree needs its own root grant, and restoration runs
only in that child. Omitting `--restore-code` keeps the normal worktree copy behavior.

For persistent overrides, use the user-global `~/.groky/config.toml`:

```toml
[ssh.targets.dev]
host = "my-server" # existing OpenSSH alias
label = "Development"
user = "developer" # optional override
# Optional, user-managed worker (disables managed installation and updates):
# worker_command = ["/usr/local/bin/groky", "worker", "--stdio"]
```

Groky target overrides take precedence over user SSH config, then system SSH
config, then defaults. Matching files retain first-value-wins semantics and
accumulate `IdentityFile` entries; repository config cannot override connection
identity or credentials. This is not complete OpenSSH compatibility: unsupported
active directives, including `Match exec`, GSSAPI authentication, ControlMaster
and agent forwarding, fail explicitly instead of being silently ignored.

Connections are pooled and held independently of individual tool calls.
The default embedded TUI owns its pool for that process's lifetime. Start with
`groky --leader` to share a persistent pool with other leader-backed TUIs and
manual `groky ssh connect` holds; grants still belong to individual sessions.
Transport loss does not automatically replay writes, edits or commands.
Workerless task IDs and bounded stdout/stderr history belong to the local service,
not a remote daemon; use `ssh_task_query` rather than expecting a completion
wakeup. A disconnect before a confirmed exit produces an unknown outcome, and the
process may still be running. Cancellation is a request, not proof of termination.
SSH project workers retain their own tasks across channel disconnects; if the
worker itself exits, unfinished outcomes are also unknown.

## What this fork changes

| Added | Left alone |
| --- | --- |
| Multi-provider catalog and custom providers | Agent loop, tools, MCP, ACP |
| `/provider-login`, `/provider-logout`, `/sync-models-dev`, `/fast` | `/login`, Welcome, `auth.json` |
| ChatGPT Codex OAuth (`openai-codex`) | Official `grok` CDN install and auto-update |
| Claude Pro/Max OAuth (`anthropic-claude`) | Anthropic console API keys (`anthropic`) |
| models.dev reasoning / context overlay | Default auto-compact threshold (85%) |
| Binary name `groky` (`~/.groky/bin`) and config home `~/.groky` | Rewriting the TUI as a different product |

## Official documentation

In-tree guides still say `grok`. On this fork the command is `groky`.
`/login` is still xAI; third-party auth is `/provider-login`.

- Upstream README: [xai-org/grok-build](https://github.com/xai-org/grok-build)
- Online docs: [docs.x.ai/build/overview](https://docs.x.ai/build/overview)
- User guide in this tree: [`crates/codegen/xai-grok-pager/docs/user-guide/`](crates/codegen/xai-grok-pager/docs/user-guide/)

Useful entry points:

| Guide | Topic |
| --- | --- |
| [Getting Started](crates/codegen/xai-grok-pager/docs/user-guide/01-getting-started.md) | First launch and concepts |
| [Authentication](crates/codegen/xai-grok-pager/docs/user-guide/02-authentication.md) | xAI `/login` (not vendor login) |
| [Keyboard Shortcuts](crates/codegen/xai-grok-pager/docs/user-guide/03-keyboard-shortcuts.md) | Keys and mouse |
| [Slash Commands](crates/codegen/xai-grok-pager/docs/user-guide/04-slash-commands.md) | `/` commands |
| [Configuration](crates/codegen/xai-grok-pager/docs/user-guide/05-configuration.md) | `config.toml`, env, paths |
| [MCP Servers](crates/codegen/xai-grok-pager/docs/user-guide/07-mcp-servers.md) | MCP |
| [Skills](crates/codegen/xai-grok-pager/docs/user-guide/08-skills.md) | SKILL.md packages |
| [Custom Models](crates/codegen/xai-grok-pager/docs/user-guide/11-custom-models.md) | Upstream BYOK notes (this fork also has `/provider-login`) |

Build-from-source requirements (Rust, DotSlash, protoc) match
[upstream “Building from source”](https://github.com/xai-org/grok-build#building-from-source).

```sh
cargo run -p xai-grok-pager-bin --bin groky
# or
./scripts/tui.sh
```

The crate is still `xai-grok-pager-bin` so merges with xAI stay small.
The product entrypoint is `groky`.

## Relationship to Grok Build

This repository is a product fork. We merge [xai-org/grok-build](https://github.com/xai-org/grok-build)
when we want an upstream fix — it is not a daily rebase. Maintainer notes:
[`crates/codegen/xai-grok-shell/src/compat/UPSTREAM.md`](crates/codegen/xai-grok-shell/src/compat/UPSTREAM.md).

Upstream does not accept external contributions
([`CONTRIBUTING.md`](CONTRIBUTING.md)). Issues and changes for **groky**
belong in this repo.

## License

First-party code is **Apache License 2.0** — see [`LICENSE`](LICENSE).
Third-party and vendored notices: [`THIRD-PARTY-NOTICES`](THIRD-PARTY-NOTICES).
