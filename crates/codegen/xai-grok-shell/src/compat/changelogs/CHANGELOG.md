# 0.1.32 — 2026-10-29

## Features

- **`groky sessions import`** scans `--dir` (default: current directory), imports by ID or unique prefix, opens a multi-select picker in a terminal, and `--all` batch-imports with a progress bar, skipping sessions already imported (`--force` to redo). Breaking: the old all-projects `--all` is now `--all-projects`.
- **`/import-session`** accepts the CLI arguments (ID, directory, `--from`, `--all`), and `a` in the picker imports every new session with progress.

# 0.1.31 — 2026-10-29

## Features

- **`/remote`** lists remote SSH projects from remembered access and past sessions, with Tab to switch All / Remembered / Recent; Enter starts a new session in the project and Ctrl+R resumes its latest one.
- **`/ssh`** server picker gains `o` to jump to remote projects; `/remote` is no longer an alias of `/ssh`.
- **SSH worker installation** asks how to get the worker when the remote host can't download it from GitHub: retry on the remote host through the `https://gh-proxy.com` mirror, or download on this computer (mirror or direct) and upload over SSH; if the chosen source fails, the prompt reappears with its error so you can pick another.

## Bug Fixes

- **Messages backend** prompt cache now survives Claude gateways such as sub2api: requests send a stable `metadata.user_id` per session, so cache reads no longer drop to zero every few turns.
- **Messages backend** no longer fails after switching from another provider mid-session: foreign or unsigned reasoning replays as plain text, and long tool call ids are shortened to Anthropic's 64-char limit.
- **Messages backend** retries a stream that ends before `message_stop` instead of committing a truncated reply.
- **Messages backend** forced tool calls turn thinking off, and `tool_choice: none` is sent as `none` rather than `auto`.
- **Title refresh** reuses the conversation's prompt cache on Claude models instead of re-reading the whole session.
- **SSH projects** `!` bash mode runs the command on the remote host instead of failing to start a shell in a directory that exists only remotely.
- **SSH projects** tell the model the remote host's OS and shell instead of the local machine's.
- **SSH projects** no longer run local or plugin hooks on this machine; the project's hooks run only on the remote worker.
- **Custom providers** on OpenAI-compatible gateways now show the provider's error (e.g. an unsupported reasoning effort) instead of retrying a generic `Server error (500)`.
- **OpenAI Codex** and other non-xAI OpenAI-compatible models no longer fail every turn with `Invalid schema for function 'use_tool'` when MCP file input is enabled; they get the inline-only `use_tool`.

# 0.1.30 — 2026-10-28

## Features

- **/import-session** discovers omp, pi, Claude Code, Codex, and OpenCode sessions for the current directory, previews migration warnings, and imports a new native session without changing the source or rerunning historical tools; `groky sessions import` provides the same local import from IDs or paths.

## Bug Fixes

- **SSH approvals** preserve concurrent access, command, and authentication requests instead of overwriting dialogs; completion, cancellation, and expiry advance only the matching request, while sudo password prompts stay tied to their approved command.
- **SSH authorization listener** reports interruptions and restores valid pending prompts after recovery without replaying commands or approval decisions.

# 0.1.29 — 2026-10-26

## Bug Fixes

- **SSH target labels** stay readable in sent messages, queued prompts and previews, and restored chat history instead of displaying raw JSON, while preserving the original target context sent to the agent.
- **SSH approvals** return to chat after successful access or command consent instead of showing the server list, while preserving project-opening follow-ups and any required per-command sudo password challenge.
- **SSH input cursors** remain visible in focused target, directory, grant and masked authentication fields, with Unicode-aware movement, scrolling and correct cursor ownership when dialogs close.

# 0.1.28 — 2026-10-25

## Features

- **`/ssh`** selects a server into an editable chat draft, connects only when needed, and sends the target with your requirements only when you submit; existing text and attachments are preserved.
- **SSH root commands** support explicit `sudo` execution with one-time approval, masked local password entry over SSH, no saved sudo credentials, and cancellation-safe authorization without automatic replay.

## Bug Fixes

- **SSH operation approvals** retire expired or cancelled requests, recover from late replies without trapping the manager, and require fresh approval before retrying without replaying remote commands.
- **SSH warnings** use warning colors distinct from errors; operation review instructions no longer appear in error red.

# 0.1.27 — 2026-10-22

## Features

- **SSH target management** supports editing and confirmed deletion of manual targets in both SSH managers, preserves IDs and untouched settings, and invalidates changed connections and grants; imported OpenSSH targets remain read-only with source-file guidance and external refresh.
- **SSH access** makes worker-free authorization the default in chat and connection-only the default without a session; remote projects have a separate explicit entry with worker requirements shown before approval.
- **SSH server selection** lists configured manual and OpenSSH candidates for tools, resolves exact names safely, and makes `/ssh` selections the session default after approval without installing a worker.
- **/ssh** accepts a server name or target ID directly, reuses an unambiguous session grant or opens worker-free authorization, and shows matching candidates instead of guessing duplicate names.
- **/ssh suggestions** automatically list configured servers while typing, filter by name or address, and support arrow selection, Tab completion and Enter confirmation using exact target IDs without connecting during discovery.
- **groky update** uses `https://gh-proxy.com` for GitHub release metadata and downloads by default; `--mirrors` (alias `--mirros`) overrides the mirror per invocation, and `--mirrors direct` bypasses it without exposing GitHub tokens to mirrors.
- **Update downloads** stream to disk with progress, speed and ETA (or downloaded bytes when size is unknown), replace the two-minute total deadline with connection/read timeouts, and remove partial binaries after interrupted transfers.

## Bug Fixes

- **SSH access requests** distinguish cancellation, explicit denial and real connection or inspection failures, preserving the original error for the waiting tool and rejecting late approvals.

# 0.1.26 — 2026-10-20

## Features

- **SSH access grants** choose remote folders before permission confirmation, including requests without a directory; cancellation denies waiting requests without late popups, each active binding remains separately revocable, and default selection continues automatically after approval.
- **SSH task continuation** waits for access approval and resumes the original tool call automatically; cancellation, session closure and client disconnect prevent late approvals from restoring access.
- **SSH operation previews** show highlighted multiline commands and exact file changes, with mouse/keyboard scrolling, raw details and command copying.
- **SSH operation approvals** offer allow-once or current-session approval for the exact grant and operation kind; Advanced can restore per-operation prompts without revoking access.
- **SSH controls** offer server selection and remote folder browsing as the primary flow, with clickable rows, scrolling and keyboard-focusable permissions; grant/default/revocation controls live under Advanced.
- **groky ssh** opens a standalone manager for targets, connections, diagnostics and folders; parameter-free add and optional open arguments use shared interactive controls, while explicit interactive connect handles local authentication without changing script/JSON commands.
- **SSH worker installation** detects the remote platform and installs the exact local release automatically, with checksum validation and an explicit local-download/SSH-upload fallback when remote downloads fail.
- **SSH worker updates** prepare matching versions on project open or resume, keep existing versions intact, and isolate their daemons while preserving cross-version grant revocation.
- **SSH projects** connect automatically, confirm the verified folder and permissions once, then prepare the matching worker and open the project without a separate grant/use/open sequence.
- **SSH project permissions** can optionally remember an exact remote project across sessions and local launch directories, reusing only matching host identity, canonical folder and approved capabilities without expanding access.

## Bug Fixes

- **SSH host trust** correctly isolates known_hosts ports and key algorithms, and offers explicit changed-key replacement with old/new fingerprints, backups and safeguards against ambiguous records.
- **SSH diagnostics** distinguish normal connection details from actual errors, with green connected status and wrapped, scrollable full errors that return to the retained folder or form.
- **SSH connection status** clears completed connect/disconnect progress without replacing newer errors or another target's progress.
- **SSH target saving** prevents duplicate submissions, preserves form fields after failure, and selects the saved target with a completed status message.
- **SSH project startup** no longer stalls on repeated pending guards, returns failures to the originating manager for retry, and isolates asynchronous results from other sessions or reopened managers.
- **SSH worker startup** uses a short private socket namespace for long home directories and retains early daemon startup diagnostics.
- **SSH project resume** restores projects opened from non-default grants and keeps worker installation confirmations visible while the session loads, without reopening dismissed dialogs.

# 0.1.25 — 2026-10-18

## Features

- **Codex account labels** use the sign-in email automatically when available, fill untouched account-ID labels on re-login, preserve manual labels and refresh behavior, and show separate account IDs when labels match.
- **Custom providers** can be removed from `/provider-login` with `d` or `Delete` and confirmation, deleting their configuration, models, and saved credentials without affecting built-in or other custom providers; in-flight model refreshes do not restore removed providers.
- **SSH targets** reuse existing SSH configuration with native password, key and agent authentication, held connections, host verification, and opt-in system credential storage through `/ssh` and `groky ssh`.
- **SSH tools** provide explicit remote read, write, edit, search, run and task controls directly over SSH/SFTP without installing remote groky, with session-scoped grants, selectable defaults, operation approval, immediate workerless revocation and no automatic replay after disconnects.
- **SSH projects** run workspace tools, Git and project extensions on a private remote worker while keeping the TUI, model requests and provider credentials local, including scoped discovery, remote resume/forks/worktrees and subagent authority.

# 0.1.24 — 2026-10-16

## Features

- **Codex accounts** add, label, select, and remove multiple ChatGPT subscriptions with `/provider-accounts`; sessions retain their own account, switches wait for the current turn, and credentials and model catalogs stay isolated without automatic rotation.
- **Provider quotas** check Codex subscriptions and supported gateways with `/provider-usage`; account-scoped snapshots, reset times, and refresh errors stay separate, stale requests are discarded after credential changes or account removal, and Claude subscriptions link to the official usage page.
- **Custom providers** select Generic, Sub2API, One API, or New API independently of the inference protocol, with an optional same-origin usage service root; gateway quota units and unknown remaining balances are shown without inventing subscription allowances.

# 0.1.23 — 2026-10-15

## Bug Fixes

- **Windows builds** Fix the release shell, update incompatible compiler-helper dependencies, and make protobuf dependency generation work on Windows.

# 0.1.22 — 2026-10-15

## Features

- **ChatGPT Codex models** refresh from the signed-in account with a five-minute account-scoped cache and bundled fallback.

## Bug Fixes

- **Providers** keep credentials tied to the selected account when providers share an endpoint or model, including model switches and resumed sessions. Missing credentials no longer reuse an old key or another provider's key.
- **Messages providers** accept base URLs without `/v1`, including GLM's Anthropic-compatible endpoint, instead of sending requests to the wrong path and retrying empty responses. Existing `/v1` URLs keep working.

# 0.1.21 — 2026-10-09

## Features

- **`/context-window`** sets a session window from the model's menu (`/context-window 256k`). groky `/window` still works.
- **Claude settings import** on Welcome (Ctrl+I; Shift+I dismisses).
- **Per-model notice** banner sits above the prompt when the catalog has one.
- **Ask mode** paints the composer flag and border green.
- **Sandbox** holds network requests and asks before allowing egress.
- **`max_request_bytes`** on a custom model or provider caps the request body so image-heavy sessions stay under the host limit.
- **Subagent model inheritance** is a Settings row with layered overrides.

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
