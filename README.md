# groky

[English](README.md) · [中文](README.zh.md)

**groky** is a product fork of [Grok Build](https://github.com/xai-org/grok-build) (`grok`).
It keeps the same agent, tools, MCP, ACP, and TUI — and adds third-party
models (OpenAI, Anthropic, OpenRouter, custom OpenAI-compatible endpoints)
plus ChatGPT Codex OAuth.

The CLI binary is **`groky`**. It can sit next to official `grok`.

Latest release: [v0.1.20](https://github.com/yuWorm/groky/releases/tag/v0.1.20)

## Install

macOS and Linux:

```sh
curl -fsSL https://raw.githubusercontent.com/yuWorm/groky/main/scripts/install-groky.sh | bash
groky --version
```

The binary lands in `~/.groky/bin/groky`. groky's own config lives under
`~/.groky/` (`config.toml`, `vendor-auth.json`). On first launch (and any
later upgrade that is still missing a file) groky copies those from
`~/.grok/` if present, then **shares** sessions, xAI login, memory, skills,
and plugins with official `grok` via `~/.grok/` (directory links +
`GROK_AUTH_PATH`). Set `GROK_HOME` to isolate everything; set
`GROKY_SKIP_HOME_MIGRATE=1` to skip the copy/link step.

- Pin a version: `bash -s 0.1.0`
- Upgrade: run the same `curl | bash` again
- **Do not** run `curl https://x.ai/cli/install.sh` — that installs official `grok`

Windows is not in v0.1.0 (upstream `bin/protoc` is a Unix stub). See
[INSTALL.md](INSTALL.md) for the release matrix and the PowerShell script
for later tags.

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
| Claude Pro/Max (not an `sk-ant-` key) | `/provider-login anthropic-claude` |
| Custom OpenAI-compatible endpoint | `/provider-login` → custom provider |
| Switch model | `/model` |
| Fast mode (GPT, including custom OpenAI-compatible relays) | `/fast` |
| Drop a vendor key | `/provider-logout` |
| Refresh vendor model lists | `/sync-models-dev` (alias `/refresh-models`); provider picker `r`; custom model list `Ctrl+R` |
| Update groky | `groky update` or `groky update --version 0.1.20` (Welcome: ctrl+u) |

xAI login is unchanged (`AuthManager`, `~/.grok/auth.json`, shared with
official `grok`). Third-party keys never go in `config.toml`; they live in
`~/.groky/vendor-auth.json`. A vendor 401 asks for `/provider-login`, not
`/login`.

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
