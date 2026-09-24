# Install groky

One-click install is documented in [README.md](README.md) / [README.zh.md](README.zh.md).
This page is the release appendix (asset names, Windows).

`groky` is the product CLI for this fork ([yuWorm/groky](https://github.com/yuWorm/groky)).
It is the same TUI as Grok Build (`xai-grok-pager-bin`), shipped under a
different binary name so it can sit next to official `grok`.

The **executable** is `~/.groky/bin/groky`. groky **config** is `~/.groky/`
(`config.toml`, `vendor-auth.json`). First launch copies those from `~/.grok/`
when groky does not have them yet, and shares sessions / xAI login / memory /
skills / plugins with official `grok` via `~/.grok/`. `GROK_HOME` isolates
everything; `GROKY_SKIP_HOME_MIGRATE=1` skips the copy/link step.

## One-click

```sh
curl -fsSL https://raw.githubusercontent.com/yuWorm/groky/main/scripts/install-groky.sh | bash
groky --version
```

Windows PowerShell:

```powershell
irm https://raw.githubusercontent.com/yuWorm/groky/main/scripts/install-groky.ps1 | iex
```

Pin a version (downloads `github.com/.../releases/download/...` and does
**not** call `api.github.com` — useful behind a shared VPN IP):

```sh
curl -fsSL https://raw.githubusercontent.com/yuWorm/groky/main/scripts/install-groky.sh | bash -s 0.1.20
groky update --version 0.1.20
```

PowerShell: `$env:GROKY_VERSION="0.1.20"; irm ... | iex`

Unpinned `groky update` / the installer without a version still query
`/releases/latest`. A `GROKY_GITHUB_TOKEN` (or `GITHUB_TOKEN`) raises that
API quota.

Re-run the same command to upgrade.

## Releases

GitHub Actions (`.github/workflows/release.yml`) builds `groky` from
`xai-grok-pager-bin` on tag `v*` (or a manual “Release groky” run):

| Asset | Runner |
| --- | --- |
| `groky-{ver}-macos-aarch64` | macos-14 |
| `groky-{ver}-macos-x86_64` | macos-14 + `--target` |
| `groky-{ver}-linux-x86_64` | ubuntu-24.04 |
| `groky-{ver}-linux-aarch64` | ubuntu-24.04-arm |
| `groky-{ver}-windows-x86_64.exe` | windows-latest |

```bash
git tag v0.1.0
git push origin v0.1.0
```

Do **not** use `curl https://x.ai/cli/install.sh` for this fork — that
installs official `grok`.

## From source

```sh
cargo run -p xai-grok-pager-bin --bin groky
# or
./scripts/tui.sh
```

The crate is still `xai-grok-pager-bin` (so merges with xAI stay small).
The product entrypoint is `groky`.
