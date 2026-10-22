# Install groky

One-click install is documented in [README.md](README.md) / [README.zh.md](README.zh.md).
This page is the release appendix (asset names, Windows).

`groky` is the product CLI for this fork ([yuWorm/groky](https://github.com/yuWorm/groky)).
It is the same TUI as Grok Build (`xai-grok-pager-bin`), shipped under a
different binary name so it can sit next to official `grok`.

The **executable** is `~/.groky/bin/groky` on macOS/Linux or
`%USERPROFILE%\.groky\bin\groky.exe` on Windows. groky **config** is `~/.groky/`
(`config.toml`, `vendor-auth.json`). First launch copies those from `~/.grok/`
when groky does not have them yet, and shares sessions / xAI login / memory /
skills / plugins with official `grok` via `~/.grok/`. `GROK_HOME` isolates
everything; `GROKY_SKIP_HOME_MIGRATE=1` skips the copy/link step.

## One-click

```sh
curl -fsSL https://raw.githubusercontent.com/yuWorm/groky/main/scripts/install-groky.sh | bash
groky --version
```

Windows x86_64 PowerShell (binaries available from v0.1.23):

```powershell
irm https://raw.githubusercontent.com/yuWorm/groky/main/scripts/install-groky.ps1 | iex
groky --version
```

Pin a version (downloads `github.com/.../releases/download/...` and does
**not** call `api.github.com` — useful behind a shared VPN IP):

```sh
curl -fsSL https://raw.githubusercontent.com/yuWorm/groky/main/scripts/install-groky.sh | bash -s 0.1.25
groky update --version 0.1.25
```

PowerShell:

```powershell
$env:GROKY_VERSION="0.1.25"
irm https://raw.githubusercontent.com/yuWorm/groky/main/scripts/install-groky.ps1 | iex
Remove-Item Env:GROKY_VERSION
groky --version
```

Unpinned updates and installers still query `/releases/latest`.
For direct GitHub access, `GROKY_GITHUB_TOKEN` (or `GITHUB_TOKEN`) raises
the API quota. Tokens are never sent to an update mirror.

## Update mirrors and download progress

`groky update` uses `https://gh-proxy.com` by default for latest-release
metadata, binaries, and checksum files. Automatic groky updates use the same
default. Override the mirror for one invocation:

```sh
groky update
groky update --mirrors https://your-mirror.example
groky update --version 0.1.26 --mirrors https://your-mirror.example
groky update --check --mirrors https://your-mirror.example
groky update --mirrors direct
```

`--mirros` is an alias for `--mirrors`. The URL is a single HTTP(S) base URL;
the updater appends `/https://github.com/...` or `/https://api.github.com/...`.
The mirror must support these URL-prefix requests (it is not an HTTP proxy
setting). Use a trusted mirror: it supplies the executable and its checksum.
`direct` bypasses the mirror and permits GitHub token authentication.
The override is not saved and does not silently fall back to another source.

Interactive downloads show percentage, downloaded/total bytes, speed and ETA.
If the server omits the size, a spinner shows downloaded bytes and speed.
Non-interactive output has no animated bar. Downloads stream to disk and have
30-second connection/read timeouts rather than a 120-second total deadline.
Interrupted downloads remove the partial binary and leave the installed
version untouched.

These options apply to `groky update`, not the Bash or PowerShell first-install
scripts above. Those scripts still access GitHub directly; re-running them
also upgrades groky.

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
