# Merging xAI grok-build

This tree is a **product fork**. Vendor/Codex code lives beside grok:

- New files under `compat/`, `dispatch/vendor.rs`, `/provider-login`
- Marked `GROK_COMPAT_HOOK` sites in grok files
- Root `README.md` / `README.zh.md` are product docs — keep ours on merge
- `upstream` = `https://github.com/xai-org/grok-build.git` (fetch only)
- `origin` = https://github.com/yuWorm/groky.git (push here)

Do **not** rebase onto every `Synced from monorepo` snapshot. Merge when you
want a grok fix or feature (about every 1–2 weeks is enough).

## One-time git identity

```bash
git remote rename origin upstream   # if origin still points at xai-org
git remote add origin git@github.com:yuWorm/groky.git
git fetch upstream
git config rerere.enabled true
```

Never `git push upstream`.

## Merge a grok snapshot

```bash
./scripts/merge-upstream.sh              # fetch + diffstat of hook files
./scripts/merge-upstream.sh --merge      # merge --no-ff upstream/main
```

Then:

1. Resolve conflicts **only** at `GROK_COMPAT_HOOK` (keep both: their code + the hook call).
   Vendor catalog overlay lives in `agent/remote_config/manager/mod.rs`
   (upstream moved it off `agent/models.rs`).
2. Exhaustive `Action` / `Effect` / `TaskResult` matches: keep **both** sides' variants.
3. Do not take upstream if it reintroduces xAI `/login` on a vendor 401.
4. Smoke:
   - xAI login still works
   - `/provider-login openai-codex`
   - a one-line `hi`
   - one tool turn
   - vendor 401 must say `/provider-login`, never `/login`

```bash
git log -1 --format='%H %s' upstream/main
git push origin HEAD
```

Optional inspect: `/merge-upstream` (or `/workflow merge-upstream`) writes a
hook-file checklist. It does **not** merge.

## What to touch vs what not to

| Keep in `compat/` / new files | Do not fork in grok files |
| --- | --- |
| OAuth, vendor-auth.json, catalog | Compact default (stay 85) |
| Codex allowlist / SSE skip | Deleting upstream scripts |
| Provider login TUI | Rewriting `/login` / AuthManager |
| `xai-dirs` `~/.groky` home + `groky_layout.rs` | Project-local `.grok/` dirs |

Product `$GROK_HOME` is `~/.groky` (GROK_COMPAT_HOOK in `xai-dirs`). Official
`grok` stays on `~/.grok`. Layout migration copies config / vendor files and
symlinks sessions (see `xai-dirs/src/groky_layout.rs`). Do not take upstream
if it reverts the default dir name to `.grok`.

Pi and Oh My Pi stay in gitignored `./sources/` as read-only references.
