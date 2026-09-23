#!/usr/bin/env bash
# Fetch xAI grok-build and show (or merge) the GROK_COMPAT hook surface.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

REMOTE="${UPSTREAM_REMOTE:-upstream}"
REF="${UPSTREAM_REF:-main}"
MERGE=0
if [[ "${1:-}" == "--merge" ]]; then
  MERGE=1
fi

if ! git remote get-url "$REMOTE" >/dev/null 2>&1; then
  echo "missing git remote '$REMOTE'." >&2
  echo "  git remote add $REMOTE https://github.com/xai-org/grok-build.git" >&2
  echo "  git fetch $REMOTE" >&2
  exit 1
fi

git config rerere.enabled true
git fetch "$REMOTE" "$REF"

LOCAL="$(git rev-parse HEAD)"
THEIRS="$(git rev-parse "$REMOTE/$REF")"
echo "HEAD      $LOCAL"
echo "$REMOTE/$REF  $THEIRS"

if [[ "$LOCAL" == "$THEIRS" ]]; then
  echo "already up to date with $REMOTE/$REF"
  exit 0
fi

echo
echo "commits on $REMOTE/$REF not in HEAD:"
git log --oneline --no-decorate "HEAD..$REMOTE/$REF" | head -30
echo

HOOK_FILES=(
  crates/codegen/xai-dirs/src/lib.rs
  crates/codegen/xai-grok-pager-render/src/util.rs
  crates/codegen/xai-grok-sampler/src/client.rs
  crates/codegen/xai-grok-sampler/src/compat.rs
  crates/codegen/xai-grok-sampler/src/stream/responses.rs
  crates/codegen/xai-grok-sampler/src/actor/request_task.rs
  crates/codegen/xai-grok-sampler/src/lib.rs
  crates/codegen/xai-grok-shell/src/agent/config.rs
  crates/codegen/xai-grok-shell/src/agent/remote_config/manager/mod.rs
  crates/codegen/xai-grok-shell/src/agent/mvp_agent/acp_agent.rs
  crates/codegen/xai-grok-shell/src/session/acp_session_impl/sampler_turn.rs
  crates/codegen/xai-grok-shell/src/extensions/notification.rs
  crates/codegen/xai-grok-shell/src/lib.rs
  crates/codegen/xai-grok-pager/src/app/actions.rs
  crates/codegen/xai-grok-pager/src/app/dispatch/mod.rs
  crates/codegen/xai-grok-pager/src/app/dispatch/modes.rs
  crates/codegen/xai-grok-pager/src/app/dispatch/router.rs
  crates/codegen/xai-grok-pager/src/app/dispatch/task_result.rs
  crates/codegen/xai-grok-pager/src/app/effects/mod.rs
  crates/codegen/xai-grok-pager/src/slash/commands/mod.rs
  crates/codegen/xai-grok-pager/src/slash/commands/release_notes.rs
  crates/codegen/xai-grok-pager/src/views/mod.rs
  crates/codegen/xai-grok-pager/src/app/agent_view/mod.rs
  crates/codegen/xai-grok-pager/src/app/agent_view/modals.rs
  crates/codegen/xai-grok-pager/src/app/agent_view/input.rs
  crates/codegen/xai-grok-pager/src/app/agent_view/render.rs
)

echo "hook-file diffstat (these are the merge hot spots):"
git diff --stat "HEAD...$REMOTE/$REF" -- "${HOOK_FILES[@]}"
echo
echo "compat/ and other new files are ours; they will not conflict."
echo "playbook: crates/codegen/xai-grok-shell/src/compat/UPSTREAM.md"

if [[ "$MERGE" -eq 1 ]]; then
  git merge --no-ff "$REMOTE/$REF" -m "sync(grok): merge $THEIRS"
  echo "resolve GROK_COMPAT_HOOK conflicts, then smoke-test (see UPSTREAM.md)."
else
  echo "dry run. re-run with --merge to merge --no-ff $REMOTE/$REF"
fi
