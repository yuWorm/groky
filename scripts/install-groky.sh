#!/usr/bin/env bash
# groky installer — product CLI for yuWorm/groky
#
# Does not call x.ai/cli (that installs official `grok`). Downloads a GitHub
# Release asset named like grok's gh-release pattern:
#   groky-{version}-{macos|linux|windows}-{x86_64|aarch64}[.exe]
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/yuWorm/groky/main/scripts/install-groky.sh | bash
#   curl -fsSL ... | bash -s 0.1.15
#   GROKY_VERSION=0.1.15 GROKY_BIN_DIR=$HOME/.local/bin bash scripts/install-groky.sh
#
# A pinned version downloads github.com/releases/download directly (no
# api.github.com). Unpinned still hits /releases/latest.
#
# Env: GROKY_REPO (default yuWorm/groky), GROKY_VERSION, GROKY_BIN_DIR,
#      GROKY_GITHUB_TOKEN (optional; raises the latest-release API rate limit)

set -euo pipefail

REPO="${GROKY_REPO:-yuWorm/groky}"
BIN_NAME="groky"
BIN_DIR="${GROKY_BIN_DIR:-$HOME/.groky/bin}"
TARGET="${1:-${GROKY_VERSION:-}}"

if [[ -n "$TARGET" && ! "$TARGET" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9._]+)?$ ]]; then
  echo "Invalid version: $TARGET (expected X.Y.Z)" >&2
  exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required" >&2
  exit 1
fi

# Optional. Empty array + `set -u` is "unbound variable" on bash 4.4+
# (`curl | bash` on Linux). Token is not required for public releases.
AUTH_HEADER=()
if [[ -n "${GROKY_GITHUB_TOKEN:-${GITHUB_TOKEN:-}}" ]]; then
  AUTH_HEADER=(-H "Authorization: Bearer ${GROKY_GITHUB_TOKEN:-$GITHUB_TOKEN}")
fi

api() {
  curl -fsSL \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    ${AUTH_HEADER[@]+"${AUTH_HEADER[@]}"} \
    "$@"
}

case "$(uname -s)" in
  Darwin) os="macos" ;;
  Linux) os="linux" ;;
  MINGW*|MSYS*|CYGWIN*) os="windows" ;;
  *) echo "Unsupported OS: $(uname -s)" >&2; exit 1 ;;
esac

case "$(uname -m)" in
  x86_64|amd64|AMD64) arch="x86_64" ;;
  arm64|aarch64|ARM64) arch="aarch64" ;;
  *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

if [[ "$os" == "macos" && "$arch" == "x86_64" ]]; then
  sysctl_bin="$(command -v sysctl || echo /usr/sbin/sysctl)"
  if [[ "$("$sysctl_bin" -n hw.optional.arm64 2>/dev/null || true)" == "1" ]]; then
    echo "Apple Silicon detected (Rosetta shell); installing native arm64." >&2
    arch="aarch64"
  fi
fi

if [[ -z "$TARGET" ]]; then
  echo "Fetching latest groky release from ${REPO}..." >&2
  json="$(api "https://api.github.com/repos/${REPO}/releases/latest")"
  tag="$(printf '%s' "$json" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)"
else
  tag="$TARGET"
  [[ "$tag" == v* ]] || tag="v$tag"
  echo "Fetching groky ${tag} from ${REPO} (direct download, no GitHub API)..." >&2
fi

if [[ -z "$tag" ]]; then
  echo "Error: could not resolve a release tag for ${REPO}" >&2
  exit 1
fi

version="${tag#v}"
asset="${BIN_NAME}-${version}-${os}-${arch}"
[[ "$os" == "windows" ]] && asset="${asset}.exe"

# Deterministic asset URL. Pinning a version never calls api.github.com.
url="https://github.com/${REPO}/releases/download/${tag}/${asset}"

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
echo "  Downloading ${asset}..." >&2
if ! curl -fsSL -o "$tmp" "$url"; then
  echo "Error: download failed (${url})" >&2
  echo "This OS/arch may not be in the release yet." >&2
  exit 1
fi

if [[ "$os" != "windows" ]]; then
  chmod +x "$tmp"
  if ! "$tmp" --version </dev/null >/dev/null 2>&1; then
    echo "Error: downloaded groky failed to run; keeping any existing install." >&2
    exit 1
  fi
fi

mkdir -p "$BIN_DIR"
dest="$BIN_DIR/${BIN_NAME}"
[[ "$os" == "windows" ]] && dest="${dest}.exe"
# Replace a running binary by moving it aside first.
if [[ -e "$dest" ]]; then
  mv -f "$dest" "${dest}.old" 2>/dev/null || true
fi
mv -f "$tmp" "$dest"
chmod +x "$dest" 2>/dev/null || true
rm -f "${dest}.old" 2>/dev/null || true
trap - EXIT

echo "  Installed ${dest}" >&2

path_has_dir() {
  case ":$PATH:" in *":$1:"*) return 0 ;; *) return 1 ;; esac
}

linked=""
if [[ "$os" != "windows" ]] && ! path_has_dir "$BIN_DIR"; then
  for candidate in "$HOME/.local/bin" "/usr/local/bin"; do
    if path_has_dir "$candidate" && [[ -d "$candidate" && -w "$candidate" ]]; then
      ln -sf "$dest" "$candidate/${BIN_NAME}"
      linked="$candidate/${BIN_NAME}"
      echo "  Symlinked ${linked} -> ${dest}" >&2
      break
    fi
  done
fi

user_shell="$(basename "${SHELL:-}")"
config_file=""
case "$user_shell" in
  bash) config_file="$HOME/.bashrc" ;;
  zsh) config_file="$HOME/.zshrc" ;;
  fish) config_file="$HOME/.config/fish/config.fish" ;;
esac

if [[ -n "$config_file" && "$os" != "windows" ]]; then
  mkdir -p "$(dirname "$config_file")"
  if [[ "$user_shell" == "fish" ]]; then
    new_block="# >>> groky installer >>>
fish_add_path ${BIN_DIR}
# <<< groky installer <<<"
  else
    new_block="# >>> groky installer >>>
export PATH=\"${BIN_DIR}:\$PATH\"
# <<< groky installer <<<"
  fi
  if [[ -f "$config_file" ]] && grep -qs "groky installer" "$config_file"; then
    tmp_cfg="${config_file}.tmp.$$"
    awk '/# >>> groky installer >>>/{skip=1; next} /# <<< groky installer <<</{skip=0; next} !skip{print}' \
      "$config_file" >"$tmp_cfg" && mv "$tmp_cfg" "$config_file"
  fi
  printf '\n%s\n' "$new_block" >>"$config_file"
  echo "  PATH updated in ${config_file}" >&2
fi

echo "" >&2
echo "groky ${version} installed." >&2
if path_has_dir "$BIN_DIR" || [[ -n "$linked" ]]; then
  echo "Run:  groky --version" >&2
else
  echo "Restart the shell, or:  export PATH=\"${BIN_DIR}:\$PATH\"" >&2
  echo "Then:  groky --version" >&2
fi
echo "This does not replace official grok (~/.grok/bin/grok)." >&2
