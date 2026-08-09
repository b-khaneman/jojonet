#!/usr/bin/env bash
#
# AI-WARP installer — one-liner friendly
#
# Local:
#   sudo bash install.sh
#   sudo bash install.sh --install
#
# Remote (Kharej / Ubuntu):
#   curl -fsSL https://raw.githubusercontent.com/b-khaneman/jojonet/main/warp/install.sh | sudo bash
# Mirror:
#   curl -fsSL https://cdn.jsdelivr.net/gh/b-khaneman/jojonet@main/warp/install.sh | sudo bash
#
set -Eeo pipefail

readonly INSTALLER_VERSION="1.0.0"
readonly GITHUB_USER="${AI_WARP_GITHUB_USER:-b-khaneman}"
readonly GITHUB_REPO="${AI_WARP_GITHUB_REPO:-jojonet}"
readonly GITHUB_BRANCH="${AI_WARP_GITHUB_BRANCH:-main}"
readonly GITHUB_PATH="warp"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
fail() { echo -e "${RED}[!]${NC} $*" >&2; exit 1; }

(( EUID == 0 )) || fail "Run as root: sudo bash install.sh"

resolve_local_root() {
  local src="${BASH_SOURCE[0]:-}"
  if [[ -n "$src" && -f "$src" ]]; then
    cd "$(dirname "$src")" && pwd
  else
    echo ""
  fi
}

mirror_urls() {
  local file="$1" u="$GITHUB_USER" r="$GITHUB_REPO" b="$GITHUB_BRANCH" p="$GITHUB_PATH"
  printf '%s\n' \
    "https://raw.githubusercontent.com/${u}/${r}/${b}/${p}/${file}" \
    "https://cdn.jsdelivr.net/gh/${u}/${r}@${b}/${p}/${file}" \
    "https://raw.gitmirror.com/${u}/${r}/${b}/${p}/${file}" \
    "https://ghproxy.net/https://raw.githubusercontent.com/${u}/${r}/${b}/${p}/${file}"
}

download_file() {
  local url="$1" dest="$2"
  curl -fsSL --connect-timeout 10 --max-time 60 "$url" -o "$dest"
  [[ -s "$dest" ]]
}

fetch_file() {
  local rel="$1" dest="$2" url=""
  mkdir -p "$(dirname "$dest")"
  while IFS= read -r url; do
    [[ -z "$url" ]] && continue
    warn "Fetching: $url"
    if download_file "$url" "$dest"; then
      log "OK: $rel"
      return 0
    fi
  done < <(mirror_urls "$rel")
  return 1
}

PACKAGE_FILES=(
  VERSION
  LICENSE
  conf/ai-domains.txt
  lib/common.sh
  lib/deps.sh
  lib/wgcf.sh
  lib/routes-build.sh
  lib/sticky.sh
  lib/health.sh
  scripts/routes.sh
  bin/ai-warp
  systemd/ai-warp.service
  systemd/ai-warp-watchdog.service
  systemd/ai-warp-watchdog.timer
  systemd/ai-warp-refresh.service
  systemd/ai-warp-refresh.timer
)

stage_from_local() {
  local root="$1" staging="$2" f
  for f in "${PACKAGE_FILES[@]}"; do
    [[ -f "${root}/${f}" ]] || fail "Missing local file: ${root}/${f}"
    mkdir -p "$(dirname "${staging}/${f}")"
    cp -f "${root}/${f}" "${staging}/${f}"
  done
}

stage_from_remote() {
  local staging="$1" f
  for f in "${PACKAGE_FILES[@]}"; do
    fetch_file "$f" "${staging}/${f}" || fail "Could not download: $f"
  done
}

install_tree() {
  local staging="$1"
  local share="/usr/local/share/ai-warp"
  local ver

  ver="$(tr -d '[:space:]' <"${staging}/VERSION" 2>/dev/null || echo "$INSTALLER_VERSION")"

  install -d -m755 /usr/local/bin
  install -d -m755 "$share"/{lib,scripts,conf,systemd}
  install -d -m700 /etc/ai-warp

  install -m644 "${staging}/VERSION" "${share}/VERSION"
  install -m644 "${staging}/LICENSE" "${share}/LICENSE"
  install -m644 "${staging}/conf/ai-domains.txt" "${share}/conf/ai-domains.txt"

  install -m644 "${staging}/lib/"*.sh "${share}/lib/"
  install -m755 "${staging}/scripts/routes.sh" "${share}/scripts/routes.sh"
  install -m644 "${staging}/systemd/"* "${share}/systemd/"

  # Pin version into common.sh consumer via wrapper env
  install -m755 "${staging}/bin/ai-warp" /usr/local/bin/ai-warp
  # Ensure shebang scripts executable
  chmod 755 /usr/local/bin/ai-warp "${share}/scripts/routes.sh"

  # Admin-editable domains live in /etc (CLI prefers this path)
  if [[ ! -f /etc/ai-warp/ai-domains.txt ]]; then
    install -m644 "${staging}/conf/ai-domains.txt" /etc/ai-warp/ai-domains.txt
  fi

  log "Installed ai-warp ${ver} → /usr/local/bin/ai-warp"
  log "Share tree → ${share}"
}

usage() {
  cat <<EOF
AI-WARP installer v${INSTALLER_VERSION}

  sudo bash install.sh              # install package + interactive menu
  sudo bash install.sh --install    # install package + auto setup (mode=ai)
  sudo bash install.sh --install google
  sudo bash install.sh --install full
  sudo bash install.sh --files-only # only copy files (no tunnel yet)
  sudo bash install.sh --help
EOF
}

main() {
  local action="menu" mode="ai" local_root staging

  case "${1:-}" in
    -h|--help) usage; exit 0 ;;
    --files-only) action="files" ;;
    --install)
      action="install"
      mode="${2:-ai}"
      ;;
    --version|-v) echo "ai-warp-installer ${INSTALLER_VERSION}"; exit 0 ;;
    "") action="menu" ;;
    *) usage; exit 1 ;;
  esac

  command -v curl >/dev/null 2>&1 || fail "curl is required"

  staging="$(mktemp -d /tmp/ai-warp-stage.XXXXXX)"
  trap 'rm -rf "$staging"' EXIT

  local_root="$(resolve_local_root)"
  if [[ -n "$local_root" && -f "${local_root}/bin/ai-warp" && -f "${local_root}/lib/common.sh" ]]; then
    log "Using local package: ${local_root}"
    stage_from_local "$local_root" "$staging"
  else
    log "Remote bootstrap — downloading AI-WARP package…"
    stage_from_remote "$staging"
  fi

  install_tree "$staging"

  case "$action" in
    files)
      log "Files installed. Run: sudo ai-warp install"
      ;;
    install)
      ai-warp install "$mode"
      ;;
    menu)
      ai-warp
      ;;
  esac
}

main "$@"
