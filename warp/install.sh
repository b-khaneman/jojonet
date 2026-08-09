#!/usr/bin/env bash
#
# AI-WARP — one-command automatic installer (zero prompts)
#
#   curl -fsSL https://raw.githubusercontent.com/b-khaneman/jojonet/main/warp/install.sh | sudo bash
#
# Mirror:
#   curl -fsSL https://cdn.jsdelivr.net/gh/b-khaneman/jojonet@main/warp/install.sh | sudo bash
#
# Local:
#   sudo bash install.sh
#
set -Eeo pipefail

readonly INSTALLER_VERSION="1.1.0"
readonly GITHUB_USER="${AI_WARP_GITHUB_USER:-b-khaneman}"
readonly GITHUB_REPO="${AI_WARP_GITHUB_REPO:-jojonet}"
readonly GITHUB_BRANCH="${AI_WARP_GITHUB_BRANCH:-main}"
readonly GITHUB_PATH="warp"

export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE="${NEEDRESTART_MODE:-a}"
export APT_LISTCHANGES_FRONTEND=none

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
info() { echo -e "${CYAN}[*]${NC} $*"; }
fail() { echo -e "${RED}[!]${NC} $*" >&2; exit 1; }

(( EUID == 0 )) || fail "با root اجرا کن: curl … | sudo bash"

ensure_curl() {
  command -v curl >/dev/null 2>&1 && return 0
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq || true
    apt-get install -y -qq curl ca-certificates || apt-get install -y curl ca-certificates
  elif command -v dnf >/dev/null 2>&1; then
    dnf -y install curl ca-certificates
  elif command -v yum >/dev/null 2>&1; then
    yum -y install curl ca-certificates
  else
    fail "curl لازم است."
  fi
  command -v curl >/dev/null 2>&1 || fail "نصب curl ناموفق بود."
}

resolve_local_root() {
  local src="${BASH_SOURCE[0]:-}"
  # Piped from curl → /dev/fd/N — treat as remote
  [[ -n "$src" && -f "$src" && "$src" != /dev/fd/* && "$src" != /proc/self/fd/* ]] || {
    echo ""
    return 0
  }
  cd "$(dirname "$src")" && pwd
}

mirror_urls() {
  local file="$1" u="$GITHUB_USER" r="$GITHUB_REPO" b="$GITHUB_BRANCH" p="$GITHUB_PATH"
  printf '%s\n' \
    "https://cdn.jsdelivr.net/gh/${u}/${r}@${b}/${p}/${file}" \
    "https://raw.githubusercontent.com/${u}/${r}/${b}/${p}/${file}" \
    "https://raw.gitmirror.com/${u}/${r}/${b}/${p}/${file}" \
    "https://ghproxy.net/https://raw.githubusercontent.com/${u}/${r}/${b}/${p}/${file}" \
    "https://mirror.ghproxy.com/https://raw.githubusercontent.com/${u}/${r}/${b}/${p}/${file}"
}

download_file() {
  local url="$1" dest="$2" i
  for i in 1 2 3; do
    if curl -fsSL --connect-timeout 12 --max-time 90 --retry 2 --retry-delay 1 \
        "$url" -o "$dest" && [[ -s "$dest" ]]; then
      return 0
    fi
    sleep 1
  done
  return 1
}

fetch_file() {
  local rel="$1" dest="$2" url=""
  mkdir -p "$(dirname "$dest")"
  while IFS= read -r url; do
    [[ -z "$url" ]] && continue
    if download_file "$url" "$dest"; then
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
    [[ -f "${root}/${f}" ]] || fail "Missing: ${root}/${f}"
    mkdir -p "$(dirname "${staging}/${f}")"
    cp -f "${root}/${f}" "${staging}/${f}"
  done
}

stage_from_remote() {
  local staging="$1" f failed=0
  info "دانلود پکیج AI-WARP…"
  for f in "${PACKAGE_FILES[@]}"; do
    if fetch_file "$f" "${staging}/${f}"; then
      log "OK  $f"
    else
      warn "FAIL $f"
      failed=1
    fi
  done
  (( failed == 0 )) || fail "دانلود پکیج ناقص بود. شبکه/فیلتر را چک کن یا از کلون محلی نصب کن."
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
  install -m755 "${staging}/bin/ai-warp" /usr/local/bin/ai-warp
  chmod 755 /usr/local/bin/ai-warp "${share}/scripts/routes.sh"

  # Always refresh domain list on reinstall (user edits stay if AI_WARP_KEEP_DOMAINS=1)
  if [[ "${AI_WARP_KEEP_DOMAINS:-0}" == "1" && -f /etc/ai-warp/ai-domains.txt ]]; then
    log "Keeping existing /etc/ai-warp/ai-domains.txt"
  else
    install -m644 "${staging}/conf/ai-domains.txt" /etc/ai-warp/ai-domains.txt
  fi

  log "ai-warp ${ver} نصب شد → /usr/local/bin/ai-warp"
}

usage() {
  cat <<EOF
AI-WARP installer v${INSTALLER_VERSION} — fully automatic by default

  curl -fsSL …/warp/install.sh | sudo bash          # auto unlock (recommended)
  sudo bash install.sh                              # same (auto)
  sudo bash install.sh --menu                       # interactive menu only
  sudo bash install.sh --files-only                 # copy files, no tunnel
  sudo bash install.sh --mode google|ai|full        # choose mode (default: ai)

Safe with JojoNet tunnels + Cloudflare CDN (only AI egress uses WARP).
EOF
}

main() {
  local action="auto" mode="ai" local_root staging

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help) usage; exit 0 ;;
      -v|--version) echo "ai-warp-installer ${INSTALLER_VERSION}"; exit 0 ;;
      --files-only) action="files"; shift ;;
      --menu) action="menu"; shift ;;
      --install) action="auto"; shift ;;
      --mode)
        mode="${2:-ai}"
        shift 2
        ;;
      --mode=*)
        mode="${1#--mode=}"
        shift
        ;;
      ai|google|full)
        mode="$1"
        shift
        ;;
      *) fail "Unknown arg: $1 (see --help)" ;;
    esac
  done

  case "$mode" in
    ai|google|full) ;;
    *) fail "Invalid mode: $mode" ;;
  esac

  echo
  echo "╔══════════════════════════════════════════════════════╗"
  echo "║   AI-WARP v${INSTALLER_VERSION} — نصب خودکار (بدون پرسش)          ║"
  echo "║   Gemini / Flow / ChatGPT / Claude / …               ║"
  echo "╚══════════════════════════════════════════════════════╝"
  echo
  info "حالت: ${mode}  |  CDN کلودفلر و تانل پنل دست نمی‌خورند"
  echo

  ensure_curl

  staging="$(mktemp -d /tmp/ai-warp-stage.XXXXXX)"
  trap 'rm -rf "$staging"' EXIT

  local_root="$(resolve_local_root)"
  if [[ -n "$local_root" && -f "${local_root}/bin/ai-warp" && -f "${local_root}/lib/common.sh" ]]; then
    log "پکیج محلی: ${local_root}"
    stage_from_local "$local_root" "$staging"
  else
    stage_from_remote "$staging"
  fi

  install_tree "$staging"

  case "$action" in
    files)
      log "فایل‌ها نصب شد. برای فعال‌سازی: sudo ai-warp install"
      ;;
    menu)
      ai-warp
      ;;
    auto)
      # Fully non-interactive unlock
      export AI_WARP_AUTO=1
      ai-warp install "$mode"
      ;;
  esac
}

main "$@"
