#!/usr/bin/env bash
#
# JOJONET Fixed Installer v1.1.0
# https://github.com/b-khaneman/jojonet
#
# One-liner:
#   curl -fsSL https://raw.githubusercontent.com/b-khaneman/jojonet/main/install.sh | sudo bash
#
# Local:
#   sudo bash install.sh
#

set -Eeo pipefail

readonly INSTALLER_VERSION="1.1.0"
readonly JOJONET_SUPPORT="@B_KHANEMAN"
readonly JOJONET_BIN="/usr/local/bin/jojonet"
readonly SHARE_DIR="/usr/local/share/jojonet"

GITHUB_USER="${JOJONET_GITHUB_USER:-b-khaneman}"
GITHUB_REPO="${JOJONET_GITHUB_REPO:-jojonet}"
GITHUB_BRANCH="${JOJONET_GITHUB_BRANCH:-main}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
fail() { echo -e "${RED}[!]${NC} $*" >&2; exit 1; }

resolve_dir() {
    local src="${BASH_SOURCE[0]:-}"
    if [[ -n "$src" && -f "$src" ]]; then
        cd "$(dirname "$src")" && pwd
    else
        echo ""
    fi
}

usage() {
    cat <<EOF
JOJONET Fixed Installer v${INSTALLER_VERSION}

Install (one-liner):
  curl -fsSL https://raw.githubusercontent.com/${GITHUB_USER}/${GITHUB_REPO}/${GITHUB_BRANCH}/install.sh | sudo bash

Local package:
  sudo bash install.sh
  sudo bash install.sh --verify

Remote explicit:
  sudo bash install.sh --remote
  sudo bash install.sh --remote USER

Uninstall:
  sudo jojonet-uninstall
  # or: sudo bash uninstall.sh
EOF
}

[[ "${1:-}" == "-h" || "${1:-}" == "--help" ]] && usage && exit 0
[[ "${1:-}" == "--version" || "${1:-}" == "-v" ]] && echo "jojonet-installer ${INSTALLER_VERSION}" && exit 0
(( EUID == 0 )) || fail "Run as root: sudo bash install.sh"

check_deps() {
    local need_download="${1:-0}"
    local deps=(ip nft awk grep systemctl sysctl ping flock mktemp)
    local missing=() cmd hint=""
    for cmd in "${deps[@]}"; do
        command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
    done
    command -v sha256sum >/dev/null 2>&1 || missing+=("sha256sum")
    if (( need_download )); then
        command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 || missing+=("curl|wget")
    fi
    if (( ${#missing[@]} > 0 )); then
        warn "Missing: ${missing[*]}"
        command -v apt-get >/dev/null 2>&1 && \
            hint="apt install -y iproute2 nftables procps iputils-ping util-linux curl coreutils"
        [[ -n "$hint" ]] && warn "Try: $hint"
        fail "Install dependencies first."
    fi
}

download_file() {
    local url="$1" dest="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$url" -o "$dest" || return 1
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$dest" "$url" || return 1
    else
        return 1
    fi
}

install_jojonet_file() {
    local src="$1"
    [[ -f "$src" ]] || fail "Source not found: $src"
    [[ -s "$src" ]] || fail "Source empty: $src"
    head -1 "$src" | grep -q '^#!/' || fail "Invalid script (missing shebang): $src"

    install -d -m755 /usr/local/bin
    install -d -m755 "$SHARE_DIR"
    install -d -m700 /etc/jojonet/instances
    install -d -m700 /etc/jojonet/keys
    install -d -m700 /etc/jojonet/paqet
    install -m755 "$src" "$JOJONET_BIN"
    log "Installed: $JOJONET_BIN"
}

install_extras_from_dir() {
    local dir="$1"
    if [[ -f "$dir/checksums.sha256" ]]; then
        install -m644 "$dir/checksums.sha256" "$SHARE_DIR/checksums.sha256"
        install -m644 "$dir/checksums.sha256" /etc/jojonet/checksums.sha256
        log "Checksums installed"
    fi
    if [[ -f "$dir/uninstall.sh" ]]; then
        install -m755 "$dir/uninstall.sh" /usr/local/bin/jojonet-uninstall
        log "Uninstaller: /usr/local/bin/jojonet-uninstall"
    fi
}

install_extras_from_github() {
    local base="https://raw.githubusercontent.com/${GITHUB_USER}/${GITHUB_REPO}/${GITHUB_BRANCH}"
    local tmp
    tmp=$(mktemp /tmp/jojonet-extra.XXXXXX) || return 0
    if download_file "$base/checksums.sha256" "$tmp" 2>/dev/null; then
        install -m644 "$tmp" "$SHARE_DIR/checksums.sha256"
        install -m644 "$tmp" /etc/jojonet/checksums.sha256
        log "Checksums downloaded"
    fi
    if download_file "$base/uninstall.sh" "$tmp" 2>/dev/null; then
        install -m755 "$tmp" /usr/local/bin/jojonet-uninstall
        log "Uninstaller downloaded"
    fi
    rm -f "$tmp"
}

print_done() {
    local ver
    ver=$(grep -m1 'JOJONET_VERSION=' "$JOJONET_BIN" 2>/dev/null | cut -d'"' -f2 || true)
    echo ""
    log "JOJONET installed successfully${ver:+ (v${ver})}!"
    echo -e "${YELLOW}Start:${NC}     sudo jojonet"
    echo -e "${YELLOW}Help:${NC}      sudo jojonet --help"
    echo -e "${YELLOW}Version:${NC}   sudo jojonet --version"
    echo -e "${YELLOW}Uninstall:${NC} sudo jojonet-uninstall"
    echo -e "${YELLOW}Support:${NC}   ${JOJONET_SUPPORT}"
    echo ""
    echo "Quick start:"
    echo "  1) FOREIGN: sudo jojonet"
    echo "  2) IRAN:    sudo jojonet <FOREIGN_IP>"
    echo "  Optional:  export JOJONET_ROLE=iran|kharej"
    echo ""
    echo "Repo: https://github.com/${GITHUB_USER}/${GITHUB_REPO}"
}

# ---------- main ----------
PKG_DIR=$(resolve_dir)
mode=""
gh_user=""

case "${1:-}" in
    --remote)
        mode="remote"
        gh_user="${2:-}"
        ;;
    --verify)
        mode="verify"
        ;;
    "")
        if [[ -n "$PKG_DIR" && -f "$PKG_DIR/jojonet" ]]; then
            mode="local"
        else
            mode="remote"
        fi
        ;;
    *)
        fail "Unknown option: $1 (try --help)"
        ;;
esac

[[ -n "$gh_user" ]] && GITHUB_USER="$gh_user"

echo -e "${GREEN}=== JOJONET Installer v${INSTALLER_VERSION} ===${NC}"

if [[ "$mode" == "verify" ]]; then
    [[ -n "$PKG_DIR" && -f "$PKG_DIR/jojonet" ]] || fail "Local jojonet not found for --verify"
    check_deps 0
    SRC="$PKG_DIR/jojonet"
    head -1 "$SRC" | grep -q '^#!/' || fail "Invalid shebang"
    grep -q 'JOJONET_VERSION=' "$SRC" || warn "No version string"
    if [[ -f "$PKG_DIR/checksums.sha256" ]]; then
        (cd "$PKG_DIR" && sha256sum -c checksums.sha256 --ignore-missing) || fail "Checksum failed"
        log "Package checksums OK"
    else
        warn "No checksums.sha256"
    fi
    exit 0
fi

if [[ "$mode" == "local" ]]; then
    check_deps 0
    install_jojonet_file "$PKG_DIR/jojonet"
    install_extras_from_dir "$PKG_DIR"
else
    check_deps 1
    remote_url="https://raw.githubusercontent.com/${GITHUB_USER}/${GITHUB_REPO}/${GITHUB_BRANCH}/jojonet"
    warn "Downloading: $remote_url"
    tmp=$(mktemp /tmp/jojonet.XXXXXX) || fail "mktemp failed"
    download_file "$remote_url" "$tmp" || fail "Download failed: $remote_url"
    install_jojonet_file "$tmp"
    rm -f "$tmp"
    install_extras_from_github
fi

sha256sum "$JOJONET_BIN" 2>/dev/null | awk '{print $1"  jojonet"}' >> /etc/jojonet/checksums.sha256 2>/dev/null || true
print_done
