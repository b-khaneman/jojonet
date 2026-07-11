#!/usr/bin/env bash
#
# JOJONET Fixed Installer v1.1.0
# Prefer: sudo bash install.sh   (from extracted package)
#

set -Eeo pipefail

readonly INSTALLER_VERSION="1.1.0"
readonly JOJONET_SUPPORT="@B_KHANEMAN"
readonly JOJONET_BIN="/usr/local/bin/jojonet"
readonly SHARE_DIR="/usr/local/share/jojonet"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
fail() { echo -e "${RED}[!]${NC} $*" >&2; exit 1; }

resolve_dir() {
    local src="${BASH_SOURCE[0]:-}"
    if [[ -n "$src" && -f "$src" ]]; then
        cd "$(dirname "$src")" && pwd
    else
        pwd
    fi
}

usage() {
    cat <<EOF
JOJONET Fixed Installer v${INSTALLER_VERSION}

Usage:
  sudo bash install.sh              Install from this package directory
  sudo bash install.sh --verify     Verify package checksums only
  sudo bash uninstall.sh            Remove JojoNet (separate script)

Security:
  This installer prefers a local package over curl|bash.
  Bundled checksums.sha256 is installed for third-party binary verification.
  Set JOJONET_ALLOW_UNSIGNED=1 only if you accept unsigned downloads.
EOF
}

[[ "${1:-}" == "-h" || "${1:-}" == "--help" ]] && usage && exit 0
(( EUID == 0 )) || fail "Run as root: sudo bash install.sh"

PKG_DIR=$(resolve_dir)
SRC="$PKG_DIR/jojonet"
SUMS="$PKG_DIR/checksums.sha256"

check_deps() {
    local deps=(ip nft awk grep systemctl sysctl ping flock mktemp sha256sum)
    local missing=() cmd
    for cmd in "${deps[@]}"; do
        command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
    done
    ((${#missing[@]} == 0)) || fail "Missing: ${missing[*]}"
}

verify_package() {
    [[ -f "$SRC" ]] || fail "jojonet not found next to install.sh"
    head -1 "$SRC" | grep -q '^#!/' || fail "Invalid jojonet shebang"
    grep -q 'JOJONET_VERSION="1.1.0"' "$SRC" || warn "Unexpected jojonet version string"
    if [[ -f "$SUMS" ]] && grep -q 'jojonet$' "$SUMS" 2>/dev/null; then
        (cd "$PKG_DIR" && sha256sum -c checksums.sha256 --ignore-missing) || fail "Package checksum failed"
        log "Package checksums OK"
    else
        warn "No self-checksum for jojonet in checksums.sha256 (will generate on install)"
    fi
}

[[ "${1:-}" == "--verify" ]] && { check_deps; verify_package; exit 0; }

check_deps
verify_package

install -d -m755 /usr/local/bin
install -d -m755 "$SHARE_DIR"
install -d -m700 /etc/jojonet/instances
install -d -m700 /etc/jojonet/keys
install -d -m700 /etc/jojonet/paqet

install -m755 "$SRC" "$JOJONET_BIN"
if [[ -f "$SUMS" ]]; then
    install -m644 "$SUMS" "$SHARE_DIR/checksums.sha256"
    install -m644 "$SUMS" /etc/jojonet/checksums.sha256
fi
if [[ -f "$PKG_DIR/uninstall.sh" ]]; then
    install -m755 "$PKG_DIR/uninstall.sh" /usr/local/bin/jojonet-uninstall
fi

# Record package hash
sha256sum "$JOJONET_BIN" | awk '{print $1"  jojonet"}' >> /etc/jojonet/checksums.sha256 2>/dev/null || true

log "Installed: $JOJONET_BIN"
log "Checksums: $SHARE_DIR/checksums.sha256"
echo ""
echo -e "${YELLOW}Start:${NC}     sudo jojonet"
echo -e "${YELLOW}Uninstall:${NC} sudo jojonet-uninstall"
echo -e "${YELLOW}Help:${NC}      sudo jojonet --help"
echo -e "${YELLOW}Support:${NC}   ${JOJONET_SUPPORT}"
echo ""
echo "Quick start:"
echo "  1) FOREIGN: sudo jojonet"
echo "  2) IRAN:    sudo jojonet <FOREIGN_IP>"
echo "  Optional:  export JOJONET_ROLE=iran|kharej"
