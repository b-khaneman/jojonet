#!/usr/bin/env bash
#
# JojoNet Panel installer
# https://github.com/b-khaneman/jojonet
#
# From the extracted package:
#   sudo bash panel/install-panel.sh [--port 2053] [--host 0.0.0.0] [--no-firewall]
# One-liner:
#   curl -fsSL https://raw.githubusercontent.com/b-khaneman/jojonet/main/panel/install-panel.sh | sudo bash
#   curl -fsSL https://raw.githubusercontent.com/b-khaneman/jojonet/main/panel/install-panel.sh | sudo bash -s -- --port 8443
#
# Everything lives inside functions and runs from the final `main` line, so a
# piped (curl | bash) run is fully parsed before any command touches stdin.

set -Eeuo pipefail

readonly SERVICE="jojonet-panel"
readonly SERVICE_USER="jojonet-panel"
readonly INSTALL_DIR="/opt/jojonet-panel"
readonly VENV_DIR="/opt/jojonet-panel/venv"
readonly BUNDLE_DIR="/opt/jojonet-panel/bundle"
readonly ETC_DIR="/etc/jojonet-panel"
readonly TLS_DIR="/etc/jojonet-panel/tls"
readonly ENV_FILE="/etc/jojonet-panel/panel.env"
readonly DATA_DIR="/var/lib/jojonet-panel"
readonly UNIT_FILE="/etc/systemd/system/jojonet-panel.service"
readonly SOCKET_FILE="/etc/systemd/system/jojonet-panel.socket"
readonly ROLLBACK_DIR="/etc/jojonet-panel/rollback"
readonly WRAPPER="/usr/local/bin/jojonet-panel"
readonly DEFAULT_PORT="2053"
readonly DEFAULT_PANEL_PATH="/jojonet-panel-entry"
readonly APPLY_UNIT="/etc/systemd/system/jojonet-panel-apply.service"
readonly APPLY_PATH_UNIT="/etc/systemd/system/jojonet-panel-apply.path"
readonly SSL_UNIT="/etc/systemd/system/jojonet-panel-ssl.service"
readonly SSL_PATH_UNIT="/etc/systemd/system/jojonet-panel-ssl.path"
readonly DEFAULT_HOST="0.0.0.0"
readonly ACME_HOOK="/etc/letsencrypt/renewal-hooks/deploy/jojonet-panel.sh"
readonly REPO_SLUG="b-khaneman/jojonet"
readonly REPO_BRANCH="main"
readonly -a TARBALL_URLS=(
    "https://codeload.github.com/${REPO_SLUG}/tar.gz/refs/heads/${REPO_BRANCH}"
    "https://ghproxy.net/https://github.com/${REPO_SLUG}/archive/refs/heads/${REPO_BRANCH}.tar.gz"
)
readonly -a PIP_MIRRORS=(
    "https://mirror-pypi.runflare.com/simple"
    "https://pypi.org/simple"
)

if [[ -t 1 ]]; then
    RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'
    CYAN=$'\033[0;36m'; BOLD=$'\033[1m'; NC=$'\033[0m'
else
    RED=""; GREEN=""; YELLOW=""; CYAN=""; BOLD=""; NC=""
fi

log()  { printf '%s[+]%s %s\n' "$GREEN" "$NC" "$*"; }
info() { printf '%s[*]%s %s\n' "$CYAN" "$NC" "$*"; }
warn() { printf '%s[!]%s %s\n' "$YELLOW" "$NC" "$*" >&2; }
die()  {
    trap - ERR
    if ((${HAVE_ROLLBACK:-0})) && ((${NEW_PANEL_OK:-0} == 0)); then
        if restore_runtime; then
            printf '%s[!]%s Previous panel files were restored and the service was started again.\n' "$YELLOW" "$NC" >&2
        fi
    fi
    printf '%s[x]%s %s\n' "$RED" "$NC" "$*" >&2
    exit 1
}
step() { printf '\n%s==> %s%s\n' "$BOLD" "$*" "$NC"; }

PORT=""
HOST=""
PORT_EXPLICIT=0
HOST_EXPLICIT=0
DOMAIN=""
EMAIL=""
NO_DOMAIN=0
TLS_ACME=0
FIREWALL=1
FIRST_INSTALL=0
OLD_PORT=""
PKG_ROOT=""
PANEL_SRC=""
PYTHON=""
PKG_MGR=""
SERVICE_GROUP="$SERVICE_USER"
LOCAL_IP=""
PUBLIC_IP=""
ADMIN_USER=""
ADMIN_PASS=""
ADMIN_RAW=""
TMP_DIRS=()
HAVE_ROLLBACK=0
NEW_PANEL_OK=0

cleanup() {
    local d
    for d in ${TMP_DIRS[@]+"${TMP_DIRS[@]}"}; do
        if [[ -n "$d" && -d "$d" ]]; then
            rm -rf -- "$d"
        fi
    done
}

on_error() {
    trap - ERR
    printf '%s[x]%s Installer failed at line %s (exit code %s).\n' "$RED" "$NC" "$2" "$1" >&2
    if ((${HAVE_ROLLBACK:-0})) && ((${NEW_PANEL_OK:-0} == 0)); then
        if restore_runtime; then
            printf '%s[!]%s Previous panel files were restored and the service was started again.\n' "$YELLOW" "$NC" >&2
        fi
    fi
}

trap cleanup EXIT
trap 'on_error $? $LINENO' ERR

usage() {
    cat <<'EOF'
JojoNet Panel installer

Usage:
  sudo bash panel/install-panel.sh [options]
  curl -fsSL https://raw.githubusercontent.com/b-khaneman/jojonet/main/panel/install-panel.sh | sudo bash -s -- [options]

Options:
  --port N        HTTPS port for the panel (default 2053, or the current one on reinstall)
  --host ADDR     Listen address (default 0.0.0.0)
  --domain NAME   Panel domain (A record -> this server): gets a Let's Encrypt
                  certificate with auto-renewal (TCP 80 must be reachable)
  --email ADDR    Contact e-mail for Let's Encrypt (optional)
  --no-domain     Drop the saved domain and go back to a self-signed certificate
  --no-firewall   Do not open the port in ufw/firewalld
  -h, --help      Show this help

Environment overrides:
  JOJONET_PANEL_PORT, JOJONET_PANEL_HOST, JOJONET_PANEL_NO_FIREWALL=1,
  JOJONET_PANEL_DOMAIN, JOJONET_PANEL_ACME_EMAIL,
  JOJONET_SKIP_CHECKSUM=1 (skip checksums.sha256 verification)
EOF
}

parse_args() {
    if [[ -n "${JOJONET_PANEL_PORT:-}" ]]; then PORT="$JOJONET_PANEL_PORT"; PORT_EXPLICIT=1; fi
    if [[ -n "${JOJONET_PANEL_HOST:-}" ]]; then HOST="$JOJONET_PANEL_HOST"; HOST_EXPLICIT=1; fi
    if [[ "${JOJONET_PANEL_NO_FIREWALL:-0}" == "1" ]]; then FIREWALL=0; fi
    DOMAIN="${JOJONET_PANEL_DOMAIN:-}"
    EMAIL="${JOJONET_PANEL_ACME_EMAIL:-}"

    while (($#)); do
        case "$1" in
            --port)
                [[ $# -ge 2 ]] || die "--port needs a value"
                PORT="$2"; PORT_EXPLICIT=1; shift 2 ;;
            --port=*)
                PORT="${1#*=}"; PORT_EXPLICIT=1; shift ;;
            --host)
                [[ $# -ge 2 ]] || die "--host needs a value"
                HOST="$2"; HOST_EXPLICIT=1; shift 2 ;;
            --host=*)
                HOST="${1#*=}"; HOST_EXPLICIT=1; shift ;;
            --domain)
                [[ $# -ge 2 ]] || die "--domain needs a value"
                DOMAIN="$2"; shift 2 ;;
            --domain=*)
                DOMAIN="${1#*=}"; shift ;;
            --email)
                [[ $# -ge 2 ]] || die "--email needs a value"
                EMAIL="$2"; shift 2 ;;
            --email=*)
                EMAIL="${1#*=}"; shift ;;
            --no-domain)
                NO_DOMAIN=1; shift ;;
            --no-firewall)
                FIREWALL=0; shift ;;
            -h|--help)
                usage; exit 0 ;;
            *)
                die "Unknown option: $1 (see --help)" ;;
        esac
    done
}

require_root() {
    [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "Run as root: sudo bash $0  |  با دسترسی root اجرا کنید"
    command -v systemctl >/dev/null 2>&1 || die "systemd is required (systemctl not found)."
}

env_value() {
    local key="$1" file="${2:-$ENV_FILE}" v=""
    [[ -n "$file" && -f "$file" ]] || return 0
    v="$(sed -n "s/^${key}=//p" "$file" | tail -n 1)"
    v="${v%\"}"; v="${v#\"}"
    v="${v%\'}"; v="${v#\'}"
    printf '%s' "$v"
}

load_existing() {
    local old_host=""
    OLD_PORT="$(env_value JOJONET_PANEL_PORT "$ENV_FILE")"
    old_host="$(env_value JOJONET_PANEL_HOST "$ENV_FILE")"
    if [[ -z "$PORT" ]]; then PORT="${OLD_PORT:-$DEFAULT_PORT}"; fi
    if ((PORT_EXPLICIT == 0)); then
        local data listen_port
        data="$(env_value JOJONET_PANEL_DATA "$ENV_FILE")"
        data="${data:-/var/lib/jojonet-panel}"
        if [[ -f "$data/listen.json" ]]; then
            listen_port="$(sed -n 's/.*"port":\([0-9][0-9]*\).*/\1/p' "$data/listen.json" | head -n 1)"
            if [[ "$listen_port" =~ ^[0-9]+$ ]]; then PORT="$listen_port"; fi
        fi
    fi
    if [[ -z "$HOST" ]]; then HOST="${old_host:-$DEFAULT_HOST}"; fi
    if ((NO_DOMAIN)); then
        DOMAIN=""
    elif [[ -z "$DOMAIN" ]]; then
        DOMAIN="$(env_value JOJONET_PANEL_DOMAIN "$ENV_FILE")"
    fi
    if [[ -z "$EMAIL" ]]; then EMAIL="$(env_value JOJONET_PANEL_ACME_EMAIL "$ENV_FILE")"; fi
}

validate_settings() {
    if [[ ! "$PORT" =~ ^[0-9]{1,5}$ ]] || ((10#$PORT < 1 || 10#$PORT > 65535)); then
        die "Invalid port '$PORT' (must be 1-65535)."
    fi
    PORT="$((10#$PORT))"
    if [[ ! "$HOST" =~ ^[A-Za-z0-9.:-]+$ ]] || ((${#HOST} > 253)); then
        die "Invalid listen address '$HOST'."
    fi
    DOMAIN="${DOMAIN,,}"
    DOMAIN="${DOMAIN%.}"
    if [[ -n "$DOMAIN" ]] && { [[ ! "$DOMAIN" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$ ]] || ((${#DOMAIN} > 253)); }; then
        die "Invalid domain '$DOMAIN' (example: panel.example.com)."
    fi
    if [[ -n "$EMAIL" && ! "$EMAIL" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$ ]]; then
        die "Invalid e-mail '$EMAIL'."
    fi
}

detect_pkg_mgr() {
    if command -v apt-get >/dev/null 2>&1; then PKG_MGR="apt"
    elif command -v dnf >/dev/null 2>&1; then PKG_MGR="dnf"
    elif command -v yum >/dev/null 2>&1; then PKG_MGR="yum"
    else PKG_MGR=""
    fi
}

install_os_deps() {
    step "Installing system packages"
    local -a pkgs=()
    case "$PKG_MGR" in
        apt)
            export DEBIAN_FRONTEND=noninteractive
            pkgs=(python3 python3-venv python3-pip openssl ca-certificates iproute2)
            command -v curl >/dev/null 2>&1 || pkgs+=(curl)
            command -v tar >/dev/null 2>&1 || pkgs+=(tar)
            apt-get update -qq </dev/null || warn "apt-get update failed; continuing with cached package lists."
            apt-get install -y -qq --no-install-recommends "${pkgs[@]}" </dev/null \
                || die "apt-get install failed: ${pkgs[*]}"
            ;;
        dnf|yum)
            # curl is only added when missing: RHEL 9 ships curl-minimal, which conflicts with curl.
            pkgs=(python3 python3-pip openssl ca-certificates iproute)
            command -v curl >/dev/null 2>&1 || pkgs+=(curl)
            command -v tar >/dev/null 2>&1 || pkgs+=(tar)
            "$PKG_MGR" install -y -q "${pkgs[@]}" </dev/null || die "$PKG_MGR install failed: ${pkgs[*]}"
            ;;
        *)
            warn "Unknown package manager; make sure python3 (>=3.10, with venv), openssl, curl, tar and ss are installed."
            ;;
    esac
    local tool
    for tool in openssl curl tar ss sha256sum runuser; do
        command -v "$tool" >/dev/null 2>&1 || die "Required tool not found: $tool"
    done
    log "System packages ready."
}

python_ok() {
    "$1" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' >/dev/null 2>&1
}

find_python() {
    local c
    for c in python3 python3.13 python3.12 python3.11 python3.10; do
        if command -v "$c" >/dev/null 2>&1 && python_ok "$c"; then
            PYTHON="$(command -v "$c")"
            return 0
        fi
    done
    return 1
}

ensure_python() {
    step "Checking Python"
    if ! find_python && [[ "$PKG_MGR" == "dnf" || "$PKG_MGR" == "yum" ]]; then
        info "System python3 is older than 3.10; trying python3.11 packages..."
        "$PKG_MGR" install -y -q python3.11 python3.11-pip </dev/null >/dev/null 2>&1 || true
    fi
    if [[ -z "$PYTHON" ]] && ! find_python; then
        local have
        have="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null || echo "none")"
        printf '%s\n' \
            "Python 3.10 or newer is required (found: $have)." \
            "Use Ubuntu 22.04+ / Debian 12+ / RHEL 9+, or install python3.10+ with venv support and re-run." \
            "پنل JojoNet به Python نسخه 3.10 یا بالاتر نیاز دارد (نسخه فعلی: $have)." \
            "از Ubuntu 22.04+ یا Debian 12+ یا RHEL 9+ استفاده کنید، یا Python 3.10+ را نصب و دوباره اجرا کنید." >&2
        exit 1
    fi
    log "Using $PYTHON ($("$PYTHON" -c 'import sys; print(sys.version.split()[0])'))"
}

detect_local_source() {
    local src="${BASH_SOURCE[0]:-}" dir=""
    [[ -n "$src" && -f "$src" ]] || return 1
    dir="$(cd "$(dirname "$src")" && pwd -P)" || return 1
    if [[ -f "$dir/app/cli.py" && -f "$dir/requirements.txt" && -f "$dir/../jojonet" ]]; then
        PANEL_SRC="$dir"
        PKG_ROOT="$(cd "$dir/.." && pwd -P)"
        return 0
    fi
    return 1
}

download_source() {
    step "Downloading JojoNet package"
    local tmp archive url d
    tmp="$(mktemp -d /tmp/jojonet-panel.XXXXXX)"
    TMP_DIRS+=("$tmp")
    archive="$tmp/source.tar.gz"
    for url in "${TARBALL_URLS[@]}"; do
        info "Trying $url"
        if curl -fsSL --connect-timeout 10 --max-time 300 --retry 2 -o "$archive" "$url" \
            && tar -tzf "$archive" >/dev/null 2>&1; then
            tar -xzf "$archive" -C "$tmp" --no-same-owner
            for d in "$tmp"/*/; do
                if [[ -f "${d}panel/app/cli.py" && -f "${d}jojonet" ]]; then
                    PKG_ROOT="${d%/}"
                    PANEL_SRC="$PKG_ROOT/panel"
                    log "Package extracted to $PKG_ROOT"
                    return 0
                fi
            done
            die "The downloaded archive does not contain panel/app — the repository layout is unexpected."
        fi
        warn "Download failed: $url"
    done
    die "Could not download the JojoNet package (GitHub and mirror both failed)."
}

check_crlf() {
    local -a files=() bad=()
    local f
    for f in "$PKG_ROOT/jojonet" "$PKG_ROOT/install.sh" "$PKG_ROOT/uninstall.sh" \
             "$PKG_ROOT/setup.sh" "$PKG_ROOT/checksums.sha256" \
             "$PANEL_SRC"/*.sh "$PANEL_SRC/requirements.txt" "$PANEL_SRC"/app/*.py \
             "$PANEL_SRC"/static/*.html "$PANEL_SRC"/static/*.js \
             "$PANEL_SRC"/static/*.css "$PANEL_SRC"/static/*.svg; do
        if [[ -f "$f" ]]; then files+=("$f"); fi
    done
    ((${#files[@]})) || die "No package files found under $PKG_ROOT"
    mapfile -t bad < <(grep -l $'\r' -- "${files[@]}" 2>/dev/null || true)
    if ((${#bad[@]})); then
        printf '%s[x]%s Windows line endings (CRLF) detected in:\n' "$RED" "$NC" >&2
        printf '      %s\n' "${bad[@]}" >&2
        printf '%s\n' \
            "    The files were probably edited/extracted on Windows. Fix with:" \
            "      find '$PKG_ROOT' -type f \\( -name '*.sh' -o -name '*.py' -o -name jojonet \\) -exec sed -i 's/\\r\$//' {} +" \
            "    فایل‌ها پایان خط ویندوزی (CRLF) دارند؛ با دستور بالا اصلاح کنید یا بسته را دوباره دانلود کنید." >&2
        exit 1
    fi
}

verify_checksums() {
    if [[ ! -f "$PKG_ROOT/checksums.sha256" ]]; then
        warn "checksums.sha256 not found; skipping integrity check."
        return 0
    fi
    if [[ "${JOJONET_SKIP_CHECKSUM:-0}" == "1" ]]; then
        warn "JOJONET_SKIP_CHECKSUM=1: skipping integrity check."
        return 0
    fi
    if (cd "$PKG_ROOT" && sha256sum -c --ignore-missing --quiet checksums.sha256); then
        log "Package checksums OK."
    else
        die "checksums.sha256 verification failed — the package is corrupted or modified. Re-download it (or set JOJONET_SKIP_CHECKSUM=1 if you changed files on purpose)."
    fi
}

validate_source() {
    step "Validating package"
    local f
    for f in "$PANEL_SRC/app/cli.py" "$PANEL_SRC/requirements.txt" "$PANEL_SRC/static/index.html" \
             "$PANEL_SRC/uninstall-panel.sh" "$PKG_ROOT/jojonet" "$PKG_ROOT/install.sh" "$PKG_ROOT/uninstall.sh"; do
        [[ -f "$f" ]] || die "Missing package file: $f"
    done
    check_crlf
    verify_checksums
    log "Package: $PKG_ROOT"
}

check_port_free() {
    local listeners pid
    listeners="$(ss -ltnpH "sport = :$PORT" 2>/dev/null || true)"
    if [[ -z "$listeners" ]]; then
        return 0
    fi
    if systemctl is-active --quiet "$SERVICE"; then
        pid="$(systemctl show -p MainPID --value "$SERVICE" 2>/dev/null || echo 0)"
        if [[ -n "$pid" && "$pid" != "0" && "$listeners" == *"pid=$pid,"* ]]; then
            info "Port $PORT is held by the existing panel service (reinstall)."
            return 0
        fi
        if [[ "$listeners" != *"pid="* && "$PORT" == "$OLD_PORT" ]]; then
            info "Port $PORT is assumed to be held by the existing panel service (reinstall)."
            return 0
        fi
    fi
    printf '%s\n' "$listeners" >&2
    die "Port $PORT is already in use. Pick another one with --port N  |  پورت $PORT اشغال است؛ با --port پورت دیگری انتخاب کنید."
}

ensure_user() {
    step "Preparing service user and directories"
    if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
        local nologin="/usr/sbin/nologin"
        [[ -x "$nologin" ]] || nologin="/sbin/nologin"
        useradd --system --user-group --home-dir "$DATA_DIR" --shell "$nologin" "$SERVICE_USER"
        log "Created system user $SERVICE_USER"
    fi
    SERVICE_GROUP="$(id -gn "$SERVICE_USER")"

    install -d -m 0755 -o root -g root "$INSTALL_DIR"
    install -d -m 0750 -o root -g "$SERVICE_GROUP" "$ETC_DIR" "$TLS_DIR"
    install -d -m 0700 -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$DATA_DIR"
    chown root:root "$INSTALL_DIR"
    chmod 0755 "$INSTALL_DIR"
    chown root:"$SERVICE_GROUP" "$ETC_DIR" "$TLS_DIR"
    chmod 0750 "$ETC_DIR" "$TLS_DIR"
    chown -R "$SERVICE_USER":"$SERVICE_GROUP" "$DATA_DIR"
    chmod 0700 "$DATA_DIR"
}

copy_files() {
    step "Copying panel files"
    rm -rf -- "$INSTALL_DIR/app" "$INSTALL_DIR/static" "$BUNDLE_DIR"
    cp -a "$PANEL_SRC/app" "$INSTALL_DIR/app"
    cp -a "$PANEL_SRC/static" "$INSTALL_DIR/static"
    find "$INSTALL_DIR/app" -type d -name '__pycache__' -prune -exec rm -rf {} +
    install -m 0644 "$PANEL_SRC/requirements.txt" "$INSTALL_DIR/requirements.txt"
    install -m 0755 "$PANEL_SRC/uninstall-panel.sh" "$INSTALL_DIR/uninstall-panel.sh"
    if [[ -f "$PANEL_SRC/apply-listen" ]]; then
        install -m 0755 "$PANEL_SRC/apply-listen" "$INSTALL_DIR/apply-listen"
    fi
    if [[ -f "$PANEL_SRC/apply-ssl" ]]; then
        install -m 0755 "$PANEL_SRC/apply-ssl" "$INSTALL_DIR/apply-ssl"
    fi

    install -d -m 0755 "$BUNDLE_DIR"
    local f
    for f in jojonet install.sh uninstall.sh; do
        install -m 0755 "$PKG_ROOT/$f" "$BUNDLE_DIR/$f"
    done
    for f in checksums.sha256 CHANGELOG.md README.md; do
        if [[ -f "$PKG_ROOT/$f" ]]; then
            install -m 0644 "$PKG_ROOT/$f" "$BUNDLE_DIR/$f"
        fi
    done
    [[ -f "$BUNDLE_DIR/checksums.sha256" ]] || warn "Bundle has no checksums.sha256; servers will install without integrity check."
    log "Files copied to $INSTALL_DIR"
}

venv_ok() {
    [[ -x "$VENV_DIR/bin/python" ]] && python_ok "$VENV_DIR/bin/python" \
        && "$VENV_DIR/bin/python" -m pip --version >/dev/null 2>&1
}

pip_install() {
    local -a common=(install --disable-pip-version-check --no-input --timeout 60)
    local idx
    if "$VENV_DIR/bin/python" -m pip "${common[@]}" "$@" </dev/null; then
        return 0
    fi
    for idx in "${PIP_MIRRORS[@]}"; do
        warn "pip failed; retrying with index $idx"
        if "$VENV_DIR/bin/python" -m pip "${common[@]}" -i "$idx" "$@" </dev/null; then
            return 0
        fi
    done
    return 1
}

setup_venv() {
    step "Setting up Python virtualenv"
    export PIP_NO_CACHE_DIR=1
    if venv_ok; then
        info "Reusing existing virtualenv."
    else
        rm -rf -- "$VENV_DIR"
        if ! "$PYTHON" -m venv "$VENV_DIR" </dev/null; then
            rm -rf -- "$VENV_DIR"
            if [[ "$PKG_MGR" == "apt" ]]; then
                local ver
                ver="$("$PYTHON" -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
                info "Installing python${ver}-venv..."
                apt-get install -y -qq "python${ver}-venv" </dev/null || true
            fi
            "$PYTHON" -m venv "$VENV_DIR" </dev/null \
                || die "Could not create virtualenv (install the python3-venv package for your Python version)."
        fi
    fi
    pip_install --upgrade pip || warn "Could not upgrade pip; continuing with the bundled version."
    pip_install -r "$INSTALL_DIR/requirements.txt" \
        || die "pip install failed on all indexes. Check internet/DNS, or set PIP_INDEX_URL to a reachable PyPI mirror and re-run."
    # Faster event loop and HTTP parser; uvicorn falls back to asyncio/h11 when the wheels are unavailable.
    pip_install --only-binary=:all: "uvloop>=0.19" "httptools>=0.6" >/dev/null 2>&1 \
        || warn "uvloop/httptools not available for this platform; using the standard (slower) server loop."
    "$VENV_DIR/bin/python" -m compileall -q "$INSTALL_DIR/app" >/dev/null 2>&1 || true
    chown -R root:root "$INSTALL_DIR"
    chmod -R u+rwX,go+rX,go-w "$INSTALL_DIR"
    log "Python dependencies installed."
}

is_ipv4() {
    local ip="$1" o
    local -a parts=()
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    IFS=. read -r -a parts <<<"$ip"
    for o in "${parts[@]}"; do
        ((10#$o <= 255)) || return 1
    done
}

detect_ips() {
    local ip=""
    ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "src") { print $(i + 1); exit }}')" || true
    if ! is_ipv4 "$ip"; then
        ip="$(hostname -I 2>/dev/null | awk '{print $1}')" || true
    fi
    if is_ipv4 "$ip"; then LOCAL_IP="$ip"; fi

    local url
    for url in https://api.ipify.org https://ipv4.icanhazip.com; do
        ip="$(curl -fsS --max-time 5 "$url" 2>/dev/null || true)"
        ip="${ip//[$'\r\n\t ']/}"
        if is_ipv4 "$ip"; then
            PUBLIC_IP="$ip"
            break
        fi
    done
    info "Local IP: ${LOCAL_IP:-unknown}  Public IP: ${PUBLIC_IP:-unknown}"
}

write_acme_hook() {
    install -d -m 0755 "$(dirname "$ACME_HOOK")"
    cat >"$ACME_HOOK.tmp" <<HOOK_EOF
#!/bin/sh
# Installed by JojoNet Panel: install the (renewed) Let's Encrypt certificate of the panel domain.
set -eu
ENV_FILE="$ENV_FILE"
TLS_DIR="$TLS_DIR"
GROUP="$SERVICE_GROUP"
HOOK_EOF
    cat >>"$ACME_HOOK.tmp" <<'HOOK_EOF'
domain="${JOJONET_PANEL_HOOK_DOMAIN:-}"
if [ -z "$domain" ] && [ -r "$ENV_FILE" ]; then
    domain="$(sed -n 's/^JOJONET_PANEL_DOMAIN=//p' "$ENV_FILE" | tail -n 1)"
fi
[ -n "$domain" ] || exit 0
live="/etc/letsencrypt/live/$domain"
if [ -n "${RENEWED_LINEAGE:-}" ] && [ "$RENEWED_LINEAGE" != "$live" ]; then
    exit 0
fi
[ -s "$live/fullchain.pem" ] && [ -s "$live/privkey.pem" ] || { echo "jojonet-panel hook: missing $live" >&2; exit 1; }
install -o root -g root -m 0644 "$live/fullchain.pem" "$TLS_DIR/cert.pem.new"
install -o root -g "$GROUP" -m 0640 "$live/privkey.pem" "$TLS_DIR/key.pem.new"
mv -f "$TLS_DIR/key.pem.new" "$TLS_DIR/key.pem"
mv -f "$TLS_DIR/cert.pem.new" "$TLS_DIR/cert.pem"
if [ -z "${JOJONET_PANEL_HOOK_NO_RESTART:-}" ]; then
    systemctl try-restart jojonet-panel.service || true
fi
HOOK_EOF
    chmod 0755 "$ACME_HOOK.tmp"
    mv -f -- "$ACME_HOOK.tmp" "$ACME_HOOK"
}

install_certbot() {
    command -v certbot >/dev/null 2>&1 && return 0
    info "Installing certbot..."
    case "$PKG_MGR" in
        apt) apt-get install -y -qq --no-install-recommends certbot </dev/null >/dev/null 2>&1 ;;
        dnf|yum)
            "$PKG_MGR" install -y -q certbot </dev/null >/dev/null 2>&1 \
                || { "$PKG_MGR" install -y -q epel-release </dev/null >/dev/null 2>&1 \
                     && "$PKG_MGR" install -y -q certbot </dev/null >/dev/null 2>&1; } ;;
        *) return 1 ;;
    esac
    command -v certbot >/dev/null 2>&1
}

acme_cert() {
    local resolved="" holder=""
    install_certbot || { warn "certbot could not be installed."; return 1; }
    resolved="$(getent ahostsv4 "$DOMAIN" 2>/dev/null | awk '{print $1}' | sort -u | tr '\n' ' ')" || true
    if [[ -z "$resolved" ]]; then
        warn "$DOMAIN does not resolve yet; add an A record pointing to ${PUBLIC_IP:-this server}."
        return 1
    fi
    if [[ -n "$PUBLIC_IP" && " $resolved" != *" $PUBLIC_IP "* ]]; then
        warn "$DOMAIN resolves to $resolved, not $PUBLIC_IP (fine behind a CDN proxy; otherwise fix the A record)."
    fi
    holder="$(ss -Htlnp 'sport = :80' 2>/dev/null | head -n 1)" || true
    if [[ -n "$holder" ]]; then
        warn "TCP port 80 is in use (${holder##*users:}); certbot --standalone needs it free for the HTTP challenge."
        return 1
    fi
    if ((FIREWALL)) && command -v ufw >/dev/null 2>&1 && [[ "$(ufw status 2>/dev/null || true)" == *"Status: active"* ]]; then
        ufw allow 80/tcp comment jojonet-panel-acme >/dev/null 2>&1 || warn "ufw: could not allow 80/tcp"
    fi
    if ((FIREWALL)) && command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
        { firewall-cmd --permanent --add-service=http && firewall-cmd --reload; } >/dev/null 2>&1 || warn "firewalld: could not open http"
    fi
    write_acme_hook
    local -a args=(certonly --standalone --preferred-challenges http --non-interactive --agree-tos
        --keep-until-expiring --key-type ecdsa --cert-name "$DOMAIN" -d "$DOMAIN")
    if [[ -n "$EMAIL" ]]; then args+=(-m "$EMAIL"); else args+=(--register-unsafely-without-email); fi
    info "Requesting a Let's Encrypt certificate for $DOMAIN..."
    local logf
    logf="$(mktemp)" || return 1
    if ! certbot "${args[@]}" </dev/null >"$logf" 2>&1; then
        tail -n 15 "$logf" >&2 || true
        rm -f -- "$logf"
        return 1
    fi
    rm -f -- "$logf"
    JOJONET_PANEL_HOOK_DOMAIN="$DOMAIN" JOJONET_PANEL_HOOK_NO_RESTART=1 sh "$ACME_HOOK" || return 1
    log "Let's Encrypt certificate installed for $DOMAIN (auto-renewed by certbot)"
}

ensure_tls() {
    step "TLS certificate"
    local cert="$TLS_DIR/cert.pem" key="$TLS_DIR/key.pem"
    if [[ -n "$DOMAIN" ]]; then
        if acme_cert; then
            TLS_ACME=1
        else
            warn "Could not get a certificate for $DOMAIN; keeping the current certificate. Fix the issue above and re-run with --domain $DOMAIN."
        fi
    else
        rm -f -- "$ACME_HOOK"
        if ((NO_DOMAIN)) && [[ -s "$cert" ]] && ! cert_is_self_signed; then
            info "Replacing the domain certificate with a self-signed one (--no-domain)."
            rm -f -- "$cert" "$key"
        fi
    fi
    if [[ -s "$cert" && -s "$key" ]]; then
        ((TLS_ACME)) || info "Keeping existing certificate $cert"
    else
        local san="DNS:localhost,IP:127.0.0.1"
        if [[ -n "$LOCAL_IP" ]]; then san+=",IP:$LOCAL_IP"; fi
        if [[ -n "$PUBLIC_IP" && "$PUBLIC_IP" != "$LOCAL_IP" ]]; then san+=",IP:$PUBLIC_IP"; fi
        if is_ipv4 "$HOST" && [[ "$HOST" != "0.0.0.0" && "$HOST" != "127.0.0.1" && "$HOST" != "$LOCAL_IP" && "$HOST" != "$PUBLIC_IP" ]]; then
            san+=",IP:$HOST"
        fi
        (
            umask 077
            openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
                -days 3650 -nodes -subj "/CN=jojonet-panel" \
                -addext "subjectAltName=$san" \
                -keyout "$key.tmp" -out "$cert.tmp" >/dev/null 2>&1
        ) || { rm -f -- "$key.tmp" "$cert.tmp"; die "openssl failed to generate the self-signed certificate."; }
        mv -f -- "$key.tmp" "$key"
        mv -f -- "$cert.tmp" "$cert"
        log "Generated self-signed EC P-256 certificate ($san)"
    fi
    chown root:root "$cert"
    chmod 0644 "$cert"
    chown root:"$SERVICE_GROUP" "$key"
    chmod 0640 "$key"
}

set_env_var() {
    local k="$1" v="$2"
    if grep -q "^${k}=" "$ENV_FILE"; then
        sed -i "s|^${k}=.*|${k}=${v}|" "$ENV_FILE"
    else
        printf '%s=%s\n' "$k" "$v" >>"$ENV_FILE"
    fi
}

set_env_default() {
    local k="$1" v="$2"
    if ! grep -q "^${k}=" "$ENV_FILE"; then
        printf '%s=%s\n' "$k" "$v" >>"$ENV_FILE"
    fi
}

ensure_panel_path() {
    local cur saved
    saved=""
    if [[ -f "$DATA_DIR/web.path" ]]; then
        saved="$(tr -d '[:space:]' < "$DATA_DIR/web.path")"
        saved="${saved%/}"
    fi
    cur="${saved:-$(env_value JOJONET_PANEL_PATH "$ENV_FILE")}"
    cur="${cur%/}"
    # Keep a chosen path. Replace an empty or old random hex path with the fixed entry.
    if [[ "$cur" =~ ^/[A-Za-z0-9][A-Za-z0-9_-]{15,63}$ && ! "$cur" =~ ^/[0-9a-f]{24}$ ]]; then
        PANEL_WEB_PATH="$cur"
    else
        PANEL_WEB_PATH="$DEFAULT_PANEL_PATH"
    fi
    set_env_var JOJONET_PANEL_PATH "$PANEL_WEB_PATH"
    install -d -m 0700 -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$DATA_DIR"
    printf '%s\n' "$PANEL_WEB_PATH" >"$DATA_DIR/web.path"
    chown "$SERVICE_USER:$SERVICE_GROUP" "$DATA_DIR/web.path"
    chmod 0600 "$DATA_DIR/web.path"
    # An explicit --port must win over a port previously saved from the admin UI.
    if ((PORT_EXPLICIT)) && [[ -f "$DATA_DIR/listen.json" ]]; then
        systemctl stop jojonet-panel-apply.path >/dev/null 2>&1 || true
        python3 - "$DATA_DIR/listen.json" "$PORT" <<'PY'
import json, sys
target, port = sys.argv[1], int(sys.argv[2])
data = json.load(open(target, encoding="utf-8"))
data["port"] = port
open(target, "w", encoding="utf-8").write(json.dumps({"path": data.get("path"), "port": port}, separators=(",", ":")) + "\n")
PY
        chown "$SERVICE_USER:$SERVICE_GROUP" "$DATA_DIR/listen.json" || true
        chmod 0600 "$DATA_DIR/listen.json" || true
    fi
}

write_env() {
    step "Writing $ENV_FILE"
    backup_runtime
    if [[ ! -f "$ENV_FILE" ]]; then
        cat >"$ENV_FILE" <<EOF
# JojoNet Panel configuration — read by systemd and the jojonet-panel command.
JOJONET_PANEL_HOST=$HOST
JOJONET_PANEL_PORT=$PORT
JOJONET_PANEL_CERT=$TLS_DIR/cert.pem
JOJONET_PANEL_KEY=$TLS_DIR/key.pem
JOJONET_PANEL_DATA=$DATA_DIR
JOJONET_PANEL_BUNDLE=$BUNDLE_DIR
JOJONET_PANEL_SECURE_COOKIES=1
EOF
        log "Created $ENV_FILE"
    else
        if ((PORT_EXPLICIT)) || ! grep -q '^JOJONET_PANEL_PORT=' "$ENV_FILE"; then
            set_env_var JOJONET_PANEL_PORT "$PORT"
        fi
        if ((HOST_EXPLICIT)) || ! grep -q '^JOJONET_PANEL_HOST=' "$ENV_FILE"; then
            set_env_var JOJONET_PANEL_HOST "$HOST"
        fi
        set_env_default JOJONET_PANEL_CERT "$TLS_DIR/cert.pem"
        set_env_default JOJONET_PANEL_KEY "$TLS_DIR/key.pem"
        set_env_default JOJONET_PANEL_DATA "$DATA_DIR"
        set_env_default JOJONET_PANEL_BUNDLE "$BUNDLE_DIR"
        set_env_default JOJONET_PANEL_SECURE_COOKIES 1
        info "Kept existing $ENV_FILE (port $PORT, host $HOST)"
    fi
    ensure_panel_path
    if [[ -n "$DOMAIN" ]]; then
        set_env_var JOJONET_PANEL_DOMAIN "$DOMAIN"
    else
        sed -i '/^JOJONET_PANEL_DOMAIN=/d' "$ENV_FILE"
    fi
    if [[ -n "$EMAIL" ]]; then
        set_env_var JOJONET_PANEL_ACME_EMAIL "$EMAIL"
    fi
    chown root:"$SERVICE_GROUP" "$ENV_FILE"
    chmod 0640 "$ENV_FILE"
}

listen_stream() {
    case "$HOST" in
        ""|0.0.0.0) printf '0.0.0.0:%s' "$PORT" ;;
        ::|"[::]") printf '[::]:%s' "$PORT" ;;
        *:*) printf '[%s]:%s' "$HOST" "$PORT" ;;
        *) printf '%s:%s' "$HOST" "$PORT" ;;
    esac
}

write_unit() {
    step "Installing systemd unit"
    # systemd opens the port (including 80/443) and passes the socket in.
    # The service stays locked down and never calls bind() itself.
    cat >"$UNIT_FILE.tmp" <<EOF
[Unit]
Description=JojoNet Panel (web UI for JojoNet tunnels)
Documentation=https://github.com/${REPO_SLUG}
After=network-online.target jojonet-panel.socket
Requires=jojonet-panel.socket
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_GROUP
EnvironmentFile=$ENV_FILE
WorkingDirectory=$INSTALL_DIR
ExecStart=$VENV_DIR/bin/python -m app.cli serve --host \${JOJONET_PANEL_HOST} --port \${JOJONET_PANEL_PORT} --cert \${JOJONET_PANEL_CERT} --key \${JOJONET_PANEL_KEY}
Environment=PYTHONDONTWRITEBYTECODE=1
Restart=on-failure
RestartSec=3
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
ReadWritePaths=$DATA_DIR
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
EOF
    chmod 0644 "$UNIT_FILE.tmp"
    mv -f -- "$UNIT_FILE.tmp" "$UNIT_FILE"
    log "Wrote $UNIT_FILE"
    cat >"$SOCKET_FILE.tmp" <<EOF
[Unit]
Description=JojoNet Panel listen socket
Before=jojonet-panel.service

[Socket]
ListenStream=$(listen_stream)
NoDelay=true
FreeBind=true
Backlog=128
Service=jojonet-panel.service

[Install]
WantedBy=sockets.target
EOF
    chmod 0644 "$SOCKET_FILE.tmp"
    mv -f -- "$SOCKET_FILE.tmp" "$SOCKET_FILE"
    log "Wrote $SOCKET_FILE"
    cat >"$APPLY_UNIT" <<EOF
[Unit]
Description=Apply JojoNet Panel path and port
After=network-online.target

[Service]
Type=oneshot
ExecStart=$INSTALL_DIR/apply-listen
EOF
    cat >"$APPLY_PATH_UNIT" <<EOF
[Unit]
Description=Watch JojoNet Panel listen settings

[Path]
PathChanged=$DATA_DIR/listen.json
Unit=jojonet-panel-apply.service

[Install]
WantedBy=multi-user.target
EOF
    chmod 0644 "$APPLY_UNIT" "$APPLY_PATH_UNIT"
    log "Wrote $APPLY_PATH_UNIT"
    cat >"$SSL_UNIT" <<EOF
[Unit]
Description=Issue a Let's Encrypt certificate for JojoNet Panel
After=network-online.target

[Service]
Type=oneshot
TimeoutStartSec=300
ExecStart=$INSTALL_DIR/apply-ssl
EOF
    cat >"$SSL_PATH_UNIT" <<EOF
[Unit]
Description=Watch JojoNet Panel TLS requests

[Path]
PathChanged=$DATA_DIR/ssl.request
Unit=jojonet-panel-ssl.service

[Install]
WantedBy=multi-user.target
EOF
    chmod 0644 "$SSL_UNIT" "$SSL_PATH_UNIT"
    log "Wrote $SSL_PATH_UNIT"
}

write_wrapper() {
    cat >"$WRAPPER.tmp" <<'WRAPPER_EOF'
#!/usr/bin/env bash
# jojonet-panel — management command for JojoNet Panel (installed by install-panel.sh)
set -Eeuo pipefail

readonly SERVICE="jojonet-panel"
readonly SERVICE_USER="jojonet-panel"
readonly INSTALL_DIR="/opt/jojonet-panel"
readonly ENV_FILE="/etc/jojonet-panel/panel.env"
readonly -a INSTALLER_URLS=(
    "https://raw.githubusercontent.com/b-khaneman/jojonet/main/panel/install-panel.sh"
    "https://cdn.jsdelivr.net/gh/b-khaneman/jojonet@main/panel/install-panel.sh"
    "https://ghproxy.net/https://raw.githubusercontent.com/b-khaneman/jojonet/main/panel/install-panel.sh"
)
UPDATE_TMP=""

die() { printf 'jojonet-panel: %s\n' "$*" >&2; exit 1; }

need_root() {
    [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "run as root: sudo jojonet-panel ${1:-}"
}

usage() {
    cat <<'EOF'
Usage: jojonet-panel <command>

  status               Service status
  start | stop | restart
  logs [N|-f]          Show the last N log lines (default 100) or follow
  url                  Print the panel URL
  update [opts]        Download and re-run the latest installer (keeps data)
  uninstall [--purge] [--yes]
                       Remove the panel (--purge also deletes data, config and user)
  set-admin [--username U] [--random]
                       Change admin credentials (prompts for a password unless --random)
  show-key             Print the vault key fingerprint
  has-admin            Exit 0 if an admin account exists
EOF
}

env_value() {
    local v=""
    [[ -r "$ENV_FILE" ]] || return 0
    v="$(sed -n "s/^$1=//p" "$ENV_FILE" | tail -n 1)"
    v="${v%\"}"; v="${v#\"}"
    printf '%s' "$v"
}

run_app() {
    [[ -r "$ENV_FILE" ]] || die "missing $ENV_FILE — is the panel installed?"
    [[ -x "$INSTALL_DIR/venv/bin/python" ]] || die "panel virtualenv not found in $INSTALL_DIR"
    (
        set -a
        # shellcheck disable=SC1090
        . "$ENV_FILE"
        set +a
        cd "$INSTALL_DIR"
        umask 077
        envs=(
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
            "LANG=C.UTF-8"
            "HOME=${JOJONET_PANEL_DATA:-/var/lib/jojonet-panel}"
            "PYTHONDONTWRITEBYTECODE=1"
        )
        while IFS= read -r name; do
            envs+=("$name=${!name}")
        done < <(compgen -e | grep '^JOJONET_PANEL_' || true)
        exec runuser -u "$SERVICE_USER" -- env -i "${envs[@]}" "$INSTALL_DIR/venv/bin/python" -m app.cli "$@"
    )
}

is_ipv4() {
    [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]
}

detect_ip() {
    local ip="" url
    for url in https://api.ipify.org https://ipv4.icanhazip.com; do
        ip="$(curl -fsS --max-time 5 "$url" 2>/dev/null || true)"
        ip="${ip//[$'\r\n\t ']/}"
        if is_ipv4 "$ip"; then printf '%s' "$ip"; return 0; fi
    done
    ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "src") { print $(i + 1); exit }}')" || true
    if is_ipv4 "$ip"; then printf '%s' "$ip"; return 0; fi
    printf '127.0.0.1'
}

cmd_url() {
    local port host addr domain
    port="$(env_value JOJONET_PANEL_PORT)"
    host="$(env_value JOJONET_PANEL_HOST)"
    domain="$(env_value JOJONET_PANEL_DOMAIN)"
    port="${port:-2053}"
    if [[ -n "$domain" ]]; then
        addr="$domain"
    else
        case "$host" in
            ""|0.0.0.0|::|"[::]") addr="$(detect_ip)" ;;
            *) addr="$host" ;;
        esac
        if [[ "$addr" == *:* && "$addr" != \[* ]]; then addr="[$addr]"; fi
    fi
    local webpath data listen_port
    data="$(env_value JOJONET_PANEL_DATA)"
    data="${data:-/var/lib/jojonet-panel}"
    webpath=""
    if [[ -f "$data/web.path" ]]; then
        webpath="$(tr -d '[:space:]' < "$data/web.path")"
        webpath="${webpath%/}"
    fi
    if [[ -z "$webpath" ]]; then
        webpath="$(env_value JOJONET_PANEL_PATH)"
        webpath="${webpath%/}"
    fi
    if [[ -f "$data/listen.json" ]]; then
        listen_port="$(sed -n 's/.*"port":\([0-9][0-9]*\).*/\1/p' "$data/listen.json" | head -n 1)"
        if [[ "$listen_port" =~ ^[0-9]+$ ]]; then port="$listen_port"; fi
    fi
    if [[ "$port" == 443 ]]; then printf 'https://%s%s/\n' "$addr" "$webpath"; else printf 'https://%s:%s%s/\n' "$addr" "$port" "$webpath"; fi
}

cmd_logs() {
    local n="${1:-100}"
    if [[ "$n" == "-f" ]]; then
        exec journalctl -u "$SERVICE" -u jojonet-panel.socket -f --no-pager
    fi
    [[ "$n" =~ ^[0-9]+$ ]] || die "logs: N must be a number"
    exec journalctl -u "$SERVICE" -u jojonet-panel.socket -n "$n" --no-pager
}

cleanup_update() {
    if [[ -n "$UPDATE_TMP" ]]; then rm -f -- "$UPDATE_TMP"; fi
}

cmd_update() {
    local url first=""
    UPDATE_TMP="$(mktemp /tmp/jojonet-panel-installer.XXXXXX)"
    trap cleanup_update EXIT
    for url in "${INSTALLER_URLS[@]}"; do
        printf 'Downloading %s\n' "$url"
        if curl -fsSL --connect-timeout 10 --max-time 60 -o "$UPDATE_TMP" "$url" && [[ -s "$UPDATE_TMP" ]]; then
            IFS= read -r first <"$UPDATE_TMP" || true
            if [[ "$first" == '#!'* ]]; then
                bash "$UPDATE_TMP" "$@"
                return
            fi
        fi
    done
    die "could not download the installer"
}

cmd_set_admin() {
    local a p1="" p2=""
    for a in "$@"; do
        case "$a" in
            --random|--password-stdin) run_app set-admin "$@"; return ;;
        esac
    done
    if [[ -t 0 ]]; then
        IFS= read -rsp "New admin password: " p1; echo >&2
        IFS= read -rsp "Repeat password: " p2; echo >&2
        [[ "$p1" == "$p2" ]] || die "passwords do not match"
    else
        IFS= read -r p1 || true
    fi
    ((${#p1} >= 10)) || die "password must be at least 10 characters"
    printf '%s\n' "$p1" | run_app set-admin "$@" --password-stdin
}

main() {
    local cmd="${1:-help}"
    if (($#)); then shift; fi
    case "$cmd" in
        help|-h|--help) usage; return 0 ;;
    esac
    need_root "$cmd"
    case "$cmd" in
        status) exec systemctl status "$SERVICE" jojonet-panel.socket --no-pager ;;
        start)
            systemctl start jojonet-panel.socket
            systemctl start "$SERVICE"
            ;;
        stop)
            systemctl stop "$SERVICE"
            systemctl stop jojonet-panel.socket
            ;;
        restart)
            systemctl restart jojonet-panel.socket
            systemctl restart "$SERVICE"
            ;;
        logs) cmd_logs "$@" ;;
        url) cmd_url ;;
        apply-listen) exec "$INSTALL_DIR/apply-listen" ;;
        update) cmd_update "$@" ;;
        uninstall)
            [[ -f "$INSTALL_DIR/uninstall-panel.sh" ]] || die "uninstaller not found in $INSTALL_DIR"
            exec bash "$INSTALL_DIR/uninstall-panel.sh" "$@" ;;
        set-admin) cmd_set_admin "$@" ;;
        show-key) run_app show-key "$@" ;;
        has-admin) run_app has-admin "$@" ;;
        *) usage >&2; exit 2 ;;
    esac
}

main "$@"
WRAPPER_EOF
    chmod 0755 "$WRAPPER.tmp"
    mv -f -- "$WRAPPER.tmp" "$WRAPPER"
    log "Installed $WRAPPER"
}

ensure_admin() {
    step "Admin account"
    if "$WRAPPER" has-admin >/dev/null 2>&1; then
        info "An admin account already exists; keeping it."
        return 0
    fi
    FIRST_INSTALL=1
    ADMIN_RAW="$("$WRAPPER" set-admin --random </dev/null)" || die "Failed to create the admin account (jojonet-panel set-admin --random)."
    ADMIN_USER="$(printf '%s\n' "$ADMIN_RAW" | sed -n 's/^username:[[:space:]]*//p' | sed -n '1p')"
    ADMIN_PASS="$(printf '%s\n' "$ADMIN_RAW" | sed -n 's/^password:[[:space:]]*//p' | sed -n '1p')"
    log "Admin account created."
}

open_firewall() {
    if ((FIREWALL == 0)); then
        info "Firewall configuration skipped (--no-firewall)."
        return 0
    fi
    local st=""
    if command -v ufw >/dev/null 2>&1; then
        st="$(ufw status 2>/dev/null || true)"
        if [[ "$st" == *"Status: active"* ]]; then
            if [[ -n "$OLD_PORT" && "$OLD_PORT" != "$PORT" ]]; then
                ufw delete allow "$OLD_PORT/tcp" >/dev/null 2>&1 || true
            fi
            if ufw allow "$PORT/tcp" comment jojonet-panel >/dev/null; then
                log "ufw: allowed $PORT/tcp"
            else
                warn "ufw: could not allow $PORT/tcp"
            fi
        fi
    fi
    if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
        if [[ -n "$OLD_PORT" && "$OLD_PORT" != "$PORT" ]]; then
            firewall-cmd --permanent --remove-port="$OLD_PORT/tcp" >/dev/null 2>&1 || true
        fi
        if firewall-cmd --permanent --add-port="$PORT/tcp" >/dev/null && firewall-cmd --reload >/dev/null; then
            log "firewalld: opened $PORT/tcp"
        else
            warn "firewalld: could not open $PORT/tcp"
        fi
    fi
}

backup_runtime() {
    install -d -m 0700 "$ROLLBACK_DIR"
    rm -f -- "$ROLLBACK_DIR/jojonet-panel.service" "$ROLLBACK_DIR/jojonet-panel.socket" \
        "$ROLLBACK_DIR/panel.env" "$ROLLBACK_DIR/web.path" "$ROLLBACK_DIR/listen.json"
    [[ -f "$UNIT_FILE" ]] && cp -a "$UNIT_FILE" "$ROLLBACK_DIR/jojonet-panel.service"
    [[ -f "$SOCKET_FILE" ]] && cp -a "$SOCKET_FILE" "$ROLLBACK_DIR/jojonet-panel.socket"
    [[ -f "$ENV_FILE" ]] && cp -a "$ENV_FILE" "$ROLLBACK_DIR/panel.env"
    [[ -f "$DATA_DIR/web.path" ]] && cp -a "$DATA_DIR/web.path" "$ROLLBACK_DIR/web.path"
    [[ -f "$DATA_DIR/listen.json" ]] && cp -a "$DATA_DIR/listen.json" "$ROLLBACK_DIR/listen.json"
    HAVE_ROLLBACK=1
}

restore_runtime() {
    [[ -f "$ROLLBACK_DIR/jojonet-panel.service" ]] || return 1
    trap - ERR
    set +e
    systemctl stop "$SERVICE" >/dev/null 2>&1
    systemctl stop jojonet-panel.socket >/dev/null 2>&1
    cp -a "$ROLLBACK_DIR/jojonet-panel.service" "$UNIT_FILE"
    if [[ -f "$ROLLBACK_DIR/jojonet-panel.socket" ]]; then
        cp -a "$ROLLBACK_DIR/jojonet-panel.socket" "$SOCKET_FILE"
    else
        rm -f -- "$SOCKET_FILE"
        systemctl disable jojonet-panel.socket >/dev/null 2>&1
    fi
    [[ -f "$ROLLBACK_DIR/panel.env" ]] && cp -a "$ROLLBACK_DIR/panel.env" "$ENV_FILE"
    [[ -f "$ROLLBACK_DIR/web.path" ]] && cp -a "$ROLLBACK_DIR/web.path" "$DATA_DIR/web.path"
    if [[ -f "$ROLLBACK_DIR/listen.json" ]]; then
        cp -a "$ROLLBACK_DIR/listen.json" "$DATA_DIR/listen.json"
    fi
    systemctl daemon-reload >/dev/null 2>&1
    if [[ -f "$SOCKET_FILE" ]]; then
        systemctl restart jojonet-panel.socket >/dev/null 2>&1
    fi
    systemctl restart "$SERVICE" >/dev/null 2>&1
    local rc=$?
    set -e
    HAVE_ROLLBACK=0
    [[ "$rc" -eq 0 ]]
}

panel_answers() {
    local path="" target="127.0.0.1" url="" code="" body=""
    if [[ -f "$DATA_DIR/web.path" ]]; then
        path="$(tr -d '[:space:]' < "$DATA_DIR/web.path")"
    fi
    path="${path:-${PANEL_WEB_PATH:-}}"
    path="${path%/}"
    [[ -n "$path" ]] || return 1
    case "$HOST" in
        ::|"[::]") target="[::1]" ;;
        ""|0.0.0.0|127.0.0.1) target="127.0.0.1" ;;
        *:*) target="[$HOST]" ;;
        *) target="$HOST" ;;
    esac
    url="https://${target}:${PORT}${path}/"
    body="$(mktemp)"
    code="$(curl -gksS -H 'Accept-Encoding: identity' -o "$body" -w '%{http_code}' --max-time 3 "$url" 2>/dev/null || true)"
    if [[ "$code" == "200" ]] && grep -q 'data-base=' "$body"; then
        rm -f -- "$body"
        return 0
    fi
    rm -f -- "$body"
    return 1
}

socket_listen_now() {
    # Captured before daemon-reload, so this is the address that is actually open.
    systemctl show jojonet-panel.socket -p Listen --value 2>/dev/null \
        | head -n 1 \
        | sed -E 's/[[:space:]]+\([^)]*\)//'
}

start_service() {
    step "Starting $SERVICE"
    local want have
    want="$(listen_stream)"
    have="$(socket_listen_now)"
    systemctl daemon-reload
    systemctl enable "$SERVICE" >/dev/null 2>&1 || warn "systemctl enable failed"
    systemctl enable jojonet-panel.socket >/dev/null 2>&1 || warn "could not enable the listen socket"
    if [[ -f "$APPLY_PATH_UNIT" && -x "$INSTALL_DIR/apply-listen" ]]; then
        systemctl enable jojonet-panel-apply.path >/dev/null 2>&1 || warn "could not enable listen watcher"
        systemctl restart jojonet-panel-apply.path >/dev/null 2>&1 || true
    fi
    if [[ -f "$SSL_PATH_UNIT" && -x "$INSTALL_DIR/apply-ssl" ]]; then
        systemctl enable jojonet-panel-ssl.path >/dev/null 2>&1 || warn "could not enable the TLS watcher"
        systemctl restart jojonet-panel-ssl.path >/dev/null 2>&1 || true
    fi
    # Same port: restart only the process. The socket stays open and queues connections.
    if [[ -n "$have" && "$have" == "$want" ]] && systemctl is-active --quiet jojonet-panel.socket; then
        info "Reloading the panel without closing the port ($want)."
        if ! systemctl restart "$SERVICE"; then
            journalctl -u "$SERVICE" -n 50 --no-pager >&2 || true
            die "The panel service failed to start."
        fi
    else
        systemctl stop "$SERVICE" >/dev/null 2>&1 || true
        systemctl stop jojonet-panel.socket >/dev/null 2>&1 || true
        if ! systemctl restart jojonet-panel.socket; then
            journalctl -u jojonet-panel.socket -n 40 --no-pager >&2 || true
            die "The listen socket failed to start on port $PORT."
        fi
        if ! systemctl restart "$SERVICE"; then
            journalctl -u "$SERVICE" -n 50 --no-pager >&2 || true
            die "The panel service failed to start."
        fi
    fi
    local i
    for ((i = 0; i < 30; i++)); do
        if systemctl is-active --quiet "$SERVICE" && panel_answers; then
            NEW_PANEL_OK=1
            log "Panel is answering HTTPS on port $PORT."
            return 0
        fi
        sleep 1
    done
    journalctl -u "$SERVICE" -n 50 --no-pager >&2 || true
    die "The panel did not answer HTTPS on port $PORT within 30s (see the log above)."
}

panel_url() {
    local addr
    if [[ -n "$DOMAIN" ]]; then
        addr="$DOMAIN"
    else
        case "$HOST" in
            0.0.0.0|::|"[::]") addr="${PUBLIC_IP:-${LOCAL_IP:-127.0.0.1}}" ;;
            *) addr="$HOST" ;;
        esac
        if [[ "$addr" == *:* && "$addr" != \[* ]]; then addr="[$addr]"; fi
    fi
    local webpath="${PANEL_WEB_PATH:-}"
    webpath="${webpath%/}"
    if [[ -z "$webpath" ]]; then
        webpath="$(env_value JOJONET_PANEL_PATH "$ENV_FILE")"
        webpath="${webpath%/}"
    fi
    if ((PORT == 443)); then printf 'https://%s%s/' "$addr" "$webpath"; else printf 'https://%s:%s%s/' "$addr" "$PORT" "$webpath"; fi
}

cert_is_self_signed() {
    local subject
    subject="$(openssl x509 -noout -subject -in "$TLS_DIR/cert.pem" 2>/dev/null)" || return 1
    [[ "$subject" =~ CN\ ?=\ ?jojonet-panel ]]
}

print_summary() {
    local url line
    url="$(panel_url)"
    line="════════════════════════════════════════════════════════════"
    printf '\n%s%s%s\n' "$GREEN" "$line" "$NC"
    printf '%s  JojoNet Panel is running  |  پنل JojoNet نصب و اجرا شد%s\n' "$BOLD" "$NC"
    printf '%s%s%s\n' "$GREEN" "$line" "$NC"
    printf '  URL / آدرس:   %s%s%s\n' "$CYAN" "$url" "$NC"
    printf '  Bare IP does not open the panel — use this full path.\n'
    printf '  ورود با IP خالی کار نمی‌کند؛ فقط همین آدرس (با مسیر مخفی) را باز کنید.\n'
    if ((FIRST_INSTALL)); then
        printf '\n%s╔%s╗%s\n' "$YELLOW" "$line" "$NC"
        if [[ -n "$ADMIN_USER" && -n "$ADMIN_PASS" ]]; then
            printf '%s║%s  Username / نام کاربری:  %s%s%s\n' "$YELLOW" "$NC" "$BOLD" "$ADMIN_USER" "$NC"
            printf '%s║%s  Password / رمز عبور:    %s%s%s\n' "$YELLOW" "$NC" "$BOLD" "$ADMIN_PASS" "$NC"
        else
            printf '%s║%s  %s\n' "$YELLOW" "$NC" "$ADMIN_RAW"
        fi
        printf '%s║%s  Save these now — they are shown only once.\n' "$YELLOW" "$NC"
        printf '%s║%s  همین حالا ذخیره کنید؛ دوباره نمایش داده نمی‌شوند.\n' "$YELLOW" "$NC"
        printf '%s╚%s╝%s\n' "$YELLOW" "$line" "$NC"
    else
        printf '  Admin account unchanged (reset with: sudo jojonet-panel set-admin)\n'
    fi
    if cert_is_self_signed; then
        printf '\n%s[!]%s The certificate is self-signed: your browser will show a security warning — continue/accept it.\n' "$YELLOW" "$NC"
        printf '    گواهی TLS خودامضا است؛ مرورگر هشدار امنیتی نشان می‌دهد — آن را تأیید کنید و ادامه دهید.\n'
        printf '    For a trusted certificate: sudo bash panel/install-panel.sh --domain panel.example.com\n'
    else
        printf '\n%s[+]%s Trusted TLS certificate for %s (renewed automatically).\n' "$GREEN" "$NC" "${DOMAIN:-the panel domain}"
    fi
    if [[ -n "$LOCAL_IP" && -n "$PUBLIC_IP" && "$LOCAL_IP" != "$PUBLIC_IP" ]]; then
        printf '%s[!]%s This server is behind NAT (local %s, public %s); make sure port %s is forwarded/allowed.\n' "$YELLOW" "$NC" "$LOCAL_IP" "$PUBLIC_IP" "$PORT"
    fi
    cat <<EOF

Useful commands / دستورات کاربردی:
  sudo jojonet-panel status            service status
  sudo jojonet-panel logs 100          last log lines
  sudo jojonet-panel url               panel address
  sudo jojonet-panel set-admin         change admin password
  sudo jojonet-panel update            update to the latest version
  sudo jojonet-panel uninstall         remove (add --purge to delete data)

Backup: $DATA_DIR (database + vault key)
EOF
}

main() {
    parse_args "$@"
    require_root
    load_existing
    validate_settings
    detect_pkg_mgr

    local local_src=0
    if detect_local_source; then
        local_src=1
        validate_source
    fi

    install_os_deps

    if ((local_src == 0)); then
        download_source
        validate_source
    fi

    check_port_free
    ensure_python
    ensure_user
    copy_files
    setup_venv
    detect_ips
    ensure_tls
    write_env
    write_unit
    write_wrapper
    ensure_admin
    open_firewall
    start_service
    print_summary
}

main "$@"
