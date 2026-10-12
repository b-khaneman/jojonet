#!/usr/bin/env bash
#
# JojoNet Panel uninstaller
#   sudo bash uninstall-panel.sh            # remove service, command and program files (keeps data/config)
#   sudo bash uninstall-panel.sh --purge    # also remove data, config, TLS, service user and firewall rule
#   sudo jojonet-panel uninstall [--purge] [--yes]
#
# The JojoNet tunnel script data (/etc/jojonet) is never touched.

set -Eeuo pipefail

readonly SERVICE="jojonet-panel"
readonly SERVICE_USER="jojonet-panel"
readonly INSTALL_DIR="/opt/jojonet-panel"
readonly ETC_DIR="/etc/jojonet-panel"
readonly ENV_FILE="/etc/jojonet-panel/panel.env"
readonly DATA_DIR="/var/lib/jojonet-panel"
readonly UNIT_FILE="/etc/systemd/system/jojonet-panel.service"
readonly UNIT_DROPIN_DIR="/etc/systemd/system/jojonet-panel.service.d"
readonly WRAPPER="/usr/local/bin/jojonet-panel"

if [[ -t 1 ]]; then
    RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'; NC=$'\033[0m'
else
    RED=""; GREEN=""; YELLOW=""; NC=""
fi

log()  { printf '%s[+]%s %s\n' "$GREEN" "$NC" "$*"; }
warn() { printf '%s[!]%s %s\n' "$YELLOW" "$NC" "$*" >&2; }
die()  { printf '%s[x]%s %s\n' "$RED" "$NC" "$*" >&2; exit 1; }

PURGE=0
ASSUME_YES=0

usage() {
    cat <<'EOF'
JojoNet Panel uninstaller

Usage: sudo bash uninstall-panel.sh [--purge] [--yes]

  --purge   Also delete /var/lib/jojonet-panel (database, vault key), /etc/jojonet-panel
            (config, TLS), the jojonet-panel user and the firewall rule
  --yes     Do not ask for confirmation
  -h        Show this help
EOF
}

parse_args() {
    while (($#)); do
        case "$1" in
            --purge) PURGE=1 ;;
            -y|--yes) ASSUME_YES=1 ;;
            -h|--help) usage; exit 0 ;;
            *) die "Unknown option: $1 (see --help)" ;;
        esac
        shift
    done
}

confirm_purge() {
    local ans=""
    printf '%s[!]%s --purge permanently deletes the panel database, saved servers, SSH secrets and vault key.\n' "$YELLOW" "$NC"
    printf '    با --purge پایگاه داده پنل، سرورهای ذخیره‌شده و کلید رمزنگاری برای همیشه حذف می‌شوند.\n'
    printf 'Continue? / ادامه می‌دهید؟ [y/N] '
    if [[ -t 0 ]]; then
        read -r ans || true
    elif [[ -r /dev/tty ]]; then
        { read -r ans </dev/tty; } 2>/dev/null || true
    else
        echo
        die "No terminal available; re-run with --yes to confirm."
    fi
    if [[ ! "$ans" =~ ^[Yy]([Ee][Ss])?$ ]]; then
        echo "Aborted. / لغو شد."
        exit 1
    fi
}

env_value() {
    local v=""
    [[ -f "$ENV_FILE" ]] || return 0
    v="$(sed -n "s/^$1=//p" "$ENV_FILE" | tail -n 1)"
    v="${v%\"}"; v="${v#\"}"
    printf '%s' "$v"
}

remove_service() {
    if systemctl cat "$SERVICE" >/dev/null 2>&1 || [[ -f "$UNIT_FILE" ]]; then
        systemctl stop "$SERVICE" >/dev/null 2>&1 || true
        systemctl disable "$SERVICE" >/dev/null 2>&1 || true
    fi
    systemctl disable jojonet-panel-apply.path >/dev/null 2>&1 || true
    systemctl stop jojonet-panel-apply.path >/dev/null 2>&1 || true
    rm -f -- "$UNIT_FILE" /etc/systemd/system/jojonet-panel-apply.service /etc/systemd/system/jojonet-panel-apply.path
    rm -rf -- "$UNIT_DROPIN_DIR"
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl reset-failed "$SERVICE" >/dev/null 2>&1 || true
    log "Service removed."
}

remove_firewall_rule() {
    local port="$1" st=""
    [[ "$port" =~ ^[0-9]+$ ]] || return 0
    if command -v ufw >/dev/null 2>&1; then
        st="$(ufw status 2>/dev/null || true)"
        if [[ "$st" == *"Status: active"* ]]; then
            if ufw delete allow "$port/tcp" >/dev/null 2>&1; then
                log "ufw: removed $port/tcp"
            fi
        fi
    fi
    if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
        if firewall-cmd --permanent --remove-port="$port/tcp" >/dev/null 2>&1; then
            firewall-cmd --reload >/dev/null 2>&1 || true
            log "firewalld: removed $port/tcp"
        fi
    fi
}

remove_user() {
    if id -u "$SERVICE_USER" >/dev/null 2>&1; then
        pkill -u "$SERVICE_USER" >/dev/null 2>&1 || true
        sleep 1
        userdel "$SERVICE_USER" >/dev/null 2>&1 || warn "Could not delete user $SERVICE_USER"
    fi
    if getent group "$SERVICE_USER" >/dev/null 2>&1; then
        groupdel "$SERVICE_USER" >/dev/null 2>&1 || true
    fi
    log "Service user removed."
}

main() {
    parse_args "$@"
    [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "Run as root: sudo bash $0"
    if ((PURGE && !ASSUME_YES)); then
        confirm_purge
    fi

    local port
    port="$(env_value JOJONET_PANEL_PORT)"

    remove_service
    rm -f -- "$WRAPPER"
    rm -rf -- "$INSTALL_DIR"
    log "Removed $WRAPPER and $INSTALL_DIR"

    if ((PURGE)); then
        remove_firewall_rule "$port"
        rm -rf -- "$DATA_DIR" "$ETC_DIR"
        rm -f -- /etc/letsencrypt/renewal-hooks/deploy/jojonet-panel.sh
        log "Removed $DATA_DIR and $ETC_DIR (a Let's Encrypt certificate, if any, stays under /etc/letsencrypt)"
        remove_user
        log "JojoNet Panel fully removed. / پنل به‌طور کامل حذف شد."
    else
        log "JojoNet Panel removed. Data and config kept in $DATA_DIR and $ETC_DIR (use --purge to delete)."
        echo "    پنل حذف شد؛ داده‌ها و تنظیمات نگه داشته شدند (برای حذف کامل: --purge)."
    fi
}

main "$@"
