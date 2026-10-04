#!/usr/bin/env bash
#
# JojoNet one-click setup
#   sudo bash setup.sh            # menu
#   sudo bash setup.sh script     # JojoNet tunnel script only
#   sudo bash setup.sh panel [--port N] [--host ADDR] [--domain NAME [--email ADDR]] [--no-firewall]
#   sudo bash setup.sh all   [panel options]
#
# Run from the extracted package directory (zip/tarball).

set -Eeuo pipefail

if [[ -t 1 ]]; then
    RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'; BOLD=$'\033[1m'; NC=$'\033[0m'
else
    RED=""; GREEN=""; YELLOW=""; BOLD=""; NC=""
fi

log()  { printf '%s[+]%s %s\n' "$GREEN" "$NC" "$*"; }
warn() { printf '%s[!]%s %s\n' "$YELLOW" "$NC" "$*" >&2; }
die()  { printf '%s[x]%s %s\n' "$RED" "$NC" "$*" >&2; exit 1; }

MODE=""
ROOT=""

usage() {
    cat <<'EOF'
JojoNet setup

Usage: sudo bash setup.sh [script|panel|all] [panel options]

  script   Install the JojoNet tunnel script (install.sh)
  panel    Install the JojoNet web panel (panel/install-panel.sh)
  all      Both (default when stdin is not a terminal)

Panel options (passed to panel/install-panel.sh): --port N  --host ADDR
  --domain NAME [--email ADDR] (trusted Let's Encrypt certificate)  --no-domain  --no-firewall
EOF
}

show_menu() {
    local choice=""
    while :; do
        printf '\n%s JojoNet Setup %s\n' "$BOLD" "$NC"
        printf '  1) نصب اسکریپت JojoNet       | Install JojoNet script\n'
        printf '  2) نصب پنل تحت وب            | Install web panel\n'
        printf '  3) نصب هر دو                 | Install both\n'
        printf '  0) خروج                      | Exit\n'
        read -rp "Choose / انتخاب کنید [0-3]: " choice || exit 0
        case "$choice" in
            1) MODE="script"; return ;;
            2) MODE="panel"; return ;;
            3) MODE="all"; return ;;
            0) exit 0 ;;
            *) warn "Invalid choice / گزینه نامعتبر" ;;
        esac
    done
}

check_files() {
    local f
    local -a need=()
    case "$MODE" in
        script) need=(jojonet install.sh uninstall.sh) ;;
        panel)  need=(jojonet install.sh uninstall.sh panel/install-panel.sh panel/uninstall-panel.sh panel/app/cli.py) ;;
        all)    need=(jojonet install.sh uninstall.sh panel/install-panel.sh panel/uninstall-panel.sh panel/app/cli.py) ;;
    esac
    for f in "${need[@]}"; do
        [[ -f "$ROOT/$f" ]] || die "Missing file: $ROOT/$f — extract the full package and run setup.sh from its folder."
    done
}

check_crlf() {
    local f
    local -a files=() bad=()
    for f in "$ROOT/setup.sh" "$ROOT/jojonet" "$ROOT/install.sh" "$ROOT/uninstall.sh" "$ROOT"/panel/*.sh; do
        if [[ -f "$f" ]]; then files+=("$f"); fi
    done
    mapfile -t bad < <(grep -l $'\r' -- "${files[@]}" 2>/dev/null || true)
    if ((${#bad[@]})); then
        printf '%s[x]%s Windows line endings (CRLF) found in:\n' "$RED" "$NC" >&2
        printf '      %s\n' "${bad[@]}" >&2
        printf '%s\n' \
            "    Fix with:" \
            "      sed -i 's/\\r\$//' ${bad[*]}" \
            "    فایل‌ها پایان خط ویندوزی دارند؛ با دستور بالا اصلاح کنید و دوباره اجرا کنید." >&2
        exit 1
    fi
}

main() {
    case "${1:-}" in
        script|1) MODE="script"; shift ;;
        panel|2)  MODE="panel"; shift ;;
        all|both|3) MODE="all"; shift ;;
        -h|--help|help) usage; exit 0 ;;
    esac

    [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "Run as root: sudo bash setup.sh  |  با sudo اجرا کنید"

    local self="${BASH_SOURCE[0]:-}"
    [[ -n "$self" && -f "$self" ]] || die "Run setup.sh from the extracted package directory (not via a pipe)."
    cd "$(dirname "$self")"
    ROOT="$(pwd -P)"

    if [[ -z "$MODE" ]]; then
        if [[ -t 0 ]]; then
            show_menu
        else
            MODE="all"
        fi
    fi

    check_files
    check_crlf
    chmod +x "$ROOT/jojonet" "$ROOT/install.sh" "$ROOT/uninstall.sh"
    if compgen -G "$ROOT/panel/*.sh" >/dev/null; then
        chmod +x "$ROOT"/panel/*.sh
    fi

    if [[ "$MODE" == "script" || "$MODE" == "all" ]]; then
        if [[ "$MODE" == "script" && $# -gt 0 ]]; then
            warn "Ignoring extra arguments for 'script': $*"
        fi
        log "Installing JojoNet script... / نصب اسکریپت JojoNet"
        bash install.sh
    fi
    if [[ "$MODE" == "panel" || "$MODE" == "all" ]]; then
        log "Installing JojoNet Panel... / نصب پنل JojoNet"
        bash panel/install-panel.sh "$@"
    fi
    log "Done. / انجام شد."
}

main "$@"
