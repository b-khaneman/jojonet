#!/usr/bin/env bash
# JojoNet — one-command install (tunnel script + web panel)
#   sudo bash install-one.sh
#   sudo bash install-one.sh --port 2053
#   sudo bash install-one.sh --domain panel.example.com --email you@example.com
set -Eeuo pipefail

self="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
cd "$self"
[[ "${EUID:-$(id -u)}" -eq 0 ]] || {
    echo "Run as root: sudo bash install-one.sh" >&2
    exit 1
}
[[ -f "$self/setup.sh" ]] || {
    echo "setup.sh not found — run this from the extracted JojoNet folder." >&2
    exit 1
}
exec bash "$self/setup.sh" all "$@"
