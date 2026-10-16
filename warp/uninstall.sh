#!/usr/bin/env bash
# AI-WARP uninstaller
set -euo pipefail
(( EUID == 0 )) || { echo "Run as root: sudo bash uninstall.sh" >&2; exit 1; }

if command -v ai-warp >/dev/null 2>&1; then
  ai-warp uninstall "$@"
else
  systemctl disable --now ai-warp-watchdog.timer 2>/dev/null || true
  systemctl disable --now ai-warp-refresh.timer 2>/dev/null || true
  systemctl disable --now wg-quick@aiwarp 2>/dev/null || true
  wg-quick down aiwarp 2>/dev/null || true
  rm -f /etc/wireguard/aiwarp.conf
  rm -rf /usr/local/share/ai-warp /usr/local/bin/ai-warp
  [[ "${1:-}" == "--purge" ]] && rm -rf /etc/ai-warp
  echo "AI-WARP removed."
fi
