#!/usr/bin/env bash
# Apply / remove AI-WARP kernel routes (invoked by wg-quick PostUp/PostDown)
set -euo pipefail

IFACE="${AI_WARP_IFACE:-aiwarp}"
CIDR_FILE="${AI_WARP_CIDR_FILE:-/etc/ai-warp/allowed-ips.txt}"
TABLE="${AI_WARP_TABLE:-51821}"

action="${1:-up}"

add_routes() {
  [[ -f "$CIDR_FILE" ]] || { echo "missing $CIDR_FILE" >&2; exit 1; }

  # Ensure iface exists
  ip link show "$IFACE" >/dev/null

  sysctl -w "net.ipv4.conf.${IFACE}.rp_filter=0" >/dev/null 2>&1 || true
  sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1 || true

  # Dedicated table default via WARP (for optional fwmark users)
  ip route replace default dev "$IFACE" table "$TABLE" 2>/dev/null \
    || ip route add default dev "$IFACE" table "$TABLE" 2>/dev/null \
    || true

  local cidr ok=0 fail=0
  while IFS= read -r cidr; do
    [[ -z "$cidr" ]] && continue
    if ip route replace "$cidr" dev "$IFACE" 2>/dev/null \
      || ip route add "$cidr" dev "$IFACE" 2>/dev/null; then
      ok=$((ok + 1))
    else
      fail=$((fail + 1))
    fi
  done <"$CIDR_FILE"

  echo "ai-warp routes: ok=${ok} fail=${fail}"
}

del_routes() {
  local cidr
  if [[ -f "$CIDR_FILE" ]]; then
    while IFS= read -r cidr; do
      [[ -z "$cidr" ]] && continue
      ip route del "$cidr" dev "$IFACE" 2>/dev/null || true
    done <"$CIDR_FILE"
  fi
  ip route flush table "$TABLE" 2>/dev/null || true
}

case "$action" in
  up) add_routes ;;
  down) del_routes ;;
  *) echo "usage: $0 up|down" >&2; exit 1 ;;
esac
