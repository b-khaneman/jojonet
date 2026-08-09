#!/usr/bin/env bash
# Health checks + watchdog actions
# shellcheck shell=bash

ai_iface_up() {
  ip link show "${AI_WARP_IFACE}" >/dev/null 2>&1
}

ai_handshake_ok() {
  local hs
  hs="$(wg show "${AI_WARP_IFACE}" latest handshakes 2>/dev/null | awk 'NF>=2 {print $NF; exit}')"
  if [[ -n "$hs" && "$hs" != "0" ]]; then
    return 0
  fi
  # Fallback: human-readable dump
  wg show "${AI_WARP_IFACE}" 2>/dev/null | grep -qi 'latest handshake'
}

ai_google_routed() {
  ip route get 8.8.8.8 2>/dev/null | grep -q "dev ${AI_WARP_IFACE}"
}

ai_healthcheck() {
  local rc=0
  echo "=== ${AI_WARP_NAME} health ==="
  echo "version : ${AI_WARP_VERSION}"
  echo "iface   : ${AI_WARP_IFACE}"
  echo "mode    : $(cat "${AI_WARP_MODE_FILE}" 2>/dev/null || echo —)"
  echo "conf    : ${AI_WARP_WG_CONF}"
  echo

  if ai_iface_up; then
    ai_log "interface: UP"
  else
    ai_err "interface: DOWN"
    rc=1
  fi

  if systemctl is-active --quiet "wg-quick@${AI_WARP_IFACE}" 2>/dev/null; then
    ai_log "systemd wg-quick@${AI_WARP_IFACE}: active"
  else
    ai_warn "systemd wg-quick@${AI_WARP_IFACE}: inactive"
    rc=1
  fi

  if systemctl is-active --quiet ai-warp-watchdog.timer 2>/dev/null; then
    ai_log "watchdog timer: active"
  else
    ai_warn "watchdog timer: inactive"
  fi

  echo
  if ai_iface_up; then
    wg show "${AI_WARP_IFACE}" 2>/dev/null || true
  fi
  echo
  echo "--- sample routes ---"
  ip route get 8.8.8.8 2>/dev/null || true
  ip route get 142.250.0.1 2>/dev/null || true
  echo

  if ai_handshake_ok; then
    ai_log "handshake: OK"
  else
    ai_warn "handshake: missing/stale"
    rc=1
  fi

  if ai_google_routed; then
    ai_log "Google path via ${AI_WARP_IFACE}: OK"
  else
    ai_warn "Google path NOT via ${AI_WARP_IFACE}"
    rc=1
  fi

  echo
  ai_sticky_status || true
  echo
  if [[ -f "${AI_WARP_CIDR_FILE}" ]]; then
    echo "CIDRs routed: $(wc -l <"${AI_WARP_CIDR_FILE}" | tr -d ' ')"
  fi
  return "$rc"
}

ai_watchdog_tick() {
  # Called by systemd timer — heal silently
  if ! ai_iface_up || ! ai_handshake_ok; then
    logger -t ai-warp "watchdog: tunnel unhealthy — restarting"
    wg-quick down "${AI_WARP_IFACE}" 2>/dev/null || true
    wg-quick up "${AI_WARP_IFACE}" 2>/dev/null || true
    systemctl restart "wg-quick@${AI_WARP_IFACE}" 2>/dev/null || true
    sleep 2
  fi

  if ai_iface_up && ! ai_google_routed; then
    logger -t ai-warp "watchdog: routes missing — re-applying"
    "${AI_WARP_SHARE}/scripts/routes.sh" up 2>/dev/null || true
  fi

  # Refresh sticky last-ip (non-fatal)
  ai_sticky_save >/dev/null 2>&1 || true
}
