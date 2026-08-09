#!/usr/bin/env bash
# Sticky / stable egress IP helpers for AI-WARP
# shellcheck shell=bash

ai_warp_egress_ip() {
  # Prefer querying through the WARP interface
  local ip=""
  if ip link show "${AI_WARP_IFACE}" >/dev/null 2>&1; then
    ip="$(curl -4 -fsS --max-time 8 --interface "${AI_WARP_IFACE}" https://ifconfig.me 2>/dev/null || true)"
    [[ -z "$ip" ]] && ip="$(curl -4 -fsS --max-time 8 --interface "${AI_WARP_IFACE}" https://api.ipify.org 2>/dev/null || true)"
  fi
  if [[ -z "$ip" ]]; then
    # Fallback: hit a Google IP that should be routed via WARP
    ip="$(curl -4 -fsS --max-time 8 https://ifconfig.me 2>/dev/null || true)"
  fi
  echo "$ip"
}

ai_sticky_save() {
  local ip
  ip="$(ai_warp_egress_ip)"
  if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "$ip" >"${AI_WARP_LAST_IP}"
    if [[ ! -s "${AI_WARP_STICKY_IP}" ]]; then
      echo "$ip" >"${AI_WARP_STICKY_IP}"
      ai_log "Sticky IP locked: ${ip}"
    fi
    echo "$ip"
    return 0
  fi
  ai_warn "Could not detect WARP egress IP."
  return 1
}

ai_sticky_status() {
  local sticky last current
  sticky="$(cat "${AI_WARP_STICKY_IP}" 2>/dev/null || true)"
  last="$(cat "${AI_WARP_LAST_IP}" 2>/dev/null || true)"
  current="$(ai_warp_egress_ip || true)"

  echo "sticky : ${sticky:-—}"
  echo "last   : ${last:-—}"
  echo "current: ${current:-—}"

  if [[ -n "$sticky" && -n "$current" && "$sticky" == "$current" ]]; then
    ai_log "Egress IP is STABLE (matches sticky lock)."
    return 0
  elif [[ -n "$sticky" && -n "$current" ]]; then
    ai_warn "Egress IP changed: sticky=${sticky} current=${current}"
    ai_warn "Free WARP may rotate IPs. Same account is still used (identity stable)."
    ai_warn "For stronger stickiness set AI_WARP_LICENSE (WARP+)."
    return 1
  fi
  return 0
}

ai_sticky_relock() {
  rm -f "${AI_WARP_STICKY_IP}"
  ai_sticky_save
}
