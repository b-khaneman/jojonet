#!/usr/bin/env bash
# wgcf account + WireGuard profile management
# shellcheck shell=bash

ai_register_warp() {
  install -d -m700 "${AI_WARP_STATE}"
  install -d -m755 "${AI_WARP_WG_DIR}"

  if [[ -s "${AI_WARP_ACCOUNT}" ]]; then
    ai_log "Reusing persistent WARP account (stable identity)."
  else
    ai_info "Registering free Cloudflare WARP account…"
    (
      cd "${AI_WARP_STATE}"
      "${AI_WARP_WGCF}" register --accept-tos
    )
    [[ -s "${AI_WARP_ACCOUNT}" ]] || ai_fail "WARP registration failed."
    ai_log "Account created and persisted at ${AI_WARP_ACCOUNT}"
  fi

  if [[ -n "${AI_WARP_LICENSE:-${JOJONET_WARP_LICENSE:-}}" ]]; then
    local lic="${AI_WARP_LICENSE:-${JOJONET_WARP_LICENSE}}"
    ai_info "Applying WARP+ license…"
    (
      cd "${AI_WARP_STATE}"
      "${AI_WARP_WGCF}" update --license-key "$lic" \
        || ai_warn "License update failed — continuing with free WARP."
    )
  fi

  ai_info "Generating WireGuard profile…"
  (
    cd "${AI_WARP_STATE}"
    "${AI_WARP_WGCF}" generate >/dev/null
    # wgcf writes ./wgcf-profile.conf in STATE dir — already the target path
    if [[ -f wgcf-profile.conf && ! -f "${AI_WARP_PROFILE}" ]]; then
      cp -f wgcf-profile.conf "${AI_WARP_PROFILE}"
    elif [[ -f wgcf-profile.conf ]]; then
      # Ensure canonical name exists even if generate used a different path
      [[ "$(realpath -m wgcf-profile.conf)" == "$(realpath -m "${AI_WARP_PROFILE}")" ]] \
        || cp -f wgcf-profile.conf "${AI_WARP_PROFILE}"
    fi
  )
  [[ -s "${AI_WARP_PROFILE}" ]] || ai_fail "Profile generation failed."
}

ai_extract_keys() {
  AI_WARP_PRIVATE_KEY="$(awk -F' = ' '/^PrivateKey/{print $2; exit}' "${AI_WARP_PROFILE}")"
  AI_WARP_PEER_KEY="$(awk -F' = ' '/^PublicKey/{print $2; exit}' "${AI_WARP_PROFILE}")"
  local addr
  addr="$(awk -F' = ' '/^Address/{print $2; exit}' "${AI_WARP_PROFILE}")"
  AI_WARP_ADDRESS_V4="$(echo "$addr" | tr ',' '\n' | awk '/\./{gsub(/ /,""); print; exit}')"
  [[ -n "${AI_WARP_PRIVATE_KEY}" && -n "${AI_WARP_PEER_KEY}" ]] \
    || ai_fail "Cannot read WireGuard keys from profile."
  [[ -n "${AI_WARP_ADDRESS_V4}" ]] || AI_WARP_ADDRESS_V4="172.16.0.2/32"
}

ai_write_wg_conf() {
  ai_extract_keys
  umask 077
  cat >"${AI_WARP_WG_CONF}" <<EOF
# ${AI_WARP_NAME} v${AI_WARP_VERSION} — generated $(date -u +%Y-%m-%dT%H:%M:%SZ)
# Table=off → no default-route hijack. Selective AI routes via PostUp.

[Interface]
PrivateKey = ${AI_WARP_PRIVATE_KEY}
Address = ${AI_WARP_ADDRESS_V4}
MTU = ${AI_WARP_MTU}
Table = off
PostUp = ${AI_WARP_SHARE}/scripts/routes.sh up
PostDown = ${AI_WARP_SHARE}/scripts/routes.sh down

[Peer]
PublicKey = ${AI_WARP_PEER_KEY}
AllowedIPs = 0.0.0.0/0
Endpoint = ${AI_WARP_ENDPOINT_IP}:${AI_WARP_ENDPOINT_PORT}
PersistentKeepalive = ${AI_WARP_KEEPALIVE}
EOF
  chmod 600 "${AI_WARP_WG_CONF}"
  ai_log "WireGuard config: ${AI_WARP_WG_CONF}"
}
