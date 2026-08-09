#!/usr/bin/env bash
# Dependency installer for AI-WARP
# shellcheck shell=bash

ai_install_deps() {
  ai_info "Installing system packages…"
  export DEBIAN_FRONTEND=noninteractive

  if ai_have apt-get; then
    apt-get update -qq
    apt-get install -y -qq \
      curl wget jq ca-certificates iproute2 iptables dnsutils \
      wireguard wireguard-tools \
      || apt-get install -y \
           curl wget jq ca-certificates iproute2 iptables dnsutils \
           wireguard wireguard-tools
  elif ai_have dnf; then
    dnf -y install curl wget jq iproute iptables bind-utils wireguard-tools
  elif ai_have yum; then
    yum -y install curl wget jq iproute iptables bind-utils wireguard-tools
  else
    ai_fail "Unsupported distro (need apt/dnf/yum)."
  fi

  # Optional — never fail install if missing
  if ai_have apt-get; then
    apt-get install -y -qq resolvconf 2>/dev/null || true
  fi

  ai_log "Dependencies ready."
}

ai_install_wgcf() {
  local arch ver url tmp mirrors
  if [[ -x "${AI_WARP_WGCF}" ]]; then
    ai_log "wgcf already present: ${AI_WARP_WGCF}"
    return 0
  fi

  arch="$(ai_arch)"
  ai_info "Downloading wgcf (linux_${arch})…"

  ver="$(
    curl -fsSL --connect-timeout 10 --max-time 30 \
      https://api.github.com/repos/ViRb3/wgcf/releases/latest 2>/dev/null \
      | jq -r '.tag_name // empty' || true
  )"
  ver="${ver#v}"
  [[ -n "$ver" ]] || ver="2.2.26"

  mirrors=(
    "https://github.com/ViRb3/wgcf/releases/download/v${ver}/wgcf_${ver}_linux_${arch}"
    "https://ghproxy.net/https://github.com/ViRb3/wgcf/releases/download/v${ver}/wgcf_${ver}_linux_${arch}"
    "https://mirror.ghproxy.com/https://github.com/ViRb3/wgcf/releases/download/v${ver}/wgcf_${ver}_linux_${arch}"
    "https://cdn.jsdelivr.net/gh/ViRb3/wgcf@v${ver}/#fallback"
  )

  tmp="$(mktemp /tmp/wgcf.XXXXXX)"
  for url in "${mirrors[@]}"; do
    [[ "$url" == *fallback* ]] && continue
    ai_warn "Trying: $url"
    if curl -fsSL --connect-timeout 12 --max-time 120 "$url" -o "$tmp" && [[ -s "$tmp" ]]; then
      install -m755 "$tmp" "${AI_WARP_WGCF}"
      rm -f "$tmp"
      ai_log "wgcf installed (v${ver})"
      return 0
    fi
  done
  rm -f "$tmp"
  ai_fail "Failed to download wgcf."
}
