#!/usr/bin/env bash
# Build allowed-ips.txt from Google CIDRs + resolved AI domains
# shellcheck shell=bash

ai_google_fallback_cidrs() {
  cat <<'EOF'
8.8.8.0/24
8.8.4.0/24
8.34.208.0/20
8.35.192.0/21
34.64.0.0/11
34.96.0.0/12
34.112.0.0/12
34.128.0.0/10
35.184.0.0/13
35.192.0.0/14
35.196.0.0/15
35.198.0.0/16
35.199.0.0/17
35.200.0.0/13
35.208.0.0/12
35.224.0.0/12
35.240.0.0/13
64.233.160.0/19
66.102.0.0/20
66.249.64.0/19
70.32.128.0/19
72.14.192.0/18
74.125.0.0/16
108.177.0.0/17
142.250.0.0/15
172.217.0.0/16
172.253.0.0/16
173.194.0.0/16
192.178.0.0/15
199.36.154.0/23
199.36.156.0/24
207.223.160.0/20
208.81.188.0/22
209.85.128.0/17
216.58.192.0/19
216.239.32.0/19
EOF
}

ai_fetch_google_cidrs() {
  local tmp
  tmp="$(mktemp)"
  if curl -fsSL --connect-timeout 10 --max-time 45 \
      https://www.gstatic.com/ipranges/goog.json -o "$tmp" 2>/dev/null; then
    jq -r '.prefixes[]?.ipv4Prefix // empty' "$tmp" 2>/dev/null \
      | grep -E '^[0-9./]+$' || ai_google_fallback_cidrs
  else
    ai_warn "goog.json unreachable — using built-in Google CIDR fallback."
    ai_google_fallback_cidrs
  fi
  rm -f "$tmp"
}

ai_resolve_domains() {
  local domains_file="${1:-$AI_WARP_DOMAINS}"
  local host ip
  [[ -f "$domains_file" ]] || return 0

  while IFS= read -r host || [[ -n "$host" ]]; do
    host="${host%%#*}"
    host="$(echo "$host" | tr -d '[:space:]')"
    [[ -z "$host" ]] && continue

    # Prefer getent; fall back to dig/host
    if ai_have getent; then
      while IFS= read -r ip; do
        [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && echo "${ip}/32"
      done < <(getent ahostsv4 "$host" 2>/dev/null | awk '{print $1}' | sort -u)
    elif ai_have dig; then
      while IFS= read -r ip; do
        [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && echo "${ip}/32"
      done < <(dig +short A "$host" 2>/dev/null | grep -E '^[0-9.]+$')
    fi
  done <"$domains_file"
}

ai_openai_extra_cidrs() {
  # OpenAI publishes limited hints; keep a small stable set + domain resolve covers rest
  cat <<'EOF'
# placeholder — domains drive OpenAI; Cloudflare anycast varies
EOF
}

ai_build_cidr_list() {
  local mode="${1:-ai}"
  local tmp
  tmp="$(mktemp)"

  ai_info "Building selective route list (mode=${mode})…"

  case "$mode" in
    ai|google|full)
      ai_fetch_google_cidrs >>"$tmp"
      ;;
  esac

  if [[ "$mode" == "ai" || "$mode" == "full" ]]; then
    ai_info "Resolving AI domains (Gemini, Flow, ChatGPT, Claude, …)…"
    ai_resolve_domains "${AI_WARP_DOMAINS}" >>"$tmp"
  elif [[ "$mode" == "google" ]]; then
    local gtmp
    gtmp="$(mktemp)"
    grep -Ei 'google|gstatic|googleapis|android|gradle|labs\.google|deepmind|gemini|notebooklm|aistudio|recaptcha|geller|aisandbox|alkali' \
      "${AI_WARP_DOMAINS}" >"$gtmp" 2>/dev/null || cp -f "${AI_WARP_DOMAINS}" "$gtmp"
    ai_info "Resolving Google / Flow / Android domains…"
    ai_resolve_domains "$gtmp" >>"$tmp"
    rm -f "$gtmp"
  fi

  if [[ "$mode" == "full" ]]; then
    ai_info "Fetching AWS CloudFront prefixes (CDN assets)…"
    local cloud
    cloud="$(mktemp)"
    if curl -fsSL --connect-timeout 10 --max-time 60 \
        https://ip-ranges.amazonaws.com/ip-ranges.json -o "$cloud"; then
      jq -r '.prefixes[] | select(.service=="CLOUDFRONT") | .ip_prefix' "$cloud" \
        2>/dev/null | grep -E '^[0-9./]+$' >>"$tmp" || true
    fi
    rm -f "$cloud"
  fi

  # Never route WARP endpoint / private nets into itself
  grep -E '^[0-9./]+$' "$tmp" \
    | grep -vE '^(10\.|127\.|169\.254\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|162\.159\.192\.1)' \
    | sort -u >"${AI_WARP_CIDR_FILE}"

  rm -f "$tmp"

  local count
  count="$(wc -l <"${AI_WARP_CIDR_FILE}" | tr -d ' ')"
  (( count > 5 )) || ai_fail "CIDR list too small ($count). Check DNS/network."
  echo "$mode" >"${AI_WARP_MODE_FILE}"
  ai_log "Route targets: ${count}"
}
