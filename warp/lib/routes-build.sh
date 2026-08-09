#!/usr/bin/env bash
# Build allowed-ips.txt from Google CIDRs + resolved AI domains
# CDN-safe: never hijack Cloudflare edge ranges as blocks (panel CDN stays direct).
# /32s resolved from AI hostnames (even if on CF anycast) are kept — required for ChatGPT etc.
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

    if ai_have getent; then
      while IFS= read -r ip; do
        [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && echo "${ip}/32"
      done < <(getent ahostsv4 "$host" 2>/dev/null | awk '{print $1}' | sort -u)
    elif ai_have dig; then
      while IFS= read -r ip; do
        [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && echo "${ip}/32"
      done < <(dig +short +time=2 +tries=1 A "$host" 2>/dev/null | grep -E '^[0-9.]+$')
    fi
  done <"$domains_file" || true
}

ai_cloudflare_blocks() {
  # Official Cloudflare edge ranges — must stay DIRECT for panel CDN / origin.
  # Cached under state for refresh.
  local cache="${AI_WARP_STATE}/cloudflare-ips-v4.txt"
  if [[ ! -s "$cache" ]] || [[ $(( $(date +%s) - $(stat -c %Y "$cache" 2>/dev/null || echo 0) )) -gt 86400 ]]; then
    curl -fsSL --connect-timeout 10 --max-time 30 \
      https://www.cloudflare.com/ips-v4 -o "$cache" 2>/dev/null || true
  fi
  if [[ -s "$cache" ]]; then
    grep -E '^[0-9./]+$' "$cache" || true
  else
    # Minimal well-known CF blocks (fallback)
    cat <<'EOF'
103.21.244.0/22
103.22.200.0/22
103.31.4.0/22
104.16.0.0/13
104.24.0.0/14
108.162.192.0/18
131.0.72.0/22
141.101.64.0/18
162.158.0.0/15
172.64.0.0/13
173.245.48.0/20
188.114.96.0/20
190.93.240.0/20
197.234.240.0/22
198.41.128.0/17
EOF
  fi
}

ai_ip_in_cidr() {
  # Best-effort: only used to drop non-/32 candidates that equal a CF block line.
  # Exact string match of cidr against CF list.
  local cidr="$1"
  grep -Fxq "$cidr" "${AI_WARP_STATE}/cloudflare-ips-v4.txt" 2>/dev/null
}

ai_filter_cdn_safe() {
  local infile="$1" outfile="$2"
  local cf_tmp own_ip cidr
  cf_tmp="$(mktemp)"
  ai_cloudflare_blocks >"$cf_tmp"

  own_ip="$(
    ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}'
  )"

  : >"$outfile"
  while IFS= read -r cidr; do
    [[ -z "$cidr" ]] && continue

    # Drop private / link-local / WARP engage nets
    [[ "$cidr" =~ ^(10\.|127\.|169\.254\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.) ]] && continue
    [[ "$cidr" =~ ^162\.159\. ]] && continue

    # Never blackhole our own public IP via WARP
    if [[ -n "$own_ip" && "$cidr" == "${own_ip}/32" ]]; then
      continue
    fi

    # Drop exact Cloudflare published *blocks* (protect panel CDN).
    # Keep /32 host routes (ChatGPT/Claude often sit on CF anycast).
    if [[ "$cidr" != */32 ]] && grep -Fxq "$cidr" "$cf_tmp" 2>/dev/null; then
      continue
    fi

    echo "$cidr" >>"$outfile"
  done <"$infile"

  rm -f "$cf_tmp"
  sort -u -o "$outfile" "$outfile"
}

ai_build_cidr_list() {
  local mode="${1:-ai}"
  local tmp filtered
  tmp="$(mktemp)"
  filtered="$(mktemp)"

  ai_info "Building selective route list (mode=${mode})…"
  install -d -m700 "${AI_WARP_STATE}"

  case "$mode" in
    ai|google|full)
      ai_fetch_google_cidrs >>"$tmp" || true
      ;;
  esac

  if [[ "$mode" == "ai" || "$mode" == "full" ]]; then
    ai_info "Resolving AI domains (Gemini, Flow, ChatGPT, Claude, …)…"
    ai_resolve_domains "${AI_WARP_DOMAINS}" >>"$tmp" || true
  elif [[ "$mode" == "google" ]]; then
    local gtmp
    gtmp="$(mktemp)"
    grep -Ei 'google|gstatic|googleapis|android|gradle|labs\.google|deepmind|gemini|notebooklm|aistudio|recaptcha|geller|aisandbox|alkali|flow' \
      "${AI_WARP_DOMAINS}" >"$gtmp" 2>/dev/null || cp -f "${AI_WARP_DOMAINS}" "$gtmp"
    ai_info "Resolving Google / Flow / Android domains…"
    ai_resolve_domains "$gtmp" >>"$tmp" || true
    rm -f "$gtmp"
  fi

  if [[ "$mode" == "full" ]]; then
    ai_info "Fetching AWS CloudFront prefixes…"
    local cloud
    cloud="$(mktemp)"
    if curl -fsSL --connect-timeout 10 --max-time 60 \
        https://ip-ranges.amazonaws.com/ip-ranges.json -o "$cloud"; then
      jq -r '.prefixes[] | select(.service=="CLOUDFRONT") | .ip_prefix' "$cloud" \
        2>/dev/null | grep -E '^[0-9./]+$' >>"$tmp" || true
    fi
    rm -f "$cloud"
  fi

  grep -E '^[0-9./]+$' "$tmp" | sort -u >"${tmp}.clean" || true
  ai_filter_cdn_safe "${tmp}.clean" "$filtered"

  # Ensure Google DNS always present as canary
  grep -q '^8\.8\.8\.0/24$' "$filtered" || echo '8.8.8.0/24' >>"$filtered"
  grep -q '^8\.8\.4\.0/24$' "$filtered" || echo '8.8.4.0/24' >>"$filtered"
  sort -u -o "$filtered" "$filtered"

  cp -f "$filtered" "${AI_WARP_CIDR_FILE}"
  rm -f "$tmp" "${tmp}.clean" "$filtered"

  local count
  count="$(wc -l <"${AI_WARP_CIDR_FILE}" | tr -d ' ')"
  if (( count < 5 )); then
    ai_warn "CIDR list small ($count) — seeding Google fallback."
    ai_google_fallback_cidrs >"${AI_WARP_CIDR_FILE}"
    count="$(wc -l <"${AI_WARP_CIDR_FILE}" | tr -d ' ')"
  fi
  (( count >= 5 )) || ai_fail "Could not build route list."
  echo "$mode" >"${AI_WARP_MODE_FILE}"
  ai_log "Route targets: ${count} (CDN Cloudflare blocks excluded)"
}
