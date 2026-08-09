#!/usr/bin/env bash
#
# JojoNet WARP Unlock — Cloudflare WARP (wgcf) selective routing
# Unlocks Gemini / Google AI / Android Studio (403 & region errors)
# on Ubuntu/Debian VPS without changing panel client configs.
#
# Usage (on Kharej / foreign server as root):
#   sudo bash install.sh
#   sudo bash install.sh --install
#   sudo bash install.sh --status
#   sudo bash install.sh --uninstall
#
# Repo: https://github.com/b-khaneman/jojonet
#

set -Eeo pipefail

readonly SCRIPT_VERSION="1.0.0"
readonly IFACE="warp"
readonly WG_DIR="/etc/wireguard"
readonly WG_CONF="${WG_DIR}/${IFACE}.conf"
readonly STATE_DIR="/etc/jojonet/warp"
readonly ACCOUNT_TOML="${STATE_DIR}/wgcf-account.toml"
readonly PROFILE_CONF="${STATE_DIR}/wgcf-profile.conf"
readonly MODE_FILE="${STATE_DIR}/mode"
readonly CIDR_CACHE="${STATE_DIR}/allowed-ips.txt"
readonly WGCF_BIN="/usr/local/bin/wgcf"
readonly ENDPOINT_IP="162.159.192.1"
readonly ENDPOINT_PORT="2408"
readonly MTU="1280"
readonly KEEPALIVE="25"

# Extra hostnames resolved at install/refresh time (Android Studio / AI APIs
# that sometimes sit outside goog.json or need explicit pinning).
readonly EXTRA_HOSTS=(
  gemini.google.com
  aistudio.google.com
  generativelanguage.googleapis.com
  notebooklm.google.com
  bard.google.com
  alkalimakersuite-pa.clients6.google.com
  ai.google.dev
  makersuite.google.com
  dl.google.com
  dl-ssl.google.com
  android.googleapis.com
  android.clients.google.com
  developer.android.com
  maven.google.com
  r8.googlesource.com
  services.gradle.org
  googleapis.com
  oauth2.googleapis.com
  www.googleapis.com
  accounts.google.com
  clients2.google.com
  clients4.google.com
  play.google.com
  gvt1.com
)

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[!]${NC} $*" >&2; }
fail() { err "$*"; exit 1; }
info() { echo -e "${CYAN}[*]${NC} $*"; }

need_root() {
  (( EUID == 0 )) || fail "با root اجرا کن: sudo bash $0"
}

detect_arch() {
  local m
  m=$(uname -m)
  case "$m" in
    x86_64|amd64) echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    armv7l|armhf) echo "armv7" ;;
    *) fail "معماری پشتیبانی نمی‌شود: $m" ;;
  esac
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

install_packages() {
  info "نصب وابستگی‌ها..."
  export DEBIAN_FRONTEND=noninteractive
  if have_cmd apt-get; then
    apt-get update -qq
    apt-get install -y -qq curl wget jq ca-certificates iproute2 iptables \
      wireguard wireguard-tools resolvconf 2>/dev/null \
      || apt-get install -y -qq curl wget jq ca-certificates iproute2 iptables \
           wireguard wireguard-tools
  elif have_cmd dnf; then
    dnf install -y curl wget jq iproute iptables wireguard-tools
  elif have_cmd yum; then
    yum install -y curl wget jq iproute iptables wireguard-tools
  else
    fail "فقط Ubuntu/Debian/CentOS پشتیبانی می‌شود."
  fi
  # resolvconf is optional; never let DNS plugin break the tunnel
  true
}

download_wgcf() {
  local arch ver url tmp mirrors m
  arch=$(detect_arch)
  info "دانلود wgcf برای linux_${arch}..."

  ver=$(curl -fsSL --connect-timeout 10 --max-time 30 \
    https://api.github.com/repos/ViRb3/wgcf/releases/latest 2>/dev/null \
    | jq -r '.tag_name // empty' || true)
  [[ -n "$ver" ]] || ver="v2.2.26"
  ver="${ver#v}"

  mirrors=(
    "https://github.com/ViRb3/wgcf/releases/download/v${ver}/wgcf_${ver}_linux_${arch}"
    "https://ghproxy.net/https://github.com/ViRb3/wgcf/releases/download/v${ver}/wgcf_${ver}_linux_${arch}"
    "https://mirror.ghproxy.com/https://github.com/ViRb3/wgcf/releases/download/v${ver}/wgcf_${ver}_linux_${arch}"
  )

  tmp=$(mktemp /tmp/wgcf.XXXXXX)
  for url in "${mirrors[@]}"; do
    warn "Trying: $url"
    if curl -fsSL --connect-timeout 10 --max-time 120 "$url" -o "$tmp" && [[ -s "$tmp" ]]; then
      install -m755 "$tmp" "$WGCF_BIN"
      rm -f "$tmp"
      log "wgcf نصب شد: $WGCF_BIN (v${ver})"
      return 0
    fi
  done
  rm -f "$tmp"
  fail "دانلود wgcf ناموفق بود."
}

ensure_wgcf() {
  if [[ -x "$WGCF_BIN" ]] || have_cmd wgcf; then
    have_cmd wgcf || ln -sf "$WGCF_BIN" /usr/bin/wgcf 2>/dev/null || true
    [[ -x "$WGCF_BIN" ]] || WGCF_BIN="$(command -v wgcf)"
    return 0
  fi
  download_wgcf
  ln -sf "$WGCF_BIN" /usr/bin/wgcf 2>/dev/null || true
}

register_warp() {
  mkdir -p "$STATE_DIR" "$WG_DIR"
  chmod 700 "$STATE_DIR"

  if [[ -s "$ACCOUNT_TOML" ]]; then
    log "اکانت WARP قبلی پیدا شد: $ACCOUNT_TOML"
  else
    info "ثبت‌نام اکانت رایگان Cloudflare WARP..."
    (
      cd "$STATE_DIR"
      "$WGCF_BIN" register --accept-tos
    )
    [[ -s "$ACCOUNT_TOML" ]] || fail "ثبت‌نام WARP شکست خورد."
    log "اکانت ساخته شد."
  fi

  # Optional WARP+ license: export JOJONET_WARP_LICENSE=xxxx-xxxx-xxxx-xxxx
  if [[ -n "${JOJONET_WARP_LICENSE:-}" ]]; then
    info "اعمال لایسنس WARP+..."
    (
      cd "$STATE_DIR"
      "$WGCF_BIN" update --license-key "$JOJONET_WARP_LICENSE" || warn "آپدیت لایسنس ناموفق بود"
    )
  fi

  info "ساخت پروفایل WireGuard..."
  (
    cd "$STATE_DIR"
    "$WGCF_BIN" generate >/dev/null
    # Older/newer wgcf both write ./wgcf-profile.conf
    [[ -f wgcf-profile.conf ]] && cp -f wgcf-profile.conf "$PROFILE_CONF"
  )
  [[ -s "$PROFILE_CONF" ]] || fail "ساخت پروفایل wgcf شکست خورد."
}

extract_keys() {
  # Reads PrivateKey / PublicKey / Address from wgcf profile
  PRIVATE_KEY=$(awk -F' = ' '/^PrivateKey/{print $2; exit}' "$PROFILE_CONF")
  PEER_PUBLIC_KEY=$(awk -F' = ' '/^PublicKey/{print $2; exit}' "$PROFILE_CONF")
  ADDRESS_LINE=$(awk -F' = ' '/^Address/{print $2; exit}' "$PROFILE_CONF")
  [[ -n "$PRIVATE_KEY" && -n "$PEER_PUBLIC_KEY" && -n "$ADDRESS_LINE" ]] \
    || fail "کلیدهای WireGuard از پروفایل خوانده نشد."

  # IPv4-only address for cheap VPS without IPv6
  ADDRESS_V4=$(echo "$ADDRESS_LINE" | tr ',' '\n' | awk '/\./{gsub(/ /,""); print; exit}')
  [[ -n "$ADDRESS_V4" ]] || ADDRESS_V4="172.16.0.2/32"
}

fetch_google_cidrs() {
  local mode="$1"
  local tmp goog cloud cloud_v4 line ip
  tmp=$(mktemp)

  info "دریافت رنج IPهای رسمی Google..."
  if ! curl -fsSL --connect-timeout 10 --max-time 45 \
      https://www.gstatic.com/ipranges/goog.json -o "$tmp"; then
    warn "دانلود goog.json ناموفق — از لیست پشتیبان استفاده می‌شود."
    cat >"$tmp" <<'EOF'
{"prefixes":[
  {"ipv4Prefix":"8.8.8.0/24"},
  {"ipv4Prefix":"8.8.4.0/24"},
  {"ipv4Prefix":"8.34.208.0/20"},
  {"ipv4Prefix":"8.35.192.0/21"},
  {"ipv4Prefix":"34.64.0.0/11"},
  {"ipv4Prefix":"34.128.0.0/11"},
  {"ipv4Prefix":"35.184.0.0/13"},
  {"ipv4Prefix":"35.192.0.0/14"},
  {"ipv4Prefix":"35.196.0.0/15"},
  {"ipv4Prefix":"35.198.0.0/16"},
  {"ipv4Prefix":"35.199.0.0/17"},
  {"ipv4Prefix":"35.199.128.0/18"},
  {"ipv4Prefix":"35.200.0.0/13"},
  {"ipv4Prefix":"35.208.0.0/12"},
  {"ipv4Prefix":"35.224.0.0/12"},
  {"ipv4Prefix":"35.240.0.0/13"},
  {"ipv4Prefix":"64.233.160.0/19"},
  {"ipv4Prefix":"66.102.0.0/20"},
  {"ipv4Prefix":"66.249.64.0/19"},
  {"ipv4Prefix":"70.32.128.0/19"},
  {"ipv4Prefix":"72.14.192.0/18"},
  {"ipv4Prefix":"74.125.0.0/16"},
  {"ipv4Prefix":"108.177.0.0/17"},
  {"ipv4Prefix":"142.250.0.0/15"},
  {"ipv4Prefix":"172.217.0.0/16"},
  {"ipv4Prefix":"172.253.0.0/16"},
  {"ipv4Prefix":"173.194.0.0/16"},
  {"ipv4Prefix":"192.178.0.0/15"},
  {"ipv4Prefix":"199.36.154.0/23"},
  {"ipv4Prefix":"199.36.156.0/24"},
  {"ipv4Prefix":"207.223.160.0/20"},
  {"ipv4Prefix":"208.81.188.0/22"},
  {"ipv4Prefix":"209.85.128.0/17"},
  {"ipv4Prefix":"216.58.192.0/19"},
  {"ipv4Prefix":"216.239.32.0/19"}
]}
EOF
  fi

  jq -r '.prefixes[]?.ipv4Prefix // empty' "$tmp" 2>/dev/null | grep -E '^[0-9./]+$' | sort -u >"${tmp}.v4" || true

  # Optional CloudFront (some CDN assets for Google/Android)
  if [[ "$mode" == "google-cdn" || "$mode" == "full" ]]; then
    info "افزودن رنج AWS CloudFront..."
    cloud=$(mktemp)
    if curl -fsSL --connect-timeout 10 --max-time 60 \
        https://ip-ranges.amazonaws.com/ip-ranges.json -o "$cloud"; then
      jq -r '.prefixes[] | select(.service=="CLOUDFRONT") | .ip_prefix' "$cloud" \
        2>/dev/null | grep -E '^[0-9./]+$' >>"${tmp}.v4" || true
    fi
    rm -f "$cloud"
  fi

  # Resolve extra hostnames → /32
  info "Resolve کردن دامنه‌های Gemini / Android Studio..."
  for host in "${EXTRA_HOSTS[@]}"; do
    while IFS= read -r ip; do
      [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
      echo "${ip}/32"
    done < <(getent ahostsv4 "$host" 2>/dev/null | awk '{print $1}' | sort -u)
  done >>"${tmp}.v4"

  # YouTube ranges only in full mode (optional — often better left direct)
  if [[ "$mode" == "full" ]]; then
    info "حالت full: رنج‌های گسترده Google (شامل ویدیو)..."
    # goog.json already covers most; add gvt* common ranges
    cat >>"${tmp}.v4" <<'EOF'
172.217.0.0/16
142.250.0.0/15
74.125.0.0/16
EOF
  fi

  sort -u "${tmp}.v4" | grep -vE '^$' >"$CIDR_CACHE"
  rm -f "$tmp" "${tmp}.v4"

  local count
  count=$(wc -l <"$CIDR_CACHE" | tr -d ' ')
  [[ "$count" -gt 5 ]] || fail "لیست AllowedIPs خیلی کوتاه است ($count)."
  log "تعداد رنج/آدرس برای WARP: $count"
}

build_wg_conf() {
  local mode="$1"
  extract_keys
  fetch_google_cidrs "$mode"

  # AllowedIPs = 0.0.0.0/0 is safe here because Table=off means wg-quick
  # will NOT install a default route. Only CIDRs from routes.sh go via WARP.
  umask 077
  cat >"$WG_CONF" <<EOF
# JojoNet WARP Unlock — generated $(date -u +%Y-%m-%dT%H:%M:%SZ)
# Mode: ${mode}
# Selective routing is applied by PostUp (see allowed-ips.txt). Rest stays direct.

[Interface]
PrivateKey = ${PRIVATE_KEY}
Address = ${ADDRESS_V4}
MTU = ${MTU}
Table = off
PostUp = /usr/local/share/jojonet-warp/routes.sh up
PostDown = /usr/local/share/jojonet-warp/routes.sh down

[Peer]
PublicKey = ${PEER_PUBLIC_KEY}
AllowedIPs = 0.0.0.0/0
Endpoint = ${ENDPOINT_IP}:${ENDPOINT_PORT}
PersistentKeepalive = ${KEEPALIVE}
EOF

  echo "$mode" >"$MODE_FILE"
  install_routes_helper
  log "کانفیگ نوشته شد: $WG_CONF"
}

install_routes_helper() {
  local dir="/usr/local/share/jojonet-warp"
  install -d -m755 "$dir"
  cat >"${dir}/routes.sh" <<'ROUTES'
#!/usr/bin/env bash
# Add/remove policy routes for JojoNet WARP interface (Table=off mode).
set -euo pipefail
IFACE="warp"
TABLE="51820"
CIDR_CACHE="/etc/jojonet/warp/allowed-ips.txt"
WG_CONF="/etc/wireguard/warp.conf"

action="${1:-up}"

add_routes() {
  ip route replace default dev "$IFACE" table "$TABLE" 2>/dev/null || \
    ip route add default dev "$IFACE" table "$TABLE" || true
  # Prefer fwmark-free destination-based routing via main table specifics
  if [[ -f "$CIDR_CACHE" ]]; then
    while IFS= read -r cidr; do
      [[ -z "$cidr" ]] && continue
      ip route replace "$cidr" dev "$IFACE" 2>/dev/null || \
        ip route add "$cidr" dev "$IFACE" 2>/dev/null || true
    done <"$CIDR_CACHE"
  fi
  # Ensure rp_filter doesn't drop WARP replies
  sysctl -w "net.ipv4.conf.${IFACE}.rp_filter=0" >/dev/null 2>&1 || true
  sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1 || true
}

del_routes() {
  if [[ -f "$CIDR_CACHE" ]]; then
    while IFS= read -r cidr; do
      [[ -z "$cidr" ]] && continue
      ip route del "$cidr" dev "$IFACE" 2>/dev/null || true
    done <"$CIDR_CACHE"
  fi
  ip route flush table "$TABLE" 2>/dev/null || true
}

case "$action" in
  up) add_routes ;;
  down) del_routes ;;
  *) echo "usage: $0 up|down" >&2; exit 1 ;;
esac
ROUTES
  chmod 755 "${dir}/routes.sh"
}

start_warp() {
  info "راه‌اندازی اینترفیس ${IFACE}..."
  wg-quick down "$IFACE" 2>/dev/null || true
  wg-quick up "$IFACE"
  systemctl enable "wg-quick@${IFACE}" >/dev/null 2>&1 || true
  systemctl restart "wg-quick@${IFACE}" >/dev/null 2>&1 || true
  sleep 1
  if ip link show "$IFACE" >/dev/null 2>&1; then
    log "اینترفیس ${IFACE} بالا آمد."
  else
    fail "اینترفیس ${IFACE} بالا نیامد. لاگ: journalctl -u wg-quick@${IFACE}"
  fi
}

test_connectivity() {
  local google_via warp_ip direct_ip
  info "تست اتصال..."

  if ! wg show "$IFACE" >/dev/null 2>&1; then
    err "WARP بالا نیست."
    return 1
  fi

  # Handshake check
  local hs
  hs=$(wg show "$IFACE" latest handshakes 2>/dev/null | awk '{print $2}')
  if [[ -z "$hs" || "$hs" == "0" ]]; then
    warn "هنوز handshake ندیده‌ایم — چند ثانیه صبر کن و دوباره --status بزن."
  else
    log "WireGuard handshake OK."
  fi

  # Trace a Google IP through WARP iface
  google_via=$(ip route get 8.8.8.8 2>/dev/null | head -1 || true)
  if echo "$google_via" | grep -q "dev ${IFACE}"; then
    log "مسیر 8.8.8.8 از ${IFACE} می‌رود — شنت Google فعال است."
  else
    warn "مسیر 8.8.8.8 از ${IFACE} نیست: $google_via"
    warn "اگر تازه نصب کردی: sudo bash $0 --refresh"
  fi

  # Compare egress (best-effort; may be rate-limited)
  direct_ip=$(curl -4 -fsS --max-time 8 https://ifconfig.me 2>/dev/null || true)
  warp_ip=$(curl -4 -fsS --max-time 8 --interface "$IFACE" https://ifconfig.me 2>/dev/null || true)
  [[ -n "$direct_ip" ]] && info "IP مستقیم سرور: $direct_ip"
  if [[ -n "$warp_ip" ]]; then
    log "IP خروجی WARP: $warp_ip"
  else
    warn "نتوانستیم از روی ${IFACE} IP بگیریم (ممکن است موقتی باشد)."
  fi

  echo
  log "برای کاربران پنل نیازی به تغییر کانفیگ کلاینت نیست."
  log "Gemini / AI Studio / Android Studio از این سرور از IP کلودفلر خارج می‌شوند."
}

do_install() {
  local mode="${1:-google}"
  need_root
  case "$mode" in
    google|google-cdn|full) ;;
    *) fail "حالت نامعتبر: $mode (مجاز: google | google-cdn | full)" ;;
  esac

  echo
  echo "╔══════════════════════════════════════════════════════╗"
  echo "║   JojoNet WARP Unlock v${SCRIPT_VERSION}                        ║"
  echo "║   Gemini / Google AI / Android Studio                ║"
  echo "╚══════════════════════════════════════════════════════╝"
  echo
  info "حالت: $mode"
  info "اینترفیس: $IFACE  |  Endpoint: ${ENDPOINT_IP}:${ENDPOINT_PORT}"
  echo

  install_packages
  ensure_wgcf
  register_warp
  build_wg_conf "$mode"
  start_warp
  test_connectivity

  echo
  log "نصب تمام شد."
  cat <<EOF

دستورات مفید:
  sudo bash $0 --status
  sudo bash $0 --refresh
  sudo bash $0 --uninstall

نکته JojoNet:
  این اسکریپت اینترفیس «${IFACE}» می‌سازد و با تانل‌های JojoNet تداخل ندارد.
  روی سرور خارج (Kharej) نصب کن؛ کاربران پنل بدون تغییر کانفیگ آنلاک می‌شوند.
EOF
}

do_refresh() {
  need_root
  [[ -s "$ACCOUNT_TOML" && -s "$PROFILE_CONF" ]] \
    || fail "اول نصب کن: sudo bash $0 --install"
  local mode
  mode=$(cat "$MODE_FILE" 2>/dev/null || echo google)
  info "به‌روزرسانی رنج IPها (mode=$mode)..."
  ensure_wgcf
  register_warp
  build_wg_conf "$mode"
  start_warp
  test_connectivity
}

do_status() {
  echo "=== JojoNet WARP Unlock status ==="
  echo "version : $SCRIPT_VERSION"
  echo "iface   : $IFACE"
  echo "conf    : $WG_CONF"
  echo "mode    : $(cat "$MODE_FILE" 2>/dev/null || echo '-')"
  echo
  if ip link show "$IFACE" >/dev/null 2>&1; then
    log "link: UP"
  else
    err "link: DOWN"
  fi
  if systemctl is-active --quiet "wg-quick@${IFACE}" 2>/dev/null; then
    log "systemd: active"
  else
    warn "systemd: inactive"
  fi
  echo
  wg show "$IFACE" 2>/dev/null || warn "wg show ناموفق"
  echo
  echo "--- sample Google route ---"
  ip route get 8.8.8.8 2>/dev/null || true
  ip route get 142.250.0.1 2>/dev/null || true
  echo
  if [[ -f "$CIDR_CACHE" ]]; then
    echo "Allowed CIDRs: $(wc -l <"$CIDR_CACHE" | tr -d ' ')"
  fi
  test_connectivity || true
}

do_uninstall() {
  need_root
  info "حذف WARP Unlock..."
  systemctl disable --now "wg-quick@${IFACE}" 2>/dev/null || true
  wg-quick down "$IFACE" 2>/dev/null || true
  rm -f "$WG_CONF"
  rm -rf /usr/local/share/jojonet-warp
  # Keep account by default so reinstall is fast; pass --purge to wipe
  if [[ "${1:-}" == "--purge" ]]; then
    rm -rf "$STATE_DIR"
    log "اکانت و state پاک شد."
  else
    warn "اکانت در $STATE_DIR نگه داشته شد (برای پاک کامل: --uninstall --purge)"
  fi
  log "حذف انجام شد."
}

print_menu() {
  cat <<EOF

  JojoNet WARP Unlock v${SCRIPT_VERSION}
  ─────────────────────────────────────
  1) نصب — فقط Google / Gemini / Android Studio  (پیشنهادی)
  2) نصب — Google + CloudFront CDN
  3) نصب — Google کامل (شامل رنج‌های وسیع‌تر)
  4) وضعیت / تست
  5) به‌روزرسانی رنج IPها
  6) حذف
  0) خروج

EOF
  local c
  read -rp "انتخاب: " c
  case "$c" in
    1) do_install google ;;
    2) do_install google-cdn ;;
    3) do_install full ;;
    4) do_status ;;
    5) do_refresh ;;
    6) do_uninstall ;;
    0) exit 0 ;;
    *) warn "نامعتبر"; exit 1 ;;
  esac
}

usage() {
  cat <<EOF
JojoNet WARP Unlock v${SCRIPT_VERSION}

Usage:
  sudo bash $0                 # منوی تعاملی
  sudo bash $0 --install       # نصب حالت google (پیشنهادی)
  sudo bash $0 --install google-cdn
  sudo bash $0 --install full
  sudo bash $0 --status
  sudo bash $0 --refresh
  sudo bash $0 --uninstall [--purge]
  sudo bash $0 --version

چه کار می‌کند؟
  ترافیک Gemini، Google AI Studio، Android Studio و سرویس‌های Google
  را از روی سرور خارج از طریق Cloudflare WARP رد می‌کند تا خطای
  403 / region رفع شود. بقیه ترافیک مستقیم می‌ماند (حداکثر سرعت).

بدون تغییر کانفیگ پنل (3x-ui / Marzban / Hiddify / ...) کار می‌کند.

اختیاری WARP+:
  export JOJONET_WARP_LICENSE="xxxx-xxxx-xxxx-xxxx"
  sudo -E bash $0 --install
EOF
}

main() {
  case "${1:-}" in
    "" ) need_root; print_menu ;;
    -h|--help) usage ;;
    -v|--version) echo "jojonet-warp ${SCRIPT_VERSION}" ;;
    --install)
      shift || true
      do_install "${1:-google}"
      ;;
    --status) do_status ;;
    --refresh) do_refresh ;;
    --uninstall)
      shift || true
      do_uninstall "${1:-}"
      ;;
    *) usage; exit 1 ;;
  esac
}

main "$@"
