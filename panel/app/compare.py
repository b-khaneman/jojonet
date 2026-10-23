"""Tunnel path comparison / benchmark (temporary overlays + iperf3/ping)."""

from __future__ import annotations

import json
import re
import shlex
from typing import Any

# Marker lines streamed in job logs for the live UI.
COMPARE_BEGIN = "===== JOJONET_COMPARE ====="
COMPARE_END = "===== END_JOJONET_COMPARE ====="
COMPARE_LINE_RE = re.compile(r"^JN_COMPARE:(.+)$")

# Overlay /udp ports — fallback when busy (like the reference UI).
BASE_UDP_PORT = 40420
IPERF_PORT = 15201

# Modes shown in the compare UI. create_mode maps to panel MODES for «ساخت همین تانل».
COMPARE_MODES: list[dict[str, Any]] = [
    {
        "id": "direct",
        "label": "مسیر مستقیم",
        "create_mode": None,
        "kind": "direct",
        "desc": "بدون تانل؛ سنجش مسیر عمومی بین دو سرور",
    },
    {
        "id": "sit",
        "label": "6to4",
        "create_mode": "sit",
        "kind": "overlay",
        "type": "sit",
        "mtu": 1440,
    },
    {
        "id": "ipip",
        "label": "IPIP",
        "create_mode": None,
        "kind": "overlay",
        "type": "ipip",
        "mtu": 1480,
        "note": "تست موقت کرنل؛ ساخت دائم در پنل هنوز IPIP4 ندارد (نزدیک‌ترین: IPIP6)",
    },
    {
        "id": "sit_udp",
        "label": "6to4 روی UDP",
        "create_mode": None,
        "kind": "overlay",
        "type": "sit_udp",
        "mtu": 1400,
    },
    {
        "id": "gre6",
        "label": "6to4 + GRE6",
        "create_mode": "gre6",
        "kind": "overlay",
        "type": "gre6",
        "mtu": 1400,
    },
    {
        "id": "vxlan",
        "label": "VXLAN",
        "create_mode": "vxlan",
        "kind": "overlay",
        "type": "vxlan",
        "mtu": 1400,
    },
    {
        "id": "geneve",
        "label": "GENEVE",
        "create_mode": None,
        "kind": "overlay",
        "type": "geneve",
        "mtu": 1400,
        "note": "تست موقت؛ ساخت دائم در پنل فعلاً نیست",
    },
    {
        "id": "l2tpv3",
        "label": "L2TPv3",
        "create_mode": None,
        "kind": "overlay",
        "type": "l2tpv3",
        "mtu": 1400,
        "note": "تست موقت؛ ساخت دائم در پنل فعلاً نیست",
    },
    {
        "id": "wireguard",
        "label": "WireGuard",
        "create_mode": "wireguard",
        "kind": "overlay",
        "type": "wireguard",
        "mtu": 1420,
    },
    {
        "id": "tun_tcp",
        "label": "TCP",
        "create_mode": "tun_tcp",
        "kind": "overlay",
        "type": "tun_tcp",
        "mtu": 1400,
    },
    {
        "id": "gre",
        "label": "GRE",
        "create_mode": "gre",
        "kind": "overlay",
        "type": "gre",
        "mtu": 1436,
    },
    {
        "id": "gretap",
        "label": "GRETAP",
        "create_mode": None,
        "kind": "overlay",
        "type": "gretap",
        "mtu": 1400,
        "note": "تست موقت؛ ساخت دائم در پنل فعلاً نیست",
    },
    {
        "id": "ipip6",
        "label": "IPIP6",
        "create_mode": "ipip6",
        "kind": "overlay",
        "type": "ipip6",
        "mtu": 1400,
    },
]


def compare_mode_ids() -> list[str]:
    return [m["id"] for m in COMPARE_MODES]


def compare_public_catalog() -> list[dict[str, Any]]:
    return [
        {
            "id": m["id"],
            "label": m["label"],
            "create_mode": m.get("create_mode"),
            "note": m.get("note") or "",
        }
        for m in COMPARE_MODES
    ]


def parse_compare_line(line: str) -> dict[str, Any] | None:
    m = COMPARE_LINE_RE.match((line or "").strip())
    if not m:
        return None
    try:
        data = json.loads(m.group(1))
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def emit_result(payload: dict[str, Any]) -> str:
    return "JN_COMPARE:" + json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def ensure_tools_script() -> str:
    return r"""
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
need=()
command -v ip >/dev/null 2>&1 || need+=(iproute2)
command -v ping >/dev/null 2>&1 || need+=(iputils-ping)
command -v iperf3 >/dev/null 2>&1 || need+=(iperf3)
command -v jq >/dev/null 2>&1 || need+=(jq)
command -v wg >/dev/null 2>&1 || need+=(wireguard-tools)
if ((${#need[@]})); then
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq </dev/null || true
    apt-get install -y -qq "${need[@]}" </dev/null || true
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y -q "${need[@]}" || true
  fi
fi
command -v iperf3 >/dev/null 2>&1 || { echo "iperf3 missing"; exit 2; }
command -v ip >/dev/null 2>&1 || { echo "ip missing"; exit 2; }
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1 || true
echo TOOLS_OK
"""


def cleanup_script() -> str:
    return r"""
set +e
pkill -f 'iperf3 -s -p 15201' >/dev/null 2>&1 || true
pkill -f 'jncmp-tcp' >/dev/null 2>&1 || true
for d in $(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1 | grep -E '^jncmp'); do
  ip link del "$d" 2>/dev/null || true
done
ip l2tp show tunnel 2>/dev/null | awk '/Tunnel/{print $2}' | while read -r tid; do
  [[ "$tid" =~ ^9[0-9]{3}$ ]] && ip l2tp del tunnel tunnel_id "$tid" 2>/dev/null || true
done
rm -f /tmp/jncmp-*.conf /tmp/jncmp-*.key /tmp/jncmp-*.pub 2>/dev/null
echo CLEAN_OK
"""


def pick_udp_port_script(preferred: int) -> str:
    p = int(preferred)
    return f"""
set -euo pipefail
pref={p}
for try in "$pref" $((pref+1)) $((pref+2)) $((pref+3)) $((pref+4)); do
  if ! ss -uln 2>/dev/null | awk '{{print $4}}' | grep -Eq "[:.]${{try}}$"; then
    echo "$try"
    exit 0
  fi
done
echo "$pref"
"""


def measure_script(*, target: str, count: int = 20, iperf_sec: int = 6) -> str:
    """Run on Iran (client). target = overlay or public IP of Kharej (IPv4 or IPv6)."""
    t = shlex.quote(target)
    return f"""
set -euo pipefail
TARGET={t}
COUNT={int(count)}
SEC={int(iperf_sec)}
IPERF_PORT={IPERF_PORT}

PING_BIN=(ping -n)
IPERF_FAM=()
if [[ "$TARGET" == *:* ]]; then
  PING_BIN=(ping -6 -n)
  IPERF_FAM=(-6)
fi

ping_out=$("${{PING_BIN[@]}}" -c "$COUNT" -W 2 "$TARGET" 2>&1 || true)
loss=$(printf '%s\\n' "$ping_out" | sed -n 's/.*, \\([0-9.]\\+%\\) packet loss.*/\\1/p' | tr -d '%' | head -1)
rtt=$(printf '%s\\n' "$ping_out" | sed -n 's/.*= \\([0-9.]\\+\\)\\/\\([0-9.]\\+\\)\\/\\([0-9.]\\+\\)\\/\\([0-9.]\\+\\).*/\\1 \\2 \\3 \\4/p' | tail -1)
min_ms=$(echo "$rtt" | awk '{{print $1+0}}')
avg_ms=$(echo "$rtt" | awk '{{print $2+0}}')
max_ms=$(echo "$rtt" | awk '{{print $3+0}}')
mdev_ms=$(echo "$rtt" | awk '{{print $4+0}}')
[[ -n "$loss" ]] || loss=100

dl_mbps=0
ul_mbps=0
# download: server sends to client (-R)
dl_json=$(iperf3 "${{IPERF_FAM[@]}}" -c "$TARGET" -p "$IPERF_PORT" -t "$SEC" -J -R 2>/dev/null || true)
ul_json=$(iperf3 "${{IPERF_FAM[@]}}" -c "$TARGET" -p "$IPERF_PORT" -t "$SEC" -J 2>/dev/null || true)
if command -v jq >/dev/null 2>&1; then
  dl_mbps=$(printf '%s' "$dl_json" | jq -r '.end.sum_received.bits_per_second // .end.sum_sent.bits_per_second // 0' 2>/dev/null || echo 0)
  ul_mbps=$(printf '%s' "$ul_json" | jq -r '.end.sum_sent.bits_per_second // 0' 2>/dev/null || echo 0)
  dl_mbps=$(awk -v b="$dl_mbps" 'BEGIN{{printf "%.1f", (b+0)/1000000}}')
  ul_mbps=$(awk -v b="$ul_mbps" 'BEGIN{{printf "%.1f", (b+0)/1000000}}')
fi

reachable=0
if "${{PING_BIN[@]}}" -c 1 -W 2 "$TARGET" >/dev/null 2>&1; then reachable=1; fi

printf 'MEASURE ok=%s loss=%s ping=%s jitter=%s dl=%s ul=%s\\n' \\
  "$reachable" "$loss" "$avg_ms" "$mdev_ms" "$dl_mbps" "$ul_mbps"
"""


def start_iperf_server_script() -> str:
    return f"""
set -euo pipefail
pkill -f 'iperf3 -s -p {IPERF_PORT}' >/dev/null 2>&1 || true
iperf3 -s -p {IPERF_PORT} -D
sleep 0.3
echo IPERF_UP
"""


def stop_iperf_server_script() -> str:
    return f"""
set +e
pkill -f 'iperf3 -s -p {IPERF_PORT}' >/dev/null 2>&1 || true
echo IPERF_DOWN
"""


def setup_overlay_script(
    *,
    mode_type: str,
    role: str,
    local_ip: str,
    peer_ip: str,
    udp_port: int,
    mtu: int,
    wg_priv: str = "",
    wg_peer_pub: str = "",
) -> str:
    """Build temporary jncmp* interface. role=kharej gets .1, iran gets .2."""
    loc = shlex.quote(local_ip)
    rem = shlex.quote(peer_ip)
    port = int(udp_port)
    mtu_i = int(mtu)
    is_kh = role == "kharej"
    ov = "10.66.200.1/30" if is_kh else "10.66.200.2/30"
    ov6_local = "fd6a:cmp::1/64" if is_kh else "fd6a:cmp::2/64"
    ov6_peer = "fd6a:cmp::2" if is_kh else "fd6a:cmp::1"
    tid = 9001 if is_kh else 9002
    sid = 1 if is_kh else 2
    peer_sid = 2 if is_kh else 1
    wg_priv_q = shlex.quote(wg_priv)
    wg_pub_q = shlex.quote(wg_peer_pub)

    return f"""
set -euo pipefail
LOCAL={loc}
PEER={rem}
PORT={port}
MTU={mtu_i}
OV={shlex.quote(ov)}
ROLE={shlex.quote(role)}
TYPE={shlex.quote(mode_type)}

# cleanup previous
ip link del jncmp 2>/dev/null || true
ip link del jncmp6 2>/dev/null || true
ip link del jncmpsit 2>/dev/null || true
ip link del jncmpwg 2>/dev/null || true
ip l2tp del tunnel tunnel_id {tid} 2>/dev/null || true
ip l2tp del tunnel tunnel_id 9001 2>/dev/null || true
ip l2tp del tunnel tunnel_id 9002 2>/dev/null || true

note=""
case "$TYPE" in
  direct)
    echo SETUP ok=1 if=none ov=$PEER note=
    exit 0
    ;;
  gre)
    ip link add jncmp type gre remote "$PEER" local "$LOCAL" ttl 255
    ip addr add "$OV" dev jncmp
    ip link set jncmp mtu "$MTU" up
    echo SETUP ok=1 if=jncmp ov=${{OV%%/*}} note=
    ;;
  gretap)
    ip link add jncmp type gretap remote "$PEER" local "$LOCAL" ttl 255
    ip addr add "$OV" dev jncmp
    ip link set jncmp mtu "$MTU" up
    echo SETUP ok=1 if=jncmp ov=${{OV%%/*}} note=
    ;;
  ipip)
    ip link add jncmp type ipip remote "$PEER" local "$LOCAL" ttl 255
    ip addr add "$OV" dev jncmp
    ip link set jncmp mtu "$MTU" up
    echo SETUP ok=1 if=jncmp ov=${{OV%%/*}} note=
    ;;
  sit)
    ip link add jncmpsit type sit remote "$PEER" local "$LOCAL" ttl 255
    ip link set jncmpsit up
    ip -6 addr add {ov6_local} dev jncmpsit
    ip link set jncmpsit mtu "$MTU"
    # measure over v4 overlay via sit peer mapping: use nested ipip6-like — put v4 on sit via 6to4 style
    # For speedtest use IPv6 endpoint
    echo SETUP ok=1 if=jncmpsit ov={ov6_peer} note=
    ;;
  sit_udp)
    # FOU/GUE may be unavailable; fall back to VXLAN on chosen UDP port
    if ip link add jncmp type vxlan id 4042 remote "$PEER" local "$LOCAL" dstport "$PORT" 2>/dev/null; then
      note="روی VXLAN UDP $PORT"
    else
      echo SETUP ok=0 if= none ov= note="کرنل VXLAN/FOU پشتیبانی نمی‌کند"
      exit 0
    fi
    ip addr add "$OV" dev jncmp
    ip link set jncmp mtu "$MTU" up
    echo SETUP ok=1 if=jncmp ov=${{OV%%/*}} note="$note"
    ;;
  vxlan)
    ip link add jncmp type vxlan id 4042 remote "$PEER" local "$LOCAL" dstport "$PORT" || {{
      alt=$((PORT+1)); note="پورت $PORT مشغول بود، روی $alt تست شد"
      ip link add jncmp type vxlan id 4042 remote "$PEER" local "$LOCAL" dstport "$alt"
      PORT=$alt
    }}
    ip addr add "$OV" dev jncmp
    ip link set jncmp mtu "$MTU" up
    echo SETUP ok=1 if=jncmp ov=${{OV%%/*}} note="$note"
    ;;
  geneve)
    ip link add jncmp type geneve id 4042 remote "$PEER" || {{
      echo SETUP ok=0 if=none ov= note="کرنل GENEVE پشتیبانی نمی‌کند"
      exit 0
    }}
    # geneve remote-only; bind via route
    ip addr add "$OV" dev jncmp
    ip link set jncmp mtu "$MTU" up
    echo SETUP ok=1 if=jncmp ov=${{OV%%/*}} note=
    ;;
  gre6)
    ip link add jncmpsit type sit remote "$PEER" local "$LOCAL" ttl 255
    ip link set jncmpsit up
    ip -6 addr add {ov6_local} dev jncmpsit
    ip link add jncmp type ip6gre remote {ov6_peer} local ${{ov6_local%%/*}} ttl 64 || {{
      echo SETUP ok=0 if=none ov= note="ساخت GRE6 ناموفق"
      exit 0
    }}
    ip addr add "$OV" dev jncmp
    ip link set jncmp mtu "$MTU" up
    echo SETUP ok=1 if=jncmp ov=${{OV%%/*}} note=
    ;;
  ipip6)
    ip link add jncmpsit type sit remote "$PEER" local "$LOCAL" ttl 255
    ip link set jncmpsit up
    ip -6 addr add {ov6_local} dev jncmpsit
    ip link add jncmp type ip6tnl mode ipip6 remote {ov6_peer} local ${{ov6_local%%/*}} || {{
      echo SETUP ok=0 if=none ov= note="ساخت IPIP6 ناموفق"
      exit 0
    }}
    ip addr add "$OV" dev jncmp
    ip link set jncmp mtu "$MTU" up
    echo SETUP ok=1 if=jncmp ov=${{OV%%/*}} note=
    ;;
  l2tpv3)
    ip l2tp add tunnel tunnel_id {tid} remote "$PEER" local "$LOCAL" encap udp udp_sport "$PORT" udp_dport "$PORT" || {{
      echo SETUP ok=0 if=none ov= note="ساخت L2TPv3 ناموفق (ماژول/پورت)"
      exit 0
    }}
    ip l2tp add session name jncmp tunnel_id {tid} session_id {sid} peer_session_id {peer_sid} || {{
      echo SETUP ok=0 if=none ov= note="سشن L2TPv3 ناموفق"
      exit 0
    }}
    ip addr add "$OV" dev jncmp
    ip link set jncmp mtu "$MTU" up
    echo SETUP ok=1 if=jncmp ov=${{OV%%/*}} note=
    ;;
  wireguard)
    command -v wg >/dev/null 2>&1 || {{ echo SETUP ok=0 if=none ov= note="wireguard-tools نیست"; exit 0; }}
    PRIV={wg_priv_q}
    PEERPUB={wg_pub_q}
    [[ -n "$PRIV" && -n "$PEERPUB" ]] || {{ echo SETUP ok=0 if=none ov= note="کلید WG ناقص"; exit 0; }}
    ip link add jncmpwg type wireguard
    echo "$PRIV" > /tmp/jncmp-wg.key
    chmod 600 /tmp/jncmp-wg.key
    wg set jncmpwg private-key /tmp/jncmp-wg.key peer "$PEERPUB" allowed-ips 10.66.200.0/30 endpoint "$PEER:$PORT" persistent-keepalive 15
    ip addr add "$OV" dev jncmpwg
    ip link set jncmpwg mtu "$MTU" up
    echo SETUP ok=1 if=jncmpwg ov=${{OV%%/*}} note=
    ;;
  tun_tcp)
    # Lightweight TCP forwarder with socat/ncat if present; else fail soft
    if command -v socat >/dev/null 2>&1; then
      if [[ "$ROLE" == "kharej" ]]; then
        pkill -f 'jncmp-tcp' >/dev/null 2>&1 || true
        # expose iperf via TCP wrapper on public :15202 — measure still uses overlay-like path through public TCP
        echo SETUP ok=1 if=tcp ov=$PEER note="سنجش TCP روی مسیر عمومی (سبک)"
      else
        echo SETUP ok=1 if=tcp ov=$PEER note="سنجش TCP روی مسیر عمومی (سبک)"
      fi
    else
      echo SETUP ok=1 if=tcp ov=$PEER note="سنجش TCP مستقیم (socat نبود)"
    fi
    ;;
  *)
    echo SETUP ok=0 if=none ov= note="حالت ناشناخته"
    ;;
esac
"""


def parse_setup_line(text: str) -> dict[str, Any]:
    out: dict[str, Any] = {"ok": False, "if": "", "ov": "", "note": ""}
    for line in (text or "").splitlines():
        if not line.startswith("SETUP "):
            continue
        for tok in line[6:].split():
            if "=" in tok:
                k, v = tok.split("=", 1)
                out[k] = v
        out["ok"] = str(out.get("ok", "0")) in ("1", "true", "True")
        return out
    return out


def parse_measure_line(text: str) -> dict[str, Any]:
    out = {
        "ok": False,
        "loss": 100.0,
        "ping": None,
        "jitter": None,
        "download_mbps": 0.0,
        "upload_mbps": 0.0,
    }
    for line in (text or "").splitlines():
        if not line.startswith("MEASURE "):
            continue
        kv = {}
        for tok in line[8:].split():
            if "=" in tok:
                k, v = tok.split("=", 1)
                kv[k] = v
        out["ok"] = kv.get("ok", "0") == "1"
        try:
            out["loss"] = float(kv.get("loss") or 100)
        except ValueError:
            out["loss"] = 100.0
        try:
            out["ping"] = float(kv.get("ping") or 0) or None
        except ValueError:
            out["ping"] = None
        try:
            out["jitter"] = float(kv.get("jitter") or 0) or None
        except ValueError:
            out["jitter"] = None
        try:
            out["download_mbps"] = float(kv.get("dl") or 0)
        except ValueError:
            out["download_mbps"] = 0.0
        try:
            out["upload_mbps"] = float(kv.get("ul") or 0)
        except ValueError:
            out["upload_mbps"] = 0.0
        return out
    return out


def rank_key(row: dict[str, Any]) -> tuple:
    if not row.get("ok"):
        return (1, 0.0, 9999.0)
    return (0, -float(row.get("download_mbps") or 0), float(row.get("ping") or 9999))


def build_summary(results: list[dict[str, Any]], peer_label: str) -> dict[str, Any]:
    ok_rows = [r for r in results if r.get("ok")]
    connected = len(ok_rows)
    total = len(results)
    best = sorted(ok_rows, key=rank_key)[0] if ok_rows else None
    return {
        "peer_label": peer_label,
        "connected": connected,
        "measured": connected,
        "total": total,
        "best": best,
        "results": sorted(results, key=rank_key),
    }
