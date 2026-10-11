from __future__ import annotations

import ipaddress
import re
from typing import Any

NAME_RE = re.compile(r"^[^<>\x00-\x1f]{1,40}$")
USER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9._-]{0,31}$")
IFACE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,14}$")
RELAY_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,23}$")
DOMAIN_RE = re.compile(
    r"^(?=.{4,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$"
)
HOST_PORT_RE = re.compile(r"^(.+):(\d{1,5})$")
KEYDIR_RE = re.compile(r"^/etc/jojonet/keys/pair_(?:\d+|\d+_\d+_\d+_\d+)$")
CONF_HEADER_RE = re.compile(r"^==> /etc/jojonet/instances/[^/]+\.conf <==\s*$")
CONF_LINE_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$")
CONF_KEYS = frozenset(
    {
        "Name",
        "TunnelMode",
        "Role",
        "Local_IP",
        "Remote_IP",
        "Subnet_Byte",
        "Tun_IP",
        "Tun_Remote_IP_Raw",
        "Tun_Server_IP",
        "Tun_Client_IP",
        "Suggested_MTU",
        "Ports",
        "TcpPort",
        "KeyDir",
        "GreKey",
        "PaqetYaml",
        "ForwardProto",
        "VxlanVni",
        "VxlanPort",
        "WgPrivateKey",
        "WgPublicKey",
        "WgPeerPublicKey",
        "HyYaml",
        "HyAuth",
        "HySni",
        "HyHopRange",
        "HyHopInterval",
        "HyTlsMode",
        "HyDomain",
        "HyAcmeEmail",
        "HyCertPath",
        "HyKeyPath",
        "RatholeToml",
        "WstunnelCmd",
        "WgObfs",
        "ObfsPort",
        "V6Iface",
        "V6Local",
        "V6Remote",
        "XrayJson",
        "XrayNet",
        "DnsDomain",
        "DnsResolver",
        "DnsMode",
    }
)
HTTPS_RE = re.compile(r"^https://[A-Za-z0-9./_~:?&=%+-]+$")
RESOLVER_HOST_RE = re.compile(
    r"^(?:(?:[0-9]{1,3}\.){3}[0-9]{1,3}|[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?)(?::[0-9]{1,5})?$"
)

XRAY_NETS: tuple[str, ...] = ("tcp", "ws", "grpc")
RELAY_ENGINES: tuple[str, ...] = ("iptables", "gost", "haproxy", "socat", "xray")
RELAY_PROTOS: tuple[str, ...] = ("tcp", "udp", "both")
DNSTT_MODES: tuple[str, ...] = ("doh", "dot", "udp")

SPOOF_UNIT = "jojonet-spoof.service"
SPOOF_MARK = "spoof"

WG_MODES: frozenset[str] = frozenset({"wireguard", "wg_icmp", "wg_faketcp"})
WG_OBFS: dict[str, str] = {"wg_icmp": "icmp", "wg_faketcp": "faketcp"}
SUBNET_KEYDIR_MODES: frozenset[str] = frozenset({"tun_tcp", "paqet"})
XRAY_MODES: frozenset[str] = frozenset({"dokodemo", "xray_reverse"})
V6_MODES: frozenset[str] = frozenset({"sit", "gre6", "ipip6"})
STREAM_MODES: frozenset[str] = frozenset({"dnstt", "icmp"})
IP_KEYDIR_MODES: frozenset[str] = (
    WG_MODES
    | frozenset({"hysteria2", "rathole", "wstunnel"})
    | XRAY_MODES
    | STREAM_MODES
)

SHARED_KEY_FILES: tuple[str, ...] = (
    "private_key.pem",
    "public_key.pem",
    "paqet.secret",
    "hy2.auth",
    "rathole.token",
    "wstunnel.token",
    "udp2raw.key",
    "xray.uuid",
    "dnstt.priv",
    "dnstt.pub",
    "dnstt.auth",
    "pingtunnel.key",
    "pingtunnel.encrypt",
)

MODES: dict[str, dict[str, str]] = {
    "gre": {
        "label": "GRE",
        "first": "kharej",
        "flag": "--peer",
        "desc": "تونل GRE کلاسیک با فوروارد پورت روی ایران.",
    },
    "tun_tcp": {
        "label": "TUN/TCP",
        "first": "kharej",
        "flag": "--tun-tcp",
        "desc": "تونل TUN روی TCP (سبک Backhaul).",
    },
    "paqet": {
        "label": "Paqet",
        "first": "kharej",
        "flag": "--paqet",
        "desc": "تونل Paqet با KCP/Raw.",
    },
    "vxlan": {
        "label": "VXLAN",
        "first": "kharej",
        "flag": "--vxlan",
        "desc": "اورلی VXLAN روی UDP.",
    },
    "wireguard": {
        "label": "WireGuard",
        "first": "kharej",
        "flag": "--wg",
        "desc": "WireGuard کم‌تأخیر روی UDP.",
    },
    "wg_icmp": {
        "label": "WireGuard/ICMP",
        "first": "kharej",
        "flag": "--wg-icmp",
        "desc": "WireGuard داخل ICMP با udp2raw (متفاوت از تانل ICMP مستقل).",
    },
    "wg_faketcp": {
        "label": "WireGuard/FakeTCP",
        "first": "kharej",
        "flag": "--wg-faketcp",
        "desc": "WireGuard داخل TCP جعلی با udp2raw.",
    },
    "hysteria2": {
        "label": "Hysteria2",
        "first": "kharej",
        "flag": "--hy2",
        "desc": "Hysteria2 برای مسیرهای پرتلفات.",
    },
    "rathole": {
        "label": "Rathole",
        "first": "iran",
        "flag": "--rathole",
        "desc": "تونل معکوس TCP؛ سرور روی ایران.",
    },
    "wstunnel": {
        "label": "Wstunnel",
        "first": "iran",
        "flag": "--wstunnel",
        "desc": "تونل معکوس WebSocket؛ سرور روی ایران.",
    },
    "dokodemo": {
        "label": "Xray Dokodemo",
        "first": "kharej",
        "flag": "--dokodemo",
        "desc": "VLESS dokodemo-door؛ ایران به خارج وصل می‌شود.",
    },
    "xray_reverse": {
        "label": "Xray Reverse",
        "first": "iran",
        "flag": "--xray-reverse",
        "desc": "VLESS reverse؛ خارج به پورتال ایران وصل می‌شود.",
    },
    "sit": {
        "label": "6to4 (SIT)",
        "first": "kharej",
        "flag": "--6to4",
        "desc": "لینک IPv6 خصوصی بین دو سرور IPv4.",
    },
    "gre6": {
        "label": "GRE6",
        "first": "kharej",
        "flag": "--gre6",
        "desc": "GRE روی 6to4 با اورلی IPv4 و فوروارد پورت.",
    },
    "ipip6": {
        "label": "IPIP6",
        "first": "kharej",
        "flag": "--ipip6",
        "desc": "IPIP روی 6to4 با اورلی IPv4 و فوروارد پورت.",
    },
    "dnstt": {
        "label": "DNSTT",
        "first": "kharej",
        "flag": "--dnstt",
        "desc": "تونل DNS (DoH/DoT/UDP). رکورد NS دامنه باید روی IP خارج باشد. می‌تواند فقط روی سرور خارج (بدون ایران) اجرا شود.",
    },
    "icmp": {
        "label": "ICMP",
        "first": "kharej",
        "flag": "--icmp",
        "desc": "تونل ICMP با pingtunnel و ChaCha20؛ با WireGuard/ICMP فرق دارد. می‌تواند فقط روی سرور خارج (بدون ایران) اجرا شود.",
    },
    "spoof": {
        "label": "Spoof",
        "first": "kharej",
        "flag": "--spoof",
        "desc": "تونل مستقل با جعل IP؛ فقط روی دیتاسنترهایی که spoof را می‌پذیرند.",
    },
}


def _no_leading_zero_octet(part: str) -> bool:
    return part == "0" or not part.startswith("0")


def valid_ipv4(value: str) -> bool:
    if not isinstance(value, str) or value.count(".") != 3:
        return False
    parts = value.split(".")
    nums: list[int] = []
    for p in parts:
        if not p.isdigit() or not _no_leading_zero_octet(p):
            return False
        n = int(p)
        if n > 255:
            return False
        nums.append(n)
    if nums[0] == 0 or nums[0] == 127 or nums[0] >= 224:
        return False
    return True


def valid_ipv6(value: str) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        ip = ipaddress.IPv6Address(value)
    except ValueError:
        return False
    return not (ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local)


def valid_port_num(n: int) -> bool:
    return 1 <= n <= 65535


def valid_xray_ports(value: str) -> bool:
    if not isinstance(value, str) or not value or len(value) > 120:
        return False
    items = value.split(",")
    if not items or len(items) > 16:
        return False
    seen: set[int] = set()
    for item in items:
        if not item or item.count(":") > 1:
            return False
        if ":" in item:
            a, b = item.split(":")
        else:
            a = b = item
        if not a.isdigit() or not b.isdigit():
            return False
        listen, target = int(a), int(b)
        if not valid_port_num(listen) or not valid_port_num(target) or listen in seen:
            return False
        seen.add(listen)
    return True


def valid_relay_name(value: str) -> bool:
    return isinstance(value, str) and bool(RELAY_NAME_RE.fullmatch(value))


def valid_relay_target(value: str, ipv4_only: bool = False) -> bool:
    if not isinstance(value, str) or not value:
        return False
    if valid_ipv4(value):
        return True
    if ipv4_only:
        return False
    if "." not in value or value.startswith(".") or value.endswith("."):
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", value))


def valid_host_port(value: str) -> bool:
    if not isinstance(value, str):
        return False
    m = HOST_PORT_RE.fullmatch(value)
    if not m:
        return False
    host, port_s = m.group(1), m.group(2)
    port = int(port_s)
    if not valid_port_num(port):
        return False
    if host == "localhost":
        return True
    if host == "0.0.0.0" or host.startswith("0."):
        return False
    if host.count(".") == 3:
        parts = host.split(".")
        try:
            nums = [int(p) for p in parts]
        except ValueError:
            return False
        if any(n < 0 or n > 255 for n in nums):
            return False
        if any(p != "0" and p.startswith("0") for p in parts):
            return False
        if nums[0] >= 224:
            return False
        return True
    return False


def valid_iface(value: Any) -> bool:
    if not isinstance(value, str) or not value or ".." in value or " " in value:
        return False
    return bool(IFACE_RE.fullmatch(value))


def valid_keydir(value: str) -> bool:
    return isinstance(value, str) and bool(KEYDIR_RE.fullmatch(value)) and ".." not in value


def ip_keydir(ip: str) -> str:
    return "/etc/jojonet/keys/pair_" + ip.replace(".", "_")


def valid_dnstt_domain(value: str) -> bool:
    if not isinstance(value, str):
        return False
    v = value.strip().lower().rstrip(".")
    return bool(DOMAIN_RE.fullmatch(v))


def valid_dnstt_resolver(mode: str, value: str) -> bool:
    if not isinstance(value, str) or not value or "\n" in value or "\r" in value:
        return False
    if mode == "doh":
        return bool(HTTPS_RE.fullmatch(value)) and ".." not in value and len(value) <= 200
    if mode not in ("dot", "udp"):
        return False
    if not RESOLVER_HOST_RE.fullmatch(value):
        return False
    host, _, port = value.rpartition(":")
    if port.isdigit():
        if not valid_port_num(int(port)):
            return False
        addr = host
    else:
        addr = value
    if mode == "udp":
        return valid_ipv4(addr) or (
            addr.count(".") == 3 and all(p.isdigit() and 0 <= int(p) <= 255 for p in addr.split("."))
        )
    return valid_ipv4(addr) or bool(DOMAIN_RE.fullmatch(addr)) or addr.count(".") >= 1


def conf_mode(conf: dict[str, str]) -> str:
    mode = (conf.get("TunnelMode") or "gre").strip()
    if mode == "wireguard":
        obfs = (conf.get("WgObfs") or "").strip()
        if obfs:
            return f"wg_{obfs}"
    return mode or "gre"


def split_confs(text: str) -> list[dict[str, str]]:
    if not text:
        return []
    chunks: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if CONF_HEADER_RE.match(line):
            current = {}
            chunks.append(current)
            continue
        if current is None or not line:
            continue
        m = CONF_LINE_RE.match(line)
        if not m:
            continue
        key, val = m.group(1), m.group(2)
        if key not in CONF_KEYS:
            continue
        if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
            val = val[1:-1]
        if any(tok in val for tok in ("$(", "`", ";", "|", "&", "\n", "\r")):
            continue
        current[key] = val
    return chunks
