from __future__ import annotations

import ipaddress
import re

MODES: dict[str, dict[str, str]] = {
    "gre": {"flag": "--peer", "first": "kharej", "label": "GRE", "desc": "سریع و سبک؛ مناسب اکثر سرورها (پیش‌فرض)"},
    "tun_tcp": {"flag": "--tun-tcp", "first": "kharej", "label": "TUN / TCP", "desc": "تانل TCP با کلید RSA؛ جایی که GRE بسته است"},
    "paqet": {"flag": "--paqet", "first": "kharej", "label": "Paqet (Raw/KCP)", "desc": "پکت خام + KCP؛ مقاوم در برابر فیلترینگ"},
    "vxlan": {"flag": "--vxlan", "first": "kharej", "label": "VXLAN", "desc": "اورلی لایه ۲ روی UDP"},
    "wireguard": {"flag": "--wg", "first": "kharej", "label": "WireGuard", "desc": "کم‌تأخیر و رمزنگاری‌شده"},
    "wg_icmp": {"flag": "--wg-icmp", "first": "kharej", "label": "WireGuard over ICMP", "desc": "وایرگارد داخل بسته‌های پینگ (udp2raw)؛ وقتی UDP و TCP بسته‌اند ولی پینگ باز است"},
    "wg_faketcp": {"flag": "--wg-faketcp", "first": "kharej", "label": "WireGuard over FakeTCP", "desc": "وایرگارد با ظاهر اتصال TCP (udp2raw)؛ عبور از محدودیت UDP و QoS"},
    "hysteria2": {"flag": "--hy2", "first": "kharej", "label": "Hysteria2", "desc": "سرعت بالا روی QUIC + Hop Port"},
    "rathole": {"flag": "--rathole", "first": "iran", "label": "Rathole Reverse", "desc": "ریورس TCP؛ اتصال از خارج به ایران"},
    "wstunnel": {"flag": "--wstunnel", "first": "iran", "label": "Wstunnel Reverse", "desc": "ریورس WebSocket؛ شبیه ترافیک وب"},
    "dokodemo": {"flag": "--dokodemo", "first": "kharej", "label": "Xray Dokodemo-door", "desc": "ایران به خارج وصل می‌شود؛ VLESS روی tcp/ws/grpc"},
    "xray_reverse": {"flag": "--xray-reverse", "first": "iran", "label": "Xray Reverse", "desc": "خارج به ایران وصل می‌شود؛ مناسب سرورهای ایران‌اکسس"},
    "sit": {"flag": "--6to4", "first": "kharej", "label": "6to4 (SIT IPv6)", "desc": "IPv6 خصوصی بین دو سرور روی پروتکل ۴۱"},
    "gre6": {"flag": "--gre6", "first": "kharej", "label": "GRE6 روی 6to4", "desc": "اورلی IPv4 روی SIT به‌همراه فوروارد پورت"},
    "ipip6": {"flag": "--ipip6", "first": "kharej", "label": "IPIP6 روی 6to4", "desc": "اورلی IPv4 سبک‌تر روی SIT به‌همراه فوروارد پورت"},
    "spoof": {"flag": "--spoof", "first": "kharej", "label": "Spoof Tunnel", "desc": "پایپ UDP با جعل IP مبدأ در دو جهت؛ هر دو دیتاسنتر باید spoof را اجازه دهند"},
}

SPOOF_TRANSPORTS = ("tcp", "udp", "icmp", "icmpv6")
SPOOF_UNIT = "jojonet-spoof.service"
SPOOF_MARK = "spoof"

# Shared-secret files live in the same keydir name pattern on both sides; WG keys are per side.
SHARED_KEY_FILES = (
    "private_key.pem", "public_key.pem", "paqet.secret", "hy2.auth", "rathole.token", "wstunnel.token", "udp2raw.key",
    "xray.uuid",
)
SUBNET_KEYDIR_MODES = {"tun_tcp", "paqet"}
# The panel generates every WireGuard key (and the udp2raw secret) itself, so these skip the post-deploy key sync.
WG_MODES = {"wireguard", "wg_icmp", "wg_faketcp"}
WG_OBFS = {"wg_icmp": "icmp", "wg_faketcp": "faketcp"}
XRAY_MODES = {"dokodemo", "xray_reverse"}
XRAY_NETS = ("tcp", "ws", "grpc")
V6_MODES = {"sit", "gre6", "ipip6"}
IP_KEYDIR_MODES = WG_MODES | {"hysteria2", "rathole", "wstunnel"} | XRAY_MODES
RELAY_ENGINES = ("iptables", "gost", "haproxy", "socat", "xray")
RELAY_PROTOS = ("tcp", "udp", "both")

KEYDIR_RE = re.compile(r"^/etc/jojonet/keys/pair_(?:[0-9]{1,3}(?:_[0-9]{1,3}){3}|[0-9]{1,3})$")
IFACE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")
NAME_RE = re.compile(r"^[^\x00-\x1f\x7f<>]{1,40}$")
USER_RE = re.compile(r"^[a-z_][a-z0-9_.-]{0,31}\$?$", re.IGNORECASE)
CONF_LINE_RE = re.compile(r'^([A-Za-z_][A-Za-z0-9_]*)="([^"\n]*)"$')
PORTS_RE = re.compile(r"^[0-9]{1,5}([,-][0-9]{1,5})*$")
XRAY_PORTS_RE = re.compile(r"^[0-9]{1,5}(:[0-9]{1,5})?(,[0-9]{1,5}(:[0-9]{1,5})?){0,15}$")
RELAY_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,23}$")
DOMAIN_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")


def valid_ipv4(value: str) -> bool:
    try:
        ip = ipaddress.IPv4Address(value)
    except (ipaddress.AddressValueError, ValueError):
        return False
    return str(ip) == value and not (ip.is_unspecified or ip.is_multicast or ip.is_loopback)


def valid_ipv6(value: str) -> bool:
    try:
        ip = ipaddress.IPv6Address(value)
    except (ipaddress.AddressValueError, ValueError):
        return False
    return not (ip.is_unspecified or ip.is_multicast or ip.is_loopback)


def valid_port_number(value: str) -> bool:
    return value.isdigit() and 1 <= int(value) <= 65535


def valid_xray_ports(value: str) -> bool:
    raw = (value or "").replace(" ", "")
    if not raw or not XRAY_PORTS_RE.fullmatch(raw):
        return False
    seen_listen: set[str] = set()
    for item in raw.split(","):
        listen, _, target = item.partition(":")
        if not valid_port_number(listen):
            return False
        if target and not valid_port_number(target):
            return False
        if listen in seen_listen:
            return False
        seen_listen.add(listen)
    return 1 <= len(seen_listen) <= 16


def valid_relay_name(value: str) -> bool:
    return bool(RELAY_NAME_RE.fullmatch(value or ""))


def valid_relay_target(value: str, *, ipv4_only: bool = False) -> bool:
    v = (value or "").strip()
    if valid_ipv4(v):
        return True
    if ipv4_only:
        return False
    return bool(DOMAIN_RE.fullmatch(v) and "." in v and not v.replace(".", "").isdigit())


def valid_host_port(value: str | None) -> bool:
    """HOST:PORT where HOST is an IPv4 address (loopback allowed) or 'localhost'."""
    host, sep, port = (value or "").rpartition(":")
    if not sep or not port.isdigit() or not 1 <= int(port) <= 65535:
        return False
    if host == "localhost":
        return True
    try:
        ip = ipaddress.IPv4Address(host)
    except (ipaddress.AddressValueError, ValueError):
        return False
    return str(ip) == host and not (ip.is_multicast or ip.is_unspecified)


def valid_iface(value: str | None) -> bool:
    return bool(value) and bool(IFACE_RE.fullmatch(value or "")) and value not in {".", ".."}


def valid_keydir(value: str | None) -> bool:
    return bool(value) and bool(KEYDIR_RE.fullmatch(value or ""))


def ip_keydir(peer_ip: str) -> str:
    return "/etc/jojonet/keys/pair_" + peer_ip.replace(".", "_")


def conf_mode(conf: dict[str, str]) -> str:
    """Panel mode of an instance conf: WireGuard variants share TunnelMode and differ by WgObfs."""
    mode = conf.get("TunnelMode") or "gre"
    if mode == "wireguard" and conf.get("WgObfs"):
        return "wg_" + conf["WgObfs"]
    return mode


def parse_conf(text: str) -> dict[str, str]:
    """Parse a jojonet instance conf (KEY="value" lines only; never evaluated)."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        m = CONF_LINE_RE.match(line.strip())
        if m and m.group(1) not in out:
            out[m.group(1)] = m.group(2)
    return out


def split_confs(text: str) -> list[dict[str, str]]:
    """Split the output of the conf dump command (blocks separated by '==> path <==' headers)."""
    confs: list[dict[str, str]] = []
    current: list[str] = []
    started = False
    for line in text.splitlines():
        if line.startswith("==> ") and line.endswith(" <=="):
            if started:
                confs.append(parse_conf("\n".join(current)))
            current = []
            started = True
        elif started:
            current.append(line)
    if started:
        confs.append(parse_conf("\n".join(current)))
    return [c for c in confs if c]
