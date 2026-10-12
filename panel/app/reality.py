"""Reality client material and the Freedom outbound that sends it through a tunnel.

The outbound is Freedom on purpose: it only pins the source address to the tunnel
IP. The config handed to a user is VLESS + Reality, and the inbound JSON uses the
same keys so 3x-ui and the client match.
"""

from __future__ import annotations

import json
import secrets
import uuid
from typing import Any
from urllib.parse import quote, urlencode

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .validators import valid_ipv4

REALITY_SNI = "www.microsoft.com"
REALITY_DEST = "www.microsoft.com:443"
REALITY_FP = "chrome"
REALITY_FLOW = "xtls-rprx-vision"
_PORT_CANDIDATES = (443, 8443, 2053, 2083, 2087, 8444, 9443)


def _b64url(raw: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64url_decode(text: str) -> bytes:
    import base64

    pad = "=" * ((4 - len(text) % 4) % 4)
    return base64.urlsafe_b64decode(text + pad)


def generate_material() -> dict[str, Any]:
    private = X25519PrivateKey.generate()
    raw_private = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    raw_public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return {
        "uuid": str(uuid.uuid4()),
        "privateKey": _b64url(raw_private),
        "publicKey": _b64url(raw_public),
        "shortId": secrets.token_hex(4),
        "subId": secrets.token_hex(8),
        "sni": REALITY_SNI,
    }


def material_ok(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    try:
        uuid.UUID(str(value.get("uuid") or ""))
        private = _b64url_decode(str(value["privateKey"]))
        public = _b64url_decode(str(value["publicKey"]))
    except (KeyError, ValueError, TypeError):
        return False
    if len(private) != 32 or len(public) != 32:
        return False
    derived = X25519PrivateKey.from_private_bytes(private).public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    if derived != public:
        return False
    short_id = str(value.get("shortId") or "")
    if len(short_id) not in (2, 4, 6, 8, 10, 12, 14, 16) or any(c not in "0123456789abcdef" for c in short_id):
        return False
    sub_id = str(value.get("subId") or "")
    if not sub_id or len(sub_id) > 32 or any(c not in "0123456789abcdef" for c in sub_id):
        return False
    if str(value.get("sni") or "") != REALITY_SNI:
        return False
    return True


def used_ports(forward_ports: Any) -> set[int]:
    text = "" if forward_ports is None else str(forward_ports)
    found: set[int] = set()
    for part in text.replace("،", ",").split(","):
        for piece in part.split(":"):
            piece = piece.strip()
            if piece.isdigit():
                port = int(piece)
                if 1 <= port <= 65535:
                    found.add(port)
    return found


def pick_port(used: set[int]) -> int:
    for port in _PORT_CANDIDATES:
        if port not in used:
            return port
    for port in range(20000, 20100):
        if port not in used:
            return port
    return 443


def ip_only(value: Any) -> str:
    text = str(value or "").strip()
    if "/" in text:
        text = text.split("/", 1)[0].strip()
    return text if valid_ipv4(text) else ""


def _side(row: dict[str, Any], iran: dict[str, Any] | None, kharej: dict[str, Any] | None) -> dict[str, str]:
    opts = row.get("options") or {}
    on_kharej = bool(opts.get("direct")) or opts.get("users") == "kharej" or row.get("iran_id") == row.get("kharej_id")
    server = kharej if on_kharej else iran
    send_through = ip_only(row.get("tun_kharej_ip") if on_kharej else row.get("tun_iran_ip"))
    peer = ip_only(row.get("tun_iran_ip") if on_kharej else row.get("tun_kharej_ip"))
    return {
        "role": "خارج" if on_kharej else "ایران",
        "name": str((server or {}).get("name") or ("سرور خارج" if on_kharej else "سرور ایران")),
        "host": ip_only((server or {}).get("host")),
        "send_through": send_through,
        "peer": peer,
    }


def _client_link(address: str, port: int, mat: dict[str, Any], tag: str) -> str:
    query = urlencode(
        {
            "encryption": "none",
            "flow": REALITY_FLOW,
            "security": "reality",
            "sni": mat["sni"],
            "fp": REALITY_FP,
            "pbk": mat["publicKey"],
            "sid": mat["shortId"],
            "spx": "/",
            "type": "tcp",
        },
        quote_via=lambda text, *_args: quote(str(text), safe=""),
    )
    return f"vless://{mat['uuid']}@{address}:{port}?{query}#{quote(tag, safe='')}"


def _inbound(tag: str, port: int, mat: dict[str, Any], inbound_tag: str) -> dict[str, Any]:
    settings = {
        "clients": [{
            "id": mat["uuid"],
            "flow": REALITY_FLOW,
            "email": tag,
            "limitIp": 0,
            "totalGB": 0,
            "expiryTime": 0,
            "enable": True,
            "tgId": "",
            "subId": mat["subId"],
            "comment": "",
            "reset": 0,
        }],
        "decryption": "none",
        "fallbacks": [],
    }
    stream = {
        "network": "tcp",
        "security": "reality",
        "externalProxy": [],
        "realitySettings": {
            "show": False,
            "xver": 0,
            "dest": REALITY_DEST,
            "serverNames": [mat["sni"]],
            "privateKey": mat["privateKey"],
            "minClientVer": "",
            "maxClientVer": "",
            "maxTimeDiff": 0,
            "shortIds": [mat["shortId"]],
            "settings": {
                "publicKey": mat["publicKey"],
                "fingerprint": REALITY_FP,
                "serverName": "",
                "spiderX": "/",
            },
        },
        "tcpSettings": {
            "acceptProxyProtocol": False,
            "header": {"type": "none"},
        },
    }
    sniffing = {
        "enabled": True,
        "destOverride": ["http", "tls", "quic"],
        "metadataOnly": False,
        "routeOnly": False,
    }
    return {
        "remark": tag,
        "enable": True,
        "expiryTime": 0,
        "listen": "",
        "port": port,
        "protocol": "vless",
        "settings": json.dumps(settings, ensure_ascii=False, separators=(",", ":")),
        "streamSettings": json.dumps(stream, ensure_ascii=False, separators=(",", ":")),
        "tag": inbound_tag,
        "sniffing": json.dumps(sniffing, ensure_ascii=False, separators=(",", ":")),
    }


def _client_config(address: str, port: int, mat: dict[str, Any], tag: str) -> dict[str, Any]:
    return {
        "remarks": tag,
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": 10808,
            "protocol": "socks",
            "settings": {"udp": True},
            "tag": "socks",
        }],
        "outbounds": [{
            "protocol": "vless",
            "tag": "proxy",
            "settings": {
                "vnext": [{
                    "address": address,
                    "port": port,
                    "users": [{
                        "id": mat["uuid"],
                        "encryption": "none",
                        "flow": REALITY_FLOW,
                    }],
                }],
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "serverName": mat["sni"],
                    "fingerprint": REALITY_FP,
                    "publicKey": mat["publicKey"],
                    "shortId": mat["shortId"],
                    "spiderX": "/",
                },
            },
        }, {
            "protocol": "freedom",
            "tag": "direct",
        }],
    }


def plan(row: dict[str, Any], iran: dict[str, Any] | None, kharej: dict[str, Any] | None) -> dict[str, Any]:
    """Build the outbound/Reality payload. `_save` is set when the caller must persist keys."""
    opts = row.get("options") or {}
    side = _side(row, iran, kharej)
    base = {
        "tunnel_id": row.get("id"),
        "kind": "ready",
        "tag": f"jojonet-{row.get('id')}",
        "panel_role": side["role"],
        "panel_name": side["name"],
        "panel_host": side["host"],
        "send_through": side["send_through"],
        "peer": side["peer"],
        "address": side["host"],
        "port": None,
        "sni": REALITY_SNI,
        "inbound_tag": "",
        "outbound": None,
        "routing": None,
        "inbound": None,
        "client": None,
        "link": "",
        "uuid": "",
        "public_key": "",
        "private_key": "",
        "short_id": "",
        "_save": None,
    }
    if opts.get("direct") or row.get("iran_id") == row.get("kharej_id"):
        base["kind"] = "direct"
        return base
    mode = str(row.get("mode") or "")
    if mode in ("dokodemo", "xray_reverse"):
        base["kind"] = "xray"
        return base
    if not side["send_through"]:
        base["kind"] = "noip"
        return base

    stored = opts.get("reality") if isinstance(opts.get("reality"), dict) else None
    mat = dict(stored) if material_ok(stored) else generate_material()
    fresh = not material_ok(stored)
    used = used_ports(row.get("forward_ports"))
    try:
        port = int(mat.get("port") or 0)
    except (TypeError, ValueError):
        port = 0
    if port < 1 or port > 65535 or port in used:
        port = pick_port(used)
        fresh = True
    mat["port"] = port
    mat["sni"] = REALITY_SNI
    tag = base["tag"]
    inbound_tag = f"inbound-{port}"
    outbound = {
        "tag": tag,
        "protocol": "freedom",
        "sendThrough": side["send_through"],
        "settings": {"domainStrategy": "AsIs"},
    }
    routing = {
        "type": "field",
        "inboundTag": [inbound_tag],
        "outboundTag": tag,
    }
    base.update({
        "port": port,
        "inbound_tag": inbound_tag,
        "outbound": outbound,
        "routing": routing,
        "uuid": mat["uuid"],
        "public_key": mat["publicKey"],
        "private_key": mat["privateKey"],
        "short_id": mat["shortId"],
        "_save": mat if fresh else None,
    })
    if side["host"]:
        base["inbound"] = _inbound(tag, port, mat, inbound_tag)
        base["client"] = _client_config(side["host"], port, mat, tag)
        base["link"] = _client_link(side["host"], port, mat, tag)
    else:
        base["kind"] = "nohost"
    return base
