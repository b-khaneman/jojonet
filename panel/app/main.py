from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import re
import socket
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Literal
from urllib.parse import parse_qs

from fastapi import Depends, FastAPI, HTTPException, Request, Response, WebSocket
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator
from starlette.middleware.gzip import GZipMiddleware
from starlette.types import ASGIApp, Receive, Scope, Send

from . import PANEL_VERSION
from .config import PanelEntry, Settings, load_settings, normalize_base_path, write_listen
from .guide import delete_guide_article, guide_public_view, write_guide_article
from .tlsinfo import build_ssl_view, normalize_domain, normalize_email, write_ssl_request
from . import mail as mail_mod
from . import wallet as wallet_mod
from .db import Database, utcnow
from .jobs import JobManager
from .orchestrator import (
    DELETE_STEPS,
    DEPLOY_STEPS,
    DNS_STEPS,
    ENABLE_BOOT_STEPS,
    INSTALL_STEPS,
    OS_UPDATE_STEPS,
    PING_TEST_STEPS,
    REMOTE_DELETE_STEPS,
    SERVER_SSL_STEPS,
    VPN_PANEL_LABELS,
    VPN_PANEL_STEPS,
    vpn_panel_already,
    vpn_panel_conflict,
    RELAY_DELETE_STEPS,
    RELAY_STATS_STEPS,
    RELAY_STEPS,
    SPOOF_CHECK_STEPS,
    TEST_STEPS,
    VERIFY_STEPS,
    Orchestrator,
    bundle_version,
)
from .security import (
    DUMMY_HASH,
    Vault,
    clear_login_failures,
    hash_password,
    login_allowed,
    new_token,
    random_password,
    record_login_failure,
    token_hash,
    verify_password,
)
from .terminal import run_web_shell
from .validators import (
    DNSTT_MODES,
    MODES,
    NAME_RE,
    RELAY_ENGINES,
    RELAY_PROTOS,
    STREAM_MODES,
    USER_RE,
    V6_MODES,
    XRAY_MODES,
    XRAY_NETS,
    valid_dnstt_domain,
    valid_dnstt_resolver,
    valid_host_port,
    valid_iface,
    valid_ipv4,
    valid_relay_name,
    valid_relay_target,
    valid_xray_ports,
)

COOKIE = "jn_session"
MAX_BODY_BYTES = 1_048_576
log = logging.getLogger("jojonet_panel")
STATIC_ASSETS = ("index.html", "app.js", "style.css", "logo.svg")
# SSE must not be buffered by the compressor; responses carrying the CSRF token stay uncompressed (BREACH).
GZIP_SKIP_PATHS = ("/api/me", "/api/login")


class SelectiveGZip:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app
        self.gzip = GZipMiddleware(app, minimum_size=512, compresslevel=6)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        path = scope.get("path", "") if scope["type"] == "http" else ""
        if path and not path.endswith("/stream") and path not in GZIP_SKIP_PATHS:
            await self.gzip(scope, receive, send)
        else:
            await self.app(scope, receive, send)


class SecretPathGate:
    """Drop every request that is not under the secret panel path. Bare IP returns an empty 404."""

    def __init__(self, app: ASGIApp, entry: PanelEntry, domain: str = "") -> None:
        self.app = app
        self.entry = entry
        self.domain = (domain or "").strip().lower().rstrip(".")

    def _allowed(self, path: str) -> bool:
        base = self.entry.path
        if len(path) < len(base):
            return False
        head = path[: len(base)]
        if not hmac.compare_digest(head.encode(), base.encode()):
            return False
        return len(path) == len(base) or path[len(base)] == "/"

    def _request_host(self, scope: Scope) -> str:
        for key, value in scope.get("headers") or []:
            if key == b"host":
                host = value.decode("latin-1", "ignore").strip().lower()
                if host.startswith("["):
                    return host.split("]", 1)[0] + "]"
                name, sep, port = host.rpartition(":")
                return name if sep and port.isdigit() else host
        return ""

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return
        path = scope.get("path") or "/"
        raw = path.lower()
        base = self.entry.path
        if ".." in path or "\\" in path or "%2e" in raw or "%2f" in raw or not self._allowed(path):
            if (
                scope["type"] == "http"
                and self.domain
                and path in ("/", "")
                and self._request_host(scope) == self.domain
            ):
                await self._redirect_root(scope, send)
                return
            await self._deny(scope, send)
            return
        rest = path[len(base) :] or "/"
        if not rest.startswith("/"):
            rest = "/" + rest
        forwarded = dict(scope)
        forwarded["path"] = rest
        raw_path = scope.get("raw_path") or b""
        base_bytes = base.encode("ascii")
        if raw_path.startswith(base_bytes):
            forwarded["raw_path"] = raw_path[len(base_bytes) :] or b"/"
        await self.app(forwarded, receive, send)

    async def _redirect_root(self, scope: Scope, send: Send) -> None:
        loc = f"https://{self.domain}{self.entry.path}/".encode("ascii", "replace")
        await send({
            "type": "http.response.start",
            "status": 301,
            "headers": [
                (b"location", loc),
                (b"content-length", b"0"),
                (b"cache-control", b"no-store"),
                (b"strict-transport-security", b"max-age=31536000; includeSubDomains"),
                (b"x-content-type-options", b"nosniff"),
                (b"x-robots-tag", b"noindex, nofollow"),
            ],
        })
        await send({"type": "http.response.body", "body": b""})

    async def _deny(self, scope: Scope, send: Send) -> None:
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
            return
        await send({
            "type": "http.response.start",
            "status": 404,
            "headers": [
                (b"content-type", b"text/plain; charset=utf-8"),
                (b"content-length", b"0"),
                (b"cache-control", b"no-store"),
                (b"x-content-type-options", b"nosniff"),
                (b"x-frame-options", b"DENY"),
                (b"referrer-policy", b"no-referrer"),
                (b"x-robots-tag", b"noindex, nofollow"),
            ],
        })
        await send({"type": "http.response.body", "body": b""})


class VersionedStaticFiles(StaticFiles):
    """URLs carrying the current ?v=<hash> never change content, so browsers may keep them for a year."""

    def __init__(self, *args: Any, version: Callable[[], str], **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._version = version

    async def get_response(self, path: str, scope: Scope) -> Response:
        response = await super().get_response(path, scope)
        if response.status_code in (200, 304):
            v = parse_qs(scope.get("query_string", b"").decode("latin-1")).get("v", [""])[0]
            response.headers["Cache-Control"] = (
                "public, max-age=31536000, immutable" if v and v == self._version() else "no-cache"
            )
        return response
CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
    "connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
)


# ---------- request models ----------
class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class PasswordIn(BaseModel):
    old_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=10, max_length=256)


class UsernameIn(BaseModel):
    username: str = Field(min_length=1, max_length=32)
    password: str = Field(min_length=1, max_length=256)

    @field_validator("username")
    @classmethod
    def _username(cls, v: str) -> str:
        v = v.strip()
        if not USER_RE.fullmatch(v) or v.endswith("$"):
            raise ValueError("نام کاربری نامعتبر است")
        return v


class EmailIn(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=256)

    @field_validator("email")
    @classmethod
    def _email(cls, v: str) -> str:
        try:
            value = normalize_email(v)
        except ValueError as exc:
            raise ValueError(str(exc)) from exc
        if not value:
            raise ValueError("ایمیل را وارد کنید")
        return value


class ForgotPasswordIn(BaseModel):
    email: str | None = Field(default=None, max_length=254)
    username: str | None = Field(default=None, max_length=64)

    @model_validator(mode="after")
    def _one(self) -> ForgotPasswordIn:
        email = (self.email or "").strip()
        username = (self.username or "").strip()
        if not email and not username:
            raise ValueError("ایمیل یا نام کاربری را وارد کنید")
        if email:
            try:
                self.email = normalize_email(email)
            except ValueError as exc:
                raise ValueError(str(exc)) from exc
            if not self.email:
                raise ValueError("ایمیل نامعتبر است")
        else:
            self.email = None
        self.username = username.lower() if username else None
        return self


class ResetPasswordIn(BaseModel):
    token: str = Field(min_length=20, max_length=200)
    password: str = Field(min_length=10, max_length=256)


class SmtpTestIn(BaseModel):
    to: str | None = Field(default=None, max_length=254)

    @field_validator("to")
    @classmethod
    def _to(cls, v: str | None) -> str | None:
        if v is None or not str(v).strip():
            return None
        try:
            value = normalize_email(v)
        except ValueError as exc:
            raise ValueError(str(exc)) from exc
        if not value:
            raise ValueError("ایمیل نامعتبر است")
        return value


class VpnPanelIn(BaseModel):
    kind: Literal["xui", "xui_classic", "pasarguard"]


class ServerIn(BaseModel):
    name: str
    role: Literal["iran", "kharej"]
    host: str
    port: int = Field(default=22, ge=1, le=65535)
    username: str = "root"
    auth_type: Literal["password", "key"] = "password"
    password: str | None = Field(default=None, max_length=1024)
    private_key: str | None = Field(default=None, max_length=32768)
    key_passphrase: str | None = Field(default=None, max_length=1024)
    sudo_password: str | None = Field(default=None, max_length=1024)
    reset_hostkey: bool = False

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        v = v.strip()
        if not NAME_RE.fullmatch(v):
            raise ValueError("نام سرور باید 1 تا 40 کاراکتر و بدون کاراکتر کنترلی یا <> باشد")
        return v

    @field_validator("host")
    @classmethod
    def _host(cls, v: str) -> str:
        v = v.strip()
        if not valid_ipv4(v):
            raise ValueError("IP سرور باید یک IPv4 معتبر باشد")
        return v

    @field_validator("username")
    @classmethod
    def _user(cls, v: str) -> str:
        v = (v or "root").strip()
        if not USER_RE.fullmatch(v):
            raise ValueError("نام کاربری SSH نامعتبر است")
        return v

    @field_validator("private_key")
    @classmethod
    def _key(cls, v: str | None) -> str | None:
        if v is None or not v.strip():
            return None
        v = v.strip().replace("\r\n", "\n") + "\n"
        if "PRIVATE KEY" not in v:
            raise ValueError("کلید خصوصی باید با فرمت PEM/OpenSSH باشد")
        return v


class SpoofOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")

    iran_spoof_ip: str
    kharej_spoof_ip: str
    listen_public: bool = True
    listen_port: int = Field(default=8443, ge=1, le=65535)
    forward: str = "127.0.0.1:443"
    up_port: int = Field(default=9000, ge=1, le=65535)
    down_port: int = Field(default=9001, ge=1, le=65535)
    up_transport: Literal["tcp", "udp", "icmp", "icmpv6"] = "tcp"
    down_transport: Literal["tcp", "udp", "icmp", "icmpv6"] = "udp"
    spoof_port: int = Field(default=53, ge=1, le=65535)
    skip_check: bool = False

    @field_validator("iran_spoof_ip", "kharej_spoof_ip")
    @classmethod
    def _spoof_ip(cls, v: str) -> str:
        v = v.strip()
        if not valid_ipv4(v):
            raise ValueError("IP جعلی (spoof) باید یک IPv4 معتبر باشد")
        return v

    @field_validator("forward")
    @classmethod
    def _forward(cls, v: str) -> str:
        v = v.strip()
        if not valid_host_port(v):
            raise ValueError("مقصد فوروارد باید به شکل IP:PORT باشد (مثلاً 127.0.0.1:443)")
        return v

    @model_validator(mode="after")
    def _ports(self) -> "SpoofOptions":
        if self.up_port == self.down_port:
            raise ValueError("پورت رفت و برگشت Spoof نباید یکی باشد")
        return self


class XrayOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")

    net: Literal["tcp", "ws", "grpc"] = "tcp"
    ctrl_port: int | None = Field(default=None, ge=1, le=65535)
    ports: str | None = Field(default=None, max_length=120)

    @field_validator("ports")
    @classmethod
    def _ports(cls, v: str | None) -> str | None:
        if v is None or not str(v).strip():
            return None
        v = str(v).replace(" ", "")
        if not valid_xray_ports(v):
            raise ValueError("پورت‌های Xray باید به شکل 443 یا 8443:443 باشند (حداکثر 16 مورد)")
        return v


class DnsttOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")

    domain: str
    resolver_mode: Literal["doh", "dot", "udp"] = "doh"
    resolver: str | None = Field(default=None, max_length=200)
    dns_port: int | None = Field(default=None, ge=1, le=65535)
    ports: str | None = Field(default=None, max_length=120)

    @field_validator("domain")
    @classmethod
    def _domain(cls, v: str) -> str:
        v = (v or "").strip().lower().rstrip(".")
        if not valid_dnstt_domain(v):
            raise ValueError("دامنه DNSTT باید یک FQDN معتبر باشد (مثلاً t.example.com)")
        return v

    @field_validator("resolver_mode")
    @classmethod
    def _mode(cls, v: str) -> str:
        v = v.strip().lower()
        if v not in DNSTT_MODES:
            raise ValueError("حالت resolver باید doh، dot یا udp باشد")
        return v

    @field_validator("ports")
    @classmethod
    def _ports(cls, v: str | None) -> str | None:
        if v is None or not str(v).strip():
            return None
        v = str(v).replace(" ", "")
        if not valid_xray_ports(v):
            raise ValueError("پورت‌ها باید به شکل 443 یا 8443:443 باشند (حداکثر 16 مورد)")
        return v

    @model_validator(mode="after")
    def _resolver(self) -> "DnsttOptions":
        if self.resolver is None or not str(self.resolver).strip():
            self.resolver = None
            return self
        r = str(self.resolver).strip()
        if not valid_dnstt_resolver(self.resolver_mode, r):
            raise ValueError("آدرس resolver با حالت انتخاب‌شده سازگار نیست")
        self.resolver = r
        return self


class IcmpOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ports: str | None = Field(default=None, max_length=120)

    @field_validator("ports")
    @classmethod
    def _ports(cls, v: str | None) -> str | None:
        if v is None or not str(v).strip():
            return None
        v = str(v).replace(" ", "")
        if not valid_xray_ports(v):
            raise ValueError("پورت‌ها باید به شکل 443 یا 8443:443 باشند (حداکثر 16 مورد)")
        return v


class TunnelIn(BaseModel):
    mode: str
    iran_id: int | None = None
    kharej_id: int
    direct: bool = False
    users: Literal["iran", "kharej"] = "iran"
    spoof: SpoofOptions | None = None
    xray: XrayOptions | None = None
    dnstt: DnsttOptions | None = None
    icmp: IcmpOptions | None = None

    @field_validator("mode")
    @classmethod
    def _mode(cls, v: str) -> str:
        if v not in MODES:
            raise ValueError("نوع تانل نامعتبر است")
        return v

    @model_validator(mode="after")
    def _options(self) -> "TunnelIn":
        if self.direct:
            if self.mode not in STREAM_MODES:
                raise ValueError("حالت مستقیم (بدون سرور ایران) فقط برای DNSTT و ICMP است")
            self.iran_id = None
            self.users = "kharej"
        elif self.mode in STREAM_MODES and self.users == "kharej":
            # DNSTT/ICMP server always lives on Kharej; users-on-Kharej means no Iran VPS.
            self.direct = True
            self.iran_id = None
        elif self.iran_id is None:
            raise ValueError("سرور ایران لازم است؛ برای DNSTT/ICMP بدون ایران گزینه direct را بزنید")
        if self.mode == "spoof" and self.users == "kharej":
            raise ValueError("تانل Spoof ورودی را روی ایران گوش می‌دهد؛ کاربران را روی ایران بگذارید")
        if self.mode == "spoof" and self.spoof is None:
            raise ValueError("برای تانل Spoof، IP جعلی هر دو سرور لازم است")
        if self.mode != "spoof":
            self.spoof = None
        if self.mode not in XRAY_MODES:
            self.xray = None
        if self.mode == "dnstt" and self.dnstt is None:
            raise ValueError("برای DNSTT دامنه لازم است (NS باید روی سرور خارج باشد)")
        if self.mode != "dnstt":
            self.dnstt = None
        if self.mode != "icmp":
            self.icmp = None
        return self


class RelayIn(BaseModel):
    engine: str
    iran_id: int
    target: str
    ports: str
    proto: Literal["tcp", "udp", "both"] = "both"
    name: str | None = Field(default=None, max_length=24)

    @field_validator("engine")
    @classmethod
    def _engine(cls, v: str) -> str:
        v = v.strip().lower()
        if v not in RELAY_ENGINES:
            raise ValueError("موتور رله باید iptables، gost، haproxy، socat یا xray باشد")
        return v

    @field_validator("ports")
    @classmethod
    def _ports(cls, v: str) -> str:
        v = v.replace(" ", "")
        if not valid_xray_ports(v):
            raise ValueError("پورت‌ها باید به شکل 443 یا 2096:443 باشند (حداکثر 16 مورد)")
        return v

    @field_validator("name")
    @classmethod
    def _name(cls, v: str | None) -> str | None:
        if v is None or not v.strip():
            return None
        v = v.strip().lower()
        if not valid_relay_name(v):
            raise ValueError("نام رله: حروف کوچک انگلیسی، عدد و خط تیره (حداکثر 24)")
        return v

    @model_validator(mode="after")
    def _target(self) -> "RelayIn":
        self.target = self.target.strip()
        if self.engine == "haproxy" and self.proto != "tcp":
            raise ValueError("رله HAProxy فقط TCP است")
        if not valid_relay_target(self.target, ipv4_only=self.engine == "iptables"):
            raise ValueError("مقصد رله باید IPv4 معتبر باشد" if self.engine == "iptables" else "مقصد رله باید IPv4 یا دامنه معتبر باشد")
        return self


class DnsIn(BaseModel):
    dns1: str
    dns2: str | None = None

    @field_validator("dns1", "dns2")
    @classmethod
    def _dns(cls, v: str | None) -> str | None:
        if v is None or not str(v).strip():
            return None
        v = str(v).strip()
        if not valid_ipv4(v):
            raise ValueError("آدرس DNS باید IPv4 معتبر باشد")
        return v

    @model_validator(mode="after")
    def _need_primary(self) -> "DnsIn":
        if not self.dns1:
            raise ValueError("حداقل یک DNS لازم است")
        return self


class SpoofCheckIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    iran_id: int
    kharej_id: int
    spoof: SpoofOptions


class DeleteIn(BaseModel):
    force: bool = False


class UserCreateIn(BaseModel):
    username: str
    password: str | None = Field(default=None, max_length=256)
    email: str | None = Field(default=None, max_length=254)
    days: int | None = Field(default=None, ge=1, le=3650)
    max_servers: int | None = Field(default=None, ge=0, le=10000)
    max_tunnels: int | None = Field(default=None, ge=0, le=10000)
    max_relays: int | None = Field(default=None, ge=0, le=10000)
    allow_vpn: bool = True
    allow_relay: bool = True
    allow_os_update: bool = True
    allow_term: bool = True
    note: str | None = Field(default=None, max_length=500)

    @field_validator("username")
    @classmethod
    def _user(cls, v: str) -> str:
        v = (v or "").strip()
        if not USER_RE.fullmatch(v) or v.endswith("$"):
            raise ValueError("نام کاربری نامعتبر است")
        return v

    @field_validator("password")
    @classmethod
    def _pw(cls, v: str | None) -> str | None:
        if v is None or not str(v).strip():
            return None
        if len(v) < 10:
            raise ValueError("رمز عبور باید حداقل ۱۰ کاراکتر باشد")
        return v

    @field_validator("email")
    @classmethod
    def _email(cls, v: str | None) -> str | None:
        if v is None or not str(v).strip():
            return None
        try:
            value = normalize_email(v)
        except ValueError as exc:
            raise ValueError(str(exc)) from exc
        return value or None

    @field_validator("note")
    @classmethod
    def _note(cls, v: str | None) -> str | None:
        if v is None or not str(v).strip():
            return None
        return str(v).strip()[:500]


class UserPatchIn(BaseModel):
    enabled: bool | None = None
    max_servers: int | None = Field(default=None, ge=0, le=10000)
    max_tunnels: int | None = Field(default=None, ge=0, le=10000)
    max_relays: int | None = Field(default=None, ge=0, le=10000)
    allow_vpn: bool | None = None
    allow_relay: bool | None = None
    allow_os_update: bool | None = None
    allow_term: bool | None = None
    note: str | None = Field(default=None, max_length=500)
    email: str | None = Field(default=None, max_length=254)

    @field_validator("note")
    @classmethod
    def _note(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = str(v).strip()
        return v[:500] if v else None

    @field_validator("email")
    @classmethod
    def _email(cls, v: str | None) -> str | None:
        if v is None:
            return None
        if not str(v).strip():
            return ""
        try:
            value = normalize_email(v)
        except ValueError as exc:
            raise ValueError(str(exc)) from exc
        return value


class UserExtendIn(BaseModel):
    days: int = Field(ge=1, le=3650)


class PanelSettingsIn(BaseModel):
    terms_enabled: bool | None = None
    sell_tunnels_enabled: bool | None = None
    register_enabled: bool | None = None
    payment_card: str | None = Field(default=None, max_length=120)
    payment_wallet_address: str | None = Field(default=None, max_length=200)
    payment_note: str | None = Field(default=None, max_length=1000)
    wallet_currency: str | None = Field(default=None, max_length=32)
    tunnel_prices: dict[str, int] | None = None
    smtp_enabled: bool | None = None
    smtp_host: str | None = Field(default=None, max_length=253)
    smtp_port: int | None = Field(default=None, ge=1, le=65535)
    smtp_user: str | None = Field(default=None, max_length=200)
    smtp_password: str | None = Field(default=None, max_length=512)
    smtp_from: str | None = Field(default=None, max_length=254)
    smtp_tls: bool | None = None


class DepositIn(BaseModel):
    amount: int = Field(ge=1000, le=10_000_000_000)
    method: Literal["card", "crypto"]
    tracking_code: str = Field(min_length=3, max_length=120)
    note: str = Field(default="", max_length=1000)
    tunnel_mode: str | None = Field(default=None, max_length=32)

    @field_validator("tracking_code")
    @classmethod
    def _track(cls, v: str) -> str:
        value = (v or "").strip()
        if len(value) < 3:
            raise ValueError("کد پیگیری را وارد کنید")
        return value

    @field_validator("tunnel_mode")
    @classmethod
    def _mode(cls, v: str | None) -> str | None:
        if v is None or not str(v).strip():
            return None
        if v not in MODES:
            raise ValueError("نوع تانل نامعتبر است")
        return v


class DepositDecideIn(BaseModel):
    action: Literal["approve", "reject"]
    note: str = Field(default="", max_length=500)


class WalletAdjustIn(BaseModel):
    amount: int = Field(ge=1, le=10_000_000_000)
    direction: Literal["credit", "debit"]
    note: str = Field(default="", max_length=500)


class RegisterIn(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=10, max_length=256)
    email: str = Field(min_length=3, max_length=254)

    @field_validator("username")
    @classmethod
    def _user(cls, v: str) -> str:
        value = (v or "").strip().lower()
        if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{2,31}", value):
            raise ValueError("نام کاربری نامعتبر است")
        return value

    @field_validator("email")
    @classmethod
    def _email(cls, v: str) -> str:
        try:
            value = normalize_email(v)
        except ValueError as exc:
            raise ValueError(str(exc)) from exc
        if not value:
            raise ValueError("ایمیل را وارد کنید")
        return value


class ListenIn(BaseModel):
    path: str = Field(min_length=1, max_length=80)
    port: int = Field(ge=1, le=65535)


class SslIn(BaseModel):
    domain: str = Field(min_length=1, max_length=253)
    email: str | None = Field(default=None, max_length=254)


class GuideStepIn(BaseModel):
    model_config = ConfigDict(extra="ignore")
    h: str = Field(default="", max_length=20000)
    p: str = Field(default="", max_length=20000)


class GuideStyleIn(BaseModel):
    model_config = ConfigDict(extra="ignore")
    fontFamily: str | None = None
    fontSize: str | None = None
    titleSize: str | None = None
    leadSize: str | None = None
    stepSize: str | None = None
    lineHeight: str | None = None


class GuideArticleIn(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(min_length=1, max_length=32)
    group: str = Field(default="", max_length=40)
    nav: str = Field(default="", max_length=20000)
    title: str = Field(min_length=1, max_length=20000)
    lead: str = Field(default="", max_length=20000)
    note: str = Field(default="", max_length=20000)
    steps: list[GuideStepIn] = Field(default_factory=list, max_length=40)
    style: GuideStyleIn | None = None


class UserPasswordIn(BaseModel):
    password: str | None = Field(default=None, max_length=256)

    @field_validator("password")
    @classmethod
    def _pw(cls, v: str | None) -> str | None:
        if v is None or not str(v).strip():
            return None
        if len(v) < 10:
            raise ValueError("رمز عبور باید حداقل ۱۰ کاراکتر باشد")
        return v


ORDER_STATUSES = ("pending", "approved", "rejected", "done", "cancelled")
TICKET_CATEGORIES = ("panel", "tunnel", "server", "billing", "other")
TICKET_STATUSES = ("open", "answered", "closed")
MAX_PENDING_ORDERS = 3


class OrderServerIn(BaseModel):
    name: str
    host: str
    port: int = Field(default=22, ge=1, le=65535)
    username: str = "root"
    auth_type: Literal["password", "key"] = "password"
    password: str | None = Field(default=None, max_length=1024)
    private_key: str | None = Field(default=None, max_length=32768)
    key_passphrase: str | None = Field(default=None, max_length=1024)
    sudo_password: str | None = Field(default=None, max_length=1024)
    include_access: bool = False

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        v = v.strip()
        if not NAME_RE.fullmatch(v):
            raise ValueError("نام سرور باید 1 تا 40 کاراکتر و بدون کاراکتر کنترلی یا <> باشد")
        return v

    @field_validator("host")
    @classmethod
    def _host(cls, v: str) -> str:
        v = v.strip()
        if not valid_ipv4(v):
            raise ValueError("IP سرور باید یک IPv4 معتبر باشد")
        return v

    @field_validator("username")
    @classmethod
    def _user(cls, v: str) -> str:
        v = (v or "root").strip()
        if not USER_RE.fullmatch(v):
            raise ValueError("نام کاربری SSH نامعتبر است")
        return v

    @field_validator("private_key")
    @classmethod
    def _key(cls, v: str | None) -> str | None:
        if v is None or not str(v).strip():
            return None
        v = str(v).strip().replace("\r\n", "\n") + "\n"
        if "PRIVATE KEY" not in v:
            raise ValueError("کلید خصوصی باید با فرمت PEM/OpenSSH باشد")
        return v


class OrderIn(BaseModel):
    mode: str
    message: str | None = Field(default=None, max_length=2000)
    iran: OrderServerIn
    kharej: OrderServerIn

    @field_validator("mode")
    @classmethod
    def _mode(cls, v: str) -> str:
        if v not in MODES:
            raise ValueError("نوع تانل نامعتبر است")
        return v

    @field_validator("message")
    @classmethod
    def _msg(cls, v: str | None) -> str | None:
        if v is None or not str(v).strip():
            return None
        return str(v).strip()[:2000]

    @model_validator(mode="after")
    def _pair(self) -> "OrderIn":
        if self.iran.host == self.kharej.host and self.iran.port == self.kharej.port:
            raise ValueError("IP و پورت دو سرور نمی‌تواند یکی باشد")
        return self


class OrderDecideIn(BaseModel):
    action: Literal["approve", "reject"]
    note: str | None = Field(default=None, max_length=1000)

    @field_validator("note")
    @classmethod
    def _note(cls, v: str | None) -> str | None:
        if v is None or not str(v).strip():
            return None
        return str(v).strip()[:1000]


class OrderFulfillIn(BaseModel):
    iran_id: int | None = None
    kharej_id: int | None = None
    iran: OrderServerIn | None = None
    kharej: OrderServerIn | None = None
    users: Literal["iran", "kharej"] = "iran"
    direct: bool = False
    spoof: SpoofOptions | None = None
    xray: XrayOptions | None = None
    dnstt: DnsttOptions | None = None
    icmp: IcmpOptions | None = None


class TicketAccessIn(BaseModel):
    host: str | None = Field(default=None, max_length=200)
    port: int | None = Field(default=None, ge=1, le=65535)
    username: str | None = Field(default=None, max_length=64)
    password: str | None = Field(default=None, max_length=1024)
    panel_url: str | None = Field(default=None, max_length=500)
    note: str | None = Field(default=None, max_length=500)

    @model_validator(mode="after")
    def _any(self) -> "TicketAccessIn":
        vals = [self.host, self.username, self.password, self.panel_url, self.note]
        if not any(v and str(v).strip() for v in vals) and self.port is None:
            raise ValueError("حداقل یک فیلد دسترسی لازم است")
        return self


class TicketCreateIn(BaseModel):
    subject: str = Field(min_length=1, max_length=200)
    category: Literal["panel", "tunnel", "server", "billing", "other"] = "other"
    body: str = Field(min_length=1, max_length=5000)
    access: TicketAccessIn | None = None

    @field_validator("subject", "body")
    @classmethod
    def _trim(cls, v: str) -> str:
        v = (v or "").strip()
        if not v:
            raise ValueError("متن خالی است")
        return v


class TicketMessageIn(BaseModel):
    body: str = Field(min_length=1, max_length=5000)
    access: TicketAccessIn | None = None

    @field_validator("body")
    @classmethod
    def _trim(cls, v: str) -> str:
        v = (v or "").strip()
        if not v:
            raise ValueError("متن پیام خالی است")
        return v


class TicketPatchIn(BaseModel):
    status: Literal["open", "answered", "closed"]


# ---------- app factory ----------
def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        log.warning("panel entry path %s (bare IP does not open the panel)", settings.base_path)
        yield
        await app.state.jobs.shutdown()
        app.state.db.close()

    app = FastAPI(title="JojoNet Panel", version=PANEL_VERSION, docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    db = Database(settings.db_path)
    try:
        wallet_mod.refund_aborted_deploys(db)
    except Exception:
        log.exception("wallet refund sweep after restart failed")
    vault = Vault(settings.vault_key_path)
    jobs = JobManager(db)
    orch = Orchestrator(db, vault, settings, jobs)
    entry = PanelEntry(settings.base_path, settings.port)
    app.state.settings, app.state.db, app.state.vault, app.state.jobs, app.state.orch = settings, db, vault, jobs, orch
    app.state.entry = entry

    index_path = settings.static_dir / "index.html"

    assets: dict[str, Any] = {"key": None, "version": "", "html": None}

    def refresh_assets() -> None:
        stamp = []
        for name in STATIC_ASSETS:
            try:
                st = (settings.static_dir / name).stat()
                stamp.append((st.st_mtime_ns, st.st_size))
            except OSError:
                stamp.append(None)
        key = tuple(stamp)
        if key == assets["key"]:
            return
        h = hashlib.sha256()
        for name in STATIC_ASSETS:
            p = settings.static_dir / name
            if p.is_file():
                h.update(p.read_bytes())
        version = h.hexdigest()[:12]
        try:
            html = index_path.read_text(encoding="utf-8").replace("__V__", version)
        except OSError:
            html = None
        assets.update(key=key, version=version, html=html)

    def asset_version() -> str:
        refresh_assets()
        return assets["version"]

    def cookie_path() -> str:
        return app.state.entry.path + "/"

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            raw_len = request.headers.get("content-length", "")
            if raw_len.isdigit() and int(raw_len) > MAX_BODY_BYTES:
                response = Response(status_code=413)
            else:
                response = await call_next(request)
        else:
            response = await call_next(request)
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
        response.headers["X-Robots-Tag"] = "noindex, nofollow"
        if "server" in response.headers:
            del response.headers["server"]
        if settings.secure_cookies:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    # ---------- helpers ----------
    def client_ip(request: Request) -> str:
        if settings.trusted_proxy:
            fwd = request.headers.get("x-forwarded-for", "")
            if fwd:
                return fwd.split(",")[-1].strip()[:64]
        return request.client.host if request.client else "unknown"

    def session_row(request: Request) -> dict[str, Any] | None:
        token = request.cookies.get(COOKIE)
        if not token or len(token) > 128:
            return None
        row = db.one(
            """SELECT s.token_hash, s.admin_id, s.csrf, s.created_at AS session_created_at,
                      s.expires_at AS session_expires_at, a.username, a.email, a.role, a.enabled,
                      a.expires_at, a.max_servers, a.max_tunnels, a.max_relays,
                      a.allow_vpn, a.allow_relay, a.allow_os_update, a.allow_term, a.note
               FROM sessions s JOIN admins a ON a.id = s.admin_id WHERE s.token_hash=?""",
            (token_hash(token),),
        )
        if row is None:
            return None
        if row["session_expires_at"] < utcnow():
            db.execute("DELETE FROM sessions WHERE token_hash=?", (row["token_hash"],))
            return None
        return row

    def account_block_reason(row: dict[str, Any]) -> str | None:
        if row.get("role") == "owner":
            return None
        if not row.get("enabled"):
            return "حساب شما غیرفعال است"
        exp = row.get("expires_at")
        if exp and exp < utcnow():
            return "اشتراک شما منقضی شده است"
        return None

    def require_auth(request: Request) -> dict[str, Any]:
        row = session_row(request)
        if row is None:
            raise HTTPException(401, "ابتدا وارد شوید")
        blocked = account_block_reason(row)
        if blocked:
            db.execute("DELETE FROM sessions WHERE token_hash=?", (row["token_hash"],))
            raise HTTPException(401, blocked)
        if request.method not in ("GET", "HEAD"):
            sent = request.headers.get("x-csrf-token", "")
            if not sent or not hmac.compare_digest(sent, row["csrf"]):
                raise HTTPException(403, "توکن CSRF نامعتبر است؛ صفحه را تازه کنید")
        return row

    def require_owner(request: Request) -> dict[str, Any]:
        sess = require_auth(request)
        if sess.get("role") != "owner":
            raise HTTPException(403, "فقط مالک پنل به این بخش دسترسی دارد")
        return sess

    def is_owner(sess: dict[str, Any]) -> bool:
        return sess.get("role") == "owner"

    def owner_clause(sess: dict[str, Any], alias: str = "") -> tuple[str, tuple]:
        if is_owner(sess):
            return "", ()
        col = f"{alias}.owner_id" if alias else "owner_id"
        return f" AND {col}=?", (sess["admin_id"],)

    def days_left(expires_at: str | None) -> int | None:
        if not expires_at:
            return None
        try:
            exp = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        except ValueError:
            return None
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        secs = (exp - datetime.now(timezone.utc)).total_seconds()
        if secs <= 0:
            return 0
        return int((secs + 86399) // 86400)

    def usage_counts(owner_id: int) -> dict[str, int]:
        def n(table: str) -> int:
            row = db.one(f"SELECT COUNT(*) AS n FROM {table} WHERE owner_id=?", (owner_id,))
            return int((row or {"n": 0})["n"])
        return {"servers": n("servers"), "tunnels": n("tunnels"), "relays": n("relays")}

    def assert_active(sess: dict[str, Any]) -> None:
        if is_owner(sess):
            return
        reason = account_block_reason(sess)
        if reason:
            raise HTTPException(403, reason)

    def assert_quota(sess: dict[str, Any], kind: str) -> None:
        if is_owner(sess):
            return
        assert_active(sess)
        labels = {"servers": "سرور", "tunnels": "تانل", "relays": "رله"}
        cap = sess.get(f"max_{kind}")
        if cap is None:
            return
        used = usage_counts(sess["admin_id"])[kind]
        if used >= int(cap):
            raise HTTPException(422, f"سقف {labels[kind]} پر است ({used}/{int(cap)})")

    def assert_capability(sess: dict[str, Any], flag: str, message: str) -> None:
        if is_owner(sess):
            return
        assert_active(sess)
        if not sess.get(flag):
            raise HTTPException(403, message)

    def setting(key: str, default: str = "1") -> str:
        row = db.one("SELECT value FROM panel_settings WHERE key=?", (key,))
        return str(row["value"]) if row and row.get("value") is not None else default

    def terms_globally_on() -> bool:
        return setting("terms_enabled", "1") != "0"

    def term_allowed(sess: dict[str, Any]) -> bool:
        if not terms_globally_on():
            return False
        if is_owner(sess):
            return True
        return bool(sess.get("allow_term", 1))

    def admin_names() -> dict[int, str]:
        return {r["id"]: r["username"] for r in db.all("SELECT id, username FROM admins")}

    def attach_owner(out: dict[str, Any], row: dict[str, Any], names: dict[int, str] | None = None) -> dict[str, Any]:
        oid = row.get("owner_id")
        out["owner_id"] = oid
        if names is None:
            names = admin_names()
        out["owner_username"] = names.get(oid, "?") if oid is not None else None
        return out

    def create_job(sess: dict[str, Any], kind: str, title: str, steps: list[str], func, **kw):  # noqa: ANN001
        kw.setdefault("owner_id", sess["admin_id"])
        return jobs.create(kind, title, steps, func, **kw)

    def server_out(row: dict[str, Any], names: dict[int, str] | None = None) -> dict[str, Any]:
        out = {
            "id": row["id"],
            "name": row["name"],
            "role": row["role"],
            "host": row["host"],
            "port": row["port"],
            "username": row["username"],
            "auth_type": row["auth_type"],
            "has_password": bool(row["secret_password"]),
            "has_key": bool(row["secret_key"]),
            "has_sudo_password": bool(row["secret_sudo"]),
            "hostkey_fingerprint": row["hostkey_fingerprint"],
            "last_check": row["last_check"],
            "last_ssl": row.get("last_ssl"),
            "created_at": row["created_at"],
        }
        return attach_owner(out, row, names)

    def server_names(sess: dict[str, Any] | None = None) -> dict[int, str]:
        extra, params = owner_clause(sess) if sess is not None else ("", ())
        return {r["id"]: r["name"] for r in db.all(f"SELECT id, name FROM servers WHERE 1=1{extra}", params)}

    def tunnel_out(row: dict[str, Any], names: dict[int, str] | None = None, owners: dict[int, str] | None = None) -> dict[str, Any]:
        names = server_names() if names is None else names
        out = {k: row[k] for k in (
            "id", "mode", "iran_id", "kharej_id", "status", "iran_iface", "kharej_iface",
            "tun_iran_ip", "tun_kharej_ip", "forward_ports", "options", "last_job_id", "last_check", "created_at",
        )}
        out["iran_name"] = names.get(row["iran_id"], "?")
        out["kharej_name"] = names.get(row["kharej_id"], "?")
        opts = row.get("options") or {}
        public_opts = dict(opts)
        public_opts.pop("reality", None)
        out["options"] = public_opts or None
        out["direct"] = bool(opts.get("direct")) or row["iran_id"] == row["kharej_id"]
        users = opts.get("users")
        if out["direct"]:
            users = "kharej"
        elif users not in ("iran", "kharej"):
            users = "iran"
        out["users"] = users
        return attach_owner(out, row, owners)

    def get_server(server_id: int, sess: dict[str, Any] | None = None) -> dict[str, Any]:
        if sess is None:
            row = db.one("SELECT * FROM servers WHERE id=?", (server_id,))
        else:
            extra, params = owner_clause(sess)
            row = db.one(f"SELECT * FROM servers WHERE id=?{extra}", (server_id, *params))
        if row is None:
            raise HTTPException(404, "سرور پیدا نشد")
        return row

    def get_tunnel(tunnel_id: int, sess: dict[str, Any] | None = None) -> dict[str, Any]:
        if sess is None:
            row = db.one("SELECT * FROM tunnels WHERE id=?", (tunnel_id,))
        else:
            extra, params = owner_clause(sess)
            row = db.one(f"SELECT * FROM tunnels WHERE id=?{extra}", (tunnel_id, *params))
        if row is None:
            raise HTTPException(404, "تانل پیدا نشد")
        return row

    def user_out(row: dict[str, Any]) -> dict[str, Any]:
        usage = usage_counts(row["id"])
        return {
            "id": row["id"],
            "username": row["username"],
            "email": row.get("email") or None,
            "role": row["role"],
            "enabled": bool(row.get("enabled")),
            "expires_at": row.get("expires_at"),
            "days_left": days_left(row.get("expires_at")),
            "max_servers": row.get("max_servers"),
            "max_tunnels": row.get("max_tunnels"),
            "max_relays": row.get("max_relays"),
            "allow_vpn": bool(row.get("allow_vpn")),
            "allow_relay": bool(row.get("allow_relay")),
            "allow_os_update": bool(row.get("allow_os_update")),
            "allow_term": bool(row.get("allow_term", 1)),
            "note": row.get("note"),
            "created_at": row["created_at"],
            "usage": usage,
            "wallet_balance": wallet_mod.balance_of(db, row["id"]),
        }

    def commerce_public() -> dict[str, Any]:
        pay = wallet_mod.payment_info(db)
        return {
            "sell_tunnels_enabled": wallet_mod.sell_enabled(db),
            "register_enabled": wallet_mod.register_enabled(db),
            "password_reset_enabled": mail_mod.smtp_ready(db, vault),
            "currency": pay["currency"],
            "payment": pay,
            "tunnel_prices": wallet_mod.load_prices(db),
        }

    def email_taken(email: str, exclude_id: int | None = None) -> bool:
        if not email:
            return False
        if exclude_id is None:
            return db.one("SELECT id FROM admins WHERE email=?", (email,)) is not None
        return db.one("SELECT id FROM admins WHERE email=? AND id!=?", (email, exclude_id)) is not None

    def me_payload(sess: dict[str, Any]) -> dict[str, Any]:
        usage = usage_counts(sess["admin_id"])
        return {
            "username": sess["username"],
            "email": sess.get("email") or None,
            "csrf": sess["csrf"],
            "panel_version": PANEL_VERSION,
            "jojonet_version": bundle_version(settings.bundle_dir),
            "role": sess.get("role") or "customer",
            "enabled": bool(sess.get("enabled", 1)),
            "expires_at": sess.get("expires_at"),
            "days_left": days_left(sess.get("expires_at")),
            "usage": usage,
            "limits": {
                "max_servers": sess.get("max_servers"),
                "max_tunnels": sess.get("max_tunnels"),
                "max_relays": sess.get("max_relays"),
            },
            "allow_vpn": bool(sess.get("allow_vpn", 1)),
            "allow_relay": bool(sess.get("allow_relay", 1)),
            "allow_os_update": bool(sess.get("allow_os_update", 1)),
            "allow_term": bool(sess.get("allow_term", 1)),
            "terms_enabled": terms_globally_on(),
            "can_term": term_allowed(sess),
            "base_path": app.state.entry.path,
            "panel_port": app.state.entry.port,
            "wallet_balance": wallet_mod.balance_of(db, sess["admin_id"]),
            "commerce": commerce_public(),
        }

    def tunnel_busy(row: dict[str, Any]) -> None:
        if row["status"] in ("deploying", "deleting"):
            raise HTTPException(409, "یک عملیات دیگر روی این تانل در حال اجراست")

    # ---------- public ----------
    @app.get("/", response_class=HTMLResponse)
    async def index() -> HTMLResponse:
        refresh_assets()
        if assets["html"] is None:
            raise HTTPException(500, "فایل‌های رابط کاربری پیدا نشد")
        html = assets["html"].replace("__BASE__", app.state.entry.path)
        return HTMLResponse(html, headers={"Cache-Control": "no-store"})

    @app.get("/api/health")
    async def health() -> dict[str, Any]:
        return {"ok": True}

    @app.get("/api/commerce")
    async def get_commerce_public() -> dict[str, Any]:
        """Public commerce flags for the login/register screen (no secrets beyond payment instructions)."""
        return commerce_public()

    @app.post("/api/register")
    async def register(data: RegisterIn, request: Request, response: Response) -> dict[str, Any]:
        if not wallet_mod.register_enabled(db):
            raise HTTPException(403, "ثبت‌نام عمومی فعلاً بسته است")
        ip = client_ip(request)
        if not login_allowed(db, ip, data.username):
            raise HTTPException(429, "تلاش‌های زیاد بود؛ کمی بعد دوباره امتحان کنید")
        if db.one("SELECT id FROM admins WHERE username=?", (data.username,)):
            raise HTTPException(409, "این نام کاربری قبلاً ثبت شده است")
        if email_taken(data.email):
            raise HTTPException(409, "این ایمیل قبلاً ثبت شده است")
        pw_hash = await asyncio.to_thread(hash_password, data.password)
        uid = db.insert("admins", {
            "username": data.username,
            "email": data.email,
            "pw_hash": pw_hash,
            "created_at": utcnow(),
            "role": "customer",
            "enabled": 1,
            "wallet_balance": 0,
            "allow_vpn": 1,
            "allow_relay": 1,
            "allow_os_update": 0,
            "allow_term": 1,
        })
        token, csrf = new_token(), new_token()
        now = datetime.now(timezone.utc).replace(microsecond=0)
        db.insert("sessions", {
            "token_hash": token_hash(token),
            "admin_id": uid,
            "csrf": csrf,
            "created_at": now.isoformat(),
            "expires_at": (now + timedelta(hours=settings.session_hours)).isoformat(),
        })
        response.set_cookie(
            COOKIE, token, max_age=settings.session_hours * 3600, httponly=True,
            secure=settings.secure_cookies, samesite="strict", path=cookie_path(),
        )
        return {"ok": True, "csrf": csrf}

    @app.post("/api/forgot-password")
    async def forgot_password(data: ForgotPasswordIn, request: Request) -> dict[str, Any]:
        ip = client_ip(request)
        rate_key = data.email or data.username or "forgot"
        if not login_allowed(db, ip, f"forgot:{rate_key}"):
            raise HTTPException(429, "تلاش‌های زیاد بود؛ کمی بعد دوباره امتحان کنید")
        record_login_failure(db, ip, f"forgot:{rate_key}")
        admin = None
        if data.email:
            admin = db.one("SELECT * FROM admins WHERE email=?", (data.email,))
        elif data.username:
            admin = db.one("SELECT * FROM admins WHERE username=?", (data.username,))
        if admin and admin.get("email") and mail_mod.smtp_ready(db, vault):
            blocked = account_block_reason(admin)
            if not blocked:
                raw = new_token()
                now = datetime.now(timezone.utc).replace(microsecond=0)
                expires = now + timedelta(seconds=mail_mod.RESET_TTL_SECONDS)
                db.execute("DELETE FROM password_resets WHERE admin_id=?", (admin["id"],))
                db.insert("password_resets", {
                    "token_hash": token_hash(raw),
                    "admin_id": admin["id"],
                    "created_at": now.isoformat(),
                    "expires_at": expires.isoformat(),
                    "used_at": None,
                })
                reset_url = panel_public_url(request, app.state.entry.path, app.state.entry.port)
                if "?" in reset_url:
                    reset_url = reset_url.rstrip("/") + f"&reset={raw}"
                else:
                    reset_url = reset_url.rstrip("/") + f"/?reset={raw}"
                try:
                    await asyncio.to_thread(
                        mail_mod.send_password_reset_mail,
                        db,
                        vault,
                        to=admin["email"],
                        username=admin["username"],
                        reset_url=reset_url,
                    )
                except Exception:
                    log.exception("password reset mail failed for admin_id=%s", admin["id"])
        return {"ok": True, "message": mail_mod.GENERIC_FORGOT_MSG}

    @app.post("/api/reset-password")
    async def reset_password(data: ResetPasswordIn) -> dict[str, Any]:
        th = token_hash(data.token.strip())
        row = db.one("SELECT * FROM password_resets WHERE token_hash=?", (th,))
        if row is None or row.get("used_at"):
            raise HTTPException(400, "لینک بازیابی نامعتبر یا منقضی است")
        if row["expires_at"] < utcnow():
            db.execute("DELETE FROM password_resets WHERE token_hash=?", (th,))
            raise HTTPException(400, "لینک بازیابی منقضی شده است؛ دوباره درخواست دهید")
        admin = db.one("SELECT * FROM admins WHERE id=?", (row["admin_id"],))
        if admin is None:
            db.execute("DELETE FROM password_resets WHERE token_hash=?", (th,))
            raise HTTPException(400, "لینک بازیابی نامعتبر است")
        blocked = account_block_reason(admin)
        if blocked:
            raise HTTPException(403, blocked)
        pw_hash = await asyncio.to_thread(hash_password, data.password)
        db.update("admins", admin["id"], {"pw_hash": pw_hash})
        db.execute(
            "UPDATE password_resets SET used_at=? WHERE token_hash=?",
            (utcnow(), th),
        )
        db.execute("DELETE FROM password_resets WHERE admin_id=? AND token_hash!=?", (admin["id"], th))
        db.execute("DELETE FROM sessions WHERE admin_id=?", (admin["id"],))
        return {"ok": True, "message": "رمز عبور عوض شد؛ الان می‌توانید وارد شوید."}

    @app.post("/api/login")
    async def login(data: LoginIn, request: Request, response: Response) -> dict[str, Any]:
        ip = client_ip(request)
        if not login_allowed(db, ip, data.username):
            raise HTTPException(429, "تلاش‌های ناموفق زیاد بود؛ 5 دقیقه دیگر دوباره امتحان کنید")
        admin = db.one("SELECT * FROM admins WHERE username=?", (data.username,))
        ok = await asyncio.to_thread(verify_password, data.password, admin["pw_hash"] if admin else DUMMY_HASH)
        if not admin or not ok:
            record_login_failure(db, ip, data.username)
            raise HTTPException(401, "نام کاربری یا رمز عبور اشتباه است")
        blocked = account_block_reason(admin)
        if blocked:
            raise HTTPException(403, blocked)
        clear_login_failures(db, ip, data.username)
        token, csrf = new_token(), new_token()
        now = datetime.now(timezone.utc).replace(microsecond=0)
        db.execute("DELETE FROM sessions WHERE expires_at < ?", (now.isoformat(),))
        db.insert("sessions", {
            "token_hash": token_hash(token),
            "admin_id": admin["id"],
            "csrf": csrf,
            "created_at": now.isoformat(),
            "expires_at": (now + timedelta(hours=settings.session_hours)).isoformat(),
        })
        response.set_cookie(
            COOKIE, token, max_age=settings.session_hours * 3600, httponly=True,
            secure=settings.secure_cookies, samesite="strict", path=cookie_path(),
        )
        return {"ok": True, "csrf": csrf}

    @app.post("/api/logout")
    async def logout(response: Response, sess: dict = Depends(require_auth)) -> dict[str, Any]:
        db.execute("DELETE FROM sessions WHERE token_hash=?", (sess["token_hash"],))
        response.delete_cookie(COOKIE, path=cookie_path())
        return {"ok": True}

    @app.get("/api/me")
    async def me(sess: dict = Depends(require_auth)) -> dict[str, Any]:
        return me_payload(sess)

    @app.post("/api/password")
    async def change_password(data: PasswordIn, sess: dict = Depends(require_auth)) -> dict[str, Any]:
        admin = db.one("SELECT * FROM admins WHERE id=?", (sess["admin_id"],))
        if not admin or not await asyncio.to_thread(verify_password, data.old_password, admin["pw_hash"]):
            raise HTTPException(400, "رمز فعلی اشتباه است")
        new_hash = await asyncio.to_thread(hash_password, data.new_password)
        db.update("admins", admin["id"], {"pw_hash": new_hash})
        db.execute("DELETE FROM sessions WHERE admin_id=? AND token_hash<>?", (admin["id"], sess["token_hash"]))
        return {"ok": True}

    @app.post("/api/username")
    async def change_username(data: UsernameIn, sess: dict = Depends(require_auth)) -> dict[str, Any]:
        admin = db.one("SELECT * FROM admins WHERE id=?", (sess["admin_id"],))
        if not admin or not await asyncio.to_thread(verify_password, data.password, admin["pw_hash"]):
            raise HTTPException(400, "رمز فعلی اشتباه است")
        if data.username != admin["username"]:
            taken = db.one("SELECT id FROM admins WHERE username=? AND id<>?", (data.username, admin["id"]))
            if taken:
                raise HTTPException(409, "این نام کاربری قبلاً استفاده شده است")
            db.update("admins", admin["id"], {"username": data.username})
        return {"ok": True, "username": data.username}

    @app.post("/api/email")
    async def change_email(data: EmailIn, sess: dict = Depends(require_auth)) -> dict[str, Any]:
        admin = db.one("SELECT * FROM admins WHERE id=?", (sess["admin_id"],))
        if not admin or not await asyncio.to_thread(verify_password, data.password, admin["pw_hash"]):
            raise HTTPException(400, "رمز فعلی اشتباه است")
        if email_taken(data.email, exclude_id=admin["id"]):
            raise HTTPException(409, "این ایمیل قبلاً ثبت شده است")
        db.update("admins", admin["id"], {"email": data.email})
        return {"ok": True, "email": data.email}

    def get_admin(user_id: int) -> dict[str, Any]:
        row = db.one("SELECT * FROM admins WHERE id=?", (user_id,))
        if row is None:
            raise HTTPException(404, "کاربر پیدا نشد")
        return row

    @app.get("/api/settings")
    async def get_settings(_: dict = Depends(require_owner)) -> dict[str, Any]:
        out = {"terms_enabled": terms_globally_on()}
        out.update(commerce_public())
        out["smtp"] = mail_mod.smtp_public(db)
        return out

    @app.patch("/api/settings")
    async def patch_settings(data: PanelSettingsIn, _: dict = Depends(require_owner)) -> dict[str, Any]:
        if data.terms_enabled is not None:
            db.execute(
                "INSERT INTO panel_settings (key, value) VALUES ('terms_enabled', ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                ("1" if data.terms_enabled else "0",),
            )
        if data.sell_tunnels_enabled is not None:
            wallet_mod.set_setting(db, "sell_tunnels_enabled", "1" if data.sell_tunnels_enabled else "0")
        if data.register_enabled is not None:
            wallet_mod.set_setting(db, "register_enabled", "1" if data.register_enabled else "0")
        if any(x is not None for x in (data.payment_card, data.payment_wallet_address, data.payment_note, data.wallet_currency)):
            pay = wallet_mod.payment_info(db)
            wallet_mod.save_payment_info(
                db,
                data.payment_card if data.payment_card is not None else pay["card"],
                data.payment_wallet_address if data.payment_wallet_address is not None else pay["wallet_address"],
                data.payment_note if data.payment_note is not None else pay["note"],
                data.wallet_currency if data.wallet_currency is not None else pay["currency"],
            )
        if data.tunnel_prices is not None:
            wallet_mod.save_prices(db, data.tunnel_prices)
        smtp_fields = (
            data.smtp_enabled, data.smtp_host, data.smtp_port, data.smtp_user,
            data.smtp_password, data.smtp_from, data.smtp_tls,
        )
        if any(x is not None for x in smtp_fields):
            try:
                mail_mod.save_smtp(
                    db,
                    vault,
                    enabled=data.smtp_enabled,
                    host=data.smtp_host,
                    port=data.smtp_port,
                    username=data.smtp_user,
                    password=data.smtp_password,
                    from_addr=data.smtp_from,
                    tls=data.smtp_tls,
                )
            except ValueError as exc:
                raise HTTPException(400, str(exc)) from exc
        out = {"terms_enabled": terms_globally_on()}
        out.update(commerce_public())
        out["smtp"] = mail_mod.smtp_public(db)
        return out

    @app.post("/api/settings/smtp/test")
    async def test_smtp(data: SmtpTestIn, sess: dict = Depends(require_owner)) -> dict[str, Any]:
        to = data.to or (sess.get("email") or "")
        if not to:
            cfg = mail_mod.smtp_public(db)
            to = cfg.get("from_addr") or ""
        if not to:
            raise HTTPException(400, "آدرس گیرنده تست را وارد کنید یا ایمیل حساب/فرستنده را تنظیم کنید")
        try:
            await asyncio.to_thread(
                mail_mod.send_mail,
                db,
                vault,
                to=to,
                subject="تست SMTP پنل JojoNet",
                text="این یک ایمیل آزمایشی از پنل JojoNet است. اگر دریافت کردید، تنظیمات SMTP درست است.\n",
            )
        except Exception as exc:
            raise HTTPException(400, f"ارسال تست ناموفق بود: {exc}") from exc
        return {"ok": True, "to": to}

    def panel_public_url(request: Request, path: str, port: int) -> str:
        host = request.headers.get("host") or request.url.hostname or "127.0.0.1"
        if host.startswith("["):
            hostname = host.split("]", 1)[0] + "]"
        else:
            host_name, sep, host_port = host.rpartition(":")
            hostname = host_name if sep and host_port.isdigit() else host
        scheme = "https" if settings.secure_cookies else (request.url.scheme or "https")
        # https on 80/443 must keep the port: browsers send https to 443, not to 80.
        if (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
            return f"{scheme}://{hostname}{path}/"
        return f"{scheme}://{hostname}:{port}{path}/"

    def listen_out(request: Request) -> dict[str, Any]:
        path = app.state.entry.path
        port = app.state.entry.port
        return {"path": path, "port": port, "url": panel_public_url(request, path, port)}

    def port_is_free(port: int) -> bool:
        if port == app.state.entry.port:
            return True
        # Ports below 1024 are opened by systemd, not by this process.
        if port < 1024:
            return True
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.bind(("0.0.0.0", port))
        except OSError:
            return False
        finally:
            sock.close()
        return True

    @app.get("/api/listen")
    async def get_listen(request: Request, _: dict = Depends(require_owner)) -> dict[str, Any]:
        return listen_out(request)

    @app.put("/api/listen")
    async def put_listen(data: ListenIn, request: Request, _: dict = Depends(require_owner)) -> dict[str, Any]:
        try:
            path = normalize_base_path(data.path)
        except ValueError:
            raise HTTPException(422, "مسیر باید یک بخش ۱۶ تا ۶۴ نویسه‌ای از حروف انگلیسی، عدد، _ یا - باشد") from None
        if not port_is_free(data.port):
            raise HTTPException(409, "این پورت الان آزاد نیست")
        if path != app.state.entry.path or data.port != app.state.entry.port:
            try:
                write_listen(settings.data_dir, path, data.port)
            except OSError as exc:
                raise HTTPException(500, "ذخیرهٔ مسیر پنل ممکن نشد") from exc
            app.state.entry.path = path
            app.state.entry.port = data.port
        return listen_out(request)

    def ssl_view() -> dict[str, Any]:
        return build_ssl_view(settings.data_dir, settings.cert, app.state.entry.path, app.state.entry.port)

    @app.get("/api/ssl")
    async def get_ssl(_: dict = Depends(require_owner)) -> dict[str, Any]:
        return ssl_view()

    @app.post("/api/ssl")
    async def post_ssl(data: SslIn, _: dict = Depends(require_owner)) -> dict[str, Any]:
        try:
            domain = normalize_domain(data.domain)
            email = normalize_email(data.email)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None
        if ssl_view().get("state") == "running":
            raise HTTPException(409, "یک درخواست SSL هنوز در جریان است")
        try:
            write_ssl_request(settings.data_dir, domain, email, app.state.entry.path, app.state.entry.port)
        except OSError as exc:
            raise HTTPException(500, "ذخیرهٔ درخواست گواهی ممکن نشد") from exc
        return ssl_view()

    @app.get("/api/guide")
    async def get_guide(_: dict = Depends(require_auth)) -> dict[str, Any]:
        return guide_public_view(settings.data_dir)

    @app.put("/api/guide")
    async def put_guide(data: GuideArticleIn, _: dict = Depends(require_owner)) -> dict[str, Any]:
        payload = data.model_dump()
        try:
            item = write_guide_article(settings.data_dir, payload)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None
        except OSError as exc:
            raise HTTPException(500, "ذخیرهٔ آموزش ممکن نشد") from exc
        return {"ok": True, "article": item}

    @app.delete("/api/guide/{article_id}")
    async def reset_guide(article_id: str, _: dict = Depends(require_owner)) -> dict[str, Any]:
        if not re.fullmatch(r"^[a-z][a-z0-9_]{0,31}$", article_id or ""):
            raise HTTPException(422, "شناسه آموزش نامعتبر است")
        try:
            deleted = delete_guide_article(settings.data_dir, article_id)
        except OSError as exc:
            raise HTTPException(500, "بازنشانی آموزش ممکن نشد") from exc
        return {"ok": True, "reset": deleted}

    @app.get("/api/users")
    async def list_users(_: dict = Depends(require_owner)) -> list[dict[str, Any]]:
        return [user_out(r) for r in db.all("SELECT * FROM admins ORDER BY role DESC, id")]

    @app.post("/api/users")
    async def add_user(data: UserCreateIn, _: dict = Depends(require_owner)) -> dict[str, Any]:
        if db.one("SELECT id FROM admins WHERE username=?", (data.username,)):
            raise HTTPException(409, "این نام کاربری قبلاً ثبت شده است")
        if data.email and email_taken(data.email):
            raise HTTPException(409, "این ایمیل قبلاً ثبت شده است")
        password = data.password or random_password(16)
        generated = data.password is None
        now = datetime.now(timezone.utc).replace(microsecond=0)
        expires = (now + timedelta(days=data.days)).isoformat() if data.days else None
        pw_hash = await asyncio.to_thread(hash_password, password)
        uid = db.insert("admins", {
            "username": data.username,
            "email": data.email,
            "pw_hash": pw_hash,
            "created_at": now.isoformat(),
            "role": "customer",
            "enabled": 1,
            "expires_at": expires,
            "max_servers": data.max_servers,
            "max_tunnels": data.max_tunnels,
            "max_relays": data.max_relays,
            "allow_vpn": 1 if data.allow_vpn else 0,
            "allow_relay": 1 if data.allow_relay else 0,
            "allow_os_update": 1 if data.allow_os_update else 0,
            "allow_term": 1 if data.allow_term else 0,
            "note": data.note,
        })
        out: dict[str, Any] = {"user": user_out(get_admin(uid))}
        if generated:
            out["password"] = password
        return out

    @app.patch("/api/users/{user_id}")
    async def patch_user(user_id: int, data: UserPatchIn, sess: dict = Depends(require_owner)) -> dict[str, Any]:
        row = get_admin(user_id)
        values: dict[str, Any] = {}
        incoming = data.model_dump(exclude_unset=True)
        if row["role"] == "owner":
            if incoming.get("enabled") is False:
                raise HTTPException(400, "مالک پنل را نمی‌توان غیرفعال کرد")
            incoming.pop("enabled", None)
        if "email" in incoming:
            email_val = incoming.pop("email")
            if email_val == "":
                values["email"] = None
            elif email_val is not None:
                if email_taken(email_val, exclude_id=user_id):
                    raise HTTPException(409, "این ایمیل قبلاً ثبت شده است")
                values["email"] = email_val
        bool_fields = ("enabled", "allow_vpn", "allow_relay", "allow_os_update", "allow_term")
        for key, val in incoming.items():
            if key in bool_fields and val is not None:
                values[key] = 1 if val else 0
            elif key in ("max_servers", "max_tunnels", "max_relays", "note"):
                values[key] = val
        if values:
            db.update("admins", user_id, values)
        if values.get("enabled") == 0:
            db.execute("DELETE FROM sessions WHERE admin_id=?", (user_id,))
        return user_out(get_admin(user_id))

    @app.post("/api/users/{user_id}/extend")
    async def extend_user(user_id: int, data: UserExtendIn, _: dict = Depends(require_owner)) -> dict[str, Any]:
        row = get_admin(user_id)
        if row["role"] == "owner":
            raise HTTPException(400, "مالک پنل انقضا ندارد")
        now = datetime.now(timezone.utc).replace(microsecond=0)
        current = row.get("expires_at")
        base = now
        if current:
            try:
                parsed = datetime.fromisoformat(str(current).replace("Z", "+00:00"))
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                if parsed > now:
                    base = parsed
            except ValueError:
                base = now
        db.update("admins", user_id, {"expires_at": (base + timedelta(days=data.days)).isoformat(), "enabled": 1})
        return user_out(get_admin(user_id))

    @app.post("/api/users/{user_id}/password")
    async def reset_user_password(user_id: int, data: UserPasswordIn, sess: dict = Depends(require_owner)) -> dict[str, Any]:
        row = get_admin(user_id)
        if row["role"] == "owner" and row["id"] == sess["admin_id"]:
            raise HTTPException(400, "رمز مالک را از «تغییر رمز عبور» عوض کنید")
        password = data.password or random_password(16)
        generated = data.password is None
        pw_hash = await asyncio.to_thread(hash_password, password)
        db.update("admins", user_id, {"pw_hash": pw_hash})
        db.execute("DELETE FROM sessions WHERE admin_id=?", (user_id,))
        out: dict[str, Any] = {"ok": True}
        if generated:
            out["password"] = password
        return out

    @app.delete("/api/users/{user_id}")
    async def delete_user(user_id: int, sess: dict = Depends(require_owner)) -> dict[str, Any]:
        row = get_admin(user_id)
        if row["id"] == sess["admin_id"] or row["role"] == "owner":
            raise HTTPException(400, "مالک پنل را نمی‌توان حذف کرد")
        if db.one("SELECT id FROM servers WHERE owner_id=?", (user_id,)) or db.one(
            "SELECT id FROM tunnels WHERE owner_id=?", (user_id,)
        ) or db.one("SELECT id FROM relays WHERE owner_id=?", (user_id,)):
            raise HTTPException(409, "ابتدا سرور/تانل/رله این مشتری را حذف کنید")
        db.execute("DELETE FROM sessions WHERE admin_id=?", (user_id,))
        db.execute("DELETE FROM admins WHERE id=?", (user_id,))
        return {"ok": True}

    @app.get("/api/info")
    async def info(_: dict = Depends(require_auth)) -> dict[str, Any]:
        return {
            "panel_version": PANEL_VERSION,
            "jojonet_version": bundle_version(settings.bundle_dir),
            "modes": [{"id": k, "label": v["label"], "first": v["first"], "desc": v["desc"]} for k, v in MODES.items()],
            "xray_nets": list(XRAY_NETS),
            "dnstt_modes": list(DNSTT_MODES),
            "relay_engines": list(RELAY_ENGINES),
            "relay_protos": list(RELAY_PROTOS),
            "direct_modes": sorted(STREAM_MODES),
            "user_sides": ["iran", "kharej"],
            "vpn_panels": [
                {"id": k, "label": v} for k, v in VPN_PANEL_LABELS.items()
            ],
            "commerce": commerce_public(),
        }

    # ---------- servers ----------
    @app.get("/api/servers")
    async def list_servers(sess: dict = Depends(require_auth)) -> list[dict[str, Any]]:
        extra, params = owner_clause(sess)
        owners = admin_names()
        return [server_out(r, owners) for r in db.all(f"SELECT * FROM servers WHERE 1=1{extra} ORDER BY role, name, id", params)]

    def check_secrets(data: ServerIn, existing: dict[str, Any] | None) -> None:
        if data.auth_type == "password":
            if not data.password and not (existing and existing["secret_password"]):
                raise HTTPException(422, "رمز عبور SSH را وارد کنید")
        else:
            if not data.private_key and not (existing and existing["secret_key"]):
                raise HTTPException(422, "کلید خصوصی SSH را وارد کنید")
            if data.private_key:
                import asyncssh

                try:
                    asyncssh.import_private_key(data.private_key, data.key_passphrase or None)
                except (asyncssh.KeyImportError, ValueError):
                    raise HTTPException(422, "کلید خصوصی نامعتبر است یا passphrase اشتباه است")

    def duplicate_check(data: ServerIn, exclude_id: int | None = None) -> None:
        row = db.one(
            "SELECT id FROM servers WHERE host=? AND port=? AND id<>?", (data.host, data.port, exclude_id or -1)
        )
        if row:
            raise HTTPException(409, "سروری با همین IP و پورت قبلاً ثبت شده است")

    @app.post("/api/servers")
    async def add_server(data: ServerIn, sess: dict = Depends(require_auth)) -> dict[str, Any]:
        assert_quota(sess, "servers")
        check_secrets(data, None)
        duplicate_check(data)
        sid = db.insert("servers", {
            "name": data.name,
            "role": data.role,
            "host": data.host,
            "port": data.port,
            "username": data.username,
            "auth_type": data.auth_type,
            "secret_password": vault.encrypt(data.password) if data.auth_type == "password" else None,
            "secret_key": vault.encrypt(data.private_key) if data.auth_type == "key" else None,
            "secret_passphrase": vault.encrypt(data.key_passphrase) if data.auth_type == "key" else None,
            "secret_sudo": vault.encrypt(data.sudo_password),
            "created_at": utcnow(),
            "owner_id": sess["admin_id"],
        })
        return server_out(get_server(sid, sess))

    @app.put("/api/servers/{server_id}")
    async def edit_server(server_id: int, data: ServerIn, sess: dict = Depends(require_auth)) -> dict[str, Any]:
        row = get_server(server_id, sess)
        check_secrets(data, row if data.auth_type == row["auth_type"] else None)
        duplicate_check(data, server_id)
        if data.role != row["role"] and db.one(
            "SELECT id FROM tunnels WHERE iran_id=? OR kharej_id=?", (server_id, server_id)
        ):
            raise HTTPException(409, "نقش سروری که تانل دارد قابل تغییر نیست")
        values: dict[str, Any] = {
            "name": data.name, "role": data.role, "host": data.host, "port": data.port,
            "username": data.username, "auth_type": data.auth_type,
        }
        if data.auth_type == "password":
            values["secret_key"] = values["secret_passphrase"] = None
            if data.password:
                values["secret_password"] = vault.encrypt(data.password)
        else:
            values["secret_password"] = None
            if data.private_key:
                values["secret_key"] = vault.encrypt(data.private_key)
                values["secret_passphrase"] = vault.encrypt(data.key_passphrase)
        if data.sudo_password:
            values["secret_sudo"] = vault.encrypt(data.sudo_password)
        if data.reset_hostkey or data.host != row["host"] or data.port != row["port"]:
            values["hostkey"] = values["hostkey_fingerprint"] = None
        db.update("servers", server_id, values)
        return server_out(get_server(server_id, sess))

    @app.delete("/api/servers/{server_id}")
    async def delete_server(server_id: int, sess: dict = Depends(require_auth)) -> dict[str, Any]:
        get_server(server_id, sess)
        if db.one("SELECT id FROM tunnels WHERE iran_id=? OR kharej_id=?", (server_id, server_id)):
            raise HTTPException(409, "این سرور در تانل‌ها استفاده شده است؛ ابتدا تانل‌ها را حذف کنید")
        if db.one("SELECT id FROM relays WHERE server_id=?", (server_id,)):
            raise HTTPException(409, "این سرور رله فعال دارد؛ ابتدا رله‌ها را حذف کنید")
        db.execute("DELETE FROM servers WHERE id=?", (server_id,))
        return {"ok": True}

    @app.post("/api/servers/{server_id}/test")
    async def test_server(server_id: int, sess: dict = Depends(require_auth)) -> dict[str, Any]:
        row = get_server(server_id, sess)
        job_id = create_job(sess, "server_test", f"تست اتصال {row['name']}", TEST_STEPS,
                             lambda job: orch.job_test_server(job, server_id), server_id=server_id)
        return {"job_id": job_id}

    @app.post("/api/servers/{server_id}/install")
    async def install_server(server_id: int, sess: dict = Depends(require_auth)) -> dict[str, Any]:
        row = get_server(server_id, sess)
        job_id = create_job(sess, "server_install", f"نصب پیش‌نیازها و jojonet روی {row['name']}", INSTALL_STEPS,
                             lambda job: orch.job_install_server(job, server_id), server_id=server_id)
        return {"job_id": job_id}

    # ---------- tunnels ----------
    @app.get("/api/tunnels")
    async def list_tunnels(sess: dict = Depends(require_auth)) -> list[dict[str, Any]]:
        extra, params = owner_clause(sess)
        names = server_names(sess)
        owners = admin_names()
        return [tunnel_out(r, names, owners) for r in db.all(f"SELECT * FROM tunnels WHERE 1=1{extra} ORDER BY id DESC", params)]

    def reality_bundle(row: dict[str, Any]) -> dict[str, Any]:
        from .reality import plan

        iran = db.one("SELECT id, name, host, role FROM servers WHERE id=?", (row["iran_id"],))
        kharej = db.one("SELECT id, name, host, role FROM servers WHERE id=?", (row["kharej_id"],))
        built = plan(row, iran, kharej)
        save = built.pop("_save", None)
        if save:
            opts = dict(row.get("options") or {})
            opts["reality"] = save
            db.update("tunnels", row["id"], {"options": opts})
            row["options"] = opts
        return built

    @app.get("/api/tunnels/{tunnel_id}/reality")
    async def tunnel_reality(tunnel_id: int, sess: dict = Depends(require_auth)) -> dict[str, Any]:
        assert_capability(sess, "allow_vpn", "اوتباند برای این حساب غیرفعال است")
        return reality_bundle(get_tunnel(tunnel_id, sess))

    @app.get("/api/tunnels/live")
    async def list_live_tunnels(sess: dict = Depends(require_auth)) -> dict[str, Any]:
        extra, params = owner_clause(sess)
        servers = db.all(f"SELECT * FROM servers WHERE 1=1{extra} ORDER BY role, name", params)
        tunnels = db.all(f"SELECT * FROM tunnels WHERE 1=1{extra}", params)
        scanned = await orch.scan_live_tunnels(servers, tunnels)
        return {"servers": scanned, "scanned_at": utcnow()}

    def mark_failed(tunnel_id: int, *, refund_if_fail: bool = False):
        def _done(ok: bool) -> None:
            row = db.one("SELECT status, mode, owner_id, last_check FROM tunnels WHERE id=?", (tunnel_id,))
            if not row:
                return
            if ok:
                return
            if row["status"] in ("deploying", "deleting"):
                db.update("tunnels", tunnel_id, {"status": "failed"})
            if (
                refund_if_fail
                and row["status"] == "deploying"
                and row.get("owner_id") is not None
                and wallet_mod.should_refund_failed_deploy(row)
            ):
                wallet_mod.refund_tunnel(db, int(row["owner_id"]), str(row["mode"]), tunnel_id)
        return _done

    def start_deploy(tunnel_id: int, title: str, redeploy: bool, sess: dict[str, Any]) -> int:
        func = orch.job_redeploy if redeploy else orch.job_deploy
        job_id = create_job(
            sess,
            "tunnel_redeploy" if redeploy else "tunnel_deploy",
            title,
            DEPLOY_STEPS,
            lambda job: func(job, tunnel_id),
            tunnel_id=tunnel_id,
            on_finish=mark_failed(tunnel_id, refund_if_fail=not redeploy),
        )
        db.update("tunnels", tunnel_id, {"status": "deploying", "last_job_id": job_id})
        return job_id

    def server_pair(iran_id: int, kharej_id: int, sess: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
        iran, kharej = get_server(iran_id, sess), get_server(kharej_id, sess)
        if iran["role"] != "iran" or kharej["role"] != "kharej":
            raise HTTPException(422, "یک سرور ایران و یک سرور خارج انتخاب کنید")
        if iran["host"] == kharej["host"]:
            raise HTTPException(422, "IP دو سرور نمی‌تواند یکی باشد")
        return iran, kharej

    @app.post("/api/spoof-check")
    async def spoof_check(data: SpoofCheckIn, sess: dict = Depends(require_auth)) -> dict[str, Any]:
        iran, kharej = server_pair(data.iran_id, data.kharej_id, sess)
        opts = data.spoof.model_dump()
        job_id = create_job(sess, "spoof_check", f"بررسی آمادگی Spoof: {iran['name']} ↔ {kharej['name']}", SPOOF_CHECK_STEPS,
                             lambda job: orch.job_spoof_check(job, iran["id"], kharej["id"], opts))
        return {"job_id": job_id}

    @app.post("/api/tunnels")
    async def add_tunnel(data: TunnelIn, sess: dict = Depends(require_auth)) -> dict[str, Any]:
        assert_quota(sess, "tunnels")
        kharej = get_server(data.kharej_id, sess)
        if data.direct:
            if kharej["role"] != "kharej":
                raise HTTPException(422, "حالت مستقیم را روی سرور خارج بسازید")
            if not valid_ipv4(kharej["host"]):
                raise HTTPException(422, "IP سرور خارج معتبر نیست")
            iran = kharej
            title = f"ساخت {MODES[data.mode]['label']} مستقیم روی {kharej['name']}"
        else:
            iran, kharej = server_pair(data.iran_id, data.kharej_id, sess)
            arrow = "ایران → خارج" if data.users == "iran" else "خارج → ایران"
            title = f"ساخت تانل {MODES[data.mode]['label']} ({arrow}): {iran['name']} ↔ {kharej['name']}"
        dup = db.one(
            "SELECT id, status FROM tunnels WHERE mode=? AND iran_id=? AND kharej_id=?", (data.mode, iran["id"], kharej["id"])
        )
        if dup:
            raise HTTPException(409, "همین تانل قبلاً ساخته شده است؛ از «استقرار مجدد» استفاده کنید")
        if data.mode in V6_MODES and db.one(
            "SELECT id FROM tunnels WHERE iran_id=? AND kharej_id=? AND mode IN ('sit','gre6','ipip6')",
            (iran["id"], kharej["id"]),
        ):
            raise HTTPException(409, "برای هر جفت سرور فقط یک تانل IPv6 (6to4/GRE6/IPIP6) مجاز است؛ ابتدا تانل قبلی را حذف کنید")
        if data.mode == "spoof" and db.one(
            "SELECT id FROM tunnels WHERE mode='spoof' AND (iran_id=? OR kharej_id=?)", (iran["id"], kharej["id"])
        ):
            raise HTTPException(409, "هر سرور فقط یک تانل Spoof می‌تواند داشته باشد؛ ابتدا تانل Spoof قبلی را حذف کنید")
        if data.mode in STREAM_MODES and db.one(
            "SELECT id FROM tunnels WHERE mode=? AND (iran_id=? OR kharej_id=?)",
            (data.mode, iran["id"], kharej["id"]),
        ):
            if data.mode == "dnstt":
                raise HTTPException(409, "هر سرور فقط یک تانل DNSTT می‌تواند داشته باشد (UDP/53)؛ ابتدا تانل قبلی را حذف کنید")
            raise HTTPException(409, "هر سرور فقط یک تانل ICMP می‌تواند داشته باشد (سوکت raw)؛ ابتدا تانل قبلی را حذف کنید")
        opts = None
        if data.spoof:
            opts = data.spoof.model_dump()
        elif data.xray:
            opts = data.xray.model_dump()
        elif data.dnstt:
            opts = data.dnstt.model_dump()
        elif data.icmp:
            opts = data.icmp.model_dump()
        if data.direct or data.users == "kharej":
            opts = dict(opts or {})
            opts["users"] = "kharej"
            if data.direct:
                opts["direct"] = True
        elif opts is not None:
            opts = dict(opts)
            opts["users"] = data.users
        charge = wallet_mod.price_for(db, data.mode)
        if charge > 0 and sess.get("role") != "owner":
            if wallet_mod.balance_of(db, sess["admin_id"]) < charge:
                cur = wallet_mod.payment_info(db)["currency"]
                raise HTTPException(
                    402,
                    f"برای ساخت این تانل به {charge:,} {cur} موجودی نیاز است. از بخش کیف پول واریز کنید.",
                )
        tid = db.insert("tunnels", {
            "mode": data.mode, "iran_id": iran["id"], "kharej_id": kharej["id"],
            "status": "deploying", "created_at": utcnow(),
            "options": opts,
            "owner_id": sess["admin_id"],
        })
        charged = 0
        if charge > 0 and sess.get("role") != "owner":
            try:
                charged = wallet_mod.charge_tunnel(db, sess["admin_id"], data.mode, tid)
            except ValueError as exc:
                db.execute("DELETE FROM tunnels WHERE id=?", (tid,))
                raise HTTPException(402, str(exc)) from None
        job_id = start_deploy(tid, title, False, sess)
        out = {"tunnel": tunnel_out(get_tunnel(tid, sess)), "job_id": job_id}
        if charged:
            out["charged"] = charged
            out["wallet_balance"] = wallet_mod.balance_of(db, sess["admin_id"])
        return out

    @app.post("/api/tunnels/{tunnel_id}/verify")
    async def verify_tunnel(tunnel_id: int, sess: dict = Depends(require_auth)) -> dict[str, Any]:
        row = get_tunnel(tunnel_id, sess)
        tunnel_busy(row)
        job_id = create_job(sess, "tunnel_verify", f"بررسی تانل #{tunnel_id} ({MODES[row['mode']]['label']})", VERIFY_STEPS,
                             lambda job: orch.job_verify(job, tunnel_id), tunnel_id=tunnel_id)
        db.update("tunnels", tunnel_id, {"last_job_id": job_id})
        return {"job_id": job_id}

    @app.post("/api/tunnels/{tunnel_id}/redeploy")
    async def redeploy_tunnel(tunnel_id: int, sess: dict = Depends(require_auth)) -> dict[str, Any]:
        row = get_tunnel(tunnel_id, sess)
        tunnel_busy(row)
        return {"job_id": start_deploy(tunnel_id, f"استقرار مجدد تانل #{tunnel_id} ({MODES[row['mode']]['label']})", True, sess)}

    @app.delete("/api/tunnels/{tunnel_id}")
    async def delete_tunnel(tunnel_id: int, data: DeleteIn | None = None, sess: dict = Depends(require_auth)) -> dict[str, Any]:
        row = get_tunnel(tunnel_id, sess)
        force = bool(data and data.force is True)
        if not force:
            tunnel_busy(row)
        job_id = create_job(sess, "tunnel_delete", f"حذف تانل #{tunnel_id} ({MODES[row['mode']]['label']})", DELETE_STEPS,
                             lambda job: orch.job_delete(job, tunnel_id, force), tunnel_id=tunnel_id,
                             on_finish=mark_failed(tunnel_id))
        db.update("tunnels", tunnel_id, {"status": "deleting", "last_job_id": job_id})
        return {"job_id": job_id}

    def get_relay(relay_id: int, sess: dict[str, Any] | None = None) -> dict[str, Any]:
        if sess is None:
            row = db.one("SELECT * FROM relays WHERE id=?", (relay_id,))
        else:
            extra, params = owner_clause(sess)
            row = db.one(f"SELECT * FROM relays WHERE id=?{extra}", (relay_id, *params))
        if row is None:
            raise HTTPException(404, "رله پیدا نشد")
        return row

    def relay_out(row: dict[str, Any], names: dict[int, str] | None = None, owners: dict[int, str] | None = None) -> dict[str, Any]:
        names = server_names() if names is None else names
        out = {k: row[k] for k in (
            "id", "name", "engine", "server_id", "target", "ports", "proto",
            "status", "last_job_id", "last_check", "created_at",
        )}
        out["server_name"] = names.get(row["server_id"], "?")
        return attach_owner(out, row, owners)

    def mark_relay_failed(relay_id: int):
        def _done(ok: bool) -> None:
            row = db.one("SELECT status FROM relays WHERE id=?", (relay_id,))
            if row and not ok and row["status"] in ("deploying", "deleting"):
                db.update("relays", relay_id, {"status": "failed"})
        return _done

    @app.get("/api/relays")
    async def list_relays(sess: dict = Depends(require_auth)) -> list[dict[str, Any]]:
        extra, params = owner_clause(sess)
        names = server_names(sess)
        owners = admin_names()
        return [relay_out(r, names, owners) for r in db.all(f"SELECT * FROM relays WHERE 1=1{extra} ORDER BY id DESC", params)]

    @app.post("/api/relays")
    async def add_relay(data: RelayIn, sess: dict = Depends(require_auth)) -> dict[str, Any]:
        assert_capability(sess, "allow_relay", "ساخت رله برای این حساب غیرفعال است")
        assert_quota(sess, "relays")
        srv = get_server(data.iran_id, sess)
        name = data.name or f"{data.engine}-{data.ports.split(',')[0].split(':')[0]}"
        if not valid_relay_name(name):
            raise HTTPException(422, "نام رله نامعتبر است")
        if db.one("SELECT id FROM relays WHERE name=? AND owner_id=?", (name, sess["admin_id"])):
            raise HTTPException(409, "رله‌ای با این نام قبلاً ثبت شده است")
        rid = db.insert("relays", {
            "name": name, "engine": data.engine, "server_id": srv["id"],
            "target": data.target, "ports": data.ports, "proto": data.proto,
            "status": "deploying", "created_at": utcnow(),
            "owner_id": sess["admin_id"],
        })
        job_id = create_job(
            sess, "relay_add", f"ساخت رله {name} ({data.engine}) روی {srv['name']}", RELAY_STEPS,
            lambda job: orch.job_relay_add(job, rid), server_id=srv["id"], on_finish=mark_relay_failed(rid),
        )
        db.update("relays", rid, {"last_job_id": job_id})
        return {"relay": relay_out(get_relay(rid, sess)), "job_id": job_id}

    @app.post("/api/relays/{relay_id}/stats")
    async def relay_stats(relay_id: int, sess: dict = Depends(require_auth)) -> dict[str, Any]:
        row = get_relay(relay_id, sess)
        job_id = create_job(
            sess, "relay_stats", f"آمار رله {row['name']}", RELAY_STATS_STEPS,
            lambda job: orch.job_relay_stats(job, relay_id), server_id=row["server_id"],
        )
        db.update("relays", relay_id, {"last_job_id": job_id})
        return {"job_id": job_id}

    @app.delete("/api/relays/{relay_id}")
    async def delete_relay(relay_id: int, data: DeleteIn | None = None, sess: dict = Depends(require_auth)) -> dict[str, Any]:
        row = get_relay(relay_id, sess)
        force = bool(data and data.force is True)
        if not force and row["status"] in ("deploying", "deleting"):
            raise HTTPException(409, "یک عملیات دیگر روی این رله در حال اجراست")
        job_id = create_job(
            sess, "relay_delete", f"حذف رله {row['name']}", RELAY_DELETE_STEPS,
            lambda job: orch.job_relay_delete(job, relay_id, force), server_id=row["server_id"],
            on_finish=mark_relay_failed(relay_id),
        )
        db.update("relays", relay_id, {"status": "deleting", "last_job_id": job_id})
        return {"job_id": job_id}

    @app.post("/api/servers/{server_id}/enable-boot")
    async def enable_boot(server_id: int, sess: dict = Depends(require_auth)) -> dict[str, Any]:
        row = get_server(server_id, sess)
        job_id = create_job(
            sess, "tunnel_enable_boot", f"ماندن تانل‌ها بعد از ریبوت روی {row['name']}", ENABLE_BOOT_STEPS,
            lambda job: orch.job_enable_boot(job, server_id), server_id=server_id,
        )
        return {"job_id": job_id}

    @app.post("/api/servers/enable-boot-all")
    async def enable_boot_all(sess: dict = Depends(require_auth)) -> dict[str, Any]:
        extra, params = owner_clause(sess)
        servers = db.all(f"SELECT id, name FROM servers WHERE 1=1{extra} ORDER BY id", params)
        job_ids = []
        for row in servers:
            job_ids.append(create_job(
                sess, "tunnel_enable_boot", f"ماندن تانل‌ها بعد از ریبوت روی {row['name']}", ENABLE_BOOT_STEPS,
                lambda job, sid=row["id"]: orch.job_enable_boot(job, sid), server_id=row["id"],
            ))
        return {"job_ids": job_ids, "count": len(job_ids)}

    @app.delete("/api/servers/{server_id}/remote-tunnels/{name}")
    async def delete_remote_tunnel(
        server_id: int, name: str, data: DeleteIn | None = None, sess: dict = Depends(require_auth),
    ) -> dict[str, Any]:
        row = get_server(server_id, sess)
        if not valid_iface(name):
            raise HTTPException(422, "نام تانل نامعتبر است")
        force = bool(data and data.force is True)
        extra, params = owner_clause(sess)
        tunnels = db.all(f"SELECT * FROM tunnels WHERE 1=1{extra}", params)
        tid = orch.match_panel_tunnel_id(server_id, name, tunnels)
        if tid is not None:
            trow = get_tunnel(tid, sess)
            if not force:
                tunnel_busy(trow)
            job_id = create_job(
                sess, "tunnel_delete", f"حذف تانل #{tid} ({MODES[trow['mode']]['label']})", DELETE_STEPS,
                lambda job: orch.job_delete(job, tid, force), tunnel_id=tid,
                on_finish=mark_failed(tid),
            )
            db.update("tunnels", tid, {"status": "deleting", "last_job_id": job_id})
            return {"job_id": job_id, "panel_tunnel_id": tid, "orphan": False}
        job_id = create_job(
            sess, "tunnel_delete_remote", f"حذف تانل ثبت‌نشده {name} از {row['name']}", REMOTE_DELETE_STEPS,
            lambda job: orch.job_delete_remote_tunnel(job, server_id, name, force), server_id=server_id,
        )
        return {"job_id": job_id, "panel_tunnel_id": None, "orphan": True}

    @app.post("/api/servers/{server_id}/dns")
    async def server_dns(server_id: int, data: DnsIn, sess: dict = Depends(require_auth)) -> dict[str, Any]:
        row = get_server(server_id, sess)
        job_id = create_job(
            sess, "server_dns", f"تنظیم DNS روی {row['name']}", DNS_STEPS,
            lambda job: orch.job_server_dns(job, server_id, data.dns1, data.dns2 or ""),
            server_id=server_id,
        )
        return {"job_id": job_id}

    @app.post("/api/servers/{server_id}/ssl")
    async def server_ssl(server_id: int, data: SslIn, sess: dict = Depends(require_auth)) -> dict[str, Any]:
        row = get_server(server_id, sess)
        try:
            domain = normalize_domain(data.domain)
            email = normalize_email(data.email)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None
        job_id = create_job(
            sess,
            "server_ssl",
            f"گواهی SSL رایگان برای {domain} روی {row['name']}",
            SERVER_SSL_STEPS,
            lambda job: orch.job_server_ssl(job, server_id, domain, email),
            server_id=server_id,
        )
        return {"job_id": job_id}

    @app.post("/api/servers/{server_id}/ping-test")
    async def server_ping(server_id: int, sess: dict = Depends(require_auth)) -> dict[str, Any]:
        row = get_server(server_id, sess)
        job_id = create_job(
            sess, "server_ping", f"تست پینگ {row['name']}", PING_TEST_STEPS,
            lambda job: orch.job_server_ping(job, server_id), server_id=server_id,
        )
        return {"job_id": job_id}

    @app.post("/api/servers/{server_id}/update-os")
    async def server_update_os(server_id: int, sess: dict = Depends(require_auth)) -> dict[str, Any]:
        assert_capability(sess, "allow_os_update", "آپدیت سیستم برای این حساب غیرفعال است")
        row = get_server(server_id, sess)
        job_id = create_job(
            sess, "server_update", f"آپدیت سیستم {row['name']}", OS_UPDATE_STEPS,
            lambda job: orch.job_server_update(job, server_id), server_id=server_id,
        )
        return {"job_id": job_id}

    @app.get("/api/servers/{server_id}/vpn-panels")
    async def server_vpn_panels(server_id: int, kind: str | None = None, sess: dict = Depends(require_auth)) -> dict[str, Any]:
        get_server(server_id, sess)
        try:
            st = await orch.probe_vpn_panels(server_id)
        except Exception as exc:
            raise HTTPException(400, f"وضعیت پنل روی سرور خوانده نشد: {exc}") from exc
        if kind in VPN_PANEL_LABELS:
            raw = {
                "xui": "1" if st.get("xui") else "0",
                "xui_flavor": st.get("xui_flavor") or "",
                "pasarguard": "1" if st.get("pasarguard") else "0",
            }
            st["kind"] = kind
            st["already"] = vpn_panel_already(kind, raw)
            st["conflict"] = vpn_panel_conflict(kind, raw)
            if st["conflict"]:
                st["message"] = (
                    "روی این سرور قبلاً X-UI اصلی نصب شده است."
                    if kind == "xui"
                    else "روی این سرور قبلاً 3x-ui سنایی نصب شده است."
                )
            elif st["already"]:
                label = VPN_PANEL_LABELS[kind]
                run = st.get("xui_running") if kind != "pasarguard" else st.get("pasarguard_running")
                st["message"] = f"همین پنل ({label}) از قبل روی سرور نصب است" + (" و روشن است." if run else ".")
            else:
                st["message"] = f"{VPN_PANEL_LABELS[kind]} روی این سرور نصب نیست."
        return st

    @app.post("/api/servers/{server_id}/vpn-panel")
    async def server_vpn_panel(server_id: int, data: VpnPanelIn, sess: dict = Depends(require_auth)) -> dict[str, Any]:
        assert_capability(sess, "allow_vpn", "نصب پنل VPN برای این حساب غیرفعال است")
        row = get_server(server_id, sess)
        label = VPN_PANEL_LABELS.get(data.kind, data.kind)
        job_id = create_job(
            sess, "vpn_panel", f"نصب {label} روی {row['name']}", VPN_PANEL_STEPS,
            lambda job: orch.job_vpn_panel(job, server_id, data.kind), server_id=server_id,
        )
        return {"job_id": job_id}

    def visible_job(job_id: int, sess: dict[str, Any]) -> dict[str, Any]:
        row = jobs.get(job_id)
        if row is None or (not is_owner(sess) and row.get("owner_id") != sess["admin_id"]):
            raise HTTPException(404, "کار پیدا نشد")
        return row

    def job_out(row: dict[str, Any], owners: dict[int, str] | None = None) -> dict[str, Any]:
        out = dict(row)
        return attach_owner(out, row, owners)

    # ---------- jobs ----------
    @app.get("/api/jobs")
    async def list_jobs(limit: int = 50, sess: dict = Depends(require_auth)) -> list[dict[str, Any]]:
        owners = admin_names()
        oid = None if is_owner(sess) else sess["admin_id"]
        return [job_out(r, owners) for r in jobs.list(max(1, min(limit, 200)), owner_id=oid)]

    @app.get("/api/jobs/{job_id}")
    async def get_job(job_id: int, sess: dict = Depends(require_auth)) -> dict[str, Any]:
        return job_out(visible_job(job_id, sess))

    @app.get("/api/jobs/{job_id}/stream")
    async def stream_job(job_id: int, request: Request, sess: dict = Depends(require_auth)) -> StreamingResponse:
        visible_job(job_id, sess)

        def sse(event: str, data: Any) -> str:
            return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"

        async def gen():
            q = jobs.subscribe(job_id)
            try:
                snap = jobs.get(job_id)
                yield sse("snapshot", snap)
                if snap and snap["status"] in ("ok", "failed"):
                    yield sse("done", {"status": snap["status"]})
                    return
                while True:
                    if await request.is_disconnected():
                        return
                    try:
                        event, data = await asyncio.wait_for(q.get(), timeout=15)
                    except (asyncio.TimeoutError, TimeoutError):
                        yield ": keepalive\n\n"
                        continue
                    yield sse(event, data)
                    if event == "done":
                        return
            finally:
                jobs.unsubscribe(job_id, q)

        return StreamingResponse(gen(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})

    # ---------- service orders ----------
    def _order_pack_server(data: OrderServerIn) -> dict[str, Any]:
        include = bool(data.include_access) or bool(data.password) or bool(data.private_key) or bool(data.sudo_password)
        out: dict[str, Any] = {
            "name": data.name,
            "host": data.host,
            "port": data.port,
            "username": data.username,
            "auth_type": data.auth_type,
            "has_access": False,
        }
        if not include:
            return out
        if data.auth_type == "password":
            if not data.password:
                raise HTTPException(422, f"برای ارسال دسترسی سرور {data.name} رمز SSH لازم است")
            out["secret_password"] = vault.encrypt(data.password)
        else:
            if not data.private_key:
                raise HTTPException(422, f"برای ارسال دسترسی سرور {data.name} کلید خصوصی لازم است")
            out["secret_key"] = vault.encrypt(data.private_key)
            out["secret_passphrase"] = vault.encrypt(data.key_passphrase)
        if data.sudo_password:
            out["secret_sudo"] = vault.encrypt(data.sudo_password)
        out["has_access"] = True
        return out

    def _order_public_server(raw: dict[str, Any] | None, *, reveal: bool) -> dict[str, Any] | None:
        if not raw:
            return None
        out = {
            "name": raw.get("name"),
            "host": raw.get("host"),
            "port": raw.get("port"),
            "username": raw.get("username"),
            "auth_type": raw.get("auth_type") or "password",
            "has_access": bool(raw.get("has_access")),
        }
        if reveal and raw.get("has_access"):
            try:
                if raw.get("secret_password"):
                    out["password"] = vault.decrypt(raw.get("secret_password"))
                if raw.get("secret_key"):
                    out["private_key"] = vault.decrypt(raw.get("secret_key"))
                if raw.get("secret_passphrase"):
                    out["key_passphrase"] = vault.decrypt(raw.get("secret_passphrase"))
                if raw.get("secret_sudo"):
                    out["sudo_password"] = vault.decrypt(raw.get("secret_sudo"))
            except ValueError:
                out["access_error"] = "رمزگشایی دسترسی ممکن نیست"
        return out

    def order_out(row: dict[str, Any], sess: dict[str, Any], names: dict[int, str] | None = None) -> dict[str, Any]:
        names = names or admin_names()
        reveal = is_owner(sess)
        return {
            "id": row["id"],
            "customer_id": row["customer_id"],
            "customer_username": names.get(row["customer_id"], "?"),
            "status": row["status"],
            "mode": row["mode"],
            "mode_label": MODES.get(row["mode"], {}).get("label", row["mode"]),
            "message": row.get("message"),
            "iran": _order_public_server(row.get("iran_json"), reveal=reveal),
            "kharej": _order_public_server(row.get("kharej_json"), reveal=reveal),
            "owner_note": row.get("owner_note"),
            "tunnel_id": row.get("tunnel_id"),
            "created_at": row["created_at"],
            "decided_at": row.get("decided_at"),
        }

    def get_order(order_id: int, sess: dict[str, Any]) -> dict[str, Any]:
        row = db.one("SELECT * FROM service_orders WHERE id=?", (order_id,))
        if row is None:
            raise HTTPException(404, "سفارش پیدا نشد")
        if not is_owner(sess) and row["customer_id"] != sess["admin_id"]:
            raise HTTPException(404, "سفارش پیدا نشد")
        return row

    def customer_sess(customer_id: int) -> dict[str, Any]:
        row = db.one(
            """SELECT id AS admin_id, username, role, enabled, expires_at,
                      max_servers, max_tunnels, max_relays,
                      allow_vpn, allow_relay, allow_os_update, allow_term, note
               FROM admins WHERE id=?""",
            (customer_id,),
        )
        if row is None or row.get("role") == "owner":
            raise HTTPException(422, "مشتری سفارش معتبر نیست")
        return row

    def _merge_order_server(base: dict[str, Any] | None, patch: OrderServerIn | None) -> OrderServerIn:
        b = base or {}
        if patch is None:
            if not b.get("name") or not b.get("host"):
                raise HTTPException(422, "مشخصات سرور ناقص است")
            return OrderServerIn(
                name=b["name"],
                host=b["host"],
                port=int(b.get("port") or 22),
                username=b.get("username") or "root",
                auth_type=b.get("auth_type") or "password",
                include_access=False,
            )
        return patch

    def _ensure_order_server(
        customer_id: int,
        role: Literal["iran", "kharej"],
        stored: dict[str, Any] | None,
        patch: OrderServerIn | None,
        server_id: int | None,
    ) -> dict[str, Any]:
        if server_id is not None:
            row = db.one("SELECT * FROM servers WHERE id=? AND owner_id=?", (server_id, customer_id))
            if row is None:
                raise HTTPException(422, f"سرور #{server_id} متعلق به این مشتری نیست")
            if row["role"] != role:
                raise HTTPException(422, f"سرور انتخاب‌شده باید نقش {role} داشته باشد")
            return row
        data = _merge_order_server(stored, patch)
        secrets_src = patch if patch and (patch.include_access or patch.password or patch.private_key) else None
        password = passphrase = key = sudo = None
        auth_type = data.auth_type
        if secrets_src:
            password = secrets_src.password
            key = secrets_src.private_key
            passphrase = secrets_src.key_passphrase
            sudo = secrets_src.sudo_password
            auth_type = secrets_src.auth_type
        elif stored and stored.get("has_access"):
            try:
                password = vault.decrypt(stored.get("secret_password"))
                key = vault.decrypt(stored.get("secret_key"))
                passphrase = vault.decrypt(stored.get("secret_passphrase"))
                sudo = vault.decrypt(stored.get("secret_sudo"))
            except ValueError as exc:
                raise HTTPException(422, "رمزگشایی دسترسی سفارش ممکن نیست؛ مشخصات را در انجام سفارش کامل کنید") from exc
            auth_type = stored.get("auth_type") or auth_type
        if auth_type == "password" and not password:
            raise HTTPException(422, f"برای ساخت سرور {role} رمز SSH لازم است")
        if auth_type == "key" and not key:
            raise HTTPException(422, f"برای ساخت سرور {role} کلید خصوصی لازم است")
        dup = db.one("SELECT id FROM servers WHERE host=? AND port=?", (data.host, data.port))
        if dup:
            row = db.one("SELECT * FROM servers WHERE id=?", (dup["id"],))
            if row and row.get("owner_id") == customer_id and row.get("role") == role:
                return row
            raise HTTPException(409, f"سروری با IP {data.host}:{data.port} از قبل ثبت شده است")
        # Quota for customer (two servers may be created).
        used = usage_counts(customer_id)["servers"]
        cust = customer_sess(customer_id)
        cap = cust.get("max_servers")
        if cap is not None and used >= int(cap):
            raise HTTPException(422, f"سقف سرور مشتری پر است ({used}/{int(cap)})")
        sid = db.insert("servers", {
            "name": data.name,
            "role": role,
            "host": data.host,
            "port": data.port,
            "username": data.username,
            "auth_type": auth_type,
            "secret_password": vault.encrypt(password) if auth_type == "password" else None,
            "secret_key": vault.encrypt(key) if auth_type == "key" else None,
            "secret_passphrase": vault.encrypt(passphrase) if auth_type == "key" else None,
            "secret_sudo": vault.encrypt(sudo),
            "created_at": utcnow(),
            "owner_id": customer_id,
        })
        return db.one("SELECT * FROM servers WHERE id=?", (sid,))  # type: ignore[return-value]

    @app.get("/api/orders")
    async def list_orders(sess: dict = Depends(require_auth)) -> list[dict[str, Any]]:
        names = admin_names()
        if is_owner(sess):
            rows = db.all("SELECT * FROM service_orders ORDER BY id DESC LIMIT 200")
        else:
            rows = db.all(
                "SELECT * FROM service_orders WHERE customer_id=? ORDER BY id DESC LIMIT 100",
                (sess["admin_id"],),
            )
        return [order_out(r, sess, names) for r in rows]

    @app.get("/api/orders/{order_id}")
    async def get_order_api(order_id: int, sess: dict = Depends(require_auth)) -> dict[str, Any]:
        return order_out(get_order(order_id, sess), sess)

    @app.post("/api/orders")
    async def create_order(data: OrderIn, sess: dict = Depends(require_auth)) -> dict[str, Any]:
        if is_owner(sess):
            raise HTTPException(403, "مالک پنل سفارش ثبت نمی‌کند؛ از ساخت تانل مستقیم استفاده کنید")
        assert_active(sess)
        pending = db.one(
            "SELECT COUNT(*) AS n FROM service_orders WHERE customer_id=? AND status='pending'",
            (sess["admin_id"],),
        )
        if int((pending or {"n": 0})["n"]) >= MAX_PENDING_ORDERS:
            raise HTTPException(422, f"حداکثر {MAX_PENDING_ORDERS} سفارش در انتظار همزمان مجاز است")
        oid = db.insert("service_orders", {
            "customer_id": sess["admin_id"],
            "status": "pending",
            "mode": data.mode,
            "message": data.message,
            "iran_json": _order_pack_server(data.iran),
            "kharej_json": _order_pack_server(data.kharej),
            "created_at": utcnow(),
        })
        return order_out(get_order(oid, sess), sess)

    @app.post("/api/orders/{order_id}/cancel")
    async def cancel_order(order_id: int, sess: dict = Depends(require_auth)) -> dict[str, Any]:
        row = get_order(order_id, sess)
        if row["status"] != "pending":
            raise HTTPException(409, "فقط سفارش در انتظار قابل لغو است")
        db.update("service_orders", order_id, {"status": "cancelled", "decided_at": utcnow()})
        return order_out(get_order(order_id, sess), sess)

    @app.post("/api/orders/{order_id}/decide")
    async def decide_order(order_id: int, data: OrderDecideIn, sess: dict = Depends(require_owner)) -> dict[str, Any]:
        row = get_order(order_id, sess)
        if row["status"] != "pending":
            raise HTTPException(409, "این سفارش دیگر در انتظار نیست")
        status = "approved" if data.action == "approve" else "rejected"
        db.update("service_orders", order_id, {
            "status": status,
            "owner_note": data.note,
            "decided_at": utcnow(),
        })
        return order_out(get_order(order_id, sess), sess)

    @app.post("/api/orders/{order_id}/fulfill")
    async def fulfill_order(order_id: int, data: OrderFulfillIn, sess: dict = Depends(require_owner)) -> dict[str, Any]:
        row = get_order(order_id, sess)
        if row["status"] not in ("approved", "pending"):
            raise HTTPException(409, "فقط سفارش تأییدشده (یا در انتظار) قابل انجام است")
        customer_id = int(row["customer_id"])
        cust = customer_sess(customer_id)
        reason = account_block_reason(cust)
        if reason:
            raise HTTPException(422, reason)
        if row["status"] == "pending":
            db.update("service_orders", order_id, {"status": "approved", "decided_at": utcnow()})
            row = get_order(order_id, sess)
        mode = row["mode"]
        if data.direct:
            kharej = _ensure_order_server(customer_id, "kharej", row.get("kharej_json"), data.kharej, data.kharej_id)
            iran = kharej
        else:
            iran = _ensure_order_server(customer_id, "iran", row.get("iran_json"), data.iran, data.iran_id)
            kharej = _ensure_order_server(customer_id, "kharej", row.get("kharej_json"), data.kharej, data.kharej_id)
            if iran["host"] == kharej["host"]:
                raise HTTPException(422, "IP دو سرور نمی‌تواند یکی باشد")
        try:
            tunnel_data = TunnelIn(
                mode=mode,
                iran_id=None if data.direct else iran["id"],
                kharej_id=kharej["id"],
                direct=data.direct,
                users=data.users,
                spoof=data.spoof,
                xray=data.xray,
                dnstt=data.dnstt,
                icmp=data.icmp,
            )
        except ValidationError as exc:
            msgs = []
            for err in exc.errors():
                msg = str(err.get("msg", "")).removeprefix("Value error, ")
                msgs.append(msg)
            raise HTTPException(422, "؛ ".join(msgs) or "گزینه‌های تانل نامعتبر است") from exc
        used_t = usage_counts(customer_id)["tunnels"]
        cap_t = cust.get("max_tunnels")
        if cap_t is not None and used_t >= int(cap_t):
            raise HTTPException(422, f"سقف تانل مشتری پر است ({used_t}/{int(cap_t)})")
        dup = db.one(
            "SELECT id FROM tunnels WHERE mode=? AND iran_id=? AND kharej_id=?",
            (mode, iran["id"], kharej["id"]),
        )
        if dup:
            raise HTTPException(409, "همین تانل قبلاً برای مشتری ساخته شده است")
        if mode in V6_MODES and db.one(
            "SELECT id FROM tunnels WHERE iran_id=? AND kharej_id=? AND mode IN ('sit','gre6','ipip6')",
            (iran["id"], kharej["id"]),
        ):
            raise HTTPException(409, "برای هر جفت سرور فقط یک تانل IPv6 (6to4/GRE6/IPIP6) مجاز است؛ ابتدا تانل قبلی را حذف کنید")
        if mode == "spoof" and db.one(
            "SELECT id FROM tunnels WHERE mode='spoof' AND (iran_id=? OR kharej_id=?)",
            (iran["id"], kharej["id"]),
        ):
            raise HTTPException(409, "هر سرور فقط یک تانل Spoof می‌تواند داشته باشد؛ ابتدا تانل Spoof قبلی را حذف کنید")
        if mode in STREAM_MODES and db.one(
            "SELECT id FROM tunnels WHERE mode=? AND (iran_id=? OR kharej_id=?)",
            (mode, iran["id"], kharej["id"]),
        ):
            if mode == "dnstt":
                raise HTTPException(409, "هر سرور فقط یک تانل DNSTT می‌تواند داشته باشد (UDP/53)؛ ابتدا تانل قبلی را حذف کنید")
            raise HTTPException(409, "هر سرور فقط یک تانل ICMP می‌تواند داشته باشد (سوکت raw)؛ ابتدا تانل قبلی را حذف کنید")
        opts = None
        if tunnel_data.spoof:
            opts = tunnel_data.spoof.model_dump()
        elif tunnel_data.xray:
            opts = tunnel_data.xray.model_dump()
        elif tunnel_data.dnstt:
            opts = tunnel_data.dnstt.model_dump()
        elif tunnel_data.icmp:
            opts = tunnel_data.icmp.model_dump()
        if tunnel_data.direct or tunnel_data.users == "kharej":
            opts = dict(opts or {})
            opts["users"] = "kharej"
            if tunnel_data.direct:
                opts["direct"] = True
        elif opts is not None:
            opts = dict(opts)
            opts["users"] = tunnel_data.users
        if tunnel_data.direct:
            title = f"انجام سفارش #{order_id}: {MODES[mode]['label']} مستقیم روی {kharej['name']}"
        else:
            arrow = "ایران → خارج" if tunnel_data.users == "iran" else "خارج → ایران"
            title = f"انجام سفارش #{order_id}: {MODES[mode]['label']} ({arrow}) {iran['name']} ↔ {kharej['name']}"
        charge = wallet_mod.price_for(db, mode)
        if charge > 0:
            if wallet_mod.balance_of(db, customer_id) < charge:
                cur = wallet_mod.payment_info(db)["currency"]
                raise HTTPException(
                    402,
                    f"موجودی مشتری برای این تانل کافی نیست ({charge:,} {cur}). ابتدا واریز را تأیید کنید.",
                )
        tid = db.insert("tunnels", {
            "mode": mode, "iran_id": iran["id"], "kharej_id": kharej["id"],
            "status": "deploying", "created_at": utcnow(),
            "options": opts,
            "owner_id": customer_id,
        })
        charged = 0
        if charge > 0:
            try:
                charged = wallet_mod.charge_tunnel(db, customer_id, mode, tid)
            except ValueError as exc:
                db.execute("DELETE FROM tunnels WHERE id=?", (tid,))
                raise HTTPException(402, str(exc)) from None
        job_id = create_job(
            sess, "tunnel_deploy", title, DEPLOY_STEPS,
            lambda job: orch.job_deploy(job, tid),
            tunnel_id=tid, owner_id=customer_id, on_finish=mark_failed(tid, refund_if_fail=True),
        )
        db.update("tunnels", tid, {"status": "deploying", "last_job_id": job_id})
        db.update("service_orders", order_id, {
            "status": "done",
            "tunnel_id": tid,
            "decided_at": row.get("decided_at") or utcnow(),
        })
        out = {
            "order": order_out(get_order(order_id, sess), sess),
            "tunnel": tunnel_out(get_tunnel(tid, sess)),
            "job_id": job_id,
        }
        if charged:
            out["charged"] = charged
            out["wallet_balance"] = wallet_mod.balance_of(db, customer_id)
        return out

    # ---------- support tickets ----------
    def _pack_ticket_access(access: TicketAccessIn | None) -> str | None:
        if access is None:
            return None
        payload = {k: v for k, v in access.model_dump().items() if v is not None and str(v).strip() != ""}
        if not payload:
            return None
        return vault.encrypt(json.dumps(payload, ensure_ascii=False))

    def _public_ticket_access(
        blob: str | None, *, reveal: bool, author_id: int, sess: dict[str, Any]
    ) -> dict[str, Any] | None:
        if not blob:
            return None
        if not reveal and author_id != sess["admin_id"] and not is_owner(sess):
            return {"has_access": True}
        if not reveal and not is_owner(sess) and author_id == sess["admin_id"]:
            # Author may see own submitted access in the same account.
            reveal = True
        if not reveal and not is_owner(sess):
            return {"has_access": True}
        try:
            raw = json.loads(vault.decrypt(blob) or "{}")
        except (ValueError, TypeError, json.JSONDecodeError):
            return {"has_access": True, "access_error": "رمزگشایی دسترسی ممکن نیست"}
        if is_owner(sess) or author_id == sess["admin_id"]:
            out = dict(raw)
            out["has_access"] = True
            return out
        return {"has_access": True}

    def ticket_out(row: dict[str, Any], sess: dict[str, Any], names: dict[int, str] | None = None,
                   messages: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        names = names or admin_names()
        out = {
            "id": row["id"],
            "customer_id": row["customer_id"],
            "customer_username": names.get(row["customer_id"], "?"),
            "subject": row["subject"],
            "category": row["category"],
            "status": row["status"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }
        if messages is not None:
            out["messages"] = messages
        else:
            last = db.one(
                "SELECT body, created_at FROM ticket_messages WHERE ticket_id=? ORDER BY id DESC LIMIT 1",
                (row["id"],),
            )
            out["last_message"] = (last or {}).get("body")
            out["last_message_at"] = (last or {}).get("created_at")
            cnt = db.one("SELECT COUNT(*) AS n FROM ticket_messages WHERE ticket_id=?", (row["id"],))
            out["message_count"] = int((cnt or {"n": 0})["n"])
        return out

    def get_ticket(ticket_id: int, sess: dict[str, Any]) -> dict[str, Any]:
        row = db.one("SELECT * FROM tickets WHERE id=?", (ticket_id,))
        if row is None:
            raise HTTPException(404, "تیکت پیدا نشد")
        if not is_owner(sess) and row["customer_id"] != sess["admin_id"]:
            raise HTTPException(404, "تیکت پیدا نشد")
        return row

    def _author_role(admin_id: int) -> str:
        row = db.one("SELECT role FROM admins WHERE id=?", (admin_id,))
        return (row or {}).get("role") or "customer"

    @app.get("/api/tickets")
    async def list_tickets(sess: dict = Depends(require_auth)) -> list[dict[str, Any]]:
        names = admin_names()
        if is_owner(sess):
            rows = db.all("SELECT * FROM tickets ORDER BY updated_at DESC, id DESC LIMIT 200")
        else:
            rows = db.all(
                "SELECT * FROM tickets WHERE customer_id=? ORDER BY updated_at DESC, id DESC LIMIT 100",
                (sess["admin_id"],),
            )
        return [ticket_out(r, sess, names) for r in rows]

    @app.post("/api/tickets")
    async def create_ticket(data: TicketCreateIn, sess: dict = Depends(require_auth)) -> dict[str, Any]:
        assert_active(sess)
        customer_id = sess["admin_id"]
        # Owner can open an internal note-style ticket under own id; still allowed.
        now = utcnow()
        tid = db.insert("tickets", {
            "customer_id": customer_id,
            "subject": data.subject,
            "category": data.category,
            "status": "open",
            "created_at": now,
            "updated_at": now,
        })
        db.insert("ticket_messages", {
            "ticket_id": tid,
            "author_id": sess["admin_id"],
            "body": data.body,
            "access_blob": _pack_ticket_access(data.access),
            "created_at": now,
        })
        return await get_ticket_api(tid, sess)

    @app.get("/api/tickets/{ticket_id}")
    async def get_ticket_api(ticket_id: int, sess: dict = Depends(require_auth)) -> dict[str, Any]:
        row = get_ticket(ticket_id, sess)
        names = admin_names()
        msgs = db.all("SELECT * FROM ticket_messages WHERE ticket_id=? ORDER BY id ASC", (ticket_id,))
        messages = []
        for m in msgs:
            item = {
                "id": m["id"],
                "ticket_id": m["ticket_id"],
                "author_id": m["author_id"],
                "author_username": names.get(m["author_id"], "?"),
                "author_role": _author_role(m["author_id"]),
                "body": m["body"],
                "access": _public_ticket_access(
                    m.get("access_blob"), reveal=is_owner(sess), author_id=m["author_id"], sess=sess
                ),
                "created_at": m["created_at"],
            }
            messages.append(item)
        return ticket_out(row, sess, names, messages)

    @app.post("/api/tickets/{ticket_id}/messages")
    async def add_ticket_message(ticket_id: int, data: TicketMessageIn, sess: dict = Depends(require_auth)) -> dict[str, Any]:
        row = get_ticket(ticket_id, sess)
        if row["status"] == "closed" and not is_owner(sess):
            raise HTTPException(409, "تیکت بسته است؛ فقط مالک می‌تواند دوباره باز کند")
        now = utcnow()
        db.insert("ticket_messages", {
            "ticket_id": ticket_id,
            "author_id": sess["admin_id"],
            "body": data.body,
            "access_blob": _pack_ticket_access(data.access),
            "created_at": now,
        })
        status = row["status"]
        if is_owner(sess):
            status = "answered"
        elif status == "answered":
            status = "open"
        elif status == "closed":
            status = "open"
        db.update("tickets", ticket_id, {"status": status, "updated_at": now})
        return await get_ticket_api(ticket_id, sess)

    @app.patch("/api/tickets/{ticket_id}")
    async def patch_ticket(ticket_id: int, data: TicketPatchIn, sess: dict = Depends(require_owner)) -> dict[str, Any]:
        get_ticket(ticket_id, sess)
        db.update("tickets", ticket_id, {"status": data.status, "updated_at": utcnow()})
        return await get_ticket_api(ticket_id, sess)

    def deposit_out(row: dict[str, Any], names: dict[int, str] | None = None) -> dict[str, Any]:
        names = names or admin_names()
        return {
            "id": row["id"],
            "user_id": row["user_id"],
            "username": names.get(row["user_id"], "?"),
            "amount": int(row["amount"]),
            "method": row["method"],
            "tracking_code": row["tracking_code"],
            "note": row.get("note") or "",
            "tunnel_mode": row.get("tunnel_mode"),
            "status": row["status"],
            "owner_note": row.get("owner_note") or "",
            "created_at": row["created_at"],
            "decided_at": row.get("decided_at"),
        }

    @app.get("/api/wallet")
    async def get_wallet(sess: dict = Depends(require_auth)) -> dict[str, Any]:
        uid = sess["admin_id"]
        ledger = db.all(
            "SELECT * FROM wallet_ledger WHERE user_id=? ORDER BY id DESC LIMIT 50",
            (uid,),
        )
        deposits = db.all(
            "SELECT * FROM deposit_requests WHERE user_id=? ORDER BY id DESC LIMIT 30",
            (uid,),
        )
        return {
            "balance": wallet_mod.balance_of(db, uid),
            "commerce": commerce_public(),
            "ledger": [
                {
                    "id": r["id"],
                    "kind": r["kind"],
                    "amount": int(r["amount"]),
                    "balance_after": int(r["balance_after"]),
                    "note": r.get("note") or "",
                    "created_at": r["created_at"],
                }
                for r in ledger
            ],
            "deposits": [deposit_out(r) for r in deposits],
        }

    @app.post("/api/wallet/deposits")
    async def create_deposit(data: DepositIn, sess: dict = Depends(require_auth)) -> dict[str, Any]:
        if sess.get("role") == "owner":
            raise HTTPException(400, "مالک نیازی به واریز ندارد")
        pending = db.one(
            "SELECT COUNT(*) AS n FROM deposit_requests WHERE user_id=? AND status='pending'",
            (sess["admin_id"],),
        )
        if pending and int(pending["n"] or 0) >= 5:
            raise HTTPException(429, "چند درخواست واریز در انتظار تأیید دارید")
        pay = wallet_mod.payment_info(db)
        if data.method == "card" and not pay["card"]:
            raise HTTPException(422, "مالک هنوز شماره کارت ثبت نکرده است")
        if data.method == "crypto" and not pay["wallet_address"]:
            raise HTTPException(422, "مالک هنوز آدرس ولت ثبت نکرده است")
        if data.tunnel_mode and wallet_mod.sell_enabled(db):
            price = wallet_mod.price_for(db, data.tunnel_mode)
            if price > 0 and data.amount < price:
                raise HTTPException(
                    422,
                    f"مبلغ واریز از قیمت این تانل کمتر است (حداقل {price:,} {pay['currency']})",
                )
        did = db.insert("deposit_requests", {
            "user_id": sess["admin_id"],
            "amount": data.amount,
            "method": data.method,
            "tracking_code": data.tracking_code,
            "note": (data.note or "").strip(),
            "tunnel_mode": data.tunnel_mode,
            "status": "pending",
            "created_at": utcnow(),
        })
        row = db.one("SELECT * FROM deposit_requests WHERE id=?", (did,))
        return {"ok": True, "deposit": deposit_out(row)}

    @app.get("/api/wallet/deposits")
    async def list_deposits(sess: dict = Depends(require_auth)) -> list[dict[str, Any]]:
        names = admin_names()
        if is_owner(sess):
            rows = db.all("SELECT * FROM deposit_requests ORDER BY id DESC LIMIT 200")
        else:
            rows = db.all(
                "SELECT * FROM deposit_requests WHERE user_id=? ORDER BY id DESC LIMIT 100",
                (sess["admin_id"],),
            )
        return [deposit_out(r, names) for r in rows]

    @app.post("/api/wallet/deposits/{deposit_id}/decide")
    async def decide_deposit(deposit_id: int, data: DepositDecideIn, sess: dict = Depends(require_owner)) -> dict[str, Any]:
        row = db.one("SELECT * FROM deposit_requests WHERE id=?", (deposit_id,))
        if not row:
            raise HTTPException(404, "درخواست واریز پیدا نشد")
        if row["status"] != "pending":
            raise HTTPException(409, "این درخواست قبلاً رسیدگی شده است")
        now = utcnow()
        if data.action == "reject":
            db.update("deposit_requests", deposit_id, {
                "status": "rejected",
                "owner_note": (data.note or "").strip(),
                "decided_at": now,
            })
        else:
            # Keep credit + status flip in one SQLite transaction so a crash cannot double-approve.
            try:
                with db._lock:
                    pending = db._conn.execute(
                        "SELECT status FROM deposit_requests WHERE id=?", (deposit_id,)
                    ).fetchone()
                    if not pending or pending["status"] != "pending":
                        raise HTTPException(409, "این درخواست قبلاً رسیدگی شده است")
                    db._conn.execute("BEGIN IMMEDIATE")
                    try:
                        db._conn.execute(
                            "UPDATE admins SET wallet_balance = COALESCE(wallet_balance, 0) + ? WHERE id=?",
                            (int(row["amount"]), int(row["user_id"])),
                        )
                        bal_row = db._conn.execute(
                            "SELECT wallet_balance FROM admins WHERE id=?", (int(row["user_id"]),)
                        ).fetchone()
                        bal = int(bal_row["wallet_balance"] or 0) if bal_row else 0
                        db._conn.execute(
                            "INSERT INTO wallet_ledger (user_id, actor_id, kind, amount, balance_after, note, ref_type, ref_id, created_at) "
                            "VALUES (?, ?, 'deposit', ?, ?, ?, 'deposit', ?, ?)",
                            (
                                int(row["user_id"]),
                                sess["admin_id"],
                                int(row["amount"]),
                                bal,
                                f"تأیید واریز #{deposit_id} — {row['tracking_code']}"[:500],
                                deposit_id,
                                now,
                            ),
                        )
                        db._conn.execute(
                            "UPDATE deposit_requests SET status='approved', owner_note=?, decided_at=? WHERE id=? AND status='pending'",
                            ((data.note or "").strip(), now, deposit_id),
                        )
                        if db._conn.execute("SELECT changes()").fetchone()[0] != 1:
                            raise HTTPException(409, "این درخواست قبلاً رسیدگی شده است")
                        db._conn.execute("COMMIT")
                    except Exception:
                        try:
                            db._conn.execute("ROLLBACK")
                        except Exception:
                            pass
                        raise
            except HTTPException:
                raise
            except ValueError as exc:
                raise HTTPException(422, str(exc)) from None
        fresh = db.one("SELECT * FROM deposit_requests WHERE id=?", (deposit_id,))
        return {"ok": True, "deposit": deposit_out(fresh), "wallet_balance": wallet_mod.balance_of(db, int(row["user_id"]))}

    @app.post("/api/users/{user_id}/wallet")
    async def adjust_user_wallet(user_id: int, data: WalletAdjustIn, sess: dict = Depends(require_owner)) -> dict[str, Any]:
        user = get_admin(user_id)
        if user.get("role") == "owner":
            raise HTTPException(400, "کیف پول مالک از این مسیر تغییر نمی‌کند")
        try:
            if data.direction == "credit":
                bal = wallet_mod.credit(
                    db, user_id, data.amount, kind="admin_credit",
                    note=(data.note or "افزایش توسط مالک").strip(),
                    actor_id=sess["admin_id"],
                )
            else:
                bal = wallet_mod.debit(
                    db, user_id, data.amount, kind="admin_debit",
                    note=(data.note or "کاهش توسط مالک").strip(),
                    actor_id=sess["admin_id"],
                )
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None
        return {"ok": True, "wallet_balance": bal, "user": user_out(get_admin(user_id))}

    @app.get("/api/users/{user_id}/overview")
    async def user_overview(user_id: int, sess: dict = Depends(require_owner)) -> dict[str, Any]:
        user = get_admin(user_id)
        servers = db.all("SELECT * FROM servers WHERE owner_id=? ORDER BY id", (user_id,))
        tunnels = db.all("SELECT * FROM tunnels WHERE owner_id=? ORDER BY id", (user_id,))
        relays = db.all("SELECT * FROM relays WHERE owner_id=? ORDER BY id", (user_id,))
        ledger = db.all(
            "SELECT * FROM wallet_ledger WHERE user_id=? ORDER BY id DESC LIMIT 40",
            (user_id,),
        )
        deposits = db.all(
            "SELECT * FROM deposit_requests WHERE user_id=? ORDER BY id DESC LIMIT 40",
            (user_id,),
        )
        names = server_names()
        return {
            "user": user_out(user),
            "servers": [server_out(s) for s in servers],
            "tunnels": [tunnel_out(t, names) for t in tunnels],
            "relays": [relay_out(r, names) for r in relays],
            "ledger": [
                {
                    "id": r["id"],
                    "kind": r["kind"],
                    "amount": int(r["amount"]),
                    "balance_after": int(r["balance_after"]),
                    "note": r.get("note") or "",
                    "created_at": r["created_at"],
                }
                for r in ledger
            ],
            "deposits": [deposit_out(r) for r in deposits],
        }

    @app.websocket("/ws/term")
    async def term_ws(ws: WebSocket) -> None:
        await ws.accept()
        token = ws.cookies.get(COOKIE)
        if not token or len(token) > 128:
            await ws.send_json({"t": "e", "m": "ابتدا وارد شوید"})
            await ws.close()
            return
        sess = db.one(
            """SELECT s.token_hash, s.admin_id, s.csrf, s.created_at AS session_created_at,
                      s.expires_at AS session_expires_at, a.username, a.role, a.enabled,
                      a.expires_at, a.max_servers, a.max_tunnels, a.max_relays,
                      a.allow_vpn, a.allow_relay, a.allow_os_update, a.allow_term, a.note
               FROM sessions s JOIN admins a ON a.id = s.admin_id WHERE s.token_hash=?""",
            (token_hash(token),),
        )
        if sess is None or sess["session_expires_at"] < utcnow():
            await ws.send_json({"t": "e", "m": "ابتدا وارد شوید"})
            await ws.close()
            return
        blocked = account_block_reason(sess)
        if blocked:
            await ws.send_json({"t": "e", "m": blocked})
            await ws.close()
            return
        if not term_allowed(sess):
            await ws.send_json({"t": "e", "m": "ترمینال برای این حساب غیرفعال است"})
            await ws.close()
            return
        try:
            server_id = int(ws.query_params.get("server_id") or "0")
        except (TypeError, ValueError):
            server_id = 0
        if server_id <= 0:
            await ws.send_json({"t": "e", "m": "سرور را انتخاب کنید"})
            await ws.close()
            return
        try:
            server = get_server(server_id, sess)
        except HTTPException as exc:
            detail = exc.detail if isinstance(exc.detail, str) else "سرور پیدا نشد"
            await ws.send_json({"t": "e", "m": detail})
            await ws.close()
            return
        try:
            creds = orch.creds(server)
        except Exception as exc:
            await ws.send_json({"t": "e", "m": str(exc)})
            await ws.close()
            return
        try:
            cols = int(ws.query_params.get("cols") or 80)
            rows = int(ws.query_params.get("rows") or 24)
        except (TypeError, ValueError):
            cols, rows = 80, 24
        label = f"{server.get('username') or 'root'}@{server.get('host')}"
        await run_web_shell(ws, creds, cols, rows, f"{server.get('name') or ''} {label}".strip())

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        msgs = []
        for err in exc.errors():
            msg = str(err.get("msg", "")).removeprefix("Value error, ")
            field = ".".join(str(p) for p in err.get("loc", ())[1:])
            msgs.append(msg if err.get("type") == "value_error" or not field else f"{field}: {msg}")
        return JSONResponse({"detail": "؛ ".join(msgs) or "ورودی نامعتبر است"}, status_code=422)

    app.mount("/static", VersionedStaticFiles(directory=str(settings.static_dir), check_dir=False, version=asset_version), name="static")
    app.add_middleware(SelectiveGZip)
    app.add_middleware(SecretPathGate, entry=entry, domain=settings.domain)
    return app
