from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import socket
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Literal
from urllib.parse import parse_qs

from fastapi import Depends, FastAPI, HTTPException, Request, Response, WebSocket
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from starlette.middleware.gzip import GZipMiddleware
from starlette.types import ASGIApp, Receive, Scope, Send

from . import PANEL_VERSION
from .config import PanelEntry, Settings, load_settings, normalize_base_path, write_listen
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

    def __init__(self, app: ASGIApp, entry: PanelEntry) -> None:
        self.app = app
        self.entry = entry

    def _allowed(self, path: str) -> bool:
        base = self.entry.path
        if len(path) < len(base):
            return False
        head = path[: len(base)]
        if not hmac.compare_digest(head.encode(), base.encode()):
            return False
        return len(path) == len(base) or path[len(base)] == "/"

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return
        path = scope.get("path") or "/"
        raw = path.lower()
        base = self.entry.path
        if ".." in path or "\\" in path or "%2e" in raw or "%2f" in raw or not self._allowed(path):
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

    @field_validator("note")
    @classmethod
    def _note(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = str(v).strip()
        return v[:500] if v else None


class UserExtendIn(BaseModel):
    days: int = Field(ge=1, le=3650)


class PanelSettingsIn(BaseModel):
    terms_enabled: bool


class ListenIn(BaseModel):
    path: str = Field(min_length=1, max_length=80)
    port: int = Field(ge=1, le=65535)


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
                      s.expires_at AS session_expires_at, a.username, a.role, a.enabled,
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
        kw["owner_id"] = sess["admin_id"]
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
        }

    def me_payload(sess: dict[str, Any]) -> dict[str, Any]:
        usage = usage_counts(sess["admin_id"])
        return {
            "username": sess["username"],
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

    def get_admin(user_id: int) -> dict[str, Any]:
        row = db.one("SELECT * FROM admins WHERE id=?", (user_id,))
        if row is None:
            raise HTTPException(404, "کاربر پیدا نشد")
        return row

    @app.get("/api/settings")
    async def get_settings(_: dict = Depends(require_owner)) -> dict[str, Any]:
        return {"terms_enabled": terms_globally_on()}

    @app.patch("/api/settings")
    async def patch_settings(data: PanelSettingsIn, _: dict = Depends(require_owner)) -> dict[str, Any]:
        db.execute(
            "INSERT INTO panel_settings (key, value) VALUES ('terms_enabled', ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            ("1" if data.terms_enabled else "0",),
        )
        return {"terms_enabled": terms_globally_on()}

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

    @app.get("/api/users")
    async def list_users(_: dict = Depends(require_owner)) -> list[dict[str, Any]]:
        return [user_out(r) for r in db.all("SELECT * FROM admins ORDER BY role DESC, id")]

    @app.post("/api/users")
    async def add_user(data: UserCreateIn, _: dict = Depends(require_owner)) -> dict[str, Any]:
        if db.one("SELECT id FROM admins WHERE username=?", (data.username,)):
            raise HTTPException(409, "این نام کاربری قبلاً ثبت شده است")
        password = data.password or random_password(16)
        generated = data.password is None
        now = datetime.now(timezone.utc).replace(microsecond=0)
        expires = (now + timedelta(days=data.days)).isoformat() if data.days else None
        pw_hash = await asyncio.to_thread(hash_password, password)
        uid = db.insert("admins", {
            "username": data.username,
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

    @app.get("/api/tunnels/live")
    async def list_live_tunnels(sess: dict = Depends(require_auth)) -> dict[str, Any]:
        extra, params = owner_clause(sess)
        servers = db.all(f"SELECT * FROM servers WHERE 1=1{extra} ORDER BY role, name", params)
        tunnels = db.all(f"SELECT * FROM tunnels WHERE 1=1{extra}", params)
        scanned = await orch.scan_live_tunnels(servers, tunnels)
        return {"servers": scanned, "scanned_at": utcnow()}

    def mark_failed(tunnel_id: int):
        def _done(ok: bool) -> None:
            row = db.one("SELECT status FROM tunnels WHERE id=?", (tunnel_id,))
            if row and not ok and row["status"] in ("deploying", "deleting"):
                db.update("tunnels", tunnel_id, {"status": "failed"})
        return _done

    def start_deploy(tunnel_id: int, title: str, redeploy: bool, sess: dict[str, Any]) -> int:
        func = orch.job_redeploy if redeploy else orch.job_deploy
        job_id = create_job(sess, "tunnel_redeploy" if redeploy else "tunnel_deploy", title, DEPLOY_STEPS,
                             lambda job: func(job, tunnel_id), tunnel_id=tunnel_id, on_finish=mark_failed(tunnel_id))
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
        tid = db.insert("tunnels", {
            "mode": data.mode, "iran_id": iran["id"], "kharej_id": kharej["id"],
            "status": "deploying", "created_at": utcnow(),
            "options": opts,
            "owner_id": sess["admin_id"],
        })
        job_id = start_deploy(tid, title, False, sess)
        return {"tunnel": tunnel_out(get_tunnel(tid, sess)), "job_id": job_id}

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
    app.add_middleware(SecretPathGate, entry=entry)
    return app
