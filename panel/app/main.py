from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Literal
from urllib.parse import parse_qs

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from starlette.middleware.gzip import GZipMiddleware
from starlette.types import ASGIApp, Receive, Scope, Send

from . import PANEL_VERSION
from .config import Settings, load_settings
from .db import Database, utcnow
from .jobs import JobManager
from .orchestrator import (
    DELETE_STEPS,
    DEPLOY_STEPS,
    INSTALL_STEPS,
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
    record_login_failure,
    token_hash,
    verify_password,
)
from .validators import MODES, NAME_RE, USER_RE, valid_host_port, valid_ipv4

COOKIE = "jn_session"
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
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
)


# ---------- request models ----------
class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class PasswordIn(BaseModel):
    old_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=10, max_length=256)


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
            raise ValueError("نام سرور باید ۱ تا ۴۰ کاراکتر و بدون کاراکتر کنترلی یا <> باشد")
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


class TunnelIn(BaseModel):
    mode: str
    iran_id: int
    kharej_id: int
    spoof: SpoofOptions | None = None

    @field_validator("mode")
    @classmethod
    def _mode(cls, v: str) -> str:
        if v not in MODES:
            raise ValueError("نوع تانل نامعتبر است")
        return v

    @model_validator(mode="after")
    def _options(self) -> "TunnelIn":
        if self.mode == "spoof" and self.spoof is None:
            raise ValueError("برای تانل Spoof، IP جعلی هر دو سرور لازم است")
        if self.mode != "spoof":
            self.spoof = None
        return self


class SpoofCheckIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    iran_id: int
    kharej_id: int
    spoof: SpoofOptions


class DeleteIn(BaseModel):
    force: bool = False


# ---------- app factory ----------
def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        yield
        await app.state.jobs.shutdown()
        app.state.db.close()

    app = FastAPI(title="JojoNet Panel", version=PANEL_VERSION, docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    db = Database(settings.db_path)
    vault = Vault(settings.vault_key_path)
    jobs = JobManager(db)
    orch = Orchestrator(db, vault, settings, jobs)
    app.state.settings, app.state.db, app.state.vault, app.state.jobs, app.state.orch = settings, db, vault, jobs, orch

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

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        if settings.secure_cookies:
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
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
            "SELECT s.*, a.username FROM sessions s JOIN admins a ON a.id = s.admin_id WHERE s.token_hash=?",
            (token_hash(token),),
        )
        if row is None:
            return None
        if row["expires_at"] < utcnow():
            db.execute("DELETE FROM sessions WHERE token_hash=?", (row["token_hash"],))
            return None
        return row

    def require_auth(request: Request) -> dict[str, Any]:
        row = session_row(request)
        if row is None:
            raise HTTPException(401, "ابتدا وارد شوید")
        if request.method not in ("GET", "HEAD"):
            sent = request.headers.get("x-csrf-token", "")
            if not sent or not hmac.compare_digest(sent, row["csrf"]):
                raise HTTPException(403, "توکن CSRF نامعتبر است؛ صفحه را تازه کنید")
        return row

    def server_out(row: dict[str, Any]) -> dict[str, Any]:
        return {
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

    def server_names() -> dict[int, str]:
        return {r["id"]: r["name"] for r in db.all("SELECT id, name FROM servers")}

    def tunnel_out(row: dict[str, Any], names: dict[int, str] | None = None) -> dict[str, Any]:
        names = server_names() if names is None else names
        out = {k: row[k] for k in (
            "id", "mode", "iran_id", "kharej_id", "status", "iran_iface", "kharej_iface",
            "tun_iran_ip", "tun_kharej_ip", "forward_ports", "options", "last_job_id", "last_check", "created_at",
        )}
        out["iran_name"] = names.get(row["iran_id"], "?")
        out["kharej_name"] = names.get(row["kharej_id"], "?")
        return out

    def get_server(server_id: int) -> dict[str, Any]:
        row = db.one("SELECT * FROM servers WHERE id=?", (server_id,))
        if row is None:
            raise HTTPException(404, "سرور پیدا نشد")
        return row

    def get_tunnel(tunnel_id: int) -> dict[str, Any]:
        row = db.one("SELECT * FROM tunnels WHERE id=?", (tunnel_id,))
        if row is None:
            raise HTTPException(404, "تانل پیدا نشد")
        return row

    def tunnel_busy(row: dict[str, Any]) -> None:
        if row["status"] in ("deploying", "deleting"):
            raise HTTPException(409, "یک عملیات دیگر روی این تانل در حال اجراست")

    # ---------- public ----------
    @app.get("/", response_class=HTMLResponse)
    async def index() -> HTMLResponse:
        refresh_assets()
        if assets["html"] is None:
            raise HTTPException(500, "فایل‌های رابط کاربری پیدا نشد")
        return HTMLResponse(assets["html"], headers={"Cache-Control": "no-store"})

    @app.get("/api/health")
    async def health() -> dict[str, Any]:
        return {"ok": True, "version": PANEL_VERSION}

    @app.post("/api/login")
    async def login(data: LoginIn, request: Request, response: Response) -> dict[str, Any]:
        ip = client_ip(request)
        if not login_allowed(db, ip):
            raise HTTPException(429, "تلاش‌های ناموفق زیاد بود؛ ۵ دقیقه دیگر دوباره امتحان کنید")
        admin = db.one("SELECT * FROM admins WHERE username=?", (data.username,))
        ok = await asyncio.to_thread(verify_password, data.password, admin["pw_hash"] if admin else DUMMY_HASH)
        if not admin or not ok:
            record_login_failure(db, ip)
            raise HTTPException(401, "نام کاربری یا رمز عبور اشتباه است")
        clear_login_failures(db, ip)
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
            secure=settings.secure_cookies, samesite="strict", path="/",
        )
        return {"ok": True, "csrf": csrf}

    @app.post("/api/logout")
    async def logout(response: Response, sess: dict = Depends(require_auth)) -> dict[str, Any]:
        db.execute("DELETE FROM sessions WHERE token_hash=?", (sess["token_hash"],))
        response.delete_cookie(COOKIE, path="/")
        return {"ok": True}

    @app.get("/api/me")
    async def me(sess: dict = Depends(require_auth)) -> dict[str, Any]:
        return {
            "username": sess["username"],
            "csrf": sess["csrf"],
            "panel_version": PANEL_VERSION,
            "jojonet_version": bundle_version(settings.bundle_dir),
        }

    @app.post("/api/password")
    async def change_password(data: PasswordIn, sess: dict = Depends(require_auth)) -> dict[str, Any]:
        admin = db.one("SELECT * FROM admins WHERE id=?", (sess["admin_id"],))
        if not admin or not await asyncio.to_thread(verify_password, data.old_password, admin["pw_hash"]):
            raise HTTPException(400, "رمز فعلی اشتباه است")
        new_hash = await asyncio.to_thread(hash_password, data.new_password)
        db.update("admins", admin["id"], {"pw_hash": new_hash})
        db.execute("DELETE FROM sessions WHERE admin_id=? AND token_hash<>?", (admin["id"], sess["token_hash"]))
        return {"ok": True}

    @app.get("/api/info")
    async def info(_: dict = Depends(require_auth)) -> dict[str, Any]:
        return {
            "panel_version": PANEL_VERSION,
            "jojonet_version": bundle_version(settings.bundle_dir),
            "modes": [{"id": k, "label": v["label"], "first": v["first"], "desc": v["desc"]} for k, v in MODES.items()],
        }

    # ---------- servers ----------
    @app.get("/api/servers")
    async def list_servers(_: dict = Depends(require_auth)) -> list[dict[str, Any]]:
        return [server_out(r) for r in db.all("SELECT * FROM servers ORDER BY role, name, id")]

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
    async def add_server(data: ServerIn, _: dict = Depends(require_auth)) -> dict[str, Any]:
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
        })
        return server_out(get_server(sid))

    @app.put("/api/servers/{server_id}")
    async def edit_server(server_id: int, data: ServerIn, _: dict = Depends(require_auth)) -> dict[str, Any]:
        row = get_server(server_id)
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
        return server_out(get_server(server_id))

    @app.delete("/api/servers/{server_id}")
    async def delete_server(server_id: int, _: dict = Depends(require_auth)) -> dict[str, Any]:
        get_server(server_id)
        if db.one("SELECT id FROM tunnels WHERE iran_id=? OR kharej_id=?", (server_id, server_id)):
            raise HTTPException(409, "این سرور در تانل‌ها استفاده شده است؛ ابتدا تانل‌ها را حذف کنید")
        db.execute("DELETE FROM servers WHERE id=?", (server_id,))
        return {"ok": True}

    @app.post("/api/servers/{server_id}/test")
    async def test_server(server_id: int, _: dict = Depends(require_auth)) -> dict[str, Any]:
        row = get_server(server_id)
        job_id = jobs.create("server_test", f"تست اتصال {row['name']}", TEST_STEPS,
                             lambda job: orch.job_test_server(job, server_id), server_id=server_id)
        return {"job_id": job_id}

    @app.post("/api/servers/{server_id}/install")
    async def install_server(server_id: int, _: dict = Depends(require_auth)) -> dict[str, Any]:
        row = get_server(server_id)
        job_id = jobs.create("server_install", f"نصب پیش‌نیازها و jojonet روی {row['name']}", INSTALL_STEPS,
                             lambda job: orch.job_install_server(job, server_id), server_id=server_id)
        return {"job_id": job_id}

    # ---------- tunnels ----------
    @app.get("/api/tunnels")
    async def list_tunnels(_: dict = Depends(require_auth)) -> list[dict[str, Any]]:
        names = server_names()
        return [tunnel_out(r, names) for r in db.all("SELECT * FROM tunnels ORDER BY id DESC")]

    def mark_failed(tunnel_id: int):
        def _done(ok: bool) -> None:
            row = db.one("SELECT status FROM tunnels WHERE id=?", (tunnel_id,))
            if row and not ok and row["status"] in ("deploying", "deleting"):
                db.update("tunnels", tunnel_id, {"status": "failed"})
        return _done

    def start_deploy(tunnel_id: int, title: str, redeploy: bool) -> int:
        func = orch.job_redeploy if redeploy else orch.job_deploy
        job_id = jobs.create("tunnel_redeploy" if redeploy else "tunnel_deploy", title, DEPLOY_STEPS,
                             lambda job: func(job, tunnel_id), tunnel_id=tunnel_id, on_finish=mark_failed(tunnel_id))
        db.update("tunnels", tunnel_id, {"status": "deploying", "last_job_id": job_id})
        return job_id

    def server_pair(iran_id: int, kharej_id: int) -> tuple[dict[str, Any], dict[str, Any]]:
        iran, kharej = get_server(iran_id), get_server(kharej_id)
        if iran["role"] != "iran" or kharej["role"] != "kharej":
            raise HTTPException(422, "یک سرور ایران و یک سرور خارج انتخاب کنید")
        if iran["host"] == kharej["host"]:
            raise HTTPException(422, "IP دو سرور نمی‌تواند یکی باشد")
        return iran, kharej

    @app.post("/api/spoof-check")
    async def spoof_check(data: SpoofCheckIn, _: dict = Depends(require_auth)) -> dict[str, Any]:
        iran, kharej = server_pair(data.iran_id, data.kharej_id)
        opts = data.spoof.model_dump()
        job_id = jobs.create("spoof_check", f"بررسی آمادگی Spoof: {iran['name']} ↔ {kharej['name']}", SPOOF_CHECK_STEPS,
                             lambda job: orch.job_spoof_check(job, iran["id"], kharej["id"], opts))
        return {"job_id": job_id}

    @app.post("/api/tunnels")
    async def add_tunnel(data: TunnelIn, _: dict = Depends(require_auth)) -> dict[str, Any]:
        iran, kharej = server_pair(data.iran_id, data.kharej_id)
        dup = db.one(
            "SELECT id, status FROM tunnels WHERE mode=? AND iran_id=? AND kharej_id=?", (data.mode, iran["id"], kharej["id"])
        )
        if dup:
            raise HTTPException(409, "همین تانل قبلاً ساخته شده است؛ از «استقرار مجدد» استفاده کنید")
        if data.mode == "spoof" and db.one(
            "SELECT id FROM tunnels WHERE mode='spoof' AND (iran_id=? OR kharej_id=?)", (iran["id"], kharej["id"])
        ):
            raise HTTPException(409, "هر سرور فقط یک تانل Spoof می‌تواند داشته باشد؛ ابتدا تانل Spoof قبلی را حذف کنید")
        tid = db.insert("tunnels", {
            "mode": data.mode, "iran_id": iran["id"], "kharej_id": kharej["id"],
            "status": "deploying", "created_at": utcnow(),
            "options": data.spoof.model_dump() if data.spoof else None,
        })
        label = MODES[data.mode]["label"]
        job_id = start_deploy(tid, f"ساخت تانل {label}: {iran['name']} ↔ {kharej['name']}", False)
        return {"tunnel": tunnel_out(get_tunnel(tid)), "job_id": job_id}

    @app.post("/api/tunnels/{tunnel_id}/verify")
    async def verify_tunnel(tunnel_id: int, _: dict = Depends(require_auth)) -> dict[str, Any]:
        row = get_tunnel(tunnel_id)
        tunnel_busy(row)
        job_id = jobs.create("tunnel_verify", f"بررسی تانل #{tunnel_id} ({MODES[row['mode']]['label']})", VERIFY_STEPS,
                             lambda job: orch.job_verify(job, tunnel_id), tunnel_id=tunnel_id)
        db.update("tunnels", tunnel_id, {"last_job_id": job_id})
        return {"job_id": job_id}

    @app.post("/api/tunnels/{tunnel_id}/redeploy")
    async def redeploy_tunnel(tunnel_id: int, _: dict = Depends(require_auth)) -> dict[str, Any]:
        row = get_tunnel(tunnel_id)
        tunnel_busy(row)
        return {"job_id": start_deploy(tunnel_id, f"استقرار مجدد تانل #{tunnel_id} ({MODES[row['mode']]['label']})", True)}

    @app.delete("/api/tunnels/{tunnel_id}")
    async def delete_tunnel(tunnel_id: int, data: DeleteIn | None = None, _: dict = Depends(require_auth)) -> dict[str, Any]:
        row = get_tunnel(tunnel_id)
        force = bool(data and data.force is True)
        if not force:
            tunnel_busy(row)
        job_id = jobs.create("tunnel_delete", f"حذف تانل #{tunnel_id} ({MODES[row['mode']]['label']})", DELETE_STEPS,
                             lambda job: orch.job_delete(job, tunnel_id, force), tunnel_id=tunnel_id,
                             on_finish=mark_failed(tunnel_id))
        db.update("tunnels", tunnel_id, {"status": "deleting", "last_job_id": job_id})
        return {"job_id": job_id}

    # ---------- jobs ----------
    @app.get("/api/jobs")
    async def list_jobs(limit: int = 50, _: dict = Depends(require_auth)) -> list[dict[str, Any]]:
        return jobs.list(max(1, min(limit, 200)))

    @app.get("/api/jobs/{job_id}")
    async def get_job(job_id: int, _: dict = Depends(require_auth)) -> dict[str, Any]:
        row = jobs.get(job_id)
        if row is None:
            raise HTTPException(404, "کار پیدا نشد")
        return row

    @app.get("/api/jobs/{job_id}/stream")
    async def stream_job(job_id: int, request: Request, _: dict = Depends(require_auth)) -> StreamingResponse:
        if jobs.get(job_id) is None:
            raise HTTPException(404, "کار پیدا نشد")

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
    return app
