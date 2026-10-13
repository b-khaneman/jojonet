"""Panel TLS status and the request file the root helper issues a certificate from."""

from __future__ import annotations

import json
import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.x509.oid import NameOID

# A public hostname. Addresses, single labels, and wildcards are rejected.
_HOST_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,253}\.[A-Za-z]{2,63}$")

REQUEST_NAME = "ssl.request"
STATUS_NAME = "ssl.status.json"
RUNNING_SECONDS = 300


def normalize_domain(raw: str) -> str:
    value = (raw or "").strip().lower().rstrip(".")
    for prefix in ("https://", "http://"):
        if value.startswith(prefix):
            value = value[len(prefix):]
            break
    value = value.split("/", 1)[0].split("?", 1)[0]
    if value.startswith("["):
        raise ValueError("یک دامنه وارد کنید، نه آدرس IP")
    value = value.split(":", 1)[0]
    try:
        ascii_name = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("دامنه نامعتبر است") from exc
    if not _HOST_RE.fullmatch(ascii_name):
        raise ValueError("یک دامنه مثل panel.example.com وارد کنید")
    if ascii_name == "localhost" or ascii_name.endswith(".local") or ascii_name.endswith(".localhost"):
        raise ValueError("برای این نام گواهی عمومی صادر نمی‌شود")
    return ascii_name


def normalize_email(raw: str | None) -> str:
    value = (raw or "").strip().lower()
    if not value:
        return ""
    if "\n" in value or "\r" in value or len(value) > 254 or not _EMAIL_RE.fullmatch(value):
        raise ValueError("ایمیل نامعتبر است")
    return value


def https_url(domain: str, path: str, port: int) -> str:
    base = "/" + str(path or "").strip().strip("/")
    if base == "/":
        base = ""
    if int(port) == 443:
        return f"https://{domain}{base}/"
    return f"https://{domain}:{int(port)}{base}/"


def _write_private(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8")
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    os.replace(tmp, path)


def _parse_time(raw: object) -> datetime | None:
    if not raw:
        return None
    text = str(raw).replace("Z", "+00:00")
    try:
        found = datetime.fromisoformat(text)
    except ValueError:
        return None
    if found.tzinfo is None:
        found = found.replace(tzinfo=timezone.utc)
    return found


def write_ssl_request(data_dir: Path, domain: str, email: str, path: str, port: int) -> dict[str, Any]:
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    body = {
        "id": secrets.token_hex(8),
        "domain": domain,
        "email": email,
        "path": path,
        "port": int(port),
        "created_at": now,
    }
    status = {
        "id": body["id"],
        "state": "running",
        "domain": domain,
        "url": "",
        "issuer": "",
        "not_after": "",
        "error": "",
        "created_at": now,
    }
    # Status first, then the request. The path unit wakes up on the request file.
    _write_private(Path(data_dir) / STATUS_NAME, status)
    _write_private(Path(data_dir) / REQUEST_NAME, body)
    return body


def read_ssl_status(data_dir: Path) -> dict[str, Any] | None:
    path = Path(data_dir) / STATUS_NAME
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError, UnicodeError):
        return None
    if not isinstance(data, dict):
        return None
    if str(data.get("state") or "") != "running":
        return data
    started = _parse_time(data.get("created_at"))
    if started is None:
        try:
            started = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
        except OSError:
            started = None
    if started is not None and datetime.now(timezone.utc) - started > timedelta(seconds=RUNNING_SECONDS):
        expired = dict(data)
        expired["state"] = "error"
        expired["error"] = "زمان دریافت گواهی تمام شد. دامنه و آزاد بودن پورت ۸۰ را بررسی کنید و دوباره تلاش کنید."
        return expired
    return data


def inspect_certificate(cert_path: Path) -> dict[str, Any] | None:
    if not cert_path.is_file():
        return None
    try:
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    except (OSError, ValueError):
        return None
    names: list[str] = []
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = list(san.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        names = []
    common = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    common_name = str(common[0].value) if common else ""
    org = cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
    issuer = str(org[0].value) if org else cert.issuer.rfc4514_string()
    domain = next((name for name in names if name not in {"localhost"}), "")
    if not domain and common_name and common_name not in {"localhost", "jojonet-panel"}:
        domain = common_name
    not_after = getattr(cert, "not_valid_after_utc", None)
    if not_after is None:
        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
    self_signed = cert.issuer == cert.subject or common_name == "jojonet-panel"
    return {
        "domain": domain,
        "issuer": issuer,
        "not_after": not_after.replace(microsecond=0).isoformat(),
        "self_signed": self_signed,
    }


def build_ssl_view(data_dir: Path, cert_path: str, panel_path: str, port: int) -> dict[str, Any]:
    job = read_ssl_status(data_dir)
    cert = inspect_certificate(Path(cert_path)) if cert_path else None
    trusted = None
    if cert and cert["domain"] and not cert["self_signed"]:
        trusted = {
            "domain": cert["domain"],
            "url": https_url(cert["domain"], panel_path, port),
            "issuer": cert["issuer"],
            "not_after": cert["not_after"],
        }
    view: dict[str, Any] = {
        "state": "idle",
        "domain": "",
        "url": "",
        "issuer": "",
        "not_after": "",
        "error": "",
        "self_signed": bool(cert and cert["self_signed"]),
    }
    if job and job.get("state") == "running":
        view["state"] = "running"
        view["domain"] = str(job.get("domain") or "")
        if trusted:
            view["url"] = trusted["url"]
            view["issuer"] = trusted["issuer"]
            view["not_after"] = trusted["not_after"]
            if not view["domain"]:
                view["domain"] = trusted["domain"]
        return view
    if job and job.get("state") == "error":
        view["state"] = "error"
        view["domain"] = str(job.get("domain") or (trusted or {}).get("domain") or "")
        view["error"] = str(job.get("error") or "دریافت گواهی انجام نشد")
        if trusted:
            view["url"] = trusted["url"]
            view["issuer"] = trusted["issuer"]
            view["not_after"] = trusted["not_after"]
        return view
    if trusted:
        view.update({"state": "ok", "self_signed": False, **trusted})
        return view
    if job and job.get("state") == "ok" and job.get("url"):
        view.update({
            "state": "ok",
            "self_signed": False,
            "domain": str(job.get("domain") or ""),
            "url": str(job.get("url") or ""),
            "issuer": str(job.get("issuer") or "Let's Encrypt"),
            "not_after": str(job.get("not_after") or ""),
        })
    return view
