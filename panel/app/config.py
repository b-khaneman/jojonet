from __future__ import annotations

import os
import re
import secrets
from dataclasses import dataclass
from pathlib import Path

# One URL segment, long enough that guessing the panel address is not practical.
_BASE_PATH_RE = re.compile(r"^/[A-Za-z0-9][A-Za-z0-9_-]{15,63}$")

PANEL_DIR = Path(__file__).resolve().parent.parent
REPO_DIR = PANEL_DIR.parent


def normalize_base_path(raw: str) -> str:
    value = (raw or "").strip().rstrip("/")
    if value and not value.startswith("/"):
        value = "/" + value
    if not _BASE_PATH_RE.fullmatch(value):
        raise ValueError("panel path must be one segment of 16–64 letters, digits, _ or -")
    return value


def resolve_base_path(data_dir: Path, explicit: str) -> str:
    """Env wins. Otherwise reuse data_dir/web.path, or create a random path (mode 0600)."""
    raw = (explicit or "").strip()
    if raw:
        return normalize_base_path(raw)
    path_file = Path(data_dir) / "web.path"
    if path_file.is_file():
        return normalize_base_path(path_file.read_text(encoding="utf-8"))
    value = "/" + secrets.token_hex(12)
    path_file.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(path_file), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(value + "\n")
    return value


def _bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _default_bundle() -> Path:
    prod = Path("/opt/jojonet-panel/bundle")
    if (prod / "jojonet").is_file():
        return prod
    return REPO_DIR


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    bundle_dir: Path
    static_dir: Path
    host: str
    port: int
    cert: str
    key: str
    secure_cookies: bool
    trusted_proxy: bool
    base_path: str
    session_hours: int = 12
    ssh_connect_timeout: int = 15
    command_timeout: int = 900

    @property
    def db_path(self) -> Path:
        return self.data_dir / "panel.db"

    @property
    def vault_key_path(self) -> Path:
        return self.data_dir / "vault.key"


def load_settings() -> Settings:
    port_raw = os.environ.get("JOJONET_PANEL_PORT", "2053").strip() or "2053"
    try:
        port = int(port_raw)
    except ValueError:
        port = 2053
    if not 1 <= port <= 65535:
        port = 2053
    data_dir = Path(os.environ.get("JOJONET_PANEL_DATA") or "/var/lib/jojonet-panel")
    return Settings(
        data_dir=data_dir,
        bundle_dir=Path(os.environ.get("JOJONET_PANEL_BUNDLE") or _default_bundle()),
        static_dir=Path(os.environ.get("JOJONET_PANEL_STATIC") or PANEL_DIR / "static"),
        host=os.environ.get("JOJONET_PANEL_HOST", "0.0.0.0").strip() or "0.0.0.0",
        port=port,
        cert=os.environ.get("JOJONET_PANEL_CERT", "").strip(),
        key=os.environ.get("JOJONET_PANEL_KEY", "").strip(),
        secure_cookies=_bool("JOJONET_PANEL_SECURE_COOKIES", True),
        trusted_proxy=_bool("JOJONET_PANEL_TRUSTED_PROXY", False),
        base_path=resolve_base_path(data_dir, os.environ.get("JOJONET_PANEL_PATH", "")),
    )
