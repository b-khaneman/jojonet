from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path

# One URL segment, long enough that guessing the panel address is not practical.
_BASE_PATH_RE = re.compile(r"^/[A-Za-z0-9][A-Za-z0-9_-]{15,63}$")
# Paths created by the old random generator (token_hex(12)). Replaced by the fixed entry.
_AUTO_PATH_RE = re.compile(r"^/[0-9a-f]{24}$")
DEFAULT_BASE_PATH = "/jojonet-panel-entry"

PANEL_DIR = Path(__file__).resolve().parent.parent
REPO_DIR = PANEL_DIR.parent


def normalize_base_path(raw: str) -> str:
    value = (raw or "").strip().rstrip("/")
    if value and not value.startswith("/"):
        value = "/" + value
    if not _BASE_PATH_RE.fullmatch(value):
        raise ValueError("panel path must be one segment of 16–64 letters, digits, _ or -")
    return value


def _write_private(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    os.replace(tmp, path)


def read_web_path(data_dir: Path) -> str | None:
    path_file = Path(data_dir) / "web.path"
    if not path_file.is_file():
        return None
    try:
        return normalize_base_path(path_file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def write_web_path(data_dir: Path, path: str) -> None:
    _write_private(Path(data_dir) / "web.path", normalize_base_path(path) + "\n")


def resolve_base_path(data_dir: Path, explicit: str) -> str:
    """Saved web.path wins. A missing or auto-generated path becomes the fixed entry."""
    saved = read_web_path(data_dir)
    if saved:
        return saved
    value = DEFAULT_BASE_PATH
    raw = (explicit or "").strip()
    if raw:
        try:
            parsed = normalize_base_path(raw)
        except ValueError:
            parsed = ""
        if parsed and not _AUTO_PATH_RE.fullmatch(parsed):
            value = parsed
    try:
        write_web_path(data_dir, value)
    except OSError:
        pass
    return value


def read_listen(data_dir: Path) -> tuple[str, int] | None:
    path_file = Path(data_dir) / "listen.json"
    if not path_file.is_file():
        return None
    try:
        data = json.loads(path_file.read_text(encoding="utf-8"))
        path = normalize_base_path(str(data.get("path") or ""))
        port = int(data.get("port"))
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return None
    if not 1 <= port <= 65535:
        return None
    return path, port


def saved_listen_port(data_dir: Path) -> int | None:
    found = read_listen(data_dir)
    return found[1] if found else None


def write_listen(data_dir: Path, path: str, port: int) -> None:
    path = normalize_base_path(path)
    if not 1 <= int(port) <= 65535:
        raise ValueError("panel port must be between 1 and 65535")
    payload = json.dumps({"path": path, "port": int(port)}, separators=(",", ":")) + "\n"
    _write_private(Path(data_dir) / "listen.json", payload)
    write_web_path(data_dir, path)


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


@dataclass
class PanelEntry:
    """Live path and port. The admin UI updates this; the path gate reads it on every request."""

    path: str
    port: int


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
