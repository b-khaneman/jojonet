from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

PANEL_DIR = Path(__file__).resolve().parent.parent
REPO_DIR = PANEL_DIR.parent


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
    return Settings(
        data_dir=Path(os.environ.get("JOJONET_PANEL_DATA") or "/var/lib/jojonet-panel"),
        bundle_dir=Path(os.environ.get("JOJONET_PANEL_BUNDLE") or _default_bundle()),
        static_dir=Path(os.environ.get("JOJONET_PANEL_STATIC") or PANEL_DIR / "static"),
        host=os.environ.get("JOJONET_PANEL_HOST", "0.0.0.0").strip() or "0.0.0.0",
        port=port,
        cert=os.environ.get("JOJONET_PANEL_CERT", "").strip(),
        key=os.environ.get("JOJONET_PANEL_KEY", "").strip(),
        secure_cookies=_bool("JOJONET_PANEL_SECURE_COOKIES", True),
        trusted_proxy=_bool("JOJONET_PANEL_TRUSTED_PROXY", False),
    )
