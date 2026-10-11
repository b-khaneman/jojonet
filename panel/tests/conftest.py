from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

PANEL_DIR = Path(__file__).resolve().parent.parent
REPO_DIR = PANEL_DIR.parent
sys.path.insert(0, str(PANEL_DIR))

from app.config import Settings  # noqa: E402

PANEL_BASE = "/jnsecretpath1234"


@pytest.fixture()
def settings(tmp_path: Path) -> Settings:
    os.environ.pop("JOJONET_PANEL_VAULT_KEY", None)
    return Settings(
        data_dir=tmp_path / "data",
        bundle_dir=REPO_DIR,
        static_dir=PANEL_DIR / "static",
        host="127.0.0.1",
        port=2053,
        cert="",
        key="",
        secure_cookies=False,
        trusted_proxy=False,
        base_path=PANEL_BASE,
    )


@pytest.fixture()
def app(settings: Settings):
    from app.main import create_app

    return create_app(settings)


class PrefixedClient:
    """Tests keep calling /api/...; the secret path is added here."""

    def __init__(self, inner, prefix: str):
        self._inner = inner
        self.prefix = prefix
        self.raw = inner

    def _u(self, url: str) -> str:
        if not isinstance(url, str) or not url.startswith("/"):
            return url
        if url == self.prefix or url.startswith(self.prefix + "/"):
            return url
        return self.prefix + url

    def get(self, url, **kw):
        return self._inner.get(self._u(url), **kw)

    def post(self, url, **kw):
        return self._inner.post(self._u(url), **kw)

    def put(self, url, **kw):
        return self._inner.put(self._u(url), **kw)

    def patch(self, url, **kw):
        return self._inner.patch(self._u(url), **kw)

    def delete(self, url, **kw):
        return self._inner.delete(self._u(url), **kw)

    def request(self, method, url, **kw):
        return self._inner.request(method, self._u(url), **kw)

    def stream(self, method, url, **kw):
        return self._inner.stream(method, self._u(url), **kw)

    def websocket_connect(self, url, **kw):
        return self._inner.websocket_connect(self._u(url), **kw)

    def __getattr__(self, name):
        return getattr(self._inner, name)


@pytest.fixture()
def client(app):
    from fastapi.testclient import TestClient

    with TestClient(app) as c:
        yield PrefixedClient(c, app.state.settings.base_path)


@pytest.fixture()
def admin(settings: Settings) -> tuple[str, str]:
    from app.db import Database, utcnow
    from app.security import hash_password

    db = Database(settings.db_path)
    db.insert("admins", {
        "username": "admin",
        "pw_hash": hash_password("correct-horse-1"),
        "created_at": utcnow(),
        "role": "owner",
        "enabled": 1,
    })
    db.close()
    return "admin", "correct-horse-1"


@pytest.fixture()
def auth(client, admin) -> dict[str, str]:
    r = client.post("/api/login", json={"username": admin[0], "password": admin[1]})
    assert r.status_code == 200, r.text
    return {"X-CSRF-Token": r.json()["csrf"]}
