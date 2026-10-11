from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

PANEL_DIR = Path(__file__).resolve().parent.parent
REPO_DIR = PANEL_DIR.parent
sys.path.insert(0, str(PANEL_DIR))

from app.config import Settings  # noqa: E402


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
    )


@pytest.fixture()
def app(settings: Settings):
    from app.main import create_app

    return create_app(settings)


@pytest.fixture()
def client(app):
    from fastapi.testclient import TestClient

    with TestClient(app) as c:
        yield c


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
