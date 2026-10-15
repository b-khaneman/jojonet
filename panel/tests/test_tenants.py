from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone

from app.db import Database, utcnow
from app.security import hash_password

from test_api import KHAREJ, SERVER


def login_as(client, username: str, password: str) -> dict[str, str]:
    r = client.post("/api/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return {"X-CSRF-Token": r.json()["csrf"]}


def add_customer(client, auth, **kw):
    body = {
        "username": "cust1",
        "password": "customer-pass-1",
        "days": 30,
        "max_servers": 2,
        "max_tunnels": 2,
        "max_relays": 2,
        "allow_vpn": True,
        "allow_relay": True,
        "allow_os_update": True,
        "allow_term": True,
    }
    body.update(kw)
    r = client.post("/api/users", json=body, headers=auth)
    assert r.status_code == 200, r.text
    return r.json()


def test_legacy_relays_drop_global_name_unique(tmp_path):
    path = tmp_path / "legacy-relays.db"
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE admins (id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE, pw_hash TEXT NOT NULL, created_at TEXT NOT NULL);
        CREATE TABLE servers (
            id INTEGER PRIMARY KEY, name TEXT NOT NULL, role TEXT NOT NULL, host TEXT NOT NULL, port INTEGER NOT NULL,
            username TEXT NOT NULL, auth_type TEXT NOT NULL, created_at TEXT NOT NULL
        );
        CREATE TABLE tunnels (id INTEGER PRIMARY KEY, mode TEXT NOT NULL, iran_id INTEGER NOT NULL, kharej_id INTEGER NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL);
        CREATE TABLE jobs (id INTEGER PRIMARY KEY, kind TEXT NOT NULL, title TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL);
        CREATE TABLE relays (
            id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, engine TEXT NOT NULL, server_id INTEGER NOT NULL,
            target TEXT NOT NULL, ports TEXT NOT NULL, proto TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL
        );
        CREATE TABLE sessions (token_hash TEXT PRIMARY KEY, admin_id INTEGER NOT NULL, csrf TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL);
        CREATE TABLE login_failures (ip TEXT NOT NULL, at REAL NOT NULL);
        """
    )
    conn.execute("INSERT INTO admins (username, pw_hash, created_at) VALUES (?,?,?)", ("admin", hash_password("correct-horse-1"), utcnow()))
    conn.execute(
        "INSERT INTO relays (name, engine, server_id, target, ports, proto, status, created_at) VALUES (?,?,?,?,?,?,?,?)",
        ("web", "gost", 1, "9.9.9.9", "443", "tcp", "ok", utcnow()),
    )
    conn.commit()
    conn.close()
    db = Database(path)
    try:
        sql = db.one("SELECT sql FROM sqlite_master WHERE type='table' AND name='relays'")["sql"]
        assert "name TEXT NOT NULL UNIQUE" not in sql
        other = db.insert(
            "admins",
            {
                "username": "cust",
                "pw_hash": hash_password("customer-pass-1"),
                "created_at": utcnow(),
                "role": "customer",
                "enabled": 1,
            },
        )
        db.execute("PRAGMA foreign_keys=OFF")
        db.execute(
            "INSERT INTO relays (name, engine, server_id, target, ports, proto, status, created_at, owner_id) VALUES (?,?,?,?,?,?,?,?,?)",
            ("web", "gost", 1, "1.1.1.1", "80", "tcp", "ok", utcnow(), other),
        )
        db.execute("PRAGMA foreign_keys=ON")
        rows = db.all("SELECT owner_id, name FROM relays WHERE name='web' ORDER BY id")
        assert len(rows) == 2
    finally:
        db.close()


def test_legacy_schema_migrates_owner_id(tmp_path):
    path = tmp_path / "legacy.db"
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE admins (id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE, pw_hash TEXT NOT NULL, created_at TEXT NOT NULL);
        CREATE TABLE servers (
            id INTEGER PRIMARY KEY, name TEXT NOT NULL, role TEXT NOT NULL, host TEXT NOT NULL, port INTEGER NOT NULL,
            username TEXT NOT NULL, auth_type TEXT NOT NULL, secret_password TEXT, secret_key TEXT,
            secret_passphrase TEXT, secret_sudo TEXT, hostkey TEXT, hostkey_fingerprint TEXT,
            last_check TEXT, created_at TEXT NOT NULL
        );
        CREATE TABLE tunnels (
            id INTEGER PRIMARY KEY, mode TEXT NOT NULL, iran_id INTEGER NOT NULL, kharej_id INTEGER NOT NULL,
            status TEXT NOT NULL, created_at TEXT NOT NULL
        );
        CREATE TABLE jobs (id INTEGER PRIMARY KEY, kind TEXT NOT NULL, title TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL);
        CREATE TABLE relays (
            id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, engine TEXT NOT NULL, server_id INTEGER NOT NULL,
            target TEXT NOT NULL, ports TEXT NOT NULL, proto TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL
        );
        CREATE TABLE sessions (token_hash TEXT PRIMARY KEY, admin_id INTEGER NOT NULL, csrf TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL);
        CREATE TABLE login_failures (ip TEXT NOT NULL, at REAL NOT NULL);
        """
    )
    conn.execute(
        "INSERT INTO admins (username, pw_hash, created_at) VALUES (?,?,?)",
        ("admin", hash_password("correct-horse-1"), utcnow()),
    )
    conn.execute(
        "INSERT INTO servers (name, role, host, port, username, auth_type, created_at) VALUES (?,?,?,?,?,?,?)",
        ("IR", "iran", "5.6.7.8", 22, "root", "password", utcnow()),
    )
    conn.commit()
    conn.close()

    db = Database(path)
    try:
        admin = db.one("SELECT * FROM admins")
        assert admin["role"] == "owner" and admin["enabled"] == 1
        srv = db.one("SELECT * FROM servers")
        assert srv["owner_id"] == admin["id"]
        assert "max_servers" in admin and "allow_vpn" in admin
    finally:
        db.close()


def test_me_is_owner_with_usage(client, auth):
    me = client.get("/api/me").json()
    assert me["role"] == "owner"
    assert me["days_left"] is None
    assert me["usage"] == {"servers": 0, "tunnels": 0, "relays": 0}
    assert me["limits"]["max_servers"] is None


def test_users_require_login(client):
    assert client.get("/api/users").status_code == 401


def test_users_api_owner_only(client, auth):
    listed = client.get("/api/users", headers=auth)
    assert listed.status_code == 200
    assert any(u["role"] == "owner" and u["username"] == "admin" for u in listed.json())

    created = add_customer(client, auth, username="ali")
    user = created["user"]
    assert user["role"] == "customer" and user["days_left"] == 30
    assert created.get("password") is None

    gen = add_customer(client, auth, username="sara", password=None)
    assert gen["password"] and len(gen["password"]) >= 10

    cid = user["id"]
    assert client.post(f"/api/users/{cid}/extend", json={"days": 10}, headers=auth).status_code == 200
    assert client.get("/api/users", headers=auth).json()
    assert client.patch(f"/api/users/{cid}", json={"enabled": False}, headers=auth).status_code == 200
    assert client.post(f"/api/users/{cid}/password", json={}, headers=auth).status_code == 200

    owner_id = next(u["id"] for u in client.get("/api/users", headers=auth).json() if u["role"] == "owner")
    assert client.delete(f"/api/users/{owner_id}", headers=auth).status_code == 400
    assert client.patch(f"/api/users/{owner_id}", json={"enabled": False}, headers=auth).status_code == 400


def test_customer_cannot_use_owner_apis(client, auth):
    add_customer(client, auth, username="cust1")
    client.post("/api/logout", headers=auth)
    hdr = login_as(client, "cust1", "customer-pass-1")
    assert client.get("/api/users", headers=hdr).status_code == 403
    assert client.post("/api/users", json={"username": "x", "password": "abcdefghij"}, headers=hdr).status_code == 403
    me = client.get("/api/me").json()
    assert me["role"] == "customer" and me["username"] == "cust1"
    assert me["days_left"] == 30


def test_two_customers_are_isolated(client, auth):
    add_customer(client, auth, username="cust1")
    add_customer(client, auth, username="cust2", password="customer-pass-2")
    client.post("/api/logout", headers=auth)

    a = login_as(client, "cust1", "customer-pass-1")
    sa = client.post("/api/servers", json=SERVER, headers=a)
    assert sa.status_code == 200, sa.text
    assert sa.json()["owner_username"] == "cust1"
    assert len(client.get("/api/servers").json()) == 1

    client.post("/api/logout", headers=a)
    b = login_as(client, "cust2", "customer-pass-2")
    other = {**SERVER, "name": "Iran-B", "host": "5.6.7.9"}
    sb = client.post("/api/servers", json=other, headers=b)
    assert sb.status_code == 200
    seen = client.get("/api/servers").json()
    assert len(seen) == 1 and seen[0]["host"] == "5.6.7.9"
    assert client.delete(f"/api/servers/{sa.json()['id']}", headers=b).status_code == 404

    client.post("/api/logout", headers=b)
    owner = login_as(client, "admin", "correct-horse-1")
    all_srv = client.get("/api/servers").json()
    assert {s["host"] for s in all_srv} == {"5.6.7.8", "5.6.7.9"}
    assert {s["owner_username"] for s in all_srv} == {"cust1", "cust2"}
    assert client.post("/api/servers", json=SERVER, headers=owner).status_code == 409

    # Owner can reveal customer SSH secrets for support
    sid = next(s["id"] for s in all_srv if s["owner_username"] == "cust1")
    secrets = client.get(f"/api/servers/{sid}/secrets", headers=owner)
    assert secrets.status_code == 200, secrets.text
    assert secrets.json()["password"] == "pw-iran"
    assert secrets.json()["owner_username"] == "cust1"
    ov = client.get(
        f"/api/users/{next(s['owner_id'] for s in all_srv if s['owner_username'] == 'cust1')}/overview",
        headers=owner,
    )
    assert ov.status_code == 200
    assert any(s.get("password") == "pw-iran" for s in ov.json()["servers"])

    # Customer cannot read another customer's secrets
    client.post("/api/logout", headers=owner)
    b2 = login_as(client, "cust2", "customer-pass-2")
    assert client.get(f"/api/servers/{sid}/secrets", headers=b2).status_code == 404


def test_term_policy_global_and_per_user(client, auth):
    me = client.get("/api/me").json()
    assert me["terms_enabled"] is True and me["can_term"] is True and me["allow_term"] is True
    r = client.patch("/api/settings", json={"terms_enabled": False}, headers=auth)
    assert r.status_code == 200 and r.json()["terms_enabled"] is False
    assert client.get("/api/me").json()["can_term"] is False
    with client.websocket_connect("/ws/term?server_id=1") as ws:
        assert "غیرفعال" in ws.receive_json()["m"]
    assert client.patch("/api/settings", json={"terms_enabled": True}, headers=auth).status_code == 200
    created = add_customer(client, auth, username="noterm", allow_term=False)
    assert created["user"]["allow_term"] is False
    client.post("/api/logout", headers=auth)
    hdr = login_as(client, "noterm", "customer-pass-1")
    me = client.get("/api/me").json()
    assert me["can_term"] is False and me["allow_term"] is False
    with client.websocket_connect("/ws/term?server_id=1") as ws:
        assert "غیرفعال" in ws.receive_json()["m"]
    assert client.patch("/api/settings", json={"terms_enabled": False}, headers=hdr).status_code == 403
    assert client.put("/api/listen", json={"path": "jojonet-panel-entry", "port": 2053}, headers=hdr).status_code == 403
    client.post("/api/logout", headers=hdr)
    owner = login_as(client, "admin", "correct-horse-1")
    r = client.patch(f"/api/users/{created['user']['id']}", json={"allow_term": True}, headers=owner)
    assert r.status_code == 200 and r.json()["allow_term"] is True


def test_quota_and_capabilities(client, auth):
    add_customer(
        client, auth, username="lim", password="customer-pass-1",
        max_servers=1, max_tunnels=0, max_relays=0,
        allow_vpn=False, allow_relay=False, allow_os_update=False,
    )
    client.post("/api/logout", headers=auth)
    hdr = login_as(client, "lim", "customer-pass-1")
    assert client.post("/api/servers", json=SERVER, headers=hdr).status_code == 200
    r = client.post("/api/servers", json={**SERVER, "name": "X", "host": "9.9.9.9"}, headers=hdr)
    assert r.status_code == 422 and "1/1" in r.json()["detail"]

    iran = client.get("/api/servers").json()[0]
    r = client.post("/api/tunnels", json={"mode": "gre", "iran_id": iran["id"], "kharej_id": iran["id"]}, headers=hdr)
    assert r.status_code == 422 and "0/0" in r.json()["detail"]
    r = client.post("/api/relays", json={"engine": "iptables", "iran_id": iran["id"], "target": "9.9.9.9", "ports": "443"}, headers=hdr)
    assert r.status_code == 403 and "رله" in r.json()["detail"]
    r = client.post(f"/api/servers/{iran['id']}/vpn-panel", json={"kind": "xui"}, headers=hdr)
    assert r.status_code == 403 and "VPN" in r.json()["detail"]
    r = client.post(f"/api/servers/{iran['id']}/update-os", headers=hdr)
    assert r.status_code == 403 and "آپدیت" in r.json()["detail"]


def test_expired_and_disabled_login(client, auth):
    created = add_customer(client, auth, username="old")
    cid = created["user"]["id"]
    past = (datetime.now(timezone.utc) - timedelta(days=1)).replace(microsecond=0).isoformat()
    client.app.state.db.update("admins", cid, {"expires_at": past})
    client.post("/api/logout", headers=auth)
    r = client.post("/api/login", json={"username": "old", "password": "customer-pass-1"})
    assert r.status_code == 403 and "منقضی" in r.json()["detail"]

    owner = login_as(client, "admin", "correct-horse-1")
    future = (datetime.now(timezone.utc) + timedelta(days=5)).replace(microsecond=0).isoformat()
    client.app.state.db.update("admins", cid, {"expires_at": future, "enabled": 0})
    client.post("/api/logout", headers=owner)
    r = client.post("/api/login", json={"username": "old", "password": "customer-pass-1"})
    assert r.status_code == 403 and "غیرفعال" in r.json()["detail"]


def test_set_admin_keeps_first_owner(settings, monkeypatch, capsys):
    from app import cli

    monkeypatch.setenv("JOJONET_PANEL_DATA", str(settings.data_dir))
    assert cli.main(["set-admin", "--random"]) == 0
    db = Database(settings.db_path)
    try:
        row = db.one("SELECT * FROM admins ORDER BY id LIMIT 1")
        assert row["role"] == "owner"
        db.insert("admins", {
            "username": "cust", "pw_hash": hash_password("customer-pass-1"),
            "created_at": utcnow(), "role": "customer", "enabled": 1,
        })
    finally:
        db.close()
    monkeypatch.setenv("JOJONET_PANEL_DATA", str(settings.data_dir))
    assert cli.main(["set-admin", "--username", "boss", "--random"]) == 0
    db = Database(settings.db_path)
    try:
        first = db.one("SELECT * FROM admins ORDER BY id LIMIT 1")
        cust = db.one("SELECT * FROM admins WHERE username=?", ("cust",))
        assert first["username"] == "boss" and first["role"] == "owner"
        assert cust and cust["role"] == "customer"
    finally:
        db.close()
    capsys.readouterr()


def test_relay_name_unique_per_owner(client, auth):
    add_customer(client, auth, username="cust1")
    add_customer(client, auth, username="cust2", password="customer-pass-2")
    client.post("/api/logout", headers=auth)
    a = login_as(client, "cust1", "customer-pass-1")
    sa = client.post("/api/servers", json={**SERVER, "host": "8.8.8.8", "name": "A"}, headers=a).json()
    r1 = client.post("/api/relays", json={"engine": "gost", "iran_id": sa["id"], "target": "9.9.9.9", "ports": "443", "name": "web"}, headers=a)
    assert r1.status_code == 200, r1.text
    client.post("/api/logout", headers=a)
    b = login_as(client, "cust2", "customer-pass-2")
    sb = client.post("/api/servers", json={**KHAREJ, "role": "iran", "name": "B"}, headers=b).json()
    r2 = client.post("/api/relays", json={"engine": "gost", "iran_id": sb["id"], "target": "9.9.9.9", "ports": "443", "name": "web"}, headers=b)
    assert r2.status_code == 200, r2.text
    assert client.post("/api/relays", json={"engine": "gost", "iran_id": sb["id"], "target": "1.1.1.1", "ports": "80", "name": "web"}, headers=b).status_code == 409
