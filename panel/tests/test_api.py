from __future__ import annotations

import time

import pytest

SERVER = {"name": "Iran-1", "role": "iran", "host": "5.6.7.8", "port": 22, "username": "root",
          "auth_type": "password", "password": "pw-iran"}
KHAREJ = {"name": "DE-1", "role": "kharej", "host": "1.2.3.4", "port": 22, "username": "root",
          "auth_type": "password", "password": "pw-kharej"}


def wait_job(client, job_id, timeout=10.0):
    end = time.time() + timeout
    while time.time() < end:
        job = client.get(f"/api/jobs/{job_id}").json()
        if job["status"] in ("ok", "failed"):
            return job
        time.sleep(0.05)
    raise AssertionError("job did not finish")


def test_bare_ip_does_not_open_panel(client):
    bare = client.raw.get("/")
    assert bare.status_code == 404 and bare.content == b""
    assert "پنل" not in bare.text and "jojonet" not in bare.text.lower()
    assert client.raw.get("/api/health").status_code == 404
    assert client.raw.get("/api/login").status_code == 404
    assert client.raw.get(client.prefix + "/../").status_code == 404
    page = client.get("/")
    assert page.status_code == 200 and "__BASE__" not in page.text
    assert f"{client.prefix}/static/app.js?v=" in page.text
    assert f'data-base="{client.prefix}"' in page.text


def test_owner_can_change_panel_path(client, admin):
    assert client.get("/api/listen").status_code == 401
    logged = client.post("/api/login", json={"username": admin[0], "password": admin[1]})
    assert logged.status_code == 200, logged.text
    auth = {"X-CSRF-Token": logged.json()["csrf"]}
    current = client.get("/api/listen", headers=auth)
    assert current.status_code == 200
    assert current.json()["path"] == client.prefix and current.json()["port"] == 2053
    assert client.put("/api/listen", json={"path": "short", "port": 2053}, headers=auth).status_code == 422
    assert client.put("/api/listen", json={"path": "jojonet-panel-entry", "port": 80}, headers=auth).status_code == 422
    saved = client.put("/api/listen", json={"path": "my-fixed-entry-path", "port": 2053}, headers=auth)
    assert saved.status_code == 200, saved.text
    body = saved.json()
    assert body["path"] == "/my-fixed-entry-path" and body["port"] == 2053
    assert body["url"].endswith(":2053/my-fixed-entry-path/")
    assert client.raw.get("/my-fixed-entry-path/api/health").status_code == 200
    assert client.raw.get(client.prefix + "/api/health").status_code == 404
    page = client.raw.get("/my-fixed-entry-path/")
    assert page.status_code == 200 and 'data-base="/my-fixed-entry-path"' in page.text


def test_health_and_headers(client):
    r = client.get("/api/health")
    assert r.status_code == 200 and r.json()["ok"] is True
    assert "default-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["cache-control"] == "no-store"


def test_index_asset_versioning(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "__V__" not in r.text
    assert "/static/app.js?v=" in r.text


def test_static_caching_and_compression(client):
    import re

    html = client.get("/", headers={"Accept-Encoding": "gzip"})
    assert html.headers.get("content-encoding") == "gzip" and html.headers["cache-control"] == "no-store"
    v = re.search(r"/static/app\.js\?v=([0-9a-f]{12})", html.text).group(1)
    js = client.get(f"/static/app.js?v={v}", headers={"Accept-Encoding": "gzip"})
    assert js.status_code == 200 and js.headers.get("content-encoding") == "gzip"
    assert js.headers["cache-control"] == "public, max-age=31536000, immutable"
    assert "javascript" in js.headers["content-type"] and "use strict" in js.text
    stale = client.get("/static/app.js?v=000000000000")
    assert stale.headers["cache-control"] == "no-cache"
    assert client.get("/static/style.css").headers["cache-control"] == "no-cache"
    etag = js.headers["etag"]
    assert client.get(f"/static/app.js?v={v}", headers={"If-None-Match": etag}).status_code == 304
    assert client.get("/static/../app/main.py").status_code == 404
    assert client.get("/", headers={"Accept-Encoding": "identity"}).headers.get("content-encoding") is None


def test_requires_login(client):
    assert client.get("/api/servers").status_code == 401
    assert client.get("/api/me").status_code == 401


def test_term_ws_requires_login(client):
    with client.websocket_connect("/ws/term?server_id=1") as ws:
        msg = ws.receive_json()
        assert msg["t"] == "e"
        assert "وارد" in msg["m"]


def test_term_ws_unknown_server(client, auth):
    with client.websocket_connect("/ws/term?server_id=99") as ws:
        msg = ws.receive_json()
        assert msg["t"] == "e"


def test_index_has_side_terminals(client):
    html = client.get("/").text
    assert "id=\"hx-left\"" in html and "id=\"hx-right\"" in html
    assert "vendor/xterm.min.js" in html
    assert "0.67" not in html


def test_login_logout_and_csrf(client, admin):
    r = client.post("/api/login", json={"username": "admin", "password": "nope"})
    assert r.status_code == 401
    r = client.post("/api/login", json={"username": "admin", "password": admin[1]})
    assert r.status_code == 200
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie
    assert f"path={client.prefix}/" in cookie
    csrf = r.json()["csrf"]
    me = client.get("/api/me").json()
    assert me["username"] == "admin" and me["csrf"] == csrf and me["jojonet_version"] == "1.6.0"
    assert me["role"] == "owner" and me["days_left"] is None
    assert client.post("/api/servers", json=SERVER).status_code == 403
    assert client.post("/api/servers", json=SERVER, headers={"X-CSRF-Token": "bad"}).status_code == 403
    assert client.post("/api/logout", headers={"X-CSRF-Token": csrf}).status_code == 200
    assert client.get("/api/me").status_code == 401


def test_login_rate_limit(client, admin):
    for _ in range(5):
        assert client.post("/api/login", json={"username": "admin", "password": "bad"}).status_code == 401
    r = client.post("/api/login", json={"username": "admin", "password": admin[1]})
    assert r.status_code == 429


def test_unknown_user_same_error(client, admin):
    r = client.post("/api/login", json={"username": "ghost", "password": "whatever"})
    assert r.status_code == 401
    assert r.json()["detail"] == client.post("/api/login", json={"username": "admin", "password": "x"}).json()["detail"]


def test_server_crud_and_validation(client, auth):
    r = client.post("/api/servers", json={**SERVER, "host": "999.1.1.1"}, headers=auth)
    assert r.status_code == 422 and "IPv4" in r.json()["detail"]
    r = client.post("/api/servers", json={**SERVER, "password": ""}, headers=auth)
    assert r.status_code == 422
    r = client.post("/api/servers", json={**SERVER, "name": "<script>"}, headers=auth)
    assert r.status_code == 422
    r = client.post("/api/servers", json={**SERVER, "auth_type": "key", "password": None, "private_key": "nope"}, headers=auth)
    assert r.status_code == 422

    r = client.post("/api/servers", json=SERVER, headers=auth)
    assert r.status_code == 200, r.text
    srv = r.json()
    assert srv["has_password"] and "password" not in srv and "secret_password" not in srv
    assert client.post("/api/servers", json=SERVER, headers=auth).status_code == 409

    r = client.put(f"/api/servers/{srv['id']}", json={**SERVER, "name": "Iran-X", "password": ""}, headers=auth)
    assert r.status_code == 200 and r.json()["name"] == "Iran-X" and r.json()["has_password"]

    db = client.app.state.db
    raw = db.one("SELECT secret_password FROM servers WHERE id=?", (srv["id"],))["secret_password"]
    assert raw and "pw-iran" not in raw
    assert client.app.state.vault.decrypt(raw) == "pw-iran"

    assert client.delete(f"/api/servers/{srv['id']}", headers=auth).status_code == 200
    assert client.get("/api/servers").json() == []


def test_tunnel_role_checks(client, auth):
    a = client.post("/api/servers", json=SERVER, headers=auth).json()
    b = client.post("/api/servers", json={**SERVER, "name": "Iran-2", "host": "5.6.7.9"}, headers=auth).json()
    r = client.post("/api/tunnels", json={"mode": "gre", "iran_id": a["id"], "kharej_id": b["id"]}, headers=auth)
    assert r.status_code == 422
    r = client.post("/api/tunnels", json={"mode": "bogus", "iran_id": a["id"], "kharej_id": b["id"]}, headers=auth)
    assert r.status_code == 422


@pytest.fixture()
def fake_orch(client, monkeypatch):
    calls = []
    orch = client.app.state.orch

    async def deploy(job, tunnel_id):
        calls.append(("deploy", tunnel_id))
        await job.start(0)
        await job.log("fake deploy")
        await job.ok(0)
        orch.db.update("tunnels", tunnel_id, {"status": "ok", "iran_iface": "gre1", "kharej_iface": "gre1"})

    async def boom(job, tunnel_id):
        calls.append(("redeploy", tunnel_id))
        await job.start(0)
        from app.jobs import StepFailed

        raise StepFailed("expected failure")

    monkeypatch.setattr(orch, "job_deploy", deploy)
    monkeypatch.setattr(orch, "job_redeploy", boom)
    return calls


def test_live_tunnels_scan_and_enable_boot(client, auth, monkeypatch):
    iran = client.post("/api/servers", json=SERVER, headers=auth).json()
    kharej = client.post("/api/servers", json=KHAREJ, headers=auth).json()
    orch = client.app.state.orch
    owner_id = orch.db.one("SELECT owner_id FROM servers WHERE id=?", (iran["id"],))["owner_id"]
    tid = orch.db.insert("tunnels", {
        "mode": "gre", "iran_id": iran["id"], "kharej_id": kharej["id"],
        "status": "ok", "iran_iface": "gre9", "kharej_iface": "gre9",
        "created_at": "2026-01-01T00:00:00+00:00", "owner_id": owner_id,
    })

    async def fake_scan(servers, tunnels):
        assert len(servers) == 2
        return [
            {
                "id": iran["id"], "name": "Iran-1", "role": "iran", "host": SERVER["host"],
                "ok": True, "error": None,
                "tunnels": [{
                    "name": "gre9", "mode": "gre", "role": "iran", "local_ip": "5.6.7.8",
                    "remote_ip": "1.2.3.4", "status": "UP", "boot": False,
                    "unit": "jojonet@gre9.service",
                    "panel_tunnel_id": tid, "orphan": False,
                }],
            },
            {
                "id": kharej["id"], "name": "DE-1", "role": "kharej", "host": KHAREJ["host"],
                "ok": True, "error": None,
                "tunnels": [{
                    "name": "orphan1", "mode": "icmp", "role": "kharej", "local_ip": "1.2.3.4",
                    "remote_ip": "", "status": "UP", "boot": True,
                    "unit": "jojonet-stream@orphan1.service",
                    "panel_tunnel_id": None, "orphan": True,
                }],
            },
        ]

    boot_calls = []

    async def fake_boot(job, server_id):
        boot_calls.append(server_id)
        await job.start(0)
        await job.ok(0)
        await job.start(1)
        await job.ok(1, "ok")

    monkeypatch.setattr(orch, "scan_live_tunnels", fake_scan)
    monkeypatch.setattr(orch, "job_enable_boot", fake_boot)

    live = client.get("/api/tunnels/live", headers=auth).json()
    assert live["servers"][0]["tunnels"][0]["panel_tunnel_id"] == tid
    assert live["servers"][1]["tunnels"][0]["orphan"] is True

    job = wait_job(client, client.post(f"/api/servers/{iran['id']}/enable-boot", headers=auth).json()["job_id"])
    assert job["status"] == "ok" and boot_calls == [iran["id"]]

    all_jobs = client.post("/api/servers/enable-boot-all", headers=auth).json()
    assert all_jobs["count"] == 2 and len(all_jobs["job_ids"]) == 2
    for jid in all_jobs["job_ids"]:
        assert wait_job(client, jid)["status"] == "ok"


def test_tunnel_lifecycle_with_fake_orchestrator(client, auth, fake_orch):
    iran = client.post("/api/servers", json=SERVER, headers=auth).json()
    kharej = client.post("/api/servers", json=KHAREJ, headers=auth).json()
    r = client.post("/api/tunnels", json={"mode": "hysteria2", "iran_id": iran["id"], "kharej_id": kharej["id"]}, headers=auth)
    assert r.status_code == 200, r.text
    tid, job_id = r.json()["tunnel"]["id"], r.json()["job_id"]
    job = wait_job(client, job_id)
    assert job["status"] == "ok" and "fake deploy" in job["log"]
    assert job["steps"][0]["status"] == "ok" and job["steps"][1]["status"] == "pending"
    t = client.get("/api/tunnels").json()[0]
    assert t["status"] == "ok" and t["iran_name"] == "Iran-1" and t["kharej_name"] == "DE-1"

    dup = client.post("/api/tunnels", json={"mode": "hysteria2", "iran_id": iran["id"], "kharej_id": kharej["id"]}, headers=auth)
    assert dup.status_code == 409
    assert client.delete(f"/api/servers/{iran['id']}", headers=auth).status_code == 409
    r = client.put(f"/api/servers/{iran['id']}", json={**SERVER, "role": "kharej", "password": ""}, headers=auth)
    assert r.status_code == 409

    job = wait_job(client, client.post(f"/api/tunnels/{tid}/redeploy", headers=auth).json()["job_id"])
    assert job["status"] == "failed" and "expected failure" in job["log"]
    assert job["steps"][0]["status"] == "failed" and job["steps"][-1]["status"] == "skipped"
    assert client.get("/api/tunnels").json()[0]["status"] == "failed"

    jobs = client.get("/api/jobs").json()
    assert len(jobs) == 2 and jobs[0]["kind"] == "tunnel_redeploy"


def test_sse_stream_finished_job(client, auth, fake_orch):
    iran = client.post("/api/servers", json=SERVER, headers=auth).json()
    kharej = client.post("/api/servers", json=KHAREJ, headers=auth).json()
    job_id = client.post("/api/tunnels", json={"mode": "gre", "iran_id": iran["id"], "kharej_id": kharej["id"]},
                         headers=auth).json()["job_id"]
    wait_job(client, job_id)
    with client.stream("GET", f"/api/jobs/{job_id}/stream", headers={"Accept-Encoding": "gzip"}) as r:
        assert r.headers.get("content-encoding") is None
        body = "".join(r.iter_text())
    assert "event: snapshot" in body and "event: done" in body
    me = client.get("/api/me", headers={"Accept-Encoding": "gzip"})
    assert me.status_code == 200 and me.headers.get("content-encoding") is None


def test_job_log_is_batched_but_never_lost(settings):
    import asyncio

    from app.db import Database
    from app.jobs import LOG_FLUSH_DELAY, LOG_FLUSH_LINES, JobManager

    db = Database(settings.db_path)

    def stored(job_id: int) -> str:
        return db.one("SELECT log FROM jobs WHERE id=?", (job_id,))["log"]

    async def scenario() -> None:
        jm = JobManager(db)
        gate = asyncio.Event()

        async def work(job):
            for i in range(LOG_FLUSH_LINES + 5):
                await job.log(f"line {i}")
            await gate.wait()
            await job.log("tail")
            await asyncio.sleep(LOG_FLUSH_DELAY * 3)
            await job.log("last")

        job_id = jm.create("t", "t", ["s"], work)
        await asyncio.sleep(0.05)
        assert stored(job_id).count("\n") == LOG_FLUSH_LINES
        assert jm.get(job_id)["log"].count("\n") == LOG_FLUSH_LINES + 5
        gate.set()
        await asyncio.sleep(LOG_FLUSH_DELAY * 2)
        assert stored(job_id).endswith("tail\n")
        for _ in range(200):
            if db.one("SELECT status FROM jobs WHERE id=?", (job_id,))["status"] == "ok":
                break
            await asyncio.sleep(0.02)
        log = stored(job_id)
        assert log.endswith("tail\nlast\n") and log.count("\n") == LOG_FLUSH_LINES + 7
        await jm.shutdown()

    try:
        asyncio.run(scenario())
    finally:
        db.close()


def test_password_change(client, auth, admin):
    r = client.post("/api/password", json={"old_password": "bad", "new_password": "another-password-1"}, headers=auth)
    assert r.status_code == 400
    r = client.post("/api/password", json={"old_password": admin[1], "new_password": "short"}, headers=auth)
    assert r.status_code == 422
    r = client.post("/api/password", json={"old_password": admin[1], "new_password": "another-password-1"}, headers=auth)
    assert r.status_code == 200
    client.post("/api/logout", headers=auth)
    assert client.post("/api/login", json={"username": "admin", "password": "another-password-1"}).status_code == 200


def test_info_modes(client, auth):
    info = client.get("/api/info").json()
    ids = [m["id"] for m in info["modes"]]
    assert ids == [
        "gre", "tun_tcp", "paqet", "vxlan", "wireguard", "wg_icmp", "wg_faketcp", "hysteria2",
        "rathole", "wstunnel", "dokodemo", "xray_reverse", "sit", "gre6", "ipip6", "dnstt", "icmp", "spoof",
    ]
    firsts = {m["id"]: m["first"] for m in info["modes"]}
    assert firsts["rathole"] == "iran" and firsts["dokodemo"] == "kharej" and firsts["xray_reverse"] == "iran"
    assert info["xray_nets"] == ["tcp", "ws", "grpc"]
    assert info["relay_engines"] == ["iptables", "gost", "haproxy", "socat", "xray"]
    assert info["direct_modes"] == ["dnstt", "icmp"]
    assert info["user_sides"] == ["iran", "kharej"]
    assert info["vpn_panels"] == [
        {"id": "xui", "label": "3x-ui سنایی"},
        {"id": "xui_classic", "label": "X-UI اصلی"},
        {"id": "pasarguard", "label": "پاسارگارد"},
    ]


def test_spoof_validation(client, auth, fake_orch):
    iran = client.post("/api/servers", json=SERVER, headers=auth).json()
    kharej = client.post("/api/servers", json=KHAREJ, headers=auth).json()
    base = {"mode": "spoof", "iran_id": iran["id"], "kharej_id": kharej["id"]}
    good = {"iran_spoof_ip": "5.160.0.1", "kharej_spoof_ip": "8.8.4.4"}
    bad_cases = [
        {},
        {"spoof": {"iran_spoof_ip": "5.160.0.1"}},
        {"spoof": {**good, "iran_spoof_ip": "5.160.0.300"}},
        {"spoof": {**good, "kharej_spoof_ip": "127.0.0.1"}},
        {"spoof": {**good, "forward": "0.0.0.0:443"}},
        {"spoof": {**good, "forward": "127.0.0.1"}},
        {"spoof": {**good, "forward": "127.0.0.1:70000"}},
        {"spoof": {**good, "forward": "1.2.3.4:53; reboot"}},
        {"spoof": {**good, "up_port": 9000, "down_port": 9000}},
        {"spoof": {**good, "up_transport": "sctp"}},
        {"spoof": {**good, "listen_port": 0}},
        {"spoof": {**good, "extra": "x"}},
    ]
    for case in bad_cases:
        r = client.post("/api/tunnels", json={**base, **case}, headers=auth)
        assert r.status_code == 422, (case, r.text)
    r = client.post("/api/tunnels", json={**base, "spoof": {**good, "forward": "localhost:51820"}}, headers=auth)
    assert r.status_code == 200, r.text
    wait_job(client, r.json()["job_id"])
    opts = client.get("/api/tunnels").json()[0]["options"]
    assert opts["forward"] == "localhost:51820" and opts["down_transport"] == "udp" and opts["spoof_port"] == 53

    other = client.post("/api/servers", json={**KHAREJ, "name": "NL-1", "host": "1.2.3.5"}, headers=auth).json()
    r = client.post("/api/tunnels", json={**base, "kharej_id": other["id"], "spoof": good}, headers=auth)
    assert r.status_code == 409
    r = client.post("/api/tunnels", json={"mode": "gre", "iran_id": iran["id"], "kharej_id": kharej["id"], "spoof": good}, headers=auth)
    assert r.status_code == 200
    gre = next(t for t in client.get("/api/tunnels").json() if t["mode"] == "gre")
    assert gre["options"] is None


def test_xray_and_relay_validation(client, auth, fake_orch):
    iran = client.post("/api/servers", json=SERVER, headers=auth).json()
    kharej = client.post("/api/servers", json=KHAREJ, headers=auth).json()
    bad = [
        {"mode": "dokodemo", "iran_id": iran["id"], "kharej_id": kharej["id"], "xray": {"net": "quic"}},
        {"mode": "dokodemo", "iran_id": iran["id"], "kharej_id": kharej["id"], "xray": {"ports": "70000"}},
        {"mode": "dokodemo", "iran_id": iran["id"], "kharej_id": kharej["id"], "xray": {"ports": "443;rm"}},
        {"mode": "dokodemo", "iran_id": iran["id"], "kharej_id": kharej["id"], "xray": {"ctrl_port": 0}},
    ]
    for case in bad:
        r = client.post("/api/tunnels", json=case, headers=auth)
        assert r.status_code == 422, (case, r.text)
    r = client.post("/api/tunnels", json={"mode": "dokodemo", "iran_id": iran["id"], "kharej_id": kharej["id"],
                                         "xray": {"net": "grpc", "ports": "8443:443"}}, headers=auth)
    assert r.status_code == 200
    wait_job(client, r.json()["job_id"])
    opts = next(t for t in client.get("/api/tunnels").json() if t["mode"] == "dokodemo")["options"]
    assert opts["net"] == "grpc" and opts["ports"] == "8443:443"
    assert client.post("/api/relays", json={"engine": "iptables", "iran_id": iran["id"], "target": "example.com", "ports": "443"}, headers=auth).status_code == 422
    assert client.post("/api/relays", json={"engine": "haproxy", "iran_id": iran["id"], "target": "9.9.9.9", "ports": "443", "proto": "udp"}, headers=auth).status_code == 422
    assert client.post("/api/relays", json={"engine": "nope", "iran_id": iran["id"], "target": "9.9.9.9", "ports": "443"}, headers=auth).status_code == 422
    assert client.post("/api/servers/{}/dns".format(iran["id"]), json={"dns1": "not-ip"}, headers=auth).status_code == 422


def test_dnstt_and_icmp_validation(client, auth, fake_orch):
    iran = client.post("/api/servers", json=SERVER, headers=auth).json()
    kharej = client.post("/api/servers", json=KHAREJ, headers=auth).json()
    base_dt = {"mode": "dnstt", "iran_id": iran["id"], "kharej_id": kharej["id"]}
    for case in (
        {},
        {"dnstt": {"domain": "nope"}},
        {"dnstt": {"domain": "t.example.com", "resolver_mode": "ftp"}},
        {"dnstt": {"domain": "t.example.com", "resolver_mode": "doh", "resolver": "http://evil"}},
        {"dnstt": {"domain": "t.example.com", "ports": "70000"}},
        {"dnstt": {"domain": "t.example.com", "extra": "x"}},
    ):
        r = client.post("/api/tunnels", json={**base_dt, **case}, headers=auth)
        assert r.status_code == 422, (case, r.text)
    r = client.post("/api/tunnels", json={**base_dt, "dnstt": {"domain": "t.example.com", "resolver_mode": "dot"}}, headers=auth)
    assert r.status_code == 200, r.text
    wait_job(client, r.json()["job_id"])
    opts = next(t for t in client.get("/api/tunnels").json() if t["mode"] == "dnstt")["options"]
    assert opts["domain"] == "t.example.com" and opts["resolver_mode"] == "dot"
    other = client.post("/api/servers", json={**KHAREJ, "name": "NL-2", "host": "1.2.3.6"}, headers=auth).json()
    r = client.post("/api/tunnels", json={**base_dt, "kharej_id": other["id"], "dnstt": {"domain": "u.example.com"}}, headers=auth)
    assert r.status_code == 409
    r = client.post("/api/tunnels", json={"mode": "icmp", "iran_id": iran["id"], "kharej_id": kharej["id"]}, headers=auth)
    assert r.status_code == 200, r.text
    wait_job(client, r.json()["job_id"])
    r = client.post("/api/tunnels", json={"mode": "icmp", "iran_id": iran["id"], "kharej_id": other["id"]}, headers=auth)
    assert r.status_code == 409


def test_direct_mode_validation(client, auth, fake_orch):
    iran = client.post("/api/servers", json=SERVER, headers=auth).json()
    kharej = client.post("/api/servers", json=KHAREJ, headers=auth).json()
    assert client.post("/api/tunnels", json={"mode": "gre", "direct": True, "kharej_id": kharej["id"]}, headers=auth).status_code == 422
    assert client.post("/api/tunnels", json={"mode": "dnstt", "direct": True, "kharej_id": kharej["id"]}, headers=auth).status_code == 422
    r = client.post(
        "/api/tunnels",
        json={"mode": "dnstt", "direct": True, "kharej_id": kharej["id"], "dnstt": {"domain": "t.example.com"}},
        headers=auth,
    )
    assert r.status_code == 200, r.text
    body = r.json()["tunnel"]
    assert body["direct"] is True and body["iran_id"] == body["kharej_id"] == kharej["id"]
    wait_job(client, r.json()["job_id"])
    paired = client.post(
        "/api/tunnels",
        json={"mode": "dnstt", "iran_id": iran["id"], "kharej_id": kharej["id"], "dnstt": {"domain": "u.example.com"}},
        headers=auth,
    )
    assert paired.status_code == 409
    r = client.post("/api/tunnels", json={"mode": "icmp", "direct": True, "kharej_id": kharej["id"]}, headers=auth)
    assert r.status_code == 200, r.text
    wait_job(client, r.json()["job_id"])


def test_users_side_validation(client, auth, fake_orch):
    iran = client.post("/api/servers", json=SERVER, headers=auth).json()
    kharej = client.post("/api/servers", json=KHAREJ, headers=auth).json()
    assert client.post("/api/tunnels", json={
        "mode": "spoof", "iran_id": iran["id"], "kharej_id": kharej["id"], "users": "kharej",
        "spoof": {"iran_spoof_ip": "5.160.0.1", "kharej_spoof_ip": "8.8.4.4"},
    }, headers=auth).status_code == 422
    r = client.post("/api/tunnels", json={
        "mode": "gre", "iran_id": iran["id"], "kharej_id": kharej["id"], "users": "kharej",
    }, headers=auth)
    assert r.status_code == 200, r.text
    body = r.json()["tunnel"]
    assert body["users"] == "kharej" and body["direct"] is False
    wait_job(client, r.json()["job_id"])
    r = client.post("/api/tunnels", json={
        "mode": "icmp", "users": "kharej", "iran_id": iran["id"], "kharej_id": kharej["id"],
    }, headers=auth)
    assert r.status_code == 200, r.text
    body = r.json()["tunnel"]
    assert body["direct"] is True and body["users"] == "kharej" and body["iran_id"] == body["kharej_id"]
    wait_job(client, r.json()["job_id"])


def test_vpn_panel_validation(client, auth, monkeypatch):
    iran = client.post("/api/servers", json=SERVER, headers=auth).json()
    assert client.post(f"/api/servers/{iran['id']}/vpn-panel", json={"kind": "nope"}, headers=auth).status_code == 422
    assert client.post(f"/api/servers/{iran['id']}/vpn-panel", json={}, headers=auth).status_code == 422

    async def fake_vpn(job, server_id, kind):
        await job.start(0)
        await job.ok(0)
        await job.start(1)
        await job.ok(1)
        await job.start(2)
        await job.ok(2, kind)
        await job.start(3)
        await job.ok(3, "http://1.2.3.4:2053/")

    monkeypatch.setattr(client.app.state.orch, "job_vpn_panel", fake_vpn)
    r = client.post(f"/api/servers/{iran['id']}/vpn-panel", json={"kind": "xui"}, headers=auth)
    assert r.status_code == 200 and "job_id" in r.json()
    assert wait_job(client, r.json()["job_id"])["status"] == "ok"
    r = client.post(f"/api/servers/{iran['id']}/vpn-panel", json={"kind": "pasarguard"}, headers=auth)
    assert r.status_code == 200 and wait_job(client, r.json()["job_id"])["status"] == "ok"
    r = client.post(f"/api/servers/{iran['id']}/vpn-panel", json={"kind": "xui_classic"}, headers=auth)
    assert r.status_code == 200 and wait_job(client, r.json()["job_id"])["status"] == "ok"


def test_cli_set_admin_and_has_admin(settings, monkeypatch, capsys):
    from app import cli

    monkeypatch.setenv("JOJONET_PANEL_DATA", str(settings.data_dir))
    assert cli.main(["has-admin"]) == 1
    assert cli.main(["set-admin", "--random"]) == 0
    out = capsys.readouterr().out
    assert "username: admin" in out and "password: " in out
    assert cli.main(["has-admin"]) == 0
    monkeypatch.setenv("JOJONET_PANEL_SECURE_COOKIES", "1")
    assert cli.main(["serve"]) == 2
    assert cli.main(["serve", "--cert", "x.pem"]) == 2
