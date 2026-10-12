from __future__ import annotations

import json

from app.reality import generate_material, material_ok, pick_port, plan, used_ports


def test_generated_reality_keys_match():
    mat = generate_material()
    assert material_ok(mat)
    assert mat["sni"] == "www.microsoft.com"
    assert len(mat["shortId"]) == 8


def test_port_skips_forwarded_443():
    used = used_ports("443, 80:8080")
    assert used == {443, 80, 8080}
    assert pick_port(used) == 8443
    assert pick_port(set()) == 443


def test_plan_builds_matching_reality_and_keeps_keys():
    row = {
        "id": 7,
        "mode": "gre",
        "iran_id": 1,
        "kharej_id": 2,
        "tun_iran_ip": "172.20.13.2",
        "tun_kharej_ip": "172.20.13.1",
        "forward_ports": "443",
        "options": {"users": "iran"},
    }
    iran = {"id": 1, "name": "Iran", "host": "185.226.118.188", "role": "iran"}
    kharej = {"id": 2, "name": "FI", "host": "65.109.221.175", "role": "kharej"}
    first = plan(row, iran, kharej)
    assert first["kind"] == "ready"
    assert first["port"] == 8443
    assert first["outbound"]["protocol"] == "freedom"
    assert first["outbound"]["sendThrough"] == "172.20.13.2"
    assert first["outbound"]["tag"] == "jojonet-7"
    assert first["routing"]["inboundTag"] == ["inbound-8443"]
    assert first["routing"]["outboundTag"] == "jojonet-7"
    assert first["_save"]["privateKey"] == first["private_key"]
    client = json.dumps(first["client"])
    assert first["private_key"] not in client
    assert first["public_key"] in client
    assert "reality" in first["link"] and "185.226.118.188:8443" in first["link"]
    inbound = json.loads(first["inbound"]["streamSettings"])
    assert inbound["security"] == "reality"
    assert inbound["realitySettings"]["privateKey"] == first["private_key"]
    assert inbound["realitySettings"]["shortIds"] == [first["short_id"]]
    assert json.loads(first["inbound"]["settings"])["clients"][0]["id"] == first["uuid"]

    stored = dict(row)
    stored["options"] = {"users": "iran", "reality": first["_save"]}
    second = plan(stored, iran, kharej)
    assert second["_save"] is None
    assert second["uuid"] == first["uuid"]
    assert second["private_key"] == first["private_key"]
    assert second["port"] == 8443


def test_direct_and_xray_tunnels_do_not_mint_keys():
    direct = plan(
        {"id": 1, "mode": "dnstt", "iran_id": 3, "kharej_id": 3, "options": {"direct": True}},
        None,
        {"id": 3, "name": "FI", "host": "1.2.3.4"},
    )
    assert direct["kind"] == "direct" and direct["_save"] is None
    xray = plan(
        {"id": 2, "mode": "dokodemo", "iran_id": 1, "kharej_id": 2, "tun_iran_ip": "10.1.0.1", "options": {}},
        {"id": 1, "name": "IR", "host": "5.6.7.8"},
        {"id": 2, "name": "FI", "host": "1.2.3.4"},
    )
    assert xray["kind"] == "xray" and xray["outbound"] is None


def test_reality_endpoint_is_stable_and_hidden_from_tunnel_list(client, auth):
    iran = client.post("/api/servers", json={
        "name": "Iran-1", "role": "iran", "host": "5.6.7.8", "port": 22,
        "username": "root", "auth_type": "password", "password": "pw-iran",
    }, headers=auth).json()
    kharej = client.post("/api/servers", json={
        "name": "DE-1", "role": "kharej", "host": "1.2.3.4", "port": 22,
        "username": "root", "auth_type": "password", "password": "pw-kharej",
    }, headers=auth).json()
    db = client.app.state.db
    owner = db.one("SELECT id FROM admins LIMIT 1")["id"]
    tid = db.insert("tunnels", {
        "mode": "gre", "iran_id": iran["id"], "kharej_id": kharej["id"],
        "status": "ok", "tun_iran_ip": "172.20.13.2", "tun_kharej_ip": "172.20.13.1",
        "forward_ports": "443", "options": {"users": "iran"},
        "created_at": "2026-01-01T00:00:00+00:00", "owner_id": owner,
    })
    first = client.get(f"/api/tunnels/{tid}/reality", headers=auth)
    assert first.status_code == 200, first.text
    body = first.json()
    assert body["kind"] == "ready"
    assert body["send_through"] == "172.20.13.2"
    assert body["address"] == "5.6.7.8"
    assert "_save" not in body
    second = client.get(f"/api/tunnels/{tid}/reality", headers=auth).json()
    assert second["uuid"] == body["uuid"]
    assert second["private_key"] == body["private_key"]
    listed = client.get("/api/tunnels", headers=auth).json()
    opts = next(t for t in listed if t["id"] == tid)["options"]
    assert "reality" not in (opts or {})
    assert client.get("/api/tunnels/999/reality", headers=auth).status_code == 404
