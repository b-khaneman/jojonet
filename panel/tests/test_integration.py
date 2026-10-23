"""End-to-end orchestration against simulated servers.

The fake servers emulate jojonet's real key behaviour (subnet-based pair dirs for TUN/TCP and Paqet,
peer-IP pair dirs for the rest, WG placeholder peer key) and only report healthy when both sides hold
matching keys, so a wrong key-sync path makes the deploy fail exactly like on real servers.
"""
from __future__ import annotations

import asyncio
import base64
import io
import re
import secrets
import tarfile
import time
import zlib

import pytest

from app import orchestrator as orch_mod
from app.sshclient import CmdResult
from app.validators import MODES, SHARED_KEY_FILES, WG_MODES, WG_OBFS, conf_mode
from conftest import REPO_DIR

FLAG_TO_MODE = {v["flag"]: k for k, v in MODES.items()}
SECRET_FILE = {
    "paqet": "paqet.secret", "hysteria2": "hy2.auth", "rathole": "rathole.token", "wstunnel": "wstunnel.token",
    "dokodemo": "xray.uuid", "xray_reverse": "xray.uuid",
    "dnstt": "dnstt.auth", "icmp": "pingtunnel.key",
}
PREFIX = {
    "gre": "172.20", "tun_tcp": "10.30", "vxlan": "10.40", "wireguard": "10.66", "wg_icmp": "10.67", "wg_faketcp": "10.68",
    "gre6": "172.22", "ipip6": "172.23",
}
NAME_PREFIX = {
    "wireguard": "wg", "wg_icmp": "wi", "wg_faketcp": "wf",
    "dokodemo": "dk", "xray_reverse": "xr", "sit": "s6", "gre6": "g6", "ipip6": "i6",
    "dnstt": "dt", "icmp": "ic",
}
SRC_RE = re.compile(r"printf '%s\\n' (\S+) >")


def subnet_byte(a: str, b: str) -> int:
    key = "|".join(sorted((a, b), key=lambda ip: tuple(int(x) for x in ip.split("."))))
    return zlib.crc32(key.encode()) % 250 + 1


class FakeServer:
    def __init__(self, world: "World", host: str, src: str | None = None):
        self.world = world
        self.host = host
        self.src = src or host
        self.confs: dict[str, dict[str, str]] = {}
        self.keys: dict[str, dict[str, str]] = {}
        self.jojonet = ""
        self.commands: list[str] = []
        self.spoof: dict[str, str] | None = None
        self.can_spoof = True
        self.python = True
        self.spoof_bin = False
        self.relays: dict[str, dict[str, str]] = {}
        self.dns: tuple[str, ...] = ()
        self.vpn_panels: dict[str, bool] = {}

    def vpn_creds_block(self, kind: str) -> str:
        if kind in ("xui", "xui_classic"):
            label = "X-UI اصلی" if kind == "xui_classic" else "3x-ui سنایی"
            url = f"http://{self.host}:2053/"
            return (
                "===== JOJONET_VPN_CREDS =====\n"
                f"kind=xui\nlabel={label}\nurl={url}\nusername=admin\npassword=admin123\n"
                "===== END_JOJONET_VPN_CREDS =====\n"
            )
        url = f"http://{self.host}:8000/dashboard/"
        return (
            "===== JOJONET_VPN_CREDS =====\n"
            f"kind=pasarguard\nlabel=پاسارگارد\nurl={url}\npassword=tmp-key-abc\n"
            "note=کلید یک‌بارمصرف ورود اول\n"
            "===== END_JOJONET_VPN_CREDS =====\n"
        )

    def spoof_pair_ok(self) -> bool:
        """Both sides configured, pointing at each other, with mirrored spoof IPs and identical transports."""
        if not self.spoof:
            return False
        peer = self.world.servers.get(self.spoof["peer"])
        if not peer or not peer.spoof or peer.spoof["peer"] != self.host or peer.spoof["mode"] == self.spoof["mode"]:
            return False
        a, b = self.spoof, peer.spoof
        same = all(a[k] == b[k] for k in a if k.startswith("JOJONET_SPOOF_") and k not in ("JOJONET_SPOOF_IP", "JOJONET_SPOOF_PEER_IP"))
        return same and a["JOJONET_SPOOF_IP"] == b["JOJONET_SPOOF_PEER_IP"] and b["JOJONET_SPOOF_IP"] == a["JOJONET_SPOOF_PEER_IP"]

    # --- jojonet emulation ---
    def keydir_for(self, mode: str, peer: str) -> str:
        if mode in ("tun_tcp", "paqet"):
            return f"/etc/jojonet/keys/pair_{subnet_byte(self.src, peer)}"
        return "/etc/jojonet/keys/pair_" + peer.replace(".", "_")

    def deploy(self, role: str, mode: str, peer: str) -> int:
        n = subnet_byte(self.src, peer)
        name = f"{NAME_PREFIX.get(mode, mode[:3])}{n}"
        conf = {"Name": name, "TunnelMode": "wireguard" if mode in WG_MODES else mode, "Role": role, "Remote_IP": peer, "Local_IP": self.src}
        if mode in WG_OBFS:
            conf["WgObfs"] = WG_OBFS[mode]
        kd = ""
        if mode not in ("gre", "vxlan"):
            kd = self.keydir_for(mode, peer)
            d = self.keys.setdefault(kd, {})
            if mode == "tun_tcp" and "private_key.pem" not in d:
                d["private_key.pem"] = "RSA-" + secrets.token_hex(8)
                d["public_key.pem"] = "PUB-" + d["private_key.pem"]
            elif mode in SECRET_FILE and SECRET_FILE[mode] not in d:
                d[SECRET_FILE[mode]] = secrets.token_hex(24)
            elif mode in WG_MODES:
                if "wg_private.key" not in d:
                    d["wg_private.key"] = "priv-" + secrets.token_hex(4)
                    d["wg_public.key"] = "pub-" + d["wg_private.key"]
                d.setdefault("wg_peer_public.key", d["wg_public.key"])
                if mode in WG_OBFS:
                    # Like ensure_shared_secret without SSH: a missing key is generated locally (and would mismatch).
                    d.setdefault("udp2raw.key", secrets.token_hex(24))
        conf["KeyDir"] = kd
        if mode == "sit":
            conf["Tun_IP"] = f"fd6a:aaaa:bbbb::{'1' if role == 'kharej' else '2'}/64"
        elif mode in PREFIX:
            me, other = (1, 2) if role == "kharej" else (2, 1)
            conf["Tun_IP"] = f"{PREFIX[mode]}.{n}.{me}/30"
            conf["Tun_Remote_IP_Raw"] = f"{PREFIX[mode]}.{n}.{other}"
        if role == "iran" and mode != "sit":
            conf["Ports"] = "443"
        self.confs[name] = conf
        return 0

    def healthy(self, name: str) -> bool:
        conf = self.confs.get(name)
        if not conf:
            return False
        peer = self.world.servers[conf["Remote_IP"]]
        mode = conf_mode(conf)
        peer_conf = next((c for c in peer.confs.values() if c["Remote_IP"] == self.host and conf_mode(c) == mode), None)
        if peer_conf is None:
            return False
        mine, theirs = self.keys.get(conf["KeyDir"], {}), peer.keys.get(peer_conf["KeyDir"], {})
        if mode in WG_MODES:
            wg_ok = mine.get("wg_peer_public.key") == theirs.get("wg_public.key") and theirs.get("wg_peer_public.key") == mine.get("wg_public.key")
            return wg_ok and (mode not in WG_OBFS or (bool(mine.get("udp2raw.key")) and mine.get("udp2raw.key") == theirs.get("udp2raw.key")))
        if mode == "tun_tcp":
            return bool(mine.get("private_key.pem")) and mine.get("private_key.pem") == theirs.get("private_key.pem")
        if mode in SECRET_FILE:
            f = SECRET_FILE[mode]
            return bool(mine.get(f)) and mine.get(f) == theirs.get(f)
        return True

    # --- command dispatcher ---
    def run(self, script: str, data: bytes | None) -> CmdResult:
        self.commands.append(script)
        self.world.log.append((self.host, script))
        if script == orch_mod.SYSINFO_SCRIPT:
            return CmdResult(0, f"os=Ubuntu 24.04\nsrc={self.src}\njojonet={self.jojonet}\nsystemd=yes\n", "")
        if script == orch_mod.PREREQ_SCRIPT:
            return CmdResult(0, "prerequisites OK\n", "")
        if script == orch_mod.ENSURE_TOOLS_SCRIPT:
            return CmdResult(0, "tools_ok\n", "")
        if "bash install.sh" in script:
            with tarfile.open(fileobj=io.BytesIO(data)) as tar:
                assert "jojonet" in tar.getnames()
            self.jojonet = orch_mod.bundle_version(orch_mod.Path(__file__).resolve().parents[2])
            return CmdResult(0, f"jojonet {self.jojonet}\n", "")
        if script == orch_mod.DUMP_CONFS:
            out = "".join(f"==> /etc/jojonet/instances/{n}.conf <==\n" + "".join(f'{k}="{v}"\n' for k, v in c.items()) for n, c in self.confs.items())
            return CmdResult(0, out, "")
        m = re.search(r"install -d -m700 (\S+)\n", script)
        if m and "tar -xzf -" in script:
            kd = m.group(1).strip("'")
            allowed = re.search(r"for f in ([^;]+); do", script).group(1).replace("'", "").split()
            n = 0
            with tarfile.open(fileobj=io.BytesIO(data)) as tar:
                for member in tar.getmembers():
                    if member.name in allowed and member.isfile():
                        self.keys.setdefault(kd, {})[member.name] = tar.extractfile(member).read().decode()
                        n += 1
            return CmdResult(0 if n else 1, f"installed={n}\n", "")
        m = re.match(r"cd (\S+) 2>/dev/null \|\| exit 0\nfor f in ([^;]+); do", script)
        if m:
            names = m.group(2).replace("'", "").split()
            d = self.keys.get(m.group(1).strip("'"), {})
            return CmdResult(0, "".join(f"{k}={d[k]}\n" for k in names if k in d), "")
        m = re.match(r"\ncd (\S+) \|\| exit 3", script)
        if m:
            files = {k: v for k, v in self.keys.get(m.group(1).strip("'"), {}).items() if k in SHARED_KEY_FILES}
            if not files:
                return CmdResult(4, "", "")
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w:gz") as tar:
                for k, v in files.items():
                    raw = v.encode()
                    info = tarfile.TarInfo(k)
                    info.size = len(raw)
                    tar.addfile(info, io.BytesIO(raw))
            return CmdResult(0, base64.b64encode(buf.getvalue()).decode(), "")
        if script == orch_mod.SPOOF_STATE:
            out = f"state={'active' if self.spoof else 'inactive'}\n"
            if self.spoof:
                out += f"mode={self.spoof['mode']}\npeer={self.spoof['peer']}\n"
            return CmdResult(0, out + f"py={'yes' if self.python else 'no'}\n", "")
        if script == orch_mod.SPOOF_REMOVE:
            self.spoof = None
            return CmdResult(0, "Spoof Tunnel removed\n", "")
        if script == "jojonet --spoof-install </dev/null":
            self.spoof_bin = True
            return CmdResult(0, "[+] Spoof Tunnel installed and checksum verified: /usr/local/bin/spoof\n", "")
        if "tester --mode sender" in script:
            assert self.spoof_bin, "spoof tester run before --spoof-install"
            src, dst = SRC_RE.search(script).group(1), re.search(r"--dst-ip (\S+)", script).group(1)
            self.world.spoof_delivered[(src, dst)] = self.can_spoof
            self.world.sender_done.set()
            return CmdResult(0, "[tester-sender] done -- sent: 20, errors: 0\n", "")
        if "tester --mode receiver" in script:
            assert self.spoof_bin, "spoof tester run before --spoof-install"
            src = SRC_RE.search(script).group(1)
            if self.world.spoof_delivered.pop((src, self.host), False):
                return CmdResult(0, f"{src} 20/20 0.0%\n[tester] 1/1 IPs passed\n", "")
            return CmdResult(0, "[tester] 0/1 IPs passed\n", "")
        m = re.search(r"JOJONET_ROLE=(\w+) JOJONET_AUTO=1 TERM=dumb ((?:JOJONET_SPOOF_\w+=\S+ )+)timeout 900 jojonet --spoof (\S+) </dev/null", script)
        if m:
            env = dict(kv.split("=", 1) for kv in m.group(2).split())
            self.spoof = {"mode": "local" if m.group(1) == "iran" else "remote", "peer": m.group(3), **env}
            return CmdResult(0, "Spoof Tunnel running\n", "")
        m = re.match(r"ss -Hlun 'sport = :(\d+)'", script)
        if m:
            bound = bool(self.spoof) and self.spoof["mode"] == "local" and self.spoof["JOJONET_SPOOF_LISTEN"].endswith(":" + m.group(1))
            return CmdResult(0, f"UNCONN 0 0 0.0.0.0:{m.group(1)} 0.0.0.0:*\n" if bound else "", "")
        if script.startswith("timeout 40 python3 -c") and "s.bind" in script:
            iran = self.world.servers[self.spoof["peer"]]
            self.world.probe_up = self.spoof_pair_ok() and iran.can_spoof
            return CmdResult(0, f"ready\nreceived {1 if self.world.probe_up else 0}\n", "")
        if script.startswith("timeout 30 python3 -c") and "noack" in script:
            kharej = self.world.servers[self.spoof["peer"]]
            ok = self.world.probe_up and kharej.can_spoof
            return CmdResult(0 if ok else 1, "ack 2\n" if ok else "noack 40\n", "")
        m = re.search(r"JOJONET_ROLE=(\w+) JOJONET_AUTO=1 TERM=dumb(?: JOJONET_\w+=\S+)* timeout 900 jojonet (\S+) (\S+) </dev/null", script)
        if m:
            return CmdResult(self.deploy(m.group(1), FLAG_TO_MODE[m.group(2)], m.group(3)), "deployed\n", "")
        m = re.match(r"jojonet --health (\S+) </dev/null", script)
        if m:
            return CmdResult(0 if self.healthy(m.group(1)) else 1, "", "")
        m = re.match(r"jojonet --delete (\S+) </dev/null", script)
        if m:
            return CmdResult(0 if self.confs.pop(m.group(1), None) else 1, "", "")
        if script == orch_mod.LIST_TUNNELS_JSON:
            import json

            items = []
            for name, c in self.confs.items():
                mode = conf_mode(c)
                unit = "jojonet-stream@" + name + ".service" if mode in ("dnstt", "icmp") else f"jojonet@{name}.service"
                items.append({
                    "name": name, "mode": mode, "role": c.get("Role", ""),
                    "local_ip": c.get("Local_IP", ""), "remote_ip": c.get("Remote_IP", ""),
                    "status": "UP" if self.healthy(name) else "DOWN", "boot": True, "unit": unit,
                })
            return CmdResult(0, json.dumps(items) + "\n", "")
        if script == orch_mod.ENABLE_BOOT_CMD:
            return CmdResult(0, "[+] Boot persistence OK. Enabled: 0 | Started: 0\n", "")
        m = re.match(r"ping(?: -6)? -c 3 -W 2 -q (\S+)", script)
        if m:
            ok = any(c.get("Tun_IP", "").startswith(m.group(1) + "/")
                     for s in self.world.servers.values() for c in s.confs.values())
            ok = ok and all(s.healthy(n) for s in self.world.servers.values() for n in s.confs)
            return CmdResult(0 if ok else 1, "rtt min/avg/max/mdev = 1.0/12.5/20.0/1.0 ms\n" if ok else "", "")
        m = re.search(r"TERM=dumb timeout 300 jojonet --relay (\S+) (\S+) (\S+) (\S+) (\S+) </dev/null", script)
        if m:
            engine, target, ports, proto, name = m.group(1), m.group(2), m.group(3), m.group(4), m.group(5)
            self.relays[name] = {"engine": engine, "target": target, "ports": ports, "proto": proto, "name": name}
            return CmdResult(0, f"Relay [{name}] UP\n", "")
        m = re.match(r"jojonet --relay-remove (\S+) </dev/null", script)
        if m:
            return CmdResult(0 if self.relays.pop(m.group(1), None) is not None else 1, "", "")
        m = re.match(r"jojonet --relay-stats (\S+) </dev/null", script)
        if m:
            rel = self.relays.get(m.group(1))
            if not rel:
                return CmdResult(1, "", "not found")
            return CmdResult(0, f"=== {rel['name']} ({rel['engine']}) → {rel['target']} ===\n  port {rel['ports']}: 0 B\n", "")
        m = re.match(r"jojonet --dns (\S+)(?: (\S+))? </dev/null", script)
        if m:
            self.dns = tuple(x for x in m.groups() if x)
            return CmdResult(0, f"DNS set: {' '.join(self.dns)}\n", "")
        if script == "jojonet --ping-test </dev/null":
            return CmdResult(0, "  ok    github.com  avg 12 ms  loss 0%\n", "")
        if script == "jojonet --update-server </dev/null":
            return CmdResult(0, "packages updated\n", "")
        if "jojonet --help" in script and "grep -F" in script:
            flag = "--xui-classic-install" if "--xui-classic-install" in script else (
                "--xui-install" if "--xui-install" in script else "--pasarguard-install"
            )
            if self.jojonet:
                return CmdResult(0, f"{flag}\n", "")
            return CmdResult(1, "", "")
        if "jojonet --xui-classic-install" in script:
            self.vpn_panels["xui_classic"] = True
            return CmdResult(0, "classic X-UI installed\n" + self.vpn_creds_block("xui_classic"), "")
        if "jojonet --xui-install" in script:
            self.vpn_panels["xui"] = True
            return CmdResult(0, "3x-ui installed\n" + self.vpn_creds_block("xui"), "")
        if "jojonet --pasarguard-install" in script:
            self.vpn_panels["pasarguard"] = True
            return CmdResult(0, "PasarGuard installed\n" + self.vpn_creds_block("pasarguard"), "")
        if "jojonet --vpn-panel-check" in script:
            xui = self.vpn_panels.get("xui") or self.vpn_panels.get("xui_classic")
            flavor = "classic" if self.vpn_panels.get("xui_classic") else ("sanaei" if self.vpn_panels.get("xui") else "")
            pg = 1 if self.vpn_panels.get("pasarguard") else 0
            return CmdResult(0, (
                "===== JOJONET_VPN_CHECK =====\n"
                f"xui={1 if xui else 0}\n"
                f"xui_flavor={flavor}\n"
                f"xui_running={1 if xui else 0}\n"
                f"pasarguard={pg}\n"
                f"pasarguard_running={pg}\n"
                "===== END_JOJONET_VPN_CHECK =====\n"
            ), "")
        if "jojonet --vpn-panel-creds" in script:
            if self.vpn_panels.get("xui"):
                return CmdResult(0, self.vpn_creds_block("xui"), "")
            if self.vpn_panels.get("xui_classic"):
                return CmdResult(0, self.vpn_creds_block("xui_classic"), "")
            if self.vpn_panels.get("pasarguard"):
                return CmdResult(0, self.vpn_creds_block("pasarguard"), "")
            return CmdResult(1, "No VPN panel login found.\n", "")
        if "unzip tar curl" in script and "tools_ok" in script:
            return CmdResult(0, "tools_ok\n", "")
        raise AssertionError(f"unexpected command: {script[:200]}")


class FakeSession:
    def __init__(self, server: FakeServer):
        self.server = server
        self.is_root = True
        self.hostkey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForTests host"

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return None

    async def run_root(self, script, input_data=None, timeout=120, on_line=None):
        data = input_data.encode() if isinstance(input_data, str) else input_data
        if "tester --mode receiver" in script and self.server.spoof_bin:
            # The real receiver listens for its timeout while the sender runs on the other server.
            world = self.server.world
            world.sender_done.clear()
            if on_line:
                await on_line("[tester] mode=receiver protocol=icmp packet_count=20 max_loss=80.0%")
            await asyncio.wait_for(world.sender_done.wait(), timeout=20)
        res = self.server.run(script, data)
        if on_line:
            for line in res.stdout.splitlines()[:5]:
                r = on_line(line)
                if asyncio.iscoroutine(r):
                    await r
        return res


class World:
    def __init__(self):
        self.servers: dict[str, FakeServer] = {}
        self.log: list[tuple[str, str]] = []
        self.probe_up = False
        self.spoof_delivered: dict[tuple[str, str], bool] = {}
        self.sender_done = asyncio.Event()


@pytest.fixture()
def world(client, monkeypatch):
    w = World()
    w.servers["5.6.7.8"] = FakeServer(w, "5.6.7.8")
    w.servers["1.2.3.4"] = FakeServer(w, "1.2.3.4")
    orch = client.app.state.orch
    real_open = orch.open

    async def fake_open(job, row):
        sess = FakeSession(w.servers[row["host"]])
        if not row["hostkey"]:
            orch.db.update("servers", row["id"], {"hostkey": sess.hostkey, "hostkey_fingerprint": "SHA256:fake"})
        await job.log(f"[{row['name']}] fake connect")
        return sess

    monkeypatch.setattr(orch, "open", fake_open)
    monkeypatch.setattr(orch_mod, "RETRY_DELAY", 0)
    assert real_open is not None
    return w


def wait_job(client, job_id, timeout=30.0):
    end = time.time() + timeout
    while time.time() < end:
        job = client.get(f"/api/jobs/{job_id}").json()
        if job["status"] in ("ok", "failed"):
            return job
        time.sleep(0.05)
    raise AssertionError("job did not finish")


def make_servers(client, auth):
    iran = client.post("/api/servers", json={"name": "IR", "role": "iran", "host": "5.6.7.8", "auth_type": "password", "password": "pw1"}, headers=auth).json()
    kharej = client.post("/api/servers", json={"name": "DE", "role": "kharej", "host": "1.2.3.4", "auth_type": "password", "password": "pw2"}, headers=auth).json()
    return iran, kharej


@pytest.mark.parametrize("mode", [m for m in MODES if m != "spoof"])
def test_deploy_verify_delete_every_mode(client, auth, world, mode):
    iran, kharej = make_servers(client, auth)
    payload = {"mode": mode, "iran_id": iran["id"], "kharej_id": kharej["id"]}
    if mode == "dnstt":
        payload["dnstt"] = {"domain": "t.example.com"}
    r = client.post("/api/tunnels", json=payload, headers=auth)
    job = wait_job(client, r.json()["job_id"])
    assert job["status"] == "ok", job["log"] + str(job["steps"])
    assert all(s["status"] in ("ok", "skipped") for s in job["steps"]), job["steps"]
    t = client.get("/api/tunnels").json()[0]
    assert t["status"] == "ok" and t["iran_iface"] and t["kharej_iface"]
    if mode in PREFIX:
        assert t["tun_kharej_ip"].endswith(".1") and t["tun_iran_ip"].endswith(".2")
    if mode == "sit":
        assert t["tun_kharej_ip"].endswith("::1") and t["tun_iran_ip"].endswith("::2")
        assert not t["forward_ports"]
    else:
        assert t["forward_ports"] == "443"

    ir, de = world.servers["5.6.7.8"], world.servers["1.2.3.4"]
    first = MODES[mode]["first"]
    deploy_order = [host for host, c in world.log if "JOJONET_AUTO=1" in c]
    assert deploy_order == (["1.2.3.4", "5.6.7.8"] if first == "kharej" else ["5.6.7.8", "1.2.3.4"])
    assert ir.jojonet == de.jojonet == orch_mod.bundle_version(REPO_DIR)
    if mode == "tun_tcp":
        kd = next(iter(ir.keys))
        assert kd == next(iter(de.keys)) and re.fullmatch(r"/etc/jojonet/keys/pair_\d+", kd)

    job = wait_job(client, client.post(f"/api/tunnels/{t['id']}/verify", headers=auth).json()["job_id"])
    assert job["status"] == "ok", job["log"]

    job = wait_job(client, client.request("DELETE", f"/api/tunnels/{t['id']}", json={"force": False}, headers=auth).json()["job_id"])
    assert job["status"] == "ok", job["log"]
    assert client.get("/api/tunnels").json() == []
    assert ir.confs == {} and de.confs == {}


SPOOF = {"iran_spoof_ip": "5.160.0.1", "kharej_spoof_ip": "8.8.4.4"}


def test_spoof_deploy_verify_delete(client, auth, world):
    iran, kharej = make_servers(client, auth)
    r = client.post("/api/tunnels", json={"mode": "spoof", "iran_id": iran["id"], "kharej_id": kharej["id"], "spoof": SPOOF}, headers=auth)
    assert r.status_code == 200, r.text
    job = wait_job(client, r.json()["job_id"])
    assert job["status"] == "ok", job["log"] + str(job["steps"])
    assert [s["status"] for s in job["steps"]] == ["ok", "ok", "ok", "skipped", "ok", "skipped", "ok", "ok"]
    ir, de = world.servers["5.6.7.8"], world.servers["1.2.3.4"]
    assert ir.spoof["mode"] == "local" and ir.spoof["peer"] == "1.2.3.4"
    assert de.spoof["mode"] == "remote" and de.spoof["peer"] == "5.6.7.8"
    assert ir.spoof["JOJONET_SPOOF_IP"] == "5.160.0.1" and ir.spoof["JOJONET_SPOOF_PEER_IP"] == "8.8.4.4"
    assert ir.spoof["JOJONET_SPOOF_LISTEN"] == "0.0.0.0:8443"
    deploy_order = [host for host, c in world.log if "JOJONET_AUTO=1" in c]
    assert deploy_order == ["1.2.3.4", "5.6.7.8"]
    t = client.get("/api/tunnels").json()[0]
    assert t["status"] == "ok" and t["options"]["up_transport"] == "tcp"
    assert t["forward_ports"] == "udp 0.0.0.0:8443 → 127.0.0.1:443"
    assert "هر دو جهت" in t["last_check"]["info"]

    dup = client.post("/api/tunnels", json={"mode": "spoof", "iran_id": iran["id"], "kharej_id": kharej["id"], "spoof": SPOOF}, headers=auth)
    assert dup.status_code == 409

    de.spoof["peer"] = "9.9.9.9"
    job = wait_job(client, client.post(f"/api/tunnels/{t['id']}/verify", headers=auth).json()["job_id"])
    assert job["status"] == "failed" and "نمی‌خواند" in job["log"]
    de.spoof["peer"] = "5.6.7.8"
    assert wait_job(client, client.post(f"/api/tunnels/{t['id']}/verify", headers=auth).json()["job_id"])["status"] == "ok"

    job = wait_job(client, client.request("DELETE", f"/api/tunnels/{t['id']}", json={}, headers=auth).json()["job_id"])
    assert job["status"] == "ok", job["log"]
    assert ir.spoof is None and de.spoof is None and client.get("/api/tunnels").json() == []


@pytest.mark.parametrize("blocked, name", [("5.6.7.8", "IR"), ("1.2.3.4", "DE")])
def test_spoof_readiness_blocks_build(client, auth, world, blocked, name):
    world.servers[blocked].can_spoof = False
    iran, kharej = make_servers(client, auth)
    r = client.post("/api/tunnels", json={"mode": "spoof", "iran_id": iran["id"], "kharej_id": kharej["id"], "spoof": SPOOF}, headers=auth)
    job = wait_job(client, r.json()["job_id"])
    assert job["status"] == "failed", job["log"]
    assert "آماده نیستند" in job["log"] and f"دیتاسنتر {name} جعل IP را مسدود" in job["log"]
    assert [s["status"] for s in job["steps"]][:3] == ["ok", "ok", "failed"]
    assert world.servers["5.6.7.8"].spoof is None and world.servers["1.2.3.4"].spoof is None
    assert not any("jojonet --spoof " in c for _, c in world.log)
    assert client.get("/api/tunnels").json()[0]["status"] == "failed"


@pytest.mark.parametrize("blocked, hint", [("5.6.7.8", "ایران به خارج نرسید"), ("1.2.3.4", "برگشت نرسید")])
def test_spoof_skip_check_then_probe_reports_direction(client, auth, world, blocked, hint):
    world.servers[blocked].can_spoof = False
    iran, kharej = make_servers(client, auth)
    r = client.post("/api/tunnels", json={"mode": "spoof", "iran_id": iran["id"], "kharej_id": kharej["id"],
                                          "spoof": {**SPOOF, "skip_check": True}}, headers=auth)
    job = wait_job(client, r.json()["job_id"])
    assert job["status"] == "failed" and hint in job["log"]
    assert not any("tester --mode" in c for _, c in world.log)
    t = client.get("/api/tunnels").json()[0]
    assert t["status"] == "degraded" and hint in t["last_check"]["info"]


def test_spoof_check_job(client, auth, world):
    iran, kharej = make_servers(client, auth)
    body = {"iran_id": iran["id"], "kharej_id": kharej["id"], "spoof": {**SPOOF, "up_transport": "tcp", "down_transport": "udp"}}
    job = wait_job(client, client.post("/api/spoof-check", json=body, headers=auth).json()["job_id"])
    assert job["status"] == "ok", job["log"]
    assert [s["status"] for s in job["steps"]] == ["ok", "ok", "ok", "ok"]
    assert "آماده Spoof هستند" in job["log"]
    tests = [(h, c) for h, c in world.log if "tester --mode" in c]
    # Iran sends as its spoof IP over TCP to the up port; Kharej answers as its spoof IP over ICMP.
    recv_up = next(c for h, c in tests if h == "1.2.3.4" and "--mode receiver" in c)
    assert "--protocol tcp" in recv_up and "--dst-port 9000" in recv_up and "5.160.0.1" in recv_up
    recv_down = next(c for h, c in tests if h == "5.6.7.8" and "--mode receiver" in c)
    assert "--protocol icmp" in recv_down and "8.8.4.4" in recv_down
    assert client.get("/api/tunnels").json() == []

    world.servers["1.2.3.4"].can_spoof = False
    job = wait_job(client, client.post("/api/spoof-check", json=body, headers=auth).json()["job_id"])
    assert job["status"] == "failed"
    assert [s["status"] for s in job["steps"]] == ["ok", "ok", "ok", "failed"]
    assert "دیتاسنتر DE جعل IP را مسدود" in job["log"]

    bad = client.post("/api/spoof-check", json={**body, "kharej_id": iran["id"]}, headers=auth)
    assert bad.status_code == 422
    bad = client.post("/api/spoof-check", json={**body, "spoof": {**SPOOF, "iran_spoof_ip": "1.2.3"}}, headers=auth)
    assert bad.status_code == 422


@pytest.mark.parametrize("mode", ["wg_icmp", "wg_faketcp"])
def test_obfuscated_wireguard_shares_udp2raw_key_and_coexists(client, auth, world, mode):
    iran, kharej = make_servers(client, auth)
    plain = client.post("/api/tunnels", json={"mode": "wireguard", "iran_id": iran["id"], "kharej_id": kharej["id"]}, headers=auth)
    assert wait_job(client, plain.json()["job_id"])["status"] == "ok"
    wg_before = world.servers["5.6.7.8"].keys["/etc/jojonet/keys/pair_1_2_3_4"]["wg_private.key"]
    r = client.post("/api/tunnels", json={"mode": mode, "iran_id": iran["id"], "kharej_id": kharej["id"]}, headers=auth)
    job = wait_job(client, r.json()["job_id"])
    assert job["status"] == "ok", job["log"]
    assert "udp2raw" in job["steps"][3]["detail"]
    ir, de = world.servers["5.6.7.8"], world.servers["1.2.3.4"]
    for s in (ir, de):
        modes = sorted(conf_mode(c) for c in s.confs.values())
        assert modes == sorted(["wireguard", mode]), "plain WireGuard must survive"
    kd_ir, kd_de = "/etc/jojonet/keys/pair_1_2_3_4", "/etc/jojonet/keys/pair_5_6_7_8"
    assert len(ir.keys[kd_ir]["udp2raw.key"]) == 48 and ir.keys[kd_ir]["udp2raw.key"] == de.keys[kd_de]["udp2raw.key"]
    assert ir.keys[kd_ir]["wg_private.key"] == wg_before, "existing WireGuard keys must be kept for the sibling tunnel"
    assert "حفظ شد" in job["log"]
    t = next(x for x in client.get("/api/tunnels").json() if x["mode"] == mode)
    assert t["tun_kharej_ip"].startswith(PREFIX[mode] + ".")
    # Every tunnel still verifies after the second deploy rewrote the shared WG keys on both sides.
    for x in client.get("/api/tunnels").json():
        assert wait_job(client, client.post(f"/api/tunnels/{x['id']}/verify", headers=auth).json()["job_id"])["status"] == "ok"
    # A mismatched udp2raw secret must show up as unhealthy.
    de.keys[kd_de]["udp2raw.key"] = "0" * 48
    assert wait_job(client, client.post(f"/api/tunnels/{t['id']}/verify", headers=auth).json()["job_id"])["status"] == "failed"


def test_spoof_without_python_skips_probe(client, auth, world):
    world.servers["1.2.3.4"].python = False
    iran, kharej = make_servers(client, auth)
    r = client.post("/api/tunnels", json={"mode": "spoof", "iran_id": iran["id"], "kharej_id": kharej["id"],
                                          "spoof": {**SPOOF, "listen_public": False, "up_transport": "icmp"}}, headers=auth)
    job = wait_job(client, r.json()["job_id"])
    assert job["status"] == "ok", job["log"]
    ir = world.servers["5.6.7.8"]
    assert ir.spoof["JOJONET_SPOOF_LISTEN"] == "127.0.0.1:8443" and ir.spoof["JOJONET_SPOOF_UP_TRANSPORT"] == "icmp"
    assert "python3" in client.get("/api/tunnels").json()[0]["last_check"]["info"]


def test_redeploy_replaces_stale_tunnel(client, auth, world):
    iran, kharej = make_servers(client, auth)
    job = wait_job(client, client.post("/api/tunnels", json={"mode": "hysteria2", "iran_id": iran["id"], "kharej_id": kharej["id"]}, headers=auth).json()["job_id"])
    assert job["status"] == "ok"
    # Simulate a broken peer secret, then redeploy must fix it.
    de = world.servers["1.2.3.4"]
    for d in de.keys.values():
        d["hy2.auth"] = "stale"
    tid = client.get("/api/tunnels").json()[0]["id"]
    assert wait_job(client, client.post(f"/api/tunnels/{tid}/verify", headers=auth).json()["job_id"])["status"] == "failed"
    assert client.get("/api/tunnels").json()[0]["status"] == "degraded"
    job = wait_job(client, client.post(f"/api/tunnels/{tid}/redeploy", headers=auth).json()["job_id"])
    assert job["status"] == "ok", job["log"]
    assert "حذف می‌شود" in job["log"]


def test_delete_unreachable_requires_force(client, auth, world, monkeypatch):
    iran, kharej = make_servers(client, auth)
    job = wait_job(client, client.post("/api/tunnels", json={"mode": "gre", "iran_id": iran["id"], "kharej_id": kharej["id"]}, headers=auth).json()["job_id"])
    assert job["status"] == "ok"
    orch = client.app.state.orch
    from app.sshclient import SSHError

    async def down(job, row):
        raise SSHError("unreachable")

    monkeypatch.setattr(orch, "open", down)
    tid = client.get("/api/tunnels").json()[0]["id"]
    job = wait_job(client, client.request("DELETE", f"/api/tunnels/{tid}", json={}, headers=auth).json()["job_id"])
    assert job["status"] == "failed"
    assert client.get("/api/tunnels").json()[0]["status"] == "failed"
    job = wait_job(client, client.request("DELETE", f"/api/tunnels/{tid}", json={"force": True}, headers=auth).json()["job_id"])
    assert job["status"] == "ok"
    assert client.get("/api/tunnels").json() == []


def test_install_job_and_test_job(client, auth, world):
    iran, _ = make_servers(client, auth)
    job = wait_job(client, client.post(f"/api/servers/{iran['id']}/install", headers=auth).json()["job_id"])
    assert job["status"] == "ok", job["log"]
    ver = orch_mod.bundle_version(REPO_DIR)
    assert world.servers["5.6.7.8"].jojonet == ver
    job = wait_job(client, client.post(f"/api/servers/{iran['id']}/test", headers=auth).json()["job_id"])
    assert job["status"] == "ok"
    srv = client.get("/api/servers").json()
    s = next(x for x in srv if x["id"] == iran["id"])
    assert s["last_check"]["ok"] is True and ver in s["last_check"]["info"]


def test_v6_one_per_pair(client, auth, world):
    iran, kharej = make_servers(client, auth)
    r = client.post("/api/tunnels", json={"mode": "sit", "iran_id": iran["id"], "kharej_id": kharej["id"]}, headers=auth)
    assert wait_job(client, r.json()["job_id"])["status"] == "ok"
    r = client.post("/api/tunnels", json={"mode": "gre6", "iran_id": iran["id"], "kharej_id": kharej["id"]}, headers=auth)
    assert r.status_code == 409


def test_xray_options_and_key_sync(client, auth, world):
    iran, kharej = make_servers(client, auth)
    r = client.post("/api/tunnels", json={
        "mode": "dokodemo", "iran_id": iran["id"], "kharej_id": kharej["id"],
        "xray": {"net": "ws", "ctrl_port": 4443, "ports": "8443:443"},
    }, headers=auth)
    job = wait_job(client, r.json()["job_id"])
    assert job["status"] == "ok", job["log"]
    t = client.get("/api/tunnels").json()[0]
    assert t["options"]["net"] == "ws" and t["options"]["ports"] == "8443:443"
    cmds = " ".join(c for _, c in world.log)
    assert "JOJONET_XRAY_NET=ws" in cmds and "JOJONET_XRAY_CTRL_PORT=4443" in cmds
    ir, de = world.servers["5.6.7.8"], world.servers["1.2.3.4"]
    kd_ir, kd_de = "/etc/jojonet/keys/pair_1_2_3_4", "/etc/jojonet/keys/pair_5_6_7_8"
    assert ir.keys[kd_ir]["xray.uuid"] == de.keys[kd_de]["xray.uuid"]
    r = client.post("/api/tunnels", json={"mode": "dokodemo", "iran_id": iran["id"], "kharej_id": kharej["id"],
                                         "xray": {"net": "quic"}}, headers=auth)
    assert r.status_code == 422


def test_relay_and_server_tools(client, auth, world):
    iran, kharej = make_servers(client, auth)
    r = client.post("/api/relays", json={
        "engine": "iptables", "iran_id": iran["id"], "target": "9.9.9.9", "ports": "443,8443:443", "proto": "both", "name": "web",
    }, headers=auth)
    assert r.status_code == 200, r.text
    job = wait_job(client, r.json()["job_id"])
    assert job["status"] == "ok", job["log"]
    rel = client.get("/api/relays").json()[0]
    assert rel["name"] == "web" and rel["status"] == "ok"
    assert world.servers["5.6.7.8"].relays["web"]["target"] == "9.9.9.9"
    job = wait_job(client, client.post(f"/api/relays/{rel['id']}/stats", headers=auth).json()["job_id"])
    assert job["status"] == "ok"
    r = client.post("/api/relays", json={"engine": "iptables", "iran_id": kharej["id"], "target": "1.1.1.1", "ports": "80"}, headers=auth)
    assert r.status_code == 200, r.text
    job = wait_job(client, r.json()["job_id"])
    assert job["status"] == "ok", job["log"]
    assert world.servers["1.2.3.4"].relays["iptables-80"]["target"] == "1.1.1.1"
    job = wait_job(client, client.request("DELETE", f"/api/relays/{rel['id']}", json={"force": False}, headers=auth).json()["job_id"])
    assert job["status"] == "ok" and world.servers["5.6.7.8"].relays == {}

    job = wait_job(client, client.post(f"/api/servers/{iran['id']}/dns", json={"dns1": "1.1.1.1", "dns2": "8.8.8.8"}, headers=auth).json()["job_id"])
    assert job["status"] == "ok" and world.servers["5.6.7.8"].dns == ("1.1.1.1", "8.8.8.8")
    job = wait_job(client, client.post(f"/api/servers/{iran['id']}/ping-test", headers=auth).json()["job_id"])
    assert job["status"] == "ok"
    job = wait_job(client, client.post(f"/api/servers/{iran['id']}/update-os", headers=auth).json()["job_id"])
    assert job["status"] == "ok"
    job = wait_job(client, client.post(f"/api/servers/{iran['id']}/vpn-panel", json={"kind": "xui"}, headers=auth).json()["job_id"])
    assert job["status"] == "ok" and world.servers["5.6.7.8"].vpn_panels.get("xui")
    assert "JOJONET_VPN_CREDS" in job["log"] and "http://5.6.7.8:2053/" in job["log"]
    assert job["steps"][-1]["name"] == "خواندن مشخصات ورود" and job["steps"][-1]["status"] == "ok"
    job = wait_job(client, client.post(f"/api/servers/{iran['id']}/vpn-panel", json={"kind": "xui"}, headers=auth).json()["job_id"])
    assert job["status"] == "ok" and "از قبل" in job["log"]
    job = wait_job(client, client.post(f"/api/servers/{kharej['id']}/vpn-panel", json={"kind": "pasarguard"}, headers=auth).json()["job_id"])
    assert job["status"] == "ok" and world.servers["1.2.3.4"].vpn_panels.get("pasarguard")
    assert "tmp-key-abc" in job["log"] and "http://1.2.3.4:8000/dashboard/" in job["log"]
    job = wait_job(client, client.post(f"/api/servers/{kharej['id']}/vpn-panel", json={"kind": "xui_classic"}, headers=auth).json()["job_id"])
    assert job["status"] == "ok" and world.servers["1.2.3.4"].vpn_panels.get("xui_classic")
    assert "http://1.2.3.4:2053/" in job["log"]
    assert client.post("/api/servers", json={"name": "X", "role": "iran", "host": "5.6.7.8", "auth_type": "password", "password": "x"}, headers=auth).status_code == 409


def test_direct_dnstt_icmp_on_kharej_only(client, auth, world):
    iran, kharej = make_servers(client, auth)
    r = client.post("/api/tunnels", json={
        "mode": "dnstt", "direct": True, "kharej_id": kharej["id"],
        "dnstt": {"domain": "t.example.com"},
    }, headers=auth)
    assert r.status_code == 200, r.text
    job = wait_job(client, r.json()["job_id"])
    assert job["status"] == "ok", job["log"] + str(job["steps"])
    t = client.get("/api/tunnels").json()[0]
    assert t["direct"] is True and t["iran_id"] == t["kharej_id"] == kharej["id"]
    assert t["kharej_iface"] and not t["iran_iface"]
    de = world.servers["1.2.3.4"]
    assert any(c.get("Remote_IP") == "1.2.3.4" and c.get("TunnelMode") == "dnstt" for c in de.confs.values())
    assert any("JOJONET_DIRECT=1" in cmd and "jojonet --dnstt 1.2.3.4" in cmd for _, cmd in world.log)
    paired = client.post("/api/tunnels", json={
        "mode": "dnstt", "iran_id": iran["id"], "kharej_id": kharej["id"],
        "dnstt": {"domain": "u.example.com"},
    }, headers=auth)
    assert paired.status_code == 409
    r = client.post("/api/tunnels", json={"mode": "icmp", "direct": True, "kharej_id": kharej["id"]}, headers=auth)
    assert r.status_code == 200, r.text
    job = wait_job(client, r.json()["job_id"])
    assert job["status"] == "ok", job["log"]
    assert any(c.get("TunnelMode") == "icmp" for c in de.confs.values())
    job = wait_job(client, client.request("DELETE", f"/api/tunnels/{t['id']}", json={"force": False}, headers=auth).json()["job_id"])
    assert job["status"] == "ok"


def test_users_on_kharej_swaps_script_role(client, auth, world):
    iran, kharej = make_servers(client, auth)
    r = client.post("/api/tunnels", json={
        "mode": "gre", "iran_id": iran["id"], "kharej_id": kharej["id"], "users": "kharej",
    }, headers=auth)
    assert r.status_code == 200, r.text
    job = wait_job(client, r.json()["job_id"])
    assert job["status"] == "ok", job["log"]
    t = client.get("/api/tunnels").json()[0]
    assert t["users"] == "kharej" and t["status"] == "ok"
    de = [c for h, c in world.log if h == "1.2.3.4"]
    ir = [c for h, c in world.log if h == "5.6.7.8"]
    assert any("JOJONET_ROLE=iran" in c and "jojonet --peer" in c for c in de), de
    assert any("JOJONET_ROLE=kharej" in c and "jojonet --peer" in c for c in ir), ir

