from __future__ import annotations

import base64
import io
import os
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from app import orchestrator as orch
from app.security import Vault, hash_password, verify_password
from app.validators import ip_keydir, split_confs, valid_iface, valid_ipv4, valid_keydir

REPO = Path(__file__).resolve().parents[2]


def test_password_hash_roundtrip():
    h = hash_password("s3cret-password")
    assert h.startswith("scrypt$")
    assert verify_password("s3cret-password", h)
    assert not verify_password("wrong", h)
    assert not verify_password("x", "garbage")
    assert not verify_password("x", "scrypt$1$2$3$!!$!!")


def test_vault_roundtrip(tmp_path):
    v = Vault(tmp_path / "vault.key")
    token = v.encrypt("hello")
    assert token and token != "hello"
    assert v.decrypt(token) == "hello"
    assert v.encrypt("") is None and v.decrypt(None) is None
    assert Vault(tmp_path / "vault.key").decrypt(token) == "hello"
    other = Vault(tmp_path / "other.key")
    with pytest.raises(ValueError):
        other.decrypt(token)


@pytest.mark.parametrize(
    "value,ok",
    [("1.2.3.4", True), ("10.0.0.1", True), ("0.0.0.0", False), ("127.0.0.1", False), ("1.2.3", False),
     ("01.2.3.4", False), ("1.2.3.4 ", False), ("224.0.0.1", False), ("a.b.c.d", False)],
)
def test_valid_ipv4(value, ok):
    assert valid_ipv4(value) is ok


def test_keydir_rules():
    assert valid_keydir("/etc/jojonet/keys/pair_1_2_3_4")
    assert valid_keydir("/etc/jojonet/keys/pair_12")
    assert not valid_keydir("/etc/jojonet/keys/pair_")
    assert not valid_keydir("/etc/jojonet/keys/pair_../x")
    assert not valid_keydir("/etc/jojonet/keys/pair_1_2_3")
    assert not valid_keydir("/tmp/pair_12")
    assert ip_keydir("5.6.7.8") == "/etc/jojonet/keys/pair_5_6_7_8"


def test_iface_rules():
    assert valid_iface("gre1") and valid_iface("hy2_ab.c-1")
    assert not valid_iface("") and not valid_iface("..") and not valid_iface("a" * 16) and not valid_iface("a b")
    assert not valid_iface(None)


def test_parse_and_split_confs():
    text = (
        '==> /etc/jojonet/instances/a.conf <==\nName="a"\nTunnelMode="hysteria2"\nRemote_IP="1.2.3.4"\n'
        'Evil=$(rm -rf /)\nKeyDir="/etc/jojonet/keys/pair_1_2_3_4"\n\n'
        '==> /etc/jojonet/instances/b.conf <==\nName="b"\nRemote_IP="5.6.7.8"\n'
    )
    confs = split_confs(text)
    assert len(confs) == 2
    assert confs[0]["Name"] == "a" and "Evil" not in confs[0]
    assert orch.Orchestrator.find_conf(confs, "5.6.7.8", "gre")["Name"] == "b"
    assert orch.Orchestrator.find_conf(confs, "1.2.3.4", "gre") is None
    assert orch.Orchestrator.find_conf(confs, "1.2.3.4", "hysteria2")["Name"] == "a"
    assert split_confs("no headers here") == []


def test_bundle_version_and_tar():
    assert orch.bundle_version(REPO) == "1.5.9"
    data = orch.build_bundle_tar(REPO)
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        names = tar.getnames()
        assert {"jojonet", "install.sh", "uninstall.sh"} <= set(names)
        assert all("/" not in n and not n.startswith(".") for n in names)
        assert tar.getmember("jojonet").mode == 0o755


def test_wg_keypair_matches():
    priv_b64, pub_b64 = orch.wg_keypair()
    priv = X25519PrivateKey.from_private_bytes(base64.b64decode(priv_b64))
    from cryptography.hazmat.primitives import serialization

    derived = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    assert base64.b64decode(pub_b64) == derived
    assert len(priv_b64) == 44 and len(pub_b64) == 44


def test_wg_keys_match_rules():
    a_priv, a_pub = orch.wg_keypair()
    b_priv, b_pub = orch.wg_keypair()
    a = {"wg_private.key": a_priv, "wg_public.key": a_pub, "wg_peer_public.key": b_pub}
    b = {"wg_private.key": b_priv, "wg_public.key": b_pub, "wg_peer_public.key": a_pub}
    assert orch.wg_keys_match(a, b) and orch.wg_keys_match(b, a)
    assert not orch.wg_keys_match(a, {**b, "wg_peer_public.key": b_pub})  # placeholder: own key as peer
    assert not orch.wg_keys_match({**a, "wg_public.key": b_pub}, b)  # public key not derived from private
    assert not orch.wg_keys_match(a, {})
    assert not orch.wg_keys_match({**a, "wg_private.key": "not-base64!"}, b)
    assert not orch.wg_keys_match({**a, "wg_private.key": base64.b64encode(b"short").decode()}, b)
    assert orch.wg_pub_of(a_priv) == a_pub


def test_conf_mode_distinguishes_wireguard_variants():
    from app.validators import conf_mode

    assert conf_mode({"TunnelMode": "wireguard"}) == "wireguard"
    assert conf_mode({"TunnelMode": "wireguard", "WgObfs": "icmp"}) == "wg_icmp"
    assert conf_mode({"TunnelMode": "wireguard", "WgObfs": "faketcp"}) == "wg_faketcp"
    assert conf_mode({"TunnelMode": "wireguard", "WgObfs": "weird"}) == "wg_weird"
    assert conf_mode({}) == "gre" and conf_mode({"TunnelMode": "hysteria2", "WgObfs": "icmp"}) == "hysteria2"
    confs = [
        {"Name": "wg1", "TunnelMode": "wireguard", "Remote_IP": "1.2.3.4"},
        {"Name": "wi1", "TunnelMode": "wireguard", "WgObfs": "icmp", "Remote_IP": "1.2.3.4"},
    ]
    assert orch.Orchestrator.find_conf(confs, "1.2.3.4", "wireguard")["Name"] == "wg1"
    assert orch.Orchestrator.find_conf(confs, "1.2.3.4", "wg_icmp")["Name"] == "wi1"
    assert orch.Orchestrator.find_conf(confs, "1.2.3.4", "wg_faketcp") is None


def test_spoof_tester_scripts():
    assert orch.spoof_test_proto("tcp") == "tcp"
    assert orch.spoof_test_proto("udp") == orch.spoof_test_proto("icmpv6") == "icmp"
    recv = orch.spoof_receiver_script("5.160.0.1", "tcp", 9000)
    assert "--mode receiver --protocol tcp" in recv and "--dst-port 9000" in recv
    assert "printf '%s\\n' 5.160.0.1 >" in recv and 'TMPDIR="$d"' in recv and "trap cleanup EXIT" in recv
    assert "iptables -w -I INPUT 1 -s 5.160.0.1 -p tcp --dport 9000 -m comment --comment jojonet-spoof-test -j ACCEPT" in recv
    assert "iptables -w -D INPUT -s 5.160.0.1 -p tcp --dport 9000 -m comment --comment jojonet-spoof-test -j ACCEPT" in recv
    assert "ufw" not in recv
    icmp = orch.spoof_receiver_script("5.160.0.1", "icmp", 9000)
    assert "-s 5.160.0.1 -p icmp -m comment" in icmp and "--dport" not in icmp
    send = orch.spoof_sender_script("5.160.0.1", "1.2.3.4", "icmp", 9001)
    assert "--mode sender --protocol icmp" in send and "--dst-ip 1.2.3.4" in send
    assert send.count("for round in 1 2") == 1 and f"--packet-count {orch.SPOOF_TEST_PACKETS // 2}" in send


@pytest.mark.skipif(shutil.which("node") is None, reason="node not available")
def test_frontend_script_parses():
    """A syntax error (e.g. a duplicate const) stops the whole UI at the loading screen."""
    app_js = Path(__file__).resolve().parents[1] / "static" / "app.js"
    res = subprocess.run(["node", "--check", str(app_js)], capture_output=True, text=True)
    assert res.returncode == 0, res.stderr


def _bash() -> str | None:
    for cand in (r"C:\Program Files\Git\bin\bash.exe", shutil.which("bash")):
        if cand and Path(cand).exists():
            return cand
    return None


@pytest.mark.skipif(_bash() is None, reason="bash not available")
def test_key_scripts_in_real_bash(tmp_path):
    """Run the exact export/install scripts in bash with /etc/jojonet/keys and /tmp redirected to tmp dirs."""
    bash = _bash()
    root = tmp_path.as_posix()
    if len(root) > 1 and root[1] == ":":
        root = "/" + root[0].lower() + root[2:]
    keys = f"{root}/keys"
    tmp = f"{root}/tmp"
    (tmp_path / "tmp").mkdir()
    src = tmp_path / "keys" / "pair_42"
    src.mkdir(parents=True)
    (src / "private_key.pem").write_text("PRIV\n")
    (src / "public_key.pem").write_text("PUB\n")
    (src / "evil.sh").write_text("bad\n")
    (src / "paqet.secret").write_text("")

    def fix(script: str) -> str:
        script = script.replace("/etc/jojonet/keys", keys).replace("/tmp/", tmp + "/")
        if os.name == "nt":  # Git Bash cannot chmod under Windows ACLs
            script = script.replace("install -d -m700", "mkdir -p").replace("install -m600", "cp")
        return script

    exp = subprocess.run([bash, "-c", fix(orch.export_keys_script("/etc/jojonet/keys/pair_42"))], capture_output=True)
    assert exp.returncode == 0, exp.stderr
    blob = base64.b64decode(exp.stdout.strip())
    with tarfile.open(fileobj=io.BytesIO(blob)) as tar:
        assert sorted(tar.getnames()) == ["private_key.pem", "public_key.pem"]

    def archive(entries) -> bytes:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            for name, content in entries:
                info = tarfile.TarInfo(name)
                info.size = len(content)
                tar.addfile(info, io.BytesIO(content))
        return buf.getvalue()

    script = fix(orch.install_keys_script("/etc/jojonet/keys/pair_1_2_3_4", orch.SHARED_KEY_FILES))
    dst = tmp_path / "keys" / "pair_1_2_3_4"
    # Traversal entries make tar reject the whole archive.
    bad = subprocess.run([bash, "-c", script], input=archive([("hy2.auth", b"abc\n"), ("../escape", b"x")]), capture_output=True)
    assert bad.returncode != 0
    assert not (tmp_path / "keys" / "escape").exists() and not (tmp_path / "escape").exists()
    # Non-whitelisted files are ignored.
    imp = subprocess.run([bash, "-c", script], input=archive([("hy2.auth", b"abc\n"), ("evil.sh", b"x")]), capture_output=True)
    assert imp.returncode == 0, (imp.stdout, imp.stderr)
    assert (dst / "hy2.auth").read_text() == "abc\n"
    assert not (dst / "evil.sh").exists()
    assert b"installed=1" in imp.stdout

    imp2 = subprocess.run([bash, "-c", fix(orch.install_keys_script("/etc/jojonet/keys/pair_9", ("hy2.auth",)))],
                          input=blob, capture_output=True)
    assert imp2.returncode != 0
    assert list((tmp_path / "tmp").iterdir()) == []
