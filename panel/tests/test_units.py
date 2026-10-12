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


def test_secret_panel_path(tmp_path):
    from app.config import DEFAULT_BASE_PATH, normalize_base_path, resolve_base_path, write_listen

    assert normalize_base_path("jnsecretpath1234") == "/jnsecretpath1234"
    assert normalize_base_path("jojonet-panel-entry") == DEFAULT_BASE_PATH
    for bad in ("/", "/short", "/has/extra-segment-here", "/../jnsecretpath1234", ""):
        with pytest.raises(ValueError):
            normalize_base_path(bad)
    assert resolve_base_path(tmp_path, "") == DEFAULT_BASE_PATH
    assert resolve_base_path(tmp_path, "") == DEFAULT_BASE_PATH
    # An old random hex path is replaced. A saved web.path is kept over the env value.
    fresh = tmp_path / "fresh"
    assert resolve_base_path(fresh, "/0123456789abcdef01234567") == DEFAULT_BASE_PATH
    chosen = tmp_path / "chosen"
    chosen.mkdir()
    (chosen / "web.path").write_text("/custompath1234567\n", encoding="utf-8")
    assert resolve_base_path(chosen, "/jnsecretpath1234") == "/custompath1234567"
    write_listen(tmp_path, "jojonet-panel-entry", 2053)
    assert (tmp_path / "listen.json").read_text(encoding="utf-8").strip() == '{"path":"/jojonet-panel-entry","port":2053}'
    from app.config import saved_listen_port
    assert saved_listen_port(tmp_path) == 2053
    write_listen(tmp_path, "jojonet-panel-entry", 80)
    assert saved_listen_port(tmp_path) == 80


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


def test_sshclient_histfile_wrap():
    from app.sshclient import _SCRUB_HISTORY, _SHELL_CMD, _already_hist_wrapped, _bash_c

    cmd = _bash_c("id -u")
    assert "HISTFILE=/dev/null" in cmd
    assert "bash --noprofile --norc" in cmd
    assert _already_hist_wrapped(cmd)
    sudo = _bash_c("id -u", via_sudo=True)
    assert sudo.startswith("env HISTFILE=/dev/null")
    assert _already_hist_wrapped(sudo)
    assert "gre6" in _SCRUB_HISTORY and "ipip6" in _SCRUB_HISTORY and "vxlan" in _SCRUB_HISTORY
    assert "HISTFILE=/dev/null" in _SHELL_CMD


@pytest.mark.parametrize(
    "value,ok",
    [("1.2.3.4", True), ("10.0.0.1", True), ("0.0.0.0", False), ("127.0.0.1", False), ("1.2.3", False),
     ("01.2.3.4", False), ("1.2.3.4 ", False), ("224.0.0.1", False), ("a.b.c.d", False)],
)
def test_valid_ipv4(value, ok):
    assert valid_ipv4(value) is ok


def test_valid_dnstt_fields():
    from app.validators import valid_dnstt_domain, valid_dnstt_resolver

    assert valid_dnstt_domain("t.example.com")
    assert not valid_dnstt_domain("localhost") and not valid_dnstt_domain("a.b")
    assert valid_dnstt_resolver("doh", "https://cloudflare-dns.com/dns-query")
    assert not valid_dnstt_resolver("doh", "http://cloudflare-dns.com/dns-query")
    assert valid_dnstt_resolver("dot", "1.1.1.1:853") and valid_dnstt_resolver("udp", "1.1.1.1:53")
    assert not valid_dnstt_resolver("udp", "example.com")


def test_valid_ipv6_and_xray_ports():
    from app.validators import valid_ipv6, valid_xray_ports, valid_relay_name, valid_relay_target

    assert valid_ipv6("fd6a:aaaa:bbbb::1")
    assert not valid_ipv6("::1") and not valid_ipv6("::") and not valid_ipv6("ff02::1")
    assert valid_xray_ports("443") and valid_xray_ports("8443:443,2053")
    assert not valid_xray_ports("0") and not valid_xray_ports("8443:443,8443:80") and not valid_xray_ports("1:2:3")
    assert valid_relay_name("web") and not valid_relay_name("Web") and not valid_relay_name("-bad")
    assert valid_relay_target("1.2.3.4") and valid_relay_target("example.com")
    assert not valid_relay_target("example.com", ipv4_only=True) and not valid_relay_target("no_dot")


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


def test_parse_live_tunnels_json():
    raw = """
some banner
[
  {"name":"dt12","mode":"dnstt","role":"kharej","local_ip":"1.2.3.4","remote_ip":"5.6.7.8","status":"UP","boot":true,"unit":"jojonet-stream@dt12.service"},
  {"name":"bad name","mode":"gre","role":"iran","local_ip":"","remote_ip":"","status":"DOWN","boot":false,"unit":"x"},
  {"name":"gre9","mode":"gre","role":"iran","local_ip":"10.0.0.1","remote_ip":"10.0.0.2","status":"DOWN","boot":"enabled","unit":"jojonet@gre9.service"}
]
"""
    items = orch.parse_live_tunnels(raw)
    assert len(items) == 2
    assert items[0]["name"] == "dt12" and items[0]["boot"] is True and items[0]["mode"] == "dnstt"
    assert items[1]["name"] == "gre9" and items[1]["boot"] is True
    assert orch.parse_live_tunnels("") == []
    assert orch.parse_live_tunnels("not json") == []


def test_bundle_version_and_tar():
    assert orch.bundle_version(REPO) == "1.6.0"
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


def test_parse_vpn_creds():
    raw = (
        "[سرور خارج] other noise\n"
        "[سرور خارج] ===== JOJONET_VPN_CREDS =====\n"
        "[سرور خارج] kind=xui\n"
        "[سرور خارج] label=3x-ui سنایی\n"
        "[سرور خارج] url=http://1.2.3.4:2053/\n"
        "[سرور خارج] username=admin\n"
        "[سرور خارج] password=Secret99\n"
        "[سرور خارج] ===== END_JOJONET_VPN_CREDS =====\n"
    )
    creds = orch.parse_vpn_creds(raw)
    assert creds["url"] == "http://1.2.3.4:2053/"
    assert creds["username"] == "admin"
    assert creds["password"] == "Secret99"
    assert creds["label"] == "3x-ui سنایی"
    assert orch.parse_vpn_creds("no creds here") == {}


def test_parse_vpn_check_and_already():
    raw = (
        "[srv] ===== JOJONET_VPN_CHECK =====\n"
        "[srv] xui=1\n"
        "[srv] xui_flavor=sanaei\n"
        "[srv] xui_running=1\n"
        "[srv] pasarguard=0\n"
        "[srv] pasarguard_running=0\n"
        "[srv] ===== END_JOJONET_VPN_CHECK =====\n"
    )
    info = orch.parse_vpn_check(raw)
    assert info["xui"] == "1" and info["xui_flavor"] == "sanaei"
    assert orch.vpn_panel_already("xui", info)
    assert not orch.vpn_panel_already("pasarguard", info)
    assert orch.vpn_panel_conflict("xui_classic", info)
    assert not orch.vpn_panel_conflict("xui", info)
    unknown = dict(info, xui_flavor="unknown")
    assert orch.vpn_panel_already("xui", unknown)
    assert not orch.vpn_panel_already("xui_classic", unknown)
    classic = dict(info, xui_flavor="classic")
    assert orch.vpn_panel_already("xui_classic", classic)
    assert orch.vpn_panel_conflict("xui", classic)


def test_systemd_socket_requires_this_process(monkeypatch):
    from app.cli import systemd_listen_socket

    monkeypatch.delenv("LISTEN_PID", raising=False)
    monkeypatch.delenv("LISTEN_FDS", raising=False)
    assert systemd_listen_socket() is None
    monkeypatch.setenv("LISTEN_PID", "1")
    monkeypatch.setenv("LISTEN_FDS", "1")
    assert systemd_listen_socket() is None


def test_installer_socket_activation_and_rollback():
    text = (REPO / "panel" / "install-panel.sh").read_text(encoding="utf-8")
    assert "ListenStream=" in text
    assert "jojonet-panel.socket" in text
    assert "panel_answers" in text
    assert "restore_runtime" in text
    assert "NoNewPrivileges=yes" in text
    assert "AmbientCapabilities" not in text
    apply = (REPO / "panel" / "apply-listen").read_text(encoding="utf-8")
    assert "jojonet-panel.socket" in apply
    assert "1 <= port <= 65535" in apply
    assert "jojonet-panel-ssl.path" in text
    assert "apply-ssl" in text
    assert "without closing the port" in text
    assert "socket_listen_now" in text
    assert "ensure_http_redirect" in text
    assert "http-redirect.py" in text
    ssl = (REPO / "panel" / "apply-ssl").read_text(encoding="utf-8")
    assert "certbot certonly" in ssl
    assert "flock -n 9" in ssl
    assert "jojonet-panel-http.service" in ssl
    redirect = (REPO / "panel" / "http-redirect.py").read_text(encoding="utf-8")
    assert "Moved permanently" in redirect and "JOJONET_PANEL_DOMAIN" in redirect


def test_server_ssl_script_and_parser():
    from app.orchestrator import normalize_ssl_not_after, parse_server_ssl, server_ssl_script

    script = server_ssl_script("vpn.example.com", "ops@example.com", "203.0.113.10")
    assert "vpn.example.com" in script
    assert "203.0.113.10" in script
    assert "certbot certonly --standalone" in script
    assert "/etc/jojonet/ssl/" in script
    parsed = parse_server_ssl(
        "noise\n===== JOJONET_SERVER_SSL =====\n"
        "ok=1\ndomain=vpn.example.com\nissuer=Let's Encrypt\n"
        "not_after=Jan 10 20:57:17 2027 GMT\n"
        "cert=/etc/jojonet/ssl/vpn.example.com/fullchain.pem\n"
        "key=/etc/jojonet/ssl/vpn.example.com/privkey.pem\n"
        "===== END_JOJONET_SERVER_SSL =====\n"
    )
    assert parsed["ok"] == "1" and parsed["domain"] == "vpn.example.com"
    assert normalize_ssl_not_after(parsed["not_after"]).startswith("2027-01-10T20:57:17")


def test_ssl_domain_view_and_certificate(tmp_path):
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    from app.tlsinfo import build_ssl_view, https_url, normalize_domain, normalize_email, write_ssl_request

    assert normalize_domain(" HTTPS://Panel.Example.com/path ") == "panel.example.com"
    for bad in ("1.2.3.4", "localhost", "not a domain", "panel"):
        try:
            normalize_domain(bad)
        except ValueError:
            pass
        else:
            raise AssertionError(bad)
    assert normalize_email("") == ""
    assert normalize_email("owner@example.com") == "owner@example.com"
    assert https_url("panel.example.com", "/jojonet-panel-entry", 443) == "https://panel.example.com/jojonet-panel-entry/"
    assert https_url("panel.example.com", "/jojonet-panel-entry", 2053).endswith(":2053/jojonet-panel-entry/")

    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "panel.example.com")])
    issuer = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Let's Encrypt")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("panel.example.com")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "cert.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    view = build_ssl_view(tmp_path, str(cert_path), "/jojonet-panel-entry", 443)
    assert view["state"] == "ok"
    assert view["url"] == "https://panel.example.com/jojonet-panel-entry/"
    assert view["issuer"] == "Let's Encrypt"
    assert view["self_signed"] is False

    data = tmp_path / "data"
    body = write_ssl_request(data, "panel.example.com", "", "/jojonet-panel-entry", 443)
    running = build_ssl_view(data, "", "/jojonet-panel-entry", 443)
    assert running["state"] == "running" and running["domain"] == "panel.example.com"
    assert body["domain"] == "panel.example.com"
    assert (data / "ssl.request").is_file()


def test_guide_sanitize_and_store(tmp_path):
    from app.guide import delete_guide_article, guide_public_view, sanitize_html, write_guide_article

    clean = sanitize_html('<b style="font-size: 18px; font-family: Vazirmatn">سلام</b><script>x</script>', 200)
    assert "<b" in clean and "18px" in clean and "script" not in clean.lower()
    stripped = sanitize_html('<span style="color: red; font-size: 16px">x</span>', 200)
    assert "red" not in stripped and "16px" in stripped
    item = write_guide_article(tmp_path, {
        "id": "gre",
        "group": "تانل‌ها",
        "title": "GRE",
        "lead": 'متن <span style="font-size: 16px; font-family: Tahoma">ویژه</span>',
        "note": "",
        "steps": [{"h": "یک", "p": "دو"}],
        "style": {"fontFamily": "Tahoma", "fontSize": "16px", "titleSize": "20px"},
    })
    assert item["style"]["fontFamily"] == "Tahoma"
    view = guide_public_view(tmp_path)
    assert view["articles"]["gre"]["title"] == "GRE"
    assert delete_guide_article(tmp_path, "gre") is True
    assert guide_public_view(tmp_path)["articles"] == {}


def test_checksums_match_lf_sources():
    import hashlib

    binary = {".woff2", ".pdf", ".zip", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico"}
    raw = (REPO / "checksums.sha256").read_text(encoding="utf-8")
    for line in raw.splitlines():
        if not line.strip():
            continue
        digest, rel = line.split("  ", 1)
        data = (REPO / rel).read_bytes()
        if Path(rel).suffix.lower() not in binary:
            data = data.replace(b"\r\n", b"\n")
        got = hashlib.sha256(data).hexdigest()
        assert got == digest, rel
