from __future__ import annotations

import asyncio
import base64
import io
import json
import re
import secrets
import shlex
import tarfile
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .config import Settings
from .db import Database, utcnow
from .jobs import Job, JobManager, StepFailed
from .security import Vault
from .sshclient import RemoteSession, ServerCreds, fingerprint
from .validators import (
    DNSTT_MODES,
    IP_KEYDIR_MODES,
    MODES,
    RELAY_ENGINES,
    SHARED_KEY_FILES,
    STREAM_MODES,
    SPOOF_MARK,
    SPOOF_UNIT,
    SUBNET_KEYDIR_MODES,
    V6_MODES,
    WG_MODES,
    WG_OBFS,
    XRAY_MODES,
    conf_mode,
    ip_keydir,
    split_confs,
    valid_dnstt_domain,
    valid_dnstt_resolver,
    valid_iface,
    valid_ipv4,
    valid_ipv6,
    valid_keydir,
    valid_relay_name,
    valid_xray_ports,
)

RETRY_DELAY = 5.0
BUNDLE_FILES = ("jojonet", "install.sh", "uninstall.sh", "checksums.sha256", "CHANGELOG.md", "README.md", "LICENSE")
VERSION_RE = re.compile(r'^readonly JOJONET_VERSION="([0-9A-Za-z.\-]+)"', re.MULTILINE)

PREREQ_SCRIPT = r"""
set -u
export DEBIAN_FRONTEND=noninteractive
command -v systemctl >/dev/null 2>&1 || { echo "systemd is required"; exit 4; }
apt_ok=1
if command -v apt-get >/dev/null 2>&1; then
    apt-get -o DPkg::Lock::Timeout=180 update -qq || echo "apt update had errors (continuing)"
    apt-get -o DPkg::Lock::Timeout=180 install -y -qq --no-install-recommends \
        curl ca-certificates iproute2 nftables iptables openssl procps iputils-ping util-linux tar gzip unzip coreutils kmod \
        || { echo "apt install failed (will accept if core tools already present)"; apt_ok=0; }
elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
    pm=$(command -v dnf || command -v yum)
    "$pm" install -y -q curl ca-certificates iproute nftables iptables openssl procps-ng iputils util-linux tar gzip unzip coreutils kmod \
        || { echo "$pm install failed (will accept if core tools already present)"; apt_ok=0; }
else
    echo "unsupported package manager (need apt, dnf or yum)"; exit 3
fi
# Core tools required to upload/run jojonet; unzip is preferred but may be installed later by ENSURE_TOOLS.
missing=""
for c in ip nft ping openssl tar curl; do command -v "$c" >/dev/null 2>&1 || missing="$missing $c"; done
missing=${missing# }
if [ -n "$missing" ]; then
  echo "missing after install:$missing"
  exit 6
fi
if [ "$apt_ok" != "1" ]; then
  echo "prerequisites OK (partial apt; core tools present)"
else
  echo "prerequisites OK"
fi
"""

# Lightweight: always run before deploy even when jojonet version already matches.
ENSURE_TOOLS_SCRIPT = r"""
set -u
export DEBIAN_FRONTEND=noninteractive
need=""
for c in unzip tar curl; do command -v "$c" >/dev/null 2>&1 || need="$need $c"; done
need=${need# }
if [ -n "$need" ]; then
  if command -v apt-get >/dev/null 2>&1; then
    apt-get -o DPkg::Lock::Timeout=120 install -y -qq --no-install-recommends $need \
      || { apt-get -o DPkg::Lock::Timeout=120 update -qq; apt-get -o DPkg::Lock::Timeout=120 install -y -qq --no-install-recommends $need; }
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y -q $need
  elif command -v yum >/dev/null 2>&1; then
    yum install -y -q $need
  else
    echo "unsupported package manager"; exit 3
  fi
fi
for c in unzip tar curl; do command -v "$c" >/dev/null 2>&1 || { echo "missing tool: $c"; exit 7; }; done
echo "tools_ok"
"""

SYSINFO_SCRIPT = r"""
. /etc/os-release 2>/dev/null; echo "os=${PRETTY_NAME:-unknown}"
echo "kernel=$(uname -r)"
echo "arch=$(uname -m)"
echo "src=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "src") { print $(i + 1); exit }}')"
echo "jojonet=$(command -v jojonet >/dev/null 2>&1 && jojonet --version 2>/dev/null | head -n1 | awk '{print $NF}')"
echo "systemd=$(command -v systemctl >/dev/null 2>&1 && echo yes || echo no)"
echo "unzip=$(command -v unzip >/dev/null 2>&1 && echo yes || echo no)"
"""

DUMP_CONFS = 'for f in /etc/jojonet/instances/*.conf; do [ -f "$f" ] || continue; echo "==> $f <=="; cat "$f"; echo; done'
LIST_TUNNELS_JSON = "jojonet --list-tunnels --json </dev/null"
ENABLE_BOOT_CMD = "jojonet --enable-boot </dev/null"

SPOOF_CONFIG = "/etc/jojonet/spoof/config.json"
SPOOF_STATE = (
    f"echo \"state=$(systemctl is-active {SPOOF_UNIT} 2>/dev/null)\"; "
    f"[ -s {SPOOF_CONFIG} ] && sed -n "
    "-e 's/^ *\"mode\": \"\\([a-z]*\\)\",*$/mode=\\1/p' "
    "-e 's/^ *\"\\(remote\\|client_ip\\)\": \"\\([0-9.]*\\)\",*$/peer=\\2/p' "
    f"{SPOOF_CONFIG}; "
    "echo \"py=$(command -v python3 >/dev/null 2>&1 && echo yes || echo no)\""
)
SPOOF_REMOVE = (
    "if command -v jojonet >/dev/null 2>&1 && grep -q -- '--spoof-remove' \"$(command -v jojonet)\"; then "
    "jojonet --spoof-remove </dev/null; else "
    f"systemctl disable --now {SPOOF_UNIT} >/dev/null 2>&1; "
    f"rm -f /etc/systemd/system/{SPOOF_UNIT} {SPOOF_CONFIG}; systemctl daemon-reload; fi"
)

# UDP echo probe through the spoof pipe: Kharej answers on the forward target, Iran sends to its listen port.
PROBE_ECHO = r"""
import socket, sys, time
host, port, nonce, dur = sys.argv[1], int(sys.argv[2]), sys.argv[3].encode(), float(sys.argv[4])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    s.bind((host, port))
except OSError as e:
    print("bind_error", e, flush=True)
    sys.exit(3)
s.settimeout(0.5)
print("ready", flush=True)
end, got = time.time() + dur, 0
while time.time() < end:
    try:
        data, addr = s.recvfrom(2048)
    except socket.timeout:
        continue
    if data == nonce:
        got += 1
        s.sendto(b"ACK:" + nonce, addr)
        end = min(end, time.time() + 3)
print("received", got, flush=True)
"""
PROBE_SEND = r"""
import socket, sys, time
host, port, nonce, dur = sys.argv[1], int(sys.argv[2]), sys.argv[3].encode(), float(sys.argv[4])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(0.5)
end, sent = time.time() + dur, 0
while time.time() < end:
    s.sendto(nonce, (host, port))
    sent += 1
    try:
        data, _ = s.recvfrom(2048)
    except socket.timeout:
        continue
    if data == b"ACK:" + nonce:
        print("ack", sent, flush=True)
        sys.exit(0)
print("noack", sent, flush=True)
sys.exit(1)
"""


SPOOF_BIN = "/usr/local/bin/spoof"
SPOOF_TEST_PACKETS = 20
SPOOF_TEST_TIMEOUT = 12


def spoof_test_proto(transport: str) -> str:
    # The upstream tester speaks only tcp and icmp; source filtering by the provider is protocol-independent.
    return "tcp" if transport == "tcp" else "icmp"


def spoof_receiver_script(src_ip: str, proto: str, port: int) -> str:
    """Receive spoofed test packets; raw sockets see them only after INPUT, so a temporary rule lets them in."""
    q_src = shlex.quote(src_ip)
    match = f"-p tcp --dport {port}" if proto == "tcp" else "-p icmp"
    return f"""
set -u
d=$(mktemp -d /tmp/jnspoof.XXXXXX) || exit 3
printf '%s\\n' {q_src} > "$d/src.txt"
rule=""
if command -v iptables >/dev/null 2>&1; then
    iptables -w -I INPUT 1 -s {q_src} {match} -m comment --comment jojonet-spoof-test -j ACCEPT >/dev/null 2>&1 && rule=1
fi
cleanup() {{
    rm -rf "$d"
    if [ -n "$rule" ]; then iptables -w -D INPUT -s {q_src} {match} -m comment --comment jojonet-spoof-test -j ACCEPT >/dev/null 2>&1 || true; fi
}}
trap cleanup EXIT
cd "$d" || exit 3
TMPDIR="$d" timeout {SPOOF_TEST_TIMEOUT + 30} {SPOOF_BIN} tester --mode receiver --protocol {proto} \\
    --src-list "$d/src.txt" --dst-port {port} --timeout {SPOOF_TEST_TIMEOUT} \\
    --packet-count {SPOOF_TEST_PACKETS} --max-loss 80 2>&1
"""


def spoof_sender_script(src_ip: str, dst_ip: str, proto: str, port: int) -> str:
    q_src = shlex.quote(src_ip)
    return f"""
set -u
f=$(mktemp /tmp/jnspoof.XXXXXX) || exit 3
trap 'rm -f "$f"' EXIT
printf '%s\\n' {q_src} > "$f"
rc=0
for round in 1 2; do
    timeout 30 {SPOOF_BIN} tester --mode sender --protocol {proto} --src-list "$f" \\
        --dst-ip {shlex.quote(dst_ip)} --dst-port {port} --packet-count {SPOOF_TEST_PACKETS // 2} 2>&1 || rc=$?
    sleep 2
done
exit $rc
"""


def spoof_env(opts: dict[str, Any], role: str) -> str:
    own, peer = (opts["iran_spoof_ip"], opts["kharej_spoof_ip"]) if role == "iran" else (opts["kharej_spoof_ip"], opts["iran_spoof_ip"])
    listen = f"{'0.0.0.0' if opts.get('listen_public', True) else '127.0.0.1'}:{int(opts['listen_port'])}"
    env = {
        "JOJONET_SPOOF_IP": own,
        "JOJONET_SPOOF_PEER_IP": peer,
        "JOJONET_SPOOF_LISTEN": listen,
        "JOJONET_SPOOF_FORWARD": opts["forward"],
        "JOJONET_SPOOF_REMOTE_PORT": str(int(opts["up_port"])),
        "JOJONET_SPOOF_RECV_PORT": str(int(opts["down_port"])),
        "JOJONET_SPOOF_UP_TRANSPORT": opts["up_transport"],
        "JOJONET_SPOOF_DOWN_TRANSPORT": opts["down_transport"],
        "JOJONET_SPOOF_PORT": str(int(opts["spoof_port"])),
    }
    return " ".join(f"{k}={shlex.quote(v)}" for k, v in env.items())


def xray_env(opts: dict[str, Any] | None) -> str:
    if not opts:
        return ""
    parts: list[str] = []
    net = str(opts.get("net") or "tcp").lower()
    if net in ("tcp", "ws", "grpc"):
        parts.append(f"JOJONET_XRAY_NET={shlex.quote(net)}")
    ctrl = opts.get("ctrl_port")
    if ctrl:
        parts.append(f"JOJONET_XRAY_CTRL_PORT={int(ctrl)}")
    ports = str(opts.get("ports") or "").replace(" ", "")
    if ports and valid_xray_ports(ports):
        parts.append(f"JOJONET_FWD_PORTS={shlex.quote(ports)}")
    return (" " + " ".join(parts)) if parts else ""


def dnstt_env(opts: dict[str, Any] | None) -> str:
    if not opts:
        return ""
    parts: list[str] = []
    domain = str(opts.get("domain") or "").strip().lower().rstrip(".")
    if valid_dnstt_domain(domain):
        parts.append(f"JOJONET_DNSTT_DOMAIN={shlex.quote(domain)}")
    mode = str(opts.get("resolver_mode") or "doh").strip().lower()
    if mode in DNSTT_MODES:
        parts.append(f"JOJONET_DNSTT_MODE={shlex.quote(mode)}")
    resolver = str(opts.get("resolver") or "").strip()
    if resolver and valid_dnstt_resolver(mode, resolver):
        parts.append(f"JOJONET_DNSTT_RESOLVER={shlex.quote(resolver)}")
    dns_port = opts.get("dns_port")
    if dns_port:
        parts.append(f"JOJONET_DNSTT_DNS_PORT={int(dns_port)}")
    ports = str(opts.get("ports") or "").replace(" ", "")
    if ports and valid_xray_ports(ports):
        parts.append(f"JOJONET_FWD_PORTS={shlex.quote(ports)}")
    return (" " + " ".join(parts)) if parts else ""


def icmp_env(opts: dict[str, Any] | None) -> str:
    if not opts:
        return ""
    ports = str(opts.get("ports") or "").replace(" ", "")
    if ports and valid_xray_ports(ports):
        return f" JOJONET_FWD_PORTS={shlex.quote(ports)}"
    return ""


def mode_env(mode: str, opts: dict[str, Any] | None) -> str:
    extra = ""
    if mode in XRAY_MODES:
        extra = xray_env(opts)
    elif mode == "dnstt":
        extra = dnstt_env(opts)
    elif mode == "icmp":
        extra = icmp_env(opts)
    if opts and opts.get("direct"):
        extra += " JOJONET_DIRECT=1"
    return extra


def is_direct_tunnel(t: dict[str, Any]) -> bool:
    opts = t.get("options") or {}
    if opts.get("direct"):
        return True
    return t.get("iran_id") == t.get("kharej_id")


def tunnel_users(t: dict[str, Any]) -> str:
    if is_direct_tunnel(t):
        return "kharej"
    u = (t.get("options") or {}).get("users")
    return u if u in ("iran", "kharej") else "iran"


def script_role(geo_role: str, mode: str, users: str) -> str:
    """JOJONET_ROLE for a geographically iran/kharej server.

    When users connect on Kharej, the script's iran role (listen / DNAT) is
    placed on the foreign VPS so traffic goes Kharej → Iran. DNSTT/ICMP and
    Spoof keep geographic roles (server/NS and Spoof listen stay on Iran/Kharej as designed).
    """
    if users != "kharej" or mode in STREAM_MODES or mode == "spoof":
        return geo_role
    return "iran" if geo_role == "kharej" else "kharej"


def bundle_version(bundle_dir: Path) -> str | None:
    try:
        m = VERSION_RE.search((bundle_dir / "jojonet").read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return None
    return m.group(1) if m else None


def build_bundle_tar(bundle_dir: Path) -> bytes:
    if not (bundle_dir / "jojonet").is_file() or not (bundle_dir / "install.sh").is_file():
        raise StepFailed(f"فایل‌های اسکریپت jojonet در {bundle_dir} پیدا نشد")
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name in BUNDLE_FILES:
            path = bundle_dir / name
            if not path.is_file():
                continue
            data = path.read_bytes()
            if name.endswith(".sh") or name == "jojonet":
                if b"\r" in data:
                    raise StepFailed(f"فایل {name} دارای CRLF است؛ بسته خراب است")
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o755 if name.endswith(".sh") or name == "jojonet" else 0o644
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def wg_keypair() -> tuple[str, str]:
    priv = X25519PrivateKey.generate()
    priv_raw = priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    pub_raw = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(priv_raw).decode(), base64.b64encode(pub_raw).decode()


WG_KEY_FILES = ("wg_private.key", "wg_public.key", "wg_peer_public.key", "udp2raw.key")
UDP2RAW_KEY_RE = re.compile(r"^[A-Za-z0-9]{16,128}$")


def wg_pub_of(priv_b64: str) -> str | None:
    try:
        raw = base64.b64decode(priv_b64, validate=True)
        if len(raw) != 32:
            return None
        pub = X25519PrivateKey.from_private_bytes(raw).public_key()
    except ValueError:
        return None
    return base64.b64encode(pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()


def wg_keys_match(a: dict[str, str], b: dict[str, str]) -> bool:
    """Both sides hold real keypairs and each side's peer key is the other's public key."""
    pa, pb = wg_pub_of(a.get("wg_private.key", "")), wg_pub_of(b.get("wg_private.key", ""))
    return (
        pa is not None and pb is not None and pa != pb
        and a.get("wg_public.key") == pa and b.get("wg_public.key") == pb
        and a.get("wg_peer_public.key") == pb and b.get("wg_peer_public.key") == pa
    )


def read_keys_script(keydir: str, names: tuple[str, ...]) -> str:
    allowed = " ".join(shlex.quote(n) for n in names)
    return (
        f"cd {shlex.quote(keydir)} 2>/dev/null || exit 0\n"
        f"for f in {allowed}; do\n"
        '    if [ -f "$f" ] && [ ! -L "$f" ]; then printf \'%s=%s\\n\' "$f" "$(tr -d \'[:space:]\' < "$f")"; fi\n'
        "done\n"
    )


def keyfiles_tar(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, content in files.items():
            data = content.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o600
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def install_keys_script(keydir: str, names: tuple[str, ...]) -> str:
    """Extract a key tarball from stdin into keydir, accepting only whitelisted regular files."""
    allowed = " ".join(shlex.quote(n) for n in names)
    kd = shlex.quote(keydir)
    return f"""
set -e
umask 077
t=$(mktemp -d /tmp/jnkeys.XXXXXX)
trap 'rm -rf "$t"' EXIT
tar -xzf - -C "$t" --no-same-owner --no-same-permissions
install -d -m700 {kd}
n=0
for f in {allowed}; do
    if [ -f "$t/$f" ] && [ ! -L "$t/$f" ] && [ -s "$t/$f" ]; then
        install -m600 "$t/$f" {kd}/"$f"
        n=$((n + 1))
    fi
done
echo "installed=$n"
[ "$n" -gt 0 ]
"""


def export_keys_script(keydir: str) -> str:
    allowed = " ".join(shlex.quote(n) for n in SHARED_KEY_FILES)
    return f"""
cd {shlex.quote(keydir)} || exit 3
files=""
for f in {allowed}; do
    if [ -f "$f" ] && [ ! -L "$f" ] && [ -s "$f" ]; then files="$files $f"; fi
done
[ -n "$files" ] || exit 4
tar -czf - $files | base64 -w0
"""


def parse_kv(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


class Orchestrator:
    def __init__(self, db: Database, vault: Vault, settings: Settings, jobs: JobManager):
        self.db = db
        self.vault = vault
        self.settings = settings
        self.jobs = jobs

    # ---------- servers ----------
    def server(self, server_id: int) -> dict[str, Any]:
        row = self.db.one("SELECT * FROM servers WHERE id=?", (server_id,))
        if row is None:
            raise StepFailed("سرور پیدا نشد (شاید حذف شده است)")
        return row

    def creds(self, row: dict[str, Any]) -> ServerCreds:
        try:
            password = self.vault.decrypt(row["secret_password"])
            key = self.vault.decrypt(row["secret_key"])
            passphrase = self.vault.decrypt(row["secret_passphrase"])
            sudo = self.vault.decrypt(row["secret_sudo"])
        except ValueError as exc:
            raise StepFailed("رمزگشایی اطلاعات سرور ممکن نیست (کلید vault عوض شده است)") from exc
        return ServerCreds(
            host=row["host"],
            port=int(row["port"]),
            username=row["username"],
            password=password if row["auth_type"] == "password" else None,
            private_key=key if row["auth_type"] == "key" else None,
            key_passphrase=passphrase,
            sudo_password=sudo,
            hostkey=row["hostkey"],
            secrets=[s for s in (password, passphrase, sudo) if s],
        )

    async def open(self, job: Job | None, row: dict[str, Any]) -> RemoteSession:
        sess = RemoteSession(self.creds(row), connect_timeout=self.settings.ssh_connect_timeout)
        await sess.connect()
        if not row["hostkey"] and sess.hostkey:
            fp = fingerprint(sess.hostkey)
            self.db.update("servers", row["id"], {"hostkey": sess.hostkey, "hostkey_fingerprint": fp})
            row["hostkey"] = sess.hostkey
            if job is not None:
                await job.log(f"[{row['name']}] کلید هاست ثبت شد: {fp}")
        if job is not None:
            await job.log(f"[{row['name']}] اتصال برقرار شد ({'root' if sess.is_root else 'sudo'})")
        return sess

    def set_check(self, server_id: int, ok: bool, info: str) -> None:
        self.db.update("servers", server_id, {"last_check": {"ok": ok, "at": utcnow(), "info": info[:300]}})

    async def sysinfo(self, sess: RemoteSession) -> dict[str, str]:
        res = await sess.run_root(SYSINFO_SCRIPT, timeout=60)
        return parse_kv(res.stdout)

    async def install_prereqs(self, job: Job, sess: RemoteSession, name: str) -> None:
        res = await sess.run_root(PREREQ_SCRIPT, timeout=900, on_line=lambda l: job.log(f"[{name}] {l}"))
        if not res.ok:
            raise StepFailed(f"نصب پیش‌نیازها روی {name} ناموفق بود (کد {res.rc})")

    async def install_jojonet(self, job: Job, sess: RemoteSession, name: str) -> str:
        data = build_bundle_tar(self.settings.bundle_dir)
        script = (
            'set -e; d=$(mktemp -d /tmp/jnpkg.XXXXXX); trap \'rm -rf "$d"\' EXIT; '
            'tar -xzf - -C "$d" --no-same-owner; cd "$d"; bash install.sh; '
            "jojonet --version"
        )
        res = await sess.run_root(script, input_data=data, timeout=600, on_line=lambda l: job.log(f"[{name}] {l}"))
        if not res.ok:
            raise StepFailed(f"نصب اسکریپت jojonet روی {name} ناموفق بود (کد {res.rc})")
        info = await self.sysinfo(sess)
        return info.get("jojonet", "")

    async def ensure_tools(self, job: Job, sess: RemoteSession, name: str, *, required: bool = True) -> None:
        """Install unzip/tar/curl when missing — even if jojonet is already current."""
        res = await sess.run_root(ENSURE_TOOLS_SCRIPT, timeout=300)
        if res.ok and "tools_ok" in (res.stdout or ""):
            await job.log(f"[{name}] unzip/tar/curl آماده است")
            return
        detail = (res.stderr or res.stdout or "").strip()[:240]
        if required:
            raise StepFailed(f"{name}: ابزارهای لازم نصب نشد ({detail or 'unzip/tar/curl'})")
        await job.log(f"⚠ [{name}] ابزار اختیاری ناقص است ({detail or 'unzip'}) — ادامه با هسته موجود")

    async def ensure_ready(self, job: Job, sess: RemoteSession, row: dict[str, Any]) -> dict[str, str]:
        name = row["name"]
        info = await self.sysinfo(sess)
        if info.get("systemd") != "yes":
            raise StepFailed(f"{name}: systemd پیدا نشد؛ این سرور پشتیبانی نمی‌شود")
        want = bundle_version(self.settings.bundle_dir)
        have = info.get("jojonet", "")
        if have and want and have == want:
            await job.log(f"[{name}] jojonet {have} نصب است")
            await self.ensure_tools(job, sess, name, required=False)
            return info
        await job.log(f"[{name}] نصب پیش‌نیازها و jojonet {want or ''} (فعلی: {have or 'ندارد'})")
        await self.install_prereqs(job, sess, name)
        info["jojonet"] = await self.install_jojonet(job, sess, name)
        if want and info["jojonet"] != want:
            raise StepFailed(f"{name}: نسخه نصب‌شده ({info['jojonet'] or '?'}) با نسخه پنل ({want}) یکی نیست")
        # unzip may be unavailable when apt mirrors/DNS are down; do not block jojonet upgrade.
        await self.ensure_tools(job, sess, name, required=False)
        return info

    # ---------- server jobs ----------
    async def job_test_server(self, job: Job, server_id: int) -> None:
        row = self.server(server_id)
        await job.start(0)
        try:
            async with await self.open(job, row) as sess:
                await job.ok(0)
                await job.start(1)
                info = await self.sysinfo(sess)
                for k in ("os", "kernel", "arch", "src", "jojonet"):
                    await job.log(f"  {k}: {info.get(k) or '-'}")
                if info.get("src") and info["src"] != row["host"]:
                    await job.log(
                        f"⚠ IP خروجی سرور ({info['src']}) با IP ثبت‌شده ({row['host']}) فرق دارد (NAT). "
                        "برای TUN/TCP و Paqet ممکن است subnet دو طرف یکی نشود."
                    )
                await job.ok(1, info.get("os", ""))
                summary = f"{info.get('os', '?')} | jojonet {info.get('jojonet') or 'نصب نیست'}"
                self.set_check(server_id, True, summary)
        except Exception as exc:
            self.set_check(server_id, False, str(exc))
            raise

    async def job_install_server(self, job: Job, server_id: int) -> None:
        row = self.server(server_id)
        async with self._lock(server_id):
            await job.start(0)
            try:
                async with await self.open(job, row) as sess:
                    await job.ok(0)
                    await job.start(1)
                    await self.install_prereqs(job, sess, row["name"])
                    await job.ok(1)
                    await job.start(2)
                    ver = await self.install_jojonet(job, sess, row["name"])
                    await job.ok(2, f"jojonet {ver}")
                    self.set_check(server_id, True, f"jojonet {ver} نصب شد")
            except Exception as exc:
                self.set_check(server_id, False, str(exc))
                raise

    # ---------- tunnels ----------
    def tunnel(self, tunnel_id: int) -> dict[str, Any]:
        row = self.db.one("SELECT * FROM tunnels WHERE id=?", (tunnel_id,))
        if row is None:
            raise StepFailed("تانل پیدا نشد")
        return row

    def _lock(self, server_id: int) -> asyncio.Lock:
        return self.jobs.server_lock(server_id)

    async def confs(self, sess: RemoteSession) -> list[dict[str, str]]:
        res = await sess.run_root(DUMP_CONFS, timeout=60)
        return split_confs(res.stdout)

    @staticmethod
    def find_conf(confs: list[dict[str, str]], peer_ip: str, mode: str) -> dict[str, str] | None:
        for c in confs:
            if c.get("Remote_IP") == peer_ip and conf_mode(c) == mode and valid_iface(c.get("Name")):
                return c
        return None

    async def delete_remote(self, job: Job, sess: RemoteSession, name: str, iface: str, mode: str = "") -> bool:
        if not valid_iface(iface):
            return True
        cmd = SPOOF_REMOVE if mode == "spoof" else f"jojonet --delete {shlex.quote(iface)} </dev/null"
        res = await sess.run_root(cmd, timeout=180, on_line=lambda l: job.log(f"[{name}] {l}"))
        return res.ok

    async def deploy_side(
        self, job: Job, sess: RemoteSession, row: dict[str, Any], role: str, mode: str, peer_ip: str, extra_env: str = "",
    ) -> dict[str, str]:
        flag = MODES[mode]["flag"]
        cmd = (
            "cd /root 2>/dev/null || cd /; "
            f"JOJONET_ROLE={role} JOJONET_AUTO=1 TERM=dumb{extra_env} "
            f"timeout 900 jojonet {flag} {shlex.quote(peer_ip)} </dev/null"
        )
        res = await sess.run_root(cmd, timeout=960, on_line=lambda l: job.log(f"[{row['name']}] {l}"))
        conf = self.find_conf(await self.confs(sess), peer_ip, mode)
        if not res.ok or conf is None:
            raise StepFailed(
                f"ساخت تانل روی {row['name']} ناموفق بود (کد {res.rc}{'، کانفیگ ساخته نشد' if conf is None else ''})"
            )
        await job.log(f"[{row['name']}] تانل {conf['Name']} ساخته شد")
        return conf

    async def _deploy_direct(self, job: Job, tunnel_id: int) -> None:
        t = self.tunnel(tunnel_id)
        mode = t["mode"]
        kharej = self.server(t["kharej_id"])
        if mode not in STREAM_MODES:
            raise StepFailed("این روش به جفت ایران و خارج نیاز دارد")
        if kharej["role"] != "kharej":
            raise StepFailed("حالت مستقیم فقط روی سرور خارج اجرا می‌شود")
        if not valid_ipv4(kharej["host"]):
            raise StepFailed(f"IP سرور {kharej['name']} معتبر نیست")
        self.db.update("tunnels", tunnel_id, {"status": "deploying", "last_job_id": job.id})
        async with self._lock(kharej["id"]):
            await job.start(0)
            async with await self.open(job, kharej) as sess:
                await job.ok(0)
                await job.start(1)
                info = await self.ensure_ready(job, sess, kharej)
                await job.ok(1, f"jojonet {info.get('jojonet', '')}")
                await job.start(2)
                src = info.get("src", "")
                if src and src != kharej["host"]:
                    await job.log(f"⚠ {kharej['name']}: IP خروجی {src} با {kharej['host']} فرق دارد (NAT)")
                drop_modes = [mode]
                confs = await self.confs(sess)
                seen: set[str] = set()
                for drop in drop_modes:
                    old = self.find_conf(confs, kharej["host"], drop)
                    if old and old["Name"] not in seen:
                        seen.add(old["Name"])
                        await job.log(f"[{kharej['name']}] تانل قبلی {old['Name']} حذف می‌شود")
                        await self.delete_remote(job, sess, kharej["name"], old["Name"])
                await job.ok(2)
                await job.step(3, "skipped", "کلیدها روی همین سرور ساخته می‌شوند")
                await job.start(4, f"{kharej['name']} (kharej / مستقیم)")
                extra = mode_env(mode, t.get("options"))
                c1 = await self.deploy_side(job, sess, kharej, "kharej", mode, kharej["host"], extra)
                self.db.update(
                    "tunnels",
                    tunnel_id,
                    {
                        "kharej_iface": c1["Name"],
                        "iran_iface": None,
                        "tun_iran_ip": None,
                        "tun_kharej_ip": _ip_only(c1.get("Tun_IP", "")),
                        "forward_ports": c1.get("Ports", "") or None,
                    },
                )
                await job.ok(4, c1["Name"])
                await job.step(5, "skipped", "حالت مستقیم: کلاینت روی دستگاه کاربر است")
                await job.step(6, "skipped", "سرور ایران ندارد")
                await job.start(7)
                ok, summary = await self.verify(job, {kharej["id"]: sess}, tunnel_id)
                if not ok:
                    raise StepFailed(summary)
                await job.ok(7, summary)

    async def job_deploy(self, job: Job, tunnel_id: int) -> None:
        t = self.tunnel(tunnel_id)
        mode = t["mode"]
        if is_direct_tunnel(t):
            await self._deploy_direct(job, tunnel_id)
            return
        iran, kharej = self.server(t["iran_id"]), self.server(t["kharej_id"])
        for r in (iran, kharej):
            if not valid_ipv4(r["host"]):
                raise StepFailed(f"IP سرور {r['name']} معتبر نیست")
        first_role = MODES[mode]["first"]
        first, second = (kharej, iran) if first_role == "kharej" else (iran, kharej)
        second_role = "iran" if first_role == "kharej" else "kharej"
        self.db.update("tunnels", tunnel_id, {"status": "deploying", "last_job_id": job.id})

        lock_a, lock_b = sorted((iran["id"], kharej["id"]))
        async with self._lock(lock_a), self._lock(lock_b):
            await job.start(0)
            async with await self.open(job, first) as s1, await self.open(job, second) as s2:
                sess = {first["id"]: s1, second["id"]: s2}
                await job.ok(0)

                await job.start(1)
                infos = {}
                for r in (first, second):
                    infos[r["id"]] = await self.ensure_ready(job, sess[r["id"]], r)
                await job.ok(1, f"jojonet {infos[first['id']].get('jojonet', '')}")

                await job.start(2)
                for r in (first, second):
                    src = infos[r["id"]].get("src", "")
                    if src and src != r["host"]:
                        msg = f"⚠ {r['name']}: IP خروجی {src} با {r['host']} فرق دارد (NAT)"
                        if mode in SUBNET_KEYDIR_MODES:
                            msg += " — subnet دو طرف ممکن است یکی نشود"
                        await job.log(msg)
                if mode == "spoof":
                    await self._deploy_spoof(job, sess, tunnel_id, iran, kharej)
                    return
                # A same-mode tunnel to the same peer would just be restarted with stale keys: remove it first.
                # IPv6 tunnels share one SIT underlay per peer, so any 6to4/GRE6/IPIP6 to that peer must go first.
                drop_modes = list(V6_MODES) if mode in V6_MODES else [mode]
                for r, peer in ((first, second), (second, first)):
                    confs = await self.confs(sess[r["id"]])
                    seen: set[str] = set()
                    for drop in drop_modes:
                        old = self.find_conf(confs, peer["host"], drop)
                        if old and old["Name"] not in seen:
                            seen.add(old["Name"])
                            await job.log(f"[{r['name']}] تانل قبلی {old['Name']} به همین سرور حذف می‌شود")
                            await self.delete_remote(job, sess[r["id"]], r["name"], old["Name"])
                await job.ok(2)

                await job.start(3)
                if mode in WG_MODES:
                    # Plain/ICMP/FakeTCP WireGuard to one peer share a key dir: keep a valid pair so sibling tunnels survive.
                    have = []
                    for r, peer in ((first, second), (second, first)):
                        res = await sess[r["id"]].run_root(read_keys_script(ip_keydir(peer["host"]), WG_KEY_FILES), timeout=60)
                        have.append(parse_kv(res.stdout) if res.ok else {})
                    a_have, b_have = have
                    if wg_keys_match(a_have, b_have):
                        a_files = {k: a_have[k] for k in WG_KEY_FILES[:3]}
                        b_files = {k: b_have[k] for k in WG_KEY_FILES[:3]}
                        await job.log("کلیدهای WireGuard معتبر موجود روی هر دو سرور حفظ شد")
                    else:
                        a_priv, a_pub = wg_keypair()
                        b_priv, b_pub = wg_keypair()
                        a_files = {"wg_private.key": a_priv, "wg_public.key": a_pub, "wg_peer_public.key": b_pub}
                        b_files = {"wg_private.key": b_priv, "wg_public.key": b_pub, "wg_peer_public.key": a_pub}
                    if mode in WG_OBFS:
                        u2r = a_have.get("udp2raw.key", "")
                        if not (UDP2RAW_KEY_RE.fullmatch(u2r) and u2r == b_have.get("udp2raw.key")):
                            u2r = secrets.token_hex(24)
                        a_files["udp2raw.key"] = b_files["udp2raw.key"] = u2r
                    for r, peer, files in ((first, second, a_files), (second, first, b_files)):
                        kd = ip_keydir(peer["host"])
                        names = tuple(files)
                        res = await sess[r["id"]].run_root(install_keys_script(kd, names), input_data=keyfiles_tar(files), timeout=60)
                        if not res.ok:
                            raise StepFailed(f"نصب کلید WireGuard روی {r['name']} ناموفق بود")
                    extra = " + کلید مشترک udp2raw" if mode in WG_OBFS else ""
                    await job.ok(3, f"کلیدهای WireGuard{extra} ساخته و روی هر دو سرور قرار گرفت")
                else:
                    await job.ok(3, "کلیدها پس از ساخت سمت اول همگام می‌شوند" if mode in SUBNET_KEYDIR_MODES | IP_KEYDIR_MODES else "نیاز ندارد")

                users = tunnel_users(t)
                role_first = script_role(first_role, mode, users)
                role_second = script_role(second_role, mode, users)
                if role_first != first_role:
                    await job.log("کاربران روی سرور خارج هستند — پورت ورودی روی خارج، مقصد سرویس روی ایران (تانل خارج → ایران)")
                await job.start(4, f"{first['name']} ({first_role}" + (f" / نقش {role_first}" if role_first != first_role else "") + ")")
                extra = mode_env(mode, t.get("options"))
                c1 = await self.deploy_side(job, sess[first["id"]], first, role_first, mode, second["host"], extra)
                self.db.update("tunnels", tunnel_id, {f"{first_role}_iface": c1["Name"]})
                await job.ok(4, c1["Name"])

                await job.start(5)
                if mode in SUBNET_KEYDIR_MODES | (IP_KEYDIR_MODES - WG_MODES):
                    src_dir = c1.get("KeyDir", "")
                    if not valid_keydir(src_dir):
                        raise StepFailed(f"مسیر کلید سمت اول نامعتبر است: {src_dir!r}")
                    dst_dir = src_dir if mode in SUBNET_KEYDIR_MODES else ip_keydir(first["host"])
                    exp = await sess[first["id"]].run_root(export_keys_script(src_dir), timeout=60)
                    if not exp.ok or not exp.stdout.strip():
                        raise StepFailed(f"خواندن کلیدها از {first['name']} ناموفق بود (کد {exp.rc})")
                    try:
                        blob = base64.b64decode(exp.stdout.strip(), validate=True)
                    except ValueError as exc:
                        raise StepFailed("داده کلید دریافتی خراب است") from exc
                    imp = await sess[second["id"]].run_root(install_keys_script(dst_dir, SHARED_KEY_FILES), input_data=blob, timeout=60)
                    if not imp.ok:
                        raise StepFailed(f"انتقال کلیدها به {second['name']} ناموفق بود")
                    await job.ok(5, f"{src_dir} → {dst_dir} ({parse_kv(imp.stdout).get('installed', '?')} فایل)")
                else:
                    await job.step(5, "skipped", "نیاز ندارد")

                await job.start(6, f"{second['name']} ({second_role}" + (f" / نقش {role_second}" if role_second != second_role else "") + ")")
                c2 = await self.deploy_side(job, sess[second["id"]], second, role_second, mode, first["host"], extra)
                self.db.update("tunnels", tunnel_id, {f"{second_role}_iface": c2["Name"]})
                await job.ok(6, c2["Name"])

                c_iran, c_kharej = (c2, c1) if first_role == "kharej" else (c1, c2)
                listen = c1 if role_first == "iran" else c2 if role_second == "iran" else c_iran
                self.db.update(
                    "tunnels",
                    tunnel_id,
                    {
                        "tun_iran_ip": _ip_only(c_iran.get("Tun_IP", "")),
                        "tun_kharej_ip": _ip_only(c_kharej.get("Tun_IP", "")),
                        "forward_ports": listen.get("Ports", "") or c_iran.get("Ports", "") or c_kharej.get("Ports", "") or None,
                    },
                )
                await job.start(7)
                ok, summary = await self.verify(job, sess, tunnel_id)
                if not ok:
                    raise StepFailed(summary)
                await job.ok(7, summary)

    # ---------- spoof ----------
    async def spoof_state(self, sess: RemoteSession) -> dict[str, str]:
        return parse_kv((await sess.run_root(SPOOF_STATE, timeout=30)).stdout)

    async def ensure_spoof_bin(self, job: Job, sess: RemoteSession, row: dict[str, Any]) -> None:
        res = await sess.run_root(
            "jojonet --spoof-install </dev/null", timeout=300, on_line=lambda l: job.log(f"[{row['name']}] {l}")
        )
        if not res.ok:
            raise StepFailed(f"نصب باینری spoof روی {row['name']} ناموفق بود (کد {res.rc})")

    async def spoof_direction(
        self, job: Job, sender: tuple[dict[str, Any], RemoteSession], receiver: tuple[dict[str, Any], RemoteSession],
        src_ip: str, transport: str, port: int,
    ) -> tuple[bool, str]:
        """Send packets with a forged source from one server and count them on the other."""
        (s_row, s_sess), (r_row, r_sess) = sender, receiver
        proto = spoof_test_proto(transport)
        label = f"{s_row['name']} → {r_row['name']}"
        await job.log(f"[spoof-test] {label}: مبدأ جعلی {src_ip} | {proto}" + (f" پورت {port}" if proto == "tcp" else ""))
        lines: list[str] = []
        listening = asyncio.Event()

        async def on_recv(line: str) -> None:
            lines.append(line)
            await job.log(f"[{r_row['name']}] {line}")
            if "mode=receiver" in line:
                listening.set()

        recv_task = asyncio.create_task(r_sess.run_root(spoof_receiver_script(src_ip, proto, port), timeout=90, on_line=on_recv))
        wait_task = asyncio.create_task(listening.wait())
        try:
            await asyncio.wait({recv_task, wait_task}, timeout=30, return_when=asyncio.FIRST_COMPLETED)
            if not listening.is_set():
                res = await recv_task if recv_task.done() else None
                return False, f"{r_row['name']}: اجرای spoof tester ممکن نشد" + (f" (کد {res.rc})" if res else "")
            await asyncio.sleep(1.5)
            send = await s_sess.run_root(
                spoof_sender_script(src_ip, r_row["host"], proto, port), timeout=90,
                on_line=lambda l: job.log(f"[{s_row['name']}] {l}"),
            )
            await recv_task
        finally:
            for task in (recv_task, wait_task):
                if not task.done():
                    task.cancel()
        if not send.ok:
            return False, f"{s_row['name']}: ارسال بسته جعلی ممکن نشد (کد {send.rc})"
        hit = re.compile(rf"^{re.escape(src_ip)} (\d+)/(\d+) ")
        for line in lines:
            m = hit.match(line.strip())
            if m:
                return True, f"{label}: OK ({m.group(1)}/{m.group(2)} بسته)"
        return False, (
            f"{label}: بسته‌ای با IP جعلی {src_ip} نرسید — دیتاسنتر {s_row['name']} جعل IP را مسدود می‌کند "
            f"یا فایروال {r_row['name']} پروتکل {proto} را می‌بندد"
        )

    async def spoof_readiness(
        self, job: Job, sess: dict[int, RemoteSession], iran: dict[str, Any], kharej: dict[str, Any], opts: dict[str, Any],
        steps: tuple[int, int] | None = None,
    ) -> tuple[bool, str]:
        """Both directions with the tunnel's own spoof IPs, transports and ports."""
        results: list[str] = []
        ok_all = True
        plan = (
            ((iran, sess[iran["id"]]), (kharej, sess[kharej["id"]]), opts["iran_spoof_ip"], opts["up_transport"], int(opts["up_port"])),
            ((kharej, sess[kharej["id"]]), (iran, sess[iran["id"]]), opts["kharej_spoof_ip"], opts["down_transport"], int(opts["down_port"])),
        )
        for i, (snd, rcv, src, transport, port) in enumerate(plan):
            if steps:
                await job.start(steps[i])
            ok, info = await self.spoof_direction(job, snd, rcv, src, transport, port)
            await job.log(f"[spoof-test] {'✔' if ok else '✖'} {info}")
            if steps:
                await job.step(steps[i], "ok" if ok else "failed", info[:200])
            results.append(info)
            ok_all = ok_all and ok
        return ok_all, "؛ ".join(results)

    async def job_spoof_check(self, job: Job, iran_id: int, kharej_id: int, opts: dict[str, Any]) -> None:
        iran, kharej = self.server(iran_id), self.server(kharej_id)
        lock_a, lock_b = sorted((iran["id"], kharej["id"]))
        async with self._lock(lock_a), self._lock(lock_b):
            await job.start(0)
            async with await self.open(job, iran) as si, await self.open(job, kharej) as sk:
                sess = {iran["id"]: si, kharej["id"]: sk}
                await job.ok(0)
                await job.start(1)
                for r in (iran, kharej):
                    await self.ensure_ready(job, sess[r["id"]], r)
                    await self.ensure_spoof_bin(job, sess[r["id"]], r)
                await job.ok(1)
                ok, summary = await self.spoof_readiness(job, sess, iran, kharej, opts, steps=(2, 3))
                if not ok:
                    raise StepFailed("سرورها برای Spoof آماده نیستند: " + summary)
                await job.log("✔ هر دو سرور آماده Spoof هستند؛ می‌توانید تانل را بسازید")

    async def _deploy_spoof(
        self, job: Job, sess: dict[int, RemoteSession], tunnel_id: int, iran: dict[str, Any], kharej: dict[str, Any]
    ) -> None:
        opts = self.tunnel(tunnel_id)["options"] or {}
        if not opts.get("iran_spoof_ip") or not opts.get("kharej_spoof_ip"):
            raise StepFailed("تنظیمات Spoof این تانل ناقص است؛ تانل را حذف و دوباره بسازید")
        await job.log("⚠ Spoof فقط وقتی کار می‌کند که دیتاسنتر هر دو سرور ارسال بسته با IP مبدأ جعلی را اجازه دهد")
        for r, peer in ((kharej, iran), (iran, kharej)):
            st = await self.spoof_state(sess[r["id"]])
            if st.get("peer") and st["peer"] != peer["host"]:
                await job.log(f"[{r['name']}] کانفیگ Spoof قبلی (به {st['peer']}) جایگزین می‌شود")
        if opts.get("skip_check"):
            await job.log("⚠ بررسی آمادگی Spoof به درخواست کاربر رد شد")
            await job.ok(2, "بدون بررسی آمادگی")
        else:
            await job.log("بررسی آمادگی Spoof: ارسال بسته با IP جعلی در هر دو جهت (spoof tester)")
            for r in (kharej, iran):
                await self.ensure_spoof_bin(job, sess[r["id"]], r)
            ready, summary = await self.spoof_readiness(job, sess, iran, kharej, opts)
            if not ready:
                raise StepFailed("سرورها برای Spoof آماده نیستند؛ تانل ساخته نشد: " + summary)
            await job.ok(2, "آمادگی Spoof تأیید شد")
        await job.step(3, "skipped", "نیاز ندارد")

        for idx, r, role, peer in ((4, kharej, "kharej", iran), (6, iran, "iran", kharej)):
            await job.start(idx, f"{r['name']} ({role})")
            cmd = (
                "cd /root 2>/dev/null || cd /; "
                f"JOJONET_ROLE={role} JOJONET_AUTO=1 TERM=dumb {spoof_env(opts, role)} "
                f"timeout 900 jojonet --spoof {shlex.quote(peer['host'])} </dev/null"
            )
            res = await sess[r["id"]].run_root(cmd, timeout=960, on_line=lambda l, n=r["name"]: job.log(f"[{n}] {l}"))
            st = await self.spoof_state(sess[r["id"]])
            want_mode = "local" if role == "iran" else "remote"
            if not res.ok or st.get("mode") != want_mode or st.get("peer") != peer["host"]:
                raise StepFailed(f"ساخت Spoof روی {r['name']} ناموفق بود (کد {res.rc}، سرویس: {st.get('state') or '?'})")
            self.db.update("tunnels", tunnel_id, {f"{role}_iface": SPOOF_MARK})
            await job.ok(idx, f"{SPOOF_UNIT} ({want_mode})")
            if idx == 4:
                await job.step(5, "skipped", "نیاز ندارد")

        bind = "0.0.0.0" if opts.get("listen_public", True) else "127.0.0.1"
        self.db.update("tunnels", tunnel_id, {
            "tun_iran_ip": None, "tun_kharej_ip": None,
            "forward_ports": f"udp {bind}:{opts['listen_port']} → {opts['forward']}",
        })
        await job.start(7)
        ok, summary = await self.verify(job, sess, tunnel_id)
        if not ok:
            raise StepFailed(summary)
        await job.ok(7, summary)

    async def verify_spoof(self, job: Job, sessions: dict[int, RemoteSession], t: dict[str, Any]) -> tuple[bool, str]:
        iran, kharej = self.server(t["iran_id"]), self.server(t["kharej_id"])
        opts = t["options"] or {}
        problems: list[str] = []
        states: dict[int, dict[str, str]] = {}
        for r, peer, want in ((kharej, iran, "remote"), (iran, kharej, "local")):
            st: dict[str, str] = {}
            for attempt in range(4):
                st = await self.spoof_state(sessions[r["id"]])
                if st.get("state") == "active":
                    break
                await asyncio.sleep(RETRY_DELAY)
            states[r["id"]] = st
            await job.log(f"[{r['name']}] {SPOOF_UNIT}: {st.get('state') or '?'} | mode={st.get('mode') or '-'} | peer={st.get('peer') or '-'}")
            if st.get("state") != "active":
                problems.append(f"{r['name']}: سرویس Spoof فعال نیست")
            elif st.get("mode") != want or st.get("peer") != peer["host"]:
                problems.append(f"{r['name']}: کانفیگ Spoof با این تانل نمی‌خواند (روی سرور تغییر کرده)")
        if problems or not opts:
            ok = False
            summary = "؛ ".join(problems) or "تنظیمات Spoof این تانل ناقص است"
        else:
            port = int(opts["listen_port"])
            res = await sessions[iran["id"]].run_root(f"ss -Hlun 'sport = :{port}' 2>/dev/null | head -n1", timeout=30)
            if not res.stdout.strip():
                problems.append(f"{iran['name']}: پورت UDP {port} باز نشده")
            ok, summary = (False, "؛ ".join(problems)) if problems else await self.spoof_probe(job, sessions, iran, kharej, opts, states)
        self.db.update(
            "tunnels", t["id"], {"status": "ok" if ok else "degraded", "last_check": {"ok": ok, "at": utcnow(), "info": summary}}
        )
        return ok, summary

    async def spoof_probe(
        self, job: Job, sessions: dict[int, RemoteSession], iran: dict[str, Any], kharej: dict[str, Any],
        opts: dict[str, Any], states: dict[int, dict[str, str]],
    ) -> tuple[bool, str]:
        f_host, _, f_port = opts["forward"].rpartition(":")
        if f_host not in ("127.0.0.1", "localhost"):
            return True, "سرویس‌ها فعال‌اند (تست سرتاسری فقط برای فوروارد روی 127.0.0.1 انجام می‌شود)"
        if states[iran["id"]].get("py") != "yes" or states[kharej["id"]].get("py") != "yes":
            return True, "سرویس‌ها فعال‌اند (python3 نیست؛ تست سرتاسری انجام نشد)"
        nonce = "jnprobe-" + secrets.token_hex(8)
        ready = asyncio.Event()
        echo_lines: list[str] = []

        async def on_echo(line: str) -> None:
            echo_lines.append(line)
            if line.startswith("ready"):
                ready.set()

        echo_cmd = f"timeout 40 python3 -c {shlex.quote(PROBE_ECHO)} {shlex.quote(f_host)} {int(f_port)} {nonce} 30"
        echo_task = asyncio.create_task(sessions[kharej["id"]].run_root(echo_cmd, timeout=60, on_line=on_echo))
        ready_task = asyncio.create_task(ready.wait())
        try:
            await asyncio.wait({echo_task, ready_task}, timeout=20, return_when=asyncio.FIRST_COMPLETED)
            if not ready.is_set():
                echo_res = await echo_task
                if any(l.startswith("bind_error") for l in echo_lines + echo_res.stdout.splitlines()):
                    await job.log(f"[{kharej['name']}] مقصد فوروارد {opts['forward']} در حال استفاده است؛ تست سرتاسری رد شد")
                    return True, f"سرویس‌ها فعال‌اند (مقصد {opts['forward']} مشغول است؛ تست سرتاسری انجام نشد)"
                return False, f"{kharej['name']}: اجرای تست UDP ممکن نشد (کد {echo_res.rc})"
            port = int(opts["listen_port"])
            send_cmd = f"timeout 30 python3 -c {shlex.quote(PROBE_SEND)} 127.0.0.1 {port} {nonce} 20"
            send_res = await sessions[iran["id"]].run_root(send_cmd, timeout=45)
            echo_res = await echo_task
        finally:
            for task in (echo_task, ready_task):
                if not task.done():
                    task.cancel()
        received = 0
        for line in echo_lines + echo_res.stdout.splitlines():
            m = re.match(r"received (\d+)", line)
            if m:
                received = max(received, int(m.group(1)))
        acked = send_res.ok and "ack" in send_res.stdout.split()
        await job.log(f"[probe] ایران→خارج: {'OK' if received else 'FAIL'} | خارج→ایران: {'OK' if acked else 'FAIL'}")
        if received and acked:
            return True, "تست سرتاسری UDP در هر دو جهت موفق بود"
        if not received:
            return False, (
                f"بسته‌ها از ایران به خارج نرسید: دیتاسنتر {iran['name']} احتمالاً IP جعلی "
                f"{opts['iran_spoof_ip']} را فیلتر می‌کند یا transport {opts['up_transport']} بسته است"
            )
        return False, (
            f"رفت موفق بود ولی برگشت نرسید: دیتاسنتر {kharej['name']} احتمالاً IP جعلی "
            f"{opts['kharej_spoof_ip']} را فیلتر می‌کند یا transport {opts['down_transport']} بسته است"
        )

    async def verify(self, job: Job, sessions: dict[int, RemoteSession], tunnel_id: int) -> tuple[bool, str]:
        t = self.tunnel(tunnel_id)
        if t["mode"] == "spoof":
            return await self.verify_spoof(job, sessions, t)
        iran, kharej = self.server(t["iran_id"]), self.server(t["kharej_id"])
        problems: list[str] = []
        sides = [(kharej, t["kharej_iface"])]
        if not is_direct_tunnel(t):
            sides.append((iran, t["iran_iface"]))
        for r, iface in sides:
            if not valid_iface(iface):
                problems.append(f"{r['name']}: نام تانل ثبت نشده")
                continue
            healthy = False
            for attempt in range(6):
                res = await sessions[r["id"]].run_root(f"jojonet --health {shlex.quote(iface)} </dev/null", timeout=120)
                if res.ok:
                    healthy = True
                    break
                await asyncio.sleep(RETRY_DELAY)
            await job.log(f"[{r['name']}] health {iface}: {'OK' if healthy else 'FAIL'}")
            if not healthy:
                problems.append(f"{r['name']}: سرویس {iface} سالم نیست")
        ping_info = ""
        remote_ip = t["tun_kharej_ip"]
        if is_direct_tunnel(t):
            remote_ip = None
            if not problems:
                ping_info = "سرویس خارج سالم است (حالت مستقیم؛ کلاینت روی دستگاه کاربر)"
        if remote_ip and (valid_ipv4(remote_ip) or valid_ipv6(remote_ip)):
            ok_ping = False
            fam = "-6 " if ":" in remote_ip else ""
            ping_cmd = f"ping {fam}-c 3 -W 2 -q {shlex.quote(remote_ip)}"
            for attempt in range(6):
                res = await sessions[iran["id"]].run_root(ping_cmd, timeout=30)
                m = re.search(r"= [0-9.]+/([0-9.]+)/", res.stdout)
                if res.ok:
                    ok_ping = True
                    ping_info = f"ping {remote_ip}: {m.group(1) + ' ms' if m else 'OK'}"
                    break
                await asyncio.sleep(RETRY_DELAY)
            await job.log(f"[{iran['name']}] {ping_info or f'ping {remote_ip}: FAIL'}")
            if not ok_ping:
                problems.append(f"پینگ از ایران به {remote_ip} جواب نداد")
        ok = not problems
        summary = (ping_info or "سرویس‌ها سالم هستند") if ok else "؛ ".join(problems)
        self.db.update(
            "tunnels", tunnel_id, {"status": "ok" if ok else "degraded", "last_check": {"ok": ok, "at": utcnow(), "info": summary}}
        )
        return ok, summary

    async def job_verify(self, job: Job, tunnel_id: int) -> None:
        t = self.tunnel(tunnel_id)
        if is_direct_tunnel(t):
            kharej = self.server(t["kharej_id"])
            await job.start(0)
            async with await self.open(job, kharej) as sk:
                await job.ok(0)
                await job.start(1)
                ok, summary = await self.verify(job, {kharej["id"]: sk}, tunnel_id)
                if not ok:
                    raise StepFailed(summary)
                await job.ok(1, summary)
            return
        iran, kharej = self.server(t["iran_id"]), self.server(t["kharej_id"])
        await job.start(0)
        async with await self.open(job, iran) as si, await self.open(job, kharej) as sk:
            await job.ok(0)
            await job.start(1)
            ok, summary = await self.verify(job, {iran["id"]: si, kharej["id"]: sk}, tunnel_id)
            if not ok:
                raise StepFailed(summary)
            await job.ok(1, summary)

    async def job_delete(self, job: Job, tunnel_id: int, force: bool) -> None:
        t = self.tunnel(tunnel_id)
        self.db.update("tunnels", tunnel_id, {"status": "deleting", "last_job_id": job.id})
        failures: list[str] = []
        for idx, (sid, iface) in enumerate(((t["iran_id"], t["iran_iface"]), (t["kharej_id"], t["kharej_iface"]))):
            await job.start(idx)
            row = self.db.one("SELECT * FROM servers WHERE id=?", (sid,))
            if row is None or not valid_iface(iface):
                await job.step(idx, "skipped", "چیزی برای حذف نیست")
                continue
            try:
                async with self._lock(sid):
                    async with await self.open(job, row) as sess:
                        if await self.delete_remote(job, sess, row["name"], iface, t["mode"]):
                            await job.ok(idx, iface)
                        else:
                            failures.append(row["name"])
                            await job.step(idx, "failed", "حذف ناقص")
            except Exception as exc:
                failures.append(row["name"])
                await job.log(f"[{row['name']}] {exc}")
                await job.step(idx, "failed", str(exc)[:200])
        await job.start(2)
        if failures and not force:
            self.db.update("tunnels", tunnel_id, {"status": "failed"})
            raise StepFailed("حذف روی " + "، ".join(failures) + " کامل نشد؛ برای حذف از پنل گزینه «حذف اجباری» را بزنید")
        self.db.execute("DELETE FROM tunnels WHERE id=?", (tunnel_id,))
        await job.ok(2, "از پنل حذف شد" + (" (اجباری)" if failures else ""))

    async def job_redeploy(self, job: Job, tunnel_id: int) -> None:
        # job_deploy removes same-mode tunnels to the same peer on both sides before building.
        await self.job_deploy(job, tunnel_id)

    # ---------- relays / server tools ----------
    def relay(self, relay_id: int) -> dict[str, Any]:
        row = self.db.one("SELECT * FROM relays WHERE id=?", (relay_id,))
        if row is None:
            raise StepFailed("رله پیدا نشد")
        return row

    async def job_relay_add(self, job: Job, relay_id: int) -> None:
        row = self.relay(relay_id)
        srv = self.server(row["server_id"])
        engine, target, ports, proto, name = row["engine"], row["target"], row["ports"], row["proto"], row["name"]
        if engine not in RELAY_ENGINES or not valid_relay_name(name):
            raise StepFailed("تنظیمات رله نامعتبر است")
        self.db.update("relays", relay_id, {"status": "deploying", "last_job_id": job.id})
        async with self._lock(srv["id"]):
            await job.start(0)
            async with await self.open(job, srv) as sess:
                await job.ok(0)
                await job.start(1)
                await self.ensure_ready(job, sess, srv)
                await job.ok(1)
                await job.start(2)
                cmd = (
                    "cd /root 2>/dev/null || cd /; "
                    f"TERM=dumb timeout 300 jojonet --relay {shlex.quote(engine)} {shlex.quote(target)} "
                    f"{shlex.quote(ports)} {shlex.quote(proto)} {shlex.quote(name)} </dev/null"
                )
                res = await sess.run_root(cmd, timeout=360, on_line=lambda l: job.log(f"[{srv['name']}] {l}"))
                if not res.ok:
                    self.db.update("relays", relay_id, {"status": "failed"})
                    raise StepFailed(f"ساخت رله روی {srv['name']} ناموفق بود (کد {res.rc})")
                self.db.update("relays", relay_id, {"status": "ok", "last_check": {"ok": True, "at": utcnow(), "info": f"{engine} {ports} → {target}"}})
                await job.ok(2, name)

    async def job_relay_delete(self, job: Job, relay_id: int, force: bool) -> None:
        row = self.relay(relay_id)
        self.db.update("relays", relay_id, {"status": "deleting", "last_job_id": job.id})
        await job.start(0)
        srv = self.db.one("SELECT * FROM servers WHERE id=?", (row["server_id"],))
        failed = False
        if srv is None or not valid_relay_name(row["name"]):
            await job.step(0, "skipped", "چیزی برای حذف نیست")
        else:
            try:
                async with self._lock(srv["id"]):
                    async with await self.open(job, srv) as sess:
                        res = await sess.run_root(
                            f"jojonet --relay-remove {shlex.quote(row['name'])} </dev/null",
                            timeout=120, on_line=lambda l: job.log(f"[{srv['name']}] {l}"),
                        )
                        if res.ok:
                            await job.ok(0, row["name"])
                        else:
                            failed = True
                            await job.step(0, "failed", "حذف ناقص")
            except Exception as exc:
                failed = True
                await job.log(str(exc))
                await job.step(0, "failed", str(exc)[:200])
        await job.start(1)
        if failed and not force:
            self.db.update("relays", relay_id, {"status": "failed"})
            raise StepFailed("حذف رله از سرور کامل نشد؛ برای حذف از پنل گزینه «حذف اجباری» را بزنید")
        self.db.execute("DELETE FROM relays WHERE id=?", (relay_id,))
        await job.ok(1, "از پنل حذف شد" + (" (اجباری)" if failed else ""))

    async def job_relay_stats(self, job: Job, relay_id: int) -> None:
        row = self.relay(relay_id)
        srv = self.server(row["server_id"])
        await job.start(0)
        async with await self.open(job, srv) as sess:
            await job.ok(0)
            await job.start(1)
            res = await sess.run_root(
                f"jojonet --relay-stats {shlex.quote(row['name'])} </dev/null",
                timeout=60, on_line=lambda l: job.log(f"[{srv['name']}] {l}"),
            )
            if not res.ok:
                raise StepFailed(f"خواندن آمار رله ناموفق بود (کد {res.rc})")
            info = (res.stdout or "").strip().splitlines()
            summary = info[-1][:200] if info else "آمار رله"
            self.db.update("relays", relay_id, {"last_check": {"ok": True, "at": utcnow(), "info": summary}})
            await job.ok(1, summary)

    async def job_server_dns(self, job: Job, server_id: int, dns1: str, dns2: str) -> None:
        row = self.server(server_id)
        extra = f" {shlex.quote(dns2)}" if dns2 else ""
        async with self._lock(server_id):
            await job.start(0)
            async with await self.open(job, row) as sess:
                await job.ok(0)
                await job.start(1)
                await self.ensure_ready(job, sess, row)
                await job.ok(1)
                await job.start(2)
                res = await sess.run_root(
                    f"jojonet --dns {shlex.quote(dns1)}{extra} </dev/null",
                    timeout=60, on_line=lambda l: job.log(f"[{row['name']}] {l}"),
                )
                if not res.ok:
                    raise StepFailed(f"تنظیم DNS روی {row['name']} ناموفق بود (کد {res.rc})")
                await job.ok(2, f"{dns1}{(' ' + dns2) if dns2 else ''}")

    async def job_server_ping(self, job: Job, server_id: int) -> None:
        row = self.server(server_id)
        await job.start(0)
        async with await self.open(job, row) as sess:
            await job.ok(0)
            await job.start(1)
            res = await sess.run_root(
                "jojonet --ping-test </dev/null", timeout=60, on_line=lambda l: job.log(f"[{row['name']}] {l}"),
            )
            if not res.ok:
                raise StepFailed(f"تست پینگ روی {row['name']} ناموفق بود (کد {res.rc})")
            await job.ok(1, "تست پینگ انجام شد")

    async def probe_vpn_panels(self, server_id: int) -> dict[str, Any]:
        row = self.server(server_id)
        async with self._lock(server_id):
            sess = RemoteSession(self.creds(row), connect_timeout=self.settings.ssh_connect_timeout)
            async with sess:
                res = await sess.run_root(
                    "TERM=dumb timeout 25 jojonet --vpn-panel-check </dev/null",
                    timeout=35,
                )
        info = parse_vpn_check(res.stdout or "")
        out = vpn_check_summary(info)
        out["ok"] = bool(res.ok and info)
        return out

    async def job_vpn_panel(self, job: Job, server_id: int, kind: str) -> None:
        flag = VPN_PANEL_FLAGS.get(kind)
        label = VPN_PANEL_LABELS.get(kind, kind)
        if not flag:
            raise StepFailed("نوع پنل نامعتبر است")
        row = self.server(server_id)
        async with self._lock(server_id):
            await job.start(0)
            async with await self.open(job, row) as sess:
                await job.ok(0)
                await job.start(1)
                probe = await sess.run_root(f"jojonet --help 2>/dev/null | grep -F -- {shlex.quote(flag)}", timeout=30)
                if not probe.ok:
                    await job.log(f"[{row['name']}] jojonet این فلگ را ندارد؛ اسکریپت از بسته پنل نصب می‌شود")
                    await self.install_jojonet(job, sess, row["name"])
                await job.ok(1)
                await job.start(2)
                check = await sess.run_root(
                    "TERM=dumb timeout 25 jojonet --vpn-panel-check </dev/null",
                    timeout=35,
                    on_line=lambda l: job.log(f"[{row['name']}] {l}"),
                )
                info = parse_vpn_check(check.stdout or "")
                if vpn_panel_conflict(kind, info):
                    raise StepFailed(vpn_panel_conflict_msg(kind, info))
                skipped = False
                if check.ok and vpn_panel_already(kind, info):
                    skipped = True
                    await job.log(f"[{row['name']}] همین پنل از قبل روی سرور نصب است؛ نصب دوباره انجام نشد.")
                    await job.ok(2, f"{label} از قبل نصب بود")
                    res = check
                else:
                    cmd = (
                        "cd /root 2>/dev/null || cd /; "
                        f"TERM=dumb timeout 900 jojonet {flag} </dev/null"
                    )
                    res = await sess.run_root(cmd, timeout=960, on_line=lambda l: job.log(f"[{row['name']}] {l}"))
                    if not res.ok:
                        raise StepFailed(f"نصب {label} روی {row['name']} ناموفق بود (کد {res.rc})")
                    await job.ok(2, f"{label} نصب شد")
                await job.start(3)
                creds_res = await sess.run_root(
                    "TERM=dumb timeout 40 jojonet --vpn-panel-creds </dev/null",
                    timeout=50,
                    on_line=lambda l: job.log(f"[{row['name']}] {l}"),
                )
                creds = parse_vpn_creds(f"{res.stdout or ''}\n{creds_res.stdout or ''}")
                if creds.get("url") or creds.get("username") or creds.get("password"):
                    await job.log("")
                    await job.log("----- مشخصات ورود پنل -----")
                    if creds.get("label"):
                        await job.log(f"  پنل:   {creds['label']}")
                    if creds.get("url"):
                        await job.log(f"  آدرس:  {creds['url']}")
                    if creds.get("username"):
                        await job.log(f"  کاربر: {creds['username']}")
                    if creds.get("password"):
                        await job.log(f"  رمز:   {creds['password']}")
                    if creds.get("note"):
                        await job.log(f"  نکته:  {creds['note']}")
                    await job.log("  این مشخصات را ذخیره کنید.")
                    await job.log("----------------------------")
                    await job.ok(3, creds.get("url") or "مشخصات ورود آماده است")
                else:
                    await job.log(f"[{row['name']}] مشخصات ورود در خروجی نصب پیدا نشد؛ لاگ بالا را ببینید.")
                    await job.ok(3, "نصب شد؛ مشخصات ورود را از لاگ بخوانید")
                self.set_check(server_id, True, f"{label} از قبل نصب بود" if skipped else f"{label} نصب شد")

    async def job_server_ssl(self, job: Job, server_id: int, domain: str, email: str) -> None:
        row = self.server(server_id)
        script = server_ssl_script(domain, email, str(row["host"]))
        async with self._lock(server_id):
            await job.start(0)
            async with await self.open(job, row) as sess:
                await job.ok(0)
                await job.start(1)
                await job.log(f"[{row['name']}] دامنه {domain} روی IP سرور {row['host']} بررسی می‌شود")
                await job.ok(1, "بررسی آغاز شد")
                await job.start(2)
                res = await sess.run_root(
                    script,
                    timeout=480,
                    on_line=lambda l: job.log(f"[{row['name']}] {l}"),
                )
                info = parse_server_ssl(res.stdout or "")
                if not res.ok or info.get("ok") != "1":
                    detail = info.get("error") or ""
                    if not detail:
                        lines = (res.stderr or res.stdout or "").strip().splitlines()
                        detail = lines[-1] if lines else ""
                    raise StepFailed(str(detail)[:240] or f"دریافت گواهی روی {row['name']} ناموفق بود (کد {res.rc})")
                await job.ok(2, f"گواهی {domain} دریافت شد")
                await job.start(3)
                payload = {
                    "ok": True,
                    "at": utcnow(),
                    "domain": info.get("domain") or domain,
                    "issuer": info.get("issuer") or "Let's Encrypt",
                    "not_after": normalize_ssl_not_after(info.get("not_after") or ""),
                    "cert": info.get("cert") or "",
                    "key": info.get("key") or "",
                    "email": email or "",
                }
                self.db.update("servers", server_id, {"last_ssl": payload})
                await job.log("")
                await job.log("----- گواهی SSL -----")
                await job.log(f"  دامنه:     {payload['domain']}")
                await job.log(f"  مرجع صدور: {payload['issuer']}")
                if payload["not_after"]:
                    await job.log(f"  انقضا:     {payload['not_after']}")
                if payload["cert"]:
                    await job.log(f"  فایل گواهی: {payload['cert']}")
                if payload["key"]:
                    await job.log(f"  فایل کلید:  {payload['key']}")
                await job.log("  تمدید خودکار certbot فعال است.")
                await job.log("----------------------")
                await job.ok(3, f"گواهی روی {row['name']} نصب شد")

    def match_panel_tunnel_id(self, server_id: int, name: str, tunnels: list[dict[str, Any]]) -> int | None:
        for t in tunnels:
            if t.get("iran_id") == server_id and t.get("iran_iface") == name:
                return int(t["id"])
            if t.get("kharej_id") == server_id and t.get("kharej_iface") == name:
                return int(t["id"])
        return None

    async def scan_server_live(self, job: Job | None, row: dict[str, Any], tunnels: list[dict[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {
            "id": row["id"],
            "name": row["name"],
            "role": row["role"],
            "host": row["host"],
            "ok": False,
            "error": None,
            "tunnels": [],
        }
        try:
            async with await self.open(job, row) as sess:
                if job is not None:
                    await job.log(f"[{row['name']}] اسکن تانل‌های زنده")
                res = await sess.run_root(LIST_TUNNELS_JSON, timeout=60)
                if not res.ok:
                    out["error"] = f"خواندن لیست ناموفق بود (کد {res.rc})"
                    return out
                items = parse_live_tunnels(res.stdout or "")
                live = []
                for item in items:
                    name = item.get("name") or ""
                    tid = self.match_panel_tunnel_id(row["id"], name, tunnels) if valid_iface(name) else None
                    live.append({
                        **item,
                        "panel_tunnel_id": tid,
                        "orphan": tid is None,
                    })
                out["ok"] = True
                out["tunnels"] = live
                return out
        except Exception as exc:
            out["error"] = str(exc)[:240]
            return out

    async def scan_live_tunnels(self, servers: list[dict[str, Any]], tunnels: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if not servers:
            return []
        results = await asyncio.gather(*(self.scan_server_live(None, row, tunnels) for row in servers))
        return list(results)

    async def job_enable_boot(self, job: Job, server_id: int) -> None:
        row = self.server(server_id)
        async with self._lock(server_id):
            await job.start(0)
            async with await self.open(job, row) as sess:
                await job.ok(0)
                await job.start(1)
                res = await sess.run_root(
                    ENABLE_BOOT_CMD, timeout=180, on_line=lambda l: job.log(f"[{row['name']}] {l}"),
                )
                if not res.ok:
                    raise StepFailed(f"فعال‌سازی ماندگاری ریبوت روی {row['name']} ناموفق بود (کد {res.rc})")
                await job.ok(1, "ماندن بعد از ریبوت فعال شد")

    async def job_delete_remote_tunnel(self, job: Job, server_id: int, name: str, force: bool) -> None:
        if not valid_iface(name):
            raise StepFailed("نام تانل نامعتبر است")
        row = self.server(server_id)
        await job.start(0)
        failed = False
        try:
            async with self._lock(server_id):
                async with await self.open(job, row) as sess:
                    if await self.delete_remote(job, sess, row["name"], name):
                        await job.ok(0, name)
                    else:
                        failed = True
                        await job.step(0, "failed", "حذف ناقص")
        except Exception as exc:
            failed = True
            await job.log(str(exc))
            await job.step(0, "failed", str(exc)[:200])
        if failed and not force:
            raise StepFailed(f"حذف تانل {name} از {row['name']} کامل نشد؛ حذف اجباری را بزنید")
        if failed:
            await job.log(f"حذف اجباری: {name} از پنل نادیده گرفته شد (روی سرور ممکن است مانده باشد)")

    async def job_server_update(self, job: Job, server_id: int) -> None:
        row = self.server(server_id)
        async with self._lock(server_id):
            await job.start(0)
            async with await self.open(job, row) as sess:
                await job.ok(0)
                await job.start(1)
                res = await sess.run_root(
                    "jojonet --update-server </dev/null", timeout=1800, on_line=lambda l: job.log(f"[{row['name']}] {l}"),
                )
                if not res.ok:
                    raise StepFailed(f"آپدیت سیستم روی {row['name']} ناموفق بود (کد {res.rc})")
                await job.ok(1, "بسته‌های سیستم به‌روز شد")


def _ip_only(value: str) -> str | None:
    ip = (value or "").split("/", 1)[0].strip()
    return ip if valid_ipv4(ip) or valid_ipv6(ip) else None


def parse_live_tunnels(text: str) -> list[dict[str, Any]]:
    """Parse `jojonet --list-tunnels --json` stdout into a list of tunnel dicts."""
    raw = (text or "").strip()
    if not raw:
        return []
    # Prefer the last JSON array in case banners precede it.
    start = raw.rfind("[")
    end = raw.rfind("]")
    if start < 0 or end < start:
        return []
    try:
        data = json.loads(raw[start : end + 1])
    except json.JSONDecodeError:
        return []
    if not isinstance(data, list):
        return []
    out: list[dict[str, Any]] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        if not name or not valid_iface(name):
            continue
        boot = item.get("boot")
        if isinstance(boot, str):
            boot = boot.strip().lower() in ("1", "true", "yes", "enabled")
        out.append({
            "name": name,
            "mode": str(item.get("mode") or "").strip() or "gre",
            "role": str(item.get("role") or "").strip(),
            "local_ip": str(item.get("local_ip") or "").strip(),
            "remote_ip": str(item.get("remote_ip") or "").strip(),
            "status": str(item.get("status") or "").strip() or "DOWN",
            "boot": bool(boot),
            "unit": str(item.get("unit") or "").strip(),
        })
    return out


DEPLOY_STEPS = [
    "اتصال SSH به هر دو سرور",
    "آماده‌سازی سرورها (پیش‌نیازها + jojonet)",
    "بررسی شبکه و تانل‌های قبلی",
    "آماده‌سازی کلیدها",
    "ساخت تانل سمت اول",
    "همگام‌سازی کلیدها",
    "ساخت تانل سمت دوم",
    "تأیید (health + ping)",
]
VERIFY_STEPS = ["اتصال SSH", "بررسی سلامت و پینگ"]
SPOOF_CHECK_STEPS = ["اتصال SSH به هر دو سرور", "آماده‌سازی (jojonet + باینری spoof)", "تست Spoof ایران → خارج", "تست Spoof خارج → ایران"]
DELETE_STEPS = ["حذف از سرور ایران", "حذف از سرور خارج", "حذف از پنل"]
TEST_STEPS = ["اتصال SSH", "اطلاعات سیستم"]
INSTALL_STEPS = ["اتصال SSH", "نصب پیش‌نیازها", "نصب اسکریپت jojonet"]
RELAY_STEPS = ["اتصال SSH", "آماده‌سازی jojonet", "ساخت رله"]
RELAY_DELETE_STEPS = ["حذف از سرور", "حذف از پنل"]
RELAY_STATS_STEPS = ["اتصال SSH", "خواندن آمار"]
DNS_STEPS = ["اتصال SSH", "آماده‌سازی jojonet", "تنظیم DNS"]
PING_TEST_STEPS = ["اتصال SSH", "تست پینگ"]
OS_UPDATE_STEPS = ["اتصال SSH", "آپدیت بسته‌های سیستم"]
ENABLE_BOOT_STEPS = ["اتصال SSH", "فعال‌سازی ماندگاری بعد از ریبوت"]
REMOTE_DELETE_STEPS = ["حذف از سرور"]
VPN_PANEL_STEPS = ["اتصال SSH", "آماده‌سازی jojonet", "نصب یک‌کلیکی پنل", "خواندن مشخصات ورود"]
SERVER_SSL_STEPS = ["اتصال SSH", "بررسی دامنه و پورت ۸۰", "دریافت گواهی Let's Encrypt", "نصب گواهی روی سرور"]
SERVER_SSL_BEGIN = "===== JOJONET_SERVER_SSL ====="
SERVER_SSL_END = "===== END_JOJONET_SERVER_SSL ====="
VPN_CHECK_BEGIN = "===== JOJONET_VPN_CHECK ====="
VPN_CHECK_END = "===== END_JOJONET_VPN_CHECK ====="
VPN_CHECK_KEYS = ("xui", "xui_flavor", "xui_running", "pasarguard", "pasarguard_running")
VPN_CREDS_BEGIN = "===== JOJONET_VPN_CREDS ====="
VPN_CREDS_END = "===== END_JOJONET_VPN_CREDS ====="
VPN_CREDS_KEYS = ("kind", "label", "url", "username", "password", "note")
SERVER_SSL_KEYS = ("ok", "domain", "issuer", "not_after", "cert", "key", "error")


def server_ssl_script(domain: str, email: str, expected_ip: str) -> str:
    """Issue a free Let's Encrypt cert on the remote VPS for the user's domain."""
    d = shlex.quote(domain)
    e = shlex.quote(email or "")
    ip = shlex.quote(expected_ip)
    begin = SERVER_SSL_BEGIN
    end = SERVER_SSL_END
    return f"""
set -eu
export DEBIAN_FRONTEND=noninteractive
DOMAIN={d}
EMAIL={e}
EXPECT_IP={ip}
OUT_DIR="/etc/jojonet/ssl/$DOMAIN"
LIVE_DIR="/etc/letsencrypt/live/$DOMAIN"
echo "domain=$DOMAIN"
echo "expect_ip=$EXPECT_IP"

resolved="$(getent ahosts "$DOMAIN" 2>/dev/null | awk '{{print $1}}' | grep -E '^[0-9.]+$' | sort -u || true)"
if [ -z "$resolved" ]; then
  echo "{begin}"
  echo "ok=0"
  echo "error=دامنه هنوز به هیچ IPv4 اشاره نمی‌کند. رکورد A را به IP همین سرور بدهید و پروکسی را خاموش کنید."
  echo "{end}"
  exit 10
fi
echo "resolved=$resolved"
match=0
for ip in $resolved; do
  if [ "$ip" = "$EXPECT_IP" ]; then match=1; break; fi
done
if [ "$match" != "1" ]; then
  echo "{begin}"
  echo "ok=0"
  echo "error=دامنه به IP دیگری اشاره می‌کند (نه $EXPECT_IP). رکورد A را اصلاح کنید و پروکسی ابری را خاموش کنید."
  echo "{end}"
  exit 11
fi

holder="$(ss -Htlnp 'sport = :80' 2>/dev/null | head -n 1 || true)"
if [ -n "$holder" ]; then
  echo "{begin}"
  echo "ok=0"
  echo "error=پورت ۸۰ روی این سرور اشغال است. سرویس روی پورت ۸۰ را موقتاً متوقف کنید و دوباره تلاش کنید."
  echo "{end}"
  exit 12
fi

if ! command -v certbot >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    apt-get -o DPkg::Lock::Timeout=180 update -qq || true
    apt-get -o DPkg::Lock::Timeout=180 install -y -qq --no-install-recommends certbot || {{
      echo "{begin}"; echo "ok=0"; echo "error=نصب certbot ناموفق بود."; echo "{end}"; exit 13;
    }}
  elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
    pm="$(command -v dnf || command -v yum)"
    "$pm" install -y -q certbot || {{
      echo "{begin}"; echo "ok=0"; echo "error=نصب certbot ناموفق بود."; echo "{end}"; exit 13;
    }}
  else
    echo "{begin}"; echo "ok=0"; echo "error=مدیر بسته پشتیبانی‌شده پیدا نشد."; echo "{end}"; exit 13
  fi
fi

mail_args="--register-unsafely-without-email"
if [ -n "$EMAIL" ]; then mail_args="--email $EMAIL"; fi
if ! certbot certonly --standalone --non-interactive --agree-tos --preferred-challenges http \\
    -d "$DOMAIN" $mail_args; then
  echo "{begin}"
  echo "ok=0"
  echo "error=Let's Encrypt گواهی صادر نکرد. DNS، فایروال پورت ۸۰ و محدودیت نرخ را بررسی کنید."
  echo "{end}"
  exit 14
fi

if [ ! -f "$LIVE_DIR/fullchain.pem" ] || [ ! -f "$LIVE_DIR/privkey.pem" ]; then
  echo "{begin}"; echo "ok=0"; echo "error=فایل گواهی بعد از صدور پیدا نشد."; echo "{end}"; exit 15
fi

mkdir -p "$OUT_DIR"
install -m 644 "$LIVE_DIR/fullchain.pem" "$OUT_DIR/fullchain.pem"
install -m 600 "$LIVE_DIR/privkey.pem" "$OUT_DIR/privkey.pem"
not_after="$(openssl x509 -in "$OUT_DIR/fullchain.pem" -noout -enddate 2>/dev/null | sed 's/^notAfter=//' || true)"
issuer="$(openssl x509 -in "$OUT_DIR/fullchain.pem" -noout -issuer 2>/dev/null | sed -n 's/.*O = \\([^,]*\\).*/\\1/p' || true)"
[ -n "$issuer" ] || issuer="Let's Encrypt"
echo "{begin}"
echo "ok=1"
echo "domain=$DOMAIN"
echo "issuer=$issuer"
echo "not_after=$not_after"
echo "cert=$OUT_DIR/fullchain.pem"
echo "key=$OUT_DIR/privkey.pem"
echo "{end}"
"""


def parse_server_ssl(text: str) -> dict[str, str]:
    if not text:
        return {}
    start = text.rfind(SERVER_SSL_BEGIN)
    if start < 0:
        return {}
    rest = text[start + len(SERVER_SSL_BEGIN) :]
    end = rest.find(SERVER_SSL_END)
    block = rest if end < 0 else rest[:end]
    out: dict[str, str] = {}
    for raw in block.splitlines():
        line = re.sub(r"^\[.*?\]\s*", "", raw).strip()
        if "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip().lower()
        val = val.strip()
        if key in SERVER_SSL_KEYS and val:
            out[key] = val
    return out


def normalize_ssl_not_after(raw: str) -> str:
    text = (raw or "").strip()
    if not text:
        return ""
    if "T" in text and text[:4].isdigit():
        return text.replace("Z", "+00:00")
    cleaned = text.replace(" GMT", "").replace(" UTC", "")
    try:
        from datetime import datetime, timezone

        return datetime.strptime(cleaned, "%b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc).isoformat()
    except ValueError:
        return text


def parse_vpn_creds(text: str) -> dict[str, str]:
    if not text:
        return {}
    start = text.rfind(VPN_CREDS_BEGIN)
    if start < 0:
        return {}
    rest = text[start + len(VPN_CREDS_BEGIN) :]
    end = rest.find(VPN_CREDS_END)
    block = rest if end < 0 else rest[:end]
    out: dict[str, str] = {}
    for raw in block.splitlines():
        line = re.sub(r"^\[.*?\]\s*", "", raw).strip()
        if "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip().lower()
        val = val.strip()
        if key in VPN_CREDS_KEYS and val:
            out[key] = val
    return out


def parse_vpn_check(text: str) -> dict[str, str]:
    if not text:
        return {}
    start = text.rfind(VPN_CHECK_BEGIN)
    if start < 0:
        return {}
    rest = text[start + len(VPN_CHECK_BEGIN) :]
    end = rest.find(VPN_CHECK_END)
    block = rest if end < 0 else rest[:end]
    out: dict[str, str] = {}
    for raw in block.splitlines():
        line = re.sub(r"^\[.*?\]\s*", "", raw).strip()
        if "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip().lower()
        val = val.strip()
        if key in VPN_CHECK_KEYS:
            out[key] = val
    return out


def vpn_panel_already(kind: str, info: dict[str, str]) -> bool:
    if kind == "pasarguard":
        return info.get("pasarguard") == "1"
    if kind == "xui":
        return info.get("xui") == "1" and info.get("xui_flavor", "unknown") in ("sanaei", "unknown", "")
    if kind == "xui_classic":
        return info.get("xui") == "1" and info.get("xui_flavor") == "classic"
    return False


def vpn_panel_conflict(kind: str, info: dict[str, str]) -> bool:
    if info.get("xui") != "1":
        return False
    flavor = info.get("xui_flavor") or "unknown"
    if kind == "xui":
        return flavor == "classic"
    if kind == "xui_classic":
        return flavor == "sanaei"
    return False


def vpn_panel_conflict_msg(kind: str, info: dict[str, str]) -> str:
    if kind == "xui":
        return "روی این سرور قبلاً X-UI اصلی نصب شده است. با 3x-ui همزمان نصب نمی‌شود. اول حذف کنید."
    if kind == "xui_classic":
        return "روی این سرور قبلاً 3x-ui سنایی نصب شده است. با X-UI اصلی همزمان نصب نمی‌شود. اول حذف کنید."
    return "نوع دیگری از پنل روی این سرور نصب است."


def vpn_check_summary(info: dict[str, str]) -> dict[str, Any]:
    xui = info.get("xui") == "1"
    pg = info.get("pasarguard") == "1"
    flavor = info.get("xui_flavor") or ""
    return {
        "xui": xui,
        "xui_flavor": flavor,
        "xui_running": info.get("xui_running") == "1",
        "pasarguard": pg,
        "pasarguard_running": info.get("pasarguard_running") == "1",
        "xui_label": "X-UI اصلی" if flavor == "classic" else ("3x-ui سنایی" if xui else ""),
    }


VPN_PANEL_FLAGS = {
    "xui": "--xui-install",
    "xui_classic": "--xui-classic-install",
    "pasarguard": "--pasarguard-install",
}
VPN_PANEL_LABELS = {
    "xui": "3x-ui سنایی",
    "xui_classic": "X-UI اصلی",
    "pasarguard": "پاسارگارد",
}
