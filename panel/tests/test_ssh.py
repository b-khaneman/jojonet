"""RemoteSession against a real in-process asyncssh server (password auth, sudo, staging, host keys)."""
from __future__ import annotations

import asyncio
import shlex

import asyncssh
import pytest

from app.sshclient import HostKeyMismatch, RemoteSession, ServerCreds, SSHError

USER, PASSWORD, SUDO = "deploy", "ssh-pass-123", "sudo-pass-456"


class Server(asyncssh.SSHServer):
    def begin_auth(self, username):
        return True

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        return username == USER and password == PASSWORD


class Remote:
    def __init__(self, root: bool):
        self.root = root
        self.files: dict[str, bytes] = {}

    def run_script(self, script: str, stdin: bytes) -> tuple[int, bytes]:
        if script.startswith('exec 0<"$0"; rm -f -- "$0"; '):
            raise AssertionError("staged scripts are handled by the caller")
        if script == "id -u":
            return 0, b"0\n"
        if script == "cat":
            return 0, stdin
        if script == "colors":
            return 0, b"\x1b[0;32m[+]\x1b[0m line1 " + SUDO.encode() + b"\nline2\r\n"
        if script == "fail":
            return 3, b"boom\n"
        return 127, b"unknown\n"

    def _unwrap_bash(self, cmd: str) -> str | None:
        marker = "bash --noprofile --norc -c "
        if marker in cmd:
            parts = shlex.split(cmd)
            idx = parts.index("-c")
            return parts[idx + 1]
        if cmd.startswith("bash -c "):
            return shlex.split(cmd)[2]
        return None

    async def handle(self, process: asyncssh.SSHServerProcess) -> None:
        cmd = process.command or ""
        stdin = await process.stdin.read()
        rc, out = 0, b""
        is_sudo = cmd.startswith("sudo ")
        inner = None if is_sudo else self._unwrap_bash(cmd)
        if not is_sudo and (inner == "id -u" or cmd == "id -u"):
            out = b"0\n" if self.root else b"1000\n"
        elif not is_sudo and (inner == "umask 077; mktemp /tmp/jnin.XXXXXXXX" or cmd == "umask 077; mktemp /tmp/jnin.XXXXXXXX"):
            name = f"/tmp/jnin.{len(self.files):08d}"
            self.files[name] = b""
            out = (name + "\n").encode()
        elif not is_sudo and ((inner and inner.startswith("cat > ")) or cmd.startswith("cat > ")):
            target = shlex.split(inner or cmd)[2]
            self.files[target] = stdin
        elif not is_sudo and (inner == "hang" or cmd == "hang"):
            await asyncio.sleep(30)
        elif is_sudo or "bash --noprofile --norc -c " in cmd or cmd.startswith("bash -c ") or cmd.startswith("HISTFILE="):
            parts = shlex.split(cmd)
            if "HISTFILE=/dev/null" not in cmd and not cmd.startswith("bash -c "):
                rc, out = 127, b"missing hist wrap\n"
                process.stdout.write(out)
                process.exit(rc)
                return
            idx = parts.index("-c")
            script, extra = parts[idx + 1], parts[idx + 2:]
            if parts[0] == "sudo" and parts[1] == "-S":
                pw, _, stdin = stdin.partition(b"\n")
                if pw.decode() != SUDO:
                    rc, out = 1, b"Sorry, try again.\n"
                    process.stdout.write(out)
                    process.exit(rc)
                    return
            elif parts[0] == "sudo":
                rc, out = 1, b"sudo: a password is required\n"
                process.stdout.write(out)
                process.exit(rc)
                return
            # Ignore post-command history scrub (long timeout path).
            if "sed -i" in script and "jojonet" in script:
                process.stdout.write(b"")
                process.exit(0)
                return
            prefix = 'exec 0<"$0"; rm -f -- "$0"; '
            if script.startswith(prefix):
                stdin = self.files.pop(extra[0])
                script = script[len(prefix):]
            rc, out = self.run_script(script, stdin)
        else:
            rc, out = 127, b"unknown command\n"
        process.stdout.write(out)
        process.exit(rc)


@pytest.fixture()
def ssh_server():
    loop = asyncio.new_event_loop()
    host_key = asyncssh.generate_private_key("ssh-ed25519")
    state = {}

    def start(root: bool):
        remote = Remote(root)
        server = loop.run_until_complete(
            asyncssh.create_server(Server, "127.0.0.1", 0, server_host_keys=[host_key], process_factory=remote.handle,
                                   encoding=None)
        )
        state["server"] = server
        return server.sockets[0].getsockname()[1], remote

    yield loop, start, host_key
    if "server" in state:
        state["server"].close()
        loop.run_until_complete(state["server"].wait_closed())
    pending = asyncio.all_tasks(loop)
    for task in pending:
        task.cancel()
    if pending:
        loop.run_until_complete(asyncio.wait(pending))
    loop.close()


def creds(port, **kw) -> ServerCreds:
    base = dict(host="127.0.0.1", port=port, username=USER, password=PASSWORD, sudo_password=SUDO, secrets=[PASSWORD, SUDO])
    base.update(kw)
    return ServerCreds(**base)


def test_sudo_session_staging_streaming_and_masking(ssh_server):
    loop, start, host_key = ssh_server
    port, remote = start(root=False)

    async def scenario():
        lines: list[str] = []
        async with RemoteSession(creds(port), connect_timeout=5) as s:
            assert not s.is_root
            assert s.hostkey and s.hostkey.split()[1] == host_key.export_public_key("openssh").decode().split()[1]
            assert (await s.run_root("id -u")).stdout.strip() == "0"
            res = await s.run_root("cat", input_data=b"payload-\x00-bytes")
            assert res.ok and res.stdout == "payload-\x00-bytes"
            assert remote.files == {}
            res = await s.run_root("colors", on_line=lines.append)
            assert res.ok
            res = await s.run_root("fail")
            assert res.rc == 3
            with pytest.raises(SSHError):
                await s.run_raw("hang", timeout=1)
        assert lines == ["[+] line1 ******", "line2"]

    loop.run_until_complete(scenario())


def test_root_session_runs_without_sudo(ssh_server):
    loop, start, _ = ssh_server
    port, _ = start(root=True)

    async def scenario():
        async with RemoteSession(creds(port, sudo_password=None), connect_timeout=5) as s:
            assert s.is_root
            assert (await s.run_root("cat", input_data="x")).stdout == "x"

    loop.run_until_complete(scenario())


def test_wrong_password_wrong_sudo_and_hostkey_mismatch(ssh_server):
    loop, start, _ = ssh_server
    port, _ = start(root=False)

    async def scenario():
        with pytest.raises(SSHError, match="احراز هویت"):
            await RemoteSession(creds(port, password="bad"), connect_timeout=5).connect()
        with pytest.raises(SSHError, match="root"):
            await RemoteSession(creds(port, sudo_password="bad"), connect_timeout=5).connect()
        with pytest.raises(SSHError, match="root"):
            await RemoteSession(creds(port, sudo_password=None), connect_timeout=5).connect()
        other = asyncssh.generate_private_key("ssh-ed25519").export_public_key("openssh").decode()
        with pytest.raises(HostKeyMismatch):
            await RemoteSession(creds(port, hostkey=other), connect_timeout=5).connect()
        with pytest.raises(SSHError, match="کلید خصوصی"):
            await RemoteSession(creds(port, private_key="not a key"), connect_timeout=5).connect()

    loop.run_until_complete(scenario())


def test_unreachable_port():
    async def scenario():
        with pytest.raises(SSHError):
            await RemoteSession(creds(1), connect_timeout=2).connect()

    asyncio.run(scenario())
