from __future__ import annotations

import asyncio
import hashlib
import base64
import os
import shlex
import socket
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

import asyncssh


def local_ip_addresses() -> set[str]:
    """Best-effort set of IPs that belong to this host (IPv4/IPv6)."""
    ips: set[str] = {"127.0.0.1", "::1"}
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None):
            ips.add(info[4][0])
    except OSError:
        pass
    for family, probe in ((socket.AF_INET, "1.1.1.1"), (socket.AF_INET6, "2606:4700:4700::1111")):
        try:
            s = socket.socket(family, socket.SOCK_DGRAM)
            try:
                s.connect((probe, 80))
                ips.add(s.getsockname()[0])
            finally:
                s.close()
        except OSError:
            continue
    return ips


def resolve_connect_host(host: str) -> str:
    """When the panel targets its own public IP, prefer loopback.

    OpenSSH 9.8+ PerSourcePenalties can lock out the host's public address after a brief
    auth/connect storm (common when the panel and a managed server share one VPS). Hairpin
    NAT to the public IP is also less reliable than 127.0.0.1.
    """
    host = (host or "").strip()
    if not host or host in {"localhost", "127.0.0.1", "::1"}:
        return "127.0.0.1" if host != "::1" else "::1"
    try:
        dests = {info[4][0] for info in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)}
    except OSError:
        return host
    local = local_ip_addresses()
    if not (dests & local):
        return host
    if any(":" not in ip for ip in dests):
        return "127.0.0.1"
    return "::1"

LineCallback = Callable[[str], Awaitable[None] | None]

# Keep panel remote commands out of interactive bash history on the server.
_HIST_ENV = "HISTFILE=/dev/null HISTSIZE=0"
# Scrub after every root command (not only long ones) so short install/checks leave no traces.
_SCRUB_AFTER_SEC = 0
_SHELL_CMD = "env HISTFILE=/dev/null HISTSIZE=0 HISTFILESIZE=0 HISTCONTROL=ignorespace bash --norc --noprofile -i"
_SCRUB_HISTORY = (
    "for f in /root/.bash_history \"$HOME/.bash_history\"; do "
    "[ -n \"$f\" ] && [ -f \"$f\" ] && [ -w \"$f\" ] || continue; "
    "sed -i "
    "-e '/jojonet/d' "
    "-e '/jojonet-panel/d' "
    "-e '/\\/etc\\/jojonet/d' "
    "-e '/\\/var\\/lib\\/jojonet/d' "
    "-e '/ip tunnel/d' "
    "-e '/tun-server/d' "
    "-e '/tun-client/d' "
    "-e '/nft.*jojonet/d' "
    "-e '/GRETun/d' "
    "-e '/LocalTun/d' "
    "-e '/jojonet-run/d' "
    "-e '/paqet/d' "
    "-e '/vxlan/d' "
    "-e '/udp2raw/d' "
    "-e '/hysteria/d' "
    "-e '/rathole/d' "
    "-e '/wstunnel/d' "
    "-e '/dnstt/d' "
    "-e '/pingtunnel/d' "
    "-e '/wireguard/d' "
    "-e '/\\<wg\\>/d' "
    "-e '/xray/d' "
    "-e '/dokodemo/d' "
    "-e '/spoof/d' "
    "-e '/6to4/d' "
    "-e '/gre6/d' "
    "-e '/ipip6/d' "
    "\"$f\" 2>/dev/null || true; "
    "done; "
    "history -c 2>/dev/null || true; "
    "history -w 2>/dev/null || true"
)


def _bash_c(script: str, *, via_sudo: bool = False) -> str:
    # sudo treats the first token as the executable; use env so HISTFILE is not argv0.
    if via_sudo:
        return "env HISTFILE=/dev/null HISTSIZE=0 bash --noprofile --norc -c " + shlex.quote(script)
    return f"{_HIST_ENV} bash --noprofile --norc -c " + shlex.quote(script)


def _already_hist_wrapped(command: str) -> bool:
    return (
        command.startswith("HISTFILE=")
        or command.startswith("env HISTFILE=")
        or "bash --noprofile --norc" in command
    )


class SSHError(Exception):
    """Human-readable (Persian) SSH failure."""


class HostKeyMismatch(SSHError):
    pass


@dataclass
class ServerCreds:
    host: str
    port: int
    username: str
    password: str | None = None
    private_key: str | None = None
    key_passphrase: str | None = None
    sudo_password: str | None = None
    hostkey: str | None = None
    secrets: list[str] = field(default_factory=list)


@dataclass
class CmdResult:
    rc: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.rc == 0


def fingerprint(public_key_openssh: str) -> str:
    parts = public_key_openssh.split()
    blob = base64.b64decode(parts[1]) if len(parts) > 1 else public_key_openssh.encode()
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


class _PinnedClient(asyncssh.SSHClient):
    def __init__(self, expected: str | None):
        self.expected = expected
        self.seen: str | None = None

    def validate_host_public_key(self, host, addr, port, key) -> bool:  # noqa: ANN001
        self.seen = key.export_public_key("openssh").decode().strip()
        if self.expected is None:
            return True
        return _key_body(self.seen) == _key_body(self.expected)


def _key_body(openssh: str) -> str:
    parts = openssh.split()
    return " ".join(parts[:2])


class RemoteSession:
    """One SSH connection; runs commands as root (directly or through sudo)."""

    def __init__(self, creds: ServerCreds, connect_timeout: int = 15):
        self.creds = creds
        self.connect_timeout = connect_timeout
        self.conn: asyncssh.SSHClientConnection | None = None
        self.proc: asyncssh.SSHClientProcess | None = None
        self.is_root = False
        self.hostkey: str | None = None

    def mask(self, text: str) -> str:
        for secret in self.creds.secrets:
            if secret and len(secret) >= 4:
                text = text.replace(secret, "******")
        return text

    async def __aenter__(self) -> "RemoteSession":
        await self.connect()
        return self

    async def __aexit__(self, *exc) -> None:  # noqa: ANN002
        await self.close()

    async def _open_conn(self) -> None:
        c = self.creds
        connect_host = resolve_connect_host(c.host)
        keys = None
        if c.private_key:
            try:
                keys = [asyncssh.import_private_key(c.private_key, c.key_passphrase or None)]
            except (asyncssh.KeyImportError, ValueError) as exc:
                raise SSHError(f"کلید خصوصی SSH نامعتبر است یا passphrase اشتباه است ({exc})") from exc
        last_exc: BaseException | None = None
        for attempt in range(3):
            client = _PinnedClient(c.hostkey)
            try:
                self.conn, _ = await asyncio.wait_for(
                    asyncssh.create_connection(
                        lambda: client,
                        connect_host,
                        port=c.port,
                        username=c.username,
                        password=c.password if not keys else None,
                        client_keys=keys,
                        # Empty trust lists (not None) force validate_host_public_key() before authentication.
                        known_hosts=([], [], []),
                        agent_path=None,
                        preferred_auth="publickey" if keys else "password,keyboard-interactive",
                        keepalive_interval=20,
                        login_timeout=self.connect_timeout,
                    ),
                    timeout=self.connect_timeout + 5,
                )
                if client.seen is None:
                    await self.close()
                    raise SSHError("کلید هاست سرور دریافت نشد")
                self.hostkey = client.seen
                return
            except asyncssh.HostKeyNotVerifiable as exc:
                raise HostKeyMismatch(
                    "کلید هاست سرور تغییر کرده است (احتمال حمله MITM یا نصب مجدد سیستم‌عامل). "
                    "اگر مطمئن هستید، در ویرایش سرور «بازنشانی کلید هاست» را بزنید."
                ) from exc
            except asyncssh.PermissionDenied as exc:
                raise SSHError("احراز هویت SSH ناموفق بود (نام کاربری/رمز یا کلید اشتباه است)") from exc
            except (asyncio.TimeoutError, TimeoutError) as exc:
                last_exc = exc
            except (OSError, asyncssh.Error) as exc:
                last_exc = exc
            await self.close()
            if attempt < 2:
                await asyncio.sleep(1.5 * (attempt + 1))
        assert last_exc is not None
        if isinstance(last_exc, (asyncio.TimeoutError, TimeoutError)):
            raise SSHError(f"اتصال به {c.host}:{c.port} در زمان مقرر برقرار نشد") from last_exc
        raise SSHError(f"اتصال SSH به {c.host}:{c.port} ناموفق بود: {last_exc}") from last_exc

    async def connect(self) -> None:
        await self._open_conn()
        try:
            res = await self.run_raw("id -u")
            self.is_root = res.stdout.strip() == "0"
            if not self.is_root:
                probe = await self.run_root("id -u", timeout=30)
                if probe.stdout.strip() != "0":
                    detail = self.mask((probe.stderr or probe.stdout).strip())[:200]
                    raise SSHError(
                        "کاربر SSH دسترسی root ندارد؛ از root استفاده کنید یا رمز sudo را درست وارد کنید"
                        + (f" ({detail})" if detail else "")
                    )
        except BaseException:
            await self.close()
            raise

    async def connect_plain(self) -> None:
        await self._open_conn()

    async def start_shell(self, cols: int = 80, rows: int = 24) -> Any:
        if self.conn is None:
            raise SSHError("اتصال SSH برقرار نیست")
        cols = max(20, min(int(cols or 80), 300))
        rows = max(8, min(int(rows or 24), 120))
        try:
            # Prefer a history-disabled bash; fall back to the account default shell.
            try:
                self.proc = await self.conn.create_process(
                    _SHELL_CMD,
                    term_type="xterm-256color",
                    term_size=(cols, rows),
                    encoding=None,
                )
            except asyncssh.Error:
                self.proc = await self.conn.create_process(
                    term_type="xterm-256color",
                    term_size=(cols, rows),
                    encoding=None,
                )
        except asyncssh.Error as exc:
            raise SSHError(f"باز کردن شل تعاملی ناموفق بود: {exc}") from exc
        return self.proc

    def resize_shell(self, cols: int, rows: int) -> None:
        if self.proc is None:
            return
        cols = max(20, min(int(cols or 80), 300))
        rows = max(8, min(int(rows or 24), 120))
        try:
            self.proc.change_terminal_size(cols, rows)
        except Exception:
            pass

    async def close(self) -> None:
        proc = self.proc
        self.proc = None
        if proc is not None:
            try:
                proc.close()
            except Exception:
                pass
        if self.conn is not None:
            # Scrub while the connection is still open (interactive terminal / session end).
            await self._scrub_history()
            self.conn.close()
            try:
                await asyncio.wait_for(self.conn.wait_closed(), timeout=5)
            except (asyncio.TimeoutError, TimeoutError):
                pass
            self.conn = None

    async def _scrub_history(self) -> None:
        if os.environ.get("JOJONET_CLEAR_HISTORY", "1") == "0":
            return
        try:
            await self.run_raw(_bash_c(_SCRUB_HISTORY), timeout=20, wrap=False)
        except SSHError:
            pass

    async def run_raw(
        self,
        command: str,
        input_data: bytes | str | None = None,
        timeout: int = 120,
        on_line: LineCallback | None = None,
        *,
        wrap: bool = True,
        scrub: bool = False,
    ) -> CmdResult:
        if self.conn is None:
            raise SSHError("اتصال SSH برقرار نیست")
        if wrap and not _already_hist_wrapped(command):
            command = _bash_c(command)
        try:
            proc = await self.conn.create_process(command, encoding=None, stderr=asyncssh.STDOUT if on_line else asyncssh.PIPE)
        except asyncssh.Error as exc:
            raise SSHError(f"اجرای فرمان ناموفق بود: {exc}") from exc
        out_chunks: list[bytes] = []
        err_chunks: list[bytes] = []

        async def feed() -> None:
            if input_data is not None:
                proc.stdin.write(input_data.encode() if isinstance(input_data, str) else input_data)
            proc.stdin.write_eof()

        async def pump_stdout() -> None:
            buf = b""
            while True:
                chunk = await proc.stdout.read(4096)
                if not chunk:
                    break
                out_chunks.append(chunk)
                if on_line:
                    buf += chunk
                    while b"\n" in buf:
                        line, buf = buf.split(b"\n", 1)
                        await _emit(on_line, self.mask(_clean(line)))
            if on_line and buf:
                await _emit(on_line, self.mask(_clean(buf)))

        async def pump_stderr() -> None:
            if on_line:
                return
            while True:
                chunk = await proc.stderr.read(4096)
                if not chunk:
                    break
                err_chunks.append(chunk)

        try:
            await asyncio.wait_for(asyncio.gather(feed(), pump_stdout(), pump_stderr(), proc.wait()), timeout=timeout)
        except (asyncio.TimeoutError, TimeoutError) as exc:
            proc.kill()
            raise SSHError(f"فرمان پس از {timeout} ثانیه پاسخ نداد (timeout)") from exc
        except (asyncssh.Error, BrokenPipeError, ConnectionError) as exc:
            raise SSHError(f"ارتباط SSH حین اجرای فرمان قطع شد: {exc}") from exc
        rc = proc.exit_status if proc.exit_status is not None else 255
        result = CmdResult(
            rc=rc,
            stdout=b"".join(out_chunks).decode("utf-8", "replace"),
            stderr=self.mask(b"".join(err_chunks).decode("utf-8", "replace")),
        )
        if scrub:
            await self._scrub_history()
        return result

    async def run_root(
        self,
        script: str,
        input_data: bytes | str | None = None,
        timeout: int = 120,
        on_line: LineCallback | None = None,
    ) -> CmdResult:
        """Run a bash script as root. stdin of the script is input_data (if any)."""
        do_scrub = timeout >= _SCRUB_AFTER_SEC
        if self.is_root:
            return await self.run_raw(_bash_c(script), input_data, timeout, on_line, wrap=False, scrub=do_scrub)
        staged = ""
        if input_data is not None:
            mk = await self.run_raw("umask 077; mktemp /tmp/jnin.XXXXXXXX")
            staged = mk.stdout.strip()
            if not mk.ok or not staged.startswith("/tmp/jnin."):
                raise SSHError("ساخت فایل موقت روی سرور ناموفق بود")
            put = await self.run_raw("cat > " + shlex.quote(staged), input_data, timeout=120)
            if not put.ok:
                raise SSHError("انتقال داده به سرور ناموفق بود")
            script = 'exec 0<"$0"; rm -f -- "$0"; ' + script
        inner = _bash_c(script, via_sudo=True) + (" " + shlex.quote(staged) if staged else "")
        if self.creds.sudo_password:
            return await self.run_raw(
                "sudo -S -p '' -k " + inner, self.creds.sudo_password + "\n", timeout, on_line, wrap=False, scrub=do_scrub
            )
        return await self.run_raw("sudo -n " + inner, None, timeout, on_line, wrap=False, scrub=do_scrub)


def _clean(raw: bytes) -> str:
    text = raw.decode("utf-8", "replace").rstrip("\r")
    # Strip ANSI colour codes from jojonet output.
    out = []
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "\x1b" and i + 1 < len(text) and text[i + 1] == "[":
            j = i + 2
            while j < len(text) and not ("@" <= text[j] <= "~"):
                j += 1
            i = j + 1
            continue
        if ch == "\r":
            i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


async def _emit(cb: LineCallback, line: str) -> None:
    res = cb(line)
    if asyncio.iscoroutine(res):
        await res
