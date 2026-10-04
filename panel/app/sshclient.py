from __future__ import annotations

import asyncio
import hashlib
import base64
import shlex
from dataclasses import dataclass, field
from typing import Awaitable, Callable

import asyncssh

LineCallback = Callable[[str], Awaitable[None] | None]


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

    async def connect(self) -> None:
        c = self.creds
        keys = None
        if c.private_key:
            try:
                keys = [asyncssh.import_private_key(c.private_key, c.key_passphrase or None)]
            except (asyncssh.KeyImportError, ValueError) as exc:
                raise SSHError(f"کلید خصوصی SSH نامعتبر است یا passphrase اشتباه است ({exc})") from exc
        client = _PinnedClient(c.hostkey)
        try:
            self.conn, _ = await asyncio.wait_for(
                asyncssh.create_connection(
                    lambda: client,
                    c.host,
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
        except asyncssh.HostKeyNotVerifiable as exc:
            raise HostKeyMismatch(
                "کلید هاست سرور تغییر کرده است (احتمال حمله MITM یا نصب مجدد سیستم‌عامل). "
                "اگر مطمئن هستید، در ویرایش سرور «بازنشانی کلید هاست» را بزنید."
            ) from exc
        except asyncssh.PermissionDenied as exc:
            raise SSHError("احراز هویت SSH ناموفق بود (نام کاربری/رمز یا کلید اشتباه است)") from exc
        except (asyncio.TimeoutError, TimeoutError) as exc:
            raise SSHError(f"اتصال به {c.host}:{c.port} در زمان مقرر برقرار نشد") from exc
        except (OSError, asyncssh.Error) as exc:
            raise SSHError(f"اتصال SSH به {c.host}:{c.port} ناموفق بود: {exc}") from exc
        try:
            if client.seen is None:
                raise SSHError("کلید هاست سرور دریافت نشد")
            self.hostkey = client.seen
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

    async def close(self) -> None:
        if self.conn is not None:
            self.conn.close()
            try:
                await asyncio.wait_for(self.conn.wait_closed(), timeout=5)
            except (asyncio.TimeoutError, TimeoutError):
                pass
            self.conn = None

    async def run_raw(
        self,
        command: str,
        input_data: bytes | str | None = None,
        timeout: int = 120,
        on_line: LineCallback | None = None,
    ) -> CmdResult:
        if self.conn is None:
            raise SSHError("اتصال SSH برقرار نیست")
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
        return CmdResult(
            rc=rc,
            stdout=b"".join(out_chunks).decode("utf-8", "replace"),
            stderr=self.mask(b"".join(err_chunks).decode("utf-8", "replace")),
        )

    async def run_root(
        self,
        script: str,
        input_data: bytes | str | None = None,
        timeout: int = 120,
        on_line: LineCallback | None = None,
    ) -> CmdResult:
        """Run a bash script as root. stdin of the script is input_data (if any)."""
        if self.is_root:
            return await self.run_raw("bash -c " + shlex.quote(script), input_data, timeout, on_line)
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
        inner = "bash -c " + shlex.quote(script) + (" " + shlex.quote(staged) if staged else "")
        if self.creds.sudo_password:
            return await self.run_raw("sudo -S -p '' -k " + inner, self.creds.sudo_password + "\n", timeout, on_line)
        return await self.run_raw("sudo -n " + inner, None, timeout, on_line)


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
