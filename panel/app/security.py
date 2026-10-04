from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import time
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_MAXMEM = 128 * SCRYPT_N * SCRYPT_R * 2

LOGIN_WINDOW = 300.0
LOGIN_MAX_FAILURES = 5


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, maxmem=SCRYPT_MAXMEM, dklen=32)
    return "scrypt${}${}${}${}${}".format(
        SCRYPT_N, SCRYPT_R, SCRYPT_P, base64.b64encode(salt).decode(), base64.b64encode(dk).decode()
    )


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt_b64, dk_b64 = stored.split("$")
        if algo != "scrypt":
            return False
        n_i, r_i, p_i = int(n), int(r), int(p)
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(dk_b64)
        dk = hashlib.scrypt(
            password.encode(), salt=salt, n=n_i, r=r_i, p=p_i, maxmem=128 * n_i * r_i * 2, dklen=len(expected)
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(dk, expected)


# Equalizes timing between "unknown user" and "wrong password".
DUMMY_HASH = hash_password(secrets.token_urlsafe(16))


def new_token() -> str:
    return secrets.token_urlsafe(32)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def random_password(length: int = 16) -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789"
    return "".join(secrets.choice(alphabet) for _ in range(length))


class Vault:
    """Encrypts SSH secrets at rest. The key lives next to the DB (0600) or in JOJONET_PANEL_VAULT_KEY."""

    def __init__(self, key_path: Path):
        env_key = os.environ.get("JOJONET_PANEL_VAULT_KEY", "").strip()
        if env_key:
            key = env_key.encode()
        else:
            key_path = Path(key_path)
            if key_path.exists():
                key = key_path.read_bytes().strip()
            else:
                key_path.parent.mkdir(parents=True, exist_ok=True)
                key = Fernet.generate_key()
                fd = os.open(str(key_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as fh:
                    fh.write(key + b"\n")
        self._fernet = Fernet(key)
        self.fingerprint = hashlib.sha256(key).hexdigest()[:16]

    def encrypt(self, value: str | None) -> str | None:
        if value is None or value == "":
            return None
        return self._fernet.encrypt(value.encode()).decode()

    def decrypt(self, value: str | None) -> str | None:
        if not value:
            return None
        try:
            return self._fernet.decrypt(value.encode()).decode()
        except InvalidToken as exc:
            raise ValueError("vault key mismatch - cannot decrypt stored secret") from exc


def login_allowed(db, ip: str) -> bool:
    cutoff = time.time() - LOGIN_WINDOW
    db.execute("DELETE FROM login_failures WHERE at < ?", (cutoff,))
    row = db.one("SELECT COUNT(*) AS n FROM login_failures WHERE ip=? AND at>=?", (ip, cutoff))
    return (row or {"n": 0})["n"] < LOGIN_MAX_FAILURES


def record_login_failure(db, ip: str) -> None:
    db.execute("INSERT INTO login_failures (ip, at) VALUES (?, ?)", (ip, time.time()))


def clear_login_failures(db, ip: str) -> None:
    db.execute("DELETE FROM login_failures WHERE ip=?", (ip,))
