from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    pw_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    admin_id INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    csrf TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS login_failures (
    ip TEXT NOT NULL,
    at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_login_failures_ip ON login_failures(ip, at);
CREATE TABLE IF NOT EXISTS servers (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('iran', 'kharej')),
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    username TEXT NOT NULL,
    auth_type TEXT NOT NULL CHECK (auth_type IN ('password', 'key')),
    secret_password TEXT,
    secret_key TEXT,
    secret_passphrase TEXT,
    secret_sudo TEXT,
    hostkey TEXT,
    hostkey_fingerprint TEXT,
    last_check TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tunnels (
    id INTEGER PRIMARY KEY,
    mode TEXT NOT NULL,
    iran_id INTEGER NOT NULL REFERENCES servers(id),
    kharej_id INTEGER NOT NULL REFERENCES servers(id),
    status TEXT NOT NULL,
    iran_iface TEXT,
    kharej_iface TEXT,
    tun_iran_ip TEXT,
    tun_kharej_ip TEXT,
    forward_ports TEXT,
    options TEXT,
    last_job_id INTEGER,
    last_check TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS jobs (
    id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL,
    title TEXT NOT NULL,
    status TEXT NOT NULL,
    steps TEXT NOT NULL DEFAULT '[]',
    log TEXT NOT NULL DEFAULT '',
    server_id INTEGER,
    tunnel_id INTEGER,
    created_at TEXT NOT NULL,
    finished_at TEXT
);
"""

JSON_FIELDS = {"last_check", "steps", "options"}


def utcnow() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class Database:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.execute("PRAGMA busy_timeout=5000")
            self._conn.executescript(SCHEMA)
            cols = {r["name"] for r in self._conn.execute("PRAGMA table_info(tunnels)")}
            if "options" not in cols:
                self._conn.execute("ALTER TABLE tunnels ADD COLUMN options TEXT")
            # Jobs interrupted by a restart can never finish.
            self._conn.execute(
                "UPDATE jobs SET status='failed', finished_at=?, log=log || ? WHERE status IN ('queued','running')",
                (utcnow(), "\n[panel restarted - job aborted]\n"),
            )
            self._conn.execute("UPDATE tunnels SET status='failed' WHERE status IN ('deploying','deleting')")

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    @staticmethod
    def _row(row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        out = dict(row)
        for key in JSON_FIELDS & out.keys():
            raw = out[key]
            out[key] = json.loads(raw) if raw else ([] if key == "steps" else None)
        return out

    def execute(self, sql: str, params: tuple | list = ()) -> sqlite3.Cursor:
        with self._lock:
            return self._conn.execute(sql, params)

    def one(self, sql: str, params: tuple | list = ()) -> dict[str, Any] | None:
        with self._lock:
            return self._row(self._conn.execute(sql, params).fetchone())

    def all(self, sql: str, params: tuple | list = ()) -> list[dict[str, Any]]:
        with self._lock:
            return [self._row(r) for r in self._conn.execute(sql, params).fetchall()]  # type: ignore[misc]

    def insert(self, table: str, values: dict[str, Any]) -> int:
        cols = list(values)
        data = [json.dumps(values[c]) if c in JSON_FIELDS and values[c] is not None else values[c] for c in cols]
        sql = f"INSERT INTO {table} ({', '.join(cols)}) VALUES ({', '.join('?' for _ in cols)})"
        with self._lock:
            return int(self._conn.execute(sql, data).lastrowid)

    def update(self, table: str, row_id: int, values: dict[str, Any]) -> None:
        if not values:
            return
        cols = list(values)
        data = [json.dumps(values[c]) if c in JSON_FIELDS and values[c] is not None else values[c] for c in cols]
        sql = f"UPDATE {table} SET {', '.join(f'{c}=?' for c in cols)} WHERE id=?"
        with self._lock:
            self._conn.execute(sql, [*data, row_id])

    def append_log(self, job_id: int, text: str) -> None:
        with self._lock:
            self._conn.execute("UPDATE jobs SET log = substr(log || ?, -400000) WHERE id=?", (text, job_id))
