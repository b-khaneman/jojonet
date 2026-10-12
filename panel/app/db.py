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
    created_at TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'customer' CHECK (role IN ('owner', 'customer')),
    enabled INTEGER NOT NULL DEFAULT 1,
    expires_at TEXT,
    max_servers INTEGER,
    max_tunnels INTEGER,
    max_relays INTEGER,
    allow_vpn INTEGER NOT NULL DEFAULT 1,
    allow_relay INTEGER NOT NULL DEFAULT 1,
    allow_os_update INTEGER NOT NULL DEFAULT 1,
    allow_term INTEGER NOT NULL DEFAULT 1,
    note TEXT
);
CREATE TABLE IF NOT EXISTS panel_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
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
    created_at TEXT NOT NULL,
    owner_id INTEGER REFERENCES admins(id)
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
    created_at TEXT NOT NULL,
    owner_id INTEGER REFERENCES admins(id)
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
    finished_at TEXT,
    owner_id INTEGER REFERENCES admins(id)
);
CREATE TABLE IF NOT EXISTS relays (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    engine TEXT NOT NULL,
    server_id INTEGER NOT NULL REFERENCES servers(id),
    target TEXT NOT NULL,
    ports TEXT NOT NULL,
    proto TEXT NOT NULL DEFAULT 'both',
    status TEXT NOT NULL,
    last_job_id INTEGER,
    last_check TEXT,
    created_at TEXT NOT NULL,
    owner_id INTEGER REFERENCES admins(id)
);
CREATE TABLE IF NOT EXISTS service_orders (
    id INTEGER PRIMARY KEY,
    customer_id INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected', 'done', 'cancelled')),
    mode TEXT NOT NULL,
    message TEXT,
    iran_json TEXT,
    kharej_json TEXT,
    owner_note TEXT,
    tunnel_id INTEGER REFERENCES tunnels(id),
    created_at TEXT NOT NULL,
    decided_at TEXT
);
CREATE TABLE IF NOT EXISTS tickets (
    id INTEGER PRIMARY KEY,
    customer_id INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    subject TEXT NOT NULL,
    category TEXT NOT NULL CHECK (category IN ('panel', 'tunnel', 'server', 'billing', 'other')),
    status TEXT NOT NULL CHECK (status IN ('open', 'answered', 'closed')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ticket_messages (
    id INTEGER PRIMARY KEY,
    ticket_id INTEGER NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
    author_id INTEGER NOT NULL REFERENCES admins(id),
    body TEXT NOT NULL,
    access_blob TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS wallet_ledger (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    actor_id INTEGER REFERENCES admins(id),
    kind TEXT NOT NULL,
    amount INTEGER NOT NULL,
    balance_after INTEGER NOT NULL,
    note TEXT,
    ref_type TEXT,
    ref_id INTEGER,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS deposit_requests (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    amount INTEGER NOT NULL,
    method TEXT NOT NULL CHECK (method IN ('card', 'crypto')),
    tracking_code TEXT NOT NULL,
    note TEXT,
    tunnel_mode TEXT,
    status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected')),
    owner_note TEXT,
    created_at TEXT NOT NULL,
    decided_at TEXT
);
"""

JSON_FIELDS = {"last_check", "steps", "options", "iran_json", "kharej_json"}

ADMIN_COLUMNS = {
    "role": "TEXT NOT NULL DEFAULT 'customer'",
    "enabled": "INTEGER NOT NULL DEFAULT 1",
    "expires_at": "TEXT",
    "max_servers": "INTEGER",
    "max_tunnels": "INTEGER",
    "max_relays": "INTEGER",
    "allow_vpn": "INTEGER NOT NULL DEFAULT 1",
    "allow_relay": "INTEGER NOT NULL DEFAULT 1",
    "allow_os_update": "INTEGER NOT NULL DEFAULT 1",
    "allow_term": "INTEGER NOT NULL DEFAULT 1",
    "note": "TEXT",
    "wallet_balance": "INTEGER NOT NULL DEFAULT 0",
}
OWNER_TABLES = ("servers", "tunnels", "relays", "jobs")
TABLE_COLUMNS = {
    "tunnels": {
        "iran_iface": "TEXT",
        "kharej_iface": "TEXT",
        "tun_iran_ip": "TEXT",
        "tun_kharej_ip": "TEXT",
        "forward_ports": "TEXT",
        "options": "TEXT",
        "last_job_id": "INTEGER",
        "last_check": "TEXT",
    },
    "jobs": {
        "steps": "TEXT NOT NULL DEFAULT '[]'",
        "log": "TEXT NOT NULL DEFAULT ''",
        "server_id": "INTEGER",
        "tunnel_id": "INTEGER",
        "finished_at": "TEXT",
    },
    "relays": {
        "last_job_id": "INTEGER",
        "last_check": "TEXT",
    },
}


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
            self._migrate()
            # Jobs interrupted by a restart can never finish.
            self._conn.execute(
                "UPDATE jobs SET status='failed', finished_at=?, log=log || ? WHERE status IN ('queued','running')",
                (utcnow(), "\n[panel restarted - job aborted]\n"),
            )
            self._conn.execute("UPDATE tunnels SET status='failed' WHERE status IN ('deploying','deleting')")
            self._conn.execute("UPDATE relays SET status='failed' WHERE status IN ('deploying','deleting')")

    def _migrate(self) -> None:
        def cols(table: str) -> set[str]:
            return {r["name"] for r in self._conn.execute(f"PRAGMA table_info({table})")}

        for table, extras in TABLE_COLUMNS.items():
            have = cols(table)
            for name, decl in extras.items():
                if name not in have:
                    self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")

        admin_cols = cols("admins")
        for name, decl in ADMIN_COLUMNS.items():
            if name not in admin_cols:
                self._conn.execute(f"ALTER TABLE admins ADD COLUMN {name} {decl}")

        for table in OWNER_TABLES:
            if "owner_id" not in cols(table):
                self._conn.execute(f"ALTER TABLE {table} ADD COLUMN owner_id INTEGER REFERENCES admins(id)")

        first = self._conn.execute("SELECT id FROM admins ORDER BY id LIMIT 1").fetchone()
        if first is not None:
            owner = self._conn.execute("SELECT id FROM admins WHERE role='owner' LIMIT 1").fetchone()
            if owner is None:
                self._conn.execute(
                    "UPDATE admins SET role='owner', expires_at=NULL WHERE id=?",
                    (first["id"],),
                )
            oid = (owner or first)["id"]
            for table in OWNER_TABLES:
                self._conn.execute(f"UPDATE {table} SET owner_id=? WHERE owner_id IS NULL", (oid,))

        self._rebuild_relays_without_global_name_unique()
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_servers_owner ON servers(owner_id)")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_tunnels_owner ON tunnels(owner_id)")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_relays_owner ON relays(owner_id)")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_jobs_owner ON jobs(owner_id)")
        self._conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_relays_owner_name ON relays(owner_id, name)")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS service_orders ("
            "id INTEGER PRIMARY KEY, "
            "customer_id INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE, "
            "status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected', 'done', 'cancelled')), "
            "mode TEXT NOT NULL, message TEXT, iran_json TEXT, kharej_json TEXT, owner_note TEXT, "
            "tunnel_id INTEGER REFERENCES tunnels(id), created_at TEXT NOT NULL, decided_at TEXT)"
        )
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS tickets ("
            "id INTEGER PRIMARY KEY, "
            "customer_id INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE, "
            "subject TEXT NOT NULL, "
            "category TEXT NOT NULL CHECK (category IN ('panel', 'tunnel', 'server', 'billing', 'other')), "
            "status TEXT NOT NULL CHECK (status IN ('open', 'answered', 'closed')), "
            "created_at TEXT NOT NULL, updated_at TEXT NOT NULL)"
        )
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS ticket_messages ("
            "id INTEGER PRIMARY KEY, "
            "ticket_id INTEGER NOT NULL REFERENCES tickets(id) ON DELETE CASCADE, "
            "author_id INTEGER NOT NULL REFERENCES admins(id), "
            "body TEXT NOT NULL, access_blob TEXT, created_at TEXT NOT NULL)"
        )
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_orders_customer ON service_orders(customer_id, status)")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_orders_status ON service_orders(status, created_at)")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_tickets_customer ON tickets(customer_id, status)")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_tickets_updated ON tickets(updated_at)")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_ticket_messages_ticket ON ticket_messages(ticket_id, id)")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS wallet_ledger ("
            "id INTEGER PRIMARY KEY, "
            "user_id INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE, "
            "actor_id INTEGER REFERENCES admins(id), "
            "kind TEXT NOT NULL, amount INTEGER NOT NULL, balance_after INTEGER NOT NULL, "
            "note TEXT, ref_type TEXT, ref_id INTEGER, created_at TEXT NOT NULL)"
        )
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS deposit_requests ("
            "id INTEGER PRIMARY KEY, "
            "user_id INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE, "
            "amount INTEGER NOT NULL, "
            "method TEXT NOT NULL CHECK (method IN ('card', 'crypto')), "
            "tracking_code TEXT NOT NULL, note TEXT, tunnel_mode TEXT, "
            "status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected')), "
            "owner_note TEXT, created_at TEXT NOT NULL, decided_at TEXT)"
        )
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_ledger_user ON wallet_ledger(user_id, id)")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_deposits_user ON deposit_requests(user_id, status)")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_deposits_status ON deposit_requests(status, created_at)")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS panel_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        if self._conn.execute("SELECT key FROM panel_settings WHERE key='terms_enabled'").fetchone() is None:
            self._conn.execute("INSERT INTO panel_settings (key, value) VALUES ('terms_enabled', '1')")
        for key, val in (
            ("sell_tunnels_enabled", "0"),
            ("register_enabled", "0"),
            ("payment_card", ""),
            ("payment_wallet_address", ""),
            ("payment_note", ""),
            ("wallet_currency", "تومان"),
            ("tunnel_prices_json", "{}"),
        ):
            if self._conn.execute("SELECT key FROM panel_settings WHERE key=?", (key,)).fetchone() is None:
                self._conn.execute("INSERT INTO panel_settings (key, value) VALUES (?, ?)", (key, val))

    def _rebuild_relays_without_global_name_unique(self) -> None:
        row = self._conn.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='relays'").fetchone()
        sql = (row[0] or "") if row else ""
        if "name TEXT NOT NULL UNIQUE" not in sql and "name TEXT UNIQUE" not in sql:
            return
        old_cols = [r["name"] for r in self._conn.execute("PRAGMA table_info(relays)")]
        self._conn.execute("PRAGMA foreign_keys=OFF")
        self._conn.execute("ALTER TABLE relays RENAME TO relays_old")
        self._conn.execute(
            """
            CREATE TABLE relays (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                engine TEXT NOT NULL,
                server_id INTEGER NOT NULL REFERENCES servers(id),
                target TEXT NOT NULL,
                ports TEXT NOT NULL,
                proto TEXT NOT NULL DEFAULT 'both',
                status TEXT NOT NULL,
                last_job_id INTEGER,
                last_check TEXT,
                created_at TEXT NOT NULL,
                owner_id INTEGER REFERENCES admins(id)
            )
            """
        )
        new_cols = {r["name"] for r in self._conn.execute("PRAGMA table_info(relays)")}
        shared = [c for c in old_cols if c in new_cols]
        self._conn.execute(
            f"INSERT INTO relays ({', '.join(shared)}) SELECT {', '.join(shared)} FROM relays_old"
        )
        self._conn.execute("DROP TABLE relays_old")
        self._conn.execute("PRAGMA foreign_keys=ON")

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
