from __future__ import annotations

import argparse
import getpass
import os
import sys

from . import PANEL_VERSION
from .config import load_settings, saved_listen_port
from .db import Database, utcnow
from .security import Vault, hash_password, random_password
from .validators import USER_RE


def cmd_set_admin(args: argparse.Namespace) -> int:
    settings = load_settings()
    username = (args.username or "admin").strip()
    if not USER_RE.fullmatch(username) or username.endswith("$"):
        print("invalid username", file=sys.stderr)
        return 2
    if args.random:
        password = random_password(16)
    elif args.password_stdin:
        password = sys.stdin.readline().rstrip("\r\n")
    else:
        password = getpass.getpass("New password: ")
        if password != getpass.getpass("Repeat: "):
            print("passwords do not match", file=sys.stderr)
            return 2
    if len(password) < 10:
        print("password must be at least 10 characters", file=sys.stderr)
        return 2
    db = Database(settings.db_path)
    try:
        pw_hash = hash_password(password)
        row = db.one("SELECT id FROM admins ORDER BY id LIMIT 1")
        if row:
            db.update("admins", row["id"], {"username": username, "pw_hash": pw_hash})
            db.execute("DELETE FROM sessions")
        else:
            db.insert("admins", {
                "username": username, "pw_hash": pw_hash, "created_at": utcnow(),
                "role": "owner", "enabled": 1,
            })
    finally:
        db.close()
    if args.random:
        print(f"username: {username}")
        print(f"password: {password}")
    else:
        print(f"admin '{username}' saved")
    return 0


def cmd_has_admin(_: argparse.Namespace) -> int:
    settings = load_settings()
    if not settings.db_path.exists():
        return 1
    db = Database(settings.db_path)
    try:
        return 0 if db.one("SELECT id FROM admins LIMIT 1") else 1
    finally:
        db.close()


def cmd_show_key(_: argparse.Namespace) -> int:
    settings = load_settings()
    vault = Vault(settings.vault_key_path)
    print(f"vault key fingerprint: {vault.fingerprint}")
    print(f"vault key file: {settings.vault_key_path}")
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    settings = load_settings()
    host = args.host or settings.host
    port = saved_listen_port(settings.data_dir) or args.port or settings.port
    cert = args.cert if args.cert is not None else settings.cert
    key = args.key if args.key is not None else settings.key
    if bool(cert) != bool(key):
        print("--cert and --key must be given together", file=sys.stderr)
        return 2
    if cert and not (os.path.isfile(cert) and os.path.isfile(key)):
        print(f"TLS files not found: {cert} / {key}", file=sys.stderr)
        return 2
    if not cert and settings.secure_cookies:
        print("refusing to serve without TLS (set JOJONET_PANEL_SECURE_COOKIES=0 for local testing only)", file=sys.stderr)
        return 2
    from .main import create_app

    uvicorn.run(
        create_app(settings),
        host=host,
        port=port,
        ssl_certfile=cert or None,
        ssl_keyfile=key or None,
        proxy_headers=settings.trusted_proxy,
        forwarded_allow_ips="127.0.0.1" if settings.trusted_proxy else None,
        server_header=False,
        # Reusing the TLS connection between clicks saves a full handshake per request on high-latency links.
        timeout_keep_alive=65,
        log_level="info",
        timeout_graceful_shutdown=5,
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="jojonet-panel", description=f"JojoNet Panel {PANEL_VERSION}")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve")
    s.add_argument("--host")
    s.add_argument("--port", type=int)
    s.add_argument("--cert")
    s.add_argument("--key")
    s.set_defaults(func=cmd_serve)
    a = sub.add_parser("set-admin")
    a.add_argument("--username")
    g = a.add_mutually_exclusive_group()
    g.add_argument("--random", action="store_true")
    g.add_argument("--password-stdin", action="store_true")
    a.set_defaults(func=cmd_set_admin)
    sub.add_parser("has-admin").set_defaults(func=cmd_has_admin)
    sub.add_parser("show-key").set_defaults(func=cmd_show_key)
    sub.add_parser("version").set_defaults(func=lambda _: print(PANEL_VERSION) or 0)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args) or 0)


if __name__ == "__main__":
    raise SystemExit(main())
