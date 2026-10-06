#!/usr/bin/env python3
"""JojoNet monthly license shop — web checkout + crypto wallets + signed JN1 keys."""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

ROOT = Path(__file__).resolve().parent
DATA = Path(os.environ.get("JOJONET_SHOP_DATA") or (ROOT / "data"))
STATIC = ROOT / "static"
PRIV = Path(os.environ.get("JOJONET_LICENSE_PRIVATE_KEY") or (DATA / "private.pem"))
DB = DATA / "shop.db"
CFG = DATA / "shop.json"

DEFAULTS = {
    "monthly_usd": 15,
    "shop_name": "JojoNet",
    "support": "@B_KHANEMAN",
    "wallets": {
        "USDT-TRC20": "",
        "USDT-BEP20": "",
        "BTC": "",
        "TON": "",
        "TRX": "",
    },
}


def utcnow() -> int:
    return int(time.time())


def load_cfg() -> dict:
    DATA.mkdir(parents=True, exist_ok=True)
    if not CFG.exists():
        CFG.write_text(json.dumps(DEFAULTS, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    cfg = json.loads(CFG.read_text(encoding="utf-8"))
    merged = dict(DEFAULTS)
    merged.update(cfg)
    wallets = dict(DEFAULTS["wallets"])
    wallets.update(cfg.get("wallets") or {})
    merged["wallets"] = wallets
    return merged


def db() -> sqlite3.Connection:
    DATA.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    con.execute(
        """CREATE TABLE IF NOT EXISTS orders (
        id TEXT PRIMARY KEY, email TEXT, coin TEXT, address TEXT, amount TEXT,
        usd REAL, status TEXT, txid TEXT, created_at INTEGER, paid_at INTEGER, license_id TEXT)"""
    )
    con.execute(
        """CREATE TABLE IF NOT EXISTS licenses (
        id TEXT PRIMARY KEY, email TEXT, key TEXT, exp INTEGER, created_at INTEGER, order_id TEXT)"""
    )
    con.execute(
        """CREATE TABLE IF NOT EXISTS admin (
        id INTEGER PRIMARY KEY CHECK (id=1), pw TEXT)"""
    )
    con.commit()
    return con


def b64url(raw: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def sign_payload(payload: str) -> str:
    if not PRIV.is_file():
        raise RuntimeError(f"missing private key: {PRIV}")
    pay = DATA / ".pay.tmp"
    sig = DATA / ".sig.tmp"
    pay.write_bytes(payload.encode("utf-8"))
    subprocess.run(
        ["openssl", "pkeyutl", "-sign", "-inkey", str(PRIV), "-rawin", "-in", str(pay), "-out", str(sig)],
        check=True, capture_output=True,
    )
    out = sig.read_bytes()
    pay.unlink(missing_ok=True)
    sig.unlink(missing_ok=True)
    return f"JN1.{b64url(payload.encode('utf-8'))}.{b64url(out)}"


def issue_license(email: str, months: int = 1, order_id: str | None = None) -> dict:
    lid = secrets.token_hex(8)
    exp = utcnow() + max(1, months) * 30 * 86400
    payload = json.dumps(
        {"v": 1, "id": lid, "email": email, "plan": "monthly", "exp": exp},
        separators=(",", ":"),
    )
    key = sign_payload(payload)
    con = db()
    con.execute(
        "INSERT INTO licenses(id,email,key,exp,created_at,order_id) VALUES(?,?,?,?,?,?)",
        (lid, email, key, exp, utcnow(), order_id),
    )
    if order_id:
        con.execute("UPDATE orders SET status=?, paid_at=?, license_id=? WHERE id=?",
                    ("paid", utcnow(), lid, order_id))
    con.commit()
    con.close()
    return {"id": lid, "email": email, "exp": exp, "key": key}


def unique_amount(base: float, oid: str) -> str:
    n = int(hashlib.sha256(oid.encode()).hexdigest()[:6], 16) % 9000 + 1000
    return f"{base + n / 1_000_000:.6f}".rstrip("0").rstrip(".")


def require_admin(request: Request) -> None:
    if not request.session.get("admin"):
        raise HTTPException(401, "admin login required")


def create_app() -> FastAPI:
    load_cfg()
    db().close()
    app = FastAPI(title="JojoNet License Shop", docs_url=None, redoc_url=None)
    secret = os.environ.get("JOJONET_SHOP_SECRET") or hashlib.sha256(
        (str(PRIV) + "jojonet-shop").encode()
    ).hexdigest()
    app.add_middleware(SessionMiddleware, secret_key=secret, same_site="strict", https_only=False)
    if STATIC.is_dir():
        app.mount("/static", StaticFiles(directory=STATIC), name="static")

    @app.get("/", response_class=HTMLResponse)
    def home() -> str:
        return (STATIC / "index.html").read_text(encoding="utf-8")

    @app.get("/api/info")
    def info() -> dict:
        cfg = load_cfg()
        coins = [k for k, v in cfg["wallets"].items() if str(v).strip()]
        return {
            "name": cfg["shop_name"],
            "monthly_usd": cfg["monthly_usd"],
            "plan": "monthly",
            "coins": coins,
            "support": cfg["support"],
        }

    @app.post("/api/orders")
    def create_order(email: str = Form(...), coin: str = Form(...)) -> dict:
        cfg = load_cfg()
        email = email.strip().lower()
        coin = coin.strip()
        if "@" not in email or "." not in email.split("@")[-1]:
            raise HTTPException(422, "ایمیل نامعتبر است")
        addr = (cfg["wallets"].get(coin) or "").strip()
        if not addr:
            raise HTTPException(422, "این رمزارز فعال نیست")
        oid = secrets.token_hex(6)
        amount = unique_amount(float(cfg["monthly_usd"]), oid)
        con = db()
        con.execute(
            "INSERT INTO orders(id,email,coin,address,amount,usd,status,txid,created_at,paid_at,license_id) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (oid, email, coin, addr, amount, float(cfg["monthly_usd"]), "pending", "", utcnow(), 0, ""),
        )
        con.commit()
        con.close()
        return {
            "order_id": oid, "email": email, "coin": coin, "address": addr,
            "amount": amount, "usd": cfg["monthly_usd"],
            "note": "دقیقاً همین مبلغ را واریز کنید تا سفارش شما مشخص شود. بعد TXID را ثبت کنید.",
        }

    @app.get("/api/orders/{oid}")
    def get_order(oid: str) -> dict:
        con = db()
        row = con.execute("SELECT * FROM orders WHERE id=?", (oid,)).fetchone()
        con.close()
        if not row:
            raise HTTPException(404, "سفارش پیدا نشد")
        out = dict(row)
        if out.get("license_id"):
            con = db()
            lic = con.execute("SELECT key,exp FROM licenses WHERE id=?", (out["license_id"],)).fetchone()
            con.close()
            if lic:
                out["key"] = lic["key"]
                out["exp"] = lic["exp"]
        return out

    @app.post("/api/orders/{oid}/txid")
    def set_txid(oid: str, txid: str = Form(...)) -> dict:
        txid = txid.strip()
        if len(txid) < 8:
            raise HTTPException(422, "TXID کوتاه است")
        con = db()
        row = con.execute("SELECT status FROM orders WHERE id=?", (oid,)).fetchone()
        if not row:
            con.close()
            raise HTTPException(404, "سفارش پیدا نشد")
        if row["status"] == "paid":
            con.close()
            return {"ok": True, "status": "paid"}
        con.execute("UPDATE orders SET txid=?, status=? WHERE id=?", (txid, "waiting", oid))
        con.commit()
        con.close()
        return {"ok": True, "status": "waiting"}

    @app.post("/api/admin/login")
    def admin_login(request: Request, password: str = Form(...)) -> dict:
        expected = os.environ.get("JOJONET_SHOP_ADMIN_PASSWORD", "")
        if not expected or not secrets.compare_digest(password, expected):
            raise HTTPException(401, "رمز مدیر اشتباه است")
        request.session["admin"] = True
        return {"ok": True}

    @app.post("/api/admin/logout")
    def admin_logout(request: Request) -> dict:
        request.session.clear()
        return {"ok": True}

    @app.get("/api/admin/orders")
    def admin_orders(request: Request) -> list:
        require_admin(request)
        con = db()
        rows = [dict(r) for r in con.execute("SELECT * FROM orders ORDER BY created_at DESC LIMIT 200")]
        con.close()
        return rows

    @app.post("/api/admin/orders/{oid}/confirm")
    def admin_confirm(request: Request, oid: str, months: int = Form(1)) -> dict:
        require_admin(request)
        con = db()
        row = con.execute("SELECT * FROM orders WHERE id=?", (oid,)).fetchone()
        con.close()
        if not row:
            raise HTTPException(404, "سفارش پیدا نشد")
        if row["status"] == "paid" and row["license_id"]:
            con = db()
            lic = con.execute("SELECT key,exp FROM licenses WHERE id=?", (row["license_id"],)).fetchone()
            con.close()
            return {"ok": True, "key": lic["key"], "exp": lic["exp"]}
        lic = issue_license(row["email"], months=max(1, int(months)), order_id=oid)
        return {"ok": True, **lic}

    @app.post("/api/admin/issue")
    def admin_issue(request: Request, email: str = Form(...), months: int = Form(1)) -> dict:
        require_admin(request)
        return issue_license(email.strip().lower(), months=max(1, int(months)))

    @app.get("/admin", response_class=HTMLResponse)
    def admin_page() -> str:
        return (STATIC / "admin.html").read_text(encoding="utf-8")

    @app.get("/health")
    def health() -> dict:
        return {"ok": True, "has_key": PRIV.is_file()}

    return app


app = create_app()


def main() -> None:
    import uvicorn

    host = os.environ.get("JOJONET_SHOP_HOST", "0.0.0.0")
    port = int(os.environ.get("JOJONET_SHOP_PORT", "2083"))
    uvicorn.run(app, host=host, port=port, server_header=False)


if __name__ == "__main__":
    main()
