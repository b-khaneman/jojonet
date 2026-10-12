"""Wallet balance, deposits, and per-tunnel pricing."""

from __future__ import annotations

import json
from typing import Any

from .db import Database, utcnow
from .validators import MODES

DEFAULT_CURRENCY = "تومان"


def setting(db: Database, key: str, default: str = "") -> str:
    row = db.one("SELECT value FROM panel_settings WHERE key=?", (key,))
    return str(row["value"]) if row else default


def set_setting(db: Database, key: str, value: str) -> None:
    db.execute(
        "INSERT INTO panel_settings (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, value),
    )


def sell_enabled(db: Database) -> bool:
    return setting(db, "sell_tunnels_enabled", "0") == "1"


def register_enabled(db: Database) -> bool:
    return setting(db, "register_enabled", "0") == "1"


def payment_info(db: Database) -> dict[str, str]:
    return {
        "card": setting(db, "payment_card", ""),
        "wallet_address": setting(db, "payment_wallet_address", ""),
        "note": setting(db, "payment_note", ""),
        "currency": setting(db, "wallet_currency", DEFAULT_CURRENCY),
    }


def save_payment_info(db: Database, card: str, wallet_address: str, note: str, currency: str) -> dict[str, str]:
    set_setting(db, "payment_card", (card or "").strip()[:120])
    set_setting(db, "payment_wallet_address", (wallet_address or "").strip()[:200])
    set_setting(db, "payment_note", (note or "").strip()[:1000])
    cur = (currency or DEFAULT_CURRENCY).strip()[:32] or DEFAULT_CURRENCY
    set_setting(db, "wallet_currency", cur)
    return payment_info(db)


def load_prices(db: Database) -> dict[str, int]:
    raw = setting(db, "tunnel_prices_json", "{}")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        data = {}
    out: dict[str, int] = {}
    if not isinstance(data, dict):
        return out
    for mode in MODES:
        try:
            val = int(data.get(mode, 0))
        except (TypeError, ValueError):
            val = 0
        out[mode] = max(0, min(val, 10_000_000_000))
    return out


def save_prices(db: Database, prices: dict[str, Any]) -> dict[str, int]:
    cleaned: dict[str, int] = {}
    for mode in MODES:
        try:
            val = int(prices.get(mode, 0))
        except (TypeError, ValueError):
            val = 0
        cleaned[mode] = max(0, min(val, 10_000_000_000))
    set_setting(db, "tunnel_prices_json", json.dumps(cleaned, ensure_ascii=False, separators=(",", ":")))
    return cleaned


def balance_of(db: Database, user_id: int) -> int:
    row = db.one("SELECT wallet_balance FROM admins WHERE id=?", (user_id,))
    if not row:
        return 0
    try:
        return max(0, int(row.get("wallet_balance") or 0))
    except (TypeError, ValueError):
        return 0


def price_for(db: Database, mode: str) -> int:
    if not sell_enabled(db):
        return 0
    return load_prices(db).get(mode, 0)


def credit(
    db: Database,
    user_id: int,
    amount: int,
    *,
    kind: str,
    note: str = "",
    actor_id: int | None = None,
    ref_type: str = "",
    ref_id: int | None = None,
) -> int:
    if amount <= 0:
        raise ValueError("مبلغ باید مثبت باشد")
    db.execute(
        "UPDATE admins SET wallet_balance = COALESCE(wallet_balance, 0) + ? WHERE id=?",
        (amount, user_id),
    )
    bal = balance_of(db, user_id)
    db.insert(
        "wallet_ledger",
        {
            "user_id": user_id,
            "actor_id": actor_id,
            "kind": kind,
            "amount": amount,
            "balance_after": bal,
            "note": (note or "")[:500],
            "ref_type": (ref_type or "")[:32],
            "ref_id": ref_id,
            "created_at": utcnow(),
        },
    )
    return bal


def debit(
    db: Database,
    user_id: int,
    amount: int,
    *,
    kind: str,
    note: str = "",
    actor_id: int | None = None,
    ref_type: str = "",
    ref_id: int | None = None,
) -> int:
    if amount <= 0:
        raise ValueError("مبلغ باید مثبت باشد")
    row = db.one("SELECT wallet_balance FROM admins WHERE id=?", (user_id,))
    if not row:
        raise ValueError("کاربر پیدا نشد")
    have = int(row.get("wallet_balance") or 0)
    if have < amount:
        raise ValueError("موجودی کیف پول کافی نیست")
    db.execute(
        "UPDATE admins SET wallet_balance = wallet_balance - ? WHERE id=? AND wallet_balance >= ?",
        (amount, user_id, amount),
    )
    bal = balance_of(db, user_id)
    if bal != have - amount:
        raise ValueError("موجودی کیف پول کافی نیست")
    db.insert(
        "wallet_ledger",
        {
            "user_id": user_id,
            "actor_id": actor_id,
            "kind": kind,
            "amount": -amount,
            "balance_after": bal,
            "note": (note or "")[:500],
            "ref_type": (ref_type or "")[:32],
            "ref_id": ref_id,
            "created_at": utcnow(),
        },
    )
    return bal


def charge_tunnel(db: Database, user_id: int, mode: str, tunnel_id: int) -> int:
    """Deduct one tunnel price. Returns amount charged (0 if free)."""
    amount = price_for(db, mode)
    if amount <= 0:
        return 0
    label = MODES.get(mode, {}).get("label", mode)
    debit(
        db,
        user_id,
        amount,
        kind="tunnel_charge",
        note=f"ساخت تانل {label}",
        actor_id=user_id,
        ref_type="tunnel",
        ref_id=tunnel_id,
    )
    return amount


def refund_tunnel(db: Database, user_id: int, mode: str, tunnel_id: int) -> int:
    """Refund a tunnel charge once. Returns amount credited (0 if nothing to refund)."""
    charged = db.one(
        "SELECT id, amount FROM wallet_ledger WHERE user_id=? AND kind='tunnel_charge' AND ref_type='tunnel' AND ref_id=? ORDER BY id DESC LIMIT 1",
        (user_id, tunnel_id),
    )
    if not charged:
        return 0
    already = db.one(
        "SELECT id FROM wallet_ledger WHERE user_id=? AND kind='tunnel_refund' AND ref_type='tunnel' AND ref_id=? LIMIT 1",
        (user_id, tunnel_id),
    )
    if already:
        return 0
    try:
        amount = abs(int(charged.get("amount") or 0))
    except (TypeError, ValueError):
        amount = 0
    if amount <= 0:
        amount = price_for(db, mode)
    if amount <= 0:
        return 0
    label = MODES.get(mode, {}).get("label", mode)
    try:
        credit(
            db,
            user_id,
            amount,
            kind="tunnel_refund",
            note=f"بازگشت هزینه تانل {label}",
            actor_id=user_id,
            ref_type="tunnel",
            ref_id=tunnel_id,
        )
    except ValueError:
        return 0
    return amount


def should_refund_failed_deploy(tunnel: dict[str, Any]) -> bool:
    """True when this looks like a first deploy that never reached a healthy state."""
    lc = tunnel.get("last_check")
    if isinstance(lc, dict) and lc.get("ok") is True:
        return False
    return True


def refund_aborted_deploys(db: Database) -> int:
    """After panel restart, refund unrefunded charges for failed first deploys."""
    rows = db.all(
        "SELECT t.id, t.mode, t.owner_id, t.last_check FROM tunnels t "
        "WHERE t.status='failed' AND t.owner_id IS NOT NULL "
        "AND EXISTS ("
        "  SELECT 1 FROM wallet_ledger w WHERE w.user_id=t.owner_id AND w.kind='tunnel_charge' "
        "  AND w.ref_type='tunnel' AND w.ref_id=t.id"
        ") "
        "AND NOT EXISTS ("
        "  SELECT 1 FROM wallet_ledger w2 WHERE w2.user_id=t.owner_id AND w2.kind='tunnel_refund' "
        "  AND w2.ref_type='tunnel' AND w2.ref_id=t.id"
        ")"
    )
    n = 0
    for row in rows:
        if not should_refund_failed_deploy(row):
            continue
        if refund_tunnel(db, int(row["owner_id"]), str(row["mode"]), int(row["id"])):
            n += 1
    return n
