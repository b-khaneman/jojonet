"""SMTP settings and outbound mail for password reset."""

from __future__ import annotations

import logging
import smtplib
import ssl
from email.message import EmailMessage
from typing import Any

from . import wallet as wallet_mod
from .db import Database
from .security import Vault
from .tlsinfo import normalize_email

log = logging.getLogger("jojonet.panel.mail")

RESET_TTL_SECONDS = 3600
GENERIC_FORGOT_MSG = (
    "اگر حسابی با این مشخصات و ایمیل ثبت‌شده وجود داشته باشد، "
    "لینک بازیابی رمز برایتان ارسال می‌شود. صندوق ورودی و اسپم را چک کنید."
)


def smtp_public(db: Database) -> dict[str, Any]:
    port_raw = wallet_mod.setting(db, "smtp_port", "587")
    try:
        port = int(port_raw)
    except (TypeError, ValueError):
        port = 587
    return {
        "enabled": wallet_mod.setting(db, "smtp_enabled", "0") == "1",
        "host": wallet_mod.setting(db, "smtp_host", ""),
        "port": max(1, min(port, 65535)),
        "username": wallet_mod.setting(db, "smtp_user", ""),
        "from_addr": wallet_mod.setting(db, "smtp_from", ""),
        "tls": wallet_mod.setting(db, "smtp_tls", "1") != "0",
        "password_set": bool(wallet_mod.setting(db, "smtp_password", "")),
    }


def save_smtp(
    db: Database,
    vault: Vault,
    *,
    enabled: bool | None = None,
    host: str | None = None,
    port: int | None = None,
    username: str | None = None,
    password: str | None = None,
    from_addr: str | None = None,
    tls: bool | None = None,
) -> dict[str, Any]:
    if enabled is not None:
        wallet_mod.set_setting(db, "smtp_enabled", "1" if enabled else "0")
    if host is not None:
        wallet_mod.set_setting(db, "smtp_host", (host or "").strip()[:253])
    if port is not None:
        wallet_mod.set_setting(db, "smtp_port", str(max(1, min(int(port), 65535))))
    if username is not None:
        wallet_mod.set_setting(db, "smtp_user", (username or "").strip()[:200])
    if from_addr is not None:
        raw = (from_addr or "").strip()
        wallet_mod.set_setting(db, "smtp_from", normalize_email(raw) if raw else "")
    if tls is not None:
        wallet_mod.set_setting(db, "smtp_tls", "1" if tls else "0")
    if password is not None:
        value = str(password)
        if value == "":
            wallet_mod.set_setting(db, "smtp_password", "")
        else:
            wallet_mod.set_setting(db, "smtp_password", vault.encrypt(value) or "")
    return smtp_public(db)


def _smtp_password(db: Database, vault: Vault) -> str:
    raw = wallet_mod.setting(db, "smtp_password", "")
    if not raw:
        return ""
    # Prefer vault decrypt; accept legacy plaintext for one-shot migration.
    try:
        return vault.decrypt(raw) or ""
    except ValueError:
        return raw


def smtp_ready(db: Database, vault: Vault) -> bool:
    cfg = smtp_public(db)
    if not cfg["enabled"] or not cfg["host"] or not cfg["from_addr"]:
        return False
    # Auth optional (some relays allow IP auth); password may be empty.
    return True


def send_mail(db: Database, vault: Vault, *, to: str, subject: str, text: str) -> None:
    cfg = smtp_public(db)
    if not cfg["enabled"]:
        raise RuntimeError("ارسال ایمیل خاموش است؛ از مدیریت SMTP را روشن کنید")
    host = cfg["host"]
    if not host:
        raise RuntimeError("آدرس سرور SMTP تنظیم نشده است")
    from_addr = cfg["from_addr"]
    if not from_addr:
        raise RuntimeError("آدرس فرستنده (From) تنظیم نشده است")
    to_addr = normalize_email(to)
    if not to_addr:
        raise RuntimeError("آدرس گیرنده نامعتبر است")

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = to_addr
    msg.set_content(text)

    password = _smtp_password(db, vault)
    username = cfg["username"] or None
    port = int(cfg["port"])
    use_tls = bool(cfg["tls"])

    if port == 465:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(host, port, timeout=30, context=context) as smtp:
            if username:
                smtp.login(username, password)
            smtp.send_message(msg)
        return

    with smtplib.SMTP(host, port, timeout=30) as smtp:
        smtp.ehlo()
        if use_tls:
            context = ssl.create_default_context()
            smtp.starttls(context=context)
            smtp.ehlo()
        if username:
            smtp.login(username, password)
        smtp.send_message(msg)


def send_password_reset_mail(
    db: Database,
    vault: Vault,
    *,
    to: str,
    username: str,
    reset_url: str,
) -> None:
    subject = "بازیابی رمز عبور پنل JojoNet"
    text = (
        f"سلام {username}،\n\n"
        "درخواست بازیابی رمز عبور برای حساب شما ثبت شد.\n"
        "اگر خودتان این درخواست را نداده‌اید، این پیام را نادیده بگیرید.\n\n"
        f"لینک بازیابی (یک ساعت اعتبار دارد):\n{reset_url}\n\n"
        "بعد از باز کردن لینک، رمز جدید را وارد کنید.\n"
    )
    send_mail(db, vault, to=to, subject=subject, text=text)
