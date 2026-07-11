# JojoNet

**اولین نسخه رسمی + آپدیت 1.1.0** — مدیر تانل ایران ↔ خارج

[![Version](https://img.shields.io/badge/version-1.1.0-blue.svg)](https://github.com/b-khaneman/jojonet)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

> JojoNet v1.1.0 — GRE / TUN-TCP / Paqet / VXLAN / **WireGuard** / **Hysteria2**

**ریپو:** https://github.com/b-khaneman/jojonet  
**پشتیبانی:** [@B_khaneman](https://t.me/B_khaneman)

---

## نصب و اجرا (کنار هم)

### ۱) نصب
```bash
curl -fsSL https://raw.githubusercontent.com/b-khaneman/jojonet/main/install.sh | sudo bash
```

### ۲) بررسی نسخه
```bash
sudo jojonet --version
```
خروجی: `jojonet 1.1.0`

### ۳) اجرا — سرور خارج (اول)
```bash
sudo jojonet
```

### ۴) اجرا — سرور ایران
```bash
sudo jojonet IP_سرور_خارج
```

---

## انتخاب نوع تانل

| اولویت | دستور | پینگ | سرعت | کی؟ |
|--------|--------|------|------|-----|
| ۱ | `sudo jojonet --wg PEER` | عالی | عالی | اگر UDP باز باشد |
| ۲ | `sudo jojonet PEER` (GRE) | عالی | عالی | اگر GRE باز باشد |
| ۳ | `sudo jojonet --hy2 PEER` | خوب | خیلی بالا | مسیر فیلتر / نیاز به سرعت |
| ۴ | `sudo jojonet --tun-tcp PEER` | متوسط | خوب | GRE بسته |
| ۵ | `sudo jojonet --paqet PEER` | متوسط | خوب | فیلتر شدید |
| ۶ | `sudo jojonet --vxlan PEER` | خوب | خوب | UDP باز، GRE بسته |

### WireGuard (پیشنهادی برای پینگ پایین)
```bash
# خارج:
sudo jojonet --wg IP_ایران
# ایران:
sudo jojonet --wg IP_خارج
```

### Hysteria2 (پیشنهادی برای سرعت بالا روی مسیر فیلتر)
```bash
# خارج:
sudo jojonet --hy2 IP_ایران
# ایران:
sudo jojonet --hy2 IP_خارج
```

---

## منو

```
1) Quick GRE
2) TUN/TCP
3) Paqet
4) VXLAN
5) WireGuard
6) Hysteria2
7) Advanced GRE
8) Manage
9) Status
...
```

---

## حذف
```bash
sudo jojonet-uninstall
```

## License
MIT
