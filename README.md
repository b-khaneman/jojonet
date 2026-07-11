# JojoNet

**اولین نسخه رسمی منتشرشده** — مدیر تانل ایران ↔ خارج

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/b-khaneman/jojonet)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

> این **اولین انتشار عمومی (v1.0.0)** پروژه JojoNet است.  
> برای نصب و استفاده، فقط از همین ریپو و لینک‌های زیر استفاده کنید.

**ریپو:** https://github.com/b-khaneman/jojonet  
**پشتیبانی:** [@B_khaneman](https://t.me/B_khaneman)

---

## نصب (نسخه اول — رسمی)

```bash
curl -fsSL https://raw.githubusercontent.com/b-khaneman/jojonet/main/install.sh | sudo bash
```

بررسی نسخه:

```bash
sudo jojonet --version
```

خروجی مورد انتظار: `jojonet 1.0.0`

---

## نصب از کلون

```bash
git clone https://github.com/b-khaneman/jojonet.git
cd jojonet
sudo bash install.sh
```

---

## این نسخه چیست؟

JojoNet v1.0.0 اولین نسخهٔ کامل و منتشرشده برای ساخت و مدیریت تانل بین سرور ایران و سرور خارج است، با پشتیبانی از:

| حالت | پروتکل | مناسب برای |
|------|--------|------------|
| **GRE** | IP/GRE | پیش‌فرض سریع |
| **TUN/TCP** | TCP | وقتی GRE بسته است |
| **Paqet** | Raw + KCP | مسیرهای فیلتر / latency بالا |
| **VXLAN** | UDP overlay | وقتی UDP باز است |

### امکانات نسخه اول
- تشخیص خودکار نقش سرور (ایران / خارج) با امکان تنظیم دستی
- چند تانل همزمان روی یک سرور
- فوروارد پورت روی سمت ایران (nftables)
- پایداری با systemd و بازیابی بعد از ریبوت
- همگام‌سازی کلید با SSH یا export/import دستی
- تأیید checksum برای دانلود باینری‌ها
- اسکریپت نصب و حذف کامل

---

## شروع سریع

1. **اول روی سرور خارج:**
   ```bash
   sudo jojonet
   ```
2. **بعد روی سرور ایران:**
   ```bash
   sudo jojonet IP_سرور_خارج
   ```
3. نقش دستی (اختیاری):
   ```bash
   export JOJONET_ROLE=iran
   sudo jojonet IP_خارج
   ```

---

## دستورات

| دستور | توضیح |
|--------|--------|
| `sudo jojonet` | منوی اصلی |
| `sudo jojonet PEER_IP` | تانل GRE سریع |
| `sudo jojonet --tun-tcp PEER_IP` | TUN/TCP |
| `sudo jojonet --paqet PEER_IP` | Paqet |
| `sudo jojonet --vxlan PEER_IP` | VXLAN |
| `sudo jojonet --health NAME` | بررسی سلامت تانل |
| `sudo jojonet --export-keys PEER [FILE]` | خروجی کلید |
| `sudo jojonet --import-keys PEER FILE` | ورود کلید |
| `sudo jojonet --help` | راهنما |
| `sudo jojonet-uninstall` | حذف کامل |

---

## حذف

```bash
sudo jojonet-uninstall
```

---

## English

**JojoNet v1.0.0 — First official public release**

Iran ↔ Foreign tunnel manager (GRE / TUN-TCP / Paqet / VXLAN) with systemd persistence.

### Install

```bash
curl -fsSL https://raw.githubusercontent.com/b-khaneman/jojonet/main/install.sh | sudo bash
sudo jojonet --version
```

Expected: `jojonet 1.0.0`

### Quick start
1. Foreign server: `sudo jojonet`
2. Iran server: `sudo jojonet <FOREIGN_IP>`

---

## License

MIT — see [LICENSE](LICENSE)

**First release:** v1.0.0  
**Author / Support:** [@B_khaneman](https://t.me/B_khaneman)
