# JojoNet Fixed v1.1.0

Iran ↔ Foreign tunnel manager — نسخه اصلاح‌شده و امن‌تر

**Repository:** https://github.com/b-khaneman/jojonet

---

## نصب یک‌خطی (پیشنهادی)

```bash
curl -fsSL https://raw.githubusercontent.com/b-khaneman/jojonet/main/install.sh | sudo bash
```

بعد چک کن:

```bash
sudo jojonet --version
```

باید ببینی: `jojonet 1.1.0`

---

## نصب از کلون

```bash
git clone https://github.com/b-khaneman/jojonet.git
cd jojonet
sudo bash install.sh
```

---

## شروع سریع

1. **سرور خارج:**
   ```bash
   sudo jojonet
   ```
2. **سرور ایران:**
   ```bash
   sudo jojonet IP_سرور_خارج
   ```
3. نقش دستی (اختیاری):
   ```bash
   export JOJONET_ROLE=iran
   # یا
   sudo jojonet --role iran IP_خارج
   ```

---

## دستورات مهم

| دستور | کاربرد |
|--------|--------|
| `sudo jojonet` | منوی اصلی |
| `sudo jojonet PEER_IP` | Quick GRE |
| `sudo jojonet --tun-tcp PEER_IP` | TUN/TCP |
| `sudo jojonet --paqet PEER_IP` | Paqet |
| `sudo jojonet --vxlan PEER_IP` | VXLAN |
| `sudo jojonet --health NAME` | بررسی سلامت |
| `sudo jojonet --export-keys PEER [FILE]` | خروجی کلید بدون SSH |
| `sudo jojonet --import-keys PEER FILE` | ورود کلید |
| `sudo jojonet --help` | راهنما |
| `sudo jojonet-uninstall` | حذف کامل |

---

## تغییرات v1.1.0

- پارسر امن کانفیگ (بدون `source`)
- تأیید SHA256 برای دانلود باینری‌ها
- پیشوند TUN خصوصی `10.30.x.x`
- Subnet یکسان در Quick و Advanced GRE
- `rp_filter` دیگر سراسری خاموش نمی‌شود
- اصلاح `GOMAXPROCS`
- نقش دستی با `JOJONET_ROLE` / `--role`
- export/import کلید بدون SSH
- healthcheck و uninstall

---

## متغیرهای محیطی

| متغیر | معنی |
|--------|------|
| `JOJONET_ROLE=iran\|kharej` | نقش دستی |
| `JOJONET_ALLOW_UNSIGNED=1` | قبول دانلود بدون checksum |
| `JOJONET_QUICK_PROBE_MTU=1` | پروب MTU در Quick GRE |
| `JOJONET_DISABLE_RP_FILTER=1` | رفتار قدیمی rp_filter |
| `JOJONET_STEALTH=1` | حالت مخفی |

---

## حذف

```bash
sudo jojonet-uninstall
```

یا:

```bash
curl -fsSL https://raw.githubusercontent.com/b-khaneman/jojonet/main/uninstall.sh | sudo bash
```

---

## پشتیبانی

- Telegram: [@B_khaneman](https://t.me/B_khaneman)
- GitHub: https://github.com/b-khaneman/jojonet

## License

MIT
