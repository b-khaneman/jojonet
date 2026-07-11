

| مورد | توضیح |
|------|--------|
| پارسر امن کانفیگ | دیگر `source` نمی‌شود |
| تأیید SHA256 | دانلود LocalTun/Paqet با checksum |
| پیشوند TUN خصوصی | `10.30.x.x` به‌جای `30.10` عمومی |
| Subnet یکسان | Advanced GRE مثل Quick از pair-hash |
| `rp_filter` | دیگر سراسری خاموش نمی‌شود |
| `GOMAXPROCS` | اصلاح شد (`1`) |
| نقش دستی | `JOJONET_ROLE` / `--role` |
| کلید بدون SSH | `--export-keys` / `--import-keys` |
| Healthcheck | `--health NAME` |
| Uninstall | `uninstall.sh` |
| نصب امن‌تر | نصب از پکیج محلی |

## نصب

```bash
cd JojoNet-Fixed
sudo bash install.sh
sudo jojonet --help
```

## شروع سریع

1. **سرور خارج:** `sudo jojonet` → گزینه 1 (یا `sudo jojonet --peer IP_ایران`)
2. **سرور ایران:** `sudo jojonet IP_خارج`
3. نقش دستی (اختیاری): `export JOJONET_ROLE=iran`

## همگام‌سازی کلید بدون SSH

```bash
sudo jojonet --export-keys PEER_IP /root/keys.tar.gz
# کپی فایل به سرور دیگر
sudo jojonet --import-keys PEER_IP /root/keys.tar.gz
```

## حالت‌های تانل

| دستور | کاربرد |
|--------|--------|
| `sudo jojonet PEER` | GRE سریع |
| `sudo jojonet --tun-tcp PEER` | وقتی GRE بسته است |
| `sudo jojonet --paqet PEER` | مسیر فیلتر / latency بالا |
| `sudo jojonet --vxlan PEER` | overlay روی UDP |

## حذف کامل

```bash
sudo jojonet-uninstall
```

## متغیرهای محیطی

- `JOJONET_ROLE=iran|kharej`
- `JOJONET_ALLOW_UNSIGNED=1` (فقط در صورت نیاز)
- `JOJONET_QUICK_PROBE_MTU=1`
- `JOJONET_DISABLE_RP_FILTER=1` (رفتار قدیمی)
- `JOJONET_STEALTH=1`

راهنمای کامل PDF: `JojoNet-Fixed-Guide.pdf`

## License

MIT
