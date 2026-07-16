# JojoNet v1.5.1

مدیر تانل **ایران ↔ خارج**  
ریپو: https://github.com/b-khaneman/jojonet  
پشتیبانی: [@B_khaneman](https://t.me/B_khaneman)

---

## تغییرات نسخه‌ها (خلاصه)

روی سرور کامل ببین:

```bash
sudo jojonet --changelog
sudo jojonet --help
```

| نسخه | چه چیزی اضافه / عوض شد |
|------|-------------------------|
| **1.5.1** | راهنمای تغییرات در `--help` / `--changelog`؛ نمایش What's new بعد از آپدیت |
| **1.5.0** | **Rathole Reverse** — ریورس TCP (ایران=SERVER، خارج=CLIENT) |
| **1.4.3** | Hop Port هیستریا۲ سخت‌گیرانه (nft/iptables، UFW، random interval) |
| **1.4.2** | **Hop Port** برای Hysteria2 (رنج UDP + تعویض دوره‌ای پورت) |
| **1.4.1** | Auto forward port برای همه تانل‌ها؛ pairing card درست per mode |
| **1.4.0** | Pre-flight، `--status`، pairing، backup، `--import-gretun`، webhook |
| **1.3.1** | GRE چندتانلی با subnet یکتا per peer |
| **1.3.0** | GRE مثل setup دستی: `172.20.10.x`، MTU 1436، iptables DNAT+MASQUERADE |
| **1.2.8** | تغییر IP طرف مقابل: `--change-peer` |
| **1.2.6** | فیکس ping (`ip_forward` + `rp_filter`) و `--fix-tunnels` |
| **1.2.0+** | Self-update از GitHub، نقشه تانل ایران/خارج |
| **1.1.0** | WireGuard + Hysteria2 |
| **1.0.0** | GRE / TUN-TCP / Paqet / VXLAN |

جزئیات کامل: [CHANGELOG.md](./CHANGELOG.md)

---

## آپدیت JojoNet (مهم)

روی سرور:

```bash
sudo jojonet --check-update
sudo jojonet --update
```

یا از منو → گزینه **14) Update JojoNet from GitHub**

اجبار به نصب مجدد:
```bash
sudo jojonet --update --force
```

اگر نسخهٔ قدیمی داری و `--update` کار نمی‌کند:

```bash
curl -fsSL https://raw.githubusercontent.com/b-khaneman/jojonet/main/install.sh | sudo bash
```

اگر GitHub فیلتر است:

```bash
curl -fsSL https://cdn.jsdelivr.net/gh/b-khaneman/jojonet@main/install.sh | sudo bash
```

- کانفیگ‌های `/etc/jojonet/` پاک نمی‌شوند
- بکاپ باینری قبلی: `/usr/local/bin/jojonet.bak.VERSION`
- بعد از آپدیت: `sudo jojonet --changelog` برای دیدن تغییرات نسخه

---

## نصب (هر دو سرور)

```bash
curl -fsSL https://raw.githubusercontent.com/b-khaneman/jojonet/main/install.sh | sudo bash
sudo jojonet
sudo jojonet --version
```

خروجی باید باشد: `jojonet 1.5.1`

> همیشه **اول سرور خارج** را راه بینداز، بعد **سرور ایران** (به‌جز Rathole که اول ایران بهتر است).

---

# راهنمای تانل‌ها (کادر به کادر)

---

## ۱) GRE — سریع و سبک (پیش‌فرض)

| | |
|--|--|
| **بهترین برای** | پینگ پایین + سرعت بالا وقتی GRE توسط ISP بسته نشده |
| **پروتکل** | GRE (بدون key، MTU 1436، `172.20.x`) |
| **منو** | گزینه `1` |
| **دستور** | `sudo jojonet PEER_IP` |

### سرور خارج
```bash
sudo jojonet
# منو → 1) Quick GRE Tunnel
# IP سرور ایران را وارد کن
```
یا:
```bash
sudo jojonet --peer IP_ایران
```

### سرور ایران
```bash
sudo jojonet --peer IP_خارج
```

### نکته
- چند تانل روی یک سرور: هر peer subnet جدا می‌گیرد (از 1.3.1)
- ایران: iptables DNAT + MASQUERADE برای فوروارد پنل

---

## ۲) TUN/PrivateIP/TCP

| | |
|--|--|
| **بهترین برای** | وقتی فقط TCP باز است |
| **منو** | گزینه `2` |
| **دستور** | `sudo jojonet --tun-tcp PEER_IP` |

---

## ۳) Paqet (Raw/KCP)

| | |
|--|--|
| **بهترین برای** | مسیرهای فیلترشده یا ناپایدار |
| **منو** | گزینه `3` |
| **دستور** | `sudo jojonet --paqet PEER_IP` |

---

## ۴) VXLAN — overlay روی UDP

| | |
|--|--|
| **بهترین برای** | وقتی GRE بسته است ولی UDP آزاد است |
| **منو** | گزینه `4` |
| **دستور** | `sudo jojonet --vxlan PEER_IP` |

---

## ۵) WireGuard — کم‌تأخیر

| | |
|--|--|
| **بهترین برای** | پینگ پایین و پایداری |
| **منو** | گزینه `5` |
| **دستور** | `sudo jojonet --wg PEER_IP` |

اگر `51820` پر بود (مثلاً `wg0`)، پورت دیگر بده.

---

## ۶) Hysteria2 — سرعت بالا + Hop Port

| | |
|--|--|
| **بهترین برای** | مسیر فیلترشده / نیاز سرعت |
| **منو** | گزینه `6` |
| **دستور** | `sudo jojonet --hy2 PEER_IP` |

### Hop Port (از 1.4.2)
موقع ساخت می‌پرسد:
- Enable Hop Port؟
- رنج (مثل `20000-50000`)
- Interval ثابت یا random (`15s-45s`)

هر دو طرف باید **همان رنج** را بزنند. روی خارج `nft` یا `iptables` لازم است.

```bash
export JOJONET_HY2_HOP_RANGE=20000-50000
export JOJONET_HY2_HOP_INTERVAL=30s
sudo jojonet --hy2 PEER_IP
```

---

## ۷) Rathole Reverse — ریورس TCP (از 1.5.0)

| | |
|--|--|
| **بهترین برای** | وقتی GRE/UDP بسته است ولی TCP معکوس کار می‌کند |
| **منو** | گزینه `7` |
| **دستور** | `sudo jojonet --rathole PEER_IP` |

| نقش | کار |
|-----|-----|
| **ایران = SERVER** | کاربران به پورت‌های عمومی ایران وصل می‌شوند |
| **خارج = CLIENT** | به پورت کنترل ایران dial می‌کند و پنل لوکال را می‌دهد |

### ترتیب پیشنهادی
```bash
# اول ایران
sudo jojonet --rathole IP_خارج

# بعد خارج
sudo jojonet --rathole IP_ایران
```

Control port پیش‌فرض: `2333` — روی فایروال ایران باز باشد.  
پنل روی خارج باید روی `127.0.0.1:PORT` گوش بدهد.

---

## ۸) Advanced GRE — تنظیم دستی

| | |
|--|--|
| **منو** | گزینه `8` |

---

# جدول انتخاب سریع

| وضعیت شبکه | انتخاب |
|------------|--------|
| همه چیز باز است | **WireGuard** یا **GRE** |
| فقط UDP خوب است | **WireGuard** / **Hysteria2** / **VXLAN** |
| GRE بسته، TCP باز | **TUN/TCP** یا **Rathole Reverse** |
| فیلتر شدید / نیاز سرعت | **Hysteria2** (+ Hop Port) |
| مسیر ناپایدار | **Paqet** یا **Hysteria2** |
| ریورس (خارج dial به ایران) | **Rathole** |

---

# دستورات کمکی

```bash
# تاریخچه نسخه‌ها
sudo jojonet --changelog
sudo jojonet --help

# وضعیت
sudo jojonet --status

# سلامت یک تانل
sudo jojonet --health NAME

# لاگ
sudo jojonet --logs NAME

# تغییر peer
sudo jojonet --change-peer NAME NEW_IP

# تعمیر همه تانل‌ها
sudo jojonet --fix-tunnels

# بکاپ / ریستور
sudo jojonet --export-config /root/jn-bak.tar.gz
sudo jojonet --import-config /root/jn-bak.tar.gz

# کلید بدون SSH
sudo jojonet --export-keys PEER_IP /root/k.tar.gz
sudo jojonet --import-keys PEER_IP /root/k.tar.gz

# نقش دستی
export JOJONET_ROLE=iran    # یا kharej
sudo jojonet --wg IP_طرف

# حذف کامل
sudo jojonet-uninstall
```

---

# ترتیب استاندارد کار

```text
1) روی هر دو سرور: نصب / آپدیت JojoNet
2) نوع تانل را از جدول بالا انتخاب کن
3) اول خارج را اجرا کن (به‌جز Rathole → اول ایران)
4) بعد طرف مقابل را با IP درست اجرا کن
5) با --status یا --health چک کن
```

---

License: MIT  
Support: @B_khaneman
