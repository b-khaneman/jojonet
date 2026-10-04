# JojoNet v1.5.9

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
| **1.5.9** | **WireGuard داخل ICMP / FakeTCP** (`--wg-icmp` / `--wg-faketcp`)، **چک آمادگی Spoof** در پنل قبل از ساخت |
| **1.5.8** | **Spoof Tunnel در پنل وب** (ساخت خودکار دو طرف + تست UDP سرتاسری)، `--spoof-remove` |
| **1.5.7** | فیکس سینک کلید TUN/TCP و Paqet، `--delete`، export/import امن، **پنل وب فارسی** |
| **1.5.6** | **Auto deploy**: نوع تانل + IP طرف مقابل؛ پیش‌فرض هوشمند (JOJONET_AUTO) |
| **1.5.5** | **Spoof Tunnel + QS-Tunnel** به‌صورت standalone systemd integration |
| **1.5.4** | **Hysteria2 TLS روی دامنه شخصی** (ACME / گواهی دستی) + Hop Port |
| **1.5.3** | **Wstunnel Reverse** — ریورس WebSocket (ایران=SERVER، خارج=CLIENT -R) |
| **1.5.2** | دیباگ Rathole: repair، فایروال، mirror دانلود، rollback/uninstall کامل |
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

یا از منو → گزینه **17) Update JojoNet from GitHub**

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

خروجی باید باشد: `jojonet 1.5.9`

> همیشه **اول سرور خارج** را راه بینداز، بعد **سرور ایران** (به‌جز Rathole/Wstunnel که اول ایران بهتر است).

### نصب یک‌کلیکی از فایل zip

فایل `JojoNet-v1.5.9-full.zip` را روی سرور کپی کن (مثلاً با `scp`) و:

```bash
sudo apt-get install -y unzip   # اگر unzip نداری
unzip JojoNet-v1.5.9-full.zip -d jojonet && cd jojonet
sudo bash setup.sh              # منو: ۱) اسکریپت  ۲) پنل وب  ۳) هر دو
```

بدون منو:

```bash
sudo bash setup.sh script   # فقط اسکریپت jojonet
sudo bash setup.sh panel    # فقط پنل وب
sudo bash setup.sh all      # هر دو
```

---

## پنل وب فارسی (اختیاری)

پنل روی **یک** سرور (یا هر لینوکس دیگری) نصب می‌شود، با SSH به سرورهای ایران و خارج وصل می‌شود، پیش‌نیازها و jojonet را نصب می‌کند، تانل را می‌سازد و با ping/health تأیید می‌کند.

```bash
sudo bash panel/install-panel.sh
sudo jojonet-panel url          # آدرس پنل
sudo jojonet-panel set-admin    # تغییر رمز مدیر
```

راهنمای کامل: [panel/README.md](./panel/README.md)

---

# راهنمای تانل‌ها (کادر به کادر)

---

## ۰) Auto deploy — فقط IP طرف مقابل (از 1.5.6)

منو: نوع تانل → IP سرور مقابل → Use automatic defaults? [Y/n] (پیش‌فرض Y) → ساخته می‌شود.

```bash
# خارج
sudo jojonet --hy2 IP_ایران
# ایران
sudo jojonet --hy2 IP_خارج

# اجبار حالت پیشرفته
JOJONET_AUTO=0 sudo jojonet --hy2 IP_مقابل
```

نقش iran/kharej خودکار تشخیص داده می‌شود. متغیرهای JOJONET_* همچنان override می‌کنند.

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

### WireGuard داخل ICMP / FakeTCP (از 1.5.9)

وقتی UDP فیلتر یا محدود است، بسته‌های WireGuard با **udp2raw** داخل ICMP echo (پینگ) یا TCP جعلی (FakeTCP) قرار می‌گیرند. روی سیم فقط پینگ یا سگمنت TCP دیده می‌شود و بسته‌ها با AES-128 + HMAC رمز می‌شوند.

| | ICMP | FakeTCP |
|--|--|--|
| **دستور** | `sudo jojonet --wg-icmp PEER_IP` | `sudo jojonet --wg-faketcp PEER_IP` |
| **منو** | گزینه `21` ← `1` | گزینه `21` ← `2` |
| **رنج overlay** | `10.67.X.0/30` | `10.68.X.0/30` |

- هر دو طرف همان دستور را می‌زنند (اول خارج، بعد ایران). MTU پیش‌فرض `1200` است.
- پورت udp2raw از جفت سرور ساخته می‌شود (ICMP: `4096+X`، FakeTCP: `4352+X`)؛ با `JOJONET_WG_OBFS_PORT` قابل تغییر است. پورت UDP خود WireGuard روی خارج `پورت+10000` است و فقط روی localhost استفاده می‌شود.
- سرویس کمکی: `jojonet-u2r@NAME.service` (همراه تانل start/stop می‌شود). قوانین iptables فقط برای IP همتا اضافه و موقع stop پاک می‌شوند.
- برای FakeTCP پورت TCP روی خارج و برای ICMP پینگ ورودی باید از ایران باز باشد.

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

### TLS روی دامنه شخصی (از 1.5.4)
موقع ساخت، بعد از SNI یک منوی TLS می‌آید:

| حالت | توضیح |
|------|-------|
| **1) self-signed** | پیش‌فرض؛ بدون دامنه، `insecure: true` (مثل قبل) |
| **2) ACME** | گواهی خودکار Let's Encrypt روی دامنه شخصی، تمدید خودکار |
| **3) custom** | فایل گواهی خودت: `cert.pem` + `key.pem` |

نکته‌های مهم:
- رکورد **A دامنه** باید به **IP سرور خارج (Kharej)** اشاره کند (چون ایران به خارج وصل می‌شود).
- برای ACME، پورت **TCP 80 و 443** روی خارج باید باز باشد (خودکار در UFW/firewalld باز می‌شود). این با Hop Port تداخل ندارد چون داده روی رنج UDP است.
- با گواهی واقعی، سمت ایران خودکار `insecure: false` و `sni = دامنه` می‌شود.
- هر دو طرف باید **همان دامنه/حالت** را بزنند.

با هاپینگ + دامنه شخصی به‌صورت غیرتعاملی:
```bash
export JOJONET_HY2_HOP_RANGE=20000-50000
export JOJONET_HY2_TLS_MODE=acme
export JOJONET_HY2_DOMAIN=vpn.example.com
export JOJONET_HY2_ACME_EMAIL=you@example.com
sudo jojonet --hy2 PEER_IP
```

گواهی دستی:
```bash
export JOJONET_HY2_TLS_MODE=custom
export JOJONET_HY2_DOMAIN=vpn.example.com
export JOJONET_HY2_CERT=/etc/ssl/vpn/cert.pem
export JOJONET_HY2_KEY=/etc/ssl/vpn/key.pem
sudo jojonet --hy2 PEER_IP
```

---

## ۷) Rathole Reverse — ریورس TCP (از 1.5.0)

| | |
|--|--|
| **بهترین برای** | وقتی GRE/UDP بسته است ولی TCP معکوس کار می‌کند |
| **منو** | گزینه `7` |
| **دستور** | `sudo jojonet --rathole / --wstunnel PEER_IP` |

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

## ۸) Wstunnel Reverse — ریورس WebSocket

دستور: `sudo jojonet --wstunnel PEER_IP` یا `sudo jojonet --ws PEER_IP`  
ایران server و خارج client است.

---

## ۹) Spoof Tunnel — انتقال مستقل با IP spoofing

```bash
# ایران = local
sudo jojonet --role iran --spoof-tunnel IP_خارج

# خارج = remote
sudo jojonet --role kharej --spoof IP_ایران
```

- نسخه پین‌شده: `v3.1.0-beta.0`
- باینری‌های `amd64` و `arm64` از release رسمی دانلود و با `checksums.txt` رسمی بررسی می‌شوند.
- کانفیگ: `/etc/jojonet/spoof/config.json`
- سرویس: `jojonet-spoof.service`
- ایران به‌صورت `local` و خارج به‌صورت `remote` اجرا می‌شود.
- پیش‌فرض transport ایران `send=tcp/recv=udp` و خارج برعکس است.
- برای یک IP مقدار عادی وارد کنید؛ برای فایل لیست IP مسیر مطلق را با `@` بدهید (مثل `@/etc/jojonet/spoof/ips.txt`).
- transportهای `tcp`، `udp`، `icmp` و `icmpv6` پشتیبانی می‌شوند.

> هشدار قطعی: هر دو سرور و هر دو provider باید source-IP spoofing را پشتیبانی کنند. دسترسی root/raw socket لازم است. این قابلیت overlay معمول JojoNet نیست.

---

## ۱۰) QS-Tunnel — DNS upload + spoofed download

```bash
# ایران = client
sudo jojonet --role iran --qs-tunnel

# خارج = server
sudo jojonet --role kharej --qs
```

- سورس روی commit `4497146ccc1e70ad510b68db5a483e0395782df4` پین شده است.
- نیازمند Python **3.12+** و پکیج‌های `aiohttp` و `numba` است.
- runtime مدیریت‌شده: `/opt/jojonet/qs-tunnel` (venv داخل همان مسیر)
- کانفیگ: `/etc/jojonet/qs-tunnel/config.json`
- سرویس: `jojonet-qs.service`
- آرایه‌های DNS/domain به‌صورت comma-separated دریافت می‌شوند.

> QS فقط UDP forwarder است؛ برای انتقال قابل‌اعتماد باید Hysteria2، WireGuard یا xhttp-h3 را روی endpointهای محلی آن قرار دهید. محدودیت طول DNS و سرعت آپلود پایین (تقریباً ۱ مگابیت برای هر client) همچنان وجود دارد. سرور خارج برای ارسال spoofed packet به root/raw socket نیاز دارد.

---

## ۱۱) Advanced GRE — تنظیم دستی

| | |
|--|--|
| **منو** | گزینه `11` |

---

# جدول انتخاب سریع

| وضعیت شبکه | انتخاب |
|------------|--------|
| همه چیز باز است | **WireGuard** یا **GRE** |
| فقط UDP خوب است | **WireGuard** / **Hysteria2** / **VXLAN** |
| GRE بسته، TCP باز | **TUN/TCP** یا **Rathole** / **Wstunnel** |
| فیلتر شدید / نیاز سرعت | **Hysteria2** (+ Hop Port) |
| مسیر ناپایدار | **Paqet** یا **Hysteria2** |
| ریورس (خارج dial به ایران) | **Rathole** / **Wstunnel** |
| هر دو provider قابلیت source spoof دارند | **Spoof Tunnel** |
| DNS مناسب + لایه UDP قابل‌اعتماد داری | **QS-Tunnel + HY2/WG/xhttp-h3** |

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

# حذف یک تانل (بدون پرسش)
sudo jojonet --delete NAME

# کلید بدون SSH (WG/HY2/Rathole/Wstunnel: IP طرف مقابل — TUN/TCP و Paqet: شماره subnet)
sudo jojonet --export-keys PEER_IP /root/k.tar.gz
sudo jojonet --import-keys PEER_IP /root/k.tar.gz
sudo jojonet --export-keys 12 /root/k.tar.gz      # pair_12 (TUN/TCP / Paqet)

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
3) اول خارج را اجرا کن (به‌جز Rathole/Wstunnel → اول ایران)
4) بعد طرف مقابل را با IP درست اجرا کن
5) با --status یا --health چک کن
```

---

License: MIT  
Support: @B_khaneman
