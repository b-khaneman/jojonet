# JojoNet v1.1.0

مدیر تانل **ایران ↔ خارج**  
ریپو: https://github.com/b-khaneman/jojonet  
پشتیبانی: [@B_khaneman](https://t.me/B_khaneman)

---

## نصب (هر دو سرور)

```bash
curl -fsSL https://raw.githubusercontent.com/b-khaneman/jojonet/main/install.sh | sudo bash
sudo jojonet
برای چک کردن ورژن اسکریپت : 
sudo jojonet --version
```

خروجی باید باشد: `jojonet 1.1.0`

> همیشه **اول سرور خارج** را راه بینداز، بعد **سرور ایران**.

---

# راهنمای تانل‌ها (کادر به کادر)

---

## ۱) GRE — سریع و سبک (پیش‌فرض)

| | |
|--|--|
| **بهترین برای** | پینگ پایین + سرعت بالا وقتی GRE توسط ISP بسته نشده |
| **پروتکل** | GRE |
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
sudo jojonet IP_خارج
```

### نتیجه
- Subnet و GRE Key خودکار از IP دو طرف ساخته می‌شود
- روی ایران پورت‌فوروارد پیش‌فرض `443` فعال می‌شود
- اگر پینگ بین تانل OK بود، تانل آماده است

### اگر کار نکرد
GRE احتمالاً فیلتر است → برو سراغ **WireGuard** یا **TUN/TCP**

---

## ۲) WireGuard — بهترین پینگ (پیشنهادی)

| | |
|--|--|
| **بهترین برای** | پینگ خیلی پایین + پایداری عالی (اگر UDP باز باشد) |
| **پروتکل** | UDP (پیش‌فرض پورت `51820`) |
| **منو** | گزینه `5` |
| **دستور** | `sudo jojonet --wg PEER_IP` |

### سرور خارج
```bash
sudo jojonet --wg IP_ایران
```
- نقش: Foreign
- پورت UDP را تأیید کن (پیش‌فرض 51820)
- کلید WireGuard ساخته می‌شود

### سرور ایران
```bash
sudo jojonet --wg IP_خارج
```
- نقش: Iran
- همان پورت UDP را بزن
- پورت‌فوروارد (مثل 443) را در صورت نیاز تنظیم کن

### نکته مهم
- هر طرف کلید خودش را دارد؛ اگر SSH بین دو سرور باز باشد، کلید peer خودکار رد و بدل می‌شود
- اگر SSH نبود:
  ```bash
  sudo jojonet --export-keys PEER_IP /root/keys.tar.gz
  # فایل را به سرور دیگر ببر
  sudo jojonet --import-keys PEER_IP /root/keys.tar.gz
  ```
- فایروال: UDP `51820` (یا پورتی که زدی) باید باز باشد

### اگر کار نکرد
UDP بسته است → **Hysteria2** یا **TUN/TCP**

---

## ۳) Hysteria2 — سرعت بالا روی مسیر فیلتر

| | |
|--|--|
| **بهترین برای** | دانلود/آپلود بالا وقتی مسیر فیلتر است |
| **پروتکل** | UDP + TLS (پیش‌فرض پورت `443`) |
| **منو** | گزینه `6` |
| **دستور** | `sudo jojonet --hy2 PEER_IP` |

### سرور خارج (Server)
```bash
sudo jojonet --hy2 IP_ایران
```
- نقش: Foreign / Server
- پورت Listen را بزن (معمولاً `443`)
- SNI را تأیید کن (پیش‌فرض `www.cloudflare.com`)

### سرور ایران (Client)
```bash
sudo jojonet --hy2 IP_خارج
```
- نقش: Iran / Client
- همان پورت سرور را بزن
- پورت‌های فوروارد را وارد کن (مثلاً `443` یا `443,80`)

### نکته
- باینری Hysteria2 خودکار دانلود می‌شود
- اگر checksum نداشت، یک‌بار تأیید کن یا:
  ```bash
  sudo JOJONET_ALLOW_UNSIGNED=1 jojonet --hy2 IP_طرف
  ```
- فایروال خارج: UDP پورت Hysteria باید باز باشد

---

## ۴) TUN/TCP — وقتی GRE بسته است

| | |
|--|--|
| **بهترین برای** | بک‌هال وقتی GRE فیلتر شده ولی TCP کار می‌کند |
| **پروتکل** | TCP (LocalTun) |
| **منو** | گزینه `2` |
| **دستور** | `sudo jojonet --tun-tcp PEER_IP` |

### سرور خارج
```bash
sudo jojonet --tun-tcp IP_ایران
```
- پورت TCP را بزن (پیش‌فرض `8443`)

### سرور ایران
```bash
sudo jojonet --tun-tcp IP_خارج
```
- همان پورت را بزن
- پورت‌فوروارد را تنظیم کن

### نکته
- کلیدها از طریق SSH یا `--export-keys` / `--import-keys` هماهنگ می‌شوند
- فایروال: TCP پورت تانل باید باز باشد
- پینگ معمولاً از GRE/WG بالاتر است

---

## ۵) Paqet — مسیرهای سخت / latency بالا

| | |
|--|--|
| **بهترین برای** | مسیرهای فیلترشده یا ناپایدار |
| **پروتکل** | Raw / KCP |
| **منو** | گزینه `3` |
| **دستور** | `sudo jojonet --paqet PEER_IP` |

### سرور خارج
```bash
sudo jojonet --paqet IP_ایران
```
- پورت Listen را تنظیم کن

### سرور ایران
```bash
sudo jojonet --paqet IP_خارج
```
- همان پورت + پورت‌فوروارد

### نکته
- کانفیگ YAML در `/etc/jojonet/paqet/` ساخته می‌شود
- برای پایداری روی مسیر بد معمولاً بهتر از GRE خام است، ولی سبک‌تر از WG نیست

---

## ۶) VXLAN — overlay روی UDP

| | |
|--|--|
| **بهترین برای** | وقتی GRE بسته است ولی UDP آزاد است |
| **پروتکل** | VXLAN (UDP، پیش‌فرض `4789`) |
| **منو** | گزینه `4` |
| **دستور** | `sudo jojonet --vxlan PEER_IP` |

### سرور خارج
```bash
sudo jojonet --vxlan IP_ایران
```

### سرور ایران
```bash
sudo jojonet --vxlan IP_خارج
```

### نکته
- VNI از IP دو طرف ساخته می‌شود
- فایروال: UDP `4789` (یا پورت انتخابی) باز باشد
- اگر UDP آزاد است، معمولاً **WireGuard** انتخاب بهتری از VXLAN است

---

## ۷) Advanced GRE — تنظیم دستی

| | |
|--|--|
| **بهترین برای** | وقتی می‌خواهی Subnet / MTU / نام اینترفیس را دستی بدهی |
| **منو** | گزینه `7` |

### هر دو سرور
```bash
sudo jojonet
# منو → 7) Advanced GRE Setup
```
1. نقش را انتخاب کن (Iran / Foreign)
2. IP محلی و IP طرف مقابل را وارد کن
3. Subnet ID را بگذار روی مقدار پیشنهادی pair (تا دو طرف یکی باشد)
4. MTU را Auto یا ثابت انتخاب کن
5. تأیید و Apply

> Subnet دو طرف باید یکی باشد؛ مقدار پیش‌فرض pair-hash برای همین است.

---

# جدول انتخاب سریع

| وضعیت شبکه | انتخاب |
|------------|--------|
| همه چیز باز است | **WireGuard** یا **GRE** |
| فقط UDP خوب است | **WireGuard** / **Hysteria2** / **VXLAN** |
| GRE بسته، TCP باز | **TUN/TCP** |
| فیلتر شدید / نیاز سرعت | **Hysteria2** |
| مسیر ناپایدار | **Paqet** یا **Hysteria2** |

---

# دستورات کمکی (هر تانل)

```bash
# وضعیت
sudo jojonet
# منو → 8) Manage / 9) Status

# سلامت یک تانل
sudo jojonet --health NAME

# کلید بدون SSH
sudo jojonet --export-keys PEER_IP /root/k.tar.gz
sudo jojonet --import-keys PEER_IP /root/k.tar.gz

# نقش دستی (اگر GeoIP اشتباه گفت)
export JOJONET_ROLE=iran    # یا kharej
sudo jojonet --wg IP_طرف

# حذف کامل
sudo jojonet-uninstall
```

---

# ترتیب استاندارد کار

```text
1) روی هر دو سرور: نصب JojoNet
2) نوع تانل را از جدول بالا انتخاب کن
3) اول خارج را اجرا کن
4) بعد ایران را با IP خارج اجرا کن
5) با --health یا پینگ تانل چک کن
6) سرویس/پنل را روی پورت فوروارد تست کن
```

---

## English summary

| Mode | Foreign | Iran |
|------|---------|------|
| GRE | `sudo jojonet --peer IRAN_IP` | `sudo jojonet FOREIGN_IP` |
| WireGuard | `sudo jojonet --wg IRAN_IP` | `sudo jojonet --wg FOREIGN_IP` |
| Hysteria2 | `sudo jojonet --hy2 IRAN_IP` | `sudo jojonet --hy2 FOREIGN_IP` |
| TUN/TCP | `sudo jojonet --tun-tcp IRAN_IP` | `sudo jojonet --tun-tcp FOREIGN_IP` |
| Paqet | `sudo jojonet --paqet IRAN_IP` | `sudo jojonet --paqet FOREIGN_IP` |
| VXLAN | `sudo jojonet --vxlan IRAN_IP` | `sudo jojonet --vxlan FOREIGN_IP` |

Always run **Foreign first**, then **Iran**.

---

MIT License — [@B_khaneman](https://t.me/B_khaneman)
