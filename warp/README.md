# JojoNet WARP Unlock

آنلاک **Gemini / Google AI Studio / Android Studio** روی سرور خارج (Ubuntu)  
با Cloudflare WARP — بدون دست زدن به کانفیگ کلاینت‌های پنل.

ریپو: https://github.com/b-khaneman/jojonet  
پشتیبانی: [@B_khaneman](https://t.me/B_khaneman)

---

## مشکل چیه؟

روی خیلی از VPSها (به‌خصوص IPهای دیتاسنتری)، Google این‌ها را می‌بندد:

- **Gemini** → 403 / Something went wrong / region not supported  
- **Google AI Studio** → region / unusual traffic  
- **Android Studio** (دانلود SDK / Gradle / dl.google.com) → 403 یا کندی شدید  

کاربر پنلت از کانفیگ‌هات وصل می‌شود، ولی خروجی سرور خارج IP دیتاسنتر است → بلاک.

## راه‌حل این پوشه

روی **سرور خارج (Kharej)** یک تانل WireGuard به Cloudflare WARP می‌سازد و **فقط** ترافیک Google/Gemini/Android را از WARP رد می‌کند.

- بقیه سایت‌ها **مستقیم** می‌مانند → سرعت پنل حفظ می‌شود  
- کانفیگ‌های 3x-ui / Marzban / Hiddify / Xray / Sing-box را **عوض نمی‌کند**  
- با تانل‌های JojoNet تداخل ندارد (اینترفیس جدا: `warp`)

```text
کاربر → پنل/تانل ایران → سرور خارج
                              ├─ Gemini / Google / Android Studio  →  WARP (Cloudflare)
                              └─ بقیه اینترنت                     →  مستقیم (IP سرور)
```

---

## نصب (فقط سرور خارج / Ubuntu)

```bash
# از داخل ریپو
cd warp
sudo bash install.sh
```

یا بدون منو:

```bash
sudo bash install.sh --install
```

آینه اگر GitHub فیلتر است (بعد از push روی main):

```bash
curl -fsSL https://raw.githubusercontent.com/b-khaneman/jojonet/main/warp/install.sh | sudo bash
```

### حالت‌ها

| گزینه | توضیح |
|--------|--------|
| **1 / `--install`** | فقط Google + Gemini + Android Studio (**پیشنهادی**) |
| **2 / `--install google-cdn`** | بالا + رنج AWS CloudFront |
| **3 / `--install full`** | Google کامل‌تر (رنج وسیع‌تر) |

---

## دستورات

```bash
sudo bash install.sh --status      # وضعیت + تست مسیر
sudo bash install.sh --refresh     # آپدیت رنج IPهای Google
sudo bash install.sh --uninstall   # حذف تانل (اکانت می‌ماند)
sudo bash install.sh --uninstall --purge  # حذف کامل
```

---

## چیزهایی که باید بدانی

1. **جا:** فقط روی سرور خارج نصب کن (جایی که ترافیک کاربران به اینترنت می‌رود).  
2. **Root:** لازم است.  
3. **فایروال:** ترافیک UDP به `162.159.192.1:2408` باید باز باشد (خروجی سرور).  
4. **IPv6:** اسکریپت عمداً IPv4-only است تا روی VPSهای ارزان بدون IPv6 خطا ندهد.  
5. **اکانت:** رایگان Cloudflare WARP از طریق `wgcf` ثبت می‌شود؛ در `/etc/jojonet/warp/` ذخیره می‌شود.  
6. **آپدیت رنج‌ها:** گاهی IPهای Google عوض می‌شود → `--refresh` بزن.

### مسیر فایل‌ها

| مسیر | کاربرد |
|------|--------|
| `/etc/wireguard/warp.conf` | کانفیگ WireGuard |
| `/etc/jojonet/warp/` | اکانت wgcf + کش CIDR |
| `wg-quick@warp` | سرویس systemd |

---

## تست بعد از نصب

```bash
sudo bash install.sh --status
ip route get 8.8.8.8
# باید چیزی شبیه این باشد: ... dev warp ...
```

بعد از مرورگر/اندروید استودیوی کاربر پنل، Gemini و دانلود SDK باید بدون 403 منطقه کار کند.

---

## حذف

```bash
sudo bash install.sh --uninstall --purge
```

---

License: MIT (همان JojoNet)
