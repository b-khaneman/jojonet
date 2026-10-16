# AI-WARP

آنلاک خودکار **Gemini / Google Flow / ChatGPT / Claude / …** روی سرور خارج  
با **یک دستور** — بدون پرسش، بدون دست زدن به کانفیگ پنل یا CDN کلودفلر.

نسخه: **1.1.0**  
پشتیبانی: [@B_khaneman](https://t.me/B_khaneman)

---

## نصب (فقط همین)

روی سرور **خارج (Kharej)** که پنل/خروجی اینترنتت روشه:

```bash
curl -fsSL https://raw.githubusercontent.com/b-khaneman/jojonet/main/warp/install.sh | sudo bash
```

اگر GitHub فیلتر است:

```bash
curl -fsSL https://cdn.jsdelivr.net/gh/b-khaneman/jojonet@main/warp/install.sh | sudo bash
```

تمام. هیچ منو، هیچ سؤال، هیچ تنظیم دستی.

اسکریپت خودش:
1. پیش‌نیازها را نصب می‌کند  
2. Cloudflare WARP را ثبت/وصل می‌کند  
3. فقط ترافیک AI را از WARP رد می‌کند  
4. Sticky IP + watchdog را فعال می‌کند  
5. تانل پنل و **CDN کلودفلر** را دست نمی‌زند  

---

## با تانل + CDN کلودفلر

| چیز | وضعیت |
|-----|--------|
| کانفیگ‌های تانل / پنل | دست‌نخورده |
| Cloudflare CDN (دامنه پنل) | مستقیم می‌ماند (رنج‌های CF از WARP حذف شده‌اند) |
| Gemini / Flow / ChatGPT / Claude / … | از WARP خارج می‌شوند |

فقط روی **همین سرور خروجی** نصب کن. بعد از نصب، از کانفیگ‌هات برو Gemini — باید بدون 403/region باز شود.

---

## دستورات اختیاری

```bash
ai-warp status     # وضعیت
ai-warp ip         # IP خروجی WARP
ai-warp refresh    # آپدیت روت‌ها
ai-warp uninstall --purge
```

---

## حالت‌ها (اگر لازم شد)

پیش‌فرض همان `ai` است (همه هوش مصنوعی‌ها).

```bash
sudo bash install.sh --mode google   # فقط Google / Flow / Android
sudo bash install.sh --mode full     # AI + CloudFront
sudo bash install.sh --menu          # منوی دستی
```

---

License: MIT
