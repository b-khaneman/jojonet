# AI-WARP

آنلاک حرفه‌ای **تمام سرویس‌های هوش مصنوعی** روی سرور خارج (Ubuntu)  
با Cloudflare WARP — بدون تغییر کانفیگ پنل.

نسخه: **1.0.0**  
پشتیبانی: [@B_khaneman](https://t.me/B_khaneman)  
ریپو: https://github.com/b-khaneman/jojonet/tree/main/warp

---

## چه چیزی آنلاک می‌شود؟

| دسته | سرویس‌ها |
|------|-----------|
| **Google AI** | Gemini، AI Studio، **Google Flow** (Veo)، NotebookLM، Jules |
| **Android** | Android Studio، SDK، `dl.google.com`، Maven Google |
| **OpenAI** | ChatGPT، API، platform.openai.com |
| **Anthropic** | Claude.ai |
| **Microsoft** | Copilot |
| **xAI** | Grok |
| **سایر** | Perplexity، Midjourney، HuggingFace، Groq، DeepSeek، Cursor، … |

ترافیک این‌ها از **WARP** خارج می‌شود → خطای **403 / region** برطرف می‌شود.  
بقیه اینترنت **مستقیم** می‌ماند → سرعت پنل حفظ می‌شود.

```text
کاربر پنل ──► ایران ──► سرور خارج
                            ├─ AI / Google Flow / Gemini / …  →  Cloudflare WARP
                            └─ بقیه سایت‌ها                   →  IP مستقیم سرور
```

---

## نصب یک‌خطی (پیشنهادی)

روی **سرور خارج (Kharej) / Ubuntu** با دسترسی root:

```bash
curl -fsSL https://raw.githubusercontent.com/b-khaneman/jojonet/main/warp/install.sh | sudo bash
```

اگر GitHub فیلتر است:

```bash
curl -fsSL https://cdn.jsdelivr.net/gh/b-khaneman/jojonet@main/warp/install.sh | sudo bash
```

نصب مستقیم بدون منو (حالت همه AIها):

```bash
curl -fsSL https://raw.githubusercontent.com/b-khaneman/jojonet/main/warp/install.sh | sudo bash -s -- --install
```

از داخل کلون ریپو:

```bash
cd warp
sudo bash install.sh --install
```

منوی تعاملی گزینه **1** را بزن (ALL AI).

---

## IP ثابت / پایدار

| لایه | رفتار |
|------|--------|
| **اکانت WARP** | یک‌بار ساخته و در `/etc/ai-warp/` ذخیره می‌شود — بعد از ریبوت عوض نمی‌شود |
| **تانل** | `systemd` + watchdog هر ۲ دقیقه — اگر قطع شود خودکار بالا می‌آید |
| **Sticky IP** | اولین IP موفق قفل می‌شود (`ai-warp ip`) |
| **رفرش روت** | هر ۶ ساعت دامنه‌های AI دوباره resolve می‌شوند |

> IP خروجی رایگان WARP گاهی عوض می‌شود؛ **هویت اکانت و تانل پایدار** است.  
> برای پایداری قوی‌تر لایسنس WARP+ بده:

```bash
export AI_WARP_LICENSE="xxxx-xxxx-xxxx-xxxx"
sudo -E bash install.sh --install
# یا بعداً:
sudo AI_WARP_LICENSE=xxxx-xxxx-xxxx-xxxx ai-warp install
```

```bash
ai-warp ip            # وضعیت sticky
ai-warp ip --relock   # قفل دوباره روی IP فعلی
```

---

## دستورات

```bash
ai-warp status       # سلامت تانل + مسیر Google + sticky IP
ai-warp refresh      # آپدیت رنج/دامنه‌ها
ai-warp restart      # ری‌استارت تانل
ai-warp uninstall    # حذف (اکانت می‌ماند)
ai-warp uninstall --purge
```

---

## حالت‌های نصب

| حالت | توضیح |
|------|--------|
| `ai` (پیش‌فرض) | همه AIها + Google Flow + Android Studio |
| `google` | فقط خانواده Google / Flow / Android |
| `full` | AI + رنج‌های CloudFront |

```bash
sudo ai-warp install ai
sudo ai-warp install google
sudo ai-warp install full
```

---

## ویرایش لیست دامنه‌ها

```bash
sudo nano /etc/ai-warp/ai-domains.txt
sudo ai-warp refresh
```

---

## مسیر فایل‌ها

| مسیر | نقش |
|------|-----|
| `/usr/local/bin/ai-warp` | CLI |
| `/usr/local/share/ai-warp/` | لایبرری + systemd unitها |
| `/etc/ai-warp/` | اکانت، sticky-ip، CIDR، domains |
| `/etc/wireguard/aiwarp.conf` | WireGuard |
| `wg-quick@aiwarp` | سرویس تانل |
| `ai-warp-watchdog.timer` | نگهبان پایداری |

اینترفیس `aiwarp` با تانل‌های JojoNet تداخل ندارد.

---

## تست

```bash
ai-warp status
ip route get 8.8.8.8
# باید dev aiwarp را نشان دهد
```

سپس از کانفیگ پنل: Gemini، Flow، ChatGPT، Claude، Android Studio را چک کن.

---

## حذف

```bash
sudo ai-warp uninstall --purge
# یا:
sudo bash uninstall.sh --purge
```

---

## ساختار پروژه

```text
warp/
├── install.sh          # نصب‌کننده یک‌خطی
├── uninstall.sh
├── VERSION / LICENSE / README.md
├── bin/ai-warp         # CLI اصلی
├── conf/ai-domains.txt # لیست AI / Flow / …
├── lib/                # ماژول‌ها (deps, wgcf, routes, sticky, health)
├── scripts/routes.sh   # اعمال روت کرنل
└── systemd/            # watchdog + refresh timers
```

License: MIT
