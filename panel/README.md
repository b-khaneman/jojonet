<div dir="rtl">

# پنل JojoNet (JojoNet Panel)

پنل تحت وب JojoNet رابطی امن و ساده برای ساخت و مدیریت تانل بین سرورهای **ایران** و **خارج** است. کافی است سرورها را در پنل اضافه کنید؛ بقیه کارها خودکار انجام می‌شود:

- افزودن سرورهای ایران و خارج (آدرس، پورت SSH، رمز یا کلید خصوصی)
- اتصال SSH به سرورها، نصب پیش‌نیازها و نصب/به‌روزرسانی اسکریپت `jojonet`
- ساخت تانل با همه حالت‌ها: `gre`، `tun_tcp`، `paqet`، `vxlan`، `wireguard`، `wg_icmp`، `wg_faketcp`، `hysteria2`، `rathole`، `wstunnel`، `dokodemo`، `xray_reverse`، `sit`، `gre6`، `ipip6`، `dnstt`، `icmp`، `spoof`
- **Xray**: Dokodemo-door (ایران به خارج) و Reverse (خارج به ایران؛ مناسب ایران‌اکسس). انتقال tcp/ws/grpc و پورت‌های فوروارد از فرم پنل.
- **IPv6**: 6to4 / GRE6 / IPIP6 — بین هر جفت ایران/خارج فقط یک تانل v6.
- **رله تک‌سرور** روی ایران یا خارج: iptables / GOST / HAProxy / Socat / Xray؛ مقصد می‌تواند سروری باشد که JojoNet ندارد.
- **DNSTT / ICMP مستقیم**: فقط سرور خارج؛ کلاینت روی دستگاه کاربر (بدون سرور ایران).
- **محل کاربران**: هنگام ساخت تانل انتخاب کنید کاربران به سرور ایران وصل شوند (تانل ایران → خارج) یا به سرور خارج (تانل خارج → ایران).
- ابزار سرور: تنظیم DNS، تست پینگ، به‌روزرسانی سیستم‌عامل از کارت هر سرور.
- **پنل‌های VPN یک‌کلیکی** (تب «پنل‌ها»): 3x-ui سنایی، X-UI اصلی (علیرضا) یا پاسارگارد. بعد از تأیید کاربر، پیشرفت نصب زنده نمایش داده می‌شود. 3x-ui و X-UI اصلی همزمان نصب نمی‌شوند. پاسارگارد به Docker نیاز دارد و روی سرور 1 گیگ ممکن است سنگین باشد.
- WireGuard داخل ICMP (`wg_icmp`) یا FakeTCP (`wg_faketcp`): برای وقتی که UDP فیلتر است؛ روی سیم فقط پینگ یا TCP دیده می‌شود.
- تانل Spoof: IP جعلی هر دو طرف را وارد کنید. پنل اول با spoof tester در هر دو جهت چک می‌کند که دیتاسنترها بسته با IP مبدأ جعلی را رد می‌کنند یا نه؛ اگر چک رد شود تانل ساخته نمی‌شود. دکمه «بررسی آمادگی Spoof» همین تست را بدون ساخت تانل اجرا می‌کند و گزینه «ساخت بدون بررسی آمادگی» از آن صرف‌نظر می‌کند. بعد از چک، سمت خارج (remote) و ایران (local) با تنظیمات آینه‌ای ساخته می‌شوند و یک تست UDP سرتاسری در هر دو جهت گرفته می‌شود. هر سرور فقط یک تانل Spoof دارد.
- بررسی سلامت تانل بعد از ساخت (health check و ping بین دو سر تانل)
- نمایش وضعیت و لاگ عملیات به‌صورت زنده
- **چندکاربره (۱.۳.۰):** مالک در تب «مدیریت» مشتری می‌سازد (روز اشتراک، سقف سرور/تانل/رله، VPN/رله/آپدیت). هر مشتری فقط دادهٔ خودش را می‌بیند.

## پیش‌نیازها

| مورد | حداقل |
|---|---|
| سیستم‌عامل | Ubuntu 20.04+ / Debian 11+ / RHEL، Rocky، Alma 8+ |
| پایتون | Python 3.10 یا بالاتر |
| دسترسی | root (یا sudo) و systemd |

> **نکته:** پایتون پیش‌فرض Ubuntu 20.04 و Debian 11 نسخه 3.8/3.9 است. روی این سیستم‌ها باید Python 3.10+ (همراه venv) را خودتان نصب کنید، یا از Ubuntu 22.04+ / Debian 12+ استفاده کنید. روی RHEL 8 نصب‌کننده تلاش می‌کند `python3.11` را خودکار نصب کند.

## نصب

### از فایل zip (پیشنهادی)

</div>

```bash
unzip JojoNet-v1.6.0-full.zip -d jojonet && cd jojonet && sudo bash setup.sh panel
```

<div dir="rtl">

برای نصب هم‌زمان اسکریپت و پنل: `sudo bash setup.sh all` (یا بدون آرگومان برای نمایش منو).

### نصب یک‌خطی با curl

</div>

```bash
curl -fsSL https://raw.githubusercontent.com/b-khaneman/jojonet/main/panel/install-panel.sh | sudo bash
```

<div dir="rtl">

با گزینه‌ها (مثلاً پورت دلخواه):

</div>

```bash
curl -fsSL https://raw.githubusercontent.com/b-khaneman/jojonet/main/panel/install-panel.sh | sudo bash -s -- --port 8443
```

<div dir="rtl">

گزینه‌های نصب‌کننده:

| گزینه | توضیح |
|---|---|
| `--port N` | پورت HTTPS پنل (پیش‌فرض `2053`) |
| `--host ADDR` | آدرس گوش‌دادن (پیش‌فرض `0.0.0.0`) |
| `--domain NAME` | دامنه پنل (رکورد A به IP همین سرور)؛ گواهی معتبر Let's Encrypt با تمدید خودکار می‌گیرد |
| `--email ADDR` | ایمیل برای Let's Encrypt (اختیاری) |
| `--no-domain` | حذف دامنه ذخیره‌شده و برگشت به گواهی خودامضا |
| `--no-firewall` | باز نکردن پورت در ufw/firewalld |

### دامنه و گواهی معتبر

</div>

```bash
sudo bash setup.sh panel --domain panel.example.com
# یا روی پنل نصب‌شده:
sudo jojonet-panel update --domain panel.example.com
```

<div dir="rtl">

- رکورد **A** دامنه باید به IP سرور اشاره کند و پورت **TCP 80** آزاد و از اینترنت در دسترس باشد (برای چالش HTTP؛ در ufw خودکار باز می‌شود).
- گواهی با certbot گرفته و هر بار تمدید شد، خودکار در پنل نصب و سرویس ری‌استارت می‌شود. دامنه ذخیره می‌شود و `update` بعدی آن را حفظ می‌کند.
- اگر گرفتن گواهی ناموفق باشد، نصب متوقف نمی‌شود و گواهی فعلی می‌ماند.
- آدرس پنل: `https://panel.example.com:2053/` (پورت با `--port` قابل تغییر است).

## اولین ورود

- در پایان نصب اول، **نام کاربری و رمز عبور مدیر به‌صورت تصادفی ساخته و فقط یک بار نمایش داده می‌شود**؛ همان لحظه ذخیره کنید.
- آدرس پنل به شکل `https://IP-سرور:2053/` است (با `sudo jojonet-panel url` هم قابل مشاهده است).
- گواهی TLS به‌صورت خودامضا (self-signed) ساخته می‌شود، پس مرورگر هشدار امنیتی نشان می‌دهد. گزینه Advanced / ادامه را بزنید.
- اگر رمز را گم کردید: `sudo jojonet-panel set-admin` (یا `--random` برای رمز تصادفی).

## دستورات مدیریتی

| دستور | کار |
|---|---|
| `sudo jojonet-panel status` | وضعیت سرویس |
| `sudo jojonet-panel start` / `stop` / `restart` | شروع / توقف / راه‌اندازی مجدد |
| `sudo jojonet-panel logs 200` | نمایش 200 خط آخر لاگ (`logs -f` برای دنبال‌کردن زنده) |
| `sudo jojonet-panel url` | نمایش آدرس پنل |
| `sudo jojonet-panel update` | دریافت و نصب آخرین نسخه (داده‌ها حفظ می‌شوند) |
| `sudo jojonet-panel set-admin` | تغییر رمز مدیر (`--username U` برای تغییر نام کاربری، `--random` برای رمز تصادفی) |
| `sudo jojonet-panel show-key` | نمایش اثرانگشت کلید رمزنگاری (vault) |
| `sudo jojonet-panel has-admin` | بررسی وجود حساب مدیر |
| `sudo jojonet-panel uninstall` | حذف پنل (`--purge` برای حذف کامل داده‌ها) |

## نکات امنیتی

- **TLS:** پنل فقط روی HTTPS اجرا می‌شود؛ کوکی‌های نشست با پرچم Secure ارسال می‌شوند.
- **رمزهای عبور:** رمز مدیر با الگوریتم scrypt هش و ذخیره می‌شود.
- **رمزنگاری اسرار SSH:** رمزها و کلیدهای SSH سرورها با Fernet رمزنگاری می‌شوند. کلید vault در `/var/lib/jojonet-panel` (فقط قابل خواندن برای کاربر سرویس) نگهداری می‌شود.
- **TOFU:** کلید میزبان (host key) هر سرور در اولین اتصال ذخیره و در اتصال‌های بعدی بررسی می‌شود؛ تغییر آن باعث رد اتصال می‌شود.
- **CSRF و Rate limit:** درخواست‌ها با توکن CSRF محافظت می‌شوند و تلاش‌های ورود ناموفق محدود می‌شوند.
- سرویس با کاربر غیر root (`jojonet-panel`) و محدودیت‌های systemd (ProtectSystem، NoNewPrivileges و…) اجرا می‌شود.
- **توصیه:** پورت پنل را در فایروال فقط برای IP خودتان باز کنید، مثلاً:

</div>

```bash
sudo ufw delete allow 2053/tcp
sudo ufw allow from YOUR.IP.ADDRESS to any port 2053 proto tcp
```

<div dir="rtl">

## تغییر پورت

نصب‌کننده را دوباره با پورت جدید اجرا کنید (داده‌ها و حساب مدیر حفظ می‌شوند):

</div>

```bash
sudo bash panel/install-panel.sh --port 8443
```

<div dir="rtl">

## پشتیبان‌گیری

همه داده‌ها (پایگاه داده، سرورها و کلید vault) در `/var/lib/jojonet-panel` است. **بدون کلید vault، اسرار SSH ذخیره‌شده قابل بازیابی نیستند.**

</div>

```bash
sudo tar -czf jojonet-panel-backup.tar.gz /var/lib/jojonet-panel /etc/jojonet-panel
```

<div dir="rtl">

برای بازگردانی: پنل را نصب کنید، `sudo jojonet-panel stop` بزنید، فایل پشتیبان را با `sudo tar -xzf jojonet-panel-backup.tar.gz -C /` باز کنید، مالکیت را اصلاح کنید (`sudo chown -R jojonet-panel:jojonet-panel /var/lib/jojonet-panel`) و `sudo jojonet-panel start` بزنید.

## حذف

| دستور | نتیجه |
|---|---|
| `sudo jojonet-panel uninstall` | حذف سرویس و فایل‌های برنامه؛ داده‌ها و تنظیمات می‌مانند |
| `sudo jojonet-panel uninstall --purge` | حذف کامل: داده‌ها، تنظیمات، گواهی، کاربر سرویس و قانون فایروال |

حذف پنل هیچ تأثیری روی اسکریپت `jojonet` و تانل‌های فعال روی سرورها (`/etc/jojonet`) ندارد.

## عیب‌یابی

- **مشاهده لاگ:** `sudo jojonet-panel logs 100` یا `journalctl -u jojonet-panel -n 100 --no-pager`
- **پورت اشغال است:** نصب‌کننده خطا می‌دهد؛ با `ss -ltnp | grep 2053` بررسی کنید یا با `--port` پورت دیگری انتخاب کنید.
- **خطای pip روی سرورهای ایران:** نصب‌کننده خودکار با میرور `mirror-pypi.runflare.com` و سپس `pypi.org` دوباره تلاش می‌کند. می‌توانید میرور دلخواه را هم تعیین کنید:

</div>

```bash
sudo PIP_INDEX_URL=https://mirror-pypi.runflare.com/simple bash panel/install-panel.sh
```

<div dir="rtl">

- **خطای CRLF:** اگر فایل‌ها روی ویندوز ویرایش یا استخراج شده باشند، با `sed -i 's/\r$//' setup.sh install.sh uninstall.sh jojonet panel/*.sh` اصلاح کنید.
- **خطای checksum:** بسته ناقص یا تغییر یافته است؛ دوباره دانلود کنید.
- **پنل باز نمی‌شود:** فایروال سرور و فایروال دیتاسنتر (Security Group) را برای پورت پنل بررسی کنید.
- **هشدار NAT / IP خصوصی:** در حالت‌های `tun_tcp` و `paqet` زیرشبکه تانل از روی IP سرورها محاسبه می‌شود. اگر سرور پشت NAT است یا IP خصوصی (مثل `10.x` یا `192.168.x` یا `172.16-31.x`) دارد، در پنل **IP عمومی** سرور را وارد کنید و مطمئن شوید پورت‌های تانل به سرور فوروارد شده‌اند؛ در غیر این صورت ممکن است زیرشبکه‌ها تداخل پیدا کنند یا تانل برقرار نشود.

</div>
