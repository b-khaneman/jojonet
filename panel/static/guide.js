'use strict';

(function () {
  const VPN = [
    {
      h: 'پنل VPN را روی سرور ایران نصب کنید',
      p: 'به بخش پنل‌ها بروید. سرور ایران را انتخاب کنید و 3x-ui سنایی را نصب کنید. اگر پنل دیگری می‌خواهید، X-UI اصلی یا پاسارگارد را انتخاب کنید. در مانیتور صبر کنید تا نصب تمام شود، بعد آدرس ورود، نام کاربری و رمز را بردارید.',
    },
  ];
  const OUT = [
    {
      h: 'فایل اوتباند را در پنل بگذارید',
      p: 'به بخش اوتباند بروید و همین تانل را باز کنید. فایل Freedom را کپی یا دانلود کنید و در تنظیمات Xray پنل، قسمت Outbounds اضافه کنید. این فایل فقط مسیر خروج ترافیک را روی تانل می‌گذارد و کانفیگ کاربر نیست. اگر متن را در ویرایشگر همان صفحه عوض کنید، کپی و دانلود همان متن ویرایش‌شده را می‌دهند.',
    },
    {
      h: 'کانفیگ Reality را برای کاربر بسازید',
      p: 'در همان صفحه کانفیگ Reality را بگیرید. در 3x-ui یک اینباند VLESS با Reality بسازید، یا فایل اینباند را وارد کنید. پورت، UUID، کلید خصوصی و Short ID باید همان مقادیر فایل باشند. اگر پورت ۴۴۳ روی فوروارد تانل است، پنل برای Reality پورت دیگری انتخاب می‌کند تا با تانل تداخل نداشته باشد. کلید خصوصی فقط در فایل اینباند سرور است و داخل لینک کاربر نمی‌آید.',
    },
    {
      h: 'مسیریابی را اضافه کنید و Xray را ری‌استارت کنید',
      p: 'قانون مسیریابی را در Xray بگذارید تا ترافیک اینباند Reality از تگ همین تانل خارج شود. سپس Xray را در پنل ری‌استارت کنید. لینک Reality را در v2rayNG یا Hiddify وارد کنید. IP خروجی باید IP سرور خارج باشد.',
    },
  ];
  const RELAY = [
    {
      h: 'رله را هم بزنید',
      p: 'رله خودش تانل جوجونت نیست. کاربر به یک سرور وصل می‌شود و ترافیک به IP مقصد می‌رود، بدون نصب جوجونت روی مقصد. به بخش رله‌ها بروید. برای TCP و UDP موتور iptables را انتخاب کنید؛ سریع‌ترین است. GOST وقتی به برنامه واسط نیاز دارید، HAProxy فقط TCP، Socat برای یک پورت ساده، و Xray dokodemo وقتی آمار ترافیک می‌خواهید. سرور رله می‌تواند ایران یا خارج باشد. IP مقصد و پورت‌ها را وارد کنید؛ مثال پورت 443,8443 یا 2096:443. اگر HAProxy را انتخاب کردید پروتکل را TCP بگذارید. ساخت رله را بزنید و در مانیتور تمام شدنش را ببینید. اگر بخش رله را نمی‌بینید، مالک پنل باید اجازه ساخت رله را برای حساب شما روشن کند.',
    },
  ];
  const BOOT = [
    {
      h: 'تانل بعد از ریبوت بالا بماند',
      p: 'روی کارت تانل و روی هر سرور، ماندن بعد از ریبوت را بزنید و در مانیتور تمام شدنش را ببینید. بدون این کار، با خاموش و روشن شدن سرور تانل بالا نمی‌آید.',
    },
  ];
  const AFTER = VPN.concat(OUT, RELAY, BOOT);

  function ready(p) {
    return {
      h: 'قبل از ساخت، سرورها آماده باشند',
      p: p || 'اگر هنوز سرور نساخته‌اید، اول آموزش شروع را بخوانید. تست اتصال هر دو سرور باید موفق باشد و نصب پیش‌نیاز روی هر دو تمام شده باشد.',
    };
  }

  function build(title, during, done) {
    return [
      ready(),
      {
        h: 'نوع تانل را انتخاب کنید',
        p: 'به بخش تانل‌ها بروید. در فهرست نوع تانل، ' + title + ' را انتخاب کنید. متن زیر فهرست را بخوانید تا سمت استقرار و سمت کاربران را با همین آموزش یکی ببینید.',
      },
    ].concat(during, [
      {
        h: 'ساخت را تا پایان مانیتور دنبال کنید',
        p: 'ساخت تانل را بزنید. به بخش مانیتور بروید و همان کار را باز بگذارید تا تمام شود. وضعیت کارت تانل باید سالم باشد. اگر خطا آمد، همان لاگ را بخوانید و قبل از ساخت دوباره، علت را برطرف کنید.',
      },
    ], done || []);
  }

  const ARTICLES = [
    {
      id: 'start',
      group: 'شروع',
      title: 'شروع کار با پنل',
      lead: 'همه تانل‌ها از همین قدم‌ها شروع می‌شوند. تا تست اتصال و نصب پیش‌نیاز تمام نشده، تانل نسازید.',
      steps: [
        { h: 'سرور ایران را اضافه کنید', p: 'به بخش سرورها بروید و افزودن سرور را بزنید. نقش را ایران بگذارید. آدرس، پورت SSH و رمز یا کلید را وارد کنید. نقش را با سرور خارج عوض نکنید؛ مسیر کاربران به همین نقش بسته است.' },
        { h: 'سرور خارج را اضافه کنید', p: 'یک سرور دیگر با نقش خارج بسازید. آدرس این سرور همان IP خروجی کاربران خواهد بود.' },
        { h: 'اتصال را تست کنید', p: 'روی هر کارت، تست اتصال را بزنید. تا نتیجه موفق نشده به قدم بعد نروید. اگر رمز یا پورت SSH اشتباه باشد، پنل نمی‌تواند تانل را نصب کند.' },
        { h: 'پیش‌نیاز و اسکریپت را نصب کنید', p: 'روی هر دو سرور، نصب پیش‌نیازها و اسکریپت را بزنید. در مانیتور صبر کنید تا کار تمام شود. این کار ابزار تانل را روی خود سرور می‌گذارد.' },
        { h: 'نوع تانل را از فهرست همین صفحه انتخاب کنید', p: 'بعد از آماده شدن سرورها، نام تانل را از ستون کنار انتخاب کنید و قدم‌های همان تانل را به ترتیب بروید. در پایان هر آموزش، نصب پنل VPN، اوتباند Reality و رله هم آمده است.' },
      ],
    },
    {
      id: 'gre',
      group: 'تانل‌ها',
      title: 'GRE',
      lead: 'تانل GRE کلاسیک با فوروارد پورت روی ایران. کاربران به ایران وصل می‌شوند و مسیر به خارج می‌رود. استقرار ابتدا از سمت خارج انجام می‌شود.',
      after: true,
      steps: build('GRE', [
        { h: 'ایران و خارج را انتخاب کنید', p: 'سرور ایران و سرور خارج را از فهرست انتخاب کنید. این نوع فیلد اضافه‌ای ندارد؛ پورت فوروارد را بعد از ساخت، پنل روی کارت تانل نشان می‌دهد.' },
      ], [
        { h: 'فوروارد پورت را بخوانید', p: 'روی کارت تانل آدرس‌ها و پورت‌های فوروارد را ببینید. سرویسی که کاربر به آن وصل می‌شود باید روی پورت ایران گوش بدهد و از تانل به خارج برسد.' },
      ]),
    },
    {
      id: 'tun_tcp',
      group: 'تانل‌ها',
      title: 'TUN/TCP',
      lead: 'تانل TUN روی TCP، به سبک Backhaul. وقتی UDP بین ایران و خارج بسته است این نوع مناسب است. کاربران روی ایران هستند و استقرار ابتدا از خارج انجام می‌شود.',
      after: true,
      steps: build('TUN/TCP', [
        { h: 'ایران و خارج را انتخاب کنید', p: 'هر دو سرور را انتخاب کنید. لازم نیست خودتان رابط TUN را روی سرور بسازید؛ پنل این کار را می‌کند.' },
      ], [
        { h: 'پورت کاربر را روی ایران باز کنید', p: 'پورت سرویس را روی ایران فوروارد کنید تا ترافیک کاربر از تانل TCP به خارج برود.' },
      ]),
    },
    {
      id: 'paqet',
      group: 'تانل‌ها',
      title: 'Paqet',
      lead: 'تانل Paqet با KCP یا Raw. به عبور بسته خام از دیتاسنتر وابسته است. کاربران روی ایران هستند و استقرار ابتدا از خارج انجام می‌شود.',
      after: true,
      steps: build('Paqet', [
        { h: 'ایران و خارج را انتخاب کنید', p: 'هر دو سرور را انتخاب کنید. تنظیم KCP را پنل خودش می‌گذارد.' },
      ], [
        { h: 'اگر ساخت ناموفق شد نوع دیگری انتخاب کنید', p: 'اگر مانیتور خطای بسته خام داد، دیتاسنتر Raw را بسته است. در این حالت WireGuard/FakeTCP یا Hysteria2 را بسازید. تا لاگ را نخوانده‌اید همان تانل را دوباره نسازید.' },
      ]),
    },
    {
      id: 'vxlan',
      group: 'تانل‌ها',
      title: 'VXLAN',
      lead: 'اورلی VXLAN روی UDP. تأخیر کم است و به باز بودن UDP بین دو سرور وابسته است. کاربران روی ایران هستند و استقرار ابتدا از خارج انجام می‌شود.',
      after: true,
      steps: build('VXLAN', [
        { h: 'UDP بین دو سرور را آزاد بگذارید', p: 'قبل از ساخت، مطمئن شوید فایروال هر دو سرور UDP بین آن‌ها را نمی‌بندد. اگر UDP بسته است، TUN/TCP یا WireGuard/FakeTCP را انتخاب کنید.' },
        { h: 'ایران و خارج را انتخاب کنید', p: 'نوع را VXLAN بگذارید و تانل را بسازید. رابط اورلی را پنل روی هر دو سرور بالا می‌آورد.' },
      ]),
    },
    {
      id: 'wireguard',
      group: 'تانل‌ها',
      title: 'WireGuard',
      lead: 'WireGuard کم‌تأخیر روی UDP. این گزینه با WireGuard/ICMP و WireGuard/FakeTCP فرق دارد. کاربران روی ایران هستند و استقرار ابتدا از خارج انجام می‌شود.',
      after: true,
      steps: build('WireGuard', [
        { h: 'همین نام را انتخاب کنید', p: 'در فهرست، WireGuard را بگذارید. WireGuard/ICMP و WireGuard/FakeTCP نوع دیگری هستند و پروتکل مسیرشان فرق دارد.' },
        { h: 'UDP باید بین دو سرور باز باشد', p: 'کلیدها را پنل خودش می‌سازد و لازم نیست دستی وارد کنید. اگر UDP بین ایران و خارج بسته است، این نوع بالا نمی‌آید؛ WireGuard/FakeTCP را انتخاب کنید.' },
      ]),
    },
    {
      id: 'wg_icmp',
      group: 'تانل‌ها',
      title: 'WireGuard/ICMP',
      lead: 'WireGuard داخل ICMP با udp2raw. با تانل مستقل ICMP فرق دارد. کاربران روی ایران هستند و استقرار ابتدا از خارج انجام می‌شود.',
      after: true,
      steps: build('WireGuard/ICMP', [
        { h: 'پینگ بین دو سرور باید جواب بدهد', p: 'این تانل روی ICMP سوار است. اگر پینگ از ایران به خارج یا برعکس بسته باشد، ساخت تمام نمی‌شود.' },
        { h: 'آن را با ICMP مستقل عوض نکنید', p: 'نوع ICMP در فهرست، pingtunnel با ChaCha20 است و WireGuard ندارد. برای WireGuard روی پینگ، فقط WireGuard/ICMP را انتخاب کنید.' },
      ]),
    },
    {
      id: 'wg_faketcp',
      group: 'تانل‌ها',
      title: 'WireGuard/FakeTCP',
      lead: 'WireGuard داخل TCP جعلی با udp2raw. وقتی UDP بسته است و TCP باز است از این نوع استفاده کنید. کاربران روی ایران هستند و استقرار ابتدا از خارج انجام می‌شود.',
      after: true,
      steps: build('WireGuard/FakeTCP', [
        { h: 'این نوع را وقتی UDP بسته است انتخاب کنید', p: 'ایران و خارج را انتخاب کنید. ظاهر بسته TCP است و داخل آن WireGuard است.' },
      ], [
        { h: 'اگر دیتاسنتر TCP غیرمعمول را قطع کرد', p: 'اگر مانیتور اتصال جعلی TCP را رد کرد، Hysteria2 یا Rathole را بسازید. یکی را سالم کنید و بعد اگر لازم بود نوع بعدی را اضافه کنید.' },
      ]),
    },
    {
      id: 'hysteria2',
      group: 'تانل‌ها',
      title: 'Hysteria2',
      lead: 'Hysteria2 برای مسیرهایی که بسته زیاد گم می‌کنند. کاربران روی ایران هستند و استقرار ابتدا از خارج انجام می‌شود.',
      after: true,
      steps: build('Hysteria2', [
        { h: 'ایران و خارج را انتخاب کنید', p: 'نوع را Hysteria2 بگذارید و تانل را بسازید. گواهی و کلید مسیر را پنل روی سرور خارج می‌گذارد.' },
        { h: 'UDP تا خارج باید برسد', p: 'کاربر به ایران وصل می‌شود، ولی خود Hysteria برای رفتن به خارج UDP می‌خواهد. اگر UDP تا خارج کامل بسته است، Rathole یا Wstunnel را انتخاب کنید.' },
      ]),
    },
    {
      id: 'rathole',
      group: 'تانل‌ها',
      title: 'Rathole',
      lead: 'تانل معکوس TCP. سرور Rathole روی ایران است و خارج به ایران وصل می‌شود. استقرار ابتدا از سمت ایران انجام می‌شود. کاربران همچنان به ایران وصل می‌شوند.',
      after: true,
      steps: build('Rathole', [
        { h: 'جهت را با تانل معمولی عوض نکنید', p: 'در این نوع، ایران شنونده است و خارج به ایران وصل می‌شود. متن زیر فهرست باید بگوید استقرار ابتدا از سمت ایران است. اگر ایران به خارج وصل نمی‌شود ولی خارج می‌تواند به ایران برسد، همین نوع را بسازید.' },
      ], [
        { h: 'پورت ورود کاربر روی ایران می‌ماند', p: 'کاربر به پورت ایران وصل می‌شود و ترافیک از تانل معکوس به خارج می‌رود.' },
      ]),
    },
    {
      id: 'wstunnel',
      group: 'تانل‌ها',
      title: 'Wstunnel',
      lead: 'تانل معکوس روی WebSocket. سرور روی ایران است و خارج به ایران وصل می‌شود. استقرار ابتدا از سمت ایران انجام می‌شود.',
      after: true,
      steps: build('Wstunnel', [
        { h: 'وقتی TCP ساده رد می‌شود این را انتخاب کنید', p: 'نوع را Wstunnel بگذارید. مسیر بین خارج و ایران باید WebSocket را عبور بدهد. جهت مثل Rathole است: شنونده ایران است.' },
        { h: 'ایران و خارج را انتخاب کنید', p: 'هر دو سرور را انتخاب کنید و تانل را بسازید. کاربر به ایران وصل می‌شود و خروج از خارج است.' },
      ]),
    },
    {
      id: 'dokodemo',
      group: 'تانل‌ها',
      title: 'Xray Dokodemo',
      lead: 'VLESS با dokodemo-door. ایران به خارج وصل می‌شود. سمت کاربران گوش می‌دهد و سمت دیگر مقصد سرویس است. استقرار ابتدا از خارج انجام می‌شود.',
      after: true,
      steps: build('Xray Dokodemo', [
        { h: 'انتقال و پورت را پر کنید', p: 'انتقال را TCP بگذارید، مگر سرویس شما WebSocket یا gRPC باشد. پورت کنترل را خالی بگذارید تا پنل خودش انتخاب کند. پورت‌های فوروارد را 443 بگذارید، یا اگر 443 روی ایران اشغال است 8443:443. یعنی کاربر به 8443 ایران وصل می‌شود و به 443 خارج می‌رسد. چند پورت را با ویرگول جدا کنید.' },
        { h: 'VLESS هر دو سرور یکی است', p: 'UUID و تنظیم VLESS را پنل روی هر دو سرور یکسان می‌گذارد. آن را دستی عوض نکنید. ایران به خارج وصل می‌شود.' },
      ]),
    },
    {
      id: 'xray_reverse',
      group: 'تانل‌ها',
      title: 'Xray Reverse',
      lead: 'VLESS reverse. خارج به پورتال ایران وصل می‌شود. استقرار ابتدا از سمت ایران انجام می‌شود. سمت کاربران گوش می‌دهد و سمت دیگر مقصد سرویس است.',
      after: true,
      steps: build('Xray Reverse', [
        { h: 'انتقال و پورت را پر کنید', p: 'انتقال را TCP بگذارید، مگر سرویس شما WebSocket یا gRPC باشد. پورت کنترل را خالی بگذارید مگر پورت مشخصی لازم دارید. پورت فوروارد را 443 یا 8443:443 وارد کنید.' },
        { h: 'جهت اتصال را برعکس Dokodemo بدانید', p: 'در این نوع خارج به پورتال ایران وصل می‌شود، نه ایران به خارج. اگر متن زیر فهرست سمت استقرار را ایران نشان داد، نوع را درست انتخاب کرده‌اید.' },
      ]),
    },
    {
      id: 'sit',
      group: 'تانل‌ها',
      title: '6to4 (SIT)',
      lead: 'یک لینک IPv6 خصوصی بین دو سرور IPv4. خودش پورت TCP را فوروارد نمی‌کند. استقرار ابتدا از خارج انجام می‌شود.',
      after: 'sit',
      steps: build('6to4 (SIT)', [
        { h: 'فقط وقتی لینک IPv6 می‌خواهید این را بسازید', p: 'ایران و خارج را انتخاب کنید. پنل لینک خصوصی IPv6 را بین دو IPv4 بالا می‌آورد.' },
      ], [
        { h: 'برای وصل شدن کاربر، GRE6 یا IPIP6 بسازید', p: 'این تانل پورت سرویس را به ایران فوروارد نمی‌کند. اگر کاربر باید به یک پورت وصل شود، آموزش GRE6 یا IPIP6 را روی همین دو سرور انجام دهید.' },
      ]),
    },
    {
      id: 'gre6',
      group: 'تانل‌ها',
      title: 'GRE6',
      lead: 'GRE روی لینک 6to4، با اورلی IPv4 و فوروارد پورت. کاربران روی ایران هستند و استقرار ابتدا از خارج انجام می‌شود.',
      after: true,
      steps: build('GRE6', [
        { h: 'ایران و خارج را انتخاب کنید', p: 'پنل اول مسیر 6to4 و بعد GRE با آدرس IPv4 را می‌سازد. لازم نیست خودتان لینک 6to4 را جدا بسازید، مگر بخواهید فقط لینک IPv6 داشته باشید که در آن صورت 6to4 (SIT) کافی است.' },
      ], [
        { h: 'فوروارد پورت را روی کارت بخوانید', p: 'پورت کاربر روی ایران است و از اورلی به خارج می‌رود. همان پورت را برای پنل VPN و اوتباند استفاده کنید.' },
      ]),
    },
    {
      id: 'ipip6',
      group: 'تانل‌ها',
      title: 'IPIP6',
      lead: 'IPIP روی لینک 6to4، با اورلی IPv4 و فوروارد پورت. کاربران روی ایران هستند و استقرار ابتدا از خارج انجام می‌شود.',
      after: true,
      steps: build('IPIP6', [
        { h: 'ایران و خارج را انتخاب کنید', p: 'فرق این نوع با GRE6 در کپسوله‌کردن بسته است. کار کاربر همان است: وصل شدن به ایران و خروج از خارج.' },
      ], [
        { h: 'فوروارد پورت را روی کارت بخوانید', p: 'پورت سرویس را از کارت تانل بردارید و در قدم اوتباند و رله همان پورت را بگذارید.' },
      ]),
    },
    {
      id: 'dnstt',
      group: 'تانل‌ها',
      title: 'DNSTT',
      lead: 'تانل DNS با DoH، DoT یا UDP. رکورد NS دامنه باید به IP سرور خارج برسد. می‌تواند فقط روی خارج، بدون سرور ایران، ساخته شود. استقرار ابتدا از خارج انجام می‌شود.',
      after: true,
      steps: [
        ready('تست اتصال سرور خارج و نصب پیش‌نیاز آن باید تمام شده باشد. سرور ایران فقط وقتی لازم است که کلاینت روی سرور ایران اجرا شود.'),
        { h: 'DNS را قبل از پنل بسازید', p: 'یک زیردامنه مثل t.example.com رکورد NS به ns.t.example.com داشته باشد و ns.t.example.com رکورد A به IP سرور خارج. تا این رکورد منتشر نشده تانل را نسازید. فقط یک DNSTT روی هر سرور مجاز است.' },
        { h: 'دامنه و resolver را وارد کنید', p: 'نوع را DNSTT بگذارید. دامنه را همان t.example.com بنویسید. Resolver ایران را DoH بگذارید، مگر دلیل مشخصی برای DoT یا UDP دارید. آدرس resolver را خالی بگذارید تا پیش‌فرض بماند، یا آدرس خودتان را بنویسید. پورت UDP خارج پیش‌فرض ۵۳۰۰ است. پورت فوروارد را 443 یا 8443:443 بگذارید.' },
        { h: 'اگر سرور ایران ندارید فقط خارج را بزنید', p: 'گزینه فقط سرور خارج را روشن کنید. در این حالت کلاینت DNSTT روی دستگاه کاربر اجرا می‌شود و فهرست سرور ایران لازم نیست. اگر این گزینه خاموش باشد باید هر دو سرور را انتخاب کنید.' },
        { h: 'ساخت را تا پایان مانیتور دنبال کنید', p: 'ساخت تانل را بزنید و در مانیتور تمام شدنش را ببینید. اگر پرس‌وجوی DNS به IP خارج نمی‌رسد، رکورد NS را دوباره بررسی کنید.' },
      ],
    },
    {
      id: 'icmp',
      group: 'تانل‌ها',
      title: 'ICMP',
      lead: 'تانل ICMP با pingtunnel و ChaCha20. با WireGuard/ICMP فرق دارد. می‌تواند فقط روی خارج، بدون سرور ایران، ساخته شود. استقرار ابتدا از خارج انجام می‌شود.',
      after: true,
      steps: [
        ready('پینگ بین دو طرف باید باز باشد. اگر حالت فقط خارج را می‌خواهید، تست اتصال و پیش‌نیاز سرور خارج کافی است.'),
        { h: 'نوع ICMP را انتخاب کنید', p: 'در فهرست، ICMP را بگذارید نه WireGuard/ICMP. WireGuard/ICMP همان WireGuard است که داخل پینگ رفته. این نوع pingtunnel است.' },
        { h: 'پورت فوروارد را وارد کنید', p: 'پورت‌ها را 443 یا 8443:443 بنویسید. فقط یک تانل ICMP روی هر سرور مجاز است. اگر پینگ بین ایران و خارج جواب ندهد، ساخت تمام نمی‌شود.' },
        { h: 'حالت فقط خارج را فقط وقتی بزنید که کلاینت روی دستگاه کاربر است', p: 'با روشن کردن فقط سرور خارج، سرور ایران حذف می‌شود و کلاینت ICMP روی دستگاه کاربر اجرا می‌شود. در غیر این صورت هر دو سرور را انتخاب کنید.' },
        { h: 'ساخت را تا پایان مانیتور دنبال کنید', p: 'ساخت تانل را بزنید و لاگ مانیتور را تا پایان باز بگذارید.' },
      ],
    },
    {
      id: 'spoof',
      group: 'تانل‌ها',
      title: 'Spoof',
      lead: 'تانل مستقل با جعل IP. فقط روی دیتاسنتری کار می‌کند که بسته با IP مبدأ جعلی را رد کند. بیشتر دیتاسنترها، از جمله Hetzner، این را می‌بندند. استقرار ابتدا از خارج انجام می‌شود.',
      after: true,
      steps: [
        ready(),
        { h: 'هر دو دیتاسنتر باید spoof را باز بگذارند', p: 'اگر یکی از دو سرور بسته با مبدأ جعلی را دور بریزد، تانل بالا نمی‌آید. قبل از پر کردن فرم این را بدانید تا وقت ساخت ناموفق نگذارید.' },
        { h: 'IP جعلی و پورت‌ها را وارد کنید', p: 'نوع را Spoof بگذارید. IP جعلی سمت ایران مبدأ بسته‌هایی است که ایران به خارج می‌فرستد. IP جعلی سمت خارج مبدأ برگشت است. این دو، آدرس خود سرورها نیستند. پورت UDP ورودی ایران، مقصد فوروارد در خارج، پروتکل رفت و برگشت و پورت‌هایشان را مطابق سرویس خودتان بگذارید. مقصد نمونه در فرم 127.0.0.1:443 است.' },
        { h: 'اول آمادگی را بررسی کنید', p: 'بررسی آمادگی Spoof را بزنید و در مانیتور نتیجه را بخوانید. پنل هر دو جهت را با spoof tester امتحان می‌کند. اگر ناموفق بود تانل را نسازید. گزینه ساخت بدون بررسی را خاموش بگذارید.' },
        { h: 'بعد از ساخت، تست UDP را در مانیتور بخوانید', p: 'اگر بررسی موفق بود ساخت تانل را بزنید. پنل بعد از ساخت یک تست UDP سرتاسری هم می‌گیرد. تا آن تست موفق نشده کاربر را به این مسیر وصل نکنید.' },
      ],
    },
    {
      id: 'vpn',
      group: 'بعد از تانل',
      title: 'پنل VPN',
      lead: 'بعد از سالم شدن تانل، پنل VPN را روی سرور ایران نصب کنید تا کاربر به ایران وصل شود و ترافیک از تانل خارج شود.',
      steps: VPN.concat([
        { h: 'مشخصات ورود را همان‌جا بردارید', p: 'بعد از اتمام نصب، آدرس و رمز روی همان کارت می‌ماند. آن را در اختیار کسی نگذارید که نباید پنل را ببیند. اگر حساب شما بخش پنل‌ها را ندارد، مالک باید اجازه VPN را روشن کند.' },
      ]),
    },
    {
      id: 'outbound',
      group: 'بعد از تانل',
      title: 'اوتباند و Reality',
      lead: 'فایل Freedom مسیر خروج Xray را روی تانل می‌گذارد. کانفیگی که به کاربر می‌دهید VLESS Reality است، نه خود فایل Freedom.',
      steps: OUT.concat([
        { h: 'خروجی را با IP خارج مقایسه کنید', p: 'بعد از ری‌استارت Xray، با کلاینت وصل شوید و IP خروجی را ببینید. باید IP سرور خارج باشد. اگر IP ایران بود، اوتباند یا قانون مسیریابی در پنل جا نیفتاده است.' },
      ]),
    },
    {
      id: 'relay',
      group: 'بعد از تانل',
      title: 'رله',
      lead: 'رله تک‌سرور است. کاربر به همین سرور وصل می‌شود و ترافیک به مقصد می‌رود. روی مقصد جوجونت نصب نمی‌شود.',
      steps: [
        { h: 'رله را بعد از تانل بسازید', p: 'اول تانل و پنل VPN باید سالم باشند. رله جای تانل را نمی‌گیرد؛ فقط ورود کاربر را به یک IP دیگر منتقل می‌کند.' },
      ].concat(RELAY, [
        { h: 'پورت رله را با پورت کاربر یکی بگذارید', p: 'پورتی که در رله می‌نویسید همان پورتی است که کاربر به آن وصل می‌شود. اگر 2096:443 بنویسید، کاربر به 2096 رله وصل می‌شود و رله به 443 مقصد می‌فرستد.' },
      ]),
    },
    {
      id: 'boot',
      group: 'بعد از تانل',
      title: 'ماندن بعد از ریبوت',
      lead: 'تانل و رله تا وقتی ماندگاری ریبوت روشن نشده، با ری‌استارت سرور پایین می‌مانند.',
      steps: BOOT.concat([
        { h: 'برای همه سرورها یک‌جا هم می‌شود', p: 'در بخش تانل‌ها، اگر دکمه ماندن بعد از ریبوت برای همه سرورها را دیدید، همان را بزنید و هر کار را در مانیتور تا پایان ببینید. بعد یک سرور را ری‌استارت آزمایشی نکنید مگر وقت داشته باشید نتیجه را در وضعیت ببینید.' },
      ]),
    },
  ];

  const DEFAULT_NOTE = 'اگر تانل را فقط روی خارج ساخته‌اید، کلاینت روی دستگاه کاربر است و نصب پنل VPN روی سرور ایران لازم نیست. رله را همچنان می‌توانید روی همان سرور خارج بسازید.';
  const FONTS = ['Vazirmatn', 'Tahoma', 'Segoe UI', 'Arial', 'Georgia', 'Times New Roman', 'Courier New', 'Consolas'];
  const SIZES = ['12px', '14px', '16px', '18px', '20px', '22px', '24px', '28px'];

  let api = null;
  let overrides = {};
  let fonts = FONTS.slice();
  let currentId = 'start';
  let editing = false;
  let dirty = false;

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text) node.textContent = text;
    return node;
  }

  function isOwner() {
    return !!(api && typeof api.owner === 'function' && api.owner());
  }

  function stepsOf(article) {
    const list = article.steps.slice();
    if (article.after === true) list.push.apply(list, AFTER);
    if (article.after === 'sit') {
      list.push({
        h: 'پنل و رله را روی GRE6 یا IPIP6 بگذارید',
        p: 'لینک 6to4 به‌تنهایی جای فوروارد پورت را نمی‌گیرد. بعد از ساخت GRE6 یا IPIP6، آموزش پنل VPN، اوتباند Reality و رله را برای همان تانل انجام دهید.',
      });
    }
    return list;
  }

  function baseArticle(id) {
    const src = ARTICLES.find((a) => a.id === id) || ARTICLES[0];
    const note = (src.id === 'dnstt' || src.id === 'icmp') ? DEFAULT_NOTE : (src.note || '');
    return {
      id: src.id,
      group: src.group,
      nav: src.title,
      title: src.title,
      lead: src.lead,
      note,
      steps: stepsOf(src).map((s) => ({ h: s.h, p: s.p })),
      style: {},
      custom: false,
    };
  }

  function resolved(id) {
    const base = baseArticle(id);
    const ov = overrides[base.id];
    if (!ov) return base;
    return {
      id: base.id,
      group: ov.group || base.group,
      nav: ov.nav || ov.title || base.nav,
      title: ov.title || base.title,
      lead: ov.lead != null ? ov.lead : base.lead,
      note: ov.note != null ? ov.note : base.note,
      steps: Array.isArray(ov.steps) && ov.steps.length ? ov.steps.map((s) => ({ h: s.h || '', p: s.p || '' })) : base.steps,
      style: ov.style && typeof ov.style === 'object' ? ov.style : {},
      custom: true,
    };
  }

  function setHtml(node, html) {
    const value = html || '';
    if (/<[a-z/!]/i.test(value)) node.innerHTML = value;
    else node.textContent = value;
  }

  function applyStyle(body, style) {
    body.style.fontFamily = style.fontFamily || '';
    body.style.fontSize = style.fontSize || '';
    body.style.lineHeight = style.lineHeight || '';
    body.style.setProperty('--guide-title-size', style.titleSize || '');
    body.style.setProperty('--guide-lead-size', style.leadSize || '');
    body.style.setProperty('--guide-step-size', style.stepSize || '');
  }

  function fillSelect(sel, items, value) {
    sel.replaceChildren();
    items.forEach((item) => {
      const opt = document.createElement('option');
      opt.value = item;
      opt.textContent = item;
      sel.append(opt);
    });
    if (value && items.includes(value)) sel.value = value;
  }

  function wrapSelection(styles) {
    const sel = window.getSelection();
    if (!sel || !sel.rangeCount || sel.isCollapsed) return;
    const range = sel.getRangeAt(0);
    const root = document.getElementById('guide-body');
    if (!root || !root.contains(range.commonAncestorContainer)) return;
    const span = document.createElement('span');
    Object.keys(styles).forEach((k) => { span.style[k] = styles[k]; });
    try {
      range.surroundContents(span);
    } catch (_err) {
      const frag = range.extractContents();
      span.append(frag);
      range.insertNode(span);
    }
    sel.removeAllRanges();
    const next = document.createRange();
    next.selectNodeContents(span);
    next.collapse(false);
    sel.addRange(next);
    dirty = true;
  }

  function toolbar() {
    let bar = document.getElementById('guide-toolbar');
    if (bar) return bar;
    bar = el('div', 'guide-toolbar');
    bar.id = 'guide-toolbar';
    bar.hidden = true;

    const font = document.createElement('select');
    font.id = 'guide-font';
    font.setAttribute('aria-label', 'فونت');
    fillSelect(font, fonts, 'Vazirmatn');
    font.addEventListener('change', () => {
      if (editing) wrapSelection({ fontFamily: font.value });
      const body = document.getElementById('guide-body');
      if (body && editing) {
        body.style.fontFamily = font.value;
        dirty = true;
      }
    });

    const size = document.createElement('select');
    size.id = 'guide-size';
    size.setAttribute('aria-label', 'اندازه فونت');
    fillSelect(size, SIZES, '16px');
    size.addEventListener('change', () => {
      const sel = window.getSelection();
      if (sel && !sel.isCollapsed && editing) wrapSelection({ fontSize: size.value });
      else if (editing) {
        const body = document.getElementById('guide-body');
        if (body) {
          body.style.fontSize = size.value;
          dirty = true;
        }
      }
    });

    const titleSize = document.createElement('select');
    titleSize.id = 'guide-title-size';
    titleSize.setAttribute('aria-label', 'اندازه عنوان');
    fillSelect(titleSize, SIZES, '20px');
    titleSize.addEventListener('change', () => {
      const body = document.getElementById('guide-body');
      if (body && editing) {
        body.style.setProperty('--guide-title-size', titleSize.value);
        dirty = true;
      }
    });

    const color = document.createElement('input');
    color.type = 'color';
    color.id = 'guide-color';
    color.value = '#0b7f96';
    color.setAttribute('aria-label', 'رنگ متن');
    color.addEventListener('input', () => {
      if (editing) wrapSelection({ color: color.value });
    });

    function cmd(label, action) {
      const btn = el('button', 'btn btn-sm', label);
      btn.type = 'button';
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        action();
        dirty = true;
      });
      return btn;
    }

    const tools = el('div', 'guide-tools');
    tools.append(
      el('label', 'guide-tool-label', 'فونت'),
      font,
      el('label', 'guide-tool-label', 'اندازه'),
      size,
      el('label', 'guide-tool-label', 'عنوان'),
      titleSize,
      el('label', 'guide-tool-label', 'رنگ'),
      color,
      cmd('ضخیم', () => document.execCommand('bold')),
      cmd('کج', () => document.execCommand('italic')),
      cmd('زیرخط', () => document.execCommand('underline')),
      cmd('+ مرحله', () => addStep()),
    );

    const actions = el('div', 'guide-edit-actions');
    const save = el('button', 'btn btn-primary btn-sm', 'ذخیره');
    save.type = 'button';
    save.id = 'guide-save';
    save.addEventListener('click', () => saveArticle());
    const cancel = el('button', 'btn btn-sm', 'انصراف');
    cancel.type = 'button';
    cancel.addEventListener('click', () => {
      editing = false;
      dirty = false;
      paint(currentId);
    });
    const reset = el('button', 'btn btn-ghost btn-sm', 'بازگشت به پیش‌فرض');
    reset.type = 'button';
    reset.id = 'guide-reset';
    reset.addEventListener('click', () => resetArticle());
    actions.append(save, cancel, reset);

    bar.append(tools, actions);
    const section = document.getElementById('tab-guide');
    const guide = section && section.querySelector('.guide');
    if (guide) section.insertBefore(bar, guide);
    else if (section) section.append(bar);
    return bar;
  }

  function ownerActions() {
    let box = document.getElementById('guide-owner-actions');
    if (box) return box;
    const head = document.querySelector('#tab-guide .section-head');
    if (!head) return null;
    box = el('div', 'section-actions');
    box.id = 'guide-owner-actions';
    box.hidden = true;
    const edit = el('button', 'btn btn-sm', 'ویرایش این آموزش');
    edit.type = 'button';
    edit.id = 'guide-edit-btn';
    edit.addEventListener('click', () => startEdit());
    box.append(edit);
    head.append(box);
    return box;
  }

  function markDirty() {
    dirty = true;
  }

  function makeEditable(node) {
    node.contentEditable = 'true';
    node.spellcheck = true;
    node.addEventListener('input', markDirty);
  }

  function addStep() {
    const ol = document.querySelector('#guide-body .guide-steps');
    if (!ol || !editing) return;
    const li = document.createElement('li');
    const h = el('h3', null, 'عنوان مرحله');
    const p = el('p', null, 'متن مرحله را اینجا بنویسید.');
    makeEditable(h);
    makeEditable(p);
    const del = el('button', 'btn btn-ghost btn-sm guide-step-del', 'حذف مرحله');
    del.type = 'button';
    del.addEventListener('click', () => {
      li.remove();
      dirty = true;
    });
    li.append(h, p, del);
    ol.append(li);
    dirty = true;
    h.focus();
  }

  function readStyle() {
    const body = document.getElementById('guide-body');
    const font = document.getElementById('guide-font');
    const titleSize = document.getElementById('guide-title-size');
    const style = {};
    if (font && font.value) style.fontFamily = font.value;
    if (body && body.style.fontSize) style.fontSize = body.style.fontSize;
    if (titleSize && titleSize.value) style.titleSize = titleSize.value;
    const lead = body && body.style.getPropertyValue('--guide-lead-size');
    const step = body && body.style.getPropertyValue('--guide-step-size');
    const line = body && body.style.lineHeight;
    if (lead) style.leadSize = lead;
    if (step) style.stepSize = step;
    if (line) style.lineHeight = line;
    return style;
  }

  function collectArticle() {
    const body = document.getElementById('guide-body');
    const title = body.querySelector('.guide-title');
    const lead = body.querySelector('.guide-lead');
    const note = body.querySelector('.guide-note');
    const kicker = body.querySelector('.guide-kicker');
    const steps = [];
    body.querySelectorAll('.guide-steps li').forEach((li) => {
      const h = li.querySelector('h3');
      const p = li.querySelector('p');
      steps.push({ h: h ? h.innerHTML.trim() : '', p: p ? p.innerHTML.trim() : '' });
    });
    return {
      id: currentId,
      group: kicker ? kicker.textContent.trim() : '',
      nav: title ? title.textContent.trim() : '',
      title: title ? title.innerHTML.trim() : '',
      lead: lead ? lead.innerHTML.trim() : '',
      note: note ? note.innerHTML.trim() : '',
      steps,
      style: readStyle(),
    };
  }

  async function saveArticle() {
    if (!api || !api.save) return;
    const payload = collectArticle();
    const btn = document.getElementById('guide-save');
    if (btn) btn.disabled = true;
    try {
      const r = await api.save(payload);
      if (r && r.article) overrides[r.article.id] = r.article;
      editing = false;
      dirty = false;
      if (api.toast) api.toast('آموزش ذخیره شد.', 'success');
      paint(currentId);
    } catch (err) {
      if (api.toast) api.toast((err && err.message) || 'ذخیره نشد.', 'error');
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  async function resetArticle() {
    if (!api || !api.reset) return;
    const ok = api.confirm
      ? await api.confirm({ title: 'بازگشت به پیش‌فرض', message: 'متن ویرایش‌شده این آموزش پاک شود و نسخه پیش‌فرض برگردد؟', okText: 'بازگشت به پیش‌فرض' })
      : window.confirm('بازگشت به پیش‌فرض؟');
    if (!ok) return;
    try {
      await api.reset(currentId);
      delete overrides[currentId];
      editing = false;
      dirty = false;
      if (api.toast) api.toast('آموزش به متن پیش‌فرض برگشت.', 'success');
      paint(currentId);
    } catch (err) {
      if (api.toast) api.toast((err && err.message) || 'بازنشانی نشد.', 'error');
    }
  }

  function startEdit() {
    if (!isOwner()) return;
    editing = true;
    dirty = false;
    paint(currentId);
  }

  function syncOwnerUi(article) {
    const actions = ownerActions();
    const bar = toolbar();
    const editBtn = document.getElementById('guide-edit-btn');
    if (actions) actions.hidden = !isOwner() || editing;
    if (bar) bar.hidden = !editing;
    if (editBtn) editBtn.textContent = article.custom ? 'ویرایش دوباره' : 'ویرایش این آموزش';
  }

  function paint(id) {
    if (editing && dirty && id !== currentId) {
      if (!window.confirm('تغییرات ذخیره نشده‌اند. ادامه بدون ذخیره؟')) return;
      editing = false;
      dirty = false;
    }
    currentId = id || currentId;
    const body = document.getElementById('guide-body');
    const nav = document.getElementById('guide-nav');
    if (!body || !nav) return;
    const article = resolved(currentId);
    nav.querySelectorAll('.guide-link').forEach((btn) => {
      const on = btn.dataset.guide === article.id;
      btn.classList.toggle('is-on', on);
      if (on) btn.setAttribute('aria-current', 'true');
      else btn.removeAttribute('aria-current');
      const ov = overrides[btn.dataset.guide];
      const src = ARTICLES.find((a) => a.id === btn.dataset.guide);
      btn.textContent = (ov && (ov.nav || ov.title)) || (src && src.title) || btn.dataset.guide;
    });
    body.replaceChildren();
    body.classList.toggle('is-editing', editing);
    applyStyle(body, article.style || {});

    const kicker = el('p', 'guide-kicker', article.group);
    const title = el('h2', 'guide-title');
    setHtml(title, article.title);
    const lead = el('p', 'guide-lead');
    setHtml(lead, article.lead);
    body.append(kicker, title, lead);

    const ol = document.createElement('ol');
    ol.className = 'guide-steps';
    article.steps.forEach((step) => {
      const li = document.createElement('li');
      const h = el('h3');
      const p = el('p');
      setHtml(h, step.h);
      setHtml(p, step.p);
      li.append(h, p);
      if (editing) {
        makeEditable(h);
        makeEditable(p);
        const del = el('button', 'btn btn-ghost btn-sm guide-step-del', 'حذف مرحله');
        del.type = 'button';
        del.addEventListener('click', () => {
          li.remove();
          dirty = true;
        });
        li.append(del);
      }
      ol.append(li);
    });
    body.append(ol);

    if (article.note || editing) {
      const note = el('p', 'guide-note');
      setHtml(note, article.note || '');
      if (editing && !article.note) note.textContent = '';
      body.append(note);
      if (editing) makeEditable(note);
    }

    if (editing) {
      makeEditable(title);
      makeEditable(lead);
      makeEditable(kicker);
      const font = document.getElementById('guide-font');
      const size = document.getElementById('guide-size');
      const titleSize = document.getElementById('guide-title-size');
      if (font) fillSelect(font, fonts, article.style.fontFamily || 'Vazirmatn');
      if (size) size.value = article.style.fontSize || '16px';
      if (titleSize) titleSize.value = article.style.titleSize || '20px';
      if (article.style.fontSize) body.style.fontSize = article.style.fontSize;
    }

    syncOwnerUi(article);
  }

  function buildNav() {
    const nav = document.getElementById('guide-nav');
    if (!nav) return;
    nav.replaceChildren();
    let group = '';
    ARTICLES.forEach((article) => {
      if (article.group !== group) {
        group = article.group;
        const head = el('div', 'guide-group', group);
        head.setAttribute('role', 'presentation');
        nav.append(head);
      }
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'guide-link';
      btn.dataset.guide = article.id;
      const ov = overrides[article.id];
      btn.textContent = (ov && (ov.nav || ov.title)) || article.title;
      btn.addEventListener('click', () => paint(article.id));
      nav.append(btn);
    });
  }

  async function loadOverrides() {
    if (!api || !api.load) return;
    try {
      const data = await api.load();
      overrides = (data && data.articles) || {};
      if (Array.isArray(data && data.fonts) && data.fonts.length) fonts = data.fonts.slice();
    } catch (_err) {
      overrides = {};
    }
  }

  window.jojoMountGuide = async function (opts) {
    api = opts || api || {};
    ownerActions();
    toolbar();
    const nav = document.getElementById('guide-nav');
    if (!nav) return;
    await loadOverrides();
    buildNav();
    paint(currentId || 'start');
  };

  window.jojoGuideRefresh = async function () {
    if (!api) return;
    const wasEditing = editing;
    if (!wasEditing) await loadOverrides();
    syncOwnerUi(resolved(currentId));
    if (!wasEditing) paint(currentId);
  };
})();
