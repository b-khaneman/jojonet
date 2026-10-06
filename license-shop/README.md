# فروشگاه اشتراک ماهانه JojoNet

پرداخت وب با رمزارز. مشتری فاکتور می‌گیرد، واریز می‌کند، TXID می‌گذارد؛ مدیر تأیید می‌کند و کلید `JN1` صادر می‌شود.

```bash
sudo bash license-shop/install-shop.sh
```

- فروشگاه: `http://IP:2083`
- مدیر: `http://IP:2083/admin`
- قیمت و کیف: `/var/lib/jojonet-license-shop/shop.json`
- کلید خصوصی باید با کلید عمومی داخل `jojonet` یکی باشد.

قبل از پخش اسکریپت، `LICENSE_SHOP_URL` را در `jojonet` روی همین آدرس بگذار.
