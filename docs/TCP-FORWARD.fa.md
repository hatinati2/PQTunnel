# انتقال TCP ورودی از IP ایران به سرویس داخل تونل

حالت مستقل Node Setup عمداً فقط transport احراز هویت‌شده و رابط `pqtun0` را بالا می‌آورد؛ مسیرهای میزبان، NAT، forwarding و قوانین فایروال را تغییر نمی‌دهد. بنابراین وصل‌شدن TCP بیرونی یا حتی فعال‌بودن رابط TUN به‌تنهایی به معنی در دسترس بودن کانفیگ VLESS/Xray از IP سرور Dialer نیست.

برای سرویسی که از قبل روی آدرس TUN سمت Gateway گوش می‌دهد، این ابزار اختیاری روی Dialer یک **TCP relay در فضای کاربر** می‌سازد. این ابزار از `socat` و یک سرویس systemd استفاده می‌کند و عمداً nftables/iptables، sysctl، route، NAT یا سرویس Xray سمت Gateway را تغییر نمی‌دهد.

## پیش‌نیازها

- سرویس تونل Dialer تنظیم و فعال باشد و Gateway از داخل تونل قابل‌دسترسی باشد.
- مقدار `PQTUNNEL_REMOTE_PREFIXES` در `/etc/default/pqtunnel-client` آدرس مقصد را شامل شود؛ برای مثال `10.66.0.1/32`.
- پورت مقصد TCP در `PQTUNNEL_ALLOWED_DST_PORTS` روی هر دو سرور مجاز باشد؛ برای مثال `tcp:10488`.
- `socat` روی Dialer نصب باشد و آدرس listen در یکی از رابط‌های محلی سرور وجود داشته باشد.
- پورت TCP موردنظر عمداً در فایروال میزبان/ارائه‌دهنده برای دسترسی بیرونی مجاز شده باشد. این ابزار فایروال را باز نمی‌کند.
- سرویس Gateway از قبل روی آدرس TUN و پورت مقصد گوش بدهد. این ابزار Xray را نصب یا بازپیکربندی نمی‌کند.

## پیش‌نمایش و نصب

روی Dialer و از checkout بررسی‌شدهٔ مخزن یا بستهٔ release متناظر اجرا کن. IPها و پورت‌های نمونه را با مقادیر واقعی جایگزین کن. آدرس `192.0.2.10` فقط برای مستندسازی رزرو شده است؛ هنگام نصب، آن را با IPv4 واقعیِ تخصیص‌یافته به Dialer جایگزین کن. در حالت dry-run لازم نیست این آدرس روی رابط میزبان وجود داشته باشد.

ابتدا فقط واحد systemd را پیش‌نمایش بگیر؛ در این مرحله فایلی نوشته و سرویسی روشن نمی‌شود:

```sh
sudo bash scripts/pqtunnel-tcp-forward.sh install --name xray --listen-address 192.0.2.10 --listen-port 10488 --target-address 10.66.0.1 --target-port 10488 --dry-run
```

اگر پیش‌نمایش درست است و عمداً می‌خواهی TCP/10488 از IP ایران در دسترس باشد، سرویس را نصب و روشن کن:

```sh
sudo bash scripts/pqtunnel-tcp-forward.sh install --name xray --listen-address 192.0.2.10 --listen-port 10488 --target-address 10.66.0.1 --target-port 10488 --start
```

اسکریپت وجود یکی از واحدهای `pqtunnel-client-transport.service` یا `pqtunnel-client.service`، قرارگرفتن مقصد در remote prefixes، مجازبودن پورت TCP در allowlist و آزاد بودن پورت شنونده را بررسی می‌کند و واحد `pqtunnel-tcp-forward-xray.service` می‌سازد. گزینهٔ `--start` نیاز دارد سرویس تونل از قبل فعال باشد؛ اسکریپت تونل را مخفیانه روشن یا بازپیکربندی نمی‌کند. سرویس relay به واحد کلاینت وابسته است تا همراه توقف/راه‌اندازی مجدد آن متوقف/شروع شود. بدون `--start` فقط فایل سرویس ساخته می‌شود و فعال نخواهد شد.

نسخهٔ فعلی فقط IPv4/TCP را پشتیبانی می‌کند. جریان را بدون خاتمه‌دادن TLS/Reality و بدون تغییر محتوای VLESS/Xray عبور می‌دهد. IP عمومی کاربر اصلی حفظ نمی‌شود؛ Gateway مبدأ TCP را به‌شکل آدرس TUN سمت Dialer می‌بیند. این ابزار مسیر عمومی اینترنت ایجاد نمی‌کند و UDP را forward نمی‌کند.

## آدرس داخل کانفیگ کلاینت

برای کانفیگ Xray/VLESS که از inbound موجود Gateway روی TCP/10488 استفاده می‌کند، آدرس سمت کلاینت را روی IP عمومی قابل‌دسترسی Dialer و پورت relay بگذار:

- Address: `192.0.2.10`
- Port: `10488`

UUID، transport، پارامترهای TLS/Reality، SNI/server name، public key و short ID را بدون نیاز تغییر نده. آدرس `10.66.0.1` برای هدف داخلی relay استفاده می‌شود، نه در گوشی یا کلاینت بیرونی. همچنین IP/پورت بیرونی PQTunnel یعنی `11784` را به‌عنوان پورت VLESS وارد نکن؛ این پورت فقط transport تونل PQTunnel را حمل می‌کند.

## بررسی و حذف

```sh
sudo systemctl --no-pager --full status pqtunnel-tcp-forward-xray.service
sudo ss -lntp '( sport = :10488 )'
sudo journalctl -u pqtunnel-tcp-forward-xray.service -f
```

از کلاینت بیرونی تست واقعی انجام بده. موفقیت اتصال TCP به relay به‌تنهایی اثبات موفقیت handshake در VLESS/Reality نیست. پیامی مثل `Connection reset by peer` می‌گوید یک سمت اتصال TCP را بسته یا reset کرده؛ آن را همراه لاگ کلاینت و لاگ Xray در Gateway بررسی کن.

برای حذف فقط سرویسی که همین ابزار ساخته است:

```sh
sudo bash scripts/pqtunnel-tcp-forward.sh remove --name xray
```

حذف این واحد سرویس دیگری را حذف نمی‌کند، Xray را متوقف نمی‌کند و route/فایروال تونل را تغییر نمی‌دهد. مسیر دسترسی کنسول/خارج از باند را حفظ کن. PQTunnel آزمایشی است و ممیزی امنیتی مستقل نشده است.
