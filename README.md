# TUNNEL-MANAGER-CORE

نصبِ دستی لازم نیست: پنل باینریِ ریلیز را دانلود و به نودها push می‌کند. مراحلِ زیر برای
گرفتنِ دستیِ باینری یا ساخت از سورس است.

## باینریِ آماده

```bash
curl -fsSL https://github.com/Angize/TUNNEL-MANAGER-CORE/releases/latest/download/tnl-core-linux-amd64 -o tnl-core && chmod +x tnl-core
```

برای ARM، `amd64` را با `arm64` عوض کن. چک‌سام: همان URL با پسوندِ `.sha256`.

## ساخت از سورس

Go **1.25+** لازم است. بستهٔ `golang` دبیان/اوبونتو معمولاً قدیمی‌تر است:

```bash
curl -fsSL https://go.dev/dl/go1.27.1.linux-amd64.tar.gz | sudo tar -C /usr/local -xz && export PATH=/usr/local/go/bin:$PATH
```

بعد (نیاز به دسترسیِ اینترنت برای ماژول‌ها — `vendor/` ندارد):

```bash
git clone https://github.com/Angize/TUNNEL-MANAGER-CORE.git && cd TUNNEL-MANAGER-CORE && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o tnl-core .
```

## اجرا

```bash
sudo ./tnl-core --config core-<id>.json
```

فقط لینوکس. اجرا به root (یا `CAP_NET_RAW` + `CAP_NET_ADMIN`)، به `/dev/net/tun` و به
`iproute2` نیاز دارد؛ ترنسپورتِ `raw` به `iptables` هم. فایلِ کانفیگ را در استقرارِ واقعی
نود می‌نویسد.

| فلگ | کار |
|---|---|
| `--config <path>` | مسیرِ فایلِ JSONِ پیکربندی (تنها راهِ اجرای واقعی) |
| `--version` | چاپِ نسخه و خروج |

---

ارکستریت با 👉 [tnl-central](https://github.com/Angize/TUNNEL-MANAGER) + [tnl-node](https://github.com/Angize/TUNNEL-MANAGER-NODE) • مجوز 👉 [LICENSE](./LICENSE)
