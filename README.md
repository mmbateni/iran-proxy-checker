# Iran Proxy Checker

Automatically finds and verifies **working Iranian IP proxies** every 24 hours.

## How it works

1. Scrapes **20+ sources** (proxy sites + GitHub live-updated lists)
2. Tests every candidate via `ip-api.com` — confirms exit IP is truly in Iran 🇮🇷
3. Tries **SOCKS5 → SOCKS4 → HTTP** per proxy and records the working protocol
4. Saves results sorted by latency to `working_iran_proxies.txt` and `working_iran_proxies.json`
5. Runs automatically every day at 20:30 UTC via GitHub Actions

## Sources scraped

| Source | Type |
|---|---|
| proxyhub.me (HTTP + SOCKS5) | HTML scrape |
| ditatompel.com | HTML scrape |
| proxydb.net | HTML scrape |
| proxy-list.download (HTTP/SOCKS4/SOCKS5) | API |
| openproxy.space (HTTP/SOCKS4/SOCKS5) | Plain text |
| advanced.name | HTML scrape |
| hidemy.name (pages 1–2) | HTML scrape |
| freeproxylists.net | HTML scrape |
| spys.one | HTML scrape |
| ProxyScrape API (HTTP/SOCKS4/SOCKS5) | API |
| Geonode API (pages 1–3) | JSON API |
| monosans/proxy-list (GitHub) | Raw text |
| TheSpeedX/PROXY-List (GitHub) | Raw text |
| hookzof/socks5_list (GitHub) | Raw CSV |
| clarketm/proxy-list (GitHub) | Raw text |
| mertguvencli/http-proxy-list (GitHub) | Raw text |
| jetkai/proxy-list (GitHub) | Raw text |
| ShiftyTR/Proxy-List (GitHub) | Raw text |
| roosterkid/openproxylist (GitHub) | Raw text |

## Output format

```
# Working Iranian Proxies — checked 2025-01-01 06:00 UTC
# 47 proxies verified via ip-api.com
# Protocol breakdown: HTTP: 21  SOCKS4: 12  SOCKS5: 14

SOCKS5   185.x.x.x:1080       312ms   Tehran   AS12345 MCI
HTTP     91.x.x.x:8080        489ms   Isfahan  AS12880 DCI
...

# --- Raw IP:PORT list (for apps like Super Proxy / NekoBox) ---
185.x.x.x:1080
91.x.x.x:8080
...

# --- SOCKS5 only ---
# --- HTTP only ---
```

## Run manually

```bash
pip install -r requirements.txt
python check_proxies.py
```

## Use the proxies on Android

1. Install **Super Proxy** or **NekoBox** from Google Play
2. Copy any `IP:PORT` from `working_iran_proxies.txt`
3. Add as SOCKS5 or HTTP → tap Start
4. Verify at `iplocation.net`

## Trigger a manual run

Go to **Actions → Iran Proxy Checker → Run workflow** in your GitHub repo.
