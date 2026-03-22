# Iran Proxy Checker

Automatically finds and verifies **working Iranian IP proxies** every 24 hours.

## How it works

1. Scrapes 6 proxy sources (proxyhub, ditatompel, proxydb, proxyscrape, geonode)
2. Tests every candidate through `ip-api.com` to confirm the exit IP is in Iran 🇮🇷
3. Saves results to `working_iran_proxies.txt` and `working_iran_proxies.json`
4. Runs automatically every day at 06:00 UTC via GitHub Actions

## Latest results

See [`working_iran_proxies.txt`](./working_iran_proxies.txt) for today's verified list.

## Run manually

```bash
pip install -r requirements.txt
python check_proxies.py
```

## Use the proxies on Android

1. Install **Super Proxy** from Google Play
2. Copy any `IP:PORT` from `working_iran_proxies.txt`
3. Add as SOCKS5 or HTTP → tap Start
4. Verify at `iplocation.net`

## Trigger a manual run

Go to **Actions → Iran Proxy Checker → Run workflow** in your GitHub repo.
