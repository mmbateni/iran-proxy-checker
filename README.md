# Iran Proxy Checker

Automatically discovers and verifies **working proxies with routing paths into the Iranian network** every day via GitHub Actions.

## How it works

The pipeline runs in three sequential jobs:

**Job 1 - ASN Discovery** (weekly, Sundays)
Builds a database of 560+ Iranian ASNs and their IP prefixes from RIPE NCC delegated stats, Hurricane Electric BGP data, and Cloudflare Radar. Saves to `merged_routable_asns.json`.

**Job 2 - Proxy Scan** (daily)
Scrapes 19+ public proxy sources, tests every candidate against geo-verification APIs (2-of-3 must confirm Iranian exit), and runs Bale reachability checks to identify EU->IR bridge proxies. Saves raw results to `working_iran_proxies.json`.

**Job 3 - R Verification** (daily, runs after Job 2)
Runs a full 4-tier verification pass on the raw scan output using `test_proxies.R`:

| Tier | Test | Meaning |
|------|------|---------|
| **IR-exit** | 2/3 geo APIs confirm exit IP is in Iran | True Iranian-exit proxy |
| **bale-tunnel** | HTTPS CONNECT to `web.bale.ai` returns 200/3xx | Browser can reach Bale directly |
| **bale-tunnel-blocked** | HTTPS tunnel works but Bale returns 403 | Tunnel open, Bale blocks that exit IP |
| **bale-bridge** | Plain HTTP to Bale responds, no HTTPS tunnel | Works for Bale app, not browser |

Also detects and discards interceptors (Zscaler, Netskope, Blue Coat, etc.) that hijack connections and show a corporate login wall.

## Output files

| File | What's inside | Useful? |
|------|--------------|---------|
| `working_iran_proxies.txt/json` | Raw scan output - every candidate that passed the Python scanner's basic check. Many false positives (407s, echo pages, dead). | ?????? Input for R, not for end users |
| `passing_all_ranked.txt/json` | All R-verified proxies sorted by tier. The master output. | ??? Yes - this is the main result |
| `passing_bale_tunnel.txt/json` | Proxies where HTTPS CONNECT to `web.bale.ai` worked. Best for browsers. | ??? Yes - highest quality |
| `passing_bale_bridge.txt/json` | HTTP-only proxies that can reach Bale but can't tunnel HTTPS. Works for the Bale app, not the browser. | ??? Yes - fallback |
| `hiddify_iran_proxies.json` | Top 10 proxies formatted as Hiddify outbound config. | ??? Yes - if you use Hiddify |
| `merged_routable_asns.json` | The ASN database - 560+ Iranian ASNs with their IP prefixes. Used by scan.py on next run. | ??? Yes - operational, don't delete |
| `bgp_raw.json` | Raw BGP/RIPE data dump from the discovery phase. | ?????? Debug only |
| `passing_bale_tunnel_blocked.txt/json` | Proxies where the HTTPS tunnel worked but Bale blocked the exit IP (401/403). Useless for Bale specifically. | ??? Not useful |

## Use the proxies

### In a browser (Edge / Chrome)
1. Open **Settings -> System -> Proxy settings** (or search "proxy" in Start menu)
2. Manual proxy setup -> ON
3. Use any `IP:PORT` from `passing_bale_tunnel.txt`
4. Open `https://web.bale.ai` to verify

### Quick test with curl
```bash
curl -x http://IP:PORT -k https://web.bale.ai/ -I
```

### In Hiddify
Import `hiddify_iran_proxies.json` directly as an outbound configuration.

### On Android
1. Install **Super Proxy** or **NekoBox** from Google Play
2. Copy any `IP:PORT` from `passing_bale_tunnel.txt`
3. Add as HTTP proxy -> tap Start
4. Verify at `iplocation.net`

## Proxy sources scraped

| Source | Type |
|--------|------|
| proxyhub.me (HTTP + SOCKS5) | HTML scrape |
| ditatompel.com | HTML scrape |
| proxydb.net | HTML scrape |
| proxy-list.download (HTTP/SOCKS4/SOCKS5) | API |
| openproxy.space (HTTP/SOCKS4/SOCKS5) | Plain text |
| advanced.name | HTML scrape |
| hidemy.name (pages 1-2) | HTML scrape |
| freeproxylists.net | HTML scrape |
| spys.one | HTML scrape |
| ProxyScrape API (HTTP/SOCKS4/SOCKS5) | API |
| Geonode API (pages 1-3) | JSON API |
| monosans/proxy-list (GitHub) | Raw text |
| TheSpeedX/PROXY-List (GitHub) | Raw text |
| hookzof/socks5_list (GitHub) | Raw CSV |
| clarketm/proxy-list (GitHub) | Raw text |
| mertguvencli/http-proxy-list (GitHub) | Raw text |
| jetkai/proxy-list (GitHub) | Raw text |
| ShiftyTR/Proxy-List (GitHub) | Raw text |
| roosterkid/openproxylist (GitHub) | Raw text |

## Run locally

```bash
pip install aiohttp aiohttp-socks
python scan.py --proxy-only --output merged_routable_asns.json

# Then verify results in R:
# install.packages(c("jsonlite", "parallel"))
# source("test_proxies.R")
```

## Trigger a manual run

Go to **Actions -> Iran Network Scan -> Run workflow** in your GitHub repo.
