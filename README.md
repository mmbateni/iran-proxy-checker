# Iran Proxy Checker

Automatically discovers and verifies **working proxies with routing paths into the Iranian network** every day via GitHub Actions.

## How it works

The pipeline runs in four sequential jobs:

**Job 0 - SNI-Fronting Discovery** (weekly, Sundays)
Probes Cloudflare anycast ranges for working `(connect_ip, fake_sni)` pairs that can front connections to Iranian infrastructure. Replicates the [patterniha domain-fronting technique](https://t.me/patterniha): Iranian DPI sees a whitelisted Cloudflare SNI in the TLS ClientHello and passes it through; Cloudflare's edge then routes the payload to the real Iranian target via the HTTP Host header. Results saved to `working_sni_fronting.json`.

**Job 1 - ASN Discovery** (weekly, Sundays)
Builds a database of 560+ Iranian ASNs and their IP prefixes from RIPE NCC delegated stats, Hurricane Electric BGP data, and Cloudflare Radar. Saves to `merged_routable_asns.json`.

**Job 2 - Proxy Scan** (daily)
Scrapes 19+ public proxy sources, tests every candidate against geo-verification APIs (2-of-3 must confirm Iranian exit), and runs Bale/Rubika/Splus reachability checks to identify EU->IR bridge proxies. Saves raw results to `working_iran_proxies.json`.

**Job 3 - R Verification** (daily, runs after Job 2)
Runs a full **5-tier** verification pass on the raw scan output using `test_proxies.R`:

| Tier | Name | Test | Meaning |
|------|------|------|---------|
| **0** | **sni-fronting** | TLS ClientHello with fake Cloudflare SNI routes to `tapi.bale.ai` via proxy | Domain-fronted — DPI only sees a whitelisted CF domain. Most censorship-resistant. |
| **1** | **IR-exit** | 2/3 geo APIs confirm exit IP is in Iran | True Iranian-exit proxy |
| **2** | **bale-tunnel** | HTTPS CONNECT to `web.bale.ai` returns 200/3xx | Browser can reach Bale directly |
| **3** | **bale-tunnel-blocked** | HTTPS tunnel works but Bale returns 403 | Tunnel open, Bale blocks that exit IP |
| **4** | **bale-bridge** | Plain HTTP to Bale responds, no HTTPS tunnel | Works for Bale app, not browser |

Also detects and discards interceptors (Zscaler, Netskope, Blue Coat, etc.) that hijack connections and show a corporate login wall.

## How SNI-fronting works (Tier 0)

```
User -> Proxy -> Cloudflare anycast IP (connect_ip)
                    |
                    | TLS ClientHello SNI = "static.cloudflareinsights.com"  <- DPI sees this
                    | HTTP Host: tapi.bale.ai                                 <- CF routes this
                    |
              Iranian infra responds
```

This is the same technique used by the [patterniha](https://t.me/patterniha) TCP-forwarder tool (`SNI-Spoofing_by_patterniha.exe`). The proxy scanner implements it natively in Python (`scan.py`) and the R verifier tests it using `curl --tls-servername` + `--resolve`. A Tier 0 proxy can be used directly as a `config.json` `CONNECT_IP` + `FAKE_SNI` pair for the patterniha tool.

## Output files

| File | What's inside | Useful? |
|------|--------------|---------|
| `working_sni_fronting.json` | Cloudflare anycast IP + fake SNI pairs that successfully front Iranian infra. Updated weekly. | ✅ Yes - Tier 0 input for R verifier + patterniha configs |
| `passing_sni_fronting.txt/json` | R-verified proxies that passed Tier 0 SNI-fronting test. Most DPI-resistant. | ✅ Yes - highest quality |
| `working_iran_proxies.txt/json` | Raw scan output — every candidate that passed the Python scanner's basic check. Many false positives. | ⚠️ Input for R, not for end users |
| `passing_all_ranked.json/txt` | All R-verified proxies sorted by tier (0→4). The master output. | ✅ Yes - main result |
| `passing_bale_tunnel.txt/json` | Proxies where HTTPS CONNECT to `web.bale.ai` worked (Tier 2). Best for browsers when no Tier 0 available. | ✅ Yes |
| `passing_bale_bridge.txt/json` | HTTP-only proxies that can reach Bale but can't tunnel HTTPS (Tier 4). Works for the Bale app, not the browser. | ✅ Yes - fallback |
| `passing_ir_exit.txt/json` | Proxies with confirmed Iranian exit IP (Tier 1). | ✅ Yes |
| `passing_bale_tunnel_blocked.txt/json` | Tunnel works but Bale blocks the exit IP (Tier 3). Useless for Bale specifically. | ⚠️ Not useful |
| `hiddify_iran_proxies.json` | Top 10 proxies formatted as Hiddify outbound config. | ✅ Yes - if you use Hiddify |
| `merged_routable_asns.json` | ASN database — 560+ Iranian ASNs with IP prefixes. Used by scan.py on next run. | ✅ Operational, don't delete |
| `bgp_raw.json` | Raw BGP/RIPE data dump from the discovery phase. | ⚠️ Debug only |

## Priority scoring

Proxies in `passing_all_ranked` are sorted by priority score (highest first):

| Tier | Base score | Bonus sources |
|------|-----------|---------------|
| sni-fronting | 1200 | +100 IR exit, +40 neighbor country, +30 SOCKS |
| IR-exit | 1000 | +20 per geo hit, +100 IR country, +30 SOCKS |
| bale-tunnel | 800 | +50 HTTPS 200, +40 neighbor country, +30 SOCKS |
| bale-tunnel-blocked | 650 | same bonuses |
| bale-bridge | 400 | same bonuses |

## Use the proxies

### Best option — SNI-fronting proxy (Tier 0)

Use any entry from `passing_sni_fronting.txt` directly as a system proxy. It will transparently apply domain-fronting on every HTTPS connection.

**Browser (Edge / Chrome):**
1. Open **Settings → System → Proxy settings**
2. Manual proxy setup → ON
3. Use any `IP:PORT` from `passing_sni_fronting.txt`
4. Open `https://web.bale.ai` to verify

**curl test:**
```bash
# Standard proxy test
curl -x http://IP:PORT -k https://web.bale.ai/ -I

# SNI-fronting test (verifies Tier 0 capability)
curl -x http://IP:PORT \
     --tls-servername static.cloudflareinsights.com \
     --resolve tapi.bale.ai:443:104.16.79.73 \
     -k https://tapi.bale.ai/ -I
```

### Use as patterniha config (SNI-Spoofing tool)

Pick any entry from `working_sni_fronting.json` and plug the values into `config.json`:

```json
{
  "LISTEN_HOST": "127.0.0.1",
  "LISTEN_PORT": 40443,
  "CONNECT_IP":  "<connect_ip from working_sni_fronting.json>",
  "CONNECT_PORT": 443,
  "FAKE_SNI":    "<fake_sni from working_sni_fronting.json>"
}
```

Then run `SNI-Spoofing_by_patterniha.exe` as Administrator and point your V2Ray/Trojan config at `127.0.0.1:40443`.

### Fallback — HTTPS tunnel proxy (Tier 2)

Use any entry from `passing_bale_tunnel.txt` if no Tier 0 proxies are available.

```bash
curl -x http://IP:PORT -k https://web.bale.ai/ -I
```

### In Hiddify
Import `hiddify_iran_proxies.json` directly as an outbound configuration.

### On Android
1. Install **Super Proxy** or **NekoBox** from Google Play
2. Copy any `IP:PORT` from `passing_sni_fronting.txt` (or `passing_bale_tunnel.txt` as fallback)
3. Add as HTTP proxy → tap Start
4. Verify at `iplocation.net`

## Manual run modes

Go to **Actions → Iran Network Scan → Run workflow** and select a mode:

| Mode | What runs |
|------|-----------|
| `full` | SNI discovery + ASN discovery + proxy scan + R verify |
| `proxy-only` | Re-uses committed ASN database, runs scan + R verify |
| `asn-only` | Refreshes ASN/prefix database only |
| `sni-only` | Refreshes SNI-fronting pairs only (`working_sni_fronting.json`) |

## Run locally

```bash
pip install aiohttp aiohttp-socks

# Full pipeline
python scan.py --proxy-only --output merged_routable_asns.json

# Refresh SNI-fronting pairs only
python scan.py --sni-fronting --output merged_routable_asns.json

# Verify results in R
# install.packages(c("jsonlite", "parallel"))
Rscript test_proxies.R working_iran_proxies.json --workers 8 --timeout 5
```

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
