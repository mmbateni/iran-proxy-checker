#!/usr/bin/env python3
"""
Iran Proxy Checker — Enhanced Edition
Scrapes 20+ sources for Iranian IP proxies, tests each one,
and saves a clean list of working proxies to working_iran_proxies.txt

Sources added vs. original:
  • 6  GitHub raw proxy-list repos (monosans, TheSpeedX, hookzof, jetkai,
       clarketm, mertguvencli)
  • proxy-list.download  (HTTP + SOCKS4 + SOCKS5)
  • openproxy.space      (HTTP + SOCKS4 + SOCKS5)
  • spys.one             (HTML scrape)
  • advanced.name        (country filter)
  • hidemy.name          (country filter)
  • freeproxylists.net   (raw text)
  • Geonode  pagination  (pages 1-3)
  • ProxyScrape per-protocol  (http / socks4 / socks5)
"""

import socket
import socks
import requests
import concurrent.futures
import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path

# ── Config ────────────────────────────────────────────────────────────────────

TIMEOUT        = 10        # seconds per proxy test
MAX_WORKERS    = 60        # concurrent test threads (raise on fast machines)
VERIFY_URL     = "http://ip-api.com/json/?fields=status,country,countryCode,query,org,city"
COUNTRY_CODE   = "IR"

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "en-US,en;q=0.9",
}

IP_PATTERN  = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})\b")
VALID_IP_RE = re.compile(
    r"^(?!0\.|10\.|127\.|169\.254\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)"
    r"\d{1,3}(?:\.\d{1,3}){3}$"
)

# ── Sources ───────────────────────────────────────────────────────────────────

# Plain-text / HTML sources — scraped with scrape_raw_text()
RAW_TEXT_SOURCES = {
    # ── Original sources ──────────────────────────────────────────────────────
    "proxyhub_socks5"   : "https://proxyhub.me/en/ir-socks5-proxy-list.html",
    "proxyhub_http"     : "https://proxyhub.me/en/ir-free-proxy-list.html",
    "ditatompel"        : "https://www.ditatompel.com/proxy/country/ir",
    "proxydb"           : "https://proxydb.net/?country=IR",

    # ── proxy-list.download ───────────────────────────────────────────────────
    "pld_http"          : "https://www.proxy-list.download/api/v1/get?type=http&country=IR",
    "pld_socks4"        : "https://www.proxy-list.download/api/v1/get?type=socks4&country=IR",
    "pld_socks5"        : "https://www.proxy-list.download/api/v1/get?type=socks5&country=IR",

    # ── openproxy.space ───────────────────────────────────────────────────────
    "openproxy_http"    : "https://openproxy.space/list/http",
    "openproxy_socks4"  : "https://openproxy.space/list/socks4",
    "openproxy_socks5"  : "https://openproxy.space/list/socks5",

    # ── advanced.name ─────────────────────────────────────────────────────────
    "advanced_http"     : "https://advanced.name/freeproxy?country=IR&type=http",
    "advanced_socks5"   : "https://advanced.name/freeproxy?country=IR&type=socks5",

    # ── hidemy.name ───────────────────────────────────────────────────────────
    "hidemy_p1"         : "https://hidemy.name/en/proxy-list/?country=IR#list",
    "hidemy_p2"         : "https://hidemy.name/en/proxy-list/?country=IR&start=64#list",

    # ── freeproxylists.net ────────────────────────────────────────────────────
    "freeproxylists"    : "https://www.freeproxylists.net/?c=IR&pt=&pr=&a%5B%5D=0&a%5B%5D=1&a%5B%5D=2&u=90",

    # ── spys.one ──────────────────────────────────────────────────────────────
    "spys_one"          : "https://spys.one/free-proxy-list/IR/",

    # ── GitHub — raw IP:PORT lists (country-tagged repos) ─────────────────────
    # monosans/proxy-list  (updated hourly, IR mixed in)
    "gh_monosans_http"  : "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "gh_monosans_s4"    : "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt",
    "gh_monosans_s5"    : "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",

    # TheSpeedX/PROXY-List
    "gh_speedx_http"    : "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "gh_speedx_s4"      : "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
    "gh_speedx_s5"      : "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",

    # hookzof/socks5_list
    "gh_hookzof"        : "https://raw.githubusercontent.com/hookzof/socks5_list/master/tg/socks.csv",

    # clarketm/proxy-list
    "gh_clarketm"       : "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",

    # mertguvencli/http-proxy-list
    "gh_mertguvencli"   : "https://raw.githubusercontent.com/mertguvencli/http-proxy-list/main/proxy-list/data.txt",

    # jetkai/proxy-list
    "gh_jetkai_http"    : "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt",
    "gh_jetkai_s5"      : "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt",

    # ShiftyTR/Proxy-List
    "gh_shifty"         : "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt",

    # roosterkid/openproxylist
    "gh_roosterkid_http": "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt",
    "gh_roosterkid_s5"  : "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt",
}

# ProxyScrape — one entry per protocol (handled by scrape_proxyscrape_api)
PROXYSCRAPE_URLS = {
    "proxyscrape_http"  : "https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&country=ir&protocol=http&anonymity=all&timeout=10000",
    "proxyscrape_socks4": "https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&country=ir&protocol=socks4&anonymity=all&timeout=10000",
    "proxyscrape_socks5": "https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&country=ir&protocol=socks5&anonymity=all&timeout=10000",
}

# Geonode — paginated JSON API
GEONODE_PAGES = [
    f"https://proxylist.geonode.com/api/proxy-list?country=IR&limit=100&page={p}&sort_by=lastChecked&sort_type=desc"
    for p in range(1, 4)   # pages 1, 2, 3  → up to 300 candidates
]


# ── Logging ───────────────────────────────────────────────────────────────────

def log(msg: str) -> None:
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)


# ── Scrapers ──────────────────────────────────────────────────────────────────

def scrape_raw_text(name: str, url: str) -> set[str]:
    """Fetch a URL and extract all IP:port pairs from the raw text/HTML."""
    try:
        r = requests.get(url, headers=HEADERS, timeout=15)
        r.raise_for_status()
        pairs = IP_PATTERN.findall(r.text)
        found = {f"{ip}:{port}" for ip, port in pairs}
        log(f"  [{name}] {len(found)} candidates")
        return found
    except Exception as e:
        log(f"  ! [{name}] failed: {e}")
        return set()


def scrape_proxyscrape_api(name: str, url: str) -> set[str]:
    """ProxyScrape returns a plain text list of IP:port."""
    try:
        r = requests.get(url, headers=HEADERS, timeout=15)
        r.raise_for_status()
        lines = r.text.strip().splitlines()
        found = {ln.strip() for ln in lines if IP_PATTERN.match(ln.strip())}
        log(f"  [{name}] {len(found)} candidates")
        return found
    except Exception as e:
        log(f"  ! [{name}] failed: {e}")
        return set()


def scrape_geonode(url: str, page: int) -> set[str]:
    """Parse one page of the Geonode JSON API."""
    proxies: set[str] = set()
    try:
        r = requests.get(url, headers=HEADERS, timeout=15)
        data = r.json()
        for p in data.get("data", []):
            ip = p.get("ip", "")
            # port can be an int or a list
            ports = p.get("port", [])
            if isinstance(ports, (int, str)):
                ports = [ports]
            for port in ports:
                proxies.add(f"{ip}:{port}")
        log(f"  [geonode page {page}] {len(proxies)} candidates")
    except Exception as e:
        log(f"  ! [geonode page {page}] failed: {e}")
    return proxies


def is_valid_ip(ip: str) -> bool:
    """Return True for publicly routable IPv4 addresses."""
    return bool(VALID_IP_RE.match(ip))


def collect_all_candidates() -> set[str]:
    """Scrape every source and return a de-duplicated set of IP:port strings."""
    candidates: set[str] = set()

    # ── Raw text / HTML sources ───────────────────────────────────────────────
    log("\n── Scraping plain-text / HTML sources ──")
    for name, url in RAW_TEXT_SOURCES.items():
        candidates |= scrape_raw_text(name, url)

    # ── ProxyScrape API (per protocol) ────────────────────────────────────────
    log("\n── Scraping ProxyScrape API ──")
    for name, url in PROXYSCRAPE_URLS.items():
        candidates |= scrape_proxyscrape_api(name, url)

    # ── Geonode paginated JSON ─────────────────────────────────────────────────
    log("\n── Scraping Geonode (3 pages) ──")
    for i, url in enumerate(GEONODE_PAGES, 1):
        candidates |= scrape_geonode(url, i)

    # ── Filter non-routable addresses ─────────────────────────────────────────
    filtered: set[str] = set()
    for proxy in candidates:
        parts = proxy.split(":")
        if len(parts) == 2 and is_valid_ip(parts[0]):
            try:
                port = int(parts[1])
                if 1 <= port <= 65535:
                    filtered.add(proxy)
            except ValueError:
                pass

    log(f"\nTotal unique routable candidates: {len(filtered)}")
    return filtered


# ── Tester ───────────────────────────────────────────────────────────────────

def test_proxy(proxy_str: str) -> dict | None:
    """
    Test a single proxy:
      1. Try SOCKS5, then SOCKS4, then HTTP.
      2. Hit ip-api.com through the proxy to confirm exit IP is in Iran.
    Returns a result dict or None.
    """
    ip, port_str = proxy_str.rsplit(":", 1)
    port = int(port_str)

    for proto in ("socks5", "socks4", "http"):
        proxy_url = f"{proto}://{ip}:{port}"
        proxies   = {"http": proxy_url, "https": proxy_url}
        try:
            start   = time.monotonic()
            r       = requests.get(VERIFY_URL, proxies=proxies, timeout=TIMEOUT)
            latency = round((time.monotonic() - start) * 1000)
            data    = r.json()

            if data.get("status") == "success" and data.get("countryCode") == COUNTRY_CODE:
                return {
                    "proxy"      : proxy_str,
                    "protocol"   : proto.upper(),
                    "latency_ms" : latency,
                    "isp"        : data.get("org", ""),
                    "city"       : data.get("city", ""),
                    "verified_ip": data.get("query", ""),
                }
        except Exception:
            continue

    return None


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    log("=" * 60)
    log("Iran Proxy Checker — Enhanced Edition")
    log("=" * 60)

    candidates = collect_all_candidates()

    if not candidates:
        log("ERROR: No candidates scraped. Aborting.")
        return

    log(f"\nTesting {len(candidates)} proxies with {TIMEOUT}s timeout "
        f"({MAX_WORKERS} threads)…\n")
    working: list[dict] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(test_proxy, p): p for p in candidates}
        done = 0
        for future in concurrent.futures.as_completed(futures):
            done += 1
            result = future.result()
            if result:
                working.append(result)
                log(
                    f"  ✓ [{result['protocol']:<6}] {result['proxy']:<26} "
                    f"{result['latency_ms']:>5}ms  {result['city']}  {result['isp']}"
                )
            if done % 50 == 0:
                log(f"  … {done}/{len(candidates)} tested, {len(working)} working so far")

    # Sort by latency
    working.sort(key=lambda x: x["latency_ms"])

    # Protocol breakdown
    proto_counts: dict[str, int] = {}
    for p in working:
        proto_counts[p["protocol"]] = proto_counts.get(p["protocol"], 0) + 1

    log(f"\n{'='*60}")
    log(f"Done.  {len(working)} working Iranian proxies found.")
    breakdown = "  ".join(f"{k}: {v}" for k, v in sorted(proto_counts.items()))
    log(f"Breakdown by protocol — {breakdown}")
    log(f"{'='*60}\n")

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # ── Plain-text output ────────────────────────────────────────────────────
    out_path = Path("working_iran_proxies.txt")
    with open(out_path, "w") as f:
        f.write(f"# Working Iranian Proxies — checked {now}\n")
        f.write(f"# {len(working)} proxies verified via ip-api.com\n")
        f.write(f"# Protocol breakdown: {breakdown}\n")
        f.write("#\n")
        f.write("# Format: PROTOCOL  IP:PORT  LATENCY  CITY  ISP\n")
        f.write("#\n\n")

        for p in working:
            f.write(
                f"{p['protocol']:<8} {p['proxy']:<26} "
                f"{p['latency_ms']:>5}ms   {p['city']:<20} {p['isp']}\n"
            )

        f.write("\n# --- Raw IP:PORT list (for apps like Super Proxy / NekoBox) ---\n")
        for p in working:
            f.write(f"{p['proxy']}\n")

        # Separate sections per protocol
        for proto in sorted(proto_counts):
            f.write(f"\n# --- {proto} only ---\n")
            for p in working:
                if p["protocol"] == proto:
                    f.write(f"{p['proxy']}\n")

    log(f"Results written to {out_path.resolve()}")

    # ── JSON output ───────────────────────────────────────────────────────────
    json_path = Path("working_iran_proxies.json")
    with open(json_path, "w") as f:
        json.dump(
            {
                "checked_at"       : now,
                "count"            : len(working),
                "protocol_counts"  : proto_counts,
                "proxies"          : working,
            },
            f,
            indent=2,
            ensure_ascii=False,
        )
    log(f"JSON results written to {json_path.resolve()}")


if __name__ == "__main__":
    main()
