#!/usr/bin/env python3
"""
Iran Proxy Checker — Throttled GeoFilter Edition
Strategy:
  1. Scrape all sources (IR-targeted + global GitHub lists)
  2. Batch geo-filter via ip-api.com with 1.5s sleep between batches
     → stays under 45 req/min free-tier limit, retries on failure
  3. Test only the confirmed Iranian proxies
"""

import socket
import requests
import concurrent.futures
import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path

# ── Config ────────────────────────────────────────────────────────────────────

TCP_TIMEOUT   = 4
PROXY_TIMEOUT = 12
MAX_WORKERS   = 50
COUNTRY_CODE  = "IR"
BATCH_SLEEP   = 1.5   # seconds between geo-lookup batches (keeps us ≤40 req/min)
BATCH_RETRIES = 3     # retry each batch this many times on failure

GEOIP_BATCH_URL = "http://ip-api.com/batch?fields=status,countryCode,query"

VERIFY_URLS = [
    "http://ip-api.com/json/?fields=status,countryCode,query,org,city",
    "http://ipwho.is/",
    "http://ipapi.co/json/",
]

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
}

IP_PORT_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})\b")
PRIVATE_RE = re.compile(
    r"^(?:0\.|10\.|127\.|169\.254\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)"
)

# ── Sources ───────────────────────────────────────────────────────────────────

RAW_TEXT_SOURCES = {
    # IR-targeted (some may be blocked, that's fine)
    "proxyhub_http"   : "https://proxyhub.me/en/ir-free-proxy-list.html",
    "proxyhub_socks5" : "https://proxyhub.me/en/ir-socks5-proxy-list.html",
    "pld_http"        : "https://www.proxy-list.download/api/v1/get?type=http&country=IR",
    "pld_socks4"      : "https://www.proxy-list.download/api/v1/get?type=socks4&country=IR",
    "pld_socks5"      : "https://www.proxy-list.download/api/v1/get?type=socks5&country=IR",
    "advanced_http"   : "https://advanced.name/freeproxy?country=IR&type=http",
    "advanced_s5"     : "https://advanced.name/freeproxy?country=IR&type=socks5",
    "ditatompel"      : "https://www.ditatompel.com/proxy/country/ir",
    "proxydb"         : "https://proxydb.net/?country=IR",

    # Global GitHub lists — geo-filter handles IR extraction
    "gh_zaeem_http"   : "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/http.txt",
    "gh_zaeem_s5"     : "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/socks5.txt",
    "gh_razvan_s5"    : "https://raw.githubusercontent.com/im-razvan/proxy_list/main/socks5.txt",
    "gh_proxy4p"      : "https://raw.githubusercontent.com/proxy4parsing/proxy-list/main/http.txt",
    "gh_ercindedeoglu_s5"  : "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/socks5.txt",
    "gh_ercindedeoglu_http": "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/http.txt",
    "gh_monosans_http": "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "gh_monosans_s5"  : "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
    "gh_speedx_http"  : "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "gh_speedx_s5"    : "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
    "gh_clarketm"     : "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
    "gh_shifty"       : "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt",
    "gh_roosterkid_h" : "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt",
    "gh_roosterkid_s5": "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt",
    "gh_jetkai_http"  : "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt",
    "gh_jetkai_s5"    : "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt",
}

PROXYSCRAPE_URLS = {
    "ps_http"  : "https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&country=ir&protocol=http&anonymity=all&timeout=10000",
    "ps_socks4": "https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&country=ir&protocol=socks4&anonymity=all&timeout=10000",
    "ps_socks5": "https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&country=ir&protocol=socks5&anonymity=all&timeout=10000",
}

GEONODE_PAGES = [
    f"https://proxylist.geonode.com/api/proxy-list?country=IR&limit=100&page={p}&sort_by=lastChecked&sort_type=desc"
    for p in range(1, 4)
]


# ── Logging ───────────────────────────────────────────────────────────────────

def log(msg: str) -> None:
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)


# ── Scrapers ──────────────────────────────────────────────────────────────────

def scrape_raw(name: str, url: str) -> set:
    try:
        r = requests.get(url, headers=HEADERS, timeout=15)
        r.raise_for_status()
        found = {f"{ip}:{port}" for ip, port in IP_PORT_RE.findall(r.text)}
        if found:
            log(f"  [{name}] {len(found)}")
        return found
    except Exception as e:
        log(f"  ! [{name}] {e}")
        return set()


def scrape_proxyscrape(name: str, url: str) -> set:
    try:
        r = requests.get(url, headers=HEADERS, timeout=15)
        r.raise_for_status()
        found = {ln.strip() for ln in r.text.strip().splitlines() if IP_PORT_RE.match(ln.strip())}
        if found:
            log(f"  [{name}] {len(found)}")
        return found
    except Exception as e:
        log(f"  ! [{name}] {e}")
        return set()


def scrape_geonode(url: str, page: int) -> set:
    proxies = set()
    try:
        r = requests.get(url, headers=HEADERS, timeout=15)
        for p in r.json().get("data", []):
            ip = p.get("ip", "")
            ports = p.get("port", [])
            if isinstance(ports, (int, str)):
                ports = [ports]
            for port in ports:
                proxies.add(f"{ip}:{port}")
        if proxies:
            log(f"  [geonode p{page}] {len(proxies)}")
    except Exception as e:
        log(f"  ! [geonode p{page}] {e}")
    return proxies


def collect_candidates() -> set:
    raw = set()
    log("── Scraping sources ──")
    for name, url in RAW_TEXT_SOURCES.items():
        raw |= scrape_raw(name, url)
    for name, url in PROXYSCRAPE_URLS.items():
        raw |= scrape_proxyscrape(name, url)
    for i, url in enumerate(GEONODE_PAGES, 1):
        raw |= scrape_geonode(url, i)

    clean = set()
    for proxy in raw:
        parts = proxy.split(":")
        if len(parts) != 2:
            continue
        ip, port_str = parts
        if PRIVATE_RE.match(ip):
            continue
        try:
            if 1 <= int(port_str) <= 65535:
                clean.add(proxy)
        except ValueError:
            pass

    log(f"\nTotal candidates: {len(clean)}")
    return clean


# ── Batch GeoIP filter (throttled) ───────────────────────────────────────────

def geoip_batch_once(ips: list) -> list:
    """Single attempt at one batch. Returns parsed JSON list or raises."""
    payload = [{"query": ip} for ip in ips]
    r = requests.post(GEOIP_BATCH_URL, json=payload, headers=HEADERS, timeout=20)
    if r.status_code == 429:
        raise RuntimeError("rate-limited (429)")
    if not r.text.strip():
        raise RuntimeError("empty response")
    return r.json()


def batch_geofilter(candidates: set) -> set:
    """
    Throttled batch geo-filter.
    Sleeps BATCH_SLEEP seconds after every request → ~40 req/min < 45/min limit.
    Retries each failing batch up to BATCH_RETRIES times with exponential backoff.
    """
    ip_to_proxies: dict = {}
    for proxy in candidates:
        ip = proxy.split(":")[0]
        ip_to_proxies.setdefault(ip, set()).add(proxy)

    unique_ips = list(ip_to_proxies.keys())
    total_batches = (len(unique_ips) + 99) // 100
    log(f"Geo-filtering {len(unique_ips)} unique IPs in {total_batches} batches "
        f"({BATCH_SLEEP}s between each)…")

    iranian_proxies: set = set()
    eta_min = round(total_batches * BATCH_SLEEP / 60, 1)
    log(f"Estimated geo-filter time: ~{eta_min} min")

    for batch_num, i in enumerate(range(0, len(unique_ips), 100)):
        batch = unique_ips[i:i + 100]
        success = False

        for attempt in range(1, BATCH_RETRIES + 1):
            try:
                results = geoip_batch_once(batch)
                for entry in results:
                    if (entry.get("status") == "success"
                            and entry.get("countryCode") == COUNTRY_CODE):
                        iranian_proxies |= ip_to_proxies.get(entry["query"], set())
                success = True
                break
            except Exception as e:
                wait = BATCH_SLEEP * (2 ** attempt)   # 3s, 6s, 12s
                log(f"  ! batch {batch_num} attempt {attempt} failed ({e}) — "
                    f"retry in {wait:.0f}s")
                time.sleep(wait)

        if not success:
            log(f"  ✗ batch {batch_num} skipped after {BATCH_RETRIES} attempts")

        # Always throttle — even after retries
        time.sleep(BATCH_SLEEP)

        if (batch_num + 1) % 50 == 0:
            log(f"  … {batch_num + 1}/{total_batches} batches done, "
                f"{len(iranian_proxies)} IR proxies so far")

    log(f"Iranian candidates after geo-filter: {len(iranian_proxies)}")
    return iranian_proxies


# ── TCP pre-check ─────────────────────────────────────────────────────────────

def tcp_reachable(ip: str, port: int) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=TCP_TIMEOUT):
            return True
    except Exception:
        return False


# ── Country detection helpers ─────────────────────────────────────────────────

def country_from_response(data: dict) -> str:
    if data.get("status") == "success" and "countryCode" in data:
        return data["countryCode"]
    if data.get("success", True) and "country_code" in data:
        return data["country_code"]
    return ""


# ── Full proxy test ───────────────────────────────────────────────────────────

def test_proxy(proxy_str: str):
    ip, port_str = proxy_str.rsplit(":", 1)
    port = int(port_str)

    if not tcp_reachable(ip, port):
        return None

    for proto in ("socks5", "socks4", "http"):
        proxy_url = f"{proto}://{ip}:{port}"
        proxies   = {"http": proxy_url, "https": proxy_url}
        for verify_url in VERIFY_URLS:
            try:
                start   = time.monotonic()
                r       = requests.get(verify_url, proxies=proxies,
                                       timeout=PROXY_TIMEOUT, headers=HEADERS)
                latency = round((time.monotonic() - start) * 1000)
                data    = r.json()
                if country_from_response(data) == COUNTRY_CODE:
                    return {
                        "proxy"      : proxy_str,
                        "protocol"   : proto.upper(),
                        "latency_ms" : latency,
                        "isp"        : data.get("org") or data.get("connection", {}).get("isp", ""),
                        "city"       : data.get("city", ""),
                        "verified_ip": data.get("query") or data.get("ip", ""),
                    }
                break
            except Exception:
                continue
    return None


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    log("=" * 60)
    log("Iran Proxy Checker — Throttled GeoFilter Edition")
    log("=" * 60)

    candidates = collect_candidates()
    if not candidates:
        log("ERROR: No candidates scraped.")
        return

    iranian = batch_geofilter(candidates)
    if not iranian:
        log("No Iranian IPs found. Aborting.")
        return

    log(f"\nTesting {len(iranian)} Iranian proxies ({MAX_WORKERS} threads)…\n")
    working = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(test_proxy, p): p for p in iranian}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                working.append(result)
                log(f"  ✓ [{result['protocol']:<6}] {result['proxy']:<26} "
                    f"{result['latency_ms']:>5}ms  {result['city']}  {result['isp']}")

    working.sort(key=lambda x: x["latency_ms"])

    proto_counts = {}
    for p in working:
        proto_counts[p["protocol"]] = proto_counts.get(p["protocol"], 0) + 1

    breakdown = "  ".join(f"{k}: {v}" for k, v in sorted(proto_counts.items()))
    log(f"\n{'='*60}")
    log(f"Done. {len(working)} working Iranian proxies.")
    if breakdown:
        log(f"Protocols — {breakdown}")
    log(f"{'='*60}\n")

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    out = Path("working_iran_proxies.txt")
    with open(out, "w") as f:
        f.write(f"# Working Iranian Proxies — checked {now}\n")
        f.write(f"# {len(working)} proxies verified\n")
        f.write(f"# {breakdown}\n#\n")
        f.write("# Format: PROTOCOL  IP:PORT  LATENCY  CITY  ISP\n#\n\n")
        for p in working:
            f.write(f"{p['protocol']:<8} {p['proxy']:<26} "
                    f"{p['latency_ms']:>5}ms   {p['city']:<20} {p['isp']}\n")
        f.write("\n# --- Raw IP:PORT (for Super Proxy / NekoBox) ---\n")
        for p in working:
            f.write(f"{p['proxy']}\n")
        for proto in sorted(proto_counts):
            f.write(f"\n# --- {proto} only ---\n")
            for p in working:
                if p["protocol"] == proto:
                    f.write(f"{p['proxy']}\n")
    log(f"Results → {out.resolve()}")

    jp = Path("working_iran_proxies.json")
    with open(jp, "w") as f:
        json.dump({"checked_at": now, "count": len(working),
                   "protocol_counts": proto_counts, "proxies": working},
                  f, indent=2, ensure_ascii=False)
    log(f"JSON  → {jp.resolve()}")


if __name__ == "__main__":
    main()
