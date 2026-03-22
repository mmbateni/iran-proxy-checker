#!/usr/bin/env python3
"""
Iran Proxy Checker — Fixed Edition
• Uses only IR-targeted sources (no global lists that waste test budget)
• TCP pre-check filters dead proxies before full verification
• Falls back to multiple verify URLs so ip-api.com rate limits don't kill us
• SOCKS5 → SOCKS4 → HTTP protocol detection
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

TCP_TIMEOUT    = 4     # seconds for the cheap TCP pre-check
PROXY_TIMEOUT  = 12   # seconds for the full HTTP verify
MAX_WORKERS    = 50   # concurrent threads

# Multiple verify endpoints — if one rate-limits us, try the next
VERIFY_URLS = [
    "http://ip-api.com/json/?fields=status,country,countryCode,query,org,city",
    "http://ipwho.is/",
    "http://ipapi.co/json/",
]
COUNTRY_CODE = "IR"

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "en-US,en;q=0.9",
}

IP_PORT_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})\b")
PRIVATE_RE = re.compile(
    r"^(?:0\.|10\.|127\.|169\.254\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)"
)


# ── IR-only sources ───────────────────────────────────────────────────────────
RAW_TEXT_SOURCES = {
    "proxyhub_http"  : "https://proxyhub.me/en/ir-free-proxy-list.html",
    "proxyhub_socks5": "https://proxyhub.me/en/ir-socks5-proxy-list.html",
    "pld_http"       : "https://www.proxy-list.download/api/v1/get?type=http&country=IR",
    "pld_socks4"     : "https://www.proxy-list.download/api/v1/get?type=socks4&country=IR",
    "pld_socks5"     : "https://www.proxy-list.download/api/v1/get?type=socks5&country=IR",
    "advanced_http"  : "https://advanced.name/freeproxy?country=IR&type=http",
    "advanced_s5"    : "https://advanced.name/freeproxy?country=IR&type=socks5",
    "ditatompel"     : "https://www.ditatompel.com/proxy/country/ir",
    "proxydb"        : "https://proxydb.net/?country=IR",
    "hidemy_p1"      : "https://hidemy.name/en/proxy-list/?country=IR#list",
    "hidemy_p2"      : "https://hidemy.name/en/proxy-list/?country=IR&start=64#list",
    "hidemy_p3"      : "https://hidemy.name/en/proxy-list/?country=IR&start=128#list",
    "spys_one"       : "https://spys.one/free-proxy-list/IR/",
    "freeproxylists" : "https://www.freeproxylists.net/?c=IR&pt=&pr=&a%5B%5D=0&a%5B%5D=1&a%5B%5D=2&u=90",
    "openproxy_s5"   : "https://openproxy.space/list/socks5",
    "gh_zaeem_s5"    : "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/socks5.txt",
    "gh_zaeem_http"  : "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/http.txt",
    "gh_razvan_s5"   : "https://raw.githubusercontent.com/im-razvan/proxy_list/main/socks5.txt",
    "gh_proxy4p"     : "https://raw.githubusercontent.com/proxy4parsing/proxy-list/main/http.txt",
    "gh_ercindedeoglu_s5"  : "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/socks5.txt",
    "gh_ercindedeoglu_http": "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/http.txt",
}

PROXYSCRAPE_URLS = {
    "ps_http"  : "https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&country=ir&protocol=http&anonymity=all&timeout=10000",
    "ps_socks4": "https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&country=ir&protocol=socks4&anonymity=all&timeout=10000",
    "ps_socks5": "https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&country=ir&protocol=socks5&anonymity=all&timeout=10000",
}

GEONODE_PAGES = [
    f"https://proxylist.geonode.com/api/proxy-list?country=IR&limit=100&page={p}&sort_by=lastChecked&sort_type=desc"
    for p in range(1, 6)
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
        pairs = IP_PORT_RE.findall(r.text)
        found = {f"{ip}:{port}" for ip, port in pairs}
        log(f"  [{name}] {len(found)} candidates")
        return found
    except Exception as e:
        log(f"  ! [{name}] {e}")
        return set()


def scrape_proxyscrape(name: str, url: str) -> set:
    try:
        r = requests.get(url, headers=HEADERS, timeout=15)
        r.raise_for_status()
        lines = r.text.strip().splitlines()
        found = {ln.strip() for ln in lines if IP_PORT_RE.match(ln.strip())}
        log(f"  [{name}] {len(found)} candidates")
        return found
    except Exception as e:
        log(f"  ! [{name}] {e}")
        return set()


def scrape_geonode(url: str, page: int) -> set:
    proxies = set()
    try:
        r = requests.get(url, headers=HEADERS, timeout=15)
        data = r.json()
        for p in data.get("data", []):
            ip = p.get("ip", "")
            ports = p.get("port", [])
            if isinstance(ports, (int, str)):
                ports = [ports]
            for port in ports:
                proxies.add(f"{ip}:{port}")
        log(f"  [geonode p{page}] {len(proxies)} candidates")
    except Exception as e:
        log(f"  ! [geonode p{page}] {e}")
    return proxies


def collect_candidates() -> set:
    raw = set()

    log("── Raw text / HTML sources ──")
    for name, url in RAW_TEXT_SOURCES.items():
        raw |= scrape_raw(name, url)

    log("── ProxyScrape API ──")
    for name, url in PROXYSCRAPE_URLS.items():
        raw |= scrape_proxyscrape(name, url)

    log("── Geonode (5 pages) ──")
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
            port = int(port_str)
            if 1 <= port <= 65535:
                clean.add(proxy)
        except ValueError:
            pass

    log(f"\nTotal unique candidates: {len(clean)}")
    return clean


# ── TCP pre-check ─────────────────────────────────────────────────────────────

def tcp_reachable(ip: str, port: int) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=TCP_TIMEOUT):
            return True
    except Exception:
        return False


# ── Country detection ─────────────────────────────────────────────────────────

def country_from_response(data: dict, url: str):
    if "countryCode" in data:
        if data.get("status") == "success":
            return data["countryCode"]
        return None
    if "country_code" in data:
        if data.get("success", True):
            return data["country_code"]
        return None
    return None


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
                r       = requests.get(
                    verify_url, proxies=proxies,
                    timeout=PROXY_TIMEOUT, headers=HEADERS
                )
                latency = round((time.monotonic() - start) * 1000)
                data    = r.json()
                cc      = country_from_response(data, verify_url)

                if cc == COUNTRY_CODE:
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
    log("Iran Proxy Checker — Fixed Edition")
    log("=" * 60)

    candidates = collect_candidates()
    if not candidates:
        log("ERROR: No candidates scraped. Aborting.")
        return

    log(f"\nTesting {len(candidates)} proxies "
        f"(TCP pre-check + full verify, {MAX_WORKERS} threads)…\n")
    working = []

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

    working.sort(key=lambda x: x["latency_ms"])

    proto_counts = {}
    for p in working:
        proto_counts[p["protocol"]] = proto_counts.get(p["protocol"], 0) + 1

    log(f"\n{'='*60}")
    log(f"Done. {len(working)} working Iranian proxies found.")
    breakdown = "  ".join(f"{k}: {v}" for k, v in sorted(proto_counts.items()))
    if breakdown:
        log(f"Protocol breakdown — {breakdown}")
    log(f"{'='*60}\n")

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    out = Path("working_iran_proxies.txt")
    with open(out, "w") as f:
        f.write(f"# Working Iranian Proxies — checked {now}\n")
        f.write(f"# {len(working)} proxies verified\n")
        f.write(f"# {breakdown}\n#\n")
        f.write("# Format: PROTOCOL  IP:PORT  LATENCY  CITY  ISP\n#\n\n")

        for p in working:
            f.write(
                f"{p['protocol']:<8} {p['proxy']:<26} "
                f"{p['latency_ms']:>5}ms   {p['city']:<20} {p['isp']}\n"
            )

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
        json.dump(
            {"checked_at": now, "count": len(working),
             "protocol_counts": proto_counts, "proxies": working},
            f, indent=2, ensure_ascii=False,
        )
    log(f"JSON  → {jp.resolve()}")


if __name__ == "__main__":
    main()
