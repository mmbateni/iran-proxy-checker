#!/usr/bin/env python3
"""
Iran Proxy Checker — Local CIDR Filter Edition
Strategy:
  1. Download Iran's IP CIDR blocks from ipdeny.com (~2KB, ONE request, no rate-limit)
  2. Filter all candidates LOCALLY using Python's ipaddress module — instant
  3. Test only the Iranian-range IPs as proxies
  Typical: 26,000 candidates → ~150 Iranian → done in ~2 minutes
"""

import ipaddress
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

# Iran CIDR sources — tried in order, first success wins
IRAN_CIDR_URLS = [
    "https://www.ipdeny.com/ipblocks/data/countries/ir.zone",
    "https://raw.githubusercontent.com/herrbischoff/country-ip-blocks/master/ipv4/ir.cidr",
    "https://raw.githubusercontent.com/ipverse/rir-ip/master/country/ir/ipv4-aggregated.txt",
]

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
    "proxyhub_http"   : "https://proxyhub.me/en/ir-free-proxy-list.html",
    "proxyhub_socks5" : "https://proxyhub.me/en/ir-socks5-proxy-list.html",
    "pld_http"        : "https://www.proxy-list.download/api/v1/get?type=http&country=IR",
    "pld_socks4"      : "https://www.proxy-list.download/api/v1/get?type=socks4&country=IR",
    "pld_socks5"      : "https://www.proxy-list.download/api/v1/get?type=socks5&country=IR",
    "advanced_http"   : "https://advanced.name/freeproxy?country=IR&type=http",
    "advanced_s5"     : "https://advanced.name/freeproxy?country=IR&type=socks5",
    "ditatompel"      : "https://www.ditatompel.com/proxy/country/ir",
    "proxydb"         : "https://proxydb.net/?country=IR",
    "spys_one"        : "https://spys.one/free-proxy-list/IR/",
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


# ── Iran CIDR loader ──────────────────────────────────────────────────────────

def load_iran_networks() -> list:
    cidr_re = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})")
    for url in IRAN_CIDR_URLS:
        try:
            r = requests.get(url, headers=HEADERS, timeout=15)
            r.raise_for_status()
            nets = []
            for line in r.text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                m = cidr_re.search(line)
                if m:
                    try:
                        nets.append(ipaddress.IPv4Network(m.group(1), strict=False))
                    except ValueError:
                        pass
            if nets:
                log(f"  Loaded {len(nets)} Iran CIDR blocks from {url}")
                return nets
        except Exception as e:
            log(f"  ! CIDR source failed ({url}): {e}")

    # Hardcoded fallback — major Iranian ISP prefixes
    log("  WARNING: Using hardcoded fallback CIDR list")
    fallback = [
        "2.144.0.0/12","2.176.0.0/12","5.22.0.0/17","5.56.128.0/17",
        "5.160.0.0/14","5.200.0.0/14","5.134.128.0/18","5.253.24.0/22",
        "31.2.128.0/17","31.14.80.0/20","31.24.200.0/21","37.0.72.0/21",
        "37.32.0.0/11","37.98.0.0/15","37.156.0.0/14","37.255.0.0/16",
        "46.36.96.0/20","46.100.0.0/14","46.209.0.0/16","46.224.0.0/12",
        "62.60.128.0/17","62.193.0.0/16","77.36.128.0/17","78.38.0.0/15",
        "78.157.32.0/21","79.127.0.0/17","80.66.176.0/20","80.191.0.0/16",
        "80.210.0.0/15","82.99.192.0/18","83.120.0.0/14","84.241.0.0/16",
        "85.9.64.0/18","85.15.0.0/16","85.133.128.0/17","85.185.0.0/16",
        "85.198.0.0/15","87.107.0.0/16","87.247.160.0/19","87.248.0.0/15",
        "89.32.0.0/14","89.144.128.0/17","89.165.0.0/16","89.196.0.0/14",
        "91.92.0.0/20","91.99.128.0/17","91.185.128.0/17","91.207.140.0/23",
        "91.209.76.0/22","91.212.0.0/21","91.217.40.0/22","91.219.68.0/22",
        "91.220.96.0/21","91.221.164.0/22","91.228.148.0/22","91.238.0.0/19",
        "92.42.48.0/20","92.114.0.0/15","92.242.192.0/18","93.93.204.0/23",
        "94.74.128.0/17","94.182.0.0/15","95.38.0.0/15","95.64.0.0/18",
        "194.225.0.0/16",
    ]
    nets = []
    for c in fallback:
        try:
            nets.append(ipaddress.IPv4Network(c, strict=False))
        except ValueError:
            pass
    return nets


# ── Local CIDR filter — NO external API, NO rate-limits ──────────────────────

def cidr_filter(candidates: set, networks: list) -> set:
    log(f"CIDR-filtering {len(candidates)} candidates locally (no API calls)…")
    t = time.monotonic()
    result = set()
    for proxy in candidates:
        ip = proxy.split(":")[0]
        try:
            addr = ipaddress.IPv4Address(ip)
            if any(addr in net for net in networks):
                result.add(proxy)
        except ValueError:
            pass
    log(f"  → {len(result)} Iranian candidates in {round(time.monotonic()-t, 2)}s")
    return result


# ── Scrapers ──────────────────────────────────────────────────────────────────

def scrape_raw(name: str, url: str) -> set:
    try:
        r = requests.get(url, headers=HEADERS, timeout=15)
        r.raise_for_status()
        found = {f"{ip}:{p}" for ip, p in IP_PORT_RE.findall(r.text)}
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
        found = {ln.strip() for ln in r.text.splitlines() if IP_PORT_RE.match(ln.strip())}
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
    log(f"\nRaw candidates: {len(clean)}")
    return clean


# ── TCP pre-check ─────────────────────────────────────────────────────────────

def tcp_reachable(ip: str, port: int) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=TCP_TIMEOUT):
            return True
    except Exception:
        return False


# ── Proxy test ────────────────────────────────────────────────────────────────

def country_from(data: dict) -> str:
    if data.get("status") == "success" and "countryCode" in data:
        return data["countryCode"]
    if data.get("success", True) and "country_code" in data:
        return data["country_code"]
    return ""


def test_proxy(proxy_str: str):
    ip, port_str = proxy_str.rsplit(":", 1)
    port = int(port_str)
    if not tcp_reachable(ip, port):
        return None
    for proto in ("socks5", "socks4", "http"):
        proxies = {"http": f"{proto}://{ip}:{port}", "https": f"{proto}://{ip}:{port}"}
        for verify_url in VERIFY_URLS:
            try:
                t = time.monotonic()
                r = requests.get(verify_url, proxies=proxies,
                                 timeout=PROXY_TIMEOUT, headers=HEADERS)
                latency = round((time.monotonic() - t) * 1000)
                data = r.json()
                if country_from(data) == COUNTRY_CODE:
                    return {
                        "proxy": proxy_str, "protocol": proto.upper(),
                        "latency_ms": latency,
                        "isp": data.get("org") or data.get("connection", {}).get("isp", ""),
                        "city": data.get("city", ""),
                        "verified_ip": data.get("query") or data.get("ip", ""),
                    }
                break
            except Exception:
                continue
    return None


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    log("=" * 60)
    log("Iran Proxy Checker — Local CIDR Filter Edition")
    log("=" * 60)

    log("\n── Loading Iran IP ranges ──")
    iran_networks = load_iran_networks()
    if not iran_networks:
        log("ERROR: Could not load Iran CIDR blocks.")
        return

    candidates = collect_candidates()
    if not candidates:
        log("ERROR: No candidates scraped.")
        return

    log("\n── Geo-filtering (local, no API) ──")
    iranian = cidr_filter(candidates, iran_networks)
    if not iranian:
        log("No Iranian-range IPs found.")
        return

    log(f"\n── Testing {len(iranian)} proxies ({MAX_WORKERS} threads) ──\n")
    working = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(test_proxy, p): p for p in iranian}
        done = 0
        for future in concurrent.futures.as_completed(futures):
            done += 1
            result = future.result()
            if result:
                working.append(result)
                log(f"  ✓ [{result['protocol']:<6}] {result['proxy']:<26} "
                    f"{result['latency_ms']:>5}ms  {result['city']}  {result['isp']}")
            if done % 25 == 0:
                log(f"  … {done}/{len(iranian)} tested, {len(working)} working so far")

    working.sort(key=lambda x: x["latency_ms"])
    proto_counts: dict = {}
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
