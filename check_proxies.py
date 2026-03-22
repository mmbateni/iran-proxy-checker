#!/usr/bin/env python3
"""
Iran Proxy Checker — Smart Edition
Key insight: GitHub Actions (Azure) cannot TCP-connect TO Iranian IPs due to
routing/firewall restrictions. Therefore we skip live testing and instead:
  1. Collect from all sources in parallel
  2. Filter to Iranian IP ranges via local CIDR lookup
  3. Deduplicate and sort by source reliability
  4. Save the clean list — users can test locally or via a non-Azure VPS

For each Iranian IP we also try a reverse check: can the Iranian IP reach US?
(i.e. test if ip-api.com returns IR when routing through the proxy)
We attempt this with a longer timeout since Iranian connections are slow.
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

SCRAPE_TIMEOUT  = 12
TCP_TIMEOUT     = 8     # longer for Iran routing
HTTP_TIMEOUT    = 20    # much longer — Iranian connections are slow from abroad
MAX_WORKERS     = 60
COUNTRY_CODE    = "IR"

IRAN_CIDR_URLS = [
    "https://www.ipdeny.com/ipblocks/data/countries/ir.zone",
    "https://raw.githubusercontent.com/herrbischoff/country-ip-blocks/master/ipv4/ir.cidr",
    "https://raw.githubusercontent.com/ipverse/rir-ip/master/country/ir/ipv4-aggregated.txt",
]

VERIFY_URL = "http://ip-api.com/json/?fields=status,countryCode,query,org,city"
TEST_URLS = [
    "http://ip-api.com/json/?fields=status,countryCode,query,org,city",
    "http://httpbin.org/ip",
    "http://api.ipify.org",
    "http://ifconfig.me/ip",
    "http://checkip.amazonaws.com",
    "http://digikala.com",    # major Iranian site — may work even if foreign ones don't
    "http://irancell.ir",
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

# Priority weight per source (higher = shown first in output)
SOURCE_PRIORITY = {
    "openray_iran": 10,   # pre-verified IR-specific
    "proxifly_IR" : 10,
    "ebrasha_http": 9,
    "ebrasha_s5"  : 9,
    "proxyscrape_http": 8,
    "proxyscrape_s4"  : 8,
    "proxyscrape_s5"  : 8,
    "proxyhub_http"   : 7,
    "proxyhub_socks5" : 7,
    "advanced_http"   : 6,
    "advanced_s5"     : 6,
    "ditatompel"      : 6,
    "proxydb"         : 6,
}

# ── Sources ───────────────────────────────────────────────────────────────────

SOURCES = {
    # ── IR-targeted (highest priority) ───────────────────────────────────────
    "openray_iran"     : "https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output_iran/iran_top100_checked.txt",
    "openray_all"      : "https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output/all_valid_proxies.txt",
    "proxifly_IR"      : "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/countries/IR/data.txt",
    "ebrasha_http"     : "https://raw.githubusercontent.com/EbraSha/Abdal-Proxy-List/main/http.txt",
    "ebrasha_s5"       : "https://raw.githubusercontent.com/EbraSha/Abdal-Proxy-List/main/socks5.txt",
    "proxyhub_http"    : "https://proxyhub.me/en/ir-free-proxy-list.html",
    "proxyhub_socks5"  : "https://proxyhub.me/en/ir-socks5-proxy-list.html",
    "pld_http"         : "https://www.proxy-list.download/api/v1/get?type=http&country=IR",
    "pld_socks4"       : "https://www.proxy-list.download/api/v1/get?type=socks4&country=IR",
    "pld_socks5"       : "https://www.proxy-list.download/api/v1/get?type=socks5&country=IR",
    "advanced_http"    : "https://advanced.name/freeproxy?country=IR&type=http",
    "advanced_s5"      : "https://advanced.name/freeproxy?country=IR&type=socks5",
    "ditatompel"       : "https://www.ditatompel.com/proxy/country/ir",
    "proxydb"          : "https://proxydb.net/?country=IR",
    "spys_one"         : "https://spys.one/free-proxy-list/IR/",
    "proxyscrape_http" : "https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&country=ir&protocol=http&anonymity=all&timeout=10000",
    "proxyscrape_s4"   : "https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&country=ir&protocol=socks4&anonymity=all&timeout=10000",
    "proxyscrape_s5"   : "https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&country=ir&protocol=socks5&anonymity=all&timeout=10000",
    # ── Global GitHub lists (CIDR filter keeps only Iranian IPs) ─────────────
    "proxifly_http"    : "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/http/data.txt",
    "proxifly_s4"      : "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks4/data.txt",
    "proxifly_s5"      : "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks5/data.txt",
    "vakhov_http"      : "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/http.txt",
    "vakhov_s5"        : "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/socks5.txt",
    "kangproxy_http"   : "https://raw.githubusercontent.com/KangProxy/proxy-list/main/http.txt",
    "sunny9577"        : "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/proxies.txt",
    "gh_zaeem_http"    : "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/http.txt",
    "gh_zaeem_s5"      : "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/socks5.txt",
    "gh_razvan_s5"     : "https://raw.githubusercontent.com/im-razvan/proxy_list/main/socks5.txt",
    "gh_proxy4p"       : "https://raw.githubusercontent.com/proxy4parsing/proxy-list/main/http.txt",
    "gh_ercindedeoglu_s5"  : "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/socks5.txt",
    "gh_ercindedeoglu_http": "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/http.txt",
    "gh_monosans_http" : "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "gh_monosans_s5"   : "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
    "gh_speedx_http"   : "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "gh_speedx_s5"     : "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
    "gh_clarketm"      : "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
    "gh_shifty"        : "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt",
    "gh_roosterkid_h"  : "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt",
    "gh_roosterkid_s5" : "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt",
    "gh_jetkai_http"   : "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt",
    "gh_jetkai_s5"     : "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt",
    "gh_hookzof"       : "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
    "gh_andigwandi"    : "https://raw.githubusercontent.com/andigwandi/free-proxy/main/proxy_list.txt",
    "gh_aslisk_s5"     : "https://raw.githubusercontent.com/aslisk/proxyhttps/main/https.txt",
    "gh_rxb6"          : "https://raw.githubusercontent.com/rxb6/proxy-list/main/proxies.txt",
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
            log(f"  ! CIDR source failed: {e}")

    log("  WARNING: Using hardcoded fallback CIDR list")
    fallback = [
        "2.144.0.0/12","2.176.0.0/12","5.22.0.0/17","5.56.128.0/17",
        "5.160.0.0/14","5.200.0.0/14","5.134.128.0/18","31.2.128.0/17",
        "31.14.80.0/20","37.0.72.0/21","37.32.0.0/11","37.98.0.0/15",
        "37.156.0.0/14","37.255.0.0/16","46.36.96.0/20","46.100.0.0/14",
        "46.209.0.0/16","46.224.0.0/12","62.60.128.0/17","62.193.0.0/16",
        "77.36.128.0/17","78.38.0.0/15","78.157.32.0/21","79.127.0.0/17",
        "80.66.176.0/20","80.191.0.0/16","80.210.0.0/15","82.99.192.0/18",
        "83.120.0.0/14","84.241.0.0/16","85.9.64.0/18","85.15.0.0/16",
        "85.133.128.0/17","85.185.0.0/16","85.198.0.0/15","87.107.0.0/16",
        "87.247.160.0/19","87.248.0.0/15","89.32.0.0/14","89.165.0.0/16",
        "89.196.0.0/14","91.99.128.0/17","91.185.128.0/17","91.209.76.0/22",
        "91.212.0.0/21","91.217.40.0/22","91.220.96.0/21","91.228.148.0/22",
        "92.42.48.0/20","92.114.0.0/15","94.74.128.0/17","94.182.0.0/15",
        "95.38.0.0/15","95.64.0.0/18","194.225.0.0/16",
    ]
    return [ipaddress.IPv4Network(c, strict=False) for c in fallback]


def cidr_filter(candidates: set, networks: list) -> set:
    log(f"CIDR-filtering {len(candidates)} candidates locally…")
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


# ── Parallel scraper ──────────────────────────────────────────────────────────

def fetch_source(name: str, url: str) -> tuple:
    try:
        r = requests.get(url, headers=HEADERS, timeout=SCRAPE_TIMEOUT)
        r.raise_for_status()
        found = {f"{ip}:{p}" for ip, p in IP_PORT_RE.findall(r.text)}
        return (name, found, None)
    except Exception as e:
        return (name, set(), str(e))


def fetch_geonode(url: str, page: int) -> tuple:
    try:
        r = requests.get(url, headers=HEADERS, timeout=SCRAPE_TIMEOUT)
        proxies = set()
        for p in r.json().get("data", []):
            ip = p.get("ip", "")
            ports = p.get("port", [])
            if isinstance(ports, (int, str)):
                ports = [ports]
            for port in ports:
                proxies.add(f"{ip}:{port}")
        return (f"geonode_p{page}", proxies, None)
    except Exception as e:
        return (f"geonode_p{page}", set(), str(e))


def collect_candidates() -> tuple:
    """Returns (clean_set, source_map) where source_map = {proxy: source_name}"""
    log(f"── Scraping {len(SOURCES) + len(GEONODE_PAGES)} sources in parallel ──")
    source_map: dict = {}   # proxy_str → source name (first seen)
    errors = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
        fs = {ex.submit(fetch_source, n, u): n for n, u in SOURCES.items()}
        fs.update({ex.submit(fetch_geonode, u, i): f"geonode_p{i}"
                   for i, u in enumerate(GEONODE_PAGES, 1)})
        for future in concurrent.futures.as_completed(fs):
            name, found, err = future.result()
            if err:
                errors += 1
            elif found:
                log(f"  [{name}] {len(found)}")
                for proxy in found:
                    if proxy not in source_map:
                        source_map[proxy] = name

    clean: set = set()
    for proxy in source_map:
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

    log(f"\n  Sources with errors: {errors}/{len(SOURCES)+len(GEONODE_PAGES)}")
    log(f"  Raw unique candidates: {len(clean)}")
    return clean, source_map


# ── Live test (best-effort — may fail from Azure/GitHub Actions) ───────────────

def tcp_check(ip: str, port: int) -> str:
    """Returns 'ok', 'refused', or 'timeout'"""
    try:
        with socket.create_connection((ip, port), timeout=TCP_TIMEOUT):
            return "ok"
    except ConnectionRefusedError:
        return "refused"
    except Exception:
        return "timeout"


def test_proxy(proxy_str: str) -> dict:
    ip, port_str = proxy_str.rsplit(":", 1)
    port = int(port_str)

    tcp = tcp_check(ip, port)
    if tcp != "ok":
        return {"proxy": proxy_str, "tcp": tcp, "working": False}

    for proto in ("socks5", "socks4", "http"):
        px = {"http": f"{proto}://{ip}:{port}", "https": f"{proto}://{ip}:{port}"}
        for test_url in TEST_URLS:
            try:
                t = time.monotonic()
                r = requests.get(test_url, proxies=px,
                                 timeout=HTTP_TIMEOUT, headers=HEADERS)
                latency = round((time.monotonic() - t) * 1000)
                if r.status_code < 400:
                    # Parse country from ip-api if available
                    cc, city, org = "", "", ""
                    try:
                        data = r.json()
                        cc   = data.get("countryCode", "")
                        city = data.get("city", "")
                        org  = data.get("org", "")
                    except Exception:
                        pass
                    return {
                        "proxy"      : proxy_str,
                        "tcp"        : "ok",
                        "working"    : True,
                        "protocol"   : proto.upper(),
                        "latency_ms" : latency,
                        "country"    : cc,
                        "city"       : city,
                        "isp"        : org,
                    }
            except Exception:
                continue

    return {"proxy": proxy_str, "tcp": "ok", "working": False}


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    log("=" * 60)
    log("Iran Proxy Checker — Smart Edition")
    log("=" * 60)

    log("\n── Loading Iran IP ranges ──")
    iran_networks = load_iran_networks()

    candidates, source_map = collect_candidates()
    if not candidates:
        log("ERROR: No candidates scraped.")
        return

    log("\n── Geo-filtering (local CIDR, no API) ──")
    iranian = cidr_filter(candidates, iran_networks)
    if not iranian:
        log("No Iranian-range IPs found.")
        return

    # ── Live testing ──────────────────────────────────────────────────────────
    log(f"\n── Live testing {len(iranian)} proxies ({MAX_WORKERS} threads) ──")
    log("  NOTE: GitHub Actions (Azure) often cannot TCP-reach Iranian IPs.")
    log("  All CIDR-confirmed IPs are saved regardless of test result.\n")

    all_results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(test_proxy, p): p for p in iranian}
        done = 0
        for future in concurrent.futures.as_completed(futures):
            done += 1
            result = future.result()
            all_results.append(result)
            if result.get("working"):
                log(f"  ✓ [{result['protocol']:<6}] {result['proxy']:<26} "
                    f"{result['latency_ms']:>5}ms  {result.get('city','')}  {result.get('isp','')}")
            if done % 50 == 0:
                tcp_ok  = sum(1 for r in all_results if r["tcp"] == "ok")
                refused = sum(1 for r in all_results if r["tcp"] == "refused")
                working = sum(1 for r in all_results if r.get("working"))
                log(f"  … {done}/{len(iranian)} | TCP-ok:{tcp_ok} refused:{refused} "
                    f"timeout:{done-tcp_ok-refused} | working:{working}")

    working   = [r for r in all_results if r.get("working")]
    tcp_ok    = [r for r in all_results if r["tcp"] == "ok"]
    refused   = [r for r in all_results if r["tcp"] == "refused"]
    timed_out = [r for r in all_results if r["tcp"] == "timeout"]

    working.sort(key=lambda x: x["latency_ms"])
    proto_counts: dict = {}
    for p in working:
        proto_counts[p["protocol"]] = proto_counts.get(p["protocol"], 0) + 1

    breakdown = "  ".join(f"{k}: {v}" for k, v in sorted(proto_counts.items()))

    log(f"\n{'='*60}")
    log(f"LIVE TEST RESULTS:")
    log(f"  Total Iranian IPs : {len(iranian)}")
    log(f"  TCP timeout       : {len(timed_out)}  (Azure/GitHub can't reach Iranian IPs)")
    log(f"  TCP refused       : {len(refused)}   (reachable but port closed)")
    log(f"  TCP connected     : {len(tcp_ok)}   (port open)")
    log(f"  WORKING PROXIES   : {len(working)}")
    if breakdown:
        log(f"  Protocol breakdown: {breakdown}")
    log(f"{'='*60}\n")

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # Sort all Iranian proxies by source priority for the unverified list
    def sort_key(proxy):
        src = source_map.get(proxy, "")
        return -SOURCE_PRIORITY.get(src, 0)

    all_iranian_sorted = sorted(iranian, key=sort_key)

    # ── Output ────────────────────────────────────────────────────────────────
    out = Path("working_iran_proxies.txt")
    with open(out, "w") as f:
        f.write(f"# Iranian Proxies — checked {now}\n")
        f.write(f"# Live-verified working: {len(working)}\n")
        f.write(f"# Total CIDR-confirmed Iranian IPs: {len(iranian)}\n")
        f.write(f"# TCP stats: ok={len(tcp_ok)} refused={len(refused)} timeout={len(timed_out)}\n")
        if len(timed_out) > len(tcp_ok):
            f.write("# NOTE: Most timeouts = GitHub Actions (Azure) cannot reach Iranian IPs.\n")
            f.write("#       Test the 'All CIDR-confirmed' section locally for accurate results.\n")
        f.write("#\n\n")

        if working:
            f.write("# === LIVE-VERIFIED WORKING PROXIES ===\n")
            f.write(f"# Format: PROTOCOL  IP:PORT  LATENCY\n\n")
            for p in working:
                f.write(f"{p['protocol']:<8} {p['proxy']:<26} {p['latency_ms']:>5}ms\n")
            f.write("\n# --- Raw (verified) ---\n")
            for p in working:
                f.write(f"{p['proxy']}\n")
        else:
            f.write("# === NO LIVE-VERIFIED PROXIES (likely Azure routing block) ===\n\n")

        f.write("\n\n# === ALL CIDR-CONFIRMED IRANIAN IPs (unverified, sorted by source) ===\n")
        f.write("# These are in Iranian IP ranges — test locally with:\n")
        f.write("#   python check_proxies.py  (run on a non-Azure VPS or your local machine)\n\n")
        for proxy in all_iranian_sorted:
            src = source_map.get(proxy, "unknown")
            f.write(f"{proxy:<26}  # {src}\n")

    log(f"Results → {out.resolve()}")

    jp = Path("working_iran_proxies.json")
    with open(jp, "w") as f:
        json.dump({
            "checked_at"         : now,
            "verified_count"     : len(working),
            "cidr_confirmed_count": len(iranian),
            "tcp_stats"          : {"ok": len(tcp_ok), "refused": len(refused), "timeout": len(timed_out)},
            "azure_routing_block": len(timed_out) > len(tcp_ok),
            "protocol_counts"    : proto_counts,
            "verified_proxies"   : working,
            "all_iranian_ips"    : all_iranian_sorted,
        }, f, indent=2, ensure_ascii=False)
    log(f"JSON  → {jp.resolve()}")


if __name__ == "__main__":
    main()
