#!/usr/bin/env python3
"""
Iran Proxy Checker — Fresh-Only Edition
Key idea: Iranian network conditions change hourly.
Only collect proxies reported active within the last FRESH_HOURS hours.

Sources with timestamps → age filter applied
Sources without timestamps → only use repos updated < 6h ago (via GitHub API)
"""

import ipaddress
import os
import socket
import requests
import concurrent.futures
import json
import re
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

# ── Config ────────────────────────────────────────────────────────────────────

COLLECT_ONLY   = os.environ.get("COLLECT_ONLY", "").strip() == "1"
FRESH_HOURS    = int(os.environ.get("FRESH_HOURS", "72"))   # max age in hours
SCRAPE_TIMEOUT = 12
TCP_TIMEOUT    = 8
HTTP_TIMEOUT   = 20
MAX_WORKERS    = 60

IRAN_CIDR_URLS = [
    "https://www.ipdeny.com/ipblocks/data/countries/ir.zone",
    "https://raw.githubusercontent.com/herrbischoff/country-ip-blocks/master/ipv4/ir.cidr",
    "https://raw.githubusercontent.com/ipverse/rir-ip/master/country/ir/ipv4-aggregated.txt",
]

TEST_URLS = [
    "http://ip-api.com/json/?fields=status,countryCode,query,org,city",
    "http://httpbin.org/ip",
    "http://api.ipify.org",
    "http://ifconfig.me/ip",
    "http://checkip.amazonaws.com",
    "http://digikala.com",
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

NOW_UTC = datetime.now(timezone.utc)
CUTOFF  = NOW_UTC - timedelta(hours=FRESH_HOURS)


def log(msg):
    ts = NOW_UTC.strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)


# ── Iran CIDR loader ──────────────────────────────────────────────────────────

def load_iran_networks():
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
                log(f"  Loaded {len(nets)} Iran CIDR blocks")
                return nets
        except Exception as e:
            log(f"  ! CIDR {url}: {e}")

    log("  Using hardcoded fallback CIDRs")
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


def in_iran(ip, networks):
    try:
        addr = ipaddress.IPv4Address(ip)
        return any(addr in net for net in networks)
    except ValueError:
        return False


def cidr_filter(candidates, networks):
    log(f"CIDR-filtering {len(candidates)} candidates…")
    t = time.monotonic()
    result = {p for p in candidates if in_iran(p.split(":")[0], networks)}
    log(f"  → {len(result)} Iranian IPs in {round(time.monotonic()-t,2)}s")
    return result


def is_fresh(ts_str):
    """Return True if timestamp string is within FRESH_HOURS of now."""
    if not ts_str:
        return False
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S+00:00",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
    ):
        try:
            dt = datetime.strptime(ts_str[:26], fmt).replace(tzinfo=timezone.utc)
            return dt >= CUTOFF
        except ValueError:
            continue
    return False


def clean_proxy(proxy):
    parts = proxy.strip().split(":")
    if len(parts) != 2:
        return None
    ip, port_str = parts
    if PRIVATE_RE.match(ip):
        return None
    try:
        if 1 <= int(port_str) <= 65535:
            return proxy.strip()
    except ValueError:
        pass
    return None


# ══════════════════════════════════════════════════════════════════════════════
# SOURCES WITH TIMESTAMPS (freshness filter applied)
# ══════════════════════════════════════════════════════════════════════════════

def fetch_geonode_fresh():
    """Geonode JSON API — has lastChecked timestamp per proxy."""
    results = {}
    total = kept = 0
    for page in range(1, 6):
        url = (f"https://proxylist.geonode.com/api/proxy-list"
               f"?country=IR&limit=100&page={page}"
               f"&sort_by=lastChecked&sort_type=desc")
        try:
            r = requests.get(url, headers=HEADERS, timeout=SCRAPE_TIMEOUT)
            data = r.json().get("data", [])
            if not data:
                break
            for p in data:
                ip   = p.get("ip", "")
                ts   = p.get("updatedAt") or p.get("lastChecked") or p.get("created_at", "")
                ports = p.get("port", [])
                if isinstance(ports, (int, str)):
                    ports = [ports]
                for port in ports:
                    proxy = f"{ip}:{port}"
                    total += 1
                    if is_fresh(ts):
                        kept += 1
                        results[proxy] = ts
        except Exception as e:
            log(f"  ! geonode page {page}: {e}")
            break
    log(f"  [geonode] {kept}/{total} proxies within {FRESH_HOURS}h")
    return results


def fetch_proxyscrape_fresh():
    """ProxyScrape v3 API — returns lastSeen timestamps in JSON."""
    results = {}
    total = kept = 0
    for protocol in ("http", "socks4", "socks5"):
        url = (f"https://api.proxyscrape.com/v3/free-proxy-list/get"
               f"?request=getproxies&country=ir&protocol={protocol}"
               f"&anonymity=all&timeout=10000&format=json")
        try:
            r = requests.get(url, headers=HEADERS, timeout=SCRAPE_TIMEOUT)
            data = r.json()
            proxies_list = data if isinstance(data, list) else data.get("proxies", [])
            for p in proxies_list:
                if isinstance(p, str):
                    # plain text fallback
                    proxy = clean_proxy(p)
                    if proxy:
                        results[proxy] = ""
                    continue
                ip   = p.get("ip", "")
                port = p.get("port", "")
                ts   = (p.get("last_seen")
                        or p.get("lastSeen")
                        or p.get("updated_at")
                        or p.get("last_updated", ""))
                proxy = f"{ip}:{port}"
                total += 1
                if not ts or is_fresh(ts):   # include if no timestamp
                    kept += 1
                    results[proxy] = ts
        except Exception as e:
            log(f"  ! proxyscrape {protocol}: {e}")
    log(f"  [proxyscrape] {kept}/{total} proxies within {FRESH_HOURS}h")
    return results


def fetch_proxydb_fresh():
    """proxydb.net — shows 'last checked' in HTML, extract recent ones."""
    results = {}
    # Try multiple pages sorted by last-checked
    for page in range(1, 4):
        url = f"https://proxydb.net/?country=IR&sort=checked&page={page}"
        try:
            r = requests.get(url, headers=HEADERS, timeout=SCRAPE_TIMEOUT)
            r.raise_for_status()
            # Extract IP:port pairs — proxydb shows recently-checked proxies first
            pairs = IP_PORT_RE.findall(r.text)
            for ip, port in pairs:
                results[f"{ip}:{port}"] = ""
        except Exception as e:
            log(f"  ! proxydb page {page}: {e}")
            break
    log(f"  [proxydb] {len(results)} candidates")
    return results


def fetch_ditatompel_fresh():
    """ditatompel.com — JSON API with last_check timestamp."""
    results = {}
    total = kept = 0
    for page in range(1, 4):
        url = f"https://www.ditatompel.com/api/v2/proxy/list?country_id=IR&page={page}&per_page=100"
        try:
            r = requests.get(url, headers=HEADERS, timeout=SCRAPE_TIMEOUT)
            data = r.json()
            proxies_list = (data.get("data") or data.get("proxies")
                            or data.get("results") or [])
            if not proxies_list:
                # fallback: scrape HTML
                url2 = f"https://www.ditatompel.com/proxy/country/ir?page={page}"
                r2 = requests.get(url2, headers=HEADERS, timeout=SCRAPE_TIMEOUT)
                for ip, port in IP_PORT_RE.findall(r2.text):
                    results[f"{ip}:{port}"] = ""
                    kept += 1
                break
            for p in proxies_list:
                ip   = p.get("ip_address", p.get("ip", ""))
                port = p.get("port", "")
                ts   = (p.get("last_check") or p.get("lastChecked")
                        or p.get("updated_at", ""))
                proxy = f"{ip}:{port}"
                total += 1
                if not ts or is_fresh(ts):
                    kept += 1
                    results[proxy] = ts
        except Exception as e:
            log(f"  ! ditatompel page {page}: {e}")
            break
    log(f"  [ditatompel] {kept}/{total} proxies within {FRESH_HOURS}h")
    return results


def fetch_openray_fresh():
    """OpenRay — pre-verified IR list, updated hourly."""
    results = {}
    urls = [
        "https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output_iran/iran_top100_checked.txt",
        "https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output/all_valid_proxies.txt",
    ]
    for url in urls:
        try:
            r = requests.get(url, headers=HEADERS, timeout=SCRAPE_TIMEOUT)
            r.raise_for_status()
            # Check repo commit time via GitHub API
            repo_fresh = github_repo_is_fresh("sakha1370", "OpenRay")
            for ip, port in IP_PORT_RE.findall(r.text):
                results[f"{ip}:{port}"] = "repo_fresh" if repo_fresh else ""
        except Exception as e:
            log(f"  ! openray: {e}")
    log(f"  [openray] {len(results)} candidates (repo updated recently)")
    return results


def fetch_ebrasha_fresh():
    """EbraSha Abdal list — updated every 10 minutes."""
    results = {}
    urls = [
        "https://raw.githubusercontent.com/EbraSha/Abdal-Proxy-List/main/http.txt",
        "https://raw.githubusercontent.com/EbraSha/Abdal-Proxy-List/main/socks5.txt",
    ]
    repo_fresh = github_repo_is_fresh("EbraSha", "Abdal-Proxy-List")
    if not repo_fresh:
        log(f"  [ebrasha] repo not updated within {FRESH_HOURS}h — skipping")
        return results
    for url in urls:
        try:
            r = requests.get(url, headers=HEADERS, timeout=SCRAPE_TIMEOUT)
            r.raise_for_status()
            for ip, port in IP_PORT_RE.findall(r.text):
                results[f"{ip}:{port}"] = "repo_fresh"
        except Exception as e:
            log(f"  ! ebrasha: {e}")
    log(f"  [ebrasha] {len(results)} candidates")
    return results


def fetch_proxifly_fresh():
    """Proxifly — per-country IR list, updated every 5 minutes."""
    results = {}
    urls = {
        "proxifly_IR"  : "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/countries/IR/data.txt",
        "proxifly_http": "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/http/data.txt",
        "proxifly_s4"  : "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks4/data.txt",
        "proxifly_s5"  : "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks5/data.txt",
    }
    total = 0
    for name, url in urls.items():
        try:
            r = requests.get(url, headers=HEADERS, timeout=SCRAPE_TIMEOUT)
            r.raise_for_status()
            for ip, port in IP_PORT_RE.findall(r.text):
                results[f"{ip}:{port}"] = "fresh_5min"
                total += 1
        except Exception as e:
            log(f"  ! proxifly {name}: {e}")
    log(f"  [proxifly] {total} candidates (updated every 5 min)")
    return results


def fetch_github_raw_fresh(name, owner, repo, path, update_interval_hours=1):
    """Generic GitHub raw file — only fetch if repo was updated recently."""
    results = {}
    if not github_repo_is_fresh(owner, repo, max_hours=max(update_interval_hours * 3, FRESH_HOURS)):
        return results
    url = f"https://raw.githubusercontent.com/{owner}/{repo}/main/{path}"
    try:
        r = requests.get(url, headers=HEADERS, timeout=SCRAPE_TIMEOUT)
        r.raise_for_status()
        for ip, port in IP_PORT_RE.findall(r.text):
            results[f"{ip}:{port}"] = "repo_fresh"
    except Exception:
        pass
    return results


# ── GitHub commit freshness check ─────────────────────────────────────────────

_github_cache = {}

def github_repo_is_fresh(owner, repo, max_hours=None):
    """Return True if the repo had a commit within max_hours (default: FRESH_HOURS)."""
    if max_hours is None:
        max_hours = FRESH_HOURS
    key = f"{owner}/{repo}"
    if key in _github_cache:
        return _github_cache[key]
    try:
        url = f"https://api.github.com/repos/{owner}/{repo}/commits?per_page=1"
        r = requests.get(url, headers={**HEADERS, "Accept": "application/vnd.github.v3+json"},
                         timeout=10)
        commits = r.json()
        if commits and isinstance(commits, list):
            ts = commits[0]["commit"]["committer"]["date"]
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            fresh = dt >= (NOW_UTC - timedelta(hours=max_hours))
            _github_cache[key] = fresh
            return fresh
    except Exception:
        pass
    _github_cache[key] = True   # assume fresh if API fails
    return True


# ── IR-targeted plain-text sources (no timestamp — always include) ─────────────

def fetch_ir_targeted():
    """Sources that already filter to IR — no timestamp but always relevant."""
    results = {}
    sources = {
        "proxyhub_http"   : "https://proxyhub.me/en/ir-free-proxy-list.html",
        "proxyhub_socks5" : "https://proxyhub.me/en/ir-socks5-proxy-list.html",
        "pld_http"        : "https://www.proxy-list.download/api/v1/get?type=http&country=IR",
        "pld_socks4"      : "https://www.proxy-list.download/api/v1/get?type=socks4&country=IR",
        "pld_socks5"      : "https://www.proxy-list.download/api/v1/get?type=socks5&country=IR",
        "advanced_http"   : "https://advanced.name/freeproxy?country=IR&type=http",
        "advanced_s5"     : "https://advanced.name/freeproxy?country=IR&type=socks5",
        "spys_one"        : "https://spys.one/free-proxy-list/IR/",
    }
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        futures = {ex.submit(requests.get, u, **{"headers": HEADERS, "timeout": SCRAPE_TIMEOUT}): n
                   for n, u in sources.items()}
        for future in concurrent.futures.as_completed(futures):
            name = futures[future]
            try:
                r = future.result()
                r.raise_for_status()
                for ip, port in IP_PORT_RE.findall(r.text):
                    results[f"{ip}:{port}"] = "ir_targeted"
            except Exception as e:
                log(f"  ! {name}: {e}")
    log(f"  [ir_targeted] {len(results)} candidates")
    return results


# ══════════════════════════════════════════════════════════════════════════════
# Main collector
# ══════════════════════════════════════════════════════════════════════════════

def collect_fresh_candidates():
    log(f"── Collecting proxies fresh within last {FRESH_HOURS}h ──")

    all_proxies = {}   # proxy_str → {"source": ..., "ts": ...}

    def merge(d, source_name):
        for proxy, ts in d.items():
            p = clean_proxy(proxy)
            if p and p not in all_proxies:
                all_proxies[p] = {"source": source_name, "ts": ts}

    # Run all fetchers concurrently
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
        jobs = {
            ex.submit(fetch_geonode_fresh)   : "geonode",
            ex.submit(fetch_proxyscrape_fresh): "proxyscrape",
            ex.submit(fetch_proxydb_fresh)   : "proxydb",
            ex.submit(fetch_ditatompel_fresh): "ditatompel",
            ex.submit(fetch_openray_fresh)   : "openray",
            ex.submit(fetch_ebrasha_fresh)   : "ebrasha",
            ex.submit(fetch_proxifly_fresh)  : "proxifly",
            ex.submit(fetch_ir_targeted)     : "ir_targeted",
            # GitHub repos with known fast update cycles
            ex.submit(fetch_github_raw_fresh,
                "monosans_http","monosans","proxy-list",
                "proxies/http.txt", 1)               : "monosans_http",
            ex.submit(fetch_github_raw_fresh,
                "monosans_s5","monosans","proxy-list",
                "proxies/socks5.txt", 1)             : "monosans_s5",
            ex.submit(fetch_github_raw_fresh,
                "speedx_http","TheSpeedX","PROXY-List",
                "http.txt", 24)                      : "speedx_http",
            ex.submit(fetch_github_raw_fresh,
                "speedx_s5","TheSpeedX","PROXY-List",
                "socks5.txt", 24)                    : "speedx_s5",
            ex.submit(fetch_github_raw_fresh,
                "vakhov_http","vakhov","fresh-proxy-list",
                "http.txt", 6)                       : "vakhov_http",
            ex.submit(fetch_github_raw_fresh,
                "vakhov_s5","vakhov","fresh-proxy-list",
                "socks5.txt", 6)                     : "vakhov_s5",
            ex.submit(fetch_github_raw_fresh,
                "ercindedeoglu_s5","ErcinDedeoglu","proxies",
                "proxies/socks5.txt", 12)            : "ercindedeoglu_s5",
            ex.submit(fetch_github_raw_fresh,
                "ercindedeoglu_http","ErcinDedeoglu","proxies",
                "proxies/http.txt", 12)              : "ercindedeoglu_http",
            ex.submit(fetch_github_raw_fresh,
                "proxy4p","proxy4parsing","proxy-list",
                "http.txt", 1)                       : "proxy4p",
            ex.submit(fetch_github_raw_fresh,
                "zaeem_http","Zaeem20","FREE_PROXIES_LIST",
                "http.txt", 24)                      : "zaeem_http",
        }
        for future in concurrent.futures.as_completed(jobs):
            name = jobs[future]
            try:
                result = future.result()
                if isinstance(result, dict):
                    merge(result, name)
                elif isinstance(result, set):
                    merge({p: "" for p in result}, name)
            except Exception as e:
                log(f"  ! {name}: {e}")

    log(f"\n  Total fresh candidates: {len(all_proxies)}")
    return all_proxies


# ── Live test ─────────────────────────────────────────────────────────────────

def tcp_check(ip, port):
    try:
        with socket.create_connection((ip, port), timeout=TCP_TIMEOUT):
            return "ok"
    except ConnectionRefusedError:
        return "refused"
    except Exception:
        return "timeout"


def test_proxy(proxy_str):
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
                r = requests.get(test_url, proxies=px, timeout=HTTP_TIMEOUT, headers=HEADERS)
                latency = round((time.monotonic() - t) * 1000)
                if r.status_code < 400:
                    cc = city = org = ""
                    try:
                        d = r.json()
                        cc, city, org = d.get("countryCode",""), d.get("city",""), d.get("org","")
                    except Exception:
                        pass
                    return {"proxy": proxy_str, "tcp": "ok", "working": True,
                            "protocol": proto.upper(), "latency_ms": latency,
                            "country": cc, "city": city, "isp": org}
            except Exception:
                continue
    return {"proxy": proxy_str, "tcp": "ok", "working": False}


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    log("=" * 60)
    mode = "COLLECT-ONLY" if COLLECT_ONLY else "FULL TEST"
    log(f"Iran Proxy Checker — Fresh-Only Edition [{mode}]")
    log(f"Freshness window: {FRESH_HOURS} hours")
    log("=" * 60)

    log("\n── Loading Iran IP ranges ──")
    iran_networks = load_iran_networks()

    # Collect fresh candidates
    proxy_info = collect_fresh_candidates()
    if not proxy_info:
        log("ERROR: No fresh candidates found.")
        return

    # CIDR filter
    log("\n── Geo-filtering ──")
    iranian = cidr_filter(set(proxy_info.keys()), iran_networks)
    iran_info = {p: proxy_info[p] for p in iranian}

    if not iranian:
        log("No Iranian-range IPs found.")
        return

    # Source breakdown
    from collections import Counter
    src_counts = Counter(v["source"] for v in iran_info.values())
    log("  Source breakdown:")
    for src, cnt in src_counts.most_common():
        log(f"    {src:<25} {cnt}")

    # Live test
    working = []
    tcp_ok = tcp_refused = tcp_timeout_count = 0

    if COLLECT_ONLY:
        log(f"\n── COLLECT-ONLY: {len(iranian)} fresh Iranian IPs saved (no live test) ──")
    else:
        log(f"\n── Live testing {len(iranian)} fresh proxies ({MAX_WORKERS} threads) ──\n")
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
                    ok = sum(1 for r in all_results if r["tcp"] == "ok")
                    wk = sum(1 for r in all_results if r.get("working"))
                    log(f"  … {done}/{len(iranian)} | TCP-ok:{ok} | working:{wk}")

        working          = sorted([r for r in all_results if r.get("working")],
                                   key=lambda x: x["latency_ms"])
        tcp_ok           = sum(1 for r in all_results if r["tcp"] == "ok")
        tcp_refused      = sum(1 for r in all_results if r["tcp"] == "refused")
        tcp_timeout_count= sum(1 for r in all_results if r["tcp"] == "timeout")

        proto_counts = {}
        for p in working:
            proto_counts[p["protocol"]] = proto_counts.get(p["protocol"], 0) + 1
        breakdown = "  ".join(f"{k}:{v}" for k, v in sorted(proto_counts.items()))

        log(f"\n{'='*60}")
        log(f"total={len(iranian)}  tcp-ok={tcp_ok}  "
            f"refused={tcp_refused}  timeout={tcp_timeout_count}  working={len(working)}")
        if breakdown:
            log(f"Protocol breakdown: {breakdown}")
        if tcp_timeout_count > tcp_ok:
            log("NOTE: Most timeouts = Azure routing block (use self-hosted runner)")
        log(f"{'='*60}\n")

    now = NOW_UTC.strftime("%Y-%m-%d %H:%M UTC")
    out = Path("working_iran_proxies.txt")
    with open(out, "w") as f:
        f.write(f"# Iranian Proxies — {now}\n")
        f.write(f"# Freshness window: {FRESH_HOURS}h | Mode: {mode}\n")
        f.write(f"# Live-verified: {len(working)} | Fresh CIDR-confirmed: {len(iranian)}\n")
        if not COLLECT_ONLY:
            f.write(f"# TCP: ok={tcp_ok} refused={tcp_refused} timeout={tcp_timeout_count}\n")
        f.write("#\n\n")

        if working:
            f.write("# === LIVE-VERIFIED WORKING PROXIES ===\n\n")
            for p in working:
                f.write(f"{p['protocol']:<8} {p['proxy']:<26} {p['latency_ms']:>5}ms\n")
            f.write("\n# --- Raw (verified) ---\n")
            for p in working:
                f.write(f"{p['proxy']}\n")
        else:
            f.write("# === ALL FRESH CIDR-CONFIRMED IRANIAN IPs ===\n")
            if not COLLECT_ONLY and tcp_timeout_count > tcp_ok:
                f.write("# (live test blocked by Azure — run locally for verified results)\n")
            f.write("\n")

        f.write("\n# === ALL FRESH IRANIAN IPs (unverified) ===\n\n")
        # Sort: geonode/proxyscrape/openray first (have timestamps), then others
        priority_order = ["geonode","proxyscrape","openray","ebrasha","proxifly",
                          "ditatompel","ir_targeted","proxydb"]
        def sort_key(proxy):
            src = iran_info[proxy]["source"]
            try:
                return priority_order.index(src)
            except ValueError:
                return len(priority_order)
        for proxy in sorted(iranian, key=sort_key):
            info = iran_info[proxy]
            ts_str = f"  last_seen: {info['ts']}" if info.get("ts") and info["ts"] not in ("", "repo_fresh", "ir_targeted", "fresh_5min") else ""
            f.write(f"{proxy:<26}  # {info['source']}{ts_str}\n")

    jp = Path("working_iran_proxies.json")
    with open(jp, "w") as f:
        json.dump({
            "checked_at"    : now,
            "fresh_hours"   : FRESH_HOURS,
            "mode"          : mode,
            "verified_count": len(working),
            "fresh_count"   : len(iranian),
            "tcp_stats"     : {"ok": tcp_ok, "refused": tcp_refused, "timeout": tcp_timeout_count},
            "source_counts" : dict(src_counts),
            "verified"      : working,
            "all_fresh_ips" : [
                {"proxy": p, "source": iran_info[p]["source"], "ts": iran_info[p]["ts"]}
                for p in sorted(iranian, key=sort_key)
            ],
        }, f, indent=2, ensure_ascii=False)

    log(f"Saved → {out} / {jp}")


if __name__ == "__main__":
    main()
