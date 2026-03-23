#!/usr/bin/env python3
"""
Iran Proxy Checker — Globally-Routable ASN Edition
====================================================
Key insight: Most of Iran's IP space is only reachable from *within* Iran
(National Information Network / SHOMA).  Proxies on those IPs always
time-out from outside.

This script filters proxy candidates to only those whose IP belongs to a
proven globally-routable Iranian ASN.  The allowlist is loaded from
merged_routable_asns.json (committed to this repo), which contains 18 ASNs
and ~4,600 real BGP-announced prefixes.  BGPView is used to refresh that
file at runtime; the JSON acts as the persistent fallback.

ASN coverage (see merged_routable_asns.json for full prefix lists):
  AS43754  Asiatech Data Transmission
  AS62229  Fars News Agency (own ASN)
  AS48159  TIC / ITC Backbone
  AS12880  Iran Telecommunications Co.
  AS16322  Pars Online / Respina
  AS42337  Respina Networks & Beyond       ← new
  AS49666  TIC Gateway (transit backbone)  ← new
  AS24631  FANAPTELECOM / Fanavari Pasargad← new
  AS56402  Dadeh Gostar Asr Novin          ← new
  AS31549  Afranet
  AS44244  IranCell / MCI
  AS197207 Mobile Communication of Iran
  AS58224  Iran Telecom PJS
  AS39501  Aria Shatel
  AS57218  RayaPars
  AS25184  Afagh Danesh Gostar
  AS51695  (Iranian ISP)
  AS47262  (Iranian ISP)
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
FRESH_HOURS    = int(os.environ.get("FRESH_HOURS", "72"))
SCRAPE_TIMEOUT = 12
TCP_TIMEOUT    = 8
HTTP_TIMEOUT   = 20
MAX_WORKERS    = 60

# Path to the committed ASN+prefix database
ASN_JSON_PATH  = Path(__file__).parent / "merged_routable_asns.json"

# All routable Iranian ASNs — drives BGPView refresh
REACHABLE_ASNS = [
    "AS43754",  # Asiatech Data Transmission — telewebion.ir
    "AS62229",  # Fars News Agency — farsnews.ir
    "AS48159",  # TIC / ITC Backbone
    "AS12880",  # Iran Telecommunications Co.
    "AS16322",  # Pars Online / Respina
    "AS42337",  # Respina Networks & Beyond
    "AS49666",  # TIC Gateway — transit for all Iranian ISPs
    "AS24631",  # FANAPTELECOM / Fanavari Pasargad
    "AS56402",  # Dadeh Gostar Asr Novin
    "AS31549",  # Afranet
    "AS44244",  # IranCell / MCI
    "AS197207", # Mobile Communication of Iran (MCI)
    "AS58224",  # Iran Telecom PJS
    "AS39501",  # Aria Shatel
    "AS57218",  # RayaPars
    "AS25184",  # Afagh Danesh Gostar
    "AS51695",  # Iranian ISP
    "AS47262",  # Iranian ISP
]

TEST_URLS = [
    "http://ip-api.com/json/?fields=status,countryCode,query,org,city",
    "http://httpbin.org/ip",
    "http://api.ipify.org",
    "http://ifconfig.me/ip",
    "http://checkip.amazonaws.com",
    "http://digikala.com",
    "http://telewebion.ir",
]

PROBE_SITES = [
    "telewebion.ir",
    "farsnews.ir",
    "tasnimnews.ir",
    "sepehrtv.ir",
    "aparatchi.com",
    "parsatv.com",
    "freeintertv.com",
    "imvbox.com",
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


# ── Prefix allowlist — three-tier loading ─────────────────────────────────────

def load_from_json() -> dict:
    """Load ASN→prefix mapping from the committed JSON file."""
    if not ASN_JSON_PATH.exists():
        return {}
    try:
        with open(ASN_JSON_PATH) as f:
            data = json.load(f)
        return data  # {"AS43754": {"name": ..., "prefixes": [...]}, ...}
    except Exception as e:
        log(f"  ! Could not read {ASN_JSON_PATH.name}: {e}")
        return {}


def fetch_asn_prefixes_bgpview(asn: str) -> list:
    """Fetch live announced IPv4 prefixes for one ASN from BGPView."""
    url = f"https://api.bgpview.io/asn/{asn.lstrip('AS')}/prefixes"
    try:
        r = requests.get(url, headers=HEADERS, timeout=15)
        r.raise_for_status()
        nets = []
        for p in r.json().get("data", {}).get("ipv4_prefixes", []):
            try:
                nets.append(p["prefix"])
            except (KeyError, TypeError):
                pass
        return nets
    except Exception as e:
        log(f"  ! BGPView {asn}: {e}")
        return []


def refresh_json_from_bgpview(existing: dict) -> dict:
    """
    Query BGPView for every ASN in REACHABLE_ASNS.
    Merges new prefixes into existing data and saves back to disk.
    Returns the updated dict.
    """
    log(f"  Refreshing {len(REACHABLE_ASNS)} ASNs from BGPView…")
    updated = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        futures = {ex.submit(fetch_asn_prefixes_bgpview, asn): asn
                   for asn in REACHABLE_ASNS}
        for future in concurrent.futures.as_completed(futures):
            asn = futures[future]
            try:
                new_prefixes = future.result()
                old_entry    = existing.get(asn, {})
                old_prefixes = set(old_entry.get("prefixes", []))
                merged       = sorted(old_prefixes | set(new_prefixes))
                updated[asn] = {
                    "name"    : old_entry.get("name", asn),
                    "prefixes": merged,
                }
                delta = len(merged) - len(old_prefixes)
                log(f"    {asn:<12} {len(merged):>4} prefixes "
                    f"({'+'  if delta >= 0 else ''}{delta} vs stored)")
            except Exception as e:
                log(f"    {asn}: error — {e}")
                if asn in existing:
                    updated[asn] = existing[asn]   # keep old data

    # Write back only if we got something useful
    if updated:
        try:
            with open(ASN_JSON_PATH, "w") as f:
                json.dump(updated, f, indent=2, ensure_ascii=False)
            log(f"  Saved updated {ASN_JSON_PATH.name}")
        except Exception as e:
            log(f"  ! Could not write {ASN_JSON_PATH.name}: {e}")

    return updated if updated else existing


def build_network_list(asn_data: dict) -> list:
    """Convert ASN dict → flat deduplicated list of IPv4Network objects."""
    all_cidrs = set()
    for entry in asn_data.values():
        all_cidrs.update(entry.get("prefixes", []))
    nets = []
    for cidr in all_cidrs:
        try:
            nets.append(ipaddress.IPv4Network(cidr, strict=False))
        except ValueError:
            pass
    return nets


def load_routable_networks() -> tuple[list, dict]:
    """
    Three-tier loading:
      1. Read merged_routable_asns.json (always fast, works offline)
      2. Refresh from BGPView (adds any new prefixes since last commit)
      3. If both fail, use minimal hardcoded fallback
    Returns (list of IPv4Network, asn_dict for saving back)
    """
    # Tier 1 — committed JSON
    asn_data = load_from_json()
    if asn_data:
        total = sum(len(v.get("prefixes", [])) for v in asn_data.values())
        log(f"  Loaded {total} prefixes across {len(asn_data)} ASNs "
            f"from {ASN_JSON_PATH.name}")
    else:
        log(f"  {ASN_JSON_PATH.name} not found — will rely on BGPView")

    # Tier 2 — BGPView refresh (merges on top of JSON data)
    asn_data = refresh_json_from_bgpview(asn_data)
    if asn_data:
        nets = build_network_list(asn_data)
        log(f"  Final allowlist: {len(nets)} unique prefixes")
        return nets, asn_data

    # Tier 3 — minimal hardcoded fallback
    log("  Both JSON and BGPView failed — using minimal hardcoded fallback")
    fallback = [
        "79.127.0.0/17",  "188.0.208.0/20", "188.0.240.0/20",
        "62.60.0.0/15",   "213.176.0.0/16",
        "2.144.0.0/12",   "2.176.0.0/12",   "94.182.0.0/15",
        "217.218.0.0/15", "217.219.0.0/16",
        "78.38.0.0/15",   "91.92.0.0/16",
        "77.36.128.0/17", "85.185.0.0/16",
        "37.32.0.0/11",   "5.200.0.0/14",
        "80.191.0.0/16",  "80.210.0.0/15",
        "87.247.0.0/16",  "185.49.96.0/22", "185.93.0.0/16",
    ]
    return [ipaddress.IPv4Network(c, strict=False) for c in fallback], {}


# ── ASN filter ────────────────────────────────────────────────────────────────

def in_routable(ip: str, networks: list) -> bool:
    try:
        addr = ipaddress.IPv4Address(ip)
        return any(addr in net for net in networks)
    except ValueError:
        return False


def asn_filter(candidates: set, networks: list) -> set:
    log(f"ASN-filtering {len(candidates)} candidates…")
    t = time.monotonic()
    result = {p for p in candidates if in_routable(p.split(":")[0], networks)}
    log(f"  → {len(result)} on routable Iranian ASNs "
        f"({round(time.monotonic()-t, 2)}s)")
    return result


# ── Site probe → auto-discover new ASNs ──────────────────────────────────────

def probe_sites_and_discover(networks: list, asn_data: dict) -> list:
    """
    Resolve probe sites. If an IP falls outside the current prefix list,
    look up its ASN via ipinfo.io and auto-add it.
    """
    log("\n── Probing known-reachable Iranian sites ──")
    extra = []
    for site in PROBE_SITES:
        try:
            ip   = socket.gethostbyname(site)
            addr = ipaddress.IPv4Address(ip)
            matched = [str(n) for n in networks if addr in n]
            if matched:
                log(f"  ✓ {site:<22} {ip:<18} → {matched[0]}")
            else:
                info = requests.get(
                    f"https://ipinfo.io/{ip}/json",
                    headers=HEADERS, timeout=8
                ).json()
                asn_str = info.get("org", "").split()[0]
                country = info.get("country", "")
                if country != "IR":
                    log(f"  - {site:<22} {ip:<18} → {asn_str} "
                        f"({country}) — non-Iranian IP (CDN/split-horizon)")
                else:
                    log(f"  ? {site:<22} {ip:<18} → {asn_str} "
                        f"— Iranian but not in allowlist, fetching…")
                    new_prefixes = fetch_asn_prefixes_bgpview(asn_str)
                    if new_prefixes:
                        extra.extend([
                            ipaddress.IPv4Network(p, strict=False)
                            for p in new_prefixes
                        ])
                        log(f"    ↳ auto-added {len(new_prefixes)} prefixes "
                            f"for {asn_str}")
        except OSError:
            log(f"  - {site:<22} (DNS failed)")
        except Exception as e:
            log(f"  - {site:<22} error: {e}")
    return extra


# ── Freshness helpers ─────────────────────────────────────────────────────────

def is_fresh(ts_str: str) -> bool:
    if not ts_str:
        return False
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S+00:00", "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
    ):
        try:
            dt = datetime.strptime(ts_str[:26], fmt).replace(tzinfo=timezone.utc)
            return dt >= CUTOFF
        except ValueError:
            continue
    return False


def clean_proxy(proxy: str):
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
# SOURCES
# ══════════════════════════════════════════════════════════════════════════════

def fetch_geonode_fresh():
    results = {}
    total = kept = 0
    for page in range(1, 6):
        url = (f"https://proxylist.geonode.com/api/proxy-list"
               f"?country=IR&limit=100&page={page}"
               f"&sort_by=lastChecked&sort_type=desc")
        try:
            r    = requests.get(url, headers=HEADERS, timeout=SCRAPE_TIMEOUT)
            data = r.json().get("data", [])
            if not data:
                break
            for p in data:
                ip    = p.get("ip", "")
                ts    = (p.get("updatedAt") or p.get("lastChecked")
                         or p.get("created_at", ""))
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
    log(f"  [geonode] {kept}/{total} within {FRESH_HOURS}h")
    return results


def fetch_proxyscrape_fresh():
    results = {}
    total = kept = 0
    for protocol in ("http", "socks4", "socks5"):
        url = (f"https://api.proxyscrape.com/v3/free-proxy-list/get"
               f"?request=getproxies&country=ir&protocol={protocol}"
               f"&anonymity=all&timeout=10000&format=json")
        try:
            r    = requests.get(url, headers=HEADERS, timeout=SCRAPE_TIMEOUT)
            body = r.text.strip()
            if not body:
                continue
            for p in r.json().get("proxies", []):
                proxy = p.get("proxy", "")
                ts    = p.get("last_seen", "") or p.get("added", "")
                total += 1
                if proxy and is_fresh(ts):
                    kept += 1
                    results[proxy] = ts
        except Exception as e:
            log(f"  ! proxyscrape {protocol}: {e}")
    log(f"  [proxyscrape] {kept}/{total} within {FRESH_HOURS}h")
    return results


def fetch_proxifly():
    results = {}
    url = ("https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main"
           "/proxies/countries/IR/data.txt")
    try:
        r = requests.get(url, headers=HEADERS, timeout=SCRAPE_TIMEOUT)
        for ip, port in IP_PORT_RE.findall(r.text):
            if not PRIVATE_RE.match(ip):
                results[f"{ip}:{port}"] = "fresh_5min"
        log(f"  [proxifly] {len(results)} IR proxies")
    except Exception as e:
        log(f"  ! proxifly: {e}")
    return results


def fetch_openray():
    results = {}
    url = ("https://raw.githubusercontent.com/sakha1370/OpenRay/"
           "refs/heads/main/output_iran/iran_top100_checked.txt")
    try:
        r = requests.get(url, headers=HEADERS, timeout=SCRAPE_TIMEOUT)
        for ip, port in IP_PORT_RE.findall(r.text):
            if not PRIVATE_RE.match(ip):
                results[f"{ip}:{port}"] = "repo_fresh"
        log(f"  [openray] {len(results)} IR proxies")
    except Exception as e:
        log(f"  ! openray: {e}")
    return results


def fetch_ir_targeted():
    results = {}
    sources = [
        ("https://proxydb.net/?protocol=socks5&country=IR", "proxydb_s5"),
        ("https://proxydb.net/?protocol=http&country=IR",   "proxydb_http"),
        ("https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main"
         "/proxies/countries/IR/data.json",                 "proxifly_json"),
    ]
    for url, label in sources:
        try:
            r = requests.get(url, headers=HEADERS, timeout=SCRAPE_TIMEOUT)
            for ip, port in IP_PORT_RE.findall(r.text):
                if not PRIVATE_RE.match(ip):
                    results[f"{ip}:{port}"] = "ir_targeted"
        except Exception as e:
            log(f"  ! {label}: {e}")
    log(f"  [ir_targeted] {len(results)} proxies")
    return results


def github_repo_updated_within(owner, repo, max_hours):
    try:
        r = requests.get(
            f"https://api.github.com/repos/{owner}/{repo}",
            headers={**HEADERS, "Accept": "application/vnd.github+json"},
            timeout=10,
        )
        pushed = r.json().get("pushed_at", "")
        return is_fresh(pushed) if pushed else False
    except Exception:
        return False


def fetch_github_raw_fresh(name, owner, repo, path, max_hours):
    if not github_repo_updated_within(owner, repo, max_hours):
        log(f"  [github/{name}] not updated within {max_hours}h — skipped")
        return {}
    url = f"https://raw.githubusercontent.com/{owner}/{repo}/main/{path}"
    try:
        r = requests.get(url, headers=HEADERS, timeout=SCRAPE_TIMEOUT)
        result = {}
        for ip, port in IP_PORT_RE.findall(r.text):
            if not PRIVATE_RE.match(ip):
                result[f"{ip}:{port}"] = "repo_fresh"
        log(f"  [github/{name}] {len(result)} proxies")
        return result
    except Exception as e:
        log(f"  ! github/{name}: {e}")
        return {}


def collect_fresh_candidates() -> dict:
    log("\n── Collecting fresh candidates (parallel) ──")
    all_proxies: dict = {}

    def merge(d, source_name):
        for proxy, ts in d.items():
            p = clean_proxy(proxy)
            if p and p not in all_proxies:
                all_proxies[p] = {"ts": ts, "source": source_name}

    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
        jobs = {
            ex.submit(fetch_geonode_fresh)      : "geonode",
            ex.submit(fetch_proxyscrape_fresh)  : "proxyscrape",
            ex.submit(fetch_proxifly)           : "proxifly",
            ex.submit(fetch_openray)            : "openray",
            ex.submit(fetch_ir_targeted)        : "ir_targeted",
            ex.submit(fetch_github_raw_fresh,
                "vakhov_s5","vakhov","fresh-proxy-list",
                "socks5.txt", 6)                : "vakhov_s5",
            ex.submit(fetch_github_raw_fresh,
                "ercindedeoglu_s5","ErcinDedeoglu","proxies",
                "proxies/socks5.txt", 12)       : "ercindedeoglu_s5",
            ex.submit(fetch_github_raw_fresh,
                "ercindedeoglu_http","ErcinDedeoglu","proxies",
                "proxies/http.txt", 12)         : "ercindedeoglu_http",
            ex.submit(fetch_github_raw_fresh,
                "proxy4p","proxy4parsing","proxy-list",
                "http.txt", 1)                  : "proxy4p",
            ex.submit(fetch_github_raw_fresh,
                "zaeem_http","Zaeem20","FREE_PROXIES_LIST",
                "http.txt", 24)                 : "zaeem_http",
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
    tcp  = tcp_check(ip, port)
    if tcp != "ok":
        return {"proxy": proxy_str, "tcp": tcp, "working": False}
    for proto in ("socks5", "socks4", "http"):
        px = {"http": f"{proto}://{ip}:{port}", "https": f"{proto}://{ip}:{port}"}
        for test_url in TEST_URLS:
            try:
                t = time.monotonic()
                r = requests.get(test_url, proxies=px, timeout=HTTP_TIMEOUT,
                                 headers=HEADERS)
                latency = round((time.monotonic() - t) * 1000)
                if r.status_code < 400:
                    cc = city = org = ""
                    try:
                        d    = r.json()
                        cc   = d.get("countryCode", "")
                        city = d.get("city", "")
                        org  = d.get("org", "")
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
    log(f"Iran Proxy Checker — Globally-Routable ASN Edition [{mode}]")
    log(f"Freshness window: {FRESH_HOURS} hours")
    log("=" * 60)

    # 1 — Load routable prefix allowlist
    log("\n── Loading routable Iranian ASN prefixes ──")
    routable_networks, asn_data = load_routable_networks()

    # 2 — Probe sites → auto-discover any new routable ASNs
    extra = probe_sites_and_discover(routable_networks, asn_data)
    if extra:
        routable_networks = list(
            {str(n): n for n in routable_networks + extra}.values()
        )
        log(f"  Updated allowlist: {len(routable_networks)} prefixes")

    # 3 — Collect candidates from all sources
    proxy_info = collect_fresh_candidates()
    if not proxy_info:
        log("ERROR: No fresh candidates found.")
        return

    # 4 — ASN filter
    log("\n── ASN-filtering (globally-routable Iranian IPs only) ──")
    routable = asn_filter(set(proxy_info.keys()), routable_networks)
    ir_info  = {p: proxy_info[p] for p in routable}

    if not routable:
        log("No candidates survived ASN filter.")
        log("The proxy sources had no IPs on the routable ASNs right now.")
        return

    from collections import Counter
    src_counts = Counter(v["source"] for v in ir_info.values())
    log("  Source breakdown:")
    for src, cnt in src_counts.most_common():
        log(f"    {src:<25} {cnt}")

    # 5 — Live test
    working = []
    tcp_ok = tcp_refused = tcp_timeout_count = 0

    if COLLECT_ONLY:
        log(f"\n── COLLECT-ONLY: {len(routable)} routable IPs saved ──")
    else:
        log(f"\n── Live testing {len(routable)} proxies ({MAX_WORKERS} threads) ──\n")
        all_results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {executor.submit(test_proxy, p): p for p in routable}
            done = 0
            for future in concurrent.futures.as_completed(futures):
                done += 1
                result = future.result()
                all_results.append(result)
                if result.get("working"):
                    log(f"  ✓ [{result['protocol']:<6}] {result['proxy']:<26} "
                        f"{result['latency_ms']:>5}ms  "
                        f"{result.get('city',''):<15}  {result.get('isp','')}")
                if done % 50 == 0:
                    ok = sum(1 for r in all_results if r["tcp"] == "ok")
                    wk = sum(1 for r in all_results if r.get("working"))
                    log(f"  … {done}/{len(routable)} | TCP-ok:{ok} | working:{wk}")

        working = sorted(
            [r for r in all_results if r.get("working")],
            key=lambda x: x["latency_ms"],
        )
        tcp_ok            = sum(1 for r in all_results if r["tcp"] == "ok")
        tcp_refused       = sum(1 for r in all_results if r["tcp"] == "refused")
        tcp_timeout_count = sum(1 for r in all_results if r["tcp"] == "timeout")

        proto_counts = {}
        for p in working:
            proto_counts[p["protocol"]] = proto_counts.get(p["protocol"], 0) + 1
        breakdown = "  ".join(f"{k}:{v}" for k, v in sorted(proto_counts.items()))

        log(f"\n{'='*60}")
        log(f"total={len(routable)}  tcp-ok={tcp_ok}  "
            f"refused={tcp_refused}  timeout={tcp_timeout_count}  "
            f"working={len(working)}")
        if breakdown:
            log(f"Protocol breakdown: {breakdown}")
        log(f"{'='*60}\n")

    # 6 — Save
    now = NOW_UTC.strftime("%Y-%m-%d %H:%M UTC")
    out = Path("working_iran_proxies.txt")
    priority_order = ["geonode", "proxyscrape", "openray", "proxifly",
                      "ir_targeted", "proxydb_s5", "proxydb_http"]

    def sort_key(proxy):
        src = ir_info[proxy]["source"]
        try:
            return priority_order.index(src)
        except ValueError:
            return len(priority_order)

    with open(out, "w") as f:
        f.write(f"# Iranian Proxies — Globally-Routable ASN Filter — {now}\n")
        f.write(f"# Freshness: {FRESH_HOURS}h | Mode: {mode}\n")
        f.write(f"# ASNs: {', '.join(REACHABLE_ASNS)}\n")
        f.write(f"# Routable prefixes: {len(routable_networks)} | "
                f"Verified: {len(working)} | Candidates: {len(routable)}\n")
        if not COLLECT_ONLY:
            f.write(f"# TCP: ok={tcp_ok} refused={tcp_refused} "
                    f"timeout={tcp_timeout_count}\n")
        f.write("#\n\n")

        if working:
            f.write("# === LIVE-VERIFIED WORKING PROXIES ===\n\n")
            for p in working:
                f.write(f"{p['protocol']:<8} {p['proxy']:<26} "
                        f"{p['latency_ms']:>5}ms  "
                        f"{p.get('city',''):<15}  {p.get('isp','')}\n")
            f.write("\n# --- Raw (verified) ---\n")
            for p in working:
                f.write(f"{p['proxy']}\n")
        else:
            f.write("# === ALL ASN-CONFIRMED IRANIAN IPs (unverified) ===\n\n")

        f.write("\n# === ALL GLOBALLY-ROUTABLE IRANIAN IPs (unverified) ===\n\n")
        for proxy in sorted(routable, key=sort_key):
            info = ir_info[proxy]
            ts_str = (
                f"  last_seen: {info['ts']}"
                if info.get("ts") and info["ts"] not in
                ("", "repo_fresh", "ir_targeted", "fresh_5min")
                else ""
            )
            f.write(f"{proxy:<26}  # {info['source']}{ts_str}\n")

    jp = Path("working_iran_proxies.json")
    with open(jp, "w") as f:
        json.dump({
            "checked_at"        : now,
            "fresh_hours"       : FRESH_HOURS,
            "mode"              : mode,
            "routable_asns"     : REACHABLE_ASNS,
            "routable_prefixes" : len(routable_networks),
            "verified_count"    : len(working),
            "routable_count"    : len(routable),
            "tcp_stats"         : {"ok": tcp_ok, "refused": tcp_refused,
                                   "timeout": tcp_timeout_count},
            "source_counts"     : dict(src_counts),
            "verified"          : working,
            "all_routable_ips"  : [
                {"proxy": p, "source": ir_info[p]["source"],
                 "ts": ir_info[p]["ts"]}
                for p in sorted(routable, key=sort_key)
            ],
        }, f, indent=2, ensure_ascii=False)

    log(f"Saved → {out} / {jp}")


if __name__ == "__main__":
    main()
