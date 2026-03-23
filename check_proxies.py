#!/usr/bin/env python3
"""
Iran Proxy Checker — Active CIDR Scanner Edition
=================================================
Two-phase approach:

PHASE 1 — Passive collection
  Fetch from geonode, proxyscrape, proxifly, openray etc.
  Keep only IPs on globally-routable Iranian ASNs.

PHASE 2 — Active CIDR scan
  Sample IPs directly from routable Iranian CIDRs and TCP-probe
  common proxy ports. Finds proxies aggregators never publish.

  Target budget: ~1.35M probes (3 IPs × 7 ports per /24 block)
  At 2000 workers / 0.5s timeout → ~6 minutes.
"""

import ipaddress, os, socket, requests, concurrent.futures
import json, re, time, random
from datetime import datetime, timezone, timedelta
from pathlib import Path

# ── Config ────────────────────────────────────────────────────────────────────

COLLECT_ONLY   = os.environ.get("COLLECT_ONLY", "").strip() == "1"
FRESH_HOURS    = int(os.environ.get("FRESH_HOURS", "72"))
SCRAPE_TIMEOUT = 12
TCP_TIMEOUT    = 8
HTTP_TIMEOUT   = 20
MAX_WORKERS    = 60
SCAN_WORKERS   = int(os.environ.get("SCAN_WORKERS", "2000"))
SCAN_TCP_TO    = float(os.environ.get("SCAN_TCP_TO", "0.5"))

# 3 IPs × 7 ports = 21 probes per /24 block → ~1.35M total, ~6min
SAMPLE_OFFSETS = [1, 100, 200]
PROXY_PORTS    = [1080, 3128, 8080, 8088, 8118, 8888, 9999]

ASN_JSON_PATH  = Path(__file__).parent / "merged_routable_asns.json"

REACHABLE_ASNS = [
    "AS43754",   # Asiatech Data Transmission — telewebion.ir
    "AS64422",   # Sima Rayan Sharif — telewebion.ir (current IP)  ← new
    "AS62229",   # Fars News Agency — farsnews.ir
    "AS48159",   # TIC / ITC Backbone
    "AS12880",   # Iran Telecommunications Co.
    "AS16322",   # Pars Online / Respina
    "AS42337",   # Respina Networks & Beyond
    "AS49666",   # TIC Gateway (transit for all Iranian ISPs)
    "AS21341",   # Fanava Group — sepehrtv.ir (current IP)         ← new
    "AS24631",   # FANAPTELECOM / Fanavari Pasargad
    "AS56402",   # Dadeh Gostar Asr Novin
    "AS31549",   # Afranet
    "AS44244",   # IranCell / MCI
    "AS197207",  # Mobile Communication of Iran (MCI)
    "AS58224",   # Iran Telecom PJS
    "AS39501",   # Aria Shatel
    "AS57218",   # RayaPars
    "AS25184",   # Afagh Danesh Gostar
    "AS51695",   # Iranian ISP
    "AS47262",   # Iranian ISP
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
    "telewebion.ir", "farsnews.ir", "tasnimnews.ir",
    "sepehrtv.ir", "aparatchi.com", "parsatv.com",
    "freeintertv.com", "imvbox.com",
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
    print(f"[{NOW_UTC.strftime('%H:%M:%S')}] {msg}", flush=True)


# ── ASN / prefix loading ──────────────────────────────────────────────────────

def load_from_json() -> dict:
    if not ASN_JSON_PATH.exists():
        return {}
    try:
        with open(ASN_JSON_PATH) as f:
            return json.load(f)
    except Exception as e:
        log(f"  ! Could not read {ASN_JSON_PATH.name}: {e}")
        return {}


def fetch_asn_prefixes(asn: str) -> list:
    """
    Fetch announced IPv4 prefixes for an ASN.
    Tries RIPE Stat first (always reachable), falls back to BGPView.
    """
    asn_num = asn.lstrip("AS")

    # ── Primary: RIPE Stat (stat.ripe.net) ────────────────────────────────────
    # Free, no key, authoritative (RIPE NCC is the European RIR).
    ripe_url = (f"https://stat.ripe.net/data/announced-prefixes/data.json"
                f"?resource=AS{asn_num}")
    try:
        r = requests.get(ripe_url, headers=HEADERS, timeout=20)
        r.raise_for_status()
        data = r.json().get("data", {}).get("prefixes", [])
        if data and isinstance(data, list):
            pfx = [p["prefix"] for p in data
                   if isinstance(p, dict) and p.get("prefix")
                   and ":" not in p["prefix"]]   # IPv4 only
            if pfx:
                return sorted(set(pfx))
    except requests.exceptions.ConnectionError:
        pass   # offline / blocked
    except Exception as e:
        log(f"  ! RIPE Stat {asn}: {e}")

    # ── Fallback: BGPView ──────────────────────────────────────────────────────
    try:
        r = requests.get(
            f"https://api.bgpview.io/asn/{asn_num}/prefixes",
            headers=HEADERS, timeout=15
        )
        r.raise_for_status()
        return [p["prefix"] for p in
                r.json().get("data", {}).get("ipv4_prefixes", [])
                if p.get("prefix")]
    except requests.exceptions.ConnectionError:
        return []
    except Exception as e:
        log(f"  ! BGPView {asn}: {e}")
        return []


def _normalise_prefixes(raw_list) -> set:
    """
    Flatten prefix lists that may contain bare strings OR single-element lists
    produced by R's write_json(auto_unbox = FALSE).
    Example input:  ["1.2.3.0/24", ["4.5.6.0/24"]]
    Example output: {"1.2.3.0/24", "4.5.6.0/24"}
    """
    out = set()
    for item in raw_list:
        if isinstance(item, str):
            out.add(item)
        elif isinstance(item, list) and len(item) == 1 and isinstance(item[0], str):
            out.add(item[0])
    return out


def refresh_json_from_bgpview(existing: dict) -> dict:
    """
    Refresh ASN prefixes from RIPE Stat / BGPView. Merges on top of JSON.
    Runs silently if both are unreachable (e.g. blocked on GitHub Actions).
    """
    refresh_ok = False
    updated = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        futures = {ex.submit(fetch_asn_prefixes, asn): asn
                   for asn in REACHABLE_ASNS}
        for future in concurrent.futures.as_completed(futures):
            asn = futures[future]
            try:
                new_p     = set(future.result())
                old_entry = existing.get(asn, {})
                # Normalise old prefixes — may be list-wrapped from R JSON
                old_p     = _normalise_prefixes(old_entry.get("prefixes", []))
                merged    = sorted(old_p | new_p)
                updated[asn] = {"name": old_entry.get("name", asn),
                                 "prefixes": merged}
                if new_p:
                    refresh_ok = True
                    delta = len(merged) - len(old_p)
                    log(f"    {asn:<12} {len(merged):>4} prefixes "
                        f"({'+'  if delta >= 0 else ''}{delta})")
            except Exception:
                if asn in existing:
                    updated[asn] = existing[asn]

    if refresh_ok:
        log(f"  Refresh complete")
        try:
            with open(ASN_JSON_PATH, "w") as f:
                json.dump(updated, f, indent=2, ensure_ascii=False)
        except Exception as e:
            log(f"  ! Could not write {ASN_JSON_PATH.name}: {e}")
    else:
        log(f"  RIPE Stat/BGPView unreachable — using JSON data only")

    return updated if updated else existing


def build_network_list(asn_data: dict) -> list:
    """
    Build a deduplicated list of IPv4Network objects from the ASN data dict.
    Handles two JSON formats:
      - prefixes stored as strings:  "1.2.3.0/24"       (Python-written JSON)
      - prefixes stored as 1-lists:  ["1.2.3.0/24"]     (R write_json default)
    """
    seen = set()
    nets = []
    for entry in asn_data.values():
        for raw in entry.get("prefixes", []):
            # Unwrap single-element list produced by R's write_json(auto_unbox=FALSE)
            cidr = raw[0] if isinstance(raw, list) and len(raw) == 1 else raw
            if not isinstance(cidr, str):
                continue
            if cidr in seen:
                continue
            seen.add(cidr)
            try:
                nets.append(ipaddress.IPv4Network(cidr, strict=False))
            except ValueError:
                pass
    return nets


def load_routable_networks() -> tuple:
    asn_data = load_from_json()
    if asn_data:
        total = sum(len(v.get("prefixes", [])) for v in asn_data.values())
        log(f"  {total} prefixes across {len(asn_data)} ASNs "
            f"from {ASN_JSON_PATH.name}")
    else:
        log(f"  {ASN_JSON_PATH.name} not found — will build from BGPView")

    log(f"  Refreshing from BGPView ({len(REACHABLE_ASNS)} ASNs)…")
    asn_data = refresh_json_from_bgpview(asn_data)

    if asn_data:
        nets = build_network_list(asn_data)
        log(f"  Final: {len(nets)} unique prefixes")
        return nets, asn_data

    log("  Fallback to hardcoded CIDRs")
    fallback = [
        "79.127.0.0/17","188.0.208.0/20","188.0.240.0/20","62.60.0.0/15",
        "213.176.0.0/16","2.144.0.0/12","2.176.0.0/12","94.182.0.0/15",
        "217.218.0.0/15","78.38.0.0/15","91.92.0.0/16","77.36.128.0/17",
        "85.185.0.0/16","37.32.0.0/11","5.200.0.0/14","80.191.0.0/16",
        "87.247.0.0/16","185.49.96.0/22","185.93.0.0/16",
    ]
    return [ipaddress.IPv4Network(c, strict=False) for c in fallback], {}


# ── PHASE 2: Active CIDR scanner ─────────────────────────────────────────────

def generate_scan_targets(networks: list) -> list:
    """
    For every /24 block in the routable networks, emit
    (ip, port) pairs for SAMPLE_OFFSETS × PROXY_PORTS.
    Total = /24_block_count × len(SAMPLE_OFFSETS) × len(PROXY_PORTS)
    """
    targets = []
    for net in networks:
        subnets = list(net.subnets(new_prefix=24)) if net.prefixlen <= 24 else [net]
        for subnet in subnets:
            base    = int(subnet.network_address)
            max_off = subnet.num_addresses - 1
            for offset in SAMPLE_OFFSETS:
                if offset >= max_off:
                    continue
                ip_str = str(ipaddress.IPv4Address(base + offset))
                for port in PROXY_PORTS:
                    targets.append((ip_str, port))

    random.shuffle(targets)
    log(f"  Generated {len(targets):,} scan targets "
        f"({len(SAMPLE_OFFSETS)} IPs × {len(PROXY_PORTS)} ports per /24)")
    return targets


def tcp_probe(args) -> tuple | None:
    ip, port = args
    try:
        with socket.create_connection((ip, port), timeout=SCAN_TCP_TO):
            return (ip, port)
    except Exception:
        return None


def scan_routable_cidrs(networks: list) -> set:
    targets = generate_scan_targets(networks)
    total   = len(targets)
    est_min = total / (SCAN_WORKERS / SCAN_TCP_TO) / 60
    log(f"  Scanning with {SCAN_WORKERS} workers, {SCAN_TCP_TO}s timeout "
        f"(est. {est_min:.1f} min)…")

    open_ports: set = set()
    done = 0
    t0   = time.monotonic()

    with concurrent.futures.ThreadPoolExecutor(max_workers=SCAN_WORKERS) as ex:
        for result in ex.map(tcp_probe, targets, chunksize=500):
            done += 1
            if result:
                open_ports.add(f"{result[0]}:{result[1]}")
            if done % 100_000 == 0:
                elapsed = time.monotonic() - t0
                rate    = done / elapsed
                eta     = (total - done) / rate if rate > 0 else 0
                log(f"  … {done:,}/{total:,} | open: {len(open_ports)} "
                    f"| {rate:.0f}/s | ETA {eta:.0f}s")

    elapsed = time.monotonic() - t0
    log(f"  Scan complete in {elapsed:.1f}s — {len(open_ports)} open ports")
    return open_ports


# ── Filters & helpers ─────────────────────────────────────────────────────────

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
        f"({round(time.monotonic()-t, 1)}s)")
    return result


def probe_sites_and_discover(networks: list) -> list:
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
                try:
                    info    = requests.get(f"https://ipinfo.io/{ip}/json",
                                           headers=HEADERS, timeout=8).json()
                    asn_str = info.get("org", "").split()[0]
                    country = info.get("country", "")
                    if country != "IR":
                        log(f"  - {site:<22} {ip:<18} → {asn_str} "
                            f"({country}) — CDN/split-horizon")
                    else:
                        log(f"  ? {site:<22} {ip:<18} → {asn_str} "
                            f"— new Iranian ASN, fetching prefixes…")
                        new_p = fetch_asn_prefixes(asn_str)
                        if new_p:
                            extra.extend([
                                ipaddress.IPv4Network(p, strict=False)
                                for p in new_p
                            ])
                            log(f"    ↳ added {len(new_p)} prefixes for {asn_str}")
                        else:
                            log(f"    ↳ BGPView unreachable — add {asn_str} "
                                f"to REACHABLE_ASNS manually")
                except Exception:
                    pass
        except OSError:
            log(f"  - {site:<22} (DNS failed)")
    return extra


def is_fresh(ts_str: str) -> bool:
    if not ts_str:
        return False
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%dT%H:%M:%S+00:00", "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%dT%H:%M:%S"):
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
# PHASE 1: Passive sources
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
            body = r.json()
            # Geonode sometimes returns {"data": null} or {"data": <int>}
            raw_data = body.get("data", []) if isinstance(body, dict) else []
            if not raw_data or not isinstance(raw_data, list):
                break
            for p in raw_data:
                # Skip non-dict entries (API occasionally returns ints)
                if not isinstance(p, dict):
                    continue
                ip    = p.get("ip", "")
                ts    = (p.get("updatedAt") or p.get("lastChecked")
                         or p.get("created_at", ""))
                # port can be int, str, or list — normalise
                port_raw = p.get("port", [])
                if isinstance(port_raw, list):
                    ports = [str(x) for x in port_raw if x]
                else:
                    ports = [str(port_raw)] if port_raw else []
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
            data = r.json()
            # API may return a list, {"proxies": [...]}, or {"proxies": 0}
            if isinstance(data, list):
                proxy_list = data
            elif isinstance(data, dict):
                raw = data.get("proxies", [])
                proxy_list = raw if isinstance(raw, list) else []
            else:
                proxy_list = []
            for p in proxy_list:
                if isinstance(p, str):
                    proxy, ts = p, ""
                elif isinstance(p, dict):
                    proxy = p.get("proxy", "")
                    ts    = p.get("last_seen", "") or p.get("added", "")
                else:
                    continue
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


def collect_passive_candidates() -> dict:
    log("\n── Phase 1: Passive collection from aggregators ──")
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

    log(f"  Passive total: {len(all_proxies)} candidates")
    return all_proxies


# ── Live proxy test ───────────────────────────────────────────────────────────

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
    log(f"Iran Proxy Checker — Active CIDR Scanner Edition [{mode}]")
    log(f"Freshness: {FRESH_HOURS}h | Scan: {SCAN_WORKERS}w/{SCAN_TCP_TO}s | "
        f"Probes/block: {len(SAMPLE_OFFSETS)}×{len(PROXY_PORTS)}={len(SAMPLE_OFFSETS)*len(PROXY_PORTS)}")
    log("=" * 60)

    log("\n── Loading routable Iranian ASN prefixes ──")
    routable_networks, asn_data = load_routable_networks()

    extra = probe_sites_and_discover(routable_networks)
    if extra:
        routable_networks = list(
            {str(n): n for n in routable_networks + extra}.values()
        )
        log(f"  Updated: {len(routable_networks)} prefixes")

    # Phase 1
    passive_info     = collect_passive_candidates()
    passive_routable = asn_filter(set(passive_info.keys()), routable_networks)
    log(f"  Passive after ASN filter: {len(passive_routable)}")

    # Phase 2
    log(f"\n── Phase 2: Active CIDR scan ──")
    scan_hits = scan_routable_cidrs(routable_networks)

    # Merge
    all_proxies: dict = {}
    for p in passive_routable:
        cp = clean_proxy(p)
        if cp:
            all_proxies[cp] = passive_info.get(p, {"ts": "", "source": "passive"})
    for p in scan_hits:
        cp = clean_proxy(p)
        if cp and cp not in all_proxies:
            all_proxies[cp] = {"ts": "scan_live", "source": "active_scan"}

    new_from_scan = len(scan_hits) - sum(
        1 for p in scan_hits if clean_proxy(p) in
        {clean_proxy(q) for q in passive_routable}
    )
    log(f"\n  Combined: {len(all_proxies)} "
        f"({len(passive_routable)} passive + {new_from_scan} new from scan)")

    if not all_proxies:
        log("ERROR: No candidates from either phase.")
        return

    from collections import Counter
    src_counts = Counter(v["source"] for v in all_proxies.values())
    log("  Source breakdown:")
    for src, cnt in src_counts.most_common():
        log(f"    {src:<25} {cnt}")

    # Phase 3: live test
    working = []
    tcp_ok = tcp_refused = tcp_timeout_count = 0

    if COLLECT_ONLY:
        log(f"\n── COLLECT-ONLY: {len(all_proxies)} candidates saved ──")
    else:
        log(f"\n── Phase 3: Live testing {len(all_proxies)} "
            f"({MAX_WORKERS} threads) ──\n")
        all_results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            futures = {ex.submit(test_proxy, p): p for p in all_proxies}
            done = 0
            for future in concurrent.futures.as_completed(futures):
                done += 1
                result = future.result()
                all_results.append(result)
                if result.get("working"):
                    log(f"  ✓ [{result['protocol']:<6}] {result['proxy']:<26} "
                        f"{result['latency_ms']:>5}ms  "
                        f"{result.get('city',''):<15}  {result.get('isp','')}")
                if done % 100 == 0:
                    ok = sum(1 for r in all_results if r["tcp"] == "ok")
                    wk = sum(1 for r in all_results if r.get("working"))
                    log(f"  … {done}/{len(all_proxies)} | TCP-ok:{ok} | working:{wk}")

        working = sorted([r for r in all_results if r.get("working")],
                         key=lambda x: x["latency_ms"])
        tcp_ok            = sum(1 for r in all_results if r["tcp"] == "ok")
        tcp_refused       = sum(1 for r in all_results if r["tcp"] == "refused")
        tcp_timeout_count = sum(1 for r in all_results if r["tcp"] == "timeout")

        proto_counts = {}
        for p in working:
            proto_counts[p["protocol"]] = proto_counts.get(p["protocol"], 0) + 1
        breakdown = "  ".join(f"{k}:{v}" for k, v in sorted(proto_counts.items()))
        log(f"\n{'='*60}")
        log(f"total={len(all_proxies)}  tcp-ok={tcp_ok}  "
            f"refused={tcp_refused}  timeout={tcp_timeout_count}  "
            f"working={len(working)}")
        if breakdown:
            log(f"Protocol breakdown: {breakdown}")
        log(f"{'='*60}\n")

    # Save
    now = NOW_UTC.strftime("%Y-%m-%d %H:%M UTC")
    out = Path("working_iran_proxies.txt")
    priority_order = ["active_scan","geonode","proxyscrape","openray",
                      "proxifly","ir_targeted"]

    def sort_key(proxy):
        src = all_proxies[proxy]["source"]
        try:
            return priority_order.index(src)
        except ValueError:
            return len(priority_order)

    with open(out, "w") as f:
        f.write(f"# Iranian Proxies — Active CIDR Scanner — {now}\n")
        f.write(f"# Mode: {mode} | Freshness: {FRESH_HOURS}h\n")
        f.write(f"# Prefixes: {len(routable_networks)} | "
                f"Scan hits: {len(scan_hits)} | "
                f"Total candidates: {len(all_proxies)}\n")
        f.write(f"# Verified: {len(working)}")
        if not COLLECT_ONLY:
            f.write(f" | TCP: ok={tcp_ok} refused={tcp_refused} "
                    f"timeout={tcp_timeout_count}")
        f.write("\n#\n\n")
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
            f.write("# === ALL CANDIDATES (unverified) ===\n\n")
        f.write("\n# === ALL CANDIDATES (unverified) ===\n\n")
        for proxy in sorted(all_proxies, key=sort_key):
            info   = all_proxies[proxy]
            ts_str = (f"  last_seen: {info['ts']}"
                      if info.get("ts") and info["ts"] not in
                      ("","repo_fresh","ir_targeted","fresh_5min",
                       "scan_live","passive")
                      else "")
            f.write(f"{proxy:<26}  # {info['source']}{ts_str}\n")

    jp = Path("working_iran_proxies.json")
    with open(jp, "w") as f:
        json.dump({
            "checked_at"        : now,
            "mode"              : mode,
            "routable_prefixes" : len(routable_networks),
            "passive_candidates": len(passive_routable),
            "scan_hits"         : len(scan_hits),
            "total_candidates"  : len(all_proxies),
            "verified_count"    : len(working),
            "tcp_stats"         : {"ok": tcp_ok, "refused": tcp_refused,
                                   "timeout": tcp_timeout_count},
            "source_counts"     : dict(src_counts),
            "verified"          : working,
            "all_candidates"    : [
                {"proxy": p, "source": all_proxies[p]["source"],
                 "ts": all_proxies[p]["ts"]}
                for p in sorted(all_proxies, key=sort_key)
            ],
        }, f, indent=2, ensure_ascii=False)

    log(f"Saved → {out} / {jp}")


if __name__ == "__main__":
    main()
