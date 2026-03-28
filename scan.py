#!/usr/bin/env python3
"""
Iran Network Scanner – Enhanced Edition v2
============================================
Robust discovery of routable Iranian ASNs and working proxies.

Improvements over v1:
  - RIPE NCC delegated stats file (direct prefix + ASN list, no BGP needed)
  - Hurricane Electric BGP country scraper
  - Cloudflare Radar ASN list (requires CLOUDFLARE_API_TOKEN)
  - Shadowserver BGP prefix data
  - Exponential-backoff retry on all RIPE Stat API calls
  - Masscan rate raised to 5000 pps
  - Stratified random IP sampling across full prefix range
  - Two-hop BGP neighbour expansion
  - IPv6 prefix discovery and storage
  - Multi-target proxy verification (2-of-3 geolocation sources must agree)
"""
import asyncio
import aiohttp
import argparse
import ipaddress
import json
import math
import os
import random
import re
import shutil
import socket
import sys
from collections import Counter, defaultdict
from datetime import datetime
from typing import Dict, List, Optional, Tuple

# ---------- Configuration ----------
RIPE_ATLAS_API_KEY   = os.environ.get("RIPE_ATLAS_API_KEY", "")
IPINFO_TOKEN         = os.environ.get("IPINFO_TOKEN", "")
CLOUDFLARE_API_TOKEN = os.environ.get("CLOUDFLARE_API_TOKEN", "")
TCP_TIMEOUT          = float(os.environ.get("TCP_TIMEOUT", "1.0"))
SCAN_WORKERS         = int(os.environ.get("SCAN_WORKERS", "2000"))
SKIP_EXIT_VERIFY     = os.environ.get("SKIP_EXIT_VERIFY", "").strip() == "1"
MIN_CONFIDENCE       = int(os.environ.get("MIN_CONFIDENCE", "1"))
HTTP_TIMEOUT         = int(os.environ.get("HTTP_TIMEOUT", "7"))

# Known Armenian ASNs — carriers with documented BGP peering into Iran
# ArmenTel (AS12297) ↔ TCI (AS12880); Ucom (AS43733) ↔ MCI (AS197207);
# VivaCell-MTS (AS44395) ↔ Irancell (AS44244).
ARMENIA_SEED_ASNS = [
    12297,   # ArmenTel / Telecom Armenia
    43733,   # Ucom LLC
    49800,   # GNC-Alfa CJSC
    44395,   # VivaCell-MTS (K-Telecom)
    201354,  # Beeline Armenia
    60280,   # DataCenter Armenia
    48716,   # Ucom Broadband
    197068,  # Rostelecom Armenia
    206804,  # Arminco LLC
    210756,  # Armex Technologies
]

# Armenian domains hosted on Armenian infrastructure (for DNS seeding)
ARMENIA_SEED_DOMAINS = [
    "ucom.am", "mts.am", "beeline.am", "rostelecom.am",
    "armentel.com", "arminco.com", "gnc.am",
    "ardshinbank.am", "evocabank.am", "inecobank.am",
    "gov.am", "police.am", "mfa.am",
]

# ── European bridge configuration ─────────────────────────────────────────────
# Bale (bale.ai) is an Iranian messaging platform reachable from European IPs
# (confirmed: Germany) but NOT from North America (Azure/GitHub runner IPs).
# This asymmetry makes Bale a reliable application-level probe: any proxy
# whose exit can reach Bale has a valid routing path into Iranian infrastructure,
# regardless of whether the exit IP geo-locates to Iran.
#
# Verification logic (see verify_proxy_http):
#   Tier 1 (standard)  – 2-of-3 geo sources agree exit = IR  → accept as IR proxy
#   Tier 2 (EU bridge) – exit geo = EU AND bale reachable    → accept as EU→IR bridge
#   Tier 3 (any-geo)   – 1-of-3 geo passes AND bale reachable → accept as unconfirmed bridge
#
# TCP connect to these hostnames/ports is sufficient — no auth needed.
BALE_TEST_ENDPOINTS: List[Tuple[str, int]] = [
    ("tapi.bale.ai",  443),   # Bot API — most reliable, always up
    ("bale.ai",       443),   # Main site
    ("bale.ai",        80),   # HTTP fallback
]
BALE_TCP_TIMEOUT = float(os.environ.get("BALE_TCP_TIMEOUT", "5.0"))

# European ASNs that host large concentrations of Iranian-operated VPN/proxy
# servers.  Many Iranian users/operators rent servers here because:
#  - German/EU DCs have fast connectivity to Iranian IPs via DE-CIX peering
#  - Hetzner, Contabo, etc. are cheap and accept crypto payment
#  - These IPs are not blocked by Iranian censors (unlike US/UK ranges)
EUROPEAN_BRIDGE_ASNS: List[int] = [
    # Germany — primary
    24940,   # Hetzner Online GmbH (largest Iranian VPS concentration)
    51167,   # Contabo GmbH
    8560,    # IONOS SE (1&1)
    3320,    # Deutsche Telekom AG
    680,     # DFN (German research network, often peered with Iranian unis)
    13184,   # Adolf Würth GmbH / AS used by several DE ISPs
    29066,   # Vodafone Germany
    # Netherlands — strong DE-CIX / AMS-IX peering into Iran
    16276,   # OVH SAS (FR/NL DCs)
    60781,   # LeaseWeb Netherlands
    20738,   # Serverius
    # France
    12876,   # SCALEWAY (formerly Online SAS)
    # General EU hosting with confirmed Iranian user base
    34119,   # Wildcard UK/EU hosting
    47583,   # Hostinger International
]

# Fallback IP prefixes for the European bridge ASNs above.
# Used when RIPE Stat API fails for these ASNs.
EUROPEAN_BRIDGE_PREFIXES: List[str] = [
    # Hetzner
    "5.9.0.0/16", "5.161.0.0/16", "23.88.0.0/17", "65.21.0.0/16",
    "65.108.0.0/16", "65.109.0.0/16", "78.46.0.0/15", "88.198.0.0/16",
    "95.216.0.0/16", "116.202.0.0/15", "128.140.0.0/17", "135.181.0.0/16",
    "136.243.0.0/16", "138.201.0.0/16", "142.132.0.0/15", "144.76.0.0/16",
    "148.251.0.0/16", "157.90.0.0/16", "159.69.0.0/16", "162.55.0.0/16",
    "167.233.0.0/16", "168.119.0.0/16", "176.9.0.0/16", "178.63.0.0/16",
    "188.34.0.0/16", "193.25.134.0/23", "195.201.0.0/16", "213.239.192.0/18",
    # Contabo
    "144.91.64.0/18", "173.212.192.0/18", "185.238.240.0/22",
    "194.163.128.0/17", "213.136.64.0/18",
    # OVH Germany/France
    "5.135.0.0/16", "51.68.0.0/16", "51.75.0.0/16", "51.77.0.0/16",
    "54.36.0.0/16", "87.98.128.0/17", "91.121.0.0/16", "137.74.0.0/16",
    "145.239.0.0/16", "149.202.0.0/16", "151.80.0.0/16", "188.165.0.0/16",
    "193.70.0.0/17",
]

# Known Iranian ASNs (seed list)
SEED_ASNS = [
    43754, 62229, 48159, 12880, 16322, 42337, 49666, 21341, 24631,
    56402, 31549, 44244, 197207, 58224, 39501, 57218, 25184, 51695, 47262,
    64422, 205585
]

# Iranian domains for DNS seeding (all confirmed self-hosted on Iranian infra)
SEED_DOMAINS = [
    "telewebion.ir", "farsnews.ir", "tasnimnews.ir", "sepehrtv.ir",
    "parsatv.com", "irna.ir", "isna.ir", "mehrnews.com", "iribnews.ir",
    "varzesh3.com", "namasha.com", "filimo.com", "aparat.com", "digikala.com",
    "snapp.ir", "irancell.ir", "mci.ir", "tic.ir",
    # Extra ISP/bank/ministry domains (reliably self-hosted)
    "shatel.ir", "rightel.com", "bmi.ir", "bankmellat.ir",
    "behdasht.gov.ir", "moe.gov.ir",
]

# Bogon prefixes to filter
BOGON_RANGES = [
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
    "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
    "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32"
]

# CDN anycast ranges — these IPs always have ports open but are NOT proxies.
# Cloudflare anycast in particular (173.245.48.0/20, 104.16.0.0/13, etc.)
# geo-locates to CA/US from North America and floods scan results with
# false positives that pass the TCP-open check but fail all geo verifications.
# Also filters Akamai, Fastly, and AWS CloudFront anycast blocks.
CDN_RANGES = [
    # Cloudflare
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
    # Fastly
    "23.235.32.0/20",
    "43.249.72.0/22",
    "103.244.50.0/24",
    "103.245.222.0/23",
    "103.245.224.0/24",
    "104.156.80.0/20",
    "151.101.0.0/16",
    "157.52.192.0/18",
    "167.82.0.0/17",
    "167.82.128.0/20",
    "167.82.160.0/20",
    "167.82.224.0/20",
    "199.27.72.0/21",
    # Akamai
    "23.32.0.0/11",
    "23.64.0.0/14",
    "23.192.0.0/11",
    "96.16.0.0/15",
    "96.6.0.0/15",
    "184.24.0.0/13",
    "184.50.0.0/15",
    "184.84.0.0/14",
]

# Build parsed CDN networks once at module load for fast lookup
_CDN_NETS = [ipaddress.IPv4Network(r, strict=False) for r in CDN_RANGES]

# Proxy ports to scan
PROXY_PORTS = [80, 443, 1080, 3128, 8080, 8088, 8118, 8888, 9999]

# Fallback prefixes if ASN DB is empty
FALLBACK_PREFIXES = [
    "5.160.0.0/12", "78.38.0.0/15", "151.232.0.0/13", "185.112.32.0/22",
    "185.141.104.0/22", "185.173.128.0/22", "185.236.172.0/22"
]

# Public proxy list sources
PROXY_SOURCES = [
    "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt",
    "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks4.txt",
    "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/all.txt",
    "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies.txt",
]

# Multi-target verification endpoints: (url, json_key, expected_value)
# A proxy must satisfy at least 2 of these 3 to be accepted.
VERIFICATION_TARGETS = [
    ("http://ip-api.com/json/?fields=status,countryCode", "countryCode", "IR"),
    ("http://ipwho.is/",                                  "country_code", "IR"),
    ("http://ipapi.co/json/",                             "country_code", "IR"),
]

# ---------- Helper functions ----------

def is_cdn_ip(ip_str: str) -> bool:
    """Return True if ip_str falls within any known CDN anycast range."""
    try:
        ip = ipaddress.IPv4Address(ip_str)
        return any(ip in net for net in _CDN_NETS)
    except Exception:
        return False

def is_cdn_prefix(prefix: str) -> bool:
    """Return True if prefix overlaps with any known CDN anycast range."""
    try:
        net = ipaddress.IPv4Network(prefix, strict=False)
        return any(net.overlaps(cdn) for cdn in _CDN_NETS)
    except Exception:
        return False

def is_bogon(ip_str: str) -> bool:
    try:
        ip = ipaddress.IPv4Address(ip_str)
        return (ip.is_private or ip.is_loopback or ip.is_link_local or
                ip.is_reserved or ip.is_multicast or is_cdn_ip(ip_str))
    except Exception:
        return True

def is_bogon_prefix(prefix: str) -> bool:
    try:
        net = ipaddress.IPv4Network(prefix, strict=False)
        for b in BOGON_RANGES:
            if net.subnet_of(ipaddress.IPv4Network(b, strict=False)):
                return True
        if is_cdn_prefix(prefix):
            return True
        return False
    except Exception:
        return True

def cidr_first_host(cidr: str) -> Optional[str]:
    try:
        net = ipaddress.IPv4Network(cidr, strict=False)
        if net.num_addresses < 2:
            return None
        return str(net.network_address + 1)
    except Exception:
        return None

def stratified_sample_ips(prefix: str, max_samples: int = 100) -> List[str]:
    """
    Sample IPs spread across the *entire* prefix range, not just the start.
    Divides the usable host space into equal buckets and picks one IP per bucket.
    """
    try:
        net = ipaddress.IPv4Network(prefix, strict=False)
        total = net.num_addresses
        if total <= 2:
            return []
        usable = total - 2  # exclude network + broadcast
        if usable <= max_samples:
            return [str(net.network_address + i + 1) for i in range(usable)]
        step = usable // max_samples
        return [str(net.network_address + 1 + i * step) for i in range(max_samples)]
    except Exception:
        return []

async def tcp_connect(ip: str, port: int, timeout: float = TCP_TIMEOUT) -> bool:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False

# ---------- Retry wrapper ----------

async def fetch_json_with_retry(url: str, session: aiohttp.ClientSession,
                                 max_retries: int = 4,
                                 timeout: int = 30,
                                 params: dict = None) -> Optional[dict]:
    """GET a JSON endpoint with exponential backoff on failure / rate-limit."""
    for attempt in range(max_retries):
        try:
            async with session.get(url, timeout=timeout, params=params) as resp:
                if resp.status == 429:
                    wait = 2 ** attempt + random.uniform(0, 1)
                    print(f"  Rate-limited by {url}, waiting {wait:.1f}s ...")
                    await asyncio.sleep(wait)
                    continue
                if resp.status != 200:
                    return None
                return await resp.json()
        except Exception as e:
            if attempt < max_retries - 1:
                wait = 2 ** attempt
                await asyncio.sleep(wait)
            else:
                print(f"  Failed to fetch {url} after {max_retries} attempts: {e}")
    return None

# ---------- RIPE Stat API ----------

async def fetch_ripe_prefixes(asn: int) -> Tuple[List[str], List[str]]:
    """
    Fetch announced IPv4 and IPv6 prefixes for an ASN from RIPE Stat.
    Returns (ipv4_prefixes, ipv6_prefixes).
    """
    url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"
    try:
        async with aiohttp.ClientSession() as session:
            data = await fetch_json_with_retry(url, session)
            if not data:
                return [], []
            prefixes = data.get("data", {}).get("prefixes", [])
            v4 = [p["prefix"] for p in prefixes if ":" not in p.get("prefix", "")]
            v6 = [p["prefix"] for p in prefixes if ":" in p.get("prefix", "")]
            return v4, v6
    except Exception:
        return [], []

async def fetch_asn_neighbours(asn: int) -> List[int]:
    """Fetch BGP neighbours for an ASN from RIPE Stat (with retry)."""
    url = f"https://stat.ripe.net/data/asn-neighbours/data.json?resource=AS{asn}"
    try:
        async with aiohttp.ClientSession() as session:
            data = await fetch_json_with_retry(url, session)
            if not data:
                return []
            neighbours = data.get("data", {}).get("neighbours", [])
            return [int(n.get("asn", n)) for n in neighbours if str(n.get("asn", n)).isdigit()]
    except Exception:
        return []

# ---------- RIPE NCC Delegated Stats (NEW) ----------

async def fetch_ripe_delegated() -> Tuple[List[int], List[str]]:
    """
    Parse the RIPE NCC delegated extended stats file to directly extract
    all Iranian ASNs and IPv4 prefixes. Much more complete than BGP-only.
    Returns (asn_list, ipv4_prefix_list).
    """
    url = "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest"
    asns: List[int] = []
    prefixes: List[str] = []
    print("Fetching RIPE NCC delegated stats file ...")
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=120) as resp:
                if resp.status != 200:
                    print(f"  RIPE delegated: HTTP {resp.status}")
                    return [], []
                text = await resp.text()
        for line in text.splitlines():
            if line.startswith("#") or line.startswith("2"):  # skip headers/summary
                continue
            parts = line.split("|")
            if len(parts) < 5:
                continue
            registry, country, rtype, start, value = parts[:5]
            if country != "IR":
                continue
            if rtype == "asn":
                try:
                    asns.append(int(start))
                except ValueError:
                    pass
            elif rtype == "ipv4":
                try:
                    count = int(value)
                    prefix_len = 32 - int(math.log2(count))
                    prefix = f"{start}/{prefix_len}"
                    if not is_bogon_prefix(prefix):
                        prefixes.append(prefix)
                except (ValueError, TypeError):
                    pass
        print(f"  RIPE delegated: {len(asns)} ASNs, {len(prefixes)} IPv4 prefixes for IR")
    except Exception as e:
        print(f"  RIPE delegated fetch error: {e}")
    return asns, prefixes

# ---------- Hurricane Electric BGP (NEW) ----------

async def fetch_he_asns() -> List[int]:
    """Scrape Hurricane Electric BGP toolkit for Iranian ASNs."""
    url = "https://bgp.he.net/country/IR"
    print("Fetching Hurricane Electric ASN list ...")
    try:
        headers = {"User-Agent": "Mozilla/5.0 (compatible; IranASNScanner/2.0)"}
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=30, headers=headers) as resp:
                if resp.status != 200:
                    print(f"  HE BGP: HTTP {resp.status}")
                    return []
                text = await resp.text()
        asns = list(set(int(a) for a in re.findall(r'/AS(\d+)', text)))
        print(f"  HE BGP: {len(asns)} ASNs")
        return asns
    except Exception as e:
        print(f"  HE BGP fetch error: {e}")
        return []

# ---------- Cloudflare Radar (NEW) ----------

async def fetch_cloudflare_radar_asns() -> List[int]:
    """Fetch Iranian ASNs from Cloudflare Radar (requires CLOUDFLARE_API_TOKEN)."""
    if not CLOUDFLARE_API_TOKEN:
        print("  Cloudflare Radar: CLOUDFLARE_API_TOKEN not set, skipping")
        return []
    print("Fetching Cloudflare Radar ASN list ...")
    url = "https://api.cloudflare.com/client/v4/radar/entities/asns"
    params = {"country": "IR", "limit": 500}
    headers = {"Authorization": f"Bearer {CLOUDFLARE_API_TOKEN}"}
    try:
        async with aiohttp.ClientSession(headers=headers) as session:
            data = await fetch_json_with_retry(url, session, params=params)
            if not data:
                return []
            asns = [int(e["asn"]) for e in data.get("result", {}).get("asns", [])]
            print(f"  Cloudflare Radar: {len(asns)} ASNs")
            return asns
    except Exception as e:
        print(f"  Cloudflare Radar fetch error: {e}")
        return []

# ---------- Shadowserver BGP (NEW) ----------

async def fetch_shadowserver_prefixes() -> List[str]:
    """
    Fetch Iranian IPv4 prefixes from Shadowserver's BGP summary.
    Uses their country-level BGP view (no auth required).
    """
    url = "https://bgp.shadowserver.org/country/IR/prefixes"
    print("Fetching Shadowserver BGP prefix list ...")
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=30) as resp:
                if resp.status != 200:
                    print(f"  Shadowserver: HTTP {resp.status}")
                    return []
                text = await resp.text()
        prefixes = []
        for line in text.splitlines():
            line = line.strip()
            if re.match(r'^\d+\.\d+\.\d+\.\d+/\d+$', line):
                if not is_bogon_prefix(line):
                    prefixes.append(line)
        print(f"  Shadowserver: {len(prefixes)} IPv4 prefixes")
        return prefixes
    except Exception as e:
        print(f"  Shadowserver fetch error: {e}")
        return []

# ---------- DNS + Cymru ----------

async def resolve_domain(domain: str) -> List[str]:
    try:
        return list(set(socket.gethostbyname_ex(domain)[2]))
    except Exception:
        return []

async def whois_cymru(ips: List[str]) -> Dict[str, dict]:
    """Query Team Cymru WHOIS for IPs. Returns dict ip -> info."""
    if not ips:
        return {}
    result = {}
    try:
        reader, writer = await asyncio.open_connection("whois.cymru.com", 43)
        writer.write(b"begin\n verbose\n" + b"\n".join(ip.encode() for ip in ips) + b"\nend\n")
        await writer.drain()
        data = await reader.read(102400)
        writer.close()
        await writer.wait_closed()
        for line in data.decode().strip().split('\n'):
            if '|' not in line or line.startswith('Bulk') or line.startswith('AS '):
                continue
            parts = [p.strip() for p in line.split('|')]
            if len(parts) >= 4:
                asn = int(parts[0]) if parts[0].isdigit() else None
                ip = parts[1]
                prefix = parts[2]
                country = parts[3]
                name = parts[6] if len(parts) >= 7 else ""
                result[ip] = {"asn": asn, "prefix": prefix, "country": country, "name": name}
    except Exception as e:
        print(f"WHOIS error: {e}")
    return result

async def discover_asns_via_dns() -> List[int]:
    print("Discovering ASNs via DNS resolution of seed domains ...")
    ips = set()
    for domain in SEED_DOMAINS:
        ips.update(await resolve_domain(domain))
    if not ips:
        return []
    whois = await whois_cymru(list(ips))
    asns = set()
    for ip, info in whois.items():
        if info.get("country") == "IR" and info.get("asn"):
            asns.add(info["asn"])
    print(f"  DNS discovery: {len(asns)} ASNs")
    return list(asns)

# ---------- BGP neighbour expansion (two-hop) ----------

async def expand_via_neighbours(seed_asns: List[int], min_shared: int = 2) -> List[int]:
    """First-hop: find ASNs that peer with >= min_shared seed ASNs."""
    peer_count: Counter = Counter()
    for asn in seed_asns:
        neighbours = await fetch_asn_neighbours(asn)
        for nb in neighbours:
            if nb not in seed_asns:
                peer_count[nb] += 1
    first_hop = [asn for asn, count in peer_count.items() if count >= min_shared]
    print(f"  First-hop neighbour expansion: {len(first_hop)} candidate ASNs")
    return first_hop

async def expand_two_hop(seed_asns: List[int], first_hop: List[int],
                          min_shared: int = 1) -> List[int]:
    """
    Second-hop: find ASNs that peer with >= min_shared first-hop ASNs
    and are not already known. Capped at 30 first-hop ASNs to limit API calls.
    """
    all_known = set(seed_asns) | set(first_hop)
    peer_count: Counter = Counter()
    for asn in first_hop[:30]:
        neighbours = await fetch_asn_neighbours(asn)
        for nb in neighbours:
            if nb not in all_known:
                peer_count[nb] += 1
    second_hop = [asn for asn, count in peer_count.items() if count >= min_shared]
    print(f"  Second-hop neighbour expansion: {len(second_hop)} additional candidate ASNs")
    return second_hop

# ---------- RIPE Atlas ----------

async def run_atlas(asns: List[int], api_key: str) -> dict:
    """Trigger RIPE Atlas traceroutes (unchanged from v1)."""
    print(f"Running RIPE Atlas measurements for {len(asns)} ASNs ...")
    results = {}
    async with aiohttp.ClientSession() as session:
        for asn in asns:
            prefixes = (await fetch_ripe_prefixes(asn))[0]
            if not prefixes:
                continue
            ip = cidr_first_host(prefixes[0])
            if not ip:
                continue
            payload = {
                "definitions": [{
                    "type": "traceroute",
                    "af": 4,
                    "target": ip,
                    "description": f"Iran ASN check AS{asn}",
                    "protocol": "TCP",
                    "port": 80,
                }],
                "probes": [{"type": "area", "value": "WW", "requested": 5}],
                "is_oneoff": True,
                "bill_to": "",
            }
            try:
                async with session.post(
                    "https://atlas.ripe.net/api/v2/measurements/",
                    json=payload,
                    headers={"Authorization": f"Key {api_key}"},
                    timeout=30
                ) as resp:
                    if resp.status in (200, 201):
                        data = await resp.json()
                        msm_ids = data.get("measurements", [])
                        results[f"AS{asn}"] = {
                            "asn": asn,
                            "target": ip,
                            "measurement_ids": msm_ids,
                            "routable": True,
                            "prefixes": prefixes,
                        }
            except Exception as e:
                print(f"  Atlas error for AS{asn}: {e}")
    return results

# ---------- Reverse lookup ----------

async def lookup_ipinfo(ip: str, token: str) -> dict:
    url = f"https://ipinfo.io/{ip}/json"
    params = {"token": token} if token else {}
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, params=params, timeout=10) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    org = data.get("org", "")
                    asn = None
                    asn_name = None
                    if org.startswith("AS"):
                        parts = org.split(" ", 1)
                        try:
                            asn = int(parts[0][2:])
                        except ValueError:
                            pass
                        asn_name = parts[1] if len(parts) > 1 else ""
                    return {
                        "asn": asn,
                        "asn_name": asn_name,
                        "country": data.get("country"),
                        "prefix": None,
                    }
    except Exception:
        pass
    return {"asn": None, "asn_name": None, "country": None, "prefix": None}

async def process_reverse_ip(ip: str, ipinfo_token: str) -> dict:
    info = await lookup_ipinfo(ip, ipinfo_token)
    if not info["asn"]:
        whois = await whois_cymru([ip])
        info = whois.get(ip, info)
    if info.get("country") == "IR" or info.get("country") is None:
        for port in PROXY_PORTS:
            if await tcp_connect(ip, port, timeout=3):
                info["tcp_ok"] = True
                info["tcp_port"] = port
                break
        else:
            info["tcp_ok"] = False
    else:
        info["tcp_ok"] = False
    info["ip"] = ip
    return info

async def run_reverse(ips: List[str], ipinfo_token: str) -> dict:
    tasks = [process_reverse_ip(ip, ipinfo_token) for ip in ips]
    results = await asyncio.gather(*tasks)
    asn_map: dict = {}
    for r in results:
        asn = r.get("asn")
        if asn and r.get("tcp_ok") and r.get("country") == "IR":
            asn_map.setdefault(asn, {
                "asn": asn,
                "name": r.get("asn_name"),
                "prefixes": [],
                "responsive_ips": [],
            })["responsive_ips"].append(r["ip"])
    return {"routable_asns": list(asn_map.values()), "all_records": results}

# ---------- Proxy scanning ----------

async def scan_prefix_with_masscan(prefix: str,
                                    per_prefix_timeout: int = 90) -> List[str]:
    """
    Use masscan at 5000 pps to scan an entire prefix for open proxy ports.

    FIX: Added per_prefix_timeout (default 90 s) so that a stalled masscan
    process cannot block the pipeline indefinitely.  90 s is enough for a full
    /16 at 5 000 pps with margin; anything larger / slower is skipped.
    """
    if not shutil.which("masscan"):
        return []
    ports = ",".join(str(p) for p in PROXY_PORTS)
    cmd = [
        "masscan", prefix,
        "-p", ports,
        "--rate=5000",        # raised from 1000
        "--open-only",
        "--banners",          # grab HTTP banners for early non-proxy filtering
        "-oJ", "-",
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        # FIX: wrap communicate() in wait_for so a hung masscan can't stall forever
        try:
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=per_prefix_timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            print(f"  Masscan timed out on {prefix} after {per_prefix_timeout}s, skipping")
            return []
        if proc.returncode != 0 or not stdout.strip():
            return []
        data = json.loads(stdout)
        results = []
        for host in data:
            ip = host.get("ip")
            for port_info in host.get("ports", []):
                results.append(f"{ip}:{port_info['port']}")
        return results
    except Exception as e:
        print(f"  Masscan error on {prefix}: {e}")
        return []

async def scan_prefix_async(prefix: str) -> List[str]:
    """
    Async TCP scanning using stratified sampling across the full prefix.
    Replaces the old fixed-offset approach that only covered the first 250 IPs.
    """
    sample_ips = stratified_sample_ips(prefix, max_samples=100)
    candidates = []
    tasks = []
    ip_port_map = []
    for ip in sample_ips:
        if is_bogon(ip):
            continue
        for port in PROXY_PORTS:
            tasks.append(tcp_connect(ip, port, timeout=TCP_TIMEOUT))
            ip_port_map.append((ip, port))
    if not tasks:
        return []
    results = await asyncio.gather(*tasks)
    for (ip, port), ok in zip(ip_port_map, results):
        if ok:
            candidates.append(f"{ip}:{port}")
    return candidates

async def check_bale_reachable(proxy_url: str,
                               timeout: float = BALE_TCP_TIMEOUT) -> bool:
    """
    Probe Bale messaging infrastructure through a proxy.

    Uses aiohttp with the proxy URL to make an HTTP HEAD request to each
    Bale endpoint.  A response of any kind (including 4xx/5xx) confirms
    that the proxy can route packets to Iranian-hosted infrastructure.

    Why this works as a geo-routing signal:
      - Bale.ai is hosted on Iranian infrastructure and reachable from the EU
        (confirmed: Germany) but blocked from North American IP ranges.
      - GitHub Actions runners use Azure IPs (North America) which cannot
        reach Bale, so if a proxy passes this check it genuinely has a
        routing path unavailable to the runner itself.
    """
    for host, port in BALE_TEST_ENDPOINTS:
        url = f"http{'s' if port == 443 else ''}://{host}/"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.head(
                    url,
                    proxy=proxy_url,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    allow_redirects=True,
                    ssl=False,
                ) as resp:
                    # 407 = proxy auth required: proxy blocked before reaching Bale
                    if resp.status < 600 and resp.status != 407:
                        return True
        except aiohttp.ClientResponseError as e:
            if e.status != 407:
                return True   # non-407 error from destination = still routable
        except Exception:
            continue
    return False


async def verify_proxy_http(proxy: str, timeout: int = HTTP_TIMEOUT) -> Optional[dict]:
    """
    Verify proxy by checking 2-of-3 geolocation sources.
    Prevents false positives from accidental open ports on non-proxy services.
    CDN anycast IPs (Cloudflare, Fastly, Akamai) are rejected immediately —
    they always have ports open but are not proxies.
    """
    ip, port_str = proxy.rsplit(":", 1)
    port = int(port_str)

    # Reject CDN anycast IPs early — they flood results with false positives
    if is_cdn_ip(ip):
        return None

    proxy_url = f"http://{ip}:{port}"

    # Randomise target order per proxy so concurrent workers don't all hammer
    # ip-api.com first — it has a 45 req/min free-tier rate limit.
    targets = list(VERIFICATION_TARGETS)
    random.shuffle(targets)

    async def check_target(session: aiohttp.ClientSession,
                            url: str, key: str, expected: str) -> bool:
        try:
            async with session.get(url, proxy=proxy_url, timeout=timeout) as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    return data.get(key) == expected
        except Exception:
            pass
        return False

    # --- HTTP proxy ---
    confirmed = 0
    async with aiohttp.ClientSession() as session:
        checks = await asyncio.gather(*[
            check_target(session, url, key, expected)
            for url, key, expected in targets
        ])
    confirmed = sum(checks)
    if confirmed >= 2:
        return {
            "proxy": proxy,
            "working": True,
            "exit_verified": True,
            "protocol": "http",
            "latency": None,
            "country": "IR",
            "geo_score": confirmed,
        }

    # --- SOCKS5 fallback ---
    try:
        import aiohttp_socks
        conn = aiohttp_socks.ProxyConnector.from_url(f"socks5://{ip}:{port}")
        async with aiohttp.ClientSession(connector=conn) as session:
            socks_checks = await asyncio.gather(*[
                check_target(session, url, key, expected)
                for url, key, expected in targets
            ])
        socks_confirmed = sum(socks_checks)
        if socks_confirmed >= 2:
            return {
                "proxy": proxy,
                "working": True,
                "exit_verified": True,
                "protocol": "socks5",
                "latency": None,
                "country": "IR",
                "geo_score": socks_confirmed,
            }
    except Exception:
        pass

    # --- SOCKS4 fallback ---
    # Some Iranian proxies advertise only SOCKS4 (no auth, IPv4 only).
    try:
        import aiohttp_socks
        conn4 = aiohttp_socks.ProxyConnector.from_url(f"socks4://{ip}:{port}")
        async with aiohttp.ClientSession(connector=conn4) as session:
            socks4_checks = await asyncio.gather(*[
                check_target(session, url, key, expected)
                for url, key, expected in targets
            ])
        socks4_confirmed = sum(socks4_checks)
        if socks4_confirmed >= 2:
            return {
                "proxy": proxy,
                "working": True,
                "exit_verified": True,
                "protocol": "socks4",
                "latency": None,
                "country": "IR",
                "geo_score": socks4_confirmed,
            }
    except Exception:
        pass

    # --- Tier 2: EU→IR bridge — exit geo ≠ IR but Bale is reachable -----------
    # A proxy with a European exit that can reach bale.ai has a routing path
    # into Iranian infrastructure that North American (Azure/GitHub) IPs lack.
    # We accept these as bridge proxies rather than discarding them.
    bale_ok = await check_bale_reachable(proxy_url)
    if bale_ok:
        # Try to determine the actual exit country from whichever geo check passed.
        exit_country = "EU"   # default label
        for url, key, _ in VERIFICATION_TARGETS:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, proxy=proxy_url, timeout=timeout) as resp:
                        if resp.status == 200:
                            data = await resp.json(content_type=None)
                            cc = data.get(key, "")
                            if cc and cc != "IR":
                                exit_country = cc
                                break
            except Exception:
                continue
        return {
            "proxy":          proxy,
            "working":        True,
            "exit_verified":  False,          # exit not in IR
            "protocol":       "http",
            "latency":        None,
            "country":        exit_country,   # actual exit country (DE, NL, etc.)
            "geo_score":      confirmed,
            "iran_reachable": True,           # confirmed via Bale probe
            "bridge_type":    "EU→IR",
        }

    return None

async def scrape_public_proxies() -> List[str]:
    """Scrape public proxy lists for additional candidates."""
    candidates: set = set()
    async with aiohttp.ClientSession() as session:
        for url in PROXY_SOURCES:
            try:
                async with session.get(url, timeout=15) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        found = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}\b', text)
                        candidates.update(found)
            except Exception:
                continue
    return list(candidates)

async def fetch_european_bridge_prefixes() -> List[str]:
    """
    Fetch announced prefixes for known European bridge ASNs from RIPE Stat.
    Falls back to EUROPEAN_BRIDGE_PREFIXES if the API is unavailable.
    These prefixes contain servers operated by Iranian users/providers that
    have routing paths into Iranian infrastructure via DE-CIX / AMS-IX peering.

    FIX: Result set is capped to the 40 most-specific (highest prefix-length)
    prefixes so that the scan phase cannot balloon to hundreds of large /16s.
    Smaller prefixes (/22, /23, /24) finish masscan in seconds and host the
    highest density of Iranian-operated VPS servers.
    """
    EU_PREFIX_CAP = int(os.environ.get("EU_PREFIX_CAP", "40"))
    print("Fetching European bridge ASN prefixes ...")
    all_prefixes: List[str] = []
    sem = asyncio.Semaphore(10)

    async def fetch_one(asn: int) -> List[str]:
        async with sem:
            v4, _ = await fetch_ripe_prefixes(asn)
            return [p for p in v4 if not is_bogon_prefix(p)]

    results = await asyncio.gather(*[fetch_one(asn) for asn in EUROPEAN_BRIDGE_ASNS])
    for r in results:
        all_prefixes.extend(r)

    all_prefixes = list(set(all_prefixes))
    if not all_prefixes:
        print("  European bridge: RIPE Stat unavailable, using fallback prefixes")
        all_prefixes = EUROPEAN_BRIDGE_PREFIXES
    else:
        # Always include the hardcoded fallbacks — they're high-signal
        all_prefixes = list(set(all_prefixes + EUROPEAN_BRIDGE_PREFIXES))

    # FIX: Cap to EU_PREFIX_CAP most-specific prefixes to bound scan time.
    # Sort descending by prefix length (e.g. /24 > /22 > /16).
    try:
        all_prefixes = sorted(
            all_prefixes,
            key=lambda p: ipaddress.IPv4Network(p, strict=False).prefixlen,
            reverse=True,
        )[:EU_PREFIX_CAP]
    except Exception:
        all_prefixes = all_prefixes[:EU_PREFIX_CAP]

    print(f"  European bridge: {len(all_prefixes)} prefixes to scan (cap={EU_PREFIX_CAP})")
    return all_prefixes


async def run_proxy_scanner(asn_db: dict, use_masscan: bool = False,
                             europe_bridge: bool = False) -> List[dict]:
    """Main proxy scanning routine."""
    all_candidates: List[str] = []

    # Gather prefixes from ASN DB
    prefixes: List[str] = []
    for asn, entry in asn_db.items():
        if entry.get("confidence", 1) < MIN_CONFIDENCE:
            continue
        prefixes.extend(entry.get("prefixes", []))
    if not prefixes:
        print("No prefixes found in ASN DB, using fallback prefixes")
        prefixes = FALLBACK_PREFIXES
    prefixes = list(set(prefixes))
    print(f"Scanning {len(prefixes)} Iranian prefixes for open proxy ports ...")

    # Optionally extend with European bridge prefixes
    eu_prefixes: List[str] = []
    if europe_bridge:
        eu_prefixes = await fetch_european_bridge_prefixes()
        all_scan_prefixes = list(set(prefixes + eu_prefixes))
        print(f"Total prefixes to scan (IR + EU bridge): {len(all_scan_prefixes)}")
    else:
        all_scan_prefixes = prefixes

    if use_masscan and shutil.which("masscan"):
        # FIX: Run masscan concurrently across prefixes (was a blocking serial loop).
        # Semaphore of 6 limits concurrent processes to avoid exhausting RAM/sockets
        # while still achieving ~6× speedup over the original sequential approach.
        mscan_sem = asyncio.Semaphore(int(os.environ.get("MASSCAN_PARALLEL", "6")))

        async def _masscan_one(pfx: str) -> List[str]:
            async with mscan_sem:
                return await scan_prefix_with_masscan(pfx)

        # FIX: For EU bridge prefixes we use async TCP sampling instead of masscan.
        # Masscan on hundreds of large Hetzner/OVH /16s is the primary time sink.
        # Async TCP sampling with stratified coverage is faster and sufficient
        # for finding Iranian-operated VPS servers within those ranges.
        if eu_prefixes:
            ir_mscan_tasks  = [_masscan_one(p) for p in prefixes]
            eu_sample_tasks = [scan_prefix_async(p) for p in eu_prefixes]
            print(f"  Masscan on {len(prefixes)} IR prefixes | "
                  f"async-TCP sampling {len(eu_prefixes)} EU bridge prefixes ...")
            ir_results, eu_results = await asyncio.gather(
                asyncio.gather(*ir_mscan_tasks),
                asyncio.gather(*eu_sample_tasks),
            )
            for res in ir_results:
                all_candidates.extend(res)
            for res in eu_results:
                all_candidates.extend(res)
        else:
            nested = await asyncio.gather(*[_masscan_one(p) for p in all_scan_prefixes])
            for res in nested:
                all_candidates.extend(res)
    else:
        tasks = [scan_prefix_async(pfx) for pfx in all_scan_prefixes]
        for res in await asyncio.gather(*tasks):
            all_candidates.extend(res)

    all_candidates = list(set(all_candidates))
    print(f"Found {len(all_candidates)} candidate proxy endpoints from prefix scan.")

    # Add public proxy candidates
    public_candidates = await scrape_public_proxies()
    print(f"Found {len(public_candidates)} public proxy candidates.")
    all_candidates = list(set(all_candidates + public_candidates))

    # FIX: Semaphore raised from 50 → 100 and HTTP_TIMEOUT lowered from 10 → 7 s
    # so the verification phase drains faster and stays within the job budget.
    verified: List[dict] = []
    sem = asyncio.Semaphore(100)

    async def verify_one(proxy: str):
        async with sem:
            return await verify_proxy_http(proxy)

    results = await asyncio.gather(*[verify_one(p) for p in all_candidates])
    verified = [r for r in results if r]
    print(f"Verified {len(verified)} working Iranian proxies.")
    return verified

# ---------- Merging ----------

def merge_results(atlas: dict, bgp: list, reverse: dict) -> dict:
    entries: dict = {}

    def add(asn: int, name: str, source: str, prefixes: list,
            prefixes_v6: list = None, confidence_boost: int = 1):
        key = f"AS{asn}"
        if key not in entries:
            entries[key] = {
                "asn": asn,
                "name": name or "",
                "confidence": 0,
                "sources": [],
                "prefixes": [],
                "prefixes_v6": [],
            }
        entries[key]["confidence"] += confidence_boost
        if source not in entries[key]["sources"]:
            entries[key]["sources"].append(source)
        entries[key]["prefixes"] = list(set(entries[key]["prefixes"] + prefixes))
        if prefixes_v6:
            entries[key]["prefixes_v6"] = list(set(entries[key]["prefixes_v6"] + prefixes_v6))
        if name and not entries[key]["name"]:
            entries[key]["name"] = name

    if atlas:
        for _, info in atlas.items():
            if info.get("routable"):
                add(info["asn"], None, "atlas", info.get("prefixes", []))

    if bgp:
        for asn_info in bgp:
            if asn_info.get("routable"):
                add(asn_info["asn"], None, "bgp",
                    asn_info.get("routable_prefixes", []),
                    asn_info.get("routable_prefixes_v6", []))

    if reverse and reverse.get("routable_asns"):
        for asn_info in reverse["routable_asns"]:
            add(asn_info["asn"], asn_info.get("name"), "reverse",
                asn_info.get("prefixes", []))

    for val in entries.values():
        conf = val["confidence"]
        val["confidence_label"] = (
            "very_high" if conf >= 3 else "high" if conf == 2 else "possible"
        )

    return entries

def print_summary(merged: dict):
    print("\n=== Merged Results ===")
    for conf in [3, 2, 1]:
        label = {3: "VERY HIGH", 2: "HIGH", 1: "POSSIBLE"}[conf]
        filtered = {k: v for k, v in merged.items() if v["confidence"] == conf}
        if filtered:
            print(f"\nConfidence {conf}/3 — {label} ({len(filtered)} ASNs)")
            for asn, val in filtered.items():
                v6_count = len(val.get("prefixes_v6", []))
                v6_str = f"  {v6_count} IPv6" if v6_count else ""
                print(f"  {asn:10} [{'+'.join(val['sources'])}] "
                      f"{len(val['prefixes'])} IPv4 prefixes{v6_str}")
    print(f"\nTotal: {len(merged)} unique routable Iranian ASNs identified.")

# ---------- Armenia-bridge ingestion ----------

def _parse_v2ray_uri_to_proxy_record(uri: str) -> Optional[dict]:
    """
    Extract a minimal proxy record from a V2Ray URI string
    (VMess/VLESS/SS/Trojan/Hysteria2).  Returns None if unparseable.
    """
    import base64 as _b64
    uri = uri.strip()
    scheme = uri.split("://")[0].lower()
    try:
        if scheme == "vmess":
            raw = uri[8:]
            raw += "=" * (-len(raw) % 4)
            obj  = json.loads(_b64.b64decode(raw).decode("utf-8", errors="ignore"))
            host = str(obj.get("add", "") or obj.get("host", ""))
            port = int(obj.get("port", 0))
        elif scheme in ("vless", "trojan", "tuic"):
            body = uri.split("://", 1)[1]
            after = body.split("@", 1)[1] if "@" in body else body
            after = after.split("#")[0].split("?")[0]
            if after.startswith("["):
                host = after.split("]")[0][1:]
                port = int(after.split("]:")[1]) if "]:" in after else 443
            else:
                host, port = after.rsplit(":", 1)
                port = int(port)
        elif scheme == "ss":
            body = uri[5:].split("#")[0].split("?")[0]
            if "@" in body:
                hp = body.rsplit("@", 1)[1]
            else:
                raw = body + "=" * (-len(body) % 4)
                decoded = _b64.b64decode(raw).decode("utf-8", errors="ignore")
                hp = decoded.rsplit("@", 1)[1] if "@" in decoded else ""
            host, port = hp.rsplit(":", 1)
            port = int(port)
        elif scheme in ("hysteria2", "hy2"):
            body = uri.split("://", 1)[1]
            after = body.split("@", 1)[1] if "@" in body else body
            after = after.split("#")[0].split("?")[0]
            host, port = after.rsplit(":", 1)
            port = int(port)
        else:
            return None
        if not host or not (1 <= port <= 65535):
            return None
        return {
            "proxy":         f"{host}:{port}",
            "working":       True,
            "exit_verified": False,
            "protocol":      scheme,
            "latency":       None,
            "country":       "AM",
            "iran_bridge":   True,
            "geo_score":     0,
            "config_uri":    uri,
        }
    except Exception:
        return None


def _load_proxies_from_txt(path: str, source_label: str) -> List[dict]:
    """
    Read a plain-text file of IP:port proxies (one per line, # comments OK).
    Each entry becomes a minimal proxy record tagged as an Armenia bridge.
    """
    results: List[dict] = []
    try:
        with open(path) as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                # Lines can be:
                #   ip:port
                #   PROTOCOL   ip:port   999ms        (check_proxies_armenia format)
                parts = line.split()
                # Find the token matching ip:port
                ip_port = None
                for token in parts:
                    m = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})$", token)
                    if m:
                        ip_port = token
                        break
                if not ip_port:
                    continue
                proto_tok = parts[0].lower() if len(parts) > 1 else "http"
                proto = proto_tok if proto_tok in ("http", "socks4", "socks5") else "http"
                results.append({
                    "proxy":         ip_port,
                    "working":       True,
                    "exit_verified": False,
                    "protocol":      proto,
                    "latency":       None,
                    "country":       "AM",
                    "iran_bridge":   True,
                    "geo_score":     0,
                    "source":        source_label,
                })
        print(f"  Armenia-bridge [{source_label}]: {len(results)} proxies from {path}")
    except Exception as e:
        print(f"  Armenia-bridge [{source_label}]: could not read {path}: {e}")
    return results


def _load_v2ray_uris_from_txt(path: str, source_label: str) -> List[dict]:
    """
    Read a plain-text file of V2Ray URIs (one per line, # comments OK).
    Returns parsed proxy records.
    """
    results: List[dict] = []
    try:
        with open(path) as f:
            lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        for uri in lines:
            rec = _parse_v2ray_uri_to_proxy_record(uri)
            if rec:
                rec["source"] = source_label
                results.append(rec)
        print(f"  Armenia-bridge [{source_label}]: {len(results)} V2Ray configs from {path}")
    except Exception as e:
        print(f"  Armenia-bridge [{source_label}]: could not read {path}: {e}")
    return results


def load_armenia_bridge_proxies() -> List[dict]:
    """
    Load working Armenian proxies / V2Ray configs from the committed output
    files of the two external repos:

      armenia-proxy-checker   → working_armenia_proxies.txt / .json
                                 armenia_iran_bridge_proxies.txt / .json
      armenia_v2ray_checker   → working_armenia_configs.txt / .json
                                 armenia_iran_bridge_configs.txt / .json

    Paths are resolved via environment variables so the caller can point at
    any directory layout (local checkout, CI workspace subdir, etc.):

      ARMENIA_PROXY_DIR   – root of the armenia-proxy-checker checkout
                            default: "armenia-proxy-checker"
      ARMENIA_V2RAY_DIR   – root of the armenia_v2ray_checker checkout
                            default: "armenia_v2ray_checker"

    When a *_bridge_* file is present it is preferred (already filtered to
    entries that passed the Iran-bridge test).  When it is absent the plain
    working_* file is used and ALL entries are treated as potential bridges
    (appropriate when running on GitHub-hosted runners where the bridge test
    cannot be performed directly).

    Returns a deduplicated list of proxy dicts compatible with the
    working_iran_proxies output format.
    """
    proxy_dir  = os.environ.get("ARMENIA_PROXY_DIR",  "armenia-proxy-checker")
    v2ray_dir  = os.environ.get("ARMENIA_V2RAY_DIR",  "armenia_v2ray_checker")

    results:   List[dict] = []
    seen_keys: set        = set()   # deduplicate on (proxy, protocol)

    def dedup_add(records: List[dict]) -> None:
        for r in records:
            key = (r["proxy"], r.get("protocol", ""))
            if key not in seen_keys:
                seen_keys.add(key)
                results.append(r)

    # ── armenia-proxy-checker outputs ──────────────────────────────────────
    # Prefer the bridge-specific file; fall back to the full working list.
    bridge_proxy_json = os.path.join(proxy_dir, "armenia_iran_bridge_proxies.json")
    bridge_proxy_txt  = os.path.join(proxy_dir, "armenia_iran_bridge_proxies.txt")
    working_proxy_json = os.path.join(proxy_dir, "working_armenia_proxies.json")
    working_proxy_txt  = os.path.join(proxy_dir, "working_armenia_proxies.txt")

    loaded_proxy = False
    for (jpath, tpath, label) in [
        (bridge_proxy_json,  bridge_proxy_txt,  "am-proxy-checker/bridge"),
        (working_proxy_json, working_proxy_txt, "am-proxy-checker/working"),
    ]:
        if loaded_proxy:
            break
        if os.path.exists(jpath):
            try:
                with open(jpath) as f:
                    data = json.load(f)
                # The JSON can have a "proxies" key (bridge format)
                # or a "verified" key (full working format).
                entries = data.get("proxies") or data.get("verified") or []
                recs: List[dict] = []
                for p in entries:
                    proxy_str = p.get("proxy", "")
                    if not proxy_str:
                        continue
                    recs.append({
                        "proxy":         proxy_str,
                        "working":       True,
                        "exit_verified": False,
                        "protocol":      p.get("protocol", "http").lower(),
                        "latency":       p.get("latency_ms"),
                        "country":       "AM",
                        "iran_bridge":   p.get("iran_bridge", True),
                        "geo_score":     0,
                        "source":        label,
                    })
                if recs:
                    dedup_add(recs)
                    print(f"  Armenia-bridge [{label}]: {len(recs)} proxies from {jpath}")
                    loaded_proxy = True
                    continue
            except Exception as e:
                print(f"  Armenia-bridge [{label}]: JSON error ({jpath}): {e}")
        if os.path.exists(tpath):
            recs = _load_proxies_from_txt(tpath, label)
            if recs:
                dedup_add(recs)
                loaded_proxy = True

    if not loaded_proxy:
        print(f"  Armenia-bridge: no proxy files found under '{proxy_dir}'")

    # ── armenia_v2ray_checker outputs ──────────────────────────────────────
    bridge_cfg_json  = os.path.join(v2ray_dir, "armenia_iran_bridge_configs.json")
    bridge_cfg_txt   = os.path.join(v2ray_dir, "armenia_iran_bridge_configs.txt")
    working_cfg_json = os.path.join(v2ray_dir, "working_armenia_configs.json")
    working_cfg_txt  = os.path.join(v2ray_dir, "working_armenia_configs.txt")

    loaded_cfg = False
    for (jpath, tpath, label) in [
        (bridge_cfg_json,  bridge_cfg_txt,  "am-v2ray-checker/bridge"),
        (working_cfg_json, working_cfg_txt, "am-v2ray-checker/working"),
    ]:
        if loaded_cfg:
            break
        if os.path.exists(jpath):
            try:
                with open(jpath) as f:
                    data = json.load(f)
                # Both bridge and working JSON have a "configs" key with uri field
                entries = data.get("configs") or data.get("outbounds") or []
                recs = []
                for entry in entries:
                    uri = entry.get("uri") or entry.get("config_uri", "")
                    if uri:
                        rec = _parse_v2ray_uri_to_proxy_record(uri)
                        if rec:
                            rec["source"] = label
                            recs.append(rec)
                    else:
                        # Hiddify outbound format: server + server_port
                        srv  = entry.get("server", "")
                        port = entry.get("server_port", 0)
                        if srv and port:
                            recs.append({
                                "proxy":         f"{srv}:{port}",
                                "working":       True,
                                "exit_verified": False,
                                "protocol":      entry.get("type", "unknown"),
                                "latency":       entry.get("latency_ms"),
                                "country":       "AM",
                                "iran_bridge":   True,
                                "geo_score":     0,
                                "source":        label,
                            })
                if recs:
                    dedup_add(recs)
                    print(f"  Armenia-bridge [{label}]: {len(recs)} configs from {jpath}")
                    loaded_cfg = True
                    continue
            except Exception as e:
                print(f"  Armenia-bridge [{label}]: JSON error ({jpath}): {e}")
        if os.path.exists(tpath):
            recs = _load_v2ray_uris_from_txt(tpath, label)
            if recs:
                dedup_add(recs)
                loaded_cfg = True

    if not loaded_cfg:
        print(f"  Armenia-bridge: no V2Ray config files found under '{v2ray_dir}'")

    print(f"  Armenia-bridge: {len(results)} total unique bridge entries loaded.")
    return results


# ---------- Main orchestration ----------

async def main():
    parser = argparse.ArgumentParser(description="Iran Network Scanner v2")
    parser.add_argument("--candidates",       help="File of IPs for reverse lookup")
    parser.add_argument("--bgp-only",         action="store_true")
    parser.add_argument("--atlas-only",       action="store_true")
    parser.add_argument("--reverse-only",     action="store_true")
    parser.add_argument("--proxy-only",       action="store_true")
    parser.add_argument("--armenia-bridge",   action="store_true",
                        help="Ingest Armenia-bridge proxies/configs and merge "
                             "them into the working proxy output")
    parser.add_argument("--europe-bridge",    action="store_true",
                        help="Also scan European hosting ASNs (Hetzner/Contabo/OVH) "
                             "and verify proxies via Bale reachability (EU→IR bridges)")
    parser.add_argument("--use-masscan",      action="store_true",
                        help="Use masscan for faster port scanning")
    parser.add_argument("--output",           default="merged_routable_asns.json")
    parser.add_argument("--save-intermediates", action="store_true")
    args = parser.parse_args()

    atlas_res = bgp_res = reverse_res = proxy_res = armenia_bridge_res = None

    if not args.reverse_only and not args.proxy_only:
        # ── Phase 1: collect ASNs from all sources ──────────────────────────

        # 1a. Seed + DNS
        dns_asns = await discover_asns_via_dns()
        working_asns = set(SEED_ASNS) | set(dns_asns)

        # 1b. RIPE NCC delegated stats (direct, comprehensive)
        delegated_asns, delegated_prefixes = await fetch_ripe_delegated()
        working_asns.update(delegated_asns)

        # 1c. Hurricane Electric
        he_asns = await fetch_he_asns()
        working_asns.update(he_asns)

        # 1d. Cloudflare Radar
        cf_asns = await fetch_cloudflare_radar_asns()
        working_asns.update(cf_asns)

        # 1e. Shadowserver direct prefixes (stored for scanning)
        shadowserver_prefixes = await fetch_shadowserver_prefixes()

        # 1f. BGP neighbour expansion (two-hop)
        first_hop = await expand_via_neighbours(list(SEED_ASNS), min_shared=2)
        working_asns.update(first_hop)
        # second_hop = await expand_two_hop(list(SEED_ASNS), first_hop, min_shared=1)
        # working_asns.update(second_hop)

        print(f"\nTotal candidate ASNs before prefix fetch: {len(working_asns)}")

        # ── Phase 2: fetch prefixes concurrently ──
        sem = asyncio.Semaphore(20)  # max 20 parallel RIPE Stat requests

        async def fetch_one(asn):
            async with sem:
                v4, v6 = await fetch_ripe_prefixes(asn)
                routable_v4 = [p for p in v4 if not is_bogon_prefix(p)]
                return {
                    "asn": asn,
                    "routable": len(routable_v4) > 0,
                    "routable_prefixes": routable_v4,
                    "routable_prefixes_v6": v6,
                    "all_prefixes": v4,
                    "is_seed": asn in SEED_ASNS,
                    "dns_confirmed": asn in dns_asns,
                    "delegated_confirmed": asn in delegated_asns,
                    "he_confirmed": asn in he_asns,
                    "cf_confirmed": asn in cf_asns,
                }

        print(f"Fetching prefixes for {len(working_asns)} ASNs (parallel) ...")
        bgp_list = await asyncio.gather(*[fetch_one(asn) for asn in working_asns])
        bgp_list = list(bgp_list)
        # Inject Shadowserver prefixes as a synthetic "extra" entry
        if shadowserver_prefixes:
            bgp_list.append({
                "asn": 0,  # sentinel for direct prefixes
                "routable": True,
                "routable_prefixes": shadowserver_prefixes,
                "routable_prefixes_v6": [],
                "all_prefixes": shadowserver_prefixes,
                "is_seed": False,
                "dns_confirmed": False,
                "delegated_confirmed": False,
                "he_confirmed": False,
                "cf_confirmed": False,
                "source_note": "shadowserver_direct",
            })

        bgp_res = bgp_list

        # ── Phase 3: optional Atlas ─────────────────────────────────────────
        if not args.bgp_only and not args.reverse_only and not args.proxy_only:
            if RIPE_ATLAS_API_KEY:
                atlas_res = await run_atlas(list(working_asns)[:20], RIPE_ATLAS_API_KEY)
            else:
                print("RIPE_ATLAS_API_KEY not set, skipping Atlas")

    # ── Reverse lookup ──────────────────────────────────────────────────────
    if args.reverse_only and args.candidates:
        with open(args.candidates) as f:
            ips = [line.strip() for line in f if line.strip()]
        reverse_res = await run_reverse(ips, IPINFO_TOKEN)

    # ── Proxy scan ──────────────────────────────────────────────────────────
    if args.proxy_only:
        asn_db: dict = {}
        if bgp_res:
            for entry in bgp_res:
                if entry["routable"] and entry["asn"] != 0:
                    asn_db[f"AS{entry['asn']}"] = {
                        "asn": entry["asn"],
                        "prefixes": entry["routable_prefixes"],
                        "confidence": 1,
                    }
        else:
            try:
                with open(args.output) as f:
                    asn_db = json.load(f)
            except Exception:
                asn_db = {}

        # FIX: Hard 50-minute wall-clock cap so the job always has time to
        # commit results even if the scan hasn't fully finished.  The GitHub
        # Actions timeout is 60 min; 50 min leaves 10 min for git push + cleanup.
        PROXY_SCAN_TIMEOUT = int(os.environ.get("PROXY_SCAN_TIMEOUT_SECS", str(50 * 60)))
        try:
            proxy_res = await asyncio.wait_for(
                run_proxy_scanner(asn_db, use_masscan=args.use_masscan,
                                  europe_bridge=args.europe_bridge),
                timeout=PROXY_SCAN_TIMEOUT,
            )
        except asyncio.TimeoutError:
            print(f"WARNING: proxy scan hit {PROXY_SCAN_TIMEOUT // 60}-minute "
                  f"wall-clock limit — saving partial results and continuing.")
            proxy_res = []

    # ── Armenia-bridge ingestion ────────────────────────────────────────────
    if args.armenia_bridge:
        print("\nIngesting Armenia→Iran bridge proxies ...")
        armenia_bridge_res = load_armenia_bridge_proxies()

    # ── Merge & save ────────────────────────────────────────────────────────
    merged = merge_results(atlas_res, bgp_res, reverse_res)

    with open(args.output, "w") as f:
        json.dump(merged, f, indent=2)

    if proxy_res:
        # Merge Armenia-bridge entries into the proxy output
        if armenia_bridge_res:
            existing = {p["proxy"] for p in proxy_res}
            new_bridges = [b for b in armenia_bridge_res if b["proxy"] not in existing]
            proxy_res = proxy_res + new_bridges
            print(f"Added {len(new_bridges)} Armenia-bridge proxies to output "
                  f"({len(proxy_res)} total).")

        # Split into Iranian-exit and EU→IR bridge proxies for separate outputs
        ir_proxies  = [p for p in proxy_res if p.get("country") == "IR"]
        eu_bridges  = [p for p in proxy_res
                       if p.get("bridge_type") == "EU→IR" or
                          (p.get("iran_reachable") and p.get("country") != "IR")]
        am_bridges  = [p for p in proxy_res if p.get("iran_bridge") and
                       p.get("country") == "AM"]
        all_usable  = proxy_res   # everything — IR exits + all bridge types

        print(f"Output breakdown: {len(ir_proxies)} IR-exit | "
              f"{len(eu_bridges)} EU→IR bridges | "
              f"{len(am_bridges)} AM→IR bridges")

        with open("working_iran_proxies.txt", "w") as f:
            for p in all_usable:
                f.write(p["proxy"] + "\n")

        # Stamp every proxy entry with the UTC verification time so downstream
        # tools (e.g. the R tester) can warn when proxies are stale.
        scan_ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        for p in all_usable:
            p.setdefault("scan_timestamp", scan_ts)

        with open("working_iran_proxies.json", "w") as f:
            json.dump(all_usable, f, indent=2)

        # Separate file for EU bridge proxies (useful for Hiddify / Xray configs)
        if eu_bridges:
            with open("eu_iran_bridge_proxies.txt", "w") as f:
                for p in eu_bridges:
                    tag = f"  # {p.get('country','EU')} → IR via Bale-verified route"
                    f.write(p["proxy"] + tag + "\n")
            with open("eu_iran_bridge_proxies.json", "w") as f:
                json.dump(eu_bridges, f, indent=2)
            print(f"Saved {len(eu_bridges)} EU→IR bridge proxies to "
                  f"eu_iran_bridge_proxies.txt / .json")

        # Hiddify outbound config — prefer IR-exit proxies, pad with bridges
        hiddify_pool = (ir_proxies + eu_bridges + am_bridges)[:10]
        hiddify = {
            "outbounds": [{
                "type": p["protocol"],
                "server": p["proxy"].rsplit(":", 1)[0],
                "server_port": int(p["proxy"].rsplit(":", 1)[1]),
                "tag": f"proxy-{i}",
                "comment": p.get("bridge_type", "IR-exit"),
            } for i, p in enumerate(hiddify_pool)],
            "route": {"final": "proxy"},
        }
        with open("hiddify_iran_proxies.json", "w") as f:
            json.dump(hiddify, f, indent=2)

    print_summary(merged)

    if args.save_intermediates:
        if atlas_res:
            with open("atlas_raw.json", "w") as f:
                json.dump(atlas_res, f, indent=2)
        if bgp_res:
            with open("bgp_raw.json", "w") as f:
                json.dump(bgp_res, f, indent=2)
        if reverse_res:
            with open("reverse_raw.json", "w") as f:
                json.dump(reverse_res, f, indent=2)

if __name__ == "__main__":
    asyncio.run(main())
