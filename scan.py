#!/usr/bin/env python3
"""
Iran Network Scanner - Enhanced Edition v2.2
============================================
Robust discovery of routable Iranian ASNs and working proxies.

v2.2 changes:
  - Added SNI-fronting discovery (probe_sni_fronting, discover_sni_fronting_pairs)
    Replicates the patterniha domain-fronting technique in pure asyncio:
    TLS ClientHello carries a whitelisted fake SNI while the payload targets
    Iranian infrastructure (tapi.bale.ai).  DPI sees only the CF-whitelisted SNI.
  - New --sni-fronting CLI flag; emits working_sni_fronting.json
  - CLOUDFLARE_WHITELIST_SNIS and CF_PROBE_RANGES constants added

v2.1 changes:
  - Added Rubika (rubika.ir) and Splus (splus.ir) as additional
    application-level Iranian infrastructure probes alongside Bale.
  - Tier-2 EU->IR bridge detection now uses a concurrent 1-of-3 probe vote
    (Bale / Rubika / Splus) via asyncio.gather — no added latency vs. v2.
  - Proxy output records include iran_probe_score (0-3) and iran_probes_ok.
  - AS202468 (Noyan Abr Arvan Co.) added to SEED_ASNS and FALLBACK_PREFIXES.
    Confirmed 2026-04-12: 37.32.26.30 / mail.paya.ir routes internationally.
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
import ssl
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

# Known Armenian ASNs - carriers with documented BGP peering into Iran
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

ARMENIA_SEED_DOMAINS = [
    "ucom.am", "mts.am", "beeline.am", "rostelecom.am",
    "armentel.com", "arminco.com", "gnc.am",
    "ardshinbank.am", "evocabank.am", "inecobank.am",
    "gov.am", "police.am", "mfa.am",
]

BALE_TEST_ENDPOINTS: List[Tuple[str, int]] = [
    ("tapi.bale.ai",  443),
    ("bale.ai",       443),
    ("bale.ai",        80),
]
BALE_TCP_TIMEOUT = float(os.environ.get("BALE_TCP_TIMEOUT", "5.0"))

RUBIKA_TEST_ENDPOINTS: List[Tuple[str, int]] = [
    ("web.rubika.ir", 443),
    ("rubika.ir",     443),
    ("rubika.ir",      80),
]

SPLUS_TEST_ENDPOINTS: List[Tuple[str, int]] = [
    ("web.splus.ir", 443),
    ("splus.ir",     443),
    ("splus.ir",      80),
]

EUROPEAN_BRIDGE_ASNS: List[int] = [
    24940, 51167, 8560, 3320, 680, 13184, 29066,
    16276, 60781, 20738,
    12876,
    34119, 47583,
]

EUROPEAN_BRIDGE_PREFIXES: List[str] = [
    "5.9.0.0/16", "5.161.0.0/16", "23.88.0.0/17", "65.21.0.0/16",
    "65.108.0.0/16", "65.109.0.0/16", "78.46.0.0/15", "88.198.0.0/16",
    "95.216.0.0/16", "116.202.0.0/15", "128.140.0.0/17", "135.181.0.0/16",
    "136.243.0.0/16", "138.201.0.0/16", "142.132.0.0/15", "144.76.0.0/16",
    "148.251.0.0/16", "157.90.0.0/16", "159.69.0.0/16", "162.55.0.0/16",
    "167.233.0.0/16", "168.119.0.0/16", "176.9.0.0/16", "178.63.0.0/16",
    "188.34.0.0/16", "193.25.134.0/23", "195.201.0.0/16", "213.239.192.0/18",
    "144.91.64.0/18", "173.212.192.0/18", "185.238.240.0/22",
    "194.163.128.0/17", "213.136.64.0/18",
    "5.135.0.0/16", "51.68.0.0/16", "51.75.0.0/16", "51.77.0.0/16",
    "54.36.0.0/16", "87.98.128.0/17", "91.121.0.0/16", "137.74.0.0/16",
    "145.239.0.0/16", "149.202.0.0/16", "151.80.0.0/16", "188.165.0.0/16",
    "193.70.0.0/17",
]

# -- SNI-fronting discovery configuration ------------------------------------
# Cloudflare-hosted domains observed to be whitelisted by Iranian DPI.
# DPI allows TLS ClientHellos carrying these SNIs through uninspected.
# Extend this list as new whitelisted SNIs are discovered in the wild.
CLOUDFLARE_WHITELIST_SNIS: List[str] = [
    "static.cloudflareinsights.com",
    "auth.vercel.com",
    "cdnjs.cloudflare.com",
    "ajax.cloudflare.com",
    "challenges.cloudflare.com",
    "www.cloudflare.com",
    "blog.cloudflare.com",
    "speed.cloudflare.com",
    "developers.cloudflare.com",
]

# Cloudflare anycast ranges to probe for SNI-fronting.
# These ranges carry Cloudflare's reverse-proxy traffic (not just DNS/registrar).
CF_PROBE_RANGES: List[str] = [
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "188.114.96.0/20",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "141.101.64.0/18",
]

SEED_ASNS = [
    43754, 62229, 48159, 12880, 16322, 42337, 49666, 21341, 24631,
    56402, 31549, 44244, 197207, 58224, 39501, 57218, 25184, 51695, 47262,
    64422, 205585,
    202468,
]

SEED_DOMAINS = [
    "telewebion.ir", "farsnews.ir", "tasnimnews.ir", "sepehrtv.ir",
    "parsatv.com", "irna.ir", "isna.ir", "mehrnews.com", "iribnews.ir",
    "varzesh3.com", "namasha.com", "filimo.com", "aparat.com", "digikala.com",
    "snapp.ir", "irancell.ir", "mci.ir", "tic.ir",
    "shatel.ir", "rightel.com", "bmi.ir", "bankmellat.ir",
    "behdasht.gov.ir", "moe.gov.ir",
    "paya.ir",
]

BOGON_RANGES = [
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
    "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
    "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32"
]

CDN_RANGES = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
    "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
    "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
    "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    "23.235.32.0/20", "43.249.72.0/22", "103.244.50.0/24",
    "103.245.222.0/23", "103.245.224.0/24", "104.156.80.0/20",
    "151.101.0.0/16", "157.52.192.0/18", "167.82.0.0/17",
    "167.82.128.0/20", "167.82.160.0/20", "167.82.224.0/20",
    "199.27.72.0/21",
    "23.32.0.0/11", "23.64.0.0/14", "23.192.0.0/11",
    "96.16.0.0/15", "96.6.0.0/15", "184.24.0.0/13",
    "184.50.0.0/15", "184.84.0.0/14",
]

_CDN_NETS = [ipaddress.IPv4Network(r, strict=False) for r in CDN_RANGES]

PROXY_PORTS = [80, 443, 1080, 3128, 8080, 8088, 8118, 8888, 9999]

FALLBACK_PREFIXES = [
    "5.160.0.0/12", "78.38.0.0/15", "151.232.0.0/13", "185.112.32.0/22",
    "185.141.104.0/22", "185.173.128.0/22", "185.236.172.0/22",
    "37.32.0.0/13",
]

PROXY_SOURCES = [
    "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt",
    "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks4.txt",
    "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/all.txt",
    "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies.txt",
]

VERIFICATION_TARGETS = [
    ("http://ip-api.com/json/?fields=status,countryCode", "countryCode", "IR"),
    ("http://ipwho.is/",                                  "country_code", "IR"),
    ("http://ipapi.co/json/",                             "country_code", "IR"),
]

# ---------- Helper functions ----------

def is_cdn_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.IPv4Address(ip_str)
        return any(ip in net for net in _CDN_NETS)
    except Exception:
        return False

def is_cdn_prefix(prefix: str) -> bool:
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
    try:
        net = ipaddress.IPv4Network(prefix, strict=False)
        total = net.num_addresses
        if total <= 2:
            return []
        usable = total - 2
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

# ---------- RIPE NCC Delegated Stats ----------

async def fetch_ripe_delegated() -> Tuple[List[int], List[str]]:
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
            if line.startswith("#") or line.startswith("2"):
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

# ---------- Hurricane Electric BGP ----------

async def fetch_he_asns() -> List[int]:
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

# ---------- Cloudflare Radar ----------

async def fetch_cloudflare_radar_asns() -> List[int]:
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

# ---------- Shadowserver BGP ----------

async def fetch_shadowserver_prefixes() -> List[str]:
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

# ---------- BGP neighbour expansion ----------

async def expand_via_neighbours(seed_asns: List[int], min_shared: int = 2) -> List[int]:
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

# ---------- SNI-fronting discovery ------------------------------------------

async def probe_sni_fronting(
    connect_ip: str,
    fake_sni: str,
    real_host: str = "tapi.bale.ai",
    port: int = 443,
    timeout: float = 5.0,
) -> bool:
    """
    Attempt a TLS connection to connect_ip:port with fake_sni in the
    ClientHello, then send an HTTP/1.1 HEAD request targeting real_host.

    This replicates the patterniha domain-fronting technique in pure asyncio:
      - Iranian DPI inspects the TLS ClientHello SNI field and sees fake_sni
        (a Cloudflare-whitelisted domain) -> connection is allowed through.
      - Cloudflare's edge terminates TLS and routes based on the HTTP Host
        header (real_host) -> request reaches Iranian infrastructure.

    Returns True if any HTTP response is received (including 4xx/5xx),
    confirming that the fronting path to real_host is open.
    """
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                connect_ip, port,
                ssl=ctx,
                server_hostname=fake_sni,   # fake SNI injected into TLS ClientHello
            ),
            timeout=timeout,
        )
        req = (
            f"HEAD / HTTP/1.1\r\n"
            f"Host: {real_host}\r\n"
            f"User-Agent: Mozilla/5.0 (compatible; IranNetScanner/2.2)\r\n"
            f"Connection: close\r\n\r\n"
        )
        writer.write(req.encode())
        await writer.drain()
        resp = await asyncio.wait_for(reader.read(512), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return b"HTTP/" in resp
    except Exception:
        return False


async def discover_sni_fronting_pairs(
    max_ips_per_range: int = 10,
    output_file: str = "working_sni_fronting.json",
    real_host: str = "tapi.bale.ai",
    sni_timeout: float = 5.0,
) -> List[dict]:
    """
    Probe Cloudflare anycast ranges for working (connect_ip, fake_sni) pairs
    that can front connections to Iranian infrastructure (real_host).

    A working pair means:
      - DPI sees the whitelisted fake_sni in the TLS ClientHello -> allowed
      - Cloudflare routes the request to real_host -> Iranian infra responds
      - The proxy operator can use this pair in SNI-spoofing configs

    Results are written to output_file (JSON) and returned as a list of dicts.
    Each dict: { connect_ip, fake_sni, port, real_host, discovered }
    """
    candidates: List[str] = []
    for prefix in CF_PROBE_RANGES:
        candidates.extend(
            stratified_sample_ips(prefix, max_samples=max_ips_per_range)
        )

    total_probes = len(candidates) * len(CLOUDFLARE_WHITELIST_SNIS)
    print(f"SNI-fronting discovery: {len(candidates)} Cloudflare IPs x "
          f"{len(CLOUDFLARE_WHITELIST_SNIS)} SNIs = {total_probes} probes "
          f"(target: {real_host}) ...")

    working: List[dict] = []
    seen_ips: set = set()
    sem = asyncio.Semaphore(200)
    lock = asyncio.Lock()

    async def probe_one(ip: str, sni: str) -> None:
        async with sem:
            async with lock:
                if ip in seen_ips:
                    return
            ok = await probe_sni_fronting(
                ip, sni, real_host=real_host, timeout=sni_timeout
            )
            if ok:
                async with lock:
                    if ip not in seen_ips:
                        seen_ips.add(ip)
                        entry = {
                            "connect_ip": ip,
                            "fake_sni":   sni,
                            "port":       443,
                            "real_host":  real_host,
                            "discovered": datetime.utcnow().strftime(
                                "%Y-%m-%dT%H:%M:%SZ"
                            ),
                        }
                        working.append(entry)
                        print(f"  [SNI-fronting] {ip}  fake_sni={sni}")

    tasks = [
        probe_one(ip, sni)
        for ip in candidates
        for sni in CLOUDFLARE_WHITELIST_SNIS
    ]
    await asyncio.gather(*tasks)

    print(f"SNI-fronting discovery complete: {len(working)} working pairs found.")
    if working:
        with open(output_file, "w") as f:
            json.dump(working, f, indent=2)
        print(f"  Saved to {output_file}")
    else:
        print(f"  No working pairs found — {real_host} may be unreachable from "
              f"this runner. Run again from a European IP for better results.")
    return working

# ---------- Proxy scanning ----------

async def scan_prefix_with_masscan(prefix: str,
                                    per_prefix_timeout: int = 90) -> List[str]:
    if not shutil.which("masscan"):
        return []
    ports = ",".join(str(p) for p in PROXY_PORTS)
    cmd = [
        "masscan", prefix,
        "-p", ports,
        "--rate=5000",
        "--open-only",
        "--banners",
        "-oJ", "-",
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
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

async def scan_prefix_async(prefix: str, max_samples: int = 100) -> List[str]:
    sample_ips = stratified_sample_ips(prefix, max_samples=max_samples)
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

async def _probe_endpoints(
    endpoints: List[Tuple[str, int]],
    proxy_url: str,
    timeout: float = BALE_TCP_TIMEOUT,
) -> bool:
    for host, port in endpoints:
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
                    if resp.status < 600 and resp.status != 407:
                        return True
        except aiohttp.ClientResponseError as e:
            if e.status != 407:
                return True
        except Exception:
            continue
    return False

async def check_bale_reachable(proxy_url: str,
                               timeout: float = BALE_TCP_TIMEOUT) -> bool:
    return await _probe_endpoints(BALE_TEST_ENDPOINTS, proxy_url, timeout)

async def check_rubika_reachable(proxy_url: str,
                                  timeout: float = BALE_TCP_TIMEOUT) -> bool:
    return await _probe_endpoints(RUBIKA_TEST_ENDPOINTS, proxy_url, timeout)

async def check_splus_reachable(proxy_url: str,
                                 timeout: float = BALE_TCP_TIMEOUT) -> bool:
    return await _probe_endpoints(SPLUS_TEST_ENDPOINTS, proxy_url, timeout)

async def verify_proxy_http(proxy: str, timeout: int = HTTP_TIMEOUT) -> Optional[dict]:
    ip, port_str = proxy.rsplit(":", 1)
    port = int(port_str)

    if is_cdn_ip(ip):
        return None

    proxy_url = f"http://{ip}:{port}"

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

    bale_ok, rubika_ok, splus_ok = await asyncio.gather(
        check_bale_reachable(proxy_url),
        check_rubika_reachable(proxy_url),
        check_splus_reachable(proxy_url),
    )
    iran_probe_score = sum([bale_ok, rubika_ok, splus_ok])

    if iran_probe_score >= 1:
        exit_country = "EU"
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
            "proxy":            proxy,
            "working":          True,
            "exit_verified":    False,
            "protocol":         "http",
            "latency":          None,
            "country":          exit_country,
            "geo_score":        confirmed,
            "iran_reachable":   True,
            "iran_probe_score": iran_probe_score,
            "iran_probes_ok":   {
                "bale":   bale_ok,
                "rubika": rubika_ok,
                "splus":  splus_ok,
            },
            "bridge_type":      "EU->IR",
        }

    return None

async def scrape_public_proxies() -> List[str]:
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
    EU_PREFIX_CAP   = int(os.environ.get("EU_PREFIX_CAP",   "20"))
    EU_FETCH_RIPE   = os.environ.get("EU_FETCH_RIPE", "").strip() == "1"

    all_prefixes: List[str] = list(EUROPEAN_BRIDGE_PREFIXES)

    if EU_FETCH_RIPE:
        print("Fetching European bridge ASN prefixes from RIPE Stat ...")
        sem = asyncio.Semaphore(10)

        async def fetch_one(asn: int) -> List[str]:
            async with sem:
                v4, _ = await fetch_ripe_prefixes(asn)
                return [p for p in v4 if not is_bogon_prefix(p)]

        ripe_results = await asyncio.gather(
            *[fetch_one(asn) for asn in EUROPEAN_BRIDGE_ASNS]
        )
        for r in ripe_results:
            all_prefixes.extend(r)
    else:
        print("Using hardcoded European bridge prefixes (set EU_FETCH_RIPE=1 for live fetch) ...")

    all_prefixes = list(set(all_prefixes))

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
    all_candidates: List[str] = []

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

    eu_prefixes: List[str] = []
    if europe_bridge:
        eu_prefixes = await fetch_european_bridge_prefixes()
        all_scan_prefixes = list(set(prefixes + eu_prefixes))
        print(f"Total prefixes to scan (IR + EU bridge): {len(all_scan_prefixes)}")
    else:
        all_scan_prefixes = prefixes

    if use_masscan and shutil.which("masscan"):
        mscan_sem = asyncio.Semaphore(int(os.environ.get("MASSCAN_PARALLEL", "6")))

        async def _masscan_one(pfx: str) -> List[str]:
            async with mscan_sem:
                return await scan_prefix_with_masscan(pfx)

        if eu_prefixes:
            ir_mscan_tasks  = [_masscan_one(p) for p in prefixes]
            eu_sample_tasks = [scan_prefix_async(p, max_samples=20) for p in eu_prefixes]
            print(f"  Masscan on {len(prefixes)} IR prefixes | "
                  f"async-TCP sampling {len(eu_prefixes)} EU bridge prefixes (20 IPs each) ...")
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
        if eu_prefixes:
            ir_tasks = [scan_prefix_async(pfx) for pfx in prefixes]
            eu_tasks = [scan_prefix_async(pfx, max_samples=20) for pfx in eu_prefixes]
            print(f"  async-TCP: {len(prefixes)} IR prefixes (100 IPs each) | "
                  f"{len(eu_prefixes)} EU prefixes (20 IPs each) ...")
            ir_res, eu_res = await asyncio.gather(
                asyncio.gather(*ir_tasks),
                asyncio.gather(*eu_tasks),
            )
            for res in ir_res:
                all_candidates.extend(res)
            for res in eu_res:
                all_candidates.extend(res)
        else:
            tasks = [scan_prefix_async(pfx) for pfx in all_scan_prefixes]
            for res in await asyncio.gather(*tasks):
                all_candidates.extend(res)

    all_candidates = list(set(all_candidates))
    print(f"Found {len(all_candidates)} candidate proxy endpoints from prefix scan.")

    public_candidates = await scrape_public_proxies()
    print(f"Found {len(public_candidates)} public proxy candidates.")
    all_candidates = list(set(all_candidates + public_candidates))

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
            print(f"\nConfidence {conf}/3 - {label} ({len(filtered)} ASNs)")
            for asn, val in filtered.items():
                v6_count = len(val.get("prefixes_v6", []))
                v6_str = f"  {v6_count} IPv6" if v6_count else ""
                print(f"  {asn:10} [{'+'.join(val['sources'])}] "
                      f"{len(val['prefixes'])} IPv4 prefixes{v6_str}")
    print(f"\nTotal: {len(merged)} unique routable Iranian ASNs identified.")

# ---------- Armenia-bridge ingestion ----------

def _parse_v2ray_uri_to_proxy_record(uri: str) -> Optional[dict]:
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
    results: List[dict] = []
    try:
        with open(path) as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
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
    proxy_dir  = os.environ.get("ARMENIA_PROXY_DIR",  "armenia-proxy-checker")
    v2ray_dir  = os.environ.get("ARMENIA_V2RAY_DIR",  "armenia_v2ray_checker")

    results:   List[dict] = []
    seen_keys: set        = set()

    def dedup_add(records: List[dict]) -> None:
        for r in records:
            key = (r["proxy"], r.get("protocol", ""))
            if key not in seen_keys:
                seen_keys.add(key)
                results.append(r)

    bridge_proxy_json  = os.path.join(proxy_dir, "armenia_iran_bridge_proxies.json")
    bridge_proxy_txt   = os.path.join(proxy_dir, "armenia_iran_bridge_proxies.txt")
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
    parser = argparse.ArgumentParser(description="Iran Network Scanner v2.2")
    parser.add_argument("--candidates",       help="File of IPs for reverse lookup")
    parser.add_argument("--bgp-only",         action="store_true")
    parser.add_argument("--atlas-only",       action="store_true")
    parser.add_argument("--reverse-only",     action="store_true")
    parser.add_argument("--proxy-only",       action="store_true")
    parser.add_argument("--armenia-bridge",   action="store_true",
                        help="Ingest Armenia-bridge proxies/configs")
    parser.add_argument("--europe-bridge",    action="store_true",
                        help="Scan European hosting ASNs for EU->IR bridges")
    parser.add_argument("--use-masscan",      action="store_true",
                        help="Use masscan for faster port scanning")
    parser.add_argument("--sni-fronting",     action="store_true",
                        help="Discover working Cloudflare SNI-fronting pairs "
                             "and emit working_sni_fronting.json")
    parser.add_argument("--output",           default="merged_routable_asns.json")
    parser.add_argument("--save-intermediates", action="store_true")
    args = parser.parse_args()

    atlas_res = bgp_res = reverse_res = proxy_res = armenia_bridge_res = None

    if not args.reverse_only and not args.proxy_only and not args.sni_fronting:
        dns_asns = await discover_asns_via_dns()
        working_asns = set(SEED_ASNS) | set(dns_asns)

        delegated_asns, delegated_prefixes = await fetch_ripe_delegated()
        working_asns.update(delegated_asns)

        he_asns = await fetch_he_asns()
        working_asns.update(he_asns)

        cf_asns = await fetch_cloudflare_radar_asns()
        working_asns.update(cf_asns)

        shadowserver_prefixes = await fetch_shadowserver_prefixes()

        first_hop = await expand_via_neighbours(list(SEED_ASNS), min_shared=2)
        working_asns.update(first_hop)

        print(f"\nTotal candidate ASNs before prefix fetch: {len(working_asns)}")

        sem = asyncio.Semaphore(20)

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
        if shadowserver_prefixes:
            bgp_list.append({
                "asn": 0,
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

        if not args.bgp_only and not args.reverse_only and not args.proxy_only:
            if RIPE_ATLAS_API_KEY:
                atlas_res = await run_atlas(list(working_asns)[:20], RIPE_ATLAS_API_KEY)
            else:
                print("RIPE_ATLAS_API_KEY not set, skipping Atlas")

    if args.reverse_only and args.candidates:
        with open(args.candidates) as f:
            ips = [line.strip() for line in f if line.strip()]
        reverse_res = await run_reverse(ips, IPINFO_TOKEN)

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

        PROXY_SCAN_TIMEOUT = int(os.environ.get("PROXY_SCAN_TIMEOUT_SECS", str(50 * 60)))
        try:
            proxy_res = await asyncio.wait_for(
                run_proxy_scanner(asn_db, use_masscan=args.use_masscan,
                                  europe_bridge=args.europe_bridge),
                timeout=PROXY_SCAN_TIMEOUT,
            )
        except asyncio.TimeoutError:
            print(f"WARNING: proxy scan hit {PROXY_SCAN_TIMEOUT // 60}-minute "
                  f"wall-clock limit - saving partial results and continuing.")
            proxy_res = []

    # -- SNI-fronting discovery ----------------------------------------------
    if args.sni_fronting:
        print("\nRunning SNI-fronting pair discovery ...")
        await discover_sni_fronting_pairs()
        # SNI-fronting is a standalone job; skip the rest of main() if that's
        # all that was requested (no --proxy-only, no --bgp-only, etc.)
        if not args.proxy_only and not args.bgp_only:
            return

    if args.armenia_bridge:
        print("\nIngesting Armenia->Iran bridge proxies ...")
        armenia_bridge_res = load_armenia_bridge_proxies()

    merged = merge_results(atlas_res, bgp_res, reverse_res)

    with open(args.output, "w") as f:
        json.dump(merged, f, indent=2)

    if proxy_res:
        if armenia_bridge_res:
            existing = {p["proxy"] for p in proxy_res}
            new_bridges = [b for b in armenia_bridge_res if b["proxy"] not in existing]
            proxy_res = proxy_res + new_bridges
            print(f"Added {len(new_bridges)} Armenia-bridge proxies to output "
                  f"({len(proxy_res)} total).")

        ir_proxies  = [p for p in proxy_res if p.get("country") == "IR"]
        eu_bridges  = [p for p in proxy_res
                       if p.get("bridge_type") == "EU->IR" or
                          (p.get("iran_reachable") and p.get("country") != "IR")]
        am_bridges  = [p for p in proxy_res if p.get("iran_bridge") and
                       p.get("country") == "AM"]
        all_usable  = proxy_res

        eu_bridges.sort(key=lambda p: p.get("iran_probe_score", 0), reverse=True)

        print(f"Output breakdown: {len(ir_proxies)} IR-exit | "
              f"{len(eu_bridges)} EU->IR bridges | "
              f"{len(am_bridges)} AM->IR bridges")

        with open("working_iran_proxies.txt", "w") as f:
            for p in all_usable:
                f.write(p["proxy"] + "\n")

        scan_ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        for p in all_usable:
            p.setdefault("scan_timestamp", scan_ts)

        with open("working_iran_proxies.json", "w") as f:
            json.dump(all_usable, f, indent=2)

        hiddify_pool = (ir_proxies + eu_bridges + am_bridges)[:10]
        hiddify = {
            "outbounds": [{
                "type": p["protocol"],
                "server": p["proxy"].rsplit(":", 1)[0],
                "server_port": int(p["proxy"].rsplit(":", 1)[1]),
                "tag": f"proxy-{i}",
                "comment": p.get("bridge_type", "IR-exit"),
                "iran_probe_score": p.get("iran_probe_score", 0),
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
