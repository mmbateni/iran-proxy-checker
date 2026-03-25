#!/usr/bin/env python3
"""
Iran Network Scanner – Enhanced Edition
========================================
Robust discovery of routable Iranian ASNs and working proxies.
"""
import asyncio
import aiohttp
import argparse
import ipaddress
import json
import os
import random
import socket
import sys
from collections import Counter, defaultdict
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import re

# ---------- Configuration ----------
RIPE_ATLAS_API_KEY = os.environ.get("RIPE_ATLAS_API_KEY", "")
IPINFO_TOKEN = os.environ.get("IPINFO_TOKEN", "")
TCP_TIMEOUT = float(os.environ.get("TCP_TIMEOUT", "1.0"))
SCAN_WORKERS = int(os.environ.get("SCAN_WORKERS", "2000"))
SKIP_EXIT_VERIFY = os.environ.get("SKIP_EXIT_VERIFY", "").strip() == "1"
MIN_CONFIDENCE = int(os.environ.get("MIN_CONFIDENCE", "1"))
HTTP_TIMEOUT = int(os.environ.get("HTTP_TIMEOUT", "10"))

# Known Iranian ASNs (seed list) – updated
SEED_ASNS = [
    43754, 62229, 48159, 12880, 16322, 42337, 49666, 21341, 24631,
    56402, 31549, 44244, 197207, 58224, 39501, 57218, 25184, 51695, 47262,
    64422, 205585
]

# Iranian domains for DNS seeding
SEED_DOMAINS = [
    "telewebion.ir", "farsnews.ir", "tasnimnews.ir", "sepehrtv.ir",
    "parsatv.com", "irna.ir", "isna.ir", "mehrnews.com", "iribnews.ir",
    "varzesh3.com", "namasha.com", "filimo.com", "aparat.com", "digikala.com",
    "snapp.ir", "irancell.ir", "mci.ir", "tic.ir", "google.com", "youtube.com"
]

# Bogon prefixes to filter
BOGON_RANGES = [
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
    "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
    "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32"
]

# Proxies to test
PROXY_PORTS = [80, 443, 1080, 3128, 8080, 8088, 8118, 8888, 9999]
# Increased sample offsets for better coverage
SAMPLE_OFFSETS = list(range(1, 256, 5))[:50]  # first 50 IPs in /24
# Fallback prefixes if ASN DB empty
FALLBACK_PREFIXES = [
    "5.160.0.0/12", "78.38.0.0/15", "151.232.0.0/13", "185.112.32.0/22",
    "185.141.104.0/22", "185.173.128.0/22", "185.236.172.0/22"
]

# Public proxy sources (for additional candidates)
PROXY_SOURCES = [
    "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt",
    "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks4.txt",
    "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/all.txt",
    "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies.txt"
]

# ---------- Helper functions ----------
def is_bogon(ip_str: str) -> bool:
    try:
        ip = ipaddress.IPv4Address(ip_str)
        return (ip.is_private or ip.is_loopback or ip.is_link_local or
                ip.is_reserved or ip.is_multicast)
    except:
        return True

def is_bogon_prefix(prefix: str) -> bool:
    try:
        net = ipaddress.IPv4Network(prefix, strict=False)
        for b in BOGON_RANGES:
            if net.subnet_of(ipaddress.IPv4Network(b, strict=False)):
                return True
        return False
    except:
        return True

def cidr_first_host(cidr: str) -> Optional[str]:
    try:
        net = ipaddress.IPv4Network(cidr, strict=False)
        if net.num_addresses < 2:
            return None
        return str(net.network_address + 1)
    except:
        return None

async def tcp_connect(ip: str, port: int, timeout: float = TCP_TIMEOUT) -> bool:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return True
    except:
        return False

# ---------- RIPE Stat API ----------
async def fetch_ripe_prefixes(asn: int) -> List[str]:
    """Fetch announced IPv4 prefixes for ASN from RIPE Stat."""
    url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=30) as resp:
                if resp.status != 200:
                    return []
                data = await resp.json()
                prefixes = data.get("data", {}).get("prefixes", [])
                return [p["prefix"] for p in prefixes if ":" not in p.get("prefix", "")]
    except:
        return []

async def fetch_asn_neighbours(asn: int) -> List[int]:
    """Fetch BGP neighbours for ASN from RIPE Stat."""
    url = f"https://stat.ripe.net/data/asn-neighbours/data.json?resource=AS{asn}"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=30) as resp:
                if resp.status != 200:
                    return []
                data = await resp.json()
                neighbours = data.get("data", {}).get("neighbours", [])
                return [int(n.get("asn", n)) for n in neighbours]
    except:
        return []

# ---------- DNS + Cymru ----------
async def resolve_domain(domain: str) -> List[str]:
    try:
        return list(set(socket.gethostbyname_ex(domain)[2]))
    except:
        return []

async def whois_cymru(ips: List[str]) -> Dict[str, dict]:
    """Query Team Cymru WHOIS for IPs. Returns dict ip->info."""
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
    return list(asns)

# ---------- BGP expansion ----------
async def expand_via_neighbours(seed_asns: List[int], min_shared: int = 2) -> List[int]:
    peer_count = Counter()
    for asn in seed_asns:
        neighbours = await fetch_asn_neighbours(asn)
        for nb in neighbours:
            if nb not in seed_asns:
                peer_count[nb] += 1
    return [asn for asn, count in peer_count.items() if count >= min_shared]

# ---------- RIPE Atlas (minimal) ----------
# (unchanged, but may be skipped if no key)

# ---------- Reverse ASN lookup ----------
async def lookup_ipinfo(ip: str, token: str) -> dict:
    url = f"https://ipinfo.io/{ip}/json"
    params = {"token": token} if token else {}
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(url, params=params, timeout=10) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    org = data.get("org", "")
                    asn = None
                    asn_name = None
                    if org.startswith("AS"):
                        parts = org.split(" ", 1)
                        asn = int(parts[0][2:])
                        asn_name = parts[1] if len(parts) > 1 else ""
                    return {
                        "asn": asn,
                        "asn_name": asn_name,
                        "country": data.get("country"),
                        "prefix": None
                    }
        except:
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

async def run_reverse(ips: List[str], ipinfo_token: str) -> Dict:
    tasks = [process_reverse_ip(ip, ipinfo_token) for ip in ips]
    results = await asyncio.gather(*tasks)
    asn_map = {}
    for r in results:
        asn = r.get("asn")
        if asn and r.get("tcp_ok") and r.get("country") == "IR":
            asn_map.setdefault(asn, {
                "asn": asn,
                "name": r.get("asn_name"),
                "prefixes": [],
                "responsive_ips": []
            })["responsive_ips"].append(r["ip"])
    return {"routable_asns": list(asn_map.values()), "all_records": results}

# ---------- Enhanced Proxy Scanning ----------
async def scan_prefix_with_masscan(prefix: str) -> List[str]:
    """Use masscan to scan an entire prefix for open proxy ports."""
    if not shutil.which("masscan"):
        return []
    ports = ",".join(str(p) for p in PROXY_PORTS)
    cmd = ["masscan", prefix, "-p", ports, "--rate=1000", "--open-only", "-oJ", "-"]
    try:
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            return []
        data = json.loads(stdout)
        results = []
        for host in data.get("hosts", []):
            ip = host.get("ip")
            for port in host.get("ports", []):
                results.append(f"{ip}:{port['port']}")
        return results
    except Exception as e:
        print(f"Masscan error on {prefix}: {e}")
        return []

async def scan_prefix_async(prefix: str) -> List[str]:
    """Async TCP scanning of sample IPs from a prefix (fallback)."""
    net = ipaddress.IPv4Network(prefix, strict=False)
    candidates = []
    tasks = []
    for offset in SAMPLE_OFFSETS:
        if offset >= net.num_addresses:
            continue
        ip = str(net.network_address + offset)
        if is_bogon(ip):
            continue
        for port in PROXY_PORTS:
            tasks.append(tcp_connect(ip, port, timeout=TCP_TIMEOUT))
            # Add the corresponding result mapping
    if tasks:
        results = await asyncio.gather(*tasks)
        idx = 0
        for offset in SAMPLE_OFFSETS:
            if offset >= net.num_addresses:
                continue
            ip = str(net.network_address + offset)
            if is_bogon(ip):
                continue
            for port in PROXY_PORTS:
                if results[idx]:
                    candidates.append(f"{ip}:{port}")
                idx += 1
    return candidates

async def verify_proxy_http(proxy: str, timeout: int = HTTP_TIMEOUT) -> Optional[dict]:
    """Verify proxy by fetching a geolocation endpoint."""
    ip, port = proxy.split(":")
    port = int(port)
    # Test HTTP proxy (will work for SOCKS as well if we use aiohttp with proxy)
    test_url = "http://ip-api.com/json/?fields=status,countryCode,query"
    try:
        async with aiohttp.ClientSession() as session:
            # aiohttp supports HTTP proxy only; for SOCKS we need a separate library
            # We'll try HTTP first
            proxy_url = f"http://{ip}:{port}"
            async with session.get(test_url, proxy=proxy_url, timeout=timeout) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    country = data.get("countryCode", "")
                    if country == "IR":
                        return {
                            "proxy": proxy,
                            "working": True,
                            "exit_verified": True,
                            "protocol": "http",
                            "latency": None,
                            "country": "IR"
                        }
    except Exception as e:
        pass
    # If HTTP fails, try SOCKS5 if available
    try:
        import socks
        import aiohttp_socks
        # Create a connector that uses SOCKS5
        conn = aiohttp_socks.ProxyConnector.from_url(f'socks5://{ip}:{port}')
        async with aiohttp.ClientSession(connector=conn) as session:
            async with session.get(test_url, timeout=timeout) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    country = data.get("countryCode", "")
                    if country == "IR":
                        return {
                            "proxy": proxy,
                            "working": True,
                            "exit_verified": True,
                            "protocol": "socks5",
                            "latency": None,
                            "country": "IR"
                        }
    except Exception:
        pass
    return None

async def scrape_public_proxies() -> List[str]:
    """Scrape public proxy lists for additional candidates."""
    candidates = set()
    async with aiohttp.ClientSession() as session:
        for url in PROXY_SOURCES:
            try:
                async with session.get(url, timeout=15) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        # Extract ip:port patterns
                        found = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}\b', text)
                        candidates.update(found)
            except:
                continue
    return list(candidates)

async def run_proxy_scanner(asn_db: dict, use_masscan: bool = False) -> List[dict]:
    """Main proxy scanning routine."""
    # 1. Gather candidate IP:port from ASN prefixes
    all_candidates = []
    # Use ASN DB or fallback
    prefixes = []
    for asn, entry in asn_db.items():
        confidence = entry.get("confidence", 1)
        if confidence < MIN_CONFIDENCE:
            continue
        prefixes.extend(entry.get("prefixes", []))
    if not prefixes:
        print("No prefixes found in ASN DB, using fallback prefixes")
        prefixes = FALLBACK_PREFIXES
    # Deduplicate prefixes
    prefixes = list(set(prefixes))

    print(f"Scanning {len(prefixes)} prefixes for open proxies...")
    # Use masscan if available and requested
    if use_masscan and shutil.which("masscan"):
        for pfx in prefixes:
            print(f"Masscan {pfx}...")
            results = await scan_prefix_with_masscan(pfx)
            all_candidates.extend(results)
    else:
        # Async scanning (slower but works)
        tasks = [scan_prefix_async(pfx) for pfx in prefixes]
        results_list = await asyncio.gather(*tasks)
        for res in results_list:
            all_candidates.extend(res)
    all_candidates = list(set(all_candidates))
    print(f"Found {len(all_candidates)} candidate proxy endpoints.")

    # 2. Add public proxy candidates
    public_candidates = await scrape_public_proxies()
    print(f"Found {len(public_candidates)} public proxy candidates.")
    all_candidates.extend(public_candidates)
    all_candidates = list(set(all_candidates))

    # 3. Verify each candidate
    verified = []
    sem = asyncio.Semaphore(50)  # limit concurrent verifications
    async def verify_one(proxy):
        async with sem:
            return await verify_proxy_http(proxy)
    tasks = [verify_one(p) for p in all_candidates]
    results = await asyncio.gather(*tasks)
    for r in results:
        if r:
            verified.append(r)
    print(f"Verified {len(verified)} working Iranian proxies.")
    return verified

# ---------- Merging ----------
def merge_results(atlas: dict, bgp: list, reverse: dict) -> dict:
    entries = {}
    def add(asn: int, name: str, source: str, prefixes: list, confidence_boost: int = 1):
        key = f"AS{asn}"
        if key not in entries:
            entries[key] = {
                "asn": asn,
                "name": name,
                "confidence": 0,
                "sources": [],
                "prefixes": []
            }
        entries[key]["confidence"] += confidence_boost
        entries[key]["sources"].append(source)
        entries[key]["prefixes"].extend(prefixes)
        entries[key]["prefixes"] = list(set(entries[key]["prefixes"]))
        if name and not entries[key]["name"]:
            entries[key]["name"] = name

    if atlas:
        for asn_str, info in atlas.items():
            if info.get("routable"):
                add(info["asn"], None, "atlas", info.get("prefixes", []), 1)

    if bgp:
        for asn_info in bgp:
            if asn_info.get("routable"):
                add(asn_info["asn"], None, "bgp", asn_info.get("routable_prefixes", []), 1)

    if reverse and reverse.get("routable_asns"):
        for asn_info in reverse["routable_asns"]:
            add(asn_info["asn"], asn_info.get("name"), "reverse",
                asn_info.get("prefixes", []), 1)

    for key, val in entries.items():
        conf = val["confidence"]
        if conf >= 3:
            val["confidence_label"] = "very_high"
        elif conf == 2:
            val["confidence_label"] = "high"
        else:
            val["confidence_label"] = "possible"
    return entries

def print_summary(merged: dict):
    print("\n=== Merged Results ===")
    for conf in [3, 2, 1]:
        label = {3: "VERY HIGH", 2: "HIGH", 1: "POSSIBLE"}[conf]
        filtered = {k:v for k,v in merged.items() if v["confidence"] == conf}
        if filtered:
            print(f"\nConfidence {conf}/3 — {label} ({len(filtered)} ASNs)")
            for asn, val in filtered.items():
                print(f"  {asn:10} [{'+'.join(val['sources'])}] {len(val['prefixes'])} prefixes")
    print(f"\nTotal: {len(merged)} unique routable Iranian ASNs identified.")

# ---------- Main orchestration ----------
async def main():
    parser = argparse.ArgumentParser(description="Iran Network Scanner")
    parser.add_argument("--candidates", help="File containing IPs for reverse lookup")
    parser.add_argument("--bgp-only", action="store_true", help="Only run BGP scan")
    parser.add_argument("--atlas-only", action="store_true", help="Only run Atlas")
    parser.add_argument("--reverse-only", action="store_true", help="Only run reverse lookup")
    parser.add_argument("--proxy-only", action="store_true", help="Only scan for proxies")
    parser.add_argument("--use-masscan", action="store_true", help="Use masscan for faster scanning")
    parser.add_argument("--output", default="merged_routable_asns.json", help="Output file")
    parser.add_argument("--save-intermediates", action="store_true", help="Save raw results")
    args = parser.parse_args()

    atlas_res = bgp_res = reverse_res = proxy_res = None

    # Build working set of ASNs for BGP and Atlas
    seed_asns = SEED_ASNS
    if not args.reverse_only and not args.proxy_only:
        dns_asns = await discover_asns_via_dns()
        working_asns = set(seed_asns + dns_asns)
        neighbours = await expand_via_neighbours(list(seed_asns), min_shared=2)
        working_asns.update(neighbours)
        if args.bgp_only or args.atlas_only or (not args.reverse_only and not args.proxy_only):
            bgp_list = []
            for asn in working_asns:
                prefixes = await fetch_ripe_prefixes(asn)
                routable = [p for p in prefixes if not is_bogon_prefix(p)]
                bgp_list.append({
                    "asn": asn,
                    "routable": len(routable) > 0,
                    "routable_prefixes": routable,
                    "all_prefixes": prefixes,
                    "is_seed": asn in seed_asns,
                    "dns_confirmed": asn in dns_asns
                })
            bgp_res = bgp_list

        if not args.bgp_only and not args.reverse_only and not args.proxy_only:
            # Run Atlas if key provided
            if RIPE_ATLAS_API_KEY:
                atlas_res = await run_atlas(list(working_asns)[:20], RIPE_ATLAS_API_KEY)
            else:
                print("RIPE_ATLAS_API_KEY not set, skipping Atlas")

    if args.reverse_only and args.candidates:
        with open(args.candidates) as f:
            ips = [line.strip() for line in f if line.strip()]
        reverse_res = await run_reverse(ips, IPINFO_TOKEN)

    if args.proxy_only:
        # Load ASN DB from previous run or use bgp_res
        asn_db = {}
        if bgp_res:
            for entry in bgp_res:
                if entry["routable"]:
                    asn_db[f"AS{entry['asn']}"] = {
                        "asn": entry["asn"],
                        "prefixes": entry["routable_prefixes"],
                        "confidence": 1
                    }
        else:
            try:
                with open(args.output) as f:
                    asn_db = json.load(f)
            except:
                asn_db = {}
        proxy_res = await run_proxy_scanner(asn_db, use_masscan=args.use_masscan)

    # Merge results
    merged = merge_results(atlas_res, bgp_res, reverse_res)

    # Save merged results
    with open(args.output, "w") as f:
        json.dump(merged, f, indent=2)

    # Save proxy results
    if proxy_res:
        with open("working_iran_proxies.txt", "w") as f:
            for p in proxy_res:
                f.write(p["proxy"] + "\n")
        with open("working_iran_proxies.json", "w") as f:
            json.dump(proxy_res, f, indent=2)
        # Hiddify config
        hiddify = {
            "outbounds": [{
                "type": p["protocol"],
                "server": p["proxy"].split(":")[0],
                "server_port": int(p["proxy"].split(":")[1]),
                "tag": f"proxy-{i}"
            } for i, p in enumerate(proxy_res[:10])],
            "route": {"final": "proxy"}
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
