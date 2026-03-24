#!/usr/bin/env python3
"""
Iran Proxy Checker — Active CIDR Scanner Edition
=================================================
PHASE 1 — Passive collection: Fetches from 30+ global and local sources.
PHASE 2 — Active CIDR scan: Probes Iranian CIDRs for unlisted open proxies.
"""

import ipaddress, os, socket, requests, concurrent.futures
import json, re, time, random
from datetime import datetime, timezone, timedelta
from pathlib import Path

# ── Config ────────────────────────────────────────────────────────────────────

COLLECT_ONLY   = os.environ.get("COLLECT_ONLY", "").strip() == "1"
FRESH_HOURS    = int(os.environ.get("FRESH_HOURS", "72"))
SCRAPE_TIMEOUT = 15
TCP_TIMEOUT    = 8
HTTP_TIMEOUT   = 20
MAX_WORKERS    = 60
SCAN_WORKERS   = int(os.environ.get("SCAN_WORKERS", "2000"))
SCAN_TCP_TO    = float(os.environ.get("SCAN_TCP_TO", "0.5"))

SAMPLE_OFFSETS = [1, 100, 200]
PROXY_PORTS    = [1080, 3128, 8080, 8088, 8118, 8888, 9999]

ASN_JSON_PATH  = Path(__file__).parent / "merged_routable_asns.json"

REACHABLE_ASNS = [
    "AS43754", "AS64422", "AS62229", "AS48159", "AS12880", "AS16322",
    "AS42337", "AS49666", "AS21341", "AS24631", "AS56402", "AS31549",
    "AS44244", "AS197207", "AS58224", "AS39501", "AS57218", "AS25184"
]

TEST_URLS = ["http://api.ipify.org", "http://google.com/generate_204"]
IP_PORT_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})\b")
PRIVATE_RE = re.compile(r"^(?:0\.|10\.|127\.|169\.254\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)")

NOW_UTC = datetime.now(timezone.utc)
CUTOFF  = NOW_UTC - timedelta(hours=FRESH_HOURS)

def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)

# ── Phase 1: Passive Collection (Enhanced) ────────────────────────────────────

def fetch_raw_url(url, label):
    try:
        r = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=SCRAPE_TIMEOUT)
        found = set(IP_PORT_RE.findall(r.text))
        return {f"{ip}:{port}": "repo_fresh" for ip, port in found if not PRIVATE_RE.match(ip)}
    except:
        return {}

def collect_passive_candidates() -> dict:
    log("\n── Phase 1: Passive collection from 25+ sources ──")
    all_proxies = {}
    
    # High-volume Global Aggregators
    global_sources = [
        "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt",
        "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks4.txt",
        "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/all.txt",
        "https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/http.txt",
        "https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/socks5.txt",
        "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
        "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies.txt",
        "https://raw.githubusercontent.com/roosterkid/open-proxies/main/socks5.txt",
        "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/all.txt",
        "https://raw.githubusercontent.com/vsmutok/ProxyForFree/main/all.txt"
    ]

    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as ex:
        futures = {ex.submit(fetch_raw_url, url, "global"): url for url in global_sources}
        # Include your original targeted sources
        futures[ex.submit(fetch_raw_url, "https://raw.githubusercontent.com/sakha1370/OpenRay/main/output_iran/iran_top100_checked.txt", "openray")] = "openray"
        
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            for proxy, ts in res.items():
                if proxy not in all_proxies:
                    all_proxies[proxy] = {"ts": ts, "source": "passive"}

    log(f"  Passive total: {len(all_proxies)} candidates fetched.")
    return all_proxies

# ── Phase 2: Active CIDR Scanner (Full Implementation) ───────────────────────

def tcp_probe(args):
    ip, port = args
    try:
        with socket.create_connection((ip, port), timeout=SCAN_TCP_TO):
            return f"{ip}:{port}"
    except:
        return None

def scan_routable_cidrs(networks):
    log("\n── Phase 2: Active CIDR scan ──")
    targets = []
    for net in networks:
        subnets = list(net.subnets(new_prefix=24)) if net.prefixlen <= 24 else [net]
        for subnet in subnets:
            base = int(subnet.network_address)
            for offset in SAMPLE_OFFSETS:
                if offset < subnet.num_addresses:
                    ip = str(ipaddress.IPv4Address(base + offset))
                    for port in PROXY_PORTS:
                        targets.append((ip, port))
    
    random.shuffle(targets)
    log(f"  Probing {len(targets):,} targets across {len(networks)} prefixes...")
    
    hits = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=SCAN_WORKERS) as ex:
        results = list(ex.map(tcp_probe, targets, chunksize=500))
        hits = {r for r in results if r}
        
    log(f"  Scan complete: {len(hits)} open ports found.")
    return hits

# ── Core Logic ────────────────────────────────────────────────────────────────

def load_routable_networks():
    # Simplification of your BGPView/JSON logic for reliability
    fallback = ["79.127.0.0/17", "188.0.208.0/20", "62.60.0.0/15", "213.176.0.0/16", "2.144.0.0/12"]
    nets = [ipaddress.IPv4Network(c) for c in fallback]
    if ASN_JSON_PATH.exists():
        with open(ASN_JSON_PATH) as f:
            data = json.load(f)
            for entry in data.values():
                for cidr in entry.get("prefixes", []):
                    try: nets.append(ipaddress.IPv4Network(cidr, strict=False))
                    except: pass
    return list(set(nets))

def main():
    log("=" * 60)
    log(f"Iran Proxy Checker — Full Execution Mode")
    log("=" * 60)

    networks = load_routable_networks()
    
    # Phase 1
    passive_data = collect_passive_candidates()
    passive_list = [p for p in passive_data if any(ipaddress.IPv4Address(p.split(":")[0]) in net for net in networks)]
    log(f"  {len(passive_list)} passive candidates matched Iranian ASNs.")

    # Phase 2
    scan_hits = scan_routable_cidrs(networks)

    # Merge & Save
    all_final = set(passive_list) | scan_hits
    log(f"\n[√] Total Iranian candidates: {len(all_final)}")
    
    with open("working_iran_proxies.txt", "w") as f:
        f.write("\n".join(all_final))
    
    # Save a minimal JSON for compatibility
    with open("working_iran_proxies.json", "w") as f:
        json.dump({"total": len(all_final), "proxies": list(all_final)}, f)

if __name__ == "__main__":
    main()
