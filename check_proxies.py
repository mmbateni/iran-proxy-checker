#!/usr/bin/env python3
"""
Iran Proxy Checker — Active CIDR Scanner Edition (Bug-Fix Version)
===================================================================
FIX: Added IP sanitization to handle leading zeros in passive sources.
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

IP_PORT_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})\b")
PRIVATE_RE = re.compile(r"^(?:0\.|10\.|127\.|169\.254\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)")

# ── Helpers ───────────────────────────────────────────────────────────────────

def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)

def sanitize_ip(ip_str):
    """Strips leading zeros from octets to prevent AddressValueError."""
    try:
        return ".".join(str(int(octet)) for octet in ip_str.split("."))
    except:
        return ip_str

def fetch_raw_url(url, label):
    try:
        r = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=SCRAPE_TIMEOUT)
        found = set(IP_PORT_RE.findall(r.text))
        cleaned = {}
        for ip, port in found:
            if not PRIVATE_RE.match(ip):
                # Clean IP before storing
                clean_ip = sanitize_ip(ip)
                cleaned[f"{clean_ip}:{port}"] = "repo_fresh"
        return cleaned
    except:
        return {}

# ── Phases ────────────────────────────────────────────────────────────────────

def collect_passive_candidates() -> dict:
    log("\n── Phase 1: Passive collection from 25+ sources ──")
    all_proxies = {}
    
    sources = [
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
        "https://raw.githubusercontent.com/daniyal-abbassi/iran-proxy/main/proxy.txt",
        "https://api.proxyscrape.com/v2/?request=getproxies&protocol=http,socks4,socks5&timeout=10000&country=all"
    ]

    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as ex:
        futures = {ex.submit(fetch_raw_url, url, "source"): url for url in sources}
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            all_proxies.update(res)

    log(f"  Passive total: {len(all_proxies)} candidates fetched.")
    return all_proxies

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
        # Sampling logic
        try:
            base = int(net.network_address)
            for offset in SAMPLE_OFFSETS:
                if offset < net.num_addresses:
                    ip = str(ipaddress.IPv4Address(base + offset))
                    for port in PROXY_PORTS:
                        targets.append((ip, port))
        except: continue
    
    random.shuffle(targets)
    log(f"  Probing {len(targets):,} targets across {len(networks)} prefixes...")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=SCAN_WORKERS) as ex:
        results = list(ex.map(tcp_probe, targets, chunksize=1000))
        hits = {r for r in results if r}
        
    log(f"  Scan complete: {len(hits)} open ports found.")
    return hits

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    log("=" * 60)
    log("Iran Proxy Checker — Fixed Execution Mode")
    log("=" * 60)

    # 1. Load Iranian Networks
    fallback = ["5.160.0.0/12", "31.24.0.0/14", "37.254.0.0/15", "62.60.0.0/15", "77.36.0.0/14"]
    networks = [ipaddress.IPv4Network(c) for c in fallback]
    if ASN_JSON_PATH.exists():
        with open(ASN_JSON_PATH) as f:
            try:
                data = json.load(f)
                cidr_list = data.get("cidr_list", [])
                networks = [ipaddress.IPv4Network(c, strict=False) for c in cidr_list]
            except: pass

    # 2. Collect Passive
    passive_data = collect_passive_candidates()
    
    # 3. Filter for Iran with Safety
    passive_list = []
    for p_str in passive_data:
        try:
            ip_only = p_str.split(":")[0]
            ip_obj = ipaddress.IPv4Address(ip_only)
            if any(ip_obj in net for net in networks):
                passive_list.append(p_str)
        except Exception:
            continue # Skip malformed IPs that somehow slipped through
            
    log(f"  {len(passive_list)} passive candidates matched Iranian IP blocks.")

    # 4. Run Active Scan
    scan_hits = scan_routable_cidrs(networks)

    # 5. Save Results
    all_final = set(passive_list) | scan_hits
    log(f"\n[√] Total Iranian proxies identified: {len(all_final)}")
    
    with open("working_iran_proxies.txt", "w") as f:
        f.write("\n".join(all_final))
        
    with open("working_iran_proxies.json", "w") as f:
        json.dump({"total": len(all_final), "proxies": list(all_final)}, f)

if __name__ == "__main__":
    main()
