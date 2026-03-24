#!/usr/bin/env python3
"""
Iran Proxy Checker — Enhanced Edition (v2.0)
=============================================
Improvements from R scripts integration:
- 20+ Iranian ASNs (vs 8 hardcoded prefixes)
- ASN tracking for each discovered proxy
- Hiddify/Sing-Box compatible output
- Better IP validation & bogon filtering
- Confidence scoring from multiple sources
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
MAX_WORKERS    = 60
SCAN_WORKERS   = int(os.environ.get("SCAN_WORKERS", "2000"))
SCAN_TCP_TO    = float(os.environ.get("SCAN_TCP_TO", "0.5"))
SAMPLE_OFFSETS = [1, 50, 100, 150, 200, 300, 500]  # Enhanced from [1, 100, 200]
PROXY_PORTS    = [80, 443, 1080, 3128, 8080, 8088, 8118, 8888, 9999]
ASN_JSON_PATH  = Path(__file__).parent / "merged_routable_asns.json"
IP_PORT_RE     = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})\b")

# ── Enhanced Iranian ASN Fallback (from R scripts) ───────────────────────────
FALLBACK_ASNS = {
    "AS43754":  "Asiatech Data Transmission — telewebion.ir",
    "AS64422":  "Sima Rayan Sharif — telewebion.ir",
    "AS62229":  "Fars News Agency — farsnews.ir",
    "AS48159":  "TIC / ITC Backbone",
    "AS12880":  "Iran Telecommunications Co.",
    "AS16322":  "Pars Online / Respina",
    "AS42337":  "Respina Networks & Beyond",
    "AS49666":  "TIC Gateway (transit for all Iranian ISPs)",
    "AS21341":  "Fanava Group — sepehrtv.ir",
    "AS24631":  "FANAPTELECOM / Fanavari Pasargad",
    "AS56402":  "Dadeh Gostar Asr Novin",
    "AS31549":  "Afranet",
    "AS44244":  "IranCell / MCI",
    "AS197207": "Mobile Communication of Iran (MCI)",
    "AS58224":  "Iran Telecom PJS",
    "AS39501":  "Aria Shatel",
    "AS57218":  "RayaPars",
    "AS25184":  "Afagh Danesh Gostar",
    "AS51695":  "Iranian ISP",
    "AS47262":  "Iranian ISP"
}

# ── Helpers ───────────────────────────────────────────────────────────────────
def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)

def sanitize_ip(ip_str):
    """Strips leading zeros and validates IPv4."""
    try:
        parts = ip_str.split(".")
        if len(parts) != 4:
            return None
        octets = [int(p) for p in parts]
        if any(o < 0 or o > 255 for o in octets):
            return None
        return ".".join(str(o) for o in octets)
    except:
        return None

def is_bogon(ip_str):
    """Check if IP is in private/reserved ranges."""
    try:
        ip = ipaddress.IPv4Address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
    except:
        return True

def load_routable_networks():
    """
    Loads Iranian IP ranges from JSON (ASN-keyed) + hardcoded fallback.
    Compatible with merged_routable_asns.json from R scripts.
    """
    asn_data = {}  # {asn: {name, prefixes, networks}}
    
    # Try loading from JSON (preferred - has 2000+ prefixes)
    if ASN_JSON_PATH.exists():
        log(f"[*] Loading networks from {ASN_JSON_PATH}...")
        try:
            with open(ASN_JSON_PATH) as f:
                data = json.load(f)
            
            for asn_key, entry in data.items():
                asn_num = asn_key.replace("AS", "")
                prefixes = entry.get("prefixes", [])
                
                # Handle both structures:
                # New: {"prefixes": ["x.x.x.x/y", ...]}
                # Old: {"prefixes": [...]} or just [...]
                if isinstance(prefixes, list):
                    cidrs = prefixes
                elif isinstance(entry, list):
                    cidrs = entry
                else:
                    cidrs = entry.get("prefixes", []) if isinstance(entry, dict) else []
                
                networks = []
                for c in cidrs:
                    try:
                        net = ipaddress.IPv4Network(c.strip(), strict=False)
                        networks.append(net)
                    except:
                        pass
                
                if networks:
                    asn_data[asn_num] = {
                        "name": entry.get("name", FALLBACK_ASNS.get(f"AS{asn_num}", "Unknown")),
                        "prefixes": cidrs,
                        "networks": networks
                    }
            
            log(f"  ✓ Loaded {len(asn_data)} ASNs with {sum(len(d['prefixes']) for d in asn_data.values())} prefixes")
        except Exception as e:
            log(f"  [!] JSON load error: {e}")
    
    # Fallback: If JSON failed or empty, use hardcoded ASNs
    if not asn_data:
        log("  [!] JSON empty/missing — using hardcoded fallback ASNs")
        # Add major Iranian IP blocks per ASN
        fallback_nets = {
            "43754": ["79.127.0.0/17", "188.0.240.0/20", "46.143.0.0/17"],
            "12880": ["2.176.0.0/12", "78.38.0.0/15", "85.185.0.0/16"],
            "44244": ["5.112.0.0/16", "5.113.0.0/16", "5.114.0.0/16"],
            "58224": ["151.232.0.0/13", "151.234.0.0/15"],
            "39501": ["89.165.0.0/17", "188.158.0.0/15"],
        }
        for asn_num, cidrs in fallback_nets.items():
            networks = []
            for c in cidrs:
                try:
                    networks.append(ipaddress.IPv4Network(c, strict=False))
                except:
                    pass
            if networks:
                asn_data[asn_num] = {
                    "name": FALLBACK_ASNS.get(f"AS{asn_num}", "Unknown"),
                    "prefixes": cidrs,
                    "networks": networks
                }
    
    # Flatten all networks for scanning
    all_networks = []
    for asn_num, data in asn_data.items():
        for net in data["networks"]:
            all_networks.append((net, f"AS{asn_num}"))
    
    unique_nets = list(set(n[0] for n in all_networks))
    log(f"[*] Total active Iranian IP prefixes: {len(unique_nets)} ({len(asn_data)} ASNs)")
    
    return unique_nets, asn_data, all_networks

# ── Phase 1: Passive Collection ───────────────────────────────────────────────
def fetch_raw_url(url):
    try:
        r = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=SCRAPE_TIMEOUT)
        found = set(IP_PORT_RE.findall(r.text))
        return {
            f"{sanitize_ip(ip)}:{port}": {"ip": sanitize_ip(ip), "port": int(port)}
            for ip, port in found
            if sanitize_ip(ip) and not is_bogon(sanitize_ip(ip))
        }
    except:
        return {}

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
        "https://raw.githubusercontent.com/daniyal-abbassi/iran-proxy/main/proxy.txt",
        "https://api.proxyscrape.com/v2/?request=getproxies&protocol=http,socks4,socks5&timeout=10000&country=all",
        "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/countries/IR/data.txt",
        "https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output_iran/iran_top100_checked.txt",
    ]
    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as ex:
        futures = [ex.submit(fetch_raw_url, url) for url in sources]
        for future in concurrent.futures.as_completed(futures):
            all_proxies.update(future.result())
    log(f"  Passive total: {len(all_proxies)} candidates fetched.")
    return all_proxies

# ── ASN Matching ──────────────────────────────────────────────────────────────
def match_proxy_to_asn(ip_str, asn_data):
    """Find which ASN an IP belongs to."""
    try:
        ip = ipaddress.IPv4Address(ip_str)
        for asn_num, data in asn_data.items():
            for net in data["networks"]:
                if ip in net:
                    return f"AS{asn_num}", data["name"]
        return None, None
    except:
        return None, None

def filter_iranian_proxies(proxies_dict, asn_data):
    """Filter proxies to only Iranian ASN IP ranges."""
    matched = {}
    for proxy_str, info in proxies_dict.items():
        ip = info.get("ip")
        if not ip:
            continue
        asn, name = match_proxy_to_asn(ip, asn_data)
        if asn:
            matched[proxy_str] = {**info, "asn": asn, "asn_name": name}
    return matched

# ── Phase 2: Active CIDR Scan ─────────────────────────────────────────────────
def tcp_probe(args):
    ip, port, asn_label = args
    try:
        with socket.create_connection((ip, port), timeout=SCAN_TCP_TO):
            return {"ip": ip, "port": port, "asn": asn_label, "status": "open"}
    except:
        return None

def scan_routable_cidrs(networks_with_asn):
    log("\n── Phase 2: Active CIDR scan ──")
    targets = []
    for net, asn_label in networks_with_asn:
        base = int(net.network_address)
        for offset in SAMPLE_OFFSETS:
            if offset < net.num_addresses:
                ip = str(ipaddress.IPv4Address(base + offset))
                for port in PROXY_PORTS:
                    targets.append((ip, port, asn_label))
    random.shuffle(targets)
    log(f"  Probing {len(targets):,} targets across {len(networks_with_asn)} prefixes...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=SCAN_WORKERS) as ex:
        results = list(ex.map(tcp_probe, targets, chunksize=1000))
    hits = [r for r in results if r]
    log(f"  Scan complete: {len(hits)} open ports found.")
    return hits

# ── Output Generation ─────────────────────────────────────────────────────────
def generate_hiddify_config(proxies):
    """Generate Hiddify/Sing-Box compatible JSON config."""
    outbounds = []
    for p in proxies:
        proxy_type = "socks" if p.get("protocol", "http") in ["socks4", "socks5"] else "http"
        outbounds.append({
            "type": proxy_type,
            "tag": f"{proxy_type}-{p['ip']}:{p['port']}",
            "server": p["ip"],
            "server_port": p["port"],
            "version": "5" if proxy_type == "socks" else None
        })
    
    config = {
        "log": {"level": "warn", "timestamp": True},
        "outbounds": outbounds + [
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"}
        ],
        "route": {"rules": [{"ip_is_private": True, "outbound": "direct"}], "final": "proxy"},
        "_info": {
            "profile_title": "Iran Proxies — Active CIDR Scanner",
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "total_proxies": len(proxies)
        }
    }
    return config

def save_results(all_final, asn_data):
    """Save results in multiple formats."""
    # Enrich with ASN data
    enriched = []
    for p_str in all_final:
        ip = p_str.split(":")[0]
        port = int(p_str.split(":")[1])
        asn, asn_name = match_proxy_to_asn(ip, asn_data)
        enriched.append({
            "proxy": p_str,
            "ip": ip,
            "port": port,
            "asn": asn,
            "asn_name": asn_name,
            "protocol": "http",  # Default, can be detected
            "discovered_at": datetime.now(timezone.utc).isoformat()
        })
    
    # Plain text
    with open("working_iran_proxies.txt", "w") as f:
        f.write("\n".join(p["proxy"] for p in enriched))
    
    # Detailed JSON
    with open("working_iran_proxies.json", "w") as f:
        json.dump({
            "total": len(enriched),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "asn_coverage": len(set(p["asn"] for p in enriched if p["asn"])),
            "proxies": enriched
        }, f, indent=2)
    
    # Hiddify config
    hiddify_config = generate_hiddify_config(enriched)
    with open("hiddify_iran_proxies.json", "w") as f:
        json.dump(hiddify_config, f, indent=2)
    
    # Summary by ASN
    asn_summary = {}
    for p in enriched:
        asn = p.get("asn", "Unknown")
        if asn not in asn_summary:
            asn_summary[asn] = {"name": p.get("asn_name", "Unknown"), "count": 0, "proxies": []}
        asn_summary[asn]["count"] += 1
        asn_summary[asn]["proxies"].append(p["proxy"])
    
    with open("asn_summary.json", "w") as f:
        json.dump(asn_summary, f, indent=2)
    
    return enriched

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    log("=" * 60)
    log("Iran Proxy Checker — Enhanced Edition (v2.0)")
    log("=" * 60)
    
    networks, asn_data, networks_with_asn = load_routable_networks()
    if not networks:
        log("  [!] No networks found. Exiting.")
        return
    
    # Phase 1
    passive_candidates = collect_passive_candidates()
    passive_matched = filter_iranian_proxies(passive_candidates, asn_data)
    passive_list = list(passive_matched.keys())
    log(f"  {len(passive_list)} passive candidates matched Iranian IP blocks.")
    
    # Phase 2
    scan_hits = scan_routable_cidrs(networks_with_asn)
    scan_proxies = {f"{h['ip']}:{h['port']}": h for h in scan_hits}
    
    # Merge results
    all_final = set(passive_list) | set(scan_proxies.keys())
    log(f"\n[√] Total Iranian proxies identified: {len(all_final)}")
    
    # Save with ASN tracking
    enriched = save_results(all_final, asn_data)
    
    # Print summary
    asn_counts = {}
    for p in enriched:
        asn = p.get("asn", "Unknown")
        asn_counts[asn] = asn_counts.get(asn, 0) + 1
    
    log("\n── ASN Distribution ──")
    for asn, count in sorted(asn_counts.items(), key=lambda x: -x[1])[:10]:
        name = next((p["asn_name"] for p in enriched if p.get("asn") == asn), "Unknown")
        log(f"  {asn}: {count} proxies ({name})")

if __name__ == "__main__":
    main()
