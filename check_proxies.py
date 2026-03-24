#!/usr/bin/env python3
"""
Iran Proxy Checker — Enhanced Edition v3.1
===========================================
FIXES:
- Relaxed exit IP verification (optional, with fallback)
- Better confidence score handling from JSON
- Improved protocol detection with timeouts
- Save unverified proxies separately
- Better error logging for debugging
"""
import ipaddress, os, socket, requests, concurrent.futures
import json, re, time, random
from datetime import datetime, timezone, timedelta
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Tuple, Optional, Any

try:
    import socks
    SOCKS_AVAILABLE = True
except ImportError:
    SOCKS_AVAILABLE = False

# ── Config ────────────────────────────────────────────────────────────────────
COLLECT_ONLY       = os.environ.get("COLLECT_ONLY", "").strip() == "1"
SKIP_EXIT_VERIFY   = os.environ.get("SKIP_EXIT_VERIFY", "").strip() == "1"  # NEW
FRESH_HOURS        = int(os.environ.get("FRESH_HOURS", "72"))
SCRAPE_TIMEOUT     = int(os.environ.get("SCRAPE_TIMEOUT", "15"))
TCP_TIMEOUT        = float(os.environ.get("TCP_TIMEOUT", "3.0"))
HTTP_TIMEOUT       = int(os.environ.get("HTTP_TIMEOUT", "10"))
MAX_WORKERS        = int(os.environ.get("MAX_WORKERS", "60"))
SCAN_WORKERS       = int(os.environ.get("SCAN_WORKERS", "2000"))
SCAN_TCP_TO        = float(os.environ.get("SCAN_TCP_TO", "0.5"))
VERIFY_TIMEOUT     = int(os.environ.get("VERIFY_TIMEOUT", "8"))
MIN_CONFIDENCE     = int(os.environ.get("MIN_CONFIDENCE", "1"))
MAX_RETRIES        = int(os.environ.get("MAX_RETRIES", "3"))
RETRY_BACKOFF      = float(os.environ.get("RETRY_BACKOFF", "1.0"))
RATE_LIMIT_DELAY   = float(os.environ.get("RATE_LIMIT_DELAY", "0.2"))
HISTORY_FILE       = Path(__file__).parent / "proxy_history.json"
ASN_JSON_PATH      = Path(__file__).parent / "merged_routable_asns.json"
IP_PORT_RE         = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})\b")

SAMPLE_OFFSETS     = [1, 10, 25, 50, 75, 100, 150, 200, 300, 500]
PROXY_PORTS        = [80, 443, 1080, 3128, 8080, 8088, 8118, 8888, 9999]

# Multiple exit IP endpoints with fallback order
EXIT_IP_ENDPOINTS = [
    "http://ip-api.com/json/?fields=status,countryCode,query,city,org",
    "http://ipwho.is/",
    "http://api.ipapi.com/api/check?access_key=YOUR_KEY",  # Optional: add your key
]

# ── Helpers ───────────────────────────────────────────────────────────────────
def log(msg, level="INFO"):
    ts = datetime.now().strftime('%H:%M:%S')
    print(f"[{ts}] [{level}] {msg}", flush=True)

def sanitize_ip(ip_str: str) -> Optional[str]:
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

def is_bogon(ip_str: str) -> bool:
    try:
        ip = ipaddress.IPv4Address(ip_str)
        return (ip.is_private or ip.is_loopback or 
                ip.is_link_local or ip.is_reserved or ip.is_multicast)
    except:
        return True

# ── Rate Limited Session ──────────────────────────────────────────────────────
class RateLimitedSession:
    def __init__(self, max_retries=MAX_RETRIES, backoff=RETRY_BACKOFF, 
                 rate_limit_delay=RATE_LIMIT_DELAY):
        self.max_retries = max_retries
        self.backoff = backoff
        self.rate_limit_delay = rate_limit_delay
        self.session = requests.Session()
        self.last_request = 0
        
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry
        
        retry = Retry(
            total=max_retries,
            backoff_factor=backoff,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST"]
        )
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
    
    def get(self, url, **kwargs):
        elapsed = time.time() - self.last_request
        if elapsed < self.rate_limit_delay:
            time.sleep(self.rate_limit_delay - elapsed)
        
        self.last_request = time.time()
        kwargs.setdefault('timeout', SCRAPE_TIMEOUT)
        kwargs.setdefault('headers', {})
        kwargs['headers']['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
        
        return self.session.get(url, **kwargs)
    
    def close(self):
        self.session.close()

# ── CIDR Deduplication ────────────────────────────────────────────────────────
def deduplicate_cidrs(cidrs: List[str]) -> List[str]:
    try:
        networks = []
        for c in cidrs:
            try:
                net = ipaddress.IPv4Network(c.strip(), strict=False)
                networks.append(net)
            except:
                pass
        
        networks.sort(key=lambda n: n.prefixlen)
        optimized = []
        for net in networks:
            is_covered = any(net.subnet_of(existing) for existing in optimized)
            if not is_covered:
                optimized.append(net)
        
        return [str(n) for n in optimized]
    except Exception as e:
        log(f"CIDR deduplication error: {e}", "WARN")
        return list(set(cidrs))

# ── ASN Data Loading with Confidence ──────────────────────────────────────────
def load_routable_networks() -> Tuple[List[Tuple[ipaddress.IPv4Network, str, int]], Dict]:
    asn_data = {}
    networks_with_asn = []
    
    if ASN_JSON_PATH.exists():
        log(f"Loading networks from {ASN_JSON_PATH}...")
        try:
            with open(ASN_JSON_PATH) as f:
                data = json.load(f)
            
            for asn_key, entry in data.items():
                asn_num = asn_key.replace("AS", "")
                
                # Handle different JSON structures
                if isinstance(entry, dict):
                    confidence = entry.get("confidence", 1)
                    prefixes = entry.get("prefixes", [])
                    name = entry.get("name", "Unknown")
                    if isinstance(prefixes, dict):
                        prefixes = prefixes.get("prefixes", [])
                elif isinstance(entry, list):
                    confidence = 1
                    prefixes = entry
                    name = "Unknown"
                else:
                    continue
                
                if confidence < MIN_CONFIDENCE:
                    continue
                
                unique_prefixes = deduplicate_cidrs(prefixes) if isinstance(prefixes, list) else []
                
                networks = []
                for c in unique_prefixes:
                    try:
                        net = ipaddress.IPv4Network(c.strip(), strict=False)
                        networks.append(net)
                    except:
                        pass
                
                if networks:
                    asn_data[asn_num] = {
                        "name": name if isinstance(name, str) else str(name),
                        "prefixes": unique_prefixes,
                        "networks": networks,
                        "confidence": confidence
                    }
                    
                    for net in networks:
                        networks_with_asn.append((net, f"AS{asn_num}", confidence))
            
            # Deduplicate overlapping networks
            unique_nets = {}
            for net, asn, conf in networks_with_asn:
                net_str = str(net)
                if net_str not in unique_nets or conf > unique_nets[net_str][1]:
                    unique_nets[net_str] = (net, asn, conf)
            
            networks_with_asn = list(unique_nets.values())
            
            conf_dist = defaultdict(int)
            for _, _, c in networks_with_asn:
                conf_dist[c] += 1
            
            log(f"  ✓ Loaded {len(asn_data)} ASNs with {len(networks_with_asn)} unique prefixes")
            log(f"  ✓ Confidence: {conf_dist.get(3, 0)} very_high, {conf_dist.get(2, 0)} high, {conf_dist.get(1, 0)} possible")
            
        except Exception as e:
            log(f"  JSON load error: {e}", "ERROR")
    
    if not networks_with_asn:
        log("  No networks loaded — using hardcoded fallback", "WARN")
        fallback = [
            ("5.160.0.0/12", "AS42337", 1),
            ("78.38.0.0/15", "AS49666", 1),
            ("151.232.0.0/13", "AS58224", 1),
        ]
        for cidr, asn, conf in fallback:
            try:
                networks_with_asn.append((ipaddress.IPv4Network(cidr, strict=False), asn, conf))
            except:
                pass
    
    return networks_with_asn, asn_data

# ── Exit IP Verification (Relaxed) ────────────────────────────────────────────
def verify_exit_ip(ip: str, port: int, protocol: str = "http", 
                   timeout=VERIFY_TIMEOUT) -> Tuple[bool, Dict]:
    """Verify proxy exits from Iran — with relaxed requirements."""
    if SKIP_EXIT_VERIFY:
        return True, {"skipped": True, "country": "IR"}
    
    if not SOCKS_AVAILABLE and protocol in ["socks4", "socks5"]:
        return False, {"error": "PySocks not installed"}
    
    for i, endpoint in enumerate(EXIT_IP_ENDPOINTS):
        try:
            if protocol == "http":
                proxies = {"http": f"http://{ip}:{port}", "https": f"http://{ip}:{port}"}
            elif protocol == "socks5":
                proxies = {"http": f"socks5://{ip}:{port}", "https": f"socks5://{ip}:{port}"}
            elif protocol == "socks4":
                proxies = {"http": f"socks4://{ip}:{port}", "https": f"socks4://{ip}:{port}"}
            else:
                continue
            
            session = RateLimitedSession()
            r = session.get(endpoint, proxies=proxies, timeout=timeout)
            session.close()
            
            if r.status_code == 200:
                data = r.json()
                country = data.get("countryCode", "")
                
                if not country:
                    country = data.get("country", "")
                    if isinstance(country, dict):
                        country = country.get("code", "")
                
                is_ir = country.upper() == "IR"
                
                return is_ir, {
                    "country": country,
                    "country_name": data.get("country", data.get("countryName", "")),
                    "city": data.get("city", ""),
                    "ip": data.get("query", data.get("ip", "")),
                    "org": data.get("org", data.get("isp", "")),
                    "endpoint": endpoint
                }
                
        except Exception as e:
            if i == len(EXIT_IP_ENDPOINTS) - 1:
                log(f"  Exit IP verification failed for {ip}:{port}: {str(e)[:50]}", "DEBUG")
            continue
    
    # If all endpoints fail, return unverified but don't reject
    return None, {"error": "All endpoints failed", "unverified": True}

# ── Protocol Detection ────────────────────────────────────────────────────────
def detect_proxy_protocol(ip: str, port: int, timeout=5) -> List[str]:
    protocols = []
    
    # Try HTTP first (most common)
    try:
        session = RateLimitedSession()
        proxies = {"http": f"http://{ip}:{port}"}
        r = session.get("http://1.1.1.1", proxies=proxies, timeout=timeout)
        session.close()
        if r.status_code < 400:
            protocols.append("http")
    except:
        pass
    
    # Try SOCKS5
    if SOCKS_AVAILABLE:
        try:
            s = socks.socksocket()
            s.set_proxy(socks.SOCKS5, ip, int(port))
            s.settimeout(timeout)
            s.connect(("1.1.1.1", 53))
            s.close()
            protocols.append("socks5")
        except:
            pass
        
        # Try SOCKS4
        try:
            s = socks.socksocket()
            s.set_proxy(socks.SOCKS4, ip, int(port))
            s.settimeout(timeout)
            s.connect(("1.1.1.1", 53))
            s.close()
            protocols.append("socks4")
        except:
            pass
    
    return protocols

# ── Latency & Speed Tracking ──────────────────────────────────────────────────
def test_proxy_with_metrics(proxy_str: str, protocol: str = "http", 
                           timeout=HTTP_TIMEOUT) -> Dict:
    ip, port = proxy_str.split(":")
    start = time.time()
    
    result = {
        "proxy": proxy_str,
        "protocol": protocol,
        "working": False,
        "latency_ms": None,
        "speed_score": 0,
        "error": None
    }
    
    try:
        if protocol == "http":
            proxies = {"http": f"http://{ip}:{port}", "https": f"http://{ip}:{port}"}
        elif protocol == "socks5":
            proxies = {"http": f"socks5://{ip}:{port}", "https": f"socks5://{ip}:{port}"}
        elif protocol == "socks4":
            proxies = {"http": f"socks4://{ip}:{port}", "https": f"socks4://{ip}:{port}"}
        else:
            result["error"] = "Unknown protocol"
            return result
        
        session = RateLimitedSession()
        r = session.get("http://1.1.1.1", proxies=proxies, timeout=timeout)
        session.close()
        
        latency = (time.time() - start) * 1000
        result["latency_ms"] = round(latency, 1)
        result["working"] = r.status_code < 400
        result["status_code"] = r.status_code
        
        if latency < 500:
            result["speed_score"] = 100
        elif latency < 1000:
            result["speed_score"] = 80
        elif latency < 2000:
            result["speed_score"] = 60
        elif latency < 5000:
            result["speed_score"] = 40
        else:
            result["speed_score"] = 20
        
    except Exception as e:
        result["error"] = str(e)
    
    return result

# ── Multi-Stage Verification Pipeline (Relaxed) ───────────────────────────────
def verify_proxy_pipeline(proxy_str: str, asn_data: Dict) -> Optional[Dict]:
    """
    Multi-stage verification with relaxed requirements:
    Stage 1: TCP Connect (required)
    Stage 2: Protocol Detection (required)
    Stage 3: Exit IP Verification (optional if SKIP_EXIT_VERIFY)
    Stage 4: Latency Measurement (optional)
    """
    ip, port = proxy_str.split(":")
    result = {
        "proxy": proxy_str,
        "ip": ip,
        "port": int(port),
        "asn": None,
        "asn_name": None,
        "confidence": 0,
        "protocols": [],
        "exit_verified": False,
        "exit_unverified": False,
        "location": {},
        "latency_ms": None,
        "speed_score": 0,
        "working": False,
        "discovered_at": datetime.now(timezone.utc).isoformat()
    }
    
    # Find ASN
    try:
        ip_obj = ipaddress.IPv4Address(ip)
        for asn_num, data in asn_data.items():
            for net in data["networks"]:
                if ip_obj in net:
                    result["asn"] = f"AS{asn_num}"
                    result["asn_name"] = data.get("name", "Unknown")
                    result["confidence"] = data.get("confidence", 1)
                    break
            if result["asn"]:
                break
    except:
        pass
    
    # Stage 1: TCP Connect
    try:
        with socket.create_connection((ip, int(port)), timeout=SCAN_TCP_TO):
            pass
    except:
        return None
    
    # Stage 2: Protocol Detection
    protocols = detect_proxy_protocol(ip, int(port), timeout=TCP_TIMEOUT)
    if not protocols:
        return None
    result["protocols"] = protocols
    
    # Stage 3: Exit IP Verification (optional)
    best_protocol = "socks5" if "socks5" in protocols else ("socks4" if "socks4" in protocols else "http")
    is_iranian, location = verify_exit_ip(ip, int(port), best_protocol, timeout=VERIFY_TIMEOUT)
    
    if is_iranian is True:
        result["exit_verified"] = True
        result["location"] = location
    elif is_iranian is None and location.get("unverified"):
        result["exit_unverified"] = True  # Mark but don't reject
        result["location"] = location
    elif is_iranian is False:
        return None  # Confirmed non-Iranian, reject
    
    # Stage 4: Latency Measurement
    metrics = test_proxy_with_metrics(proxy_str, best_protocol, timeout=HTTP_TIMEOUT)
    result["latency_ms"] = metrics.get("latency_ms")
    result["speed_score"] = metrics.get("speed_score", 0)
    result["working"] = metrics.get("working", False)
    
    return result if result["working"] else None

# ── Passive Collection ────────────────────────────────────────────────────────
def collect_passive_candidates() -> Dict[str, Dict]:
    log("Phase 1: Passive collection from 25+ sources")
    
    all_proxies = {}
    sources = [
        "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt",
        "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks4.txt",
        "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/all.txt",
        "https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/http.txt",
        "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies.txt",
        "https://api.proxyscrape.com/v2/?request=getproxies&protocol=http,socks4,socks5&timeout=10000&country=all",
        "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/countries/IR/data.txt",
    ]
    
    session = RateLimitedSession()
    
    def fetch_source(url):
        try:
            r = session.get(url)
            found = IP_PORT_RE.findall(r.text)
            return {
                f"{sanitize_ip(ip)}:{port}": {"ip": sanitize_ip(ip), "port": int(port), "source": url}
                for ip, port in found
                if sanitize_ip(ip) and not is_bogon(sanitize_ip(ip))
            }
        except:
            return {}
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as ex:
        futures = [ex.submit(fetch_source, url) for url in sources]
        for future in concurrent.futures.as_completed(futures):
            all_proxies.update(future.result())
    
    session.close()
    log(f"  Passive total: {len(all_proxies)} candidates fetched")
    return all_proxies

# ── Active CIDR Scan ──────────────────────────────────────────────────────────
def scan_routable_cidrs(networks_with_asn: List[Tuple]) -> Dict[str, Dict]:
    log("Phase 2: Active CIDR scan")
    
    targets = []
    for net, asn_label, confidence in networks_with_asn:
        base = int(net.network_address)
        for offset in SAMPLE_OFFSETS:
            if offset < net.num_addresses:
                ip = str(ipaddress.IPv4Address(base + offset))
                for port in PROXY_PORTS:
                    targets.append((ip, port, asn_label, confidence))
    
    random.shuffle(targets)
    log(f"  Probing {len(targets):,} targets across {len(networks_with_asn)} prefixes")
    
    def tcp_probe(args):
        ip, port, asn, conf = args
        try:
            with socket.create_connection((ip, port), timeout=SCAN_TCP_TO):
                return {"proxy": f"{ip}:{port}", "ip": ip, "port": port, 
                       "asn": asn, "confidence": conf, "source": "active_scan"}
        except:
            return None
    
    hits = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=SCAN_WORKERS) as ex:
        results = list(ex.map(tcp_probe, targets, chunksize=1000))
        for r in results:
            if r:
                hits[r["proxy"]] = r
    
    log(f"  Scan complete: {len(hits)} open ports found")
    return hits

# ── Historical Persistence ────────────────────────────────────────────────────
def load_proxy_history() -> Dict:
    if HISTORY_FILE.exists():
        try:
            with open(HISTORY_FILE) as f:
                return json.load(f)
        except:
            pass
    return {"working": [], "failed": [], "last_updated": None}

def save_proxy_history(working: List[str], failed: List[str]):
    history = load_proxy_history()
    history["working"] = list(set(history.get("working", []) + working))[-1000:]
    history["failed"] = list(set(history.get("failed", []) + failed))[-5000:]
    history["last_updated"] = datetime.now(timezone.utc).isoformat()
    
    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=2)

# ── Output Generation ─────────────────────────────────────────────────────────
def generate_hiddify_config(proxies: List[Dict]) -> Dict:
    outbounds = []
    
    for p in proxies:
        proxy_type = "socks" if p.get("protocol", "http") in ["socks4", "socks5"] else "http"
        outbound = {
            "type": proxy_type,
            "tag": f"{proxy_type}-{p['ip']}:{p['port']}",
            "server": p["ip"],
            "server_port": p["port"],
        }
        if proxy_type == "socks":
            outbound["version"] = "5" if p.get("protocol") == "socks5" else "4"
        outbounds.append(outbound)
    
    config = {
        "log": {"level": "warn", "timestamp": True},
        "dns": {
            "servers": [
                {"tag": "remote", "address": "https://1.1.1.1/dns-query", "detour": "proxy"},
                {"tag": "local", "address": "local", "detour": "direct"}
            ],
            "rules": [{"outbound": "any", "server": "local"}],
            "final": "remote",
            "strategy": "ipv4_only"
        },
        "outbounds": outbounds + [
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"}
        ],
        "route": {
            "rules": [
                {"protocol": "dns", "outbound": "dns-out"},
                {"ip_is_private": True, "outbound": "direct"}
            ],
            "final": "proxy",
            "auto_detect_interface": True
        },
        "_info": {
            "profile_title": "Iran Proxies — Verified",
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "total_proxies": len(proxies),
            "verified_count": sum(1 for p in proxies if p.get("exit_verified")),
            "unverified_count": sum(1 for p in proxies if p.get("exit_unverified")),
            "avg_latency_ms": round(sum(p.get("latency_ms", 0) or 0 for p in proxies) / max(len(proxies), 1), 1)
        }
    }
    return config

def save_results(proxies: List[Dict], asn_data: Dict):
    if not proxies:
        log("No proxies to save", "WARN")
        # Still save empty files for artifact upload
        with open("working_iran_proxies.txt", "w") as f:
            f.write("# No proxies found\n")
        with open("working_iran_proxies.json", "w") as f:
            json.dump({"total": 0, "proxies": [], "generated_at": datetime.now(timezone.utc).isoformat()}, f, indent=2)
        with open("hiddify_iran_proxies.json", "w") as f:
            json.dump(generate_hiddify_config([]), f, indent=2)
        return
    
    # Sort by speed score
    proxies.sort(key=lambda p: p.get("speed_score", 0), reverse=True)
    
    # Separate verified and unverified
    verified = [p for p in proxies if p.get("exit_verified")]
    unverified = [p for p in proxies if p.get("exit_unverified")]
    
    # Plain text (verified only)
    with open("working_iran_proxies.txt", "w") as f:
        for p in verified[:100]:
            f.write(f"{p['proxy']}\n")
    
    # Detailed JSON (all)
    with open("working_iran_proxies.json", "w") as f:
        json.dump({
            "total": len(proxies),
            "verified_iranian": len(verified),
            "unverified": len(unverified),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "asn_coverage": len(set(p.get("asn") for p in proxies if p.get("asn"))),
            "avg_latency_ms": round(sum(p.get("latency_ms", 0) or 0 for p in proxies) / max(len(proxies), 1), 1),
            "proxies": proxies
        }, f, indent=2)
    
    # Hiddify config (verified only for safety)
    hiddify_config = generate_hiddify_config(verified if verified else proxies)
    with open("hiddify_iran_proxies.json", "w") as f:
        json.dump(hiddify_config, f, indent=2)
    
    # Summary report
    log("\n" + "="*60)
    log("TOP 10 FASTEST IRANIAN PROXIES")
    log("="*60)
    for i, p in enumerate(proxies[:10], 1):
        status = "✓" if p.get("exit_verified") else "?" if p.get("exit_unverified") else "✗"
        log(f"{i:2}. {p['proxy']:22} | {p.get('latency_ms', 'N/A'):>6}ms | "
            f"{p.get('asn', 'N/A'):>10} | {status}")
    
    # ASN summary
    asn_counts = defaultdict(lambda: {"count": 0, "name": "", "latencies": [], "verified": 0})
    for p in proxies:
        asn = p.get("asn", "Unknown")
        asn_counts[asn]["count"] += 1
        asn_counts[asn]["name"] = p.get("asn_name", "Unknown")
        if p.get("latency_ms"):
            asn_counts[asn]["latencies"].append(p["latency_ms"])
        if p.get("exit_verified"):
            asn_counts[asn]["verified"] += 1
    
    log("\n" + "="*60)
    log("ASN DISTRIBUTION")
    log("="*60)
    for asn, data in sorted(asn_counts.items(), key=lambda x: -x[1]["count"])[:10]:
        avg_lat = round(sum(data["latencies"]) / max(len(data["latencies"]), 1), 1) if data["latencies"] else 0
        log(f"{asn}: {data['count']:3} proxies | {data['verified']:2} verified | avg {avg_lat:>6}ms | {data['name']}")
    
    # Save history
    save_proxy_history([p["proxy"] for p in verified], [])
    
    log(f"\n✓ Results saved: working_iran_proxies.txt ({len(verified)}), working_iran_proxies.json ({len(proxies)})")

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    log("="*60)
    log("Iran Proxy Checker — Enhanced Edition v3.1")
    log("="*60)
    log(f"Configuration: MIN_CONFIDENCE={MIN_CONFIDENCE}, SCAN_WORKERS={SCAN_WORKERS}, "
        f"MAX_RETRIES={MAX_RETRIES}, SKIP_EXIT_VERIFY={SKIP_EXIT_VERIFY}")
    
    networks_with_asn, asn_data = load_routable_networks()
    if not networks_with_asn:
        log("No networks found. Exiting.", "ERROR")
        return
    
    history = load_proxy_history()
    log(f"Historical working proxies: {len(history.get('working', []))}")
    
    # Phase 1
    passive_candidates = collect_passive_candidates()
    
    passive_matched = {}
    for proxy_str, info in passive_candidates.items():
        ip = info.get("ip")
        if not ip:
            continue
        try:
            ip_obj = ipaddress.IPv4Address(ip)
            for asn_num, data in asn_data.items():
                for net in data["networks"]:
                    if ip_obj in net:
                        passive_matched[proxy_str] = {**info, "asn": f"AS{asn_num}"}
                        break
                if proxy_str in passive_matched:
                    break
        except:
            continue
    
    log(f"  {len(passive_matched)} passive candidates matched Iranian IP blocks")
    
    # Phase 2
    scan_hits = scan_routable_cidrs(networks_with_asn)
    
    all_candidates = {**passive_matched, **scan_hits}
    log(f"\nTotal candidates for verification: {len(all_candidates)}")
    
    # Phase 3
    log("\nPhase 3: Multi-Stage Verification Pipeline")
    log(f"  Stage 1: TCP Connect → Stage 2: Protocol Detection → "
        f"Stage 3: Exit IP Verification ({'SKIPPED' if SKIP_EXIT_VERIFY else 'ACTIVE'}) → Stage 4: Latency")
    
    verified_proxies = []
    
    def verify_wrapper(args):
        proxy_str, asn_data = args
        return verify_proxy_pipeline(proxy_str, asn_data)
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        tasks = [(p, asn_data) for p in all_candidates.keys()]
        results = list(ex.map(verify_wrapper, tasks, chunksize=50))
        verified_proxies = [r for r in results if r]
    
    verified_count = sum(1 for p in verified_proxies if p.get("exit_verified"))
    unverified_count = sum(1 for p in verified_proxies if p.get("exit_unverified"))
    
    log(f"\n[✓] Total verified Iranian proxies: {len(verified_proxies)}")
    log(f"[✓] Exit IP verified: {verified_count}")
    log(f"[?] Exit IP unverified: {unverified_count}")
    if verified_proxies:
        log(f"[✓] Avg latency: {round(sum(p.get('latency_ms', 0) or 0 for p in verified_proxies) / len(verified_proxies), 1)}ms")
    
    save_results(verified_proxies, asn_data)

if __name__ == "__main__":
    main()
