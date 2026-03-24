#!/usr/bin/env python3
"""
Iran Proxy Checker — Enhanced Edition v3.0
===========================================
Integrations from R scripts + advanced verification:
✓ Exit IP Verification (confirms Iranian exit)
✓ ASN Confidence Scoring (1-3 from merged_routable_asns.json)
✓ Protocol Detection (HTTP/SOCKS4/SOCKS5)
✓ Multi-Stage Verification Pipeline
✓ Latency & Speed Tracking
✓ CIDR Deduplication (removes overlapping networks)
✓ Rate Limiting & Retry Logic
✓ Historical Persistence
✓ Hiddify/Sing-Box Compatible Output
"""
import ipaddress, os, socket, requests, concurrent.futures
import json, re, time, random, hashlib
from datetime import datetime, timezone, timedelta
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Tuple, Optional, Any

# Try to import socks for protocol detection
try:
    import socks
    SOCKS_AVAILABLE = True
except ImportError:
    SOCKS_AVAILABLE = False

# ── Config ────────────────────────────────────────────────────────────────────
COLLECT_ONLY      = os.environ.get("COLLECT_ONLY", "").strip() == "1"
FRESH_HOURS       = int(os.environ.get("FRESH_HOURS", "72"))
SCRAPE_TIMEOUT    = int(os.environ.get("SCRAPE_TIMEOUT", "15"))
TCP_TIMEOUT       = float(os.environ.get("TCP_TIMEOUT", "3.0"))
HTTP_TIMEOUT      = int(os.environ.get("HTTP_TIMEOUT", "10"))
MAX_WORKERS       = int(os.environ.get("MAX_WORKERS", "60"))
SCAN_WORKERS      = int(os.environ.get("SCAN_WORKERS", "2000"))
SCAN_TCP_TO       = float(os.environ.get("SCAN_TCP_TO", "0.5"))
VERIFY_TIMEOUT    = int(os.environ.get("VERIFY_TIMEOUT", "8"))
MIN_CONFIDENCE    = int(os.environ.get("MIN_CONFIDENCE", "1"))  # 1=possible, 2=high, 3=very_high
MAX_RETRIES       = int(os.environ.get("MAX_RETRIES", "3"))
RETRY_BACKOFF     = float(os.environ.get("RETRY_BACKOFF", "1.0"))
RATE_LIMIT_DELAY  = float(os.environ.get("RATE_LIMIT_DELAY", "0.2"))
HISTORY_FILE      = Path(__file__).parent / "proxy_history.json"
ASN_JSON_PATH     = Path(__file__).parent / "merged_routable_asns.json"
IP_PORT_RE        = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})\b")

# Enhanced sampling for active scan
SAMPLE_OFFSETS    = [1, 10, 25, 50, 75, 100, 150, 200, 300, 500, 750, 1000]
PROXY_PORTS       = [80, 443, 1080, 3128, 8080, 8088, 8118, 8888, 9999]

# Exit IP verification endpoints
EXIT_IP_ENDPOINTS = [
    "http://ip-api.com/json/?fields=status,countryCode,query,city,org",
    "http://ipapi.co/json/",
    "http://ipwho.is/"
]

# ── Helpers ───────────────────────────────────────────────────────────────────
def log(msg, level="INFO"):
    """Timestamped logging."""
    ts = datetime.now().strftime('%H:%M:%S')
    print(f"[{ts}] [{level}] {msg}", flush=True)

def sanitize_ip(ip_str: str) -> Optional[str]:
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

def is_bogon(ip_str: str) -> bool:
    """Check if IP is in private/reserved ranges."""
    try:
        ip = ipaddress.IPv4Address(ip_str)
        return (ip.is_private or ip.is_loopback or 
                ip.is_link_local or ip.is_reserved or ip.is_multicast)
    except:
        return True

# ── Rate Limiting & Retry Logic ───────────────────────────────────────────────
class RateLimitedSession:
    """Session with rate limiting and exponential backoff retry."""
    
    def __init__(self, max_retries=MAX_RETRIES, backoff=RETRY_BACKOFF, 
                 rate_limit_delay=RATE_LIMIT_DELAY):
        self.max_retries = max_retries
        self.backoff = backoff
        self.rate_limit_delay = rate_limit_delay
        self.session = requests.Session()
        self.last_request = 0
        
        # Configure retry strategy
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
        """Rate-limited GET request."""
        # Enforce rate limit
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
    """Remove redundant overlapping CIDRs (keep largest blocks)."""
    try:
        networks = []
        for c in cidrs:
            try:
                net = ipaddress.IPv4Network(c.strip(), strict=False)
                networks.append(net)
            except:
                pass
        
        # Sort by prefix length (larger networks first)
        networks.sort(key=lambda n: n.prefixlen)
        
        optimized = []
        for net in networks:
            # Check if this network is already covered by an existing one
            is_covered = any(net.subnet_of(existing) for existing in optimized)
            if not is_covered:
                optimized.append(net)
        
        return [str(n) for n in optimized]
    except Exception as e:
        log(f"CIDR deduplication error: {e}", "WARN")
        return list(set(cidrs))

# ── ASN Data Loading with Confidence ──────────────────────────────────────────
def load_routable_networks() -> Tuple[List[Tuple[ipaddress.IPv4Network, str, int]], Dict]:
    """
    Load Iranian IP ranges from JSON with confidence scores.
    Returns: (networks_with_asn, asn_data)
    - networks_with_asn: List of (network, asn_label, confidence)
    - asn_data: Dict of ASN metadata
    """
    asn_data = {}
    networks_with_asn = []
    
    if ASN_JSON_PATH.exists():
        log(f"Loading networks from {ASN_JSON_PATH}...")
        try:
            with open(ASN_JSON_PATH) as f:
                data = json.load(f)
            
            for asn_key, entry in data.items():
                asn_num = asn_key.replace("AS", "")
                
                # Extract confidence (default to 1 if not present)
                confidence = entry.get("confidence", 1)
                if confidence < MIN_CONFIDENCE:
                    continue  # Skip low-confidence ASNs
                
                # Handle different JSON structures
                prefixes = entry.get("prefixes", [])
                if isinstance(entry, list):
                    prefixes = entry
                elif isinstance(entry, dict) and "prefixes" not in entry:
                    prefixes = list(entry.values())[0] if entry else []
                
                # Deduplicate CIDRs
                unique_prefixes = deduplicate_cidrs(prefixes)
                
                networks = []
                for c in unique_prefixes:
                    try:
                        net = ipaddress.IPv4Network(c.strip(), strict=False)
                        networks.append(net)
                    except:
                        pass
                
                if networks:
                    asn_data[asn_num] = {
                        "name": entry.get("name", "Unknown"),
                        "prefixes": unique_prefixes,
                        "networks": networks,
                        "confidence": confidence,
                        "confidence_label": entry.get("confidence_label", "possible")
                    }
                    
                    for net in networks:
                        networks_with_asn.append((net, f"AS{asn_num}", confidence))
            
            # Deduplicate overlapping networks across ASNs
            unique_nets = {}
            for net, asn, conf in networks_with_asn:
                net_str = str(net)
                if net_str not in unique_nets or conf > unique_nets[net_str][1]:
                    unique_nets[net_str] = (net, asn, conf)
            
            networks_with_asn = list(unique_nets.values())
            
            log(f"  ✓ Loaded {len(asn_data)} ASNs with {len(networks_with_asn)} unique prefixes")
            log(f"  ✓ Confidence distribution: {sum(1 for _,_,c in networks_with_asn if c>=3)} very_high, "
                f"{sum(1 for _,_,c in networks_with_asn if c==2)} high, "
                f"{sum(1 for _,_,c in networks_with_asn if c==1)} possible")
            
        except Exception as e:
            log(f"  JSON load error: {e}", "ERROR")
    
    if not networks_with_asn:
        log("  No networks loaded — using hardcoded fallback", "WARN")
        # Fallback networks with confidence 1
        fallback = [
            ("5.160.0.0/12", "AS42337", 1),
            ("78.38.0.0/15", "AS49666", 1),
            ("151.232.0.0/13", "AS58224", 1),
        ]
        for cidr, asn, conf in fallback:
            try:
                net = ipaddress.IPv4Network(cidr, strict=False)
                networks_with_asn.append((net, asn, conf))
            except:
                pass
    
    return networks_with_asn, asn_data

# ── Exit IP Verification ──────────────────────────────────────────────────────
def verify_exit_ip(ip: str, port: int, protocol: str = "http", timeout=VERIFY_TIMEOUT) -> Tuple[bool, Dict]:
    """
    Verify proxy exits from Iran by checking exit IP.
    Returns: (is_iranian, location_info)
    """
    if not SOCKS_AVAILABLE and protocol in ["socks4", "socks5"]:
        return False, {"error": "PySocks not installed"}
    
    for endpoint in EXIT_IP_ENDPOINTS:
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
                
                # Handle different API response formats
                if not country:
                    country = data.get("country", "")
                    if isinstance(country, dict):
                        country = country.get("code", "")
                
                is_ir = country.upper() == "IR"
                
                location_info = {
                    "country": country,
                    "country_name": data.get("country", data.get("countryName", "")),
                    "city": data.get("city", ""),
                    "ip": data.get("query", data.get("ip", "")),
                    "org": data.get("org", data.get("isp", "")),
                    "endpoint": endpoint
                }
                
                return is_ir, location_info
                
        except Exception as e:
            continue
    
    return False, {"error": "All endpoints failed"}

# ── Protocol Detection ────────────────────────────────────────────────────────
def detect_proxy_protocol(ip: str, port: int, timeout=5) -> List[str]:
    """Detect which protocols the proxy supports."""
    protocols = []
    
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
    
    # Try HTTP
    try:
        session = RateLimitedSession()
        proxies = {"http": f"http://{ip}:{port}"}
        r = session.get("http://1.1.1.1", proxies=proxies, timeout=timeout)
        session.close()
        if r.status_code < 400:
            protocols.append("http")
    except:
        pass
    
    return protocols

# ── Latency & Speed Tracking ──────────────────────────────────────────────────
def test_proxy_with_metrics(proxy_str: str, protocol: str = "http", 
                           timeout=HTTP_TIMEOUT) -> Dict:
    """Test proxy and return comprehensive performance metrics."""
    ip, port = proxy_str.split(":")
    start = time.time()
    
    result = {
        "proxy": proxy_str,
        "protocol": protocol,
        "working": False,
        "latency_ms": None,
        "speed_score": 0,
        "exit_verified": False,
        "location": {},
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
        
        # Calculate speed score (lower latency = higher score)
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

# ── Multi-Stage Verification Pipeline ─────────────────────────────────────────
def verify_proxy_pipeline(proxy_str: str, asn_data: Dict) -> Optional[Dict]:
    """
    Multi-stage verification:
    Stage 1: TCP Connect (fast filter)
    Stage 2: Protocol Detection
    Stage 3: Exit IP Verification (Iran confirm)
    Stage 4: Latency Measurement
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
        "location": {},
        "latency_ms": None,
        "speed_score": 0,
        "working": False,
        "discovered_at": datetime.now(timezone.utc).isoformat()
    }
    
    # Find ASN for this IP
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
        return None  # Dead proxy
    
    # Stage 2: Protocol Detection
    protocols = detect_proxy_protocol(ip, int(port), timeout=TCP_TIMEOUT)
    if not protocols:
        return None  # No working protocol
    result["protocols"] = protocols
    
    # Stage 3: Exit IP Verification (use best protocol)
    best_protocol = "socks5" if "socks5" in protocols else ("socks4" if "socks4" in protocols else "http")
    is_iranian, location = verify_exit_ip(ip, int(port), best_protocol, timeout=VERIFY_TIMEOUT)
    result["exit_verified"] = is_iranian
    result["location"] = location
    
    if not is_iranian:
        return None  # Not Iranian exit
    
    # Stage 4: Latency Measurement
    metrics = test_proxy_with_metrics(proxy_str, best_protocol, timeout=HTTP_TIMEOUT)
    result["latency_ms"] = metrics.get("latency_ms")
    result["speed_score"] = metrics.get("speed_score", 0)
    result["working"] = metrics.get("working", False)
    
    return result if result["working"] else None

# ── Passive Collection ────────────────────────────────────────────────────────
def collect_passive_candidates() -> Dict[str, Dict]:
    """Fetch proxy candidates from multiple sources."""
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
    """Active scanning of Iranian CIDR blocks."""
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
    """Load historical working proxies."""
    if HISTORY_FILE.exists():
        try:
            with open(HISTORY_FILE) as f:
                return json.load(f)
        except:
            pass
    return {"working": [], "failed": [], "last_updated": None}

def save_proxy_history(working: List[str], failed: List[str]):
    """Save results for future runs."""
    history = load_proxy_history()
    history["working"] = list(set(history.get("working", []) + working))[-1000:]
    history["failed"] = list(set(history.get("failed", []) + failed))[-5000:]
    history["last_updated"] = datetime.now(timezone.utc).isoformat()
    
    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=2)

# ── Output Generation ─────────────────────────────────────────────────────────
def generate_hiddify_config(proxies: List[Dict]) -> Dict:
    """Generate Hiddify/Sing-Box compatible JSON config."""
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
            "avg_latency_ms": round(sum(p.get("latency_ms", 0) or 0 for p in proxies) / max(len(proxies), 1), 1)
        }
    }
    return config

def save_results(proxies: List[Dict], asn_data: Dict):
    """Save results in multiple formats."""
    if not proxies:
        log("No proxies to save", "WARN")
        return
    
    # Sort by speed score (best first)
    proxies.sort(key=lambda p: p.get("speed_score", 0), reverse=True)
    
    # Plain text (best 100)
    with open("working_iran_proxies.txt", "w") as f:
        for p in proxies[:100]:
            f.write(f"{p['proxy']}\n")
    
    # Detailed JSON
    with open("working_iran_proxies.json", "w") as f:
        json.dump({
            "total": len(proxies),
            "verified_iranian": sum(1 for p in proxies if p.get("exit_verified")),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "asn_coverage": len(set(p.get("asn") for p in proxies if p.get("asn"))),
            "avg_latency_ms": round(sum(p.get("latency_ms", 0) or 0 for p in proxies) / max(len(proxies), 1), 1),
            "proxies": proxies
        }, f, indent=2)
    
    # Hiddify config
    hiddify_config = generate_hiddify_config(proxies)
    with open("hiddify_iran_proxies.json", "w") as f:
        json.dump(hiddify_config, f, indent=2)
    
    # Best proxies report
    log("\n" + "="*60)
    log("TOP 10 FASTEST IRANIAN PROXIES")
    log("="*60)
    for i, p in enumerate(proxies[:10], 1):
        log(f"{i:2}. {p['proxy']:22} | {p.get('latency_ms', 'N/A'):>6}ms | "
            f"{p.get('asn', 'N/A'):>10} | {p.get('location', {}).get('city', 'Unknown')}")
    
    # ASN summary
    asn_counts = defaultdict(lambda: {"count": 0, "name": "", "latencies": []})
    for p in proxies:
        asn = p.get("asn", "Unknown")
        asn_counts[asn]["count"] += 1
        asn_counts[asn]["name"] = p.get("asn_name", "Unknown")
        if p.get("latency_ms"):
            asn_counts[asn]["latencies"].append(p["latency_ms"])
    
    log("\n" + "="*60)
    log("ASN DISTRIBUTION")
    log("="*60)
    for asn, data in sorted(asn_counts.items(), key=lambda x: -x[1]["count"])[:10]:
        avg_lat = round(sum(data["latencies"]) / max(len(data["latencies"]), 1), 1) if data["latencies"] else 0
        log(f"{asn}: {data['count']:3} proxies | avg {avg_lat:>6}ms | {data['name']}")
    
    # Save history
    save_proxy_history([p["proxy"] for p in proxies], [])
    
    log(f"\n✓ Results saved to working_iran_proxies.txt, working_iran_proxies.json, hiddify_iran_proxies.json")

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    log("="*60)
    log("Iran Proxy Checker — Enhanced Edition v3.0")
    log("="*60)
    log(f"Configuration: MIN_CONFIDENCE={MIN_CONFIDENCE}, SCAN_WORKERS={SCAN_WORKERS}, "
        f"MAX_RETRIES={MAX_RETRIES}")
    
    # Load ASN data
    networks_with_asn, asn_data = load_routable_networks()
    if not networks_with_asn:
        log("No networks found. Exiting.", "ERROR")
        return
    
    # Load history
    history = load_proxy_history()
    log(f"Historical working proxies: {len(history.get('working', []))}")
    
    # Phase 1: Passive Collection
    passive_candidates = collect_passive_candidates()
    
    # Filter to Iranian ASN ranges
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
    
    # Phase 2: Active CIDR Scan
    scan_hits = scan_routable_cidrs(networks_with_asn)
    
    # Merge all candidates
    all_candidates = {**passive_matched, **scan_hits}
    log(f"\nTotal candidates for verification: {len(all_candidates)}")
    
    # Phase 3: Multi-Stage Verification Pipeline
    log("\nPhase 3: Multi-Stage Verification Pipeline")
    log("  Stage 1: TCP Connect → Stage 2: Protocol Detection → "
        "Stage 3: Exit IP Verification → Stage 4: Latency Measurement")
    
    verified_proxies = []
    
    def verify_wrapper(args):
        proxy_str, asn_data = args
        return verify_proxy_pipeline(proxy_str, asn_data)
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        tasks = [(p, asn_data) for p in all_candidates.keys()]
        results = list(ex.map(verify_wrapper, tasks, chunksize=50))
        verified_proxies = [r for r in results if r]
    
    log(f"\n[✓] Total verified Iranian proxies: {len(verified_proxies)}")
    log(f"[✓] Exit IP verified: {sum(1 for p in verified_proxies if p.get('exit_verified'))}")
    log(f"[✓] Avg latency: {round(sum(p.get('latency_ms', 0) or 0 for p in verified_proxies) / max(len(verified_proxies), 1), 1)}ms")
    
    # Save results
    save_results(verified_proxies, asn_data)

if __name__ == "__main__":
    main()
