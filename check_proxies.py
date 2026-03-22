#!/usr/bin/env python3
"""
Iran Proxy Checker
Scrapes multiple sources for Iranian IP proxies, tests each one,
and saves a clean list of working proxies to working_iran_proxies.txt
"""

import socket
import socks
import requests
import concurrent.futures
import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path

SOURCES = {
    "proxyhub_socks5": "https://proxyhub.me/en/ir-socks5-proxy-list.html",
    "proxyhub_http": "https://proxyhub.me/en/ir-free-proxy-list.html",
    "ditatompel": "https://www.ditatompel.com/proxy/country/ir",
    "proxydb": "https://proxydb.net/?country=IR",
    "proxyscrape_api": "https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&country=ir&protocol=all&anonymity=all&timeout=10000",
    "geonode": "https://proxylist.geonode.com/api/proxy-list?country=IR&limit=100&page=1&sort_by=lastChecked&sort_type=desc",
}

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Linux; Android 12; Pixel 6) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36"
}

IP_PATTERN = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})\b")

VERIFY_URL = "http://ip-api.com/json/?fields=status,country,countryCode,query"
TIMEOUT = 10


def log(msg):
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)


# ── Scrapers ──────────────────────────────────────────────────────────────────

def scrape_raw_text(url):
    """Fetch a URL and extract all IP:port pairs from the raw text."""
    try:
        r = requests.get(url, headers=HEADERS, timeout=15)
        r.raise_for_status()
        pairs = IP_PATTERN.findall(r.text)
        return {f"{ip}:{port}" for ip, port in pairs}
    except Exception as e:
        log(f"  ! scrape_raw_text failed for {url}: {e}")
        return set()


def scrape_geonode(url):
    """Parse Geonode JSON API."""
    proxies = set()
    try:
        r = requests.get(url, headers=HEADERS, timeout=15)
        data = r.json()
        for p in data.get("data", []):
            ip = p.get("ip", "")
            for port in p.get("port", []):
                proxies.add(f"{ip}:{port}")
    except Exception as e:
        log(f"  ! geonode parse failed: {e}")
    return proxies


def scrape_proxyscrape_api(url):
    """ProxyScrape returns a plain text list."""
    try:
        r = requests.get(url, headers=HEADERS, timeout=15)
        r.raise_for_status()
        lines = r.text.strip().splitlines()
        return {line.strip() for line in lines if IP_PATTERN.match(line.strip())}
    except Exception as e:
        log(f"  ! proxyscrape API failed: {e}")
        return set()


def collect_all_candidates():
    """Scrape every source and return a de-duplicated set of IP:port strings."""
    candidates = set()

    log("Scraping proxyhub (SOCKS5)…")
    candidates |= scrape_raw_text(SOURCES["proxyhub_socks5"])

    log("Scraping proxyhub (HTTP)…")
    candidates |= scrape_raw_text(SOURCES["proxyhub_http"])

    log("Scraping ditatompel…")
    candidates |= scrape_raw_text(SOURCES["ditatompel"])

    log("Scraping proxydb…")
    candidates |= scrape_raw_text(SOURCES["proxydb"])

    log("Scraping ProxyScrape API…")
    candidates |= scrape_proxyscrape_api(SOURCES["proxyscrape_api"])

    log("Scraping Geonode…")
    candidates |= scrape_geonode(SOURCES["geonode"])

    # Exclude obviously non-routable addresses
    filtered = {
        p for p in candidates
        if not p.startswith(("0.", "10.", "127.", "172.", "192.168.", "::"))
    }
    log(f"Total unique candidates collected: {len(filtered)}")
    return filtered


# ── Tester ───────────────────────────────────────────────────────────────────

def test_proxy(proxy_str):
    """
    Test a single proxy:
      1. Try SOCKS5, fall back to HTTP.
      2. Hit ip-api.com through the proxy to confirm country == Iran.
    Returns a dict with result info, or None if it fails.
    """
    ip, port_str = proxy_str.split(":")
    port = int(port_str)

    for proto in ("socks5", "http"):
        proxy_url = f"{proto}://{ip}:{port}"
        proxies = {"http": proxy_url, "https": proxy_url}
        try:
            start = time.monotonic()
            r = requests.get(VERIFY_URL, proxies=proxies, timeout=TIMEOUT)
            latency = round((time.monotonic() - start) * 1000)
            data = r.json()

            if data.get("status") == "success" and data.get("countryCode") == "IR":
                return {
                    "proxy": proxy_str,
                    "protocol": proto.upper(),
                    "latency_ms": latency,
                    "isp": data.get("org", ""),
                    "city": data.get("city", ""),
                    "verified_ip": data.get("query", ""),
                }
        except Exception:
            continue

    return None


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    log("=" * 60)
    log("Iran Proxy Checker starting")
    log("=" * 60)

    candidates = collect_all_candidates()

    if not candidates:
        log("ERROR: No candidates scraped. Aborting.")
        return

    log(f"\nTesting {len(candidates)} proxies with {TIMEOUT}s timeout…")
    working = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=40) as executor:
        futures = {executor.submit(test_proxy, p): p for p in candidates}
        done = 0
        for future in concurrent.futures.as_completed(futures):
            done += 1
            result = future.result()
            if result:
                working.append(result)
                log(f"  ✓ WORKING [{result['protocol']}] {result['proxy']} "
                    f"({result['latency_ms']}ms) — {result['isp']}")
            if done % 20 == 0:
                log(f"  … {done}/{len(candidates)} tested, {len(working)} working so far")

    # Sort by latency
    working.sort(key=lambda x: x["latency_ms"])

    log(f"\n{'='*60}")
    log(f"Done. {len(working)} working Iranian proxies found.")
    log(f"{'='*60}\n")

    # ── Write plain text output ──────────────────────────────────────────────
    out_path = Path("working_iran_proxies.txt")
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    with open(out_path, "w") as f:
        f.write(f"# Working Iranian Proxies — checked {now}\n")
        f.write(f"# {len(working)} proxies verified via ip-api.com\n")
        f.write("#\n")
        f.write("# Format: PROTOCOL  IP:PORT  LATENCY  ISP\n")
        f.write("#\n\n")

        for p in working:
            f.write(
                f"{p['protocol']:<8} {p['proxy']:<26} "
                f"{p['latency_ms']:>5}ms   {p['isp']}\n"
            )

        f.write("\n# --- Raw IP:PORT list (for apps like Super Proxy) ---\n")
        for p in working:
            f.write(f"{p['proxy']}\n")

    log(f"Results written to {out_path.resolve()}")

    # ── Write JSON output (for scripting) ────────────────────────────────────
    json_path = Path("working_iran_proxies.json")
    with open(json_path, "w") as f:
        json.dump({
            "checked_at": now,
            "count": len(working),
            "proxies": working
        }, f, indent=2)

    log(f"JSON results written to {json_path.resolve()}")


if __name__ == "__main__":
    main()
