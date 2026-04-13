# =============================================================================
# test_proxies.R  - Windows-ready, parallel via socket cluster
#
# INTERACTIVE (RStudio): set INPUT_FILE below and hit Source
# CLI:  Rscript test_proxies.R working_iran_proxies.json
#       Rscript test_proxies.R working_iran_proxies.txt --workers 20 --timeout 5
#
# install.packages(c("jsonlite", "parallel"))   # one-time
# =============================================================================

suppressPackageStartupMessages({
  library(jsonlite)
  library(parallel)
})

`%||%` <- function(a, b) if (!is.null(a) && length(a) > 0L) a else b

# -- 1 Edit these when running interactively in RStudio ------------------------
INPUT_FILE <- "D:/IR_proxy_testing/working_iran_proxies.json"
WORKERS    <- 32L    # socket-cluster workers on Windows (tune to your CPU cores)
TIMEOUT    <- 5L     # hard wall-clock seconds per geo-check

# NOTE: Close PingPlotter (and any VPN) before running.
# PingPlotter opens background sockets that the R socket cluster inherits,
# causing "closing unused connection" warnings and corrupting worker results.

# Ports that speak SOCKS5 rather than HTTP CONNECT.
# Any proxy on one of these ports is tested with socks5:// instead of http://.
# Extend this list if you find other SOCKS ports in your proxy files.
SOCKS5_PORTS <- c(1080L, 1081L, 4145L, 5678L, 9050L, 9150L, 10800L)

# Warn if the proxy file is older than this many hours.
# Public proxies go dead within 1-6h; anything older than this is likely stale.
STALE_WARN_HOURS <- 3L

# Bale reachability endpoints - mirrors BALE_TEST_ENDPOINTS in scan.py.
# Any HTTP response (including 4xx/5xx) confirms the proxy can route to
# Iranian-hosted infrastructure. A timeout or connection error means it can't.
# This is Tier 2 verification, identical to what scan.py does on the runner.
BALE_ENDPOINTS <- c(
  "https://tapi.bale.ai/",   # Bot API - most stable
  "https://bale.ai/",        # Main site
  "http://bale.ai/"          # HTTP fallback
)

# Rubika (rubika.ir) — Iranian social/messaging platform.
# Same EU-reachable / NA-blocked asymmetry as Bale. Independent CDN path.
RUBIKA_ENDPOINTS <- c(
  "https://web.rubika.ir/",
  "https://rubika.ir/",
  "http://rubika.ir/"
)

# Splus (splus.ir) — Iranian media streaming platform.
# Third independent probe; different CDN path from Bale and Rubika.
SPLUS_ENDPOINTS <- c(
  "https://web.splus.ir/",
  "https://splus.ir/",
  "http://splus.ir/"
)

# -- Corporate / intercepting proxy ranges -------------------------------------
# These IPs route traffic but inject a corporate login wall (Zscaler, Netskope,
# Palo Alto Prisma, etc.) before forwarding - useless for Iranian network access.
# Proxies in these ranges are skipped entirely before testing.
# Root cause of the Zscaler screenshot: 165.225.113.220 is Zscaler.
CORPORATE_RANGES <- list(
  # Zscaler - c() would coerce 16L to "16", so use list() to preserve integer type
  list("165.225.0.0",   16L),
  list("136.226.0.0",   16L),
  list("147.161.0.0",   16L),
  list("185.46.212.0",  22L),
  list("104.129.192.0", 20L),
  list("170.85.0.0",    16L),
  # Netskope
  list("163.116.128.0", 17L),
  list("163.116.0.0",   17L),
  # Palo Alto Prisma / GlobalProtect
  list("199.167.52.0",  22L)
)

# -- Country proximity tiers for pre-test ordering ----------------------------
# Proxies whose exit IP is in a country geographically / politically closer to
# Iran are more likely to have routing paths into the Iranian network.
# Used only to ORDER the input list (better candidates tested first).
IRAN_NEIGHBOR_CC  <- c("AM", "AZ", "TR", "IQ", "AF", "TM", "PK")  # direct neighbors
IRAN_REGIONAL_CC  <- c("RU", "DE", "NL", "FI", "SE", "AT", "CH",  # EU hosting used
                        "FR", "GB", "PL", "UA", "GE", "KZ")        #   by Iranian ops

# -- IP range helpers ----------------------------------------------------------
# Pure base-R: no packages needed, safe to run in cluster workers.

ip_to_int <- function(ip) {
  # Returns the numeric (double) value of an IPv4 address.
  # Uses numeric, NOT integer - R integers are 32-bit signed and overflow
  # for IPs >= 128.0.0.0 (~2.1B limit). Doubles hold all 32-bit values exactly.
  parts <- suppressWarnings(as.numeric(strsplit(ip, "\\.")[[1L]]))
  if (length(parts) != 4L || any(is.na(parts)) ||
      any(parts < 0) || any(parts > 255)) return(NA_real_)
  parts[1L] * 16777216 + parts[2L] * 65536 + parts[3L] * 256 + parts[4L]
}

is_in_cidr <- function(ip, network, prefix_len) {
  # Pure numeric CIDR check - avoids R integer overflow entirely.
  # All arithmetic stays in double; no bitwise ops needed.
  prefix_len <- as.numeric(prefix_len)
  if (is.na(prefix_len) || prefix_len < 0 || prefix_len > 32) return(FALSE)
  ip_i  <- ip_to_int(ip)
  net_i <- ip_to_int(network)
  if (is.na(ip_i) || is.na(net_i)) return(FALSE)
  # Number of host bits
  host_bits <- 32 - prefix_len
  # Divisor equivalent to 2^host_bits
  divisor <- 2 ^ host_bits
  # Two IPs are in the same subnet iff floor(ip/divisor) == floor(net/divisor)
  floor(ip_i / divisor) == floor(net_i / divisor)
}

is_corporate_ip <- function(ip) {
  for (r in CORPORATE_RANGES) {
    if (is_in_cidr(ip, r[[1L]], r[[2L]])) return(TRUE)
  }
  FALSE
}

# -- Pre-test priority heuristic -----------------------------------------------
# Assigns a rough score to each proxy string BEFORE testing, used only to
# order the input list so the most promising candidates are tested first.
# Score is based on port pattern and IP octet hints only (no live checks).
pretest_score <- function(proxy_str) {
  parts <- strsplit(proxy_str, ":")[[1L]]
  if (length(parts) != 2L) return(0L)
  ip   <- parts[1L]
  port <- suppressWarnings(as.integer(parts[2L]))
  if (is.na(port)) return(0L)

  score <- 0L

  # Iranian IP space heuristics (first two octets of well-known IR ranges)
  first2 <- paste(strsplit(ip, "\\.")[[1L]][1:2], collapse=".")
  ir_hints <- c("5.160","5.200","5.201","5.202","5.238","31.2","31.14","31.24",
                "31.40","31.58","31.59","37.98","37.152","37.156","37.202",
                "78.38","78.39","79.127","80.191","80.210","82.99","85.9",
                "85.15","86.57","87.107","87.128","88.135","89.32","89.33",
                "89.34","89.144","91.98","91.99","91.108","91.186","91.235",
                "91.239","92.42","92.49","93.114","93.115","94.74","94.184",
                "95.38","95.80","95.81","95.142","103.77","103.231",
                "109.122","109.123","109.162","110.38","113.176",
                "176.65","178.131","178.215","179.43","185.4","185.49",
                "185.55","185.81","185.94","185.95","185.96","185.97",
                "185.98","185.99","185.100","185.101","185.102","185.103",
                "185.104","185.105","185.106","185.107","185.108","185.109",
                "185.110","185.111","185.112","185.113","185.116","185.117",
                "185.118","185.119","185.120","185.121","185.122","185.123",
                "185.124","185.125","185.126","185.127","185.128","185.129",
                "185.130","185.131","185.132","185.133","185.134","185.135",
                "185.136","185.137","185.138","185.139","185.140","185.141",
                "188.208","188.209","188.210","188.213","188.214",
                "194.225","195.146","195.147","195.148","196.245",
                "217.144","217.145","217.146","217.147","217.172","217.173")
  if (first2 %in% ir_hints) score <- score + 50L

  # SOCKS protocol is harder to intercept / fingerprint than HTTP
  if (port %in% c(1080L, 1081L, 4145L, 5678L, 9050L, 9150L)) score <- score + 10L

  # Standard proxy ports are less likely to be honeypots / CDN false positives
  if (port %in% c(80L, 443L, 3128L, 8080L, 8118L, 8888L)) score <- score + 5L

  score
}

# -- Post-test priority score --------------------------------------------------
# Ranks tested results from most to least useful for Iranian network access.
# Higher score = closer to the goal = appears first in output files.
priority_score <- function(tier, country, geo_score, proto, bale_status, https_status) {
  base <- switch(tier,
    "IR-exit"             = 1000L,
    "bale-tunnel"         = 800L,   # HTTPS CONNECT works + Bale responds
    "bale-tunnel-blocked" = 650L,   # HTTPS tunnel open but Bale blocks exit IP
    "bale-bridge"         = 400L,   # HTTP only, no HTTPS tunnel
    "fail"                = 0L,
    0L
  )

  # Geo confidence (only matters for IR-exit)
  base <- base + (geo_score %||% 0L) * 20L

  # SOCKS > HTTP (harder to intercept, works with more apps)
  if (!is.na(proto) && proto %in% c("socks5", "socks4")) base <- base + 30L

  # Neighbor country exit is more likely to have peering into Iran
  if (!is.na(country) && country %in% IRAN_NEIGHBOR_CC)  base <- base + 40L
  if (!is.na(country) && country %in% IRAN_REGIONAL_CC)  base <- base + 15L
  if (!is.na(country) && country == "IR")                 base <- base + 100L

  # Plain Bale HTTP quality (for bale-bridge tier only)
  if (!is.na(bale_status)) {
    if (bale_status == 200L)                              base <- base + 20L
    else if (bale_status >= 300L && bale_status < 400L)  base <- base + 10L
  }

  # HTTPS tunnel quality boost (200 = full browser access, worth extra)
  if (!is.na(https_status) && https_status > 0L) {
    if (https_status == 200L)                             base <- base + 50L
    else if (https_status >= 301L && https_status < 400L) base <- base + 30L
  }

  base
}

# -- 2 CLI overrides (Rscript mode) --------------------------------------------
local({
  a <- commandArgs(trailingOnly = TRUE)
  if (length(a) == 0) return()
  if (!startsWith(a[1], "--")) INPUT_FILE <<- a[1]
  for (i in seq_along(a)) {
    if (a[i] == "--workers" && i < length(a)) WORKERS <<- as.integer(a[i+1])
    if (a[i] == "--timeout" && i < length(a)) TIMEOUT <<- as.integer(a[i+1])
  }
})

# -- 3 Geo-check targets (same 3 as scan.py) -----------------------------------
GEO_CHECKS <- list(
  list(url = "http://ip-api.com/json/?fields=status,countryCode", key = "countryCode"),
  list(url = "http://ipwho.is/",                                   key = "country_code"),
  list(url = "http://ipapi.co/json/",                              key = "country_code")
)

# -- 4 Load proxies from .txt or scan.py .json ---------------------------------
load_proxies <- function(path) {
  if (!file.exists(path)) stop("File not found: ", path)
  pat <- "^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}:\\d{2,5}$"
  
  if (grepl("\\.json$", path, ignore.case = TRUE)) {
    dat   <- fromJSON(path, simplifyVector = FALSE)
    items <- if (is.null(names(dat))) dat else unname(dat)
    plist <- vapply(items, function(x) {
      v <- x[["proxy"]]; if (is.null(v) || !nzchar(v)) "" else as.character(v)
    }, character(1L))
  } else {
    lines <- trimws(readLines(path, warn = FALSE))
    lines <- lines[nzchar(lines) & !startsWith(lines, "#")]
    plist <- character(0L)
    for (ln in lines) {
      tok <- strsplit(ln, "\\s+")[[1L]]
      m   <- tok[grepl(pat, tok)]
      if (length(m)) plist <- c(plist, m[1L])
    }
  }
  unique(plist[grepl(pat, plist)])
}

# -- 5a Bale reachability check ------------------------------------------------
#
# Three-layer verification - ALL three must pass for a proxy to be accepted
# as a Bale bridge:
#
#   Layer 1 - HTTP status:  any code 1-599 except 407 (proxy auth required)
#   Layer 2 - Final URL:    after following all redirects, the effective URL
#                           must still be on bale.ai / tapi.bale.ai.
#                           If it landed on zscaler.net, bluecoat.com, etc.,
#                           the proxy hijacked the connection.
#   Layer 3 - 407 guard:    407 means the proxy itself blocked the request
#                           before it reached Bale - NOT a bridge signal.
#
# curl's -w "%{http_code} %{url_effective}" writes both fields separated by
# a space after the response body (which is discarded with -o NUL/-o /dev/null).
# We parse them as two tokens from the last line of stdout.
#
# Known interceptor domains (extend as needed):
INTERCEPTOR_DOMAINS <- c(
  # Zscaler family
  "zscaler.net", "zscalerone.net", "zscalertwo.net",
  "zscalerthree.net", "zscalerbeta.net", "zscalergov.net",
  "zscloud.net", "zscalerprivateaccess.net",
  # Symantec / Broadcom Blue Coat
  "bluecoat.com", "symantec.com", "broadcom.com",
  # Forcepoint / Websense
  "forcepoint.com", "websense.com",
  # Cisco Umbrella / Ironport
  "umbrella.com", "opendns.com", "cisco.com",
  # Palo Alto Prisma
  "prismaaccess.com", "gpcloudservice.com",
  # Netskope
  "netskope.com", "netskopeusercontent.com",
  # McAfee / Trellix Web Gateway
  "mcafee.com", "trellix.com", "skyhighsecurity.com",
  # Barracuda
  "barracudanetworks.com", "cudaops.com",
  # iboss
  "iboss.com",
  # Menlo Security
  "menlosecurity.com",
  # Cloudflare Gateway (not a bridge - Cloudflare's own filtering)
  "cloudflaregateway.com", "cloudflareclient.com",
  # Generic captive portal / auth wall indicators
  "captive-portal", "safe-browsing", "gateway.security"
)

is_interceptor_url <- function(url) {
  if (is.na(url) || !nzchar(url)) return(FALSE)
  # Extract hostname: remove scheme, path, query
  host <- tryCatch({
    h <- sub("^https?://", "", url)
    h <- sub("/.*$", "", h)
    h <- sub(":.*$", "", h)    # strip port if present
    tolower(h)
  }, error = function(e) "")
  if (!nzchar(host)) return(FALSE)
  # Check if host ends with any known interceptor domain
  any(vapply(INTERCEPTOR_DOMAINS, function(d)
    host == d || endsWith(host, paste0(".", d)),
    logical(1L)))
}

# Generic Iranian-infra probe helper used by check_bale + new probes.
check_iranian_infra <- function(proxy_url, timeout_secs, endpoints) {
  curl_bin <- if (.Platform$OS.type == "windows") "curl.exe" else "curl"
  for (ep in endpoints) {
    args <- c(
      "-s",
      "-o",  if (.Platform$OS.type == "windows") "NUL" else "/dev/null",
      "-w",  "%{http_code} %{url_effective}",
      "-m",  as.character(timeout_secs),
      "--connect-timeout", "3",
      "-x",  proxy_url,
      "-L",  "--insecure",
      ep
    )
    raw <- try(suppressWarnings(
      system2(curl_bin, args, stdout = TRUE, stderr = FALSE)
    ), silent = TRUE)
    if (inherits(raw, "try-error") || length(raw) == 0L) next
    last_line <- trimws(tail(raw[nzchar(trimws(raw))], 1L))
    tokens    <- strsplit(last_line, " ", fixed = TRUE)[[1L]]
    status    <- suppressWarnings(as.integer(tokens[1L]))
    final_url <- if (length(tokens) >= 2L) paste(tokens[-1L], collapse=" ") else ""
    if (is.na(status) || status <= 0L || status >= 600L) next
    if (status == 407L) next
    if (is_interceptor_url(final_url))
      return(list(reachable=FALSE, status=status, endpoint=ep,
                  final_url=final_url, intercepted=TRUE))
    return(list(reachable=TRUE, status=status, endpoint=ep,
                final_url=final_url, intercepted=FALSE))
  }
  list(reachable=FALSE, status=NA_integer_, endpoint=NA_character_,
       final_url=NA_character_, intercepted=FALSE)
}

check_bale <- function(proxy_url, timeout_secs, bale_endpoints) {
  # Thin wrapper — preserves original call signature.
  check_iranian_infra(proxy_url, timeout_secs, bale_endpoints)
}

# HTTPS CONNECT tunnel target - the actual Bale web client URL browsers need
BALE_HTTPS_TARGET <- "https://web.bale.ai/"

# -- 5b HTTPS CONNECT tunnel check --------------------------------------------
#
# This is what the browser actually does: sends HTTP CONNECT web.bale.ai:443
# to the proxy, then opens TLS inside the tunnel.
# ERR_TUNNEL_CONNECTION_FAILED in the browser = this check returns FALSE.
#
# Result tiers based on HTTPS status code:
#   200 / 3xx  -> "bale-tunnel"         (full browser access to web.bale.ai)
#   401 / 403  -> "bale-tunnel-blocked" (tunnel works but Bale blocks exit IP)
#   0 / timeout-> no HTTPS CONNECT support (stay as plain bale-bridge)
#   407        -> proxy auth required (useless)
#
check_bale_https <- function(proxy_url, timeout_secs) {
  # --proxytunnel forces HTTP CONNECT tunnel instead of plain HTTP forwarding.
  # Without it, curl sends GET http://web.bale.ai/ which hits the echo/debug
  # page and returns 200 — a false positive.
  # -o tmp_body writes the body to a file so stdout contains ONLY the -w output,
  # avoiding any embedded newline in the -w argument that would split the string.
  curl_bin <- if (.Platform$OS.type == "windows") "curl.exe" else "curl"
  tmp_body <- tempfile(fileext = ".txt")
  on.exit(unlink(tmp_body), add = TRUE)

  args <- c(
    "-s",
    "-o",  tmp_body,
    "-w",  "%{http_code} %{url_effective}",
    "-m",  as.character(timeout_secs),
    "--connect-timeout", "4",
    "-x",  proxy_url,
    "--proxytunnel",
    "-k",
    "-L", "--max-redirs", "5",
    BALE_HTTPS_TARGET
  )

  raw <- try(suppressWarnings(
    system2(curl_bin, args, stdout = TRUE, stderr = FALSE)
  ), silent = TRUE)

  if (inherits(raw, "try-error") || length(raw) == 0L)
    return(list(tunnel = "none", https_status = 0L, https_url = ""))

  last_line <- trimws(tail(raw[nzchar(trimws(raw))], 1L))
  tokens    <- strsplit(last_line, " ", fixed = TRUE)[[1L]]
  status    <- suppressWarnings(as.integer(tokens[1L]))
  final_url <- if (length(tokens) >= 2L) paste(tokens[-1L], collapse = " ") else ""

  if (is.na(status) || status == 0L)
    return(list(tunnel = "none", https_status = 0L, https_url = ""))

  if (status == 407L)
    return(list(tunnel = "auth-required", https_status = 407L, https_url = ""))

  # Body check: Bale echo page (plain HTTP) contains "REMOTE_ADDR = ".
  # Real HTTPS tunnel responses never contain this string.
  body_text <- tryCatch(
    paste(readLines(tmp_body, warn = FALSE), collapse = " "),
    error = function(e) ""
  )
  if (grepl("REMOTE_ADDR", body_text, fixed = TRUE))
    return(list(tunnel = "echo-page", https_status = 0L, https_url = ""))

  # URL destination check: final URL must remain on bale.ai
  if (nzchar(final_url) && !grepl("bale[.]ai", final_url, ignore.case = TRUE)) {
    if (is_interceptor_url(final_url))
      return(list(tunnel = "intercepted", https_status = status, https_url = final_url))
    return(list(tunnel = "none", https_status = status, https_url = final_url))
  }

  if (status == 200L || (status >= 301L && status <= 399L))
    return(list(tunnel = "open-200", https_status = status, https_url = final_url))

  if (status == 401L || status == 403L)
    return(list(tunnel = "open-blocked", https_status = status, https_url = final_url))

  list(tunnel = "open-other", https_status = status, https_url = final_url)
}

# -- 5c Test one proxy using system curl (hard OS-level timeout) ---------------
#
# Protocol selection:
#   Ports in SOCKS5_PORTS ??? socks5://   (SOCKS proxies drop HTTP CONNECT silently)
#   All other ports       ??? http://
# curl -x accepts both protocols natively.
#

# run_checks is a top-level function so it can be exported to cluster workers.
# Runs all 3 geo-check URLs through a given proxy URL and returns hit count + country.
run_checks <- function(purl, timeout_secs, geo_checks) {
  h <- 0L; cc <- "?"
  for (chk in geo_checks) {
    args <- c(
      "-s",
      "-m",                as.character(timeout_secs),
      "--connect-timeout", as.character(max(2L, timeout_secs %/% 2L)),
      "-x",                purl,
      "--max-redirs", "3",
      "-L", "-o", "-",
      chk$url
    )
    raw <- try(suppressWarnings(system2("curl", args, stdout=TRUE, stderr=FALSE)),
               silent=TRUE)
    if (inherits(raw, "try-error") || length(raw) == 0L) next
    body <- try(fromJSON(paste(raw, collapse=""), simplifyVector=TRUE), silent=TRUE)
    if (inherits(body, "try-error") || is.null(body)) next
    val <- body[[chk$key]]
    if (!is.null(val) && length(val)==1L && nzchar(val)) {
      if (cc == "?") cc <- val
      if (identical(val, "IR")) h <- h + 1L
    }
  }
  list(hits=h, country=cc)
}

test_proxy <- function(proxy_str, timeout_secs, geo_checks) {
  parts <- strsplit(proxy_str, ":")[[1L]]
  if (length(parts) != 2L)
    return(list(proxy=proxy_str, ok=FALSE, tier="fail", country="parse-err",
                score=0L, proto="?", bale=FALSE, bale_status=NA_integer_))
  
  host <- parts[1L]
  port <- suppressWarnings(as.integer(parts[2L]))
  if (is.na(port))
    return(list(proxy=proxy_str, ok=FALSE, tier="fail", country="bad-port",
                score=0L, proto="?", bale=FALSE, bale_status=NA_integer_))
  
  # Choose protocol based on port - fixes the 0/3 problem for SOCKS ports
  proto     <- if (port %in% SOCKS5_PORTS) "socks5" else "http"
  proxy_url <- sprintf("%s://%s:%d", proto, host, port)
  
  res     <- run_checks(proxy_url, timeout_secs, geo_checks)
  hits    <- res$hits
  country <- res$country
  
  # SOCKS4 fallback - try socks4:// when socks5:// returned nothing useful.
  if (hits == 0L && proto == "socks5") {
    res4 <- run_checks(sprintf("socks4://%s:%d", host, port), timeout_secs, geo_checks)
    if (res4$hits > hits) {
      hits    <- res4$hits
      country <- res4$country
      proto   <- "socks4"
    }
  }
  
  # -- Tier 1: 2-of-3 geo sources confirm IR exit -------------------------------
  if (hits >= 2L)
    return(list(proxy=proxy_str, ok=TRUE, tier="IR-exit",
                country=country, score=hits, proto=proto,
                bale=FALSE, bale_status=NA_integer_,
                https_status=NA_integer_, https_url=""))
  
  # -- Tier 2: Iranian infra probes (Bale -> Rubika -> Splus, short-circuit) ----
  # Run in priority order; stop as soon as one probe passes. This avoids paying
  # 3x the curl timeout per proxy on the common "Bale passes" case.
  # All-fail case still costs 3x, but that is unavoidable for genuine non-bridges.
  FAIL_PROBE <- list(reachable=FALSE, status=NA_integer_, endpoint=NA_character_,
                     final_url=NA_character_, intercepted=FALSE)

  bale_res   <- check_bale(proxy_url, timeout_secs, BALE_ENDPOINTS)
  rubika_res <- if (!isTRUE(bale_res$reachable) && !isTRUE(bale_res$intercepted))
                  check_iranian_infra(proxy_url, timeout_secs, RUBIKA_ENDPOINTS)
                else FAIL_PROBE
  splus_res  <- if (!isTRUE(bale_res$reachable)  && !isTRUE(bale_res$intercepted) &&
                    !isTRUE(rubika_res$reachable) && !isTRUE(rubika_res$intercepted))
                  check_iranian_infra(proxy_url, timeout_secs, SPLUS_ENDPOINTS)
                else FAIL_PROBE

  iran_probe_score <- sum(c(isTRUE(bale_res$reachable),
                            isTRUE(rubika_res$reachable),
                            isTRUE(splus_res$reachable)))

  # Intercepted by a corporate gateway on any probe domain
  any_intercepted <- isTRUE(bale_res$intercepted) ||
                     isTRUE(rubika_res$intercepted) ||
                     isTRUE(splus_res$intercepted)
  if (any_intercepted) {
    first_int <- if (isTRUE(bale_res$intercepted)) bale_res
                 else if (isTRUE(rubika_res$intercepted)) rubika_res
                 else splus_res
    return(list(proxy=proxy_str, ok=FALSE, tier="intercepted",
                country=country, score=hits, proto=proto,
                bale=FALSE, bale_status=first_int$status,
                iran_probe_score=0L,
                https_status=NA_integer_, https_url="",
                final_url=first_int$final_url %||% ""))
  }

  if (iran_probe_score >= 1L) {
    # Bale responds via plain HTTP - now test whether the proxy supports
    # HTTPS CONNECT (what browsers actually need for web.bale.ai).
    https_res <- check_bale_https(proxy_url, timeout_secs)

    tier <- switch(https_res$tunnel,
      "open-200"     = "bale-tunnel",          # browser can reach web.bale.ai
      "open-blocked" = "bale-tunnel-blocked",  # tunnel open, Bale blocks exit IP
      "open-other"   = "bale-tunnel",          # other 2xx/5xx - tunnel works
      "bale-bridge"                            # HTTPS CONNECT failed, HTTP only
    )

    return(list(proxy             = proxy_str,
                ok               = TRUE,
                tier             = tier,
                country          = country,
                score            = hits,
                proto            = proto,
                bale             = isTRUE(bale_res$reachable),
                bale_status      = bale_res$status,
                iran_probe_score = iran_probe_score,
                https_status     = https_res$https_status,
                https_url        = https_res$https_url %||% "",
                final_url        = bale_res$final_url %||% ""))
  }
  
  # -- No tier passed ------------------------------------------------------------
  list(proxy=proxy_str, ok=FALSE, tier="fail",
       country=country, score=hits, proto=proto,
       bale=FALSE, bale_status=NA_integer_,
       https_status=NA_integer_, https_url="", final_url="")
}

# -- 6 Load --------------------------------------------------------------------
cat(sprintf("Loading proxies from: %s\n", INPUT_FILE))
proxies <- tryCatch(
  load_proxies(INPUT_FILE),
  error = function(e) { cat("ERROR:", conditionMessage(e), "\n"); NULL }
)
if (is.null(proxies) || length(proxies) == 0L) {
  cat("No valid ip:port entries found. Check INPUT_FILE path.\n")
  if (!interactive()) quit(status=1L)
  stop("No proxies loaded")
}

total <- length(proxies)
cat(sprintf("Loaded %d proxies  |  workers=%d  timeout=%ds\n\n",
            total, WORKERS, TIMEOUT))

# -- Pre-test filter: remove corporate intercepting proxies --------------------
# Zscaler and similar gateways show a login wall instead of forwarding traffic.
# They waste test slots and produce misleading "working proxy" results.
corp_flags <- vapply(proxies, function(p) {
  ip <- strsplit(p, ":")[[1L]][1L]
  is_corporate_ip(ip)
}, logical(1L))

n_corp <- sum(corp_flags)
if (n_corp > 0L) {
  cat(sprintf("Skipping %d corporate/intercepting IPs (Zscaler etc.):\n", n_corp))
  cat(paste0("  ", proxies[corp_flags], "\n"), sep="")
  cat("\n")
  proxies <- proxies[!corp_flags]
}
total <- length(proxies)

# -- Pre-test ordering: most-promising candidates first ------------------------
# Heuristic scoring based on IP range hints and port patterns.
# Iranian IP ranges score highest, SOCKS ports score higher than HTTP.
# This means you see useful results sooner without waiting for the full run.
pre_scores <- vapply(proxies, pretest_score, integer(1L))
proxies    <- proxies[order(pre_scores, decreasing = TRUE)]

cat(sprintf("Testing %d proxies after filtering (ordered by IR proximity)...\n\n",
            total))

# -- Staleness check ------------------------------------------------------------
# If the JSON contains scan_timestamp fields (written by scan.py), warn the user
# when proxies are older than STALE_WARN_HOURS - dead proxies test as 0/3.
check_staleness <- function(path, warn_hours) {
  if (!grepl("\\.json$", path, ignore.case = TRUE)) return(invisible(NULL))
  tryCatch({
    dat <- fromJSON(path, simplifyVector = FALSE)
    items <- if (is.null(names(dat))) dat else unname(dat)
    ts_vals <- vapply(items, function(x) x[["scan_timestamp"]] %||% "", character(1L))
    ts_vals <- ts_vals[nzchar(ts_vals)]
    if (length(ts_vals) == 0L) return(invisible(NULL))
    # Parse the most recent timestamp
    latest <- max(as.POSIXct(ts_vals, format = "%Y-%m-%dT%H:%M:%SZ", tz = "UTC"),
                  na.rm = TRUE)
    age_h  <- as.numeric(difftime(Sys.time(), latest, units = "hours"))
    if (is.na(age_h)) return(invisible(NULL))
    msg <- sprintf("Proxy file age: %.1f hours (scanned at %s UTC)",
                   age_h, format(latest, "%Y-%m-%d %H:%M"))
    if (age_h > warn_hours) {
      cat(sprintf("\n*** STALE WARNING: %s ***\n", msg))
      cat(sprintf("    Proxies older than %dh are likely dead (0/3 is expected).\n",
                  warn_hours))
      cat("    Run the GitHub Actions workflow first, then re-test immediately.\n\n")
    } else {
      cat(sprintf("Freshness : %s  [OK]\n\n", msg))
    }
  }, error = function(e) invisible(NULL))
}
check_staleness(INPUT_FILE, STALE_WARN_HOURS)

# -- 7 Run (Windows socket cluster OR Unix mclapply) ---------------------------
worker_fn <- function(p) test_proxy(p, TIMEOUT, GEO_CHECKS)

t0 <- proc.time()

if (.Platform$OS.type == "windows" && WORKERS > 1L) {
  cores <- min(WORKERS, detectCores(logical = TRUE))
  cat(sprintf("Starting Windows socket cluster with %d workers...\n\n", cores))
  cl <- makeCluster(cores)
  on.exit(stopCluster(cl), add = TRUE)                   # always clean up
  clusterExport(cl, varlist = c("GEO_CHECKS", "TIMEOUT", "SOCKS5_PORTS",
                                "BALE_ENDPOINTS", "RUBIKA_ENDPOINTS",
                                "SPLUS_ENDPOINTS", "BALE_HTTPS_TARGET",
                                "IRAN_NEIGHBOR_CC", "IRAN_REGIONAL_CC",
                                "CORPORATE_RANGES", "INTERCEPTOR_DOMAINS",
                                "ip_to_int", "is_in_cidr", "is_corporate_ip",
                                "is_interceptor_url",
                                "test_proxy", "check_bale",
                                "check_iranian_infra", "check_bale_https",
                                "run_checks", "priority_score", "%||%"),
                envir = environment())
  clusterEvalQ(cl, suppressPackageStartupMessages(library(jsonlite)))
  results_raw <- parLapplyLB(cl, proxies, worker_fn)     # LB = load-balanced
  
} else if (.Platform$OS.type == "unix" && WORKERS > 1L) {
  results_raw <- mclapply(proxies, worker_fn,
                          mc.cores = min(WORKERS, detectCores(logical=FALSE)),
                          mc.preschedule = FALSE)
} else {
  cat("Running sequentially (single worker)...\n\n")
  results_raw <- lapply(proxies, worker_fn)
}

elapsed <- (proc.time() - t0)[["elapsed"]]

# -- 8 Print results -----------------------------------------------------------
results <- do.call(rbind, lapply(seq_along(results_raw), function(i) {
  r <- results_raw[[i]]
  # Crash guard: mclapply returns a character error string when a worker fails.
  if (!is.list(r)) {
    proxy_str <- if (i <= length(proxies)) proxies[[i]] else "unknown:0"
    cat(sprintf("[%4d/%d] %-26s  [ERROR] worker crashed\n", i, total, proxy_str))
    r <- list(proxy=proxy_str, ok=FALSE, tier="fail", country="?", score=0L,
              proto="?", bale=FALSE, bale_status=NA_integer_,
              https_status=NA_integer_, https_url="", final_url="")
  }
  proto_tag <- sprintf("%-6s", toupper(r$proto %||% "?"))
  tier <- r$tier %||% "fail"
  tag <- switch(tier,
    "IR-exit"             = sprintf("[ OK ] IR-EXIT             (%s)", proto_tag),
    "bale-tunnel"         = sprintf("[ OK ] BALE-TUNNEL         (%s) HTTP %s HTTPS %s",
                                     proto_tag,
                                     r$bale_status  %||% "?",
                                     r$https_status %||% "?"),
    "bale-tunnel-blocked" = sprintf("[ ~~ ] BALE-TUNNEL-BLOCKED (%s) HTTPS %s (IP blocked by Bale)",
                                     proto_tag, r$https_status %||% "?"),
    "bale-bridge"         = sprintf("[ ~~ ] BALE-BRIDGE HTTP-only (%s) HTTP %s",
                                     proto_tag, r$bale_status %||% "?"),
    "intercepted"         = sprintf("[HIJACK] %s -> %s",
                                     r$country, r$final_url %||% "?"),
    sprintf("[FAIL ] %-4s %d/3 (%s)", r$country, r$score, proto_tag)
  )
  cat(sprintf("[%4d/%d] %-26s  %s\n", i, total, r$proxy, tag))
  data.frame(proxy        = r$proxy,
             ok           = isTRUE(r$ok),
             tier         = tier,
             country      = r$country,
             score        = r$score,
             proto        = r$proto        %||% "?",
             bale         = isTRUE(r$bale),
             bale_status  = r$bale_status  %||% NA_integer_,
             https_status = r$https_status %||% NA_integer_,
             https_url    = r$https_url    %||% "",
             final_url    = r$final_url    %||% "",
             stringsAsFactors = FALSE)
}))

# -- 9 Summary + save ---------------------------------------------------------
passed           <- results[results$ok, , drop=FALSE]
ir_exit          <- results[results$tier == "IR-exit",             , drop=FALSE]
bale_tunnel      <- results[results$tier == "bale-tunnel",         , drop=FALSE]
bale_tunnel_blk  <- results[results$tier == "bale-tunnel-blocked", , drop=FALSE]
bale_bridge      <- results[results$tier == "bale-bridge",         , drop=FALSE]
intercepted      <- results[results$tier == "intercepted",         , drop=FALSE]

# Priority scoring now uses https_status too
if (nrow(passed) > 0L) {
  passed$priority <- mapply(priority_score,
                             passed$tier, passed$country, passed$score,
                             passed$proto, passed$bale_status, passed$https_status)
  passed <- passed[order(passed$priority, decreasing = TRUE), ]
  ir_exit         <- passed[passed$tier == "IR-exit",             , drop=FALSE]
  bale_tunnel     <- passed[passed$tier == "bale-tunnel",         , drop=FALSE]
  bale_tunnel_blk <- passed[passed$tier == "bale-tunnel-blocked", , drop=FALSE]
  bale_bridge     <- passed[passed$tier == "bale-bridge",         , drop=FALSE]
}

cat(sprintf(
  "\n%s\n IR-exit              : %d  (full IR routing)\n Bale-tunnel          : %d  (HTTPS tunnel to web.bale.ai works)\n Bale-tunnel-blocked  : %d  (tunnel works, Bale blocks exit IP)\n Bale-bridge HTTP-only: %d  (plain HTTP only, no HTTPS tunnel)\n Intercepted          : %d  (hijacked - NOT usable)\n Total passed: %d / %d  (%.1f%%)   Elapsed: %.0fs\n",
  strrep("-", 56),
  nrow(ir_exit), nrow(bale_tunnel), nrow(bale_tunnel_blk),
  nrow(bale_bridge), nrow(intercepted),
  nrow(passed), total,
  if (total > 0L) 100 * nrow(passed) / total else 0,
  elapsed
))

# Report intercepted proxies so the operator knows which ones were hijacked
if (nrow(intercepted) > 0L) {
  cat("\nIntercepted proxies (connection hijacked - do NOT use):\n")
  for (i in seq_len(nrow(intercepted))) {
    cat(sprintf("  %-26s  redirected to: %s\n",
                intercepted$proxy[i],
                intercepted$final_url[i]))
  }
}

out_dir <- tryCatch(dirname(normalizePath(INPUT_FILE)), error=function(e) getwd())

if (nrow(ir_exit) > 0L) {
  cat("\nIR-exit proxies (best first):\n")
  for (i in seq_len(nrow(ir_exit)))
    cat(sprintf("  [pri=%d] %-26s  %s geo=%d/3\n",
                ir_exit$priority[i], ir_exit$proxy[i],
                ir_exit$proto[i], ir_exit$score[i]))
  writeLines(ir_exit$proxy, file.path(out_dir, "passing_ir_exit.txt"))
  write_json(ir_exit, file.path(out_dir, "passing_ir_exit.json"),
             pretty=TRUE, auto_unbox=TRUE)
}

if (nrow(bale_tunnel) > 0L) {
  cat("\nBale-tunnel proxies - HTTPS to web.bale.ai works (best first):\n")
  for (i in seq_len(nrow(bale_tunnel)))
    cat(sprintf("  [pri=%d] %-26s  %s | country=%s | HTTP %s | HTTPS %s\n",
                bale_tunnel$priority[i], bale_tunnel$proxy[i],
                bale_tunnel$proto[i], bale_tunnel$country[i],
                bale_tunnel$bale_status[i], bale_tunnel$https_status[i]))
  writeLines(bale_tunnel$proxy, file.path(out_dir, "passing_bale_tunnel.txt"))
  write_json(bale_tunnel, file.path(out_dir, "passing_bale_tunnel.json"),
             pretty=TRUE, auto_unbox=TRUE)
}

if (nrow(bale_tunnel_blk) > 0L) {
  cat("\nBale-tunnel-blocked proxies - HTTPS tunnel works, Bale blocks exit IP:\n")
  for (i in seq_len(nrow(bale_tunnel_blk)))
    cat(sprintf("  [pri=%d] %-26s  country=%s | HTTPS %s\n",
                bale_tunnel_blk$priority[i], bale_tunnel_blk$proxy[i],
                bale_tunnel_blk$country[i], bale_tunnel_blk$https_status[i]))
  writeLines(bale_tunnel_blk$proxy, file.path(out_dir, "passing_bale_tunnel_blocked.txt"))
  write_json(bale_tunnel_blk, file.path(out_dir, "passing_bale_tunnel_blocked.json"),
             pretty=TRUE, auto_unbox=TRUE)
}

if (nrow(bale_bridge) > 0L) {
  cat("\nBale-bridge HTTP-only proxies (no HTTPS tunnel):\n")
  for (i in seq_len(nrow(bale_bridge)))
    cat(sprintf("  [pri=%d] %-26s  %s | country=%s | HTTP %s\n",
                bale_bridge$priority[i], bale_bridge$proxy[i],
                bale_bridge$proto[i], bale_bridge$country[i],
                bale_bridge$bale_status[i]))
  writeLines(bale_bridge$proxy, file.path(out_dir, "passing_bale_bridge.txt"))
  write_json(bale_bridge, file.path(out_dir, "passing_bale_bridge.json"),
             pretty=TRUE, auto_unbox=TRUE)
}

if (nrow(passed) > 0L) {
  writeLines(passed$proxy, file.path(out_dir, "passing_all_ranked.txt"))
  write_json(passed, file.path(out_dir, "passing_all_ranked.json"),
             pretty=TRUE, auto_unbox=TRUE)

  # Print setup instructions for the #1 proxy
  top      <- passed$proxy[1]
  top_tier <- passed$tier[1]
  top_parts <- strsplit(top, ":")[[1L]]
  cat(sprintf("\n-- Use the top proxy (%s, tier=%s) --\n", top, top_tier))
  cat(sprintf("  Windows proxy settings: %s  port %s\n", top_parts[1], top_parts[2]))
  cat(sprintf("  curl.exe test: curl.exe -x http://%s -k https://web.bale.ai/ -I\n", top))
}

if (nrow(passed) == 0L) cat("\nNo working proxies found.\n")

if (nrow(passed) > 0L) {
  cat(sprintf("\nSaved to %s:\n", out_dir))
  if (nrow(ir_exit)         > 0L) cat("  passing_ir_exit.txt / .json\n")
  if (nrow(bale_tunnel)     > 0L) cat("  passing_bale_tunnel.txt / .json\n")
  if (nrow(bale_tunnel_blk) > 0L) cat("  passing_bale_tunnel_blocked.txt / .json\n")
  if (nrow(bale_bridge)     > 0L) cat("  passing_bale_bridge.txt / .json\n")
  cat("  passing_all_ranked.txt / .json  (all tiers, priority-sorted)\n")
}

# -- Country breakdown (all tested, not just passing) --------------------------
cat(sprintf("\n%s\n Country breakdown (all %d tested)\n%s\n",
            strrep("-", 40), total, strrep("-", 40)))
country_tbl <- sort(table(results$country), decreasing = TRUE)
for (i in seq_along(country_tbl)) {
  cc    <- names(country_tbl)[i]
  count <- country_tbl[[i]]
  bar   <- strrep("|", min(count, 40L))
  pct   <- 100 * count / total
  cat(sprintf("  %-6s %4d  (%4.1f%%)  %s\n", cc, count, pct, bar))
}

# Protocol breakdown
cat(sprintf("\n Protocol breakdown\n%s\n", strrep("-", 40)))
proto_tbl <- sort(table(results$proto), decreasing = TRUE)
for (i in seq_along(proto_tbl)) {
  cat(sprintf("  %-8s %4d\n", names(proto_tbl)[i], proto_tbl[[i]]))
}
