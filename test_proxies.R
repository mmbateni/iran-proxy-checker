# =============================================================================
# test_proxies.R  - Windows-ready, parallel via socket cluster
# INTERACTIVE (RStudio): set INPUT_FILE below and hit Source
# CLI:  Rscript test_proxies.R working_iran_proxies.json
# Rscript test_proxies.R working_iran_proxies.txt --workers 20 --timeout 5
# install.packages(c("jsonlite", "parallel"))   # one-time
# Tier ladder (highest to lowest priority):
# Tier 0: sni-fronting        domain-fronted via Cloudflare, DPI-resistant
# Tier 1: IR-exit             2-of-3 geo sources confirm Iranian exit
# Tier 2: bale-tunnel         HTTPS CONNECT tunnel to web.bale.ai works
# Tier 3: bale-tunnel-blocked tunnel works, Bale blocks exit IP
# Tier 4: bale-bridge         HTTP only, no HTTPS tunnel
# PERFORMANCE NOTE: SNI-fronting (Tier 0) is tested ONLY on proxies that
# already passed Tier 2 (bale-tunnel). This prevents the ~30s per-proxy
# overhead of testing 6 SNI pairs on proxies that will never pass.
# Result: SNI check runs on ~50 proxies instead of ~700.
# =============================================================================

suppressPackageStartupMessages({
  library(jsonlite)
  library(parallel)
})

`%||%` <- function(a, b) if (!is.null(a) && length(a) > 0L) a else b

#-- 1 Edit these when running interactively in RStudio ------------------------
INPUT_FILE <- "working_iran_proxies.json"  # GitHub Actions: relative path
WORKERS    <- 32L
TIMEOUT    <- 5L

# Ports that speak SOCKS5 rather than HTTP CONNECT.
SOCKS5_PORTS <- c(1080L, 1081L, 4145L, 5678L, 9050L, 9150L, 10800L)

# Warn if the proxy file is older than this many hours.
STALE_WARN_HOURS <- 3L

# Bale reachability endpoints
BALE_ENDPOINTS <- c(
  "https://tapi.bale.ai/",
  "https://bale.ai/",
  "http://bale.ai/"
)

# Rubika endpoints
RUBIKA_ENDPOINTS <- c(
  "https://web.rubika.ir/",
  "https://rubika.ir/",
  "http://rubika.ir/"
)

# Splus endpoints
SPLUS_ENDPOINTS <- c(
  "https://web.splus.ir/",
  "https://splus.ir/",
  "http://splus.ir/"
)

# SNI-fronting: default hardcoded pairs (from patterniha sample configs).
# Overridden at runtime by working_sni_fronting.json if present.
# Only tested on proxies that already passed Tier 2 (bale-tunnel).
SNI_FRONTING_PAIRS_DEFAULT <- list(
  list(connect_ip = "104.16.79.73",  fake_sni = "static.cloudflareinsights.com"),
  list(connect_ip = "188.114.98.0",  fake_sni = "auth.vercel.com"),
  list(connect_ip = "104.21.0.0",    fake_sni = "cdnjs.cloudflare.com"),
  list(connect_ip = "172.64.0.0",    fake_sni = "challenges.cloudflare.com"),
  list(connect_ip = "104.16.0.1",    fake_sni = "speed.cloudflare.com"),
  list(connect_ip = "104.24.0.1",    fake_sni = "developers.cloudflare.com")
)

# The real Iranian-infra host routed inside the Cloudflare-fronted tunnel.
SNI_REAL_HOST <- "tapi.bale.ai"

# Corporate / intercepting proxy ranges to skip entirely
CORPORATE_RANGES <- list(
  list("165.225.0.0",   16L),
  list("136.226.0.0",   16L),
  list("147.161.0.0",   16L),
  list("185.46.212.0",  22L),
  list("104.129.192.0", 20L),
  list("170.85.0.0",    16L),
  list("163.116.128.0", 17L),
  list("163.116.0.0",   17L),
  list("199.167.52.0",  22L)
)

# Country proximity tiers
IRAN_NEIGHBOR_CC <- c("AM", "AZ", "TR", "IQ", "AF", "TM", "PK")
IRAN_REGIONAL_CC <- c("RU", "DE", "NL", "FI", "SE", "AT", "CH",
                      "FR", "GB", "PL", "UA", "GE", "KZ")

#-- IP range helpers ----------------------------------------------------------
ip_to_int <- function(ip) {
  parts <- suppressWarnings(as.numeric(strsplit(ip, "\\.")[[1L]]))
  if (length(parts) != 4L || any(is.na(parts)) ||
      any(parts < 0) || any(parts > 255)) return(NA_real_)
  parts[1L] * 16777216 + parts[2L] * 65536 + parts[3L] * 256 + parts[4L]
}

is_in_cidr <- function(ip, network, prefix_len) {
  prefix_len <- as.numeric(prefix_len)
  if (is.na(prefix_len) || prefix_len < 0 || prefix_len > 32) return(FALSE)
  ip_i  <- ip_to_int(ip)
  net_i <- ip_to_int(network)
  if (is.na(ip_i) || is.na(net_i)) return(FALSE)
  host_bits <- 32 - prefix_len
  divisor <- 2 ^ host_bits
  floor(ip_i / divisor) == floor(net_i / divisor)
}

is_corporate_ip <- function(ip) {
  for (r in CORPORATE_RANGES) {
    if (is_in_cidr(ip, r[[1L]], r[[2L]])) return(TRUE)
  }
  FALSE
}

#-- SNI-fronting pair loader --------------------------------------------------
load_sni_pairs <- function(json_path = Sys.getenv("SNI_PAIRS_FILE",
                                                   "working_sni_fronting.json")) {
  if (!file.exists(json_path)) {
    cat(sprintf("SNI pairs file not found (%s) - using hardcoded defaults.\n",
                json_path))
    return(SNI_FRONTING_PAIRS_DEFAULT)
  }
  tryCatch({
    pairs <- fromJSON(json_path, simplifyVector = FALSE)
    cat(sprintf("Loaded %d SNI-fronting pairs from %s\n", length(pairs), json_path))
    pairs
  }, error = function(e) {
    cat(sprintf("Could not parse %s: %s - using hardcoded defaults.\n",
                json_path, conditionMessage(e)))
    SNI_FRONTING_PAIRS_DEFAULT
  })
}

#-- Tier 0: SNI-fronting check ------------------------------------------------
# ONLY called on proxies that already passed Tier 2 (bale-tunnel).
# This avoids paying the full per-pair timeout cost (~30s) on the ~650 proxies
# that will never pass, keeping total job runtime within the 60-minute budget.
# Uses curl --tls-servername (fake SNI) + --resolve (connect_ip redirect).
# Short-circuits on first working pair so typical cost is 1 x timeout_secs.
check_sni_fronting <- function(proxy_url, timeout_secs,
                               sni_pairs = SNI_FRONTING_PAIRS_DEFAULT,
                               real_host = SNI_REAL_HOST) {
  curl_bin <- if (.Platform$OS.type == "windows") "curl.exe" else "curl"
  for (pair in sni_pairs) {
    connect_ip  <- pair$connect_ip
    fake_sni    <- pair$fake_sni
    resolve_arg <- sprintf("%s:443:%s", real_host, connect_ip)
    args <- c(
      "-s",
      "-o", if (.Platform$OS.type == "windows") "NUL" else "/dev/null",
      "-w", "%{http_code}",
      "-m", as.character(timeout_secs),
      "--connect-timeout", "3",
      "-x", proxy_url,
      "--tls-servername", fake_sni,
      "--resolve", resolve_arg,
      "-k", "-L",
      sprintf("https://%s/", real_host)
    )
    raw <- try(suppressWarnings(
      system2(curl_bin, args, stdout = TRUE, stderr = FALSE)
    ), silent = TRUE)
    status <- suppressWarnings(as.integer(trimws(paste(raw, collapse = " "))))
    if (!is.na(status) && status > 0L && status != 407L && status < 600L)
      return(list(
        ok = TRUE,
        connect_ip = connect_ip,
        fake_sni = fake_sni,
        status = status
      ))
  }
  list(ok = FALSE,
       connect_ip = NA_character_,
       fake_sni = NA_character_,
       status = NA_integer_)
}

#-- Pre-test priority heuristic -----------------------------------------------
pretest_score <- function(proxy_str) {
  parts <- strsplit(proxy_str, ":")[[1L]]
  if (length(parts) != 2L) return(0L)
  ip   <- parts[1L]
  port <- suppressWarnings(as.integer(parts[2L]))
  if (is.na(port)) return(0L)
  score <- 0L
  first2 <- paste(strsplit(ip, "\\.")[[1L]][1:2], collapse = ".")
  ir_hints <- c("5.160", "5.200", "5.201", "5.202", "5.238", "31.2", "31.14", "31.24",
                "31.40", "31.58", "31.59", "37.98", "37.152", "37.156", "37.202",
                "78.38", "78.39", "79.127", "80.191", "80.210", "82.99", "85.9",
                "85.15", "86.57", "87.107", "87.128", "88.135", "89.32", "89.33",
                "89.34", "89.144", "91.98", "91.99", "91.108", "91.186", "91.235",
                "91.239", "92.42", "92.49", "93.114", "93.115", "94.74", "94.184",
                "95.38", "95.80", "95.81", "95.142", "103.77", "103.231",
                "109.122", "109.123", "109.162", "110.38", "113.176",
                "176.65", "178.131", "178.215", "179.43", "185.4", "185.49",
                "185.55", "185.81", "185.94", "185.95", "185.96", "185.97",
                "185.98", "185.99", "185.100", "185.101", "185.102", "185.103",
                "185.104", "185.105", "185.106", "185.107", "185.108", "185.109",
                "185.110", "185.111", "185.112", "185.113", "185.116", "185.117",
                "185.118", "185.119", "185.120", "185.121", "185.122", "185.123",
                "185.124", "185.125", "185.126", "185.127", "185.128", "185.129",
                "185.130", "185.131", "185.132", "185.133", "185.134", "185.135",
                "185.136", "185.137", "185.138", "185.139", "185.140", "185.141",
                "188.208", "188.209", "188.210", "188.213", "188.214",
                "194.225", "195.146", "195.147", "195.148", "196.245",
                "217.144", "217.145", "217.146", "217.147", "217.172", "217.173")
  if (first2 %in% ir_hints) score <- score + 50L
  if (port %in% c(1080L, 1081L, 4145L, 5678L, 9050L, 9150L)) score <- score + 10L
  if (port %in% c(80L, 443L, 3128L, 8080L, 8118L, 8888L)) score <- score + 5L
  score
}

#-- Post-test priority score --------------------------------------------------
priority_score <- function(tier, country, geo_score, proto, bale_status, https_status) {
  base <- switch(tier,
                 "sni-fronting"        = 1200L,
                 "IR-exit"             = 1000L,
                 "bale-tunnel"         = 800L,
                 "bale-tunnel-blocked" = 650L,
                 "bale-bridge"         = 400L,
                 "fail"                = 0L,
                 0L)
  base <- base + (geo_score %||% 0L) * 20L
  if (!is.na(proto) && proto %in% c("socks5", "socks4")) base <- base + 30L
  if (!is.na(country) && country %in% IRAN_NEIGHBOR_CC)  base <- base + 40L
  if (!is.na(country) && country %in% IRAN_REGIONAL_CC)  base <- base + 15L
  if (!is.na(country) && country == "IR")                 base <- base + 100L
  if (!is.na(bale_status)) {
    if (bale_status == 200L)                              base <- base + 20L
    else if (bale_status >= 300L && bale_status < 400L)  base <- base + 10L
  }
  if (!is.na(https_status) && https_status > 0L) {
    if (https_status == 200L)                              base <- base + 50L
    else if (https_status >= 301L && https_status < 400L) base <- base + 30L
  }
  base
}

#-- 2 CLI overrides -----------------------------------------------------------
local({
  a <- commandArgs(trailingOnly = TRUE)
  if (length(a) == 0L) return()
  if (!startsWith(a[1L], "--")) INPUT_FILE <- a[1L]
  for (i in seq_along(a)) {
    if (a[i] == "--workers" && i < length(a)) WORKERS <- as.integer(a[i+1L])
    if (a[i] == "--timeout" && i < length(a)) TIMEOUT <- as.integer(a[i+1L])
  }
})

#-- 3 Geo-check targets -------------------------------------------------------
GEO_CHECKS <- list(
  list(url = "http://ip-api.com/json/?fields=status,countryCode", key = "countryCode"),
  list(url = "http://ipwho.is/",                                   key = "country_code"),
  list(url = "http://ipapi.co/json/",                              key = "country_code")
)

#-- 4 Load proxies ------------------------------------------------------------
load_proxies <- function(path) {
  if (!file.exists(path)) stop("File not found: ", path)
  pat <- "^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}:\\d{2,5}$"
  if (grepl("\\.json$", path, ignore.case = TRUE)) {
    dat    <- fromJSON(path, simplifyVector = FALSE)
    items  <- if (is.null(names(dat))) dat else unname(dat)
    plist  <- vapply(items, function(x) {
      v <- x[["proxy"]]; if (is.null(v) || !nzchar(v)) "" else as.character(v)
    }, character(1L))
  } else {
    lines  <- trimws(readLines(path, warn = FALSE))
    lines  <- lines[nzchar(lines) & !startsWith(lines, "#")]
    plist  <- character(0L)
    for (ln in lines) {
      tok  <- strsplit(ln, "\\s+")[[1L]]
      m    <- tok[grepl(pat, tok)]
      if (length(m)) plist <- c(plist, m[1L])
    }
  }
  unique(plist[grepl(pat, plist)])
}

#-- 5a Iranian infra reachability checks --------------------------------------
INTERCEPTOR_DOMAINS <- c(
  "zscaler.net", "zscalerone.net", "zscalertwo.net",
  "zscalerthree.net", "zscalerbeta.net", "zscalergov.net",
  "zscloud.net", "zscalerprivateaccess.net",
  "bluecoat.com", "symantec.com", "broadcom.com",
  "forcepoint.com", "websense.com",
  "umbrella.com", "opendns.com", "cisco.com",
  "prismaaccess.com", "gpcloudservice.com",
  "netskope.com", "netskopeusercontent.com",
  "mcafee.com", "trellix.com", "skyhighsecurity.com",
  "barracudanetworks.com", "cudaops.com",
  "iboss.com",
  "menlosecurity.com",
  "cloudflaregateway.com", "cloudflareclient.com",
  "captive-portal", "safe-browsing", "gateway.security"
)

is_interceptor_url <- function(url) {
  if (is.na(url) || !nzchar(url)) return(FALSE)
  host <- tryCatch({
    h <- sub("^https?://", "", url)
    h <- sub("/.*$", "", h)
    h <- sub(":.*$", "", h)
    tolower(h)
  }, error = function(e) "")
  if (!nzchar(host)) return(FALSE)
  any(vapply(INTERCEPTOR_DOMAINS, function(d)
    host == d || endsWith(host, paste0(".", d)),
    logical(1L)))
}

check_iranian_infra <- function(proxy_url, timeout_secs, endpoints) {
  curl_bin <- if (.Platform$OS.type == "windows") "curl.exe" else "curl"
  for (ep in endpoints) {
    args <- c(
      "-s",
      "-o", if (.Platform$OS.type == "windows") "NUL" else "/dev/null",
      "-w", "%{http_code} %{url_effective}",
      "-m", as.character(timeout_secs),
      "--connect-timeout", "3",
      "-x", proxy_url,
      "-L", "--insecure",
      ep
    )
    raw <- try(suppressWarnings(
      system2(curl_bin, args, stdout = TRUE, stderr = FALSE)
    ), silent = TRUE)
    if (inherits(raw, "try-error") || length(raw) == 0L) next
    last_line <- trimws(tail(raw[nzchar(trimws(raw))], 1L))
    tokens    <- strsplit(last_line, " ", fixed = TRUE)[[1L]]
    status    <- suppressWarnings(as.integer(tokens[1L]))
    final_url <- if (length(tokens) >= 2L) paste(tokens[-1L], collapse = " ") else ""
    if (is.na(status) || status <= 0L || status >= 600L) next
    if (status == 407L) next
    if (is_interceptor_url(final_url))
      return(list(reachable = FALSE, status = status, endpoint = ep,
                  final_url = final_url, intercepted = TRUE))
    return(list(reachable = TRUE, status = status, endpoint = ep,
                final_url = final_url, intercepted = FALSE))
  }
  list(reachable = FALSE, status = NA_integer_, endpoint = NA_character_,
       final_url = NA_character_, intercepted = FALSE)
}

check_bale <- function(proxy_url, timeout_secs, bale_endpoints) {
  check_iranian_infra(proxy_url, timeout_secs, bale_endpoints)
}

BALE_HTTPS_TARGET <- "https://web.bale.ai/"

#-- 5b HTTPS CONNECT tunnel check --------------------------------------------
check_bale_https <- function(proxy_url, timeout_secs) {
  curl_bin <- if (.Platform$OS.type == "windows") "curl.exe" else "curl"
  tmp_body <- tempfile(fileext = ".txt")
  on.exit(unlink(tmp_body), add = TRUE)
  args <- c(
    "-s",
    "-o", tmp_body,
    "-w", "%{http_code} %{url_effective}",
    "-m", as.character(timeout_secs),
    "--connect-timeout", "4",
    "-x", proxy_url,
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
  body_text <- tryCatch(
    paste(readLines(tmp_body, warn = FALSE), collapse = " "),
    error = function(e) ""
  )
  if (grepl("REMOTE_ADDR", body_text, fixed = TRUE))
    return(list(tunnel = "echo-page", https_status = 0L, https_url = ""))
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

#-- 5c Test one proxy ---------------------------------------------------------
run_checks <- function(purl, timeout_secs, geo_checks) {
  h <- 0L; cc <- "?"
  for (chk in geo_checks) {
    args <- c(
      "-s",
      "-m", as.character(timeout_secs),
      "--connect-timeout", as.character(max(2L, timeout_secs %/% 2L)),
      "-x", purl,
      "--max-redirs", "3",
      "-L", "-o", "-",
      chk$url
    )
    raw <- try(suppressWarnings(system2("curl", args, stdout = TRUE, stderr = FALSE)),
               silent = TRUE)
    if (inherits(raw, "try-error") || length(raw) == 0L) next
    body <- try(fromJSON(paste(raw, collapse = " "), simplifyVector = TRUE), silent = TRUE)
    if (inherits(body, "try-error") || is.null(body) || !is.list(body)) next
    val <- body[[chk$key]]
    if (!is.null(val) && length(val) == 1L && nzchar(val)) {
      if (cc == "?") cc <- val
      if (identical(val, "IR")) h <- h + 1L
    }
  }
  list(hits = h, country = cc)
}

test_proxy <- function(proxy_str, timeout_secs, geo_checks,
                       sni_pairs = SNI_FRONTING_PAIRS_DEFAULT) {
  parts <- strsplit(proxy_str, ":")[[1L]]
  if (length(parts) != 2L)
    return(list(proxy = proxy_str, ok = FALSE, tier = "fail", country = "parse-err",
                score = 0L, proto = "?", bale = FALSE, bale_status = NA_integer_,
                https_status = NA_integer_, https_url = "", final_url = "",
                sni_connect_ip = NA_character_, sni_fake_sni = NA_character_))
  host <- parts[1L]
  port <- suppressWarnings(as.integer(parts[2L]))
  if (is.na(port))
    return(list(proxy = proxy_str, ok = FALSE, tier = "fail", country = "bad-port",
                score = 0L, proto = "?", bale = FALSE, bale_status = NA_integer_,
                https_status = NA_integer_, https_url = "", final_url = "",
                sni_connect_ip = NA_character_, sni_fake_sni = NA_character_))
  proto     <- if (port %in% SOCKS5_PORTS) "socks5" else "http"
  proxy_url <- sprintf("%s://%s:%d", proto, host, port)

  #-- Geo check ---------------------------------------------------------------
  res     <- run_checks(proxy_url, timeout_secs, geo_checks)
  hits    <- res$hits
  country <- res$country

  # SOCKS4 fallback
  if (hits == 0L && proto == "socks5") {
    res4 <- run_checks(sprintf("socks4://%s:%d", host, port), timeout_secs, geo_checks)
    if (res4$hits > hits) {
      hits    <- res4$hits
      country <- res4$country
      proto   <- "socks4"
    }
  }

  #-- Tier 1: 2-of-3 geo sources confirm IR exit ----------------------------
  if (hits >= 2L)
    return(list(proxy = proxy_str, ok = TRUE, tier = "IR-exit",
                country = country, score = hits, proto = proto,
                bale = FALSE, bale_status = NA_integer_,
                https_status = NA_integer_, https_url = "",
                sni_connect_ip = NA_character_, sni_fake_sni = NA_character_))

  #-- Iranian infra probes (Bale -> Rubika -> Splus) ------------------------
  FAIL_PROBE <- list(reachable = FALSE, status = NA_integer_, endpoint = NA_character_,
                     final_url = NA_character_, intercepted = FALSE)
  bale_res   <- check_bale(proxy_url, timeout_secs, BALE_ENDPOINTS)
  rubika_res <- if (!isTRUE(bale_res$reachable) && !isTRUE(bale_res$intercepted))
    check_iranian_infra(proxy_url, timeout_secs, RUBIKA_ENDPOINTS)
  else FAIL_PROBE
  splus_res  <- if (!isTRUE(bale_res$reachable) && !isTRUE(bale_res$intercepted) &&
                   !isTRUE(rubika_res$reachable) && !isTRUE(rubika_res$intercepted))
    check_iranian_infra(proxy_url, timeout_secs, SPLUS_ENDPOINTS)
  else FAIL_PROBE

  iran_probe_score <- sum(c(isTRUE(bale_res$reachable),
                            isTRUE(rubika_res$reachable),
                            isTRUE(splus_res$reachable)))
  any_intercepted <- isTRUE(bale_res$intercepted) ||
    isTRUE(rubika_res$intercepted) ||
    isTRUE(splus_res$intercepted)

  if (any_intercepted) {
    first_int <- if (isTRUE(bale_res$intercepted)) bale_res
    else if (isTRUE(rubika_res$intercepted)) rubika_res
    else splus_res
    return(list(proxy = proxy_str, ok = FALSE, tier = "intercepted",
                country = country, score = hits, proto = proto,
                bale = FALSE, bale_status = first_int$status,
                iran_probe_score = 0L,
                https_status = NA_integer_, https_url = "",
                final_url = first_int$final_url %||% "",
                sni_connect_ip = NA_character_, sni_fake_sni = NA_character_))
  }

  if (iran_probe_score >= 1L) {
    # HTTPS tunnel check (Tier 2 vs 4 split)
    https_res <- check_bale_https(proxy_url, timeout_secs)
    tier <- switch(https_res$tunnel,
                   "open-200"     = "bale-tunnel",
                   "open-blocked" = "bale-tunnel-blocked",
                   "open-other"   = "bale-tunnel",
                   "bale-bridge")

    #-- Tier 0: SNI-fronting --------------------------------------------------
    sni_connect_ip <- NA_character_
    sni_fake_sni   <- NA_character_
    if (tier == "bale-tunnel") {
      sni_res <- check_sni_fronting(proxy_url, timeout_secs, sni_pairs)
      if (isTRUE(sni_res$ok)) {
        tier           <- "sni-fronting"
        sni_connect_ip <- sni_res$connect_ip
        sni_fake_sni   <- sni_res$fake_sni
      }
    }

    return(list(proxy             = proxy_str,
                ok                = TRUE,
                tier              = tier,
                country           = country,
                score             = hits,
                proto             = proto,
                bale              = isTRUE(bale_res$reachable),
                bale_status       = bale_res$status,
                iran_probe_score  = iran_probe_score,
                https_status      = https_res$https_status,
                https_url         = https_res$https_url %||% "",
                final_url         = bale_res$final_url %||% "",
                sni_connect_ip    = sni_connect_ip,
                sni_fake_sni      = sni_fake_sni))
  }

  #-- No tier passed --------------------------------------------------------
  list(proxy = proxy_str, ok = FALSE, tier = "fail",
       country = country, score = hits, proto = proto,
       bale = FALSE, bale_status = NA_integer_,
       https_status = NA_integer_, https_url = "", final_url = "",
       sni_connect_ip = NA_character_, sni_fake_sni = NA_character_)
}

#-- 6 Load --------------------------------------------------------------------
cat(sprintf("Loading proxies from: %s\n", INPUT_FILE))
proxies <- tryCatch(
  load_proxies(INPUT_FILE),
  error = function(e) { cat("ERROR:", conditionMessage(e), "\n"); NULL }
)
if (is.null(proxies) || length(proxies) == 0L) {
  cat("No valid ip:port entries found. Check INPUT_FILE path.\n")
  if (!interactive()) quit(status = 1L)
  stop("No proxies loaded")
}
total <- length(proxies)
cat(sprintf("Loaded %d proxies  |  workers=%d  timeout=%ds\n\n",
            total, WORKERS, TIMEOUT))

#-- Pre-test filter: remove corporate proxies --------------------------------
corp_flags <- vapply(proxies, function(p) {
  ip <- strsplit(p, ":")[[1L]][1L]
  is_corporate_ip(ip)
}, logical(1L))
n_corp <- sum(corp_flags)
if (n_corp > 0L) {
  cat(sprintf("Skipping %d corporate/intercepting IPs (Zscaler etc.):\n", n_corp))
  cat(paste0("  ", proxies[corp_flags], "\n"), sep = "")
  cat("\n")
  proxies <- proxies[!corp_flags]
}
total <- length(proxies)

#-- Pre-test ordering --------------------------------------------------------
pre_scores <- vapply(proxies, pretest_score, integer(1L))
proxies    <- proxies[order(pre_scores, decreasing = TRUE)]
cat(sprintf("Testing %d proxies after filtering (ordered by IR proximity)...\n\n",
            total))

#-- Staleness check ----------------------------------------------------------
check_staleness <- function(path, warn_hours) {
  if (!grepl("\\.json$", path, ignore.case = TRUE)) return(invisible(NULL))
  tryCatch({
    dat <- fromJSON(path, simplifyVector = FALSE)
    items <- if (is.null(names(dat))) dat else unname(dat)
    ts_vals <- vapply(items, function(x) x[["scan_timestamp"]] %||% "", character(1L))
    ts_vals <- ts_vals[nzchar(ts_vals)]
    if (length(ts_vals) == 0L) return(invisible(NULL))
    latest <- max(as.POSIXct(ts_vals, format = "%Y-%m-%dT%H:%M:%SZ", tz = "UTC"),
                  na.rm = TRUE)
    age_h <- as.numeric(difftime(Sys.time(), latest, units = "hours"))
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

#-- Load SNI-fronting pairs --------------------------------------------------
SNI_PAIRS <- load_sni_pairs()

#-- 7 Run --------------------------------------------------------------------
worker_fn <- function(p) test_proxy(p, TIMEOUT, GEO_CHECKS, SNI_PAIRS)
t0 <- proc.time()
if (.Platform$OS.type == "windows" && WORKERS > 1L) {
  cores <- min(WORKERS, detectCores(logical = TRUE))
  cat(sprintf("Starting Windows socket cluster with %d workers...\n\n", cores))
  cl <- makeCluster(cores)
  on.exit(stopCluster(cl), add = TRUE)
  clusterExport(cl, varlist = c("GEO_CHECKS", "TIMEOUT", "SOCKS5_PORTS",
                                "BALE_ENDPOINTS", "RUBIKA_ENDPOINTS",
                                "SPLUS_ENDPOINTS", "BALE_HTTPS_TARGET",
                                "IRAN_NEIGHBOR_CC", "IRAN_REGIONAL_CC",
                                "CORPORATE_RANGES", "INTERCEPTOR_DOMAINS",
                                "SNI_PAIRS", "SNI_REAL_HOST",
                                "SNI_FRONTING_PAIRS_DEFAULT",
                                "ip_to_int", "is_in_cidr", "is_corporate_ip",
                                "is_interceptor_url",
                                "test_proxy", "check_bale",
                                "check_iranian_infra", "check_bale_https",
                                "check_sni_fronting", "load_sni_pairs",
                                "run_checks", "priority_score", "%||%"),
                envir = environment())
  clusterEvalQ(cl, suppressPackageStartupMessages(library(jsonlite)))
  results_raw <- parLapplyLB(cl, proxies, worker_fn)
} else if (.Platform$OS.type == "unix" && WORKERS > 1L) {
  results_raw <- mclapply(proxies, worker_fn,
                          mc.cores = min(WORKERS, detectCores(logical = FALSE)),
                          mc.preschedule = FALSE)
} else {
  cat("Running sequentially (single worker)...\n\n")
  results_raw <- lapply(proxies, worker_fn)
}
elapsed <- (proc.time() - t0)[["elapsed"]]

#-- 8 Print results ----------------------------------------------------------
results <- do.call(rbind, lapply(seq_along(results_raw), function(i) {
  r <- results_raw[[i]]
  if (!is.list(r)) {
    proxy_str <- if (i <= length(proxies)) proxies[[i]] else "unknown:0"
    cat(sprintf("[%4d/%d] %-26s  [ERROR] worker crashed\n", i, total, proxy_str))
    r <- list(proxy = proxy_str, ok = FALSE, tier = "fail", country = "?", score = 0L,
              proto = "?", bale = FALSE, bale_status = NA_integer_,
              https_status = NA_integer_, https_url = "", final_url = "",
              sni_connect_ip = NA_character_, sni_fake_sni = NA_character_)
  }
  proto_tag <- sprintf("%-6s", toupper(r$proto %||% "?"))
  tier <- r$tier %||% "fail"
  tag <- switch(tier,
                "sni-fronting"        = sprintf("[ T0 ] SNI-FRONTING        (%s) via %s fake_sni=%s HTTP %s",
                                                proto_tag,
                                                r$sni_connect_ip %||% "?",
                                                r$sni_fake_sni %||% "?",
                                                r$bale_status %||% "?"),
                "IR-exit"             = sprintf("[ T1 ] IR-EXIT             (%s)", proto_tag),
                "bale-tunnel"         = sprintf("[ T2 ] BALE-TUNNEL         (%s) HTTP %s HTTPS %s",
                                                proto_tag,
                                                r$bale_status %||% "?",
                                                r$https_status %||% "?"),
                "bale-tunnel-blocked" = sprintf("[ T3 ] BALE-TUNNEL-BLOCKED (%s) HTTPS %s (IP blocked by Bale)",
                                                proto_tag, r$https_status %||% "?"),
                "bale-bridge"         = sprintf("[ T4 ] BALE-BRIDGE HTTP-only (%s) HTTP %s",
                                                proto_tag, r$bale_status %||% "?"),
                "intercepted"         = sprintf("[HIJACK] %s -> %s",
                                                r$country, r$final_url %||% "?"),
                sprintf("[FAIL ] %-4s %d/3 (%s)", r$country, r$score, proto_tag))
  cat(sprintf("[%4d/%d] %-26s  %s\n", i, total, r$proxy, tag))
  data.frame(proxy          = r$proxy,
             ok             = isTRUE(r$ok),
             tier           = tier,
             country        = r$country,
             score          = r$score,
             proto          = r$proto %||% "?",
             bale           = isTRUE(r$bale),
             bale_status    = r$bale_status %||% NA_integer_,
             https_status   = r$https_status %||% NA_integer_,
             https_url      = r$https_url %||% "",
             final_url      = r$final_url %||% "",
             sni_connect_ip = r$sni_connect_ip %||% NA_character_,
             sni_fake_sni   = r$sni_fake_sni %||% NA_character_,
             stringsAsFactors = FALSE)
}))

#-- 9 Summary + save ---------------------------------------------------------
passed           <- results[results$ok, , drop = FALSE]
sni_fronting     <- results[results$tier == "sni-fronting", , drop = FALSE]
ir_exit          <- results[results$tier == "IR-exit", , drop = FALSE]
bale_tunnel      <- results[results$tier == "bale-tunnel", , drop = FALSE]
bale_tunnel_blk  <- results[results$tier == "bale-tunnel-blocked", , drop = FALSE]
bale_bridge      <- results[results$tier == "bale-bridge", , drop = FALSE]
intercepted      <- results[results$tier == "intercepted", , drop = FALSE]

if (nrow(passed) > 0L) {
  passed$priority <- mapply(priority_score,
                            passed$tier, passed$country, passed$score,
                            passed$proto, passed$bale_status, passed$https_status)
  passed <- passed[order(passed$priority, decreasing = TRUE), ]
  sni_fronting    <- passed[passed$tier == "sni-fronting", , drop = FALSE]
  ir_exit         <- passed[passed$tier == "IR-exit", , drop = FALSE]
  bale_tunnel     <- passed[passed$tier == "bale-tunnel", , drop = FALSE]
  bale_tunnel_blk <- passed[passed$tier == "bale-tunnel-blocked", , drop = FALSE]
  bale_bridge     <- passed[passed$tier == "bale-bridge", , drop = FALSE]
}

cat(sprintf(
  "\n%s\n SNI-fronting (Tier 0)    : %d  (domain-fronted, DPI-resistant)\n IR-exit (Tier 1)         : %d  (full IR routing)\n Bale-tunnel (Tier 2)     : %d  (HTTPS tunnel to web.bale.ai works)\n Bale-tunnel-blk (Tier 3) : %d  (tunnel works, Bale blocks exit IP)\n Bale-bridge (Tier 4)     : %d  (plain HTTP only, no HTTPS tunnel)\n Intercepted              : %d  (hijacked - NOT usable)\n Total passed: %d / %d  (%.1f%%)   Elapsed: %.0fs\n",
  strrep("-", 60),
  nrow(sni_fronting), nrow(ir_exit), nrow(bale_tunnel),
  nrow(bale_tunnel_blk), nrow(bale_bridge), nrow(intercepted),
  nrow(passed), total,
  if (total > 0L) 100 * nrow(passed) / total else 0,
  elapsed
))

if (nrow(intercepted) > 0L) {
  cat("\nIntercepted proxies (connection hijacked - do NOT use):\n")
  for (i in seq_len(nrow(intercepted)))
    cat(sprintf("  %-26s  redirected to: %s\n",
                intercepted$proxy[i], intercepted$final_url[i]))
}

out_dir <- tryCatch(dirname(normalizePath(INPUT_FILE)), error = function(e) getwd())
r_out <- Sys.getenv("R_OUTPUT_DIR", "")
if (nzchar(r_out) && dir.exists(r_out)) out_dir <- r_out

if (nrow(sni_fronting) > 0L) {
  cat("\nSNI-fronting proxies - domain-fronted via Cloudflare (best first):\n")
  for (i in seq_len(nrow(sni_fronting)))
    cat(sprintf("  [pri=%d] %-26s  %s | fake_sni=%s -> %s | HTTP %s\n",
                sni_fronting$priority[i], sni_fronting$proxy[i],
                sni_fronting$proto[i],
                sni_fronting$sni_fake_sni[i],
                sni_fronting$sni_connect_ip[i],
                sni_fronting$bale_status[i]))
  writeLines(sni_fronting$proxy, file.path(out_dir, "passing_sni_fronting.txt"))
  write_json(sni_fronting, file.path(out_dir, "passing_sni_fronting.json"),
             pretty = TRUE, auto_unbox = TRUE)
}

if (nrow(ir_exit) > 0L) {
  cat("\nIR-exit proxies (best first):\n")
  for (i in seq_len(nrow(ir_exit)))
    cat(sprintf("  [pri=%d] %-26s  %s geo=%d/3\n",
                ir_exit$priority[i], ir_exit$proxy[i],
                ir_exit$proto[i], ir_exit$score[i]))
  writeLines(ir_exit$proxy, file.path(out_dir, "passing_ir_exit.txt"))
  write_json(ir_exit, file.path(out_dir, "passing_ir_exit.json"),
             pretty = TRUE, auto_unbox = TRUE)
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
             pretty = TRUE, auto_unbox = TRUE)
}

if (nrow(bale_tunnel_blk) > 0L) {
  cat("\nBale-tunnel-blocked proxies - HTTPS tunnel works, Bale blocks exit IP:\n")
  for (i in seq_len(nrow(bale_tunnel_blk)))
    cat(sprintf("  [pri=%d] %-26s  country=%s | HTTPS %s\n",
                bale_tunnel_blk$priority[i], bale_tunnel_blk$proxy[i],
                bale_tunnel_blk$country[i], bale_tunnel_blk$https_status[i]))
  writeLines(bale_tunnel_blk$proxy, file.path(out_dir, "passing_bale_tunnel_blocked.txt"))
  write_json(bale_tunnel_blk, file.path(out_dir, "passing_bale_tunnel_blocked.json"),
             pretty = TRUE, auto_unbox = TRUE)
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
             pretty = TRUE, auto_unbox = TRUE)
}

if (nrow(passed) > 0L) {
  writeLines(passed$proxy, file.path(out_dir, "passing_all_ranked.txt"))
  write_json(passed, file.path(out_dir, "passing_all_ranked.json"),
             pretty = TRUE, auto_unbox = TRUE)
  top       <- passed$proxy[1]
  top_tier  <- passed$tier[1]
  top_parts <- strsplit(top, ":")[[1L]]
  cat(sprintf("\n-- Use the top proxy (%s, tier=%s) --\n", top, top_tier))
  if (top_tier == "sni-fronting") {
    cat(sprintf("  config.json: CONNECT_IP=%s  FAKE_SNI=%s  CONNECT_PORT=443\n",
                passed$sni_connect_ip[1], passed$sni_fake_sni[1]))
    cat(sprintf("  curl test: curl -x http://%s --tls-servername %s --resolve tapi.bale.ai:443:%s -k https://tapi.bale.ai/ -I\n",
                top, passed$sni_fake_sni[1], passed$sni_connect_ip[1]))
  } else {
    cat(sprintf("  Windows proxy settings: %s  port %s\n", top_parts[1], top_parts[2]))
    cat(sprintf("  curl test: curl -x http://%s -k https://web.bale.ai/ -I\n", top))
  }
}
if (nrow(passed) == 0L) cat("\nNo working proxies found.\n")

if (nrow(passed) > 0L) {
  cat(sprintf("\nSaved to %s:\n", out_dir))
  if (nrow(sni_fronting) > 0L)     cat("  passing_sni_fronting.txt / .json\n")
  if (nrow(ir_exit) > 0L)          cat("  passing_ir_exit.txt / .json\n")
  if (nrow(bale_tunnel) > 0L)      cat("  passing_bale_tunnel.txt / .json\n")
  if (nrow(bale_tunnel_blk) > 0L)  cat("  passing_bale_tunnel_blocked.txt / .json\n")
  if (nrow(bale_bridge) > 0L)      cat("  passing_bale_bridge.txt / .json\n")
  cat("  passing_all_ranked.txt / .json  (all tiers, priority-sorted)\n")
}

#-- Country breakdown --------------------------------------------------------
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

cat(sprintf("\n Protocol breakdown\n%s\n", strrep("-", 40)))
proto_tbl <- sort(table(results$proto), decreasing = TRUE)
for (i in seq_along(proto_tbl))
  cat(sprintf("  %-8s %4d\n", names(proto_tbl)[i], proto_tbl[[i]]))

if (nrow(sni_fronting) > 0L) {
  cat(sprintf("\n SNI-fronting pair usage\n%s\n", strrep("-", 40)))
  sni_tbl <- sort(table(paste0(sni_fronting$sni_connect_ip, " / ",
                               sni_fronting$sni_fake_sni)), decreasing = TRUE)
  for (i in seq_along(sni_tbl))
    cat(sprintf("  %-55s %4d\n", names(sni_tbl)[i], sni_tbl[[i]]))
}
