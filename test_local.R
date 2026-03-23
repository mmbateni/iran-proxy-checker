# ─────────────────────────────────────────────────────────────────────────────
# Iran Proxy Tester — Live-Verified Edition (ASN-Aware)
# Fetches proxies from globally-routable Iranian ASNs, then re-tests
# from YOUR network in BC/Canada, confirming an Iranian exit IP.
#
# install.packages(c("httr2", "curl", "jsonlite", "cli", "optparse"))
# ─────────────────────────────────────────────────────────────────────────────

suppressPackageStartupMessages({
  library(httr2); library(curl); library(jsonlite)
  library(cli);   library(optparse); library(parallel)
})

option_list <- list(
  make_option("--file",       type="character", default=NULL,
              help="Optional extra proxy list file to merge in"),
  make_option("--timeout",    type="integer",   default=20L,
              help="HTTP timeout per proxy in seconds [default: %default]"),
  make_option("--tcp",        type="integer",   default=8L,
              help="TCP connect timeout in seconds [default: %default]"),
  make_option("--workers",    type="integer",   default=15L,
              help="Parallel workers [default: %default]"),
  make_option("--output",     type="character", default="verified_local.txt",
              help="Output file [default: %default]"),
  make_option("--skip-fetch", action="store_true", default=FALSE,
              help="Skip live fetch, only test --file")
)
args   <- parse_args(OptionParser(option_list = option_list))
TOUT   <- args$timeout
TCP_TO <- args$tcp
NW     <- min(args$workers, parallel::detectCores(logical=TRUE))
OUTF   <- args$output
UA     <- "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

`%||%` <- function(a, b) if (!is.null(a) && length(a) > 0 && !is.na(a[[1]])) a else b

log_ts <- function(msg) {
  cli::cli_text("[{format(Sys.time(),'%H:%M:%S',tz='UTC')}] {msg}")
}

# ══════════════════════════════════════════════════════════════════════════════
# ASN allowlist — same as check_proxies.py
# ══════════════════════════════════════════════════════════════════════════════

ROUTABLE_ASNS <- c(
  "AS43754",   # Asiatech Data Transmission — telewebion.ir
  "AS64422",   # Sima Rayan Sharif — telewebion.ir (current IP)
  "AS62229",   # Fars News Agency — farsnews.ir
  "AS48159",   # TIC / ITC Backbone
  "AS12880",   # Iran Telecommunications Co.
  "AS16322",   # Pars Online / Respina
  "AS42337",   # Respina Networks & Beyond
  "AS49666",   # TIC Gateway (transit for all Iranian ISPs)
  "AS21341",   # Fanava Group — sepehrtv.ir
  "AS24631",   # FANAPTELECOM / Fanavari Pasargad
  "AS56402",   # Dadeh Gostar Asr Novin
  "AS31549",   # Afranet
  "AS44244",   # IranCell / MCI
  "AS197207",  # Mobile Communication of Iran (MCI)
  "AS58224",   # Iran Telecom PJS
  "AS39501",   # Aria Shatel
  "AS57218",   # RayaPars
  "AS25184",   # Afagh Danesh Gostar
  "AS51695",   # Iranian ISP
  "AS47262"    # Iranian ISP
)

FALLBACK_CIDRS <- c(
  "79.127.0.0/17", "188.0.208.0/20", "188.0.240.0/20", "5.160.0.0/14",
  "194.225.0.0/20", "62.60.0.0/15", "213.176.0.0/16",
  "2.144.0.0/12", "2.176.0.0/12", "94.182.0.0/15",
  "217.218.0.0/15", "217.219.0.0/16",
  "78.38.0.0/15", "91.92.0.0/16",
  "77.36.128.0/17", "85.185.0.0/16", "37.32.0.0/11",
  "5.200.0.0/14", "80.191.0.0/16", "80.210.0.0/15",
  "87.247.0.0/16", "185.49.96.0/22", "185.93.0.0/16"
)

# ── IP-in-CIDR helper ─────────────────────────────────────────────────────────
# Uses numeric (double) arithmetic to avoid R's 32-bit integer overflow
# which caused NA results for IPs > 127.255.255.255.
ip_to_num <- function(ip) {
  parts <- as.numeric(strsplit(ip, "\\.")[[1]])
  parts[1]*16777216 + parts[2]*65536 + parts[3]*256 + parts[4]
}

cidr_to_range <- function(cidr) {
  parts  <- strsplit(cidr, "/")[[1]]
  prefix <- as.numeric(parts[2])
  net    <- ip_to_num(parts[1])
  mask   <- (2^32 - 1) - (2^(32 - prefix) - 1)
  start  <- bitwAnd(as.integer(net %% 2^31) * 2L, as.integer(mask %% 2^31) * 2L)
  # Use pure numeric (no bitwAnd overflow): mask out via modular arithmetic
  net_masked <- floor(net / 2^(32 - prefix)) * 2^(32 - prefix)
  list(start = net_masked, end = net_masked + 2^(32 - prefix) - 1)
}

in_any_cidr <- function(ip, cidrs) {
  tryCatch({
    ip_num <- ip_to_num(ip)
    any(vapply(cidrs, function(cidr) {
      parts  <- strsplit(cidr, "/")[[1]]
      prefix <- as.numeric(parts[2])
      block  <- 2^(32 - prefix)
      net    <- ip_to_num(parts[1])
      start  <- floor(net / block) * block
      ip_num >= start && ip_num < start + block
    }, logical(1)))
  }, error = function(e) FALSE)
}

# ── Fetch routable CIDRs: JSON → BGPView → fallback ──────────────────────────
fetch_routable_cidrs <- function(asns, ua) {
  cidrs <- character(0)
  
  # Tier 1: committed JSON (fast, works offline)
  script_dir <- tryCatch(dirname(normalizePath(sys.frames()[[1]]$ofile)),
                         error = function(e) ".")
  json_path  <- file.path(script_dir, "merged_routable_asns.json")
  if (file.exists(json_path)) {
    tryCatch({
      db <- jsonlite::fromJSON(json_path, simplifyVector = FALSE)
      for (entry in db) cidrs <- c(cidrs, unlist(entry$prefixes))
      if (length(cidrs))
        log_ts(sprintf("  Loaded %d prefixes from merged_routable_asns.json",
                       length(unique(cidrs))))
    }, error = function(e)
      log_ts(sprintf("  ! JSON load: %s", conditionMessage(e))))
  }
  
  # Tier 2: RIPE Stat refresh (primary) with BGPView fallback
  # RIPE Stat is always publicly accessible; BGPView is often blocked.
  log_ts(sprintf("  Refreshing from RIPE Stat (%d ASNs)…", length(asns)))
  new_found <- FALSE
  for (asn in asns) {
    tryCatch({
      asn_num  <- sub("^AS", "", asn)
      ripe_url <- paste0(
        "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS",
        asn_num
      )
      r    <- request(ripe_url) |>
        req_timeout(20) |> req_headers("User-Agent" = ua) |> req_perform()
      d    <- resp_body_json(r)
      rows <- if (is.list(d$data$prefixes) && length(d$data$prefixes) > 0)
        d$data$prefixes else list()
      pfx  <- vapply(rows, function(p) {
        pr <- if (!is.null(p$prefix)) p$prefix else ""
        if (nzchar(pr) && !grepl(":", pr)) pr else ""  # IPv4 only
      }, character(1))
      pfx <- pfx[nzchar(pfx)]
      if (length(pfx)) {
        cidrs     <- c(cidrs, pfx)
        new_found <- TRUE
        log_ts(sprintf("  %s → %d prefixes", asn, length(pfx)))
      }
    }, error = function(e) {
      msg <- conditionMessage(e)
      if (!grepl("resolve|connect|network", msg, ignore.case = TRUE))
        log_ts(sprintf("  ! RIPE Stat %s: %s", asn, msg))
    })
    Sys.sleep(0.1)   # be polite to RIPE Stat
  }
  if (!new_found) log_ts("  RIPE Stat unreachable — using JSON data only")
  
  if (length(cidrs)) {
    u <- unique(cidrs)
    log_ts(sprintf("  Total routable prefixes: %d", length(u)))
    return(u)
  }
  
  log_ts("  Both JSON and BGPView failed — using hardcoded fallback CIDRs")
  FALLBACK_CIDRS
}

# ── Collect proxy candidates ──────────────────────────────────────────────────
fetch_live_verified <- function(ua) {
  proxies <- character(0)
  
  # proxyscrape IR
  for (proto in c("http","socks4","socks5")) {
    url <- paste0("https://api.proxyscrape.com/v3/free-proxy-list/get",
                  "?request=displayproxies&country=ir&protocol=", proto,
                  "&anonymity=all&timeout=5000&simplified=true")
    tryCatch({
      r    <- request(url) |> req_timeout(15) |>
        req_headers("User-Agent" = ua) |> req_perform()
      body <- tryCatch(resp_body_string(r), error = function(e) "")
      if (!nzchar(trimws(body))) {
        log_ts(sprintf("  proxyscrape %-7s → (no results)", proto))
      } else {
        lines <- strsplit(body, "\n")[[1]]
        lines <- trimws(lines[grepl("^\\d+\\.\\d+\\.\\d+\\.\\d+:\\d+", lines)])
        if (length(lines)) {
          log_ts(sprintf("  proxyscrape %-7s → %d proxies", proto, length(lines)))
          proxies <- c(proxies, lines)
        } else {
          log_ts(sprintf("  proxyscrape %-7s → (no results)", proto))
        }
      }
    }, error = function(e)
      log_ts(sprintf("  ! proxyscrape %s: %s", proto, conditionMessage(e))))
  }
  
  # proxifly IR
  tryCatch({
    url <- "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/countries/IR/data.txt"
    r   <- request(url) |> req_timeout(15) |> req_headers("User-Agent"=ua) |> req_perform()
    m   <- regmatches(resp_body_string(r),
                      gregexpr("\\d{1,3}(?:\\.\\d{1,3}){3}:\\d{2,5}",
                               resp_body_string(r), perl=TRUE))[[1]]
    if (length(m)) {
      log_ts(sprintf("  proxifly IR          → %d proxies", length(m)))
      proxies <- c(proxies, m)
    }
  }, error = function(e) log_ts(sprintf("  ! proxifly: %s", conditionMessage(e))))
  
  # OpenRay Iran top-100
  tryCatch({
    url <- paste0("https://raw.githubusercontent.com/sakha1370/OpenRay/",
                  "refs/heads/main/output_iran/iran_top100_checked.txt")
    r   <- request(url) |> req_timeout(15) |> req_headers("User-Agent"=ua) |> req_perform()
    m   <- regmatches(resp_body_string(r),
                      gregexpr("\\d{1,3}(?:\\.\\d{1,3}){3}:\\d{2,5}",
                               resp_body_string(r), perl=TRUE))[[1]]
    if (length(m)) {
      log_ts(sprintf("  OpenRay Iran top100  → %d proxies", length(m)))
      proxies <- c(proxies, m)
    }
  }, error = function(e) log_ts(sprintf("  ! openray: %s", conditionMessage(e))))
  
  # Geonode IR
  tryCatch({
    url <- paste0("https://proxylist.geonode.com/api/proxy-list",
                  "?country=IR&limit=100&page=1&sort_by=lastChecked&sort_type=desc")
    r   <- request(url) |> req_timeout(15) |> req_headers("User-Agent"=ua) |> req_perform()
    d   <- resp_body_json(r)
    rows <- if (is.list(d$data) && length(d$data) > 0) d$data else list()
    geo  <- vapply(rows, function(p) {
      ip   <- if (!is.null(p$ip)   && length(p$ip)   > 0) as.character(p$ip[[1]])   else ""
      # port may be int, str, or list
      port_raw <- p$port
      port <- if (is.list(port_raw) && length(port_raw) > 0) {
        as.character(port_raw[[1]])
      } else if (!is.null(port_raw)) {
        as.character(port_raw)
      } else ""
      paste0(ip, ":", port)
    }, character(1))
    geo <- geo[grepl("^\\d+\\.\\d+\\.\\d+\\.\\d+:\\d+$", geo)]
    if (length(geo)) {
      log_ts(sprintf("  Geonode IR           → %d proxies", length(geo)))
      proxies <- c(proxies, geo)
    }
  }, error = function(e) log_ts(sprintf("  ! geonode: %s", conditionMessage(e))))
  
  # proxydb IR
  for (proto in c("socks5","http")) {
    tryCatch({
      url <- paste0("https://proxydb.net/?protocol=", proto, "&country=IR")
      r   <- request(url) |> req_timeout(15) |> req_headers("User-Agent"=ua) |> req_perform()
      m   <- regmatches(resp_body_string(r),
                        gregexpr("\\d{1,3}(?:\\.\\d{1,3}){3}:\\d{2,5}",
                                 resp_body_string(r), perl=TRUE))[[1]]
      if (length(m)) {
        log_ts(sprintf("  proxydb IR %-7s   → %d proxies", proto, length(m)))
        proxies <- c(proxies, m)
      }
    }, error = function(e) log_ts(sprintf("  ! proxydb %s: %s", proto, conditionMessage(e))))
  }
  
  unique(trimws(proxies[nchar(trimws(proxies)) > 0]))
}

# ── ASN filter ────────────────────────────────────────────────────────────────
asn_filter_proxies <- function(proxies, cidrs) {
  if (length(proxies) == 0) return(proxies)
  log_ts(sprintf("ASN-filtering %d proxies…", length(proxies)))
  keep <- vapply(proxies, function(p) {
    ip <- strsplit(p, ":")[[1]][1]
    tryCatch(in_any_cidr(ip, cidrs), error = function(e) FALSE)
  }, logical(1))
  result <- proxies[keep & !is.na(keep)]
  log_ts(sprintf("  → %d on routable Iranian ASNs (%d discarded)",
                 length(result), sum(!keep | is.na(keep))))
  result
}

# ── Proxy tester ──────────────────────────────────────────────────────────────
VERIFY_URL    <- "http://ip-api.com/json/?fields=status,countryCode,query,org,city"
FALLBACK_URLS <- c("http://api.ipify.org","http://ifconfig.me/ip",
                   "http://checkip.amazonaws.com","http://icanhazip.com")

test_one <- function(proxy_str, tcp_to, http_to, verify_url, fallback_urls, ua) {
  `%||%` <- function(a,b) if (!is.null(a) && length(a) > 0 && !is.na(a[[1]])) a else b
  parts <- strsplit(proxy_str, ":")[[1]]
  if (length(parts) != 2) return(list(proxy=proxy_str, status="INVALID"))
  ip <- parts[1]; port <- as.integer(parts[2])
  
  tcp_ok <- tryCatch({
    con <- socketConnection(host=ip, port=port, open="r+b",
                            timeout=tcp_to, blocking=TRUE)
    close(con); TRUE
  }, error = function(e) FALSE)
  if (!tcp_ok) return(list(proxy=proxy_str, status="TCP_DEAD"))
  
  for (proto in c("socks5","http","socks4")) {
    proxy_url <- sprintf("%s://%s:%d", proto, ip, port)
    
    result <- tryCatch({
      h <- new_handle()
      handle_setopt(h, proxy=proxy_url, timeout=http_to,
                    useragent=ua, followlocation=TRUE)
      t0  <- proc.time()[["elapsed"]]
      res <- curl_fetch_memory(verify_url, handle=h)
      lat <- round((proc.time()[["elapsed"]]-t0)*1000)
      if (res$status_code >= 200 && res$status_code < 400) {
        d  <- tryCatch(jsonlite::fromJSON(rawToChar(res$content)),
                       error = function(e) list())
        cc <- d$countryCode %||% ""
        if (!is.null(d$status) && d$status == "success")
          list(proxy=proxy_str,
               status=if(cc=="IR") "WORKING" else "WRONG_COUNTRY",
               protocol=toupper(proto), latency_ms=lat,
               exit_ip=d$query%||%"", country=cc,
               city=d$city%||%"", isp=d$org%||%"")
        else NULL
      } else NULL
    }, error = function(e) NULL)
    if (!is.null(result)) return(result)
    
    for (furl in fallback_urls) {
      r2 <- tryCatch({
        h2 <- new_handle()
        handle_setopt(h2, proxy=proxy_url, timeout=http_to,
                      useragent=ua, followlocation=TRUE)
        t0  <- proc.time()[["elapsed"]]
        res <- curl_fetch_memory(furl, handle=h2)
        lat <- round((proc.time()[["elapsed"]]-t0)*1000)
        if (res$status_code >= 200 && res$status_code < 400)
          list(proxy=proxy_str, status="WORKING_UNVERIFIED",
               protocol=toupper(proto), latency_ms=lat,
               exit_ip=trimws(rawToChar(res$content)),
               country="?", city="", isp="")
        else NULL
      }, error = function(e) NULL)
      if (!is.null(r2)) return(r2)
    }
  }
  list(proxy=proxy_str, status="TCP_OPEN_NO_RESPONSE")
}

run_parallel <- function(proxies, nw, tcp_to, http_to) {
  log_ts(sprintf("Testing %d proxies (%d workers | TCP:%ds HTTP:%ds)…",
                 length(proxies), nw, tcp_to, http_to))
  env <- list(VERIFY_URL=VERIFY_URL, FALLBACK_URLS=FALLBACK_URLS,
              UA=UA, tcp_to=tcp_to, http_to=http_to)
  cl  <- makeCluster(nw, type="PSOCK")
  on.exit(stopCluster(cl), add=TRUE)
  clusterExport(cl, c("test_one","env"), envir=environment())
  clusterEvalQ(cl, {
    library(curl); library(jsonlite)
    `%||%` <- function(a,b) if (!is.null(a)&&length(a)>0&&!is.na(a[[1]])) a else b
  })
  parLapply(cl, proxies, function(p)
    test_one(p, env$tcp_to, env$http_to, env$VERIFY_URL, env$FALLBACK_URLS, env$UA))
}

# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

cli::cli_rule(center=" Iran Proxy Tester — Live-Verified ASN Edition ")
cat("\n")

my_ip <- tryCatch({
  d <- resp_body_json(request(VERIFY_URL) |> req_timeout(8) |> req_perform())
  sprintf("%s (%s, %s, %s)", d$query%||%"?", d$city%||%"?",
          d$regionName%||%"?", d$countryCode%||%"?")
}, error = function(e) "unknown")
log_ts(sprintf("Your public IP: %s", my_ip))
cat("\n")

routable_cidrs <- fetch_routable_cidrs(ROUTABLE_ASNS, UA)

proxies <- character(0)
if (!args$`skip-fetch`) {
  log_ts("Fetching IR proxy candidates from live sources…")
  proxies <- fetch_live_verified(UA)
  log_ts(sprintf("Raw pool: %d unique IR proxy candidates", length(proxies)))
  cat("\n")
  proxies <- asn_filter_proxies(proxies, routable_cidrs)
  log_ts(sprintf("After ASN filter: %d proxies to test", length(proxies)))
}

if (!is.null(args$file) && file.exists(args$file)) {
  lines <- readLines(args$file, warn=FALSE)
  lines <- trimws(lines[!grepl("^\\s*#", lines) & nchar(trimws(lines)) > 0])
  m     <- unique(unlist(regmatches(lines,
                                    gregexpr("\\d{1,3}(?:\\.\\d{1,3}){3}:\\d{2,5}", lines, perl=TRUE))))
  m     <- asn_filter_proxies(m, routable_cidrs)
  log_ts(sprintf("Merged %d ASN-filtered proxies from %s", length(m), args$file))
  proxies <- unique(c(proxies, m))
}

if (length(proxies) == 0) {
  cli::cli_alert_danger(paste(
    "No proxies survived ASN filter.",
    "Run check_proxies.py first (active scan) and pass its output with --file."
  ))
  quit(status=1)
}

cat("\n")
results <- run_parallel(proxies, NW, TCP_TO, TOUT)

working  <- Filter(function(r) identical(r$status,"WORKING"),              results)
unverif  <- Filter(function(r) identical(r$status,"WORKING_UNVERIFIED"),   results)
wrong_cc <- Filter(function(r) identical(r$status,"WRONG_COUNTRY"),        results)
tcp_open <- Filter(function(r) identical(r$status,"TCP_OPEN_NO_RESPONSE"), results)
tcp_dead <- Filter(function(r) identical(r$status,"TCP_DEAD"),             results)

by_lat  <- function(lst) lst[order(sapply(lst, function(r) r$latency_ms%||%99999))]
working <- by_lat(working)
unverif <- by_lat(unverif)

for (r in c(working, unverif)) {
  icon <- if(identical(r$status,"WORKING")) "\u2705" else "\u26a0\ufe0f"
  cli::cli_text(sprintf("  %s [%-6s] %-26s %5dms  %-15s %s",
                        icon, r$protocol%||%"", r$proxy, r$latency_ms%||%0,
                        r$city%||%"", r$isp%||%""))
}

cat("\n")
cli::cli_rule()
cli::cli_text(sprintf("RESULTS FROM: %s", my_ip))
cli::cli_rule()
cat(sprintf("  \033[32m%2d\033[0m Working   — Iranian exit IP confirmed\n", length(working)))
cat(sprintf("  \033[33m%2d\033[0m Connected — country unverified\n",        length(unverif)))
cat(sprintf("  \033[36m%2d\033[0m Wrong country exit IP\n",                 length(wrong_cc)))
cat(sprintf("  \033[35m%2d\033[0m TCP open, proxy protocol timed out\n",    length(tcp_open)))
cat(sprintf("  \033[31m%2d\033[0m TCP dead\n",                              length(tcp_dead)))
cat(sprintf("  \033[90m%2d\033[0m Routable prefixes loaded\n",              length(routable_cidrs)))
cat("\n")

now <- format(Sys.time(), "%Y-%m-%d %H:%M UTC", tz="UTC")
lines_out <- c(
  sprintf("# Iranian Proxies (ASN-filtered) verified from %s", my_ip),
  sprintf("# %s  |  working=%d  unverified=%d  tcp_open=%d  dead=%d",
          now, length(working), length(unverif), length(tcp_open), length(tcp_dead)),
  sprintf("# Routable ASNs: %s", paste(ROUTABLE_ASNS, collapse=", ")),
  "#", ""
)
if (length(working) > 0) {
  lines_out <- c(lines_out, "# CONFIRMED WORKING (Iranian exit IP):", "")
  for (r in working)
    lines_out <- c(lines_out,
                   sprintf("%-8s %-26s %5dms  %-16s %s",
                           r$protocol, r$proxy, r$latency_ms,
                           r$city%||%"", r$isp%||%""))
  lines_out <- c(lines_out, "", "# Raw:", sapply(working, `[[`, "proxy"))
}
if (length(unverif) > 0) {
  lines_out <- c(lines_out, "", "# CONNECTED (country unverified):")
  lines_out <- c(lines_out, sapply(unverif, `[[`, "proxy"))
}
writeLines(lines_out, OUTF)
write_json(
  list(tested_from=my_ip, tested_at=now,
       routable_asns=ROUTABLE_ASNS,
       routable_cidrs_loaded=length(routable_cidrs),
       working=working, unverified=unverif, tcp_open=tcp_open),
  sub("\\.txt$", ".json", OUTF),
  pretty=TRUE, auto_unbox=TRUE
)
log_ts(sprintf("Saved → %s", OUTF))

if (length(working) == 0 && length(unverif) == 0) {
  cat("\n")
  cli::cli_alert_info(paste(
    "No working proxies found from live sources.",
    "Try: Rscript test_local.R --file working_iran_proxies.txt",
    "to test the active-scan candidates from check_proxies.py."
  ))
}