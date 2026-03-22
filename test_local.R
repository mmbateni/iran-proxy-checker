# ─────────────────────────────────────────────────────────────────────────────
# Iran Proxy Tester — Live-Verified Edition
# Fetches ONLY proxies that proxyscrape/other checkers have verified alive
# in the last few minutes, then re-tests from YOUR network in BC/Canada.
#
# install.packages(c("httr2", "curl", "jsonlite", "cli", "optparse"))
# ─────────────────────────────────────────────────────────────────────────────

suppressPackageStartupMessages({
  library(httr2); library(curl); library(jsonlite)
  library(cli);   library(optparse); library(parallel)
})

option_list <- list(
  make_option("--file",    type="character", default=NULL,
              help="Optional extra proxy list file to merge in"),
  make_option("--timeout", type="integer",   default=20L,
              help="HTTP timeout per proxy in seconds [default: %default]"),
  make_option("--tcp",     type="integer",   default=8L,
              help="TCP connect timeout in seconds [default: %default]"),
  make_option("--workers", type="integer",   default=15L,
              help="Parallel workers [default: %default]"),
  make_option("--output",  type="character", default="verified_local.txt",
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

`%||%` <- function(a,b) if(!is.null(a)&&length(a)>0&&!is.na(a)) a else b

log_ts <- function(msg) {
  cli::cli_text("[{format(Sys.time(),'%H:%M:%S',tz='UTC')}] {msg}")
}

# ══════════════════════════════════════════════════════════════════════════════
# STEP 1 — Fetch proxies that are verified alive RIGHT NOW
# ══════════════════════════════════════════════════════════════════════════════

fetch_live_verified <- function() {
  proxies <- character(0)
  
  # ── proxyscrape API — returns only currently-working IR proxies ─────────────
  # This is the same API proxyscrape.com's checker uses internally
  for (proto in c("http","socks4","socks5")) {
    url <- paste0(
      "https://api.proxyscrape.com/v3/free-proxy-list/get",
      "?request=displayproxies&country=ir&protocol=", proto,
      "&anonymity=all&timeout=5000&simplified=true"
    )
    tryCatch({
      r <- request(url) |> req_timeout(15) |>
        req_headers("User-Agent"=UA) |> req_perform()
      lines <- strsplit(resp_body_string(r), "\n")[[1]]
      lines <- trimws(lines[grepl("^\\d+\\.\\d+\\.\\d+\\.\\d+:\\d+", lines)])
      if (length(lines)) {
        log_ts(sprintf("  proxyscrape %-7s → %d proxies", proto, length(lines)))
        proxies <- c(proxies, lines)
      }
    }, error=function(e) log_ts(sprintf("  ! proxyscrape %s: %s", proto, conditionMessage(e))))
  }
  
  # ── proxifly IR-specific list (updated every 5 min) ─────────────────────────
  tryCatch({
    url <- "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/countries/IR/data.txt"
    r   <- request(url) |> req_timeout(15) |> req_headers("User-Agent"=UA) |> req_perform()
    m   <- regmatches(resp_body_string(r),
                      gregexpr("\\d{1,3}(?:\\.\\d{1,3}){3}:\\d{2,5}",
                               resp_body_string(r), perl=TRUE))[[1]]
    if (length(m)) {
      log_ts(sprintf("  proxifly IR          → %d proxies", length(m)))
      proxies <- c(proxies, m)
    }
  }, error=function(e) log_ts(sprintf("  ! proxifly: %s", conditionMessage(e))))
  
  # ── OpenRay Iran top-100 (hourly verified) ───────────────────────────────────
  tryCatch({
    url <- "https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output_iran/iran_top100_checked.txt"
    r   <- request(url) |> req_timeout(15) |> req_headers("User-Agent"=UA) |> req_perform()
    m   <- regmatches(resp_body_string(r),
                      gregexpr("\\d{1,3}(?:\\.\\d{1,3}){3}:\\d{2,5}",
                               resp_body_string(r), perl=TRUE))[[1]]
    if (length(m)) {
      log_ts(sprintf("  OpenRay Iran top100  → %d proxies", length(m)))
      proxies <- c(proxies, m)
    }
  }, error=function(e) log_ts(sprintf("  ! openray: %s", conditionMessage(e))))
  
  # ── Geonode IR — sorted by lastChecked ──────────────────────────────────────
  tryCatch({
    url <- paste0("https://proxylist.geonode.com/api/proxy-list",
                  "?country=IR&limit=100&page=1&sort_by=lastChecked&sort_type=desc")
    r   <- request(url) |> req_timeout(15) |> req_headers("User-Agent"=UA) |> req_perform()
    d   <- resp_body_json(r)
    geo <- vapply(d$data %||% list(), function(p) {
      ip   <- p$ip   %||% ""
      port <- p$port %||% ""
      if (is.list(port)) port <- port[[1]] %||% ""
      paste0(ip,":",port)
    }, character(1))
    geo <- geo[grepl("^\\d+\\.\\d+\\.\\d+\\.\\d+:\\d+$", geo)]
    if (length(geo)) {
      log_ts(sprintf("  Geonode IR           → %d proxies", length(geo)))
      proxies <- c(proxies, geo)
    }
  }, error=function(e) log_ts(sprintf("  ! geonode: %s", conditionMessage(e))))
  
  unique(trimws(proxies[nchar(trimws(proxies)) > 0]))
}

# ══════════════════════════════════════════════════════════════════════════════
# STEP 2 — Test each proxy from YOUR network
# ══════════════════════════════════════════════════════════════════════════════

VERIFY_URL    <- "http://ip-api.com/json/?fields=status,countryCode,query,org,city"
FALLBACK_URLS <- c("http://api.ipify.org","http://ifconfig.me/ip",
                   "http://checkip.amazonaws.com","http://icanhazip.com")

test_one <- function(proxy_str, tcp_to, http_to, verify_url, fallback_urls, ua) {
  `%||%` <- function(a,b) if(!is.null(a)&&length(a)>0&&!is.na(a)) a else b
  parts <- strsplit(proxy_str,":")[[1]]
  if (length(parts)!=2) return(list(proxy=proxy_str, status="INVALID"))
  ip <- parts[1]; port <- as.integer(parts[2])
  
  # TCP check
  tcp_ok <- tryCatch({
    con <- socketConnection(host=ip, port=port, open="r+b", timeout=tcp_to, blocking=TRUE)
    close(con); TRUE
  }, error=function(e) FALSE)
  if (!tcp_ok) return(list(proxy=proxy_str, status="TCP_DEAD"))
  
  # Try protocols — SOCKS5 first (most common on IR lists)
  for (proto in c("socks5","http","socks4")) {
    proxy_url <- sprintf("%s://%s:%d", proto, ip, port)
    
    # Primary: ip-api for country confirmation
    result <- tryCatch({
      h <- new_handle()
      handle_setopt(h, proxy=proxy_url, timeout=http_to, useragent=ua, followlocation=TRUE)
      t0  <- proc.time()[["elapsed"]]
      res <- curl_fetch_memory(verify_url, handle=h)
      lat <- round((proc.time()[["elapsed"]]-t0)*1000)
      if (res$status_code>=200 && res$status_code<400) {
        d  <- tryCatch(jsonlite::fromJSON(rawToChar(res$content)), error=function(e) list())
        cc <- d$countryCode %||% ""
        if (!is.null(d$status) && d$status=="success")
          list(proxy=proxy_str, status=if(cc=="IR")"WORKING" else "WRONG_COUNTRY",
               protocol=toupper(proto), latency_ms=lat,
               exit_ip=d$query%||%"", country=cc,
               city=d$city%||%"", isp=d$org%||%"")
        else NULL
      } else NULL
    }, error=function(e) NULL)
    if (!is.null(result)) return(result)
    
    # Fallback: any connectivity
    for (furl in fallback_urls) {
      r2 <- tryCatch({
        h2 <- new_handle()
        handle_setopt(h2, proxy=proxy_url, timeout=http_to, useragent=ua, followlocation=TRUE)
        t0  <- proc.time()[["elapsed"]]
        res <- curl_fetch_memory(furl, handle=h2)
        lat <- round((proc.time()[["elapsed"]]-t0)*1000)
        if (res$status_code>=200 && res$status_code<400)
          list(proxy=proxy_str, status="WORKING_UNVERIFIED",
               protocol=toupper(proto), latency_ms=lat,
               exit_ip=trimws(rawToChar(res$content)),
               country="?", city="", isp="")
        else NULL
      }, error=function(e) NULL)
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
  clusterEvalQ(cl, { library(curl); library(jsonlite)
    `%||%` <- function(a,b) if(!is.null(a)&&length(a)>0&&!is.na(a)) a else b })
  parLapply(cl, proxies, function(p)
    test_one(p, env$tcp_to, env$http_to, env$VERIFY_URL, env$FALLBACK_URLS, env$UA))
}

# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

cli::cli_rule(center=" Iran Proxy Tester — Live-Verified Edition ")
cat("\n")

# Own IP
my_ip <- tryCatch({
  d <- resp_body_json(request(VERIFY_URL) |> req_timeout(8) |> req_perform())
  sprintf("%s (%s, %s, %s)", d$query%||%"?", d$city%||%"?",
          d$regionName%||%"?", d$countryCode%||%"?")
}, error=function(e) "unknown")
log_ts(sprintf("Your public IP: %s", my_ip))
cat("\n")

# Fetch live-verified proxies
proxies <- character(0)
if (!args$`skip-fetch`) {
  log_ts(sprintf("Fetching proxies verified alive RIGHT NOW (sources with <5min update cycle)…"))
  proxies <- fetch_live_verified()
  log_ts(sprintf("Live-verified pool: %d unique IR proxies", length(proxies)))
}

# Merge optional file
if (!is.null(args$file) && file.exists(args$file)) {
  lines <- readLines(args$file, warn=FALSE)
  lines <- trimws(lines[!grepl("^\\s*#",lines) & nchar(trimws(lines))>0])
  m     <- unique(unlist(regmatches(lines,
                                    gregexpr("\\d{1,3}(?:\\.\\d{1,3}){3}:\\d{2,5}", lines, perl=TRUE))))
  log_ts(sprintf("Merged %d proxies from %s", length(m), args$file))
  proxies <- unique(c(proxies, m))
}

if (length(proxies) == 0) {
  cli::cli_alert_danger("No proxies to test. Check your internet connection.")
  quit(status=1)
}

cat("\n")
results <- run_parallel(proxies, NW, TCP_TO, TOUT)

# Categorise & sort
working  <- Filter(function(r) identical(r$status,"WORKING"),            results)
unverif  <- Filter(function(r) identical(r$status,"WORKING_UNVERIFIED"), results)
wrong_cc <- Filter(function(r) identical(r$status,"WRONG_COUNTRY"),      results)
tcp_open <- Filter(function(r) identical(r$status,"TCP_OPEN_NO_RESPONSE"),results)
tcp_dead <- Filter(function(r) identical(r$status,"TCP_DEAD"),            results)

by_lat   <- function(lst) lst[order(sapply(lst, function(r) r$latency_ms%||%99999))]
working  <- by_lat(working)
unverif  <- by_lat(unverif)

# Print working ones
for (r in c(working, unverif)) {
  icon <- if(identical(r$status,"WORKING")) "\u2705" else "\u26a0\ufe0f"
  cli::cli_text(sprintf("  %s [%-6s] %-26s %5dms  %-15s %s",
                        icon, r$protocol%||%"", r$proxy, r$latency_ms%||%0,
                        r$city%||%"", r$isp%||%""))
}

# Summary
cat("\n")
cli::cli_rule()
cli::cli_text(sprintf("RESULTS FROM: %s", my_ip))
cli::cli_rule()
cat(sprintf("  \033[32m%2d\033[0m Working   — Iranian exit IP confirmed\n",   length(working)))
cat(sprintf("  \033[33m%2d\033[0m Connected — country unverified\n",          length(unverif)))
cat(sprintf("  \033[36m%2d\033[0m Wrong country exit IP\n",                   length(wrong_cc)))
cat(sprintf("  \033[35m%2d\033[0m TCP open, proxy protocol timed out\n",      length(tcp_open)))
cat(sprintf("  \033[31m%2d\033[0m TCP dead\n",                                length(tcp_dead)))
cat("\n")

# Save
now <- format(Sys.time(), "%Y-%m-%d %H:%M UTC", tz="UTC")
lines_out <- c(
  sprintf("# Iranian Proxies verified from %s", my_ip),
  sprintf("# %s  |  working=%d  unverified=%d  tcp_open=%d  dead=%d",
          now, length(working), length(unverif), length(tcp_open), length(tcp_dead)),
  "#", ""
)
if (length(working)>0) {
  lines_out <- c(lines_out, "# CONFIRMED WORKING (Iranian exit IP):", "")
  for (r in working)
    lines_out <- c(lines_out,
                   sprintf("%-8s %-26s %5dms  %-16s %s",
                           r$protocol, r$proxy, r$latency_ms, r$city%||%"", r$isp%||%""))
  lines_out <- c(lines_out, "", "# Raw:", sapply(working,`[[`,"proxy"))
}
if (length(unverif)>0) {
  lines_out <- c(lines_out, "", "# CONNECTED (country unverified):")
  lines_out <- c(lines_out, sapply(unverif,`[[`,"proxy"))
}
writeLines(lines_out, OUTF)
write_json(list(tested_from=my_ip, tested_at=now,
                working=working, unverified=unverif, tcp_open=tcp_open),
           sub("\\.txt$",".json",OUTF), pretty=TRUE, auto_unbox=TRUE)
log_ts(sprintf("Saved → %s", OUTF))

if (length(working)==0 && length(unverif)==0) {
  cat("\n")
  cli::cli_alert_warning("No working proxies found.")
  cli::cli_bullets(c(
    "i"="Free Iranian proxies are very short-lived (often <1 hour).",
    "i"="Run again in a few hours when fresh proxies appear.",
    "i"="The {.val tcp_open} ones below responded on TCP — try manually:",
    "i"=paste(sapply(tcp_open[seq_len(min(5,length(tcp_open)))],`[[`,"proxy"),
              collapse=", ")
  ))
}