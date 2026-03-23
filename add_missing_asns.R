# ─────────────────────────────────────────────────────────────────────────────
# add_missing_asns.R
# Run ONCE locally to populate merged_routable_asns.json, then commit & push.
# Uses RIPE Stat API (stat.ripe.net) — always publicly accessible, no key.
#
# Usage:
#   Rscript add_missing_asns.R
#   git add merged_routable_asns.json
#   git commit -m "feat: add missing ASN prefixes"
#   git push
#
# install.packages(c("httr2", "jsonlite", "cli"))
# ─────────────────────────────────────────────────────────────────────────────

suppressPackageStartupMessages({
  library(httr2)
  library(jsonlite)
  library(cli)
})

UA <- "Mozilla/5.0 (compatible; iran-proxy-checker/1.0)"

# ── All ASNs — mirrors REACHABLE_ASNS in check_proxies.py ────────────────────
ALL_ASNS <- list(
  AS43754  = "Asiatech Data Transmission — telewebion.ir",
  AS64422  = "Sima Rayan Sharif — telewebion.ir (current IP)",
  AS62229  = "Fars News Agency — farsnews.ir",
  AS48159  = "TIC / ITC Backbone",
  AS12880  = "Iran Telecommunications Co.",
  AS16322  = "Pars Online / Respina",
  AS42337  = "Respina Networks & Beyond",
  AS49666  = "TIC Gateway (transit for all Iranian ISPs)",
  AS21341  = "Fanava Group — sepehrtv.ir",
  AS24631  = "FANAPTELECOM / Fanavari Pasargad",
  AS56402  = "Dadeh Gostar Asr Novin",
  AS31549  = "Afranet",
  AS44244  = "IranCell / MCI",
  AS197207 = "Mobile Communication of Iran (MCI)",
  AS58224  = "Iran Telecom PJS",
  AS39501  = "Aria Shatel",
  AS57218  = "RayaPars",
  AS25184  = "Afagh Danesh Gostar",
  AS51695  = "Iranian ISP",
  AS47262  = "Iranian ISP"
)

log_ts <- function(msg) {
  cli::cli_text("[{format(Sys.time(),'%H:%M:%S',tz='UTC')}] {msg}")
}

# ── RIPE Stat prefix fetcher ──────────────────────────────────────────────────
# stat.ripe.net/data/announced-prefixes/data.json?resource=AS43754
# Returns all IPv4 prefixes currently announced by the ASN in global BGP.
# Free, no auth, no rate-limit issues.
fetch_prefixes_ripe <- function(asn, ua) {
  asn_num <- sub("^AS", "", asn)
  url     <- paste0(
    "https://stat.ripe.net/data/announced-prefixes/data.json",
    "?resource=AS", asn_num,
    "&starttime=", format(Sys.time() - 3600, "%Y-%m-%dT%H:%M", tz="UTC")
  )
  tryCatch({
    r <- request(url) |>
      req_timeout(30) |>
      req_headers("User-Agent" = ua) |>
      req_perform()
    d <- resp_body_json(r)
    
    prefixes_raw <- d$data$prefixes %||% list()
    if (!is.list(prefixes_raw) || length(prefixes_raw) == 0)
      return(character(0))
    
    # Each entry: {prefix: "x.x.x.x/y", timelines: [...]}
    pfx <- vapply(prefixes_raw, function(p) {
      pr <- p$prefix %||% ""
      # Only keep IPv4 (no colons)
      if (nzchar(pr) && !grepl(":", pr)) pr else ""
    }, character(1))
    
    sort(unique(pfx[nzchar(pfx)]))
  }, error = function(e) {
    log_ts(sprintf("  ! RIPE Stat %s: %s", asn, conditionMessage(e)))
    character(0)
  })
}

`%||%` <- function(a, b) if (!is.null(a) && length(a) > 0) a else b

# ── Load existing JSON ────────────────────────────────────────────────────────
script_dir <- tryCatch(
  dirname(normalizePath(sys.frames()[[1]]$ofile)),
  error = function(e) "."
)
json_path <- file.path(script_dir, "merged_routable_asns.json")

if (file.exists(json_path)) {
  db <- jsonlite::fromJSON(json_path, simplifyVector = FALSE)
  log_ts(sprintf("Loaded %d ASNs from %s", length(db), basename(json_path)))
} else {
  db <- list()
  log_ts(sprintf("%s not found — will create fresh", basename(json_path)))
}

# ── Connectivity check ────────────────────────────────────────────────────────
log_ts("Checking RIPE Stat connectivity…")
ripe_ok <- tryCatch({
  r <- request("https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS62229") |>
    req_timeout(15) |> req_headers("User-Agent" = UA) |> req_perform()
  resp_status(r) == 200
}, error = function(e) FALSE)

if (!ripe_ok) {
  cli::cli_alert_danger("Cannot reach stat.ripe.net — check your internet connection.")
  quit(status = 1)
}
log_ts("  RIPE Stat reachable ✓")
cat("\n")

# ── Decide which ASNs need fetching ──────────────────────────────────────────
needs_fetch <- names(ALL_ASNS)[vapply(names(ALL_ASNS), function(asn) {
  entry <- db[[asn]]
  is.null(entry) || length(entry$prefixes) == 0
}, logical(1))]

already_ok <- setdiff(names(ALL_ASNS), needs_fetch)
if (length(already_ok) > 0)
  log_ts(sprintf("Already populated: %s", paste(already_ok, collapse=", ")))

if (length(needs_fetch) == 0) {
  cli::cli_alert_success("All ASNs already have prefixes — nothing to do.")
  cli::cli_alert_info("Delete merged_routable_asns.json and re-run to force a full refresh.")
  quit(status = 0)
}

log_ts(sprintf("Fetching %d ASNs from RIPE Stat…", length(needs_fetch)))
cat("\n")

# ── Fetch and merge ───────────────────────────────────────────────────────────
any_updated <- FALSE
failed      <- character(0)

for (asn in needs_fetch) {
  name <- ALL_ASNS[[asn]]
  log_ts(sprintf("%-12s %s", asn, name))
  
  new_pfx <- fetch_prefixes_ripe(asn, UA)
  Sys.sleep(0.3)   # be polite to RIPE Stat
  
  if (length(new_pfx) == 0) {
    log_ts(sprintf("  → 0 prefixes returned"))
    failed <- c(failed, asn)
    next
  }
  
  old_pfx <- if (!is.null(db[[asn]]$prefixes))
    unlist(db[[asn]]$prefixes) else character(0)
  merged  <- sort(unique(c(old_pfx, new_pfx)))
  
  db[[asn]] <- list(name = name, prefixes = as.list(merged))
  log_ts(sprintf("  → %d prefixes", length(merged)))
  any_updated <- TRUE
}

cat("\n")

# ── Save ──────────────────────────────────────────────────────────────────────
if (!any_updated) {
  cli::cli_alert_warning("No new data fetched — JSON not updated.")
  quit(status = 1)
}

# Carry over any existing ASNs not in ALL_ASNS
for (asn in setdiff(names(db), names(ALL_ASNS)))
  db[[asn]] <- db[[asn]]

jsonlite::write_json(db, json_path, pretty = TRUE, auto_unbox = FALSE)

total_pfx  <- sum(vapply(db, function(e) length(e$prefixes), integer(1)))
total_asns <- length(db)

cli::cli_alert_success(sprintf(
  "Saved %s  (%d ASNs, %d total prefixes)",
  basename(json_path), total_asns, total_pfx
))

if (length(failed) > 0)
  cli::cli_alert_warning(sprintf(
    "These ASNs returned 0 prefixes (small/new ASNs may not be in RIPE Stat yet): %s",
    paste(failed, collapse=", ")
  ))

cat("\n")
cli::cli_rule()
cli::cli_bullets(c(
  "v" = sprintf("git add %s", basename(json_path)),
  "v" = 'git commit -m "feat: add missing ASN prefixes"',
  "v" = "git push"
))
cli::cli_rule()