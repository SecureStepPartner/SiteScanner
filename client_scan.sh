#!/usr/bin/env bash
set -Eeuo pipefail

BASE_DIR="${HOME}/client-scans"
DATE_STAMP="$(date +%Y%m%d_%H%M%S)"
TOTAL_STEPS=5
CURRENT_STEP=0

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "[!] Missing required command: $1"
    exit 1
  }
}

sanitize_name() {
  echo "$1" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9.-]/_/g'
}

print_banner() {
  echo "======================================================"
  echo " Client External Exposure Scan"
  echo "======================================================"
  echo
}

progress_bar() {
  local current="$1"
  local total="$2"
  local label="$3"
  local width=40
  local filled=$(( current * width / total ))
  local empty=$(( width - filled ))
  local percent=$(( current * 100 / total ))
  local i

  printf "\r["
  for ((i = 0; i < filled; i++)); do
    printf "#"
  done
  for ((i = 0; i < empty; i++)); do
    printf "-"
  done
  printf "] %3d%%  %s" "$percent" "$label"

  if [ "$current" -eq "$total" ]; then
    echo
  fi
}

advance_progress() {
  CURRENT_STEP=$((CURRENT_STEP + 1))
  progress_bar "$CURRENT_STEP" "$TOTAL_STEPS" "$1"
}

run_step() {
  local step_name="$1"
  shift

  echo
  echo "------------------------------------------------------"
  echo "[*] START: ${step_name}"
  echo "------------------------------------------------------"

  "$@"

  echo "[*] DONE:  ${step_name}"
}

check_deps() {
  local deps=(
    subfinder dnsx httpx katana nuclei
    jq awk sed sort grep wc date
  )
  local dep

  for dep in "${deps[@]}"; do
    require_cmd "$dep"
  done
}

prompt_for_target() {
  read -rp "Enter primary domain (example: cibovita.com): " ROOT_DOMAIN
  ROOT_DOMAIN="$(echo "$ROOT_DOMAIN" | xargs)"

  if [[ -z "${ROOT_DOMAIN}" ]]; then
    echo "[!] Domain cannot be empty."
    exit 1
  fi

  if [[ ! "${ROOT_DOMAIN}" =~ ^[a-zA-Z0-9.-]+$ ]]; then
    echo "[!] Domain contains invalid characters: ${ROOT_DOMAIN}"
    exit 1
  fi

  read -rp "Add more related domains? Separate with spaces, or press Enter to skip: " EXTRA_DOMAINS
}

build_scope_file() {
  local out_file="$1"
  {
    echo "$ROOT_DOMAIN"
    if [[ -n "${EXTRA_DOMAINS:-}" ]]; then
      for d in ${EXTRA_DOMAINS}; do
        echo "$d"
      done
    fi
  } | tr '[:upper:]' '[:lower:]' | sed '/^$/d' | sort -u > "$out_file"
}

setup_dirs() {
  CLIENT_NAME="$(sanitize_name "$ROOT_DOMAIN")"
  RUN_ID="${CLIENT_NAME}_${DATE_STAMP}"
  OUT_DIR="${BASE_DIR}/${CLIENT_NAME}/${DATE_STAMP}"

  mkdir -p "${OUT_DIR}"/{input,enum,resolved,http,crawl,nuclei,reports,logs,tmp}

  FILE_PREFIX="${RUN_ID}"
  LOG_FILE="${OUT_DIR}/logs/${FILE_PREFIX}_run.log"

  exec > >(tee -a "${LOG_FILE}") 2>&1

  echo "[*] Output directory: ${OUT_DIR}"
  echo "[*] Run ID: ${RUN_ID}"
}

run_subfinder() {
  run_step "subfinder" \
    subfinder -dL "${OUT_DIR}/input/${FILE_PREFIX}_roots.txt" \
      -all -silent \
      -o "${OUT_DIR}/enum/${FILE_PREFIX}_subfinder.txt"

  sort -u "${OUT_DIR}/enum/${FILE_PREFIX}_subfinder.txt" \
    > "${OUT_DIR}/enum/${FILE_PREFIX}_all_subdomains.txt"

  advance_progress "subfinder complete"
}

run_dnsx() {
  run_step "dnsx" \
    dnsx -l "${OUT_DIR}/enum/${FILE_PREFIX}_all_subdomains.txt" \
      -resp -silent -retry 2 \
      -o "${OUT_DIR}/resolved/${FILE_PREFIX}_dnsx_raw.txt"

  awk '{print $1}' "${OUT_DIR}/resolved/${FILE_PREFIX}_dnsx_raw.txt" | sort -u \
    > "${OUT_DIR}/resolved/${FILE_PREFIX}_live_hosts.txt"

  advance_progress "dnsx complete"
}

run_httpx() {
  run_step "httpx" \
    httpx -l "${OUT_DIR}/resolved/${FILE_PREFIX}_live_hosts.txt" \
      -silent \
      -follow-host-redirects \
      -status-code \
      -title \
      -tech-detect \
      -web-server \
      -tls-probe \
      -cname \
      -ip \
      -cdn \
      -location \
      -json \
      -o "${OUT_DIR}/http/${FILE_PREFIX}_httpx.jsonl"

  jq -r '.url' "${OUT_DIR}/http/${FILE_PREFIX}_httpx.jsonl" | sed '/^null$/d' | sort -u \
    > "${OUT_DIR}/http/${FILE_PREFIX}_live_urls.txt"

  advance_progress "httpx complete"
}

run_katana() {
  run_step "katana" \
    katana -list "${OUT_DIR}/http/${FILE_PREFIX}_live_urls.txt" \
      -silent \
      -d 3 \
      -c 10 \
      -rl 2 \
      -o "${OUT_DIR}/crawl/${FILE_PREFIX}_katana.txt"

  advance_progress "katana complete"
}

run_nuclei() {
  run_step "nuclei" \
    nuclei -l "${OUT_DIR}/http/${FILE_PREFIX}_live_urls.txt" \
      -rl 2 \
      -c 10 \
      -retries 1 \
      -timeout 5 \
      -severity info,low,medium,high,critical \
      -tags exposure,misconfig,tech,panel,tls,dns,wordpress,cve \
      -etags intrusive,fuzz,ssrf,fileupload,rce,oast,dos,bruteforce \
      -dashboard \
      -jsonl \
      -o "${OUT_DIR}/nuclei/${FILE_PREFIX}_nuclei_safe.jsonl"

  advance_progress "nuclei complete"
}

html_escape() {
  sed \
    -e 's/\&/\&amp;/g' \
    -e 's/</\&lt;/g' \
    -e 's/>/\&gt;/g'
}

build_summary() {
  ROOTS_FILE="${OUT_DIR}/input/${FILE_PREFIX}_roots.txt"
  SUBS_FILE="${OUT_DIR}/enum/${FILE_PREFIX}_all_subdomains.txt"
  DNS_FILE="${OUT_DIR}/resolved/${FILE_PREFIX}_dnsx_raw.txt"
  URLS_FILE="${OUT_DIR}/http/${FILE_PREFIX}_live_urls.txt"
  HTTPX_FILE="${OUT_DIR}/http/${FILE_PREFIX}_httpx.jsonl"
  KATANA_FILE="${OUT_DIR}/crawl/${FILE_PREFIX}_katana.txt"
  NUCLEI_FILE="${OUT_DIR}/nuclei/${FILE_PREFIX}_nuclei_safe.jsonl"
  SUMMARY_FILE="${OUT_DIR}/reports/${FILE_PREFIX}_summary.txt"
  HTML_FILE="${OUT_DIR}/reports/${FILE_PREFIX}_results.html"

  roots_count="$(wc -l < "${ROOTS_FILE}" || echo 0)"
  sub_count="$(wc -l < "${SUBS_FILE}" || echo 0)"
  live_host_count="$(wc -l < "${OUT_DIR}/resolved/${FILE_PREFIX}_live_hosts.txt" || echo 0)"
  url_count="$(wc -l < "${URLS_FILE}" || echo 0)"
  crawl_count="$(wc -l < "${KATANA_FILE}" 2>/dev/null || echo 0)"
  findings_count="$(wc -l < "${NUCLEI_FILE}" 2>/dev/null || echo 0)"

  {
    echo "Client Scan Summary"
    echo "==================="
    echo
    echo "Primary domain: ${ROOT_DOMAIN}"
    echo "Run ID: ${RUN_ID}"
    echo "Timestamp: ${DATE_STAMP}"
    echo "Domains in scope: ${roots_count}"
    echo
    echo "Subdomains discovered: ${sub_count}"
    echo "Resolvable hosts: ${live_host_count}"
    echo "Live web URLs: ${url_count}"
    echo "Crawled URLs: ${crawl_count}"
    echo "Nuclei findings: ${findings_count}"
    echo
    echo "Important files"
    echo "---------------"
    echo "Roots file:      ${ROOTS_FILE}"
    echo "Subdomains:      ${SUBS_FILE}"
    echo "DNS results:     ${DNS_FILE}"
    echo "Live URLs:       ${URLS_FILE}"
    echo "HTTP probe JSON: ${HTTPX_FILE}"
    echo "Katana output:   ${KATANA_FILE}"
    echo "Nuclei output:   ${NUCLEI_FILE}"
    echo "Run log:         ${LOG_FILE}"
  } > "${SUMMARY_FILE}"

  top_urls_html="$(head -50 "${URLS_FILE}" 2>/dev/null | while read -r line; do
    printf '<tr><td>%s</td></tr>\n' "$(printf '%s' "$line" | html_escape)"
  done)"

  top_subs_html="$(head -50 "${SUBS_FILE}" 2>/dev/null | while read -r line; do
    printf '<tr><td>%s</td></tr>\n' "$(printf '%s' "$line" | html_escape)"
  done)"

  nuclei_rows_html="$(
    if [[ -s "${NUCLEI_FILE}" ]]; then
      jq -r '
        [
          (.info.severity // "unknown"),
          (.info.name // "unknown"),
          (.matched-at // .matched // .host // "n/a"),
          (.template-id // "n/a")
        ] | @tsv
      ' "${NUCLEI_FILE}" 2>/dev/null | head -100 | while IFS=$'\t' read -r sev name matched tid; do
        printf '<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n' \
          "$(printf '%s' "$sev" | html_escape)" \
          "$(printf '%s' "$name" | html_escape)" \
          "$(printf '%s' "$matched" | html_escape)" \
          "$(printf '%s' "$tid" | html_escape)"
      done
    fi
  )"

  cat > "${HTML_FILE}" <<EOF2
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>${ROOT_DOMAIN} Scan Results</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 24px; color: #222; }
    h1, h2, h3 { margin-bottom: 8px; }
    .meta, .card { border: 1px solid #ddd; border-radius: 8px; padding: 16px; margin-bottom: 18px; }
    .grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; }
    .stat { border: 1px solid #ddd; border-radius: 8px; padding: 14px; text-align: center; }
    .stat .num { font-size: 28px; font-weight: bold; }
    table { width: 100%; border-collapse: collapse; margin-top: 8px; }
    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; vertical-align: top; }
    th { background: #f5f5f5; }
    code { background: #f4f4f4; padding: 2px 4px; border-radius: 4px; }
    .small { color: #666; font-size: 12px; }
  </style>
</head>
<body>
  <h1>Client External Exposure Scan</h1>

  <div class="meta">
    <p><strong>Primary domain:</strong> ${ROOT_DOMAIN}</p>
    <p><strong>Run ID:</strong> ${RUN_ID}</p>
    <p><strong>Timestamp:</strong> ${DATE_STAMP}</p>
    <p><strong>Output folder:</strong> <code>${OUT_DIR}</code></p>
  </div>

  <div class="grid">
    <div class="stat"><div class="num">${roots_count}</div><div>Domains in Scope</div></div>
    <div class="stat"><div class="num">${sub_count}</div><div>Subdomains</div></div>
    <div class="stat"><div class="num">${live_host_count}</div><div>Resolvable Hosts</div></div>
    <div class="stat"><div class="num">${url_count}</div><div>Live URLs</div></div>
    <div class="stat"><div class="num">${findings_count}</div><div>Nuclei Findings</div></div>
  </div>

  <div class="card">
    <h2>Important Files</h2>
    <table>
      <tr><th>Type</th><th>Path</th></tr>
      <tr><td>Roots</td><td><code>${ROOTS_FILE}</code></td></tr>
      <tr><td>Subdomains</td><td><code>${SUBS_FILE}</code></td></tr>
      <tr><td>DNS</td><td><code>${DNS_FILE}</code></td></tr>
      <tr><td>HTTPX JSONL</td><td><code>${HTTPX_FILE}</code></td></tr>
      <tr><td>Live URLs</td><td><code>${URLS_FILE}</code></td></tr>
      <tr><td>Katana</td><td><code>${KATANA_FILE}</code></td></tr>
      <tr><td>Nuclei</td><td><code>${NUCLEI_FILE}</code></td></tr>
      <tr><td>Run Log</td><td><code>${LOG_FILE}</code></td></tr>
    </table>
  </div>

  <div class="card">
    <h2>Sample Live URLs</h2>
    <table>
      <tr><th>URL</th></tr>
      ${top_urls_html}
    </table>
  </div>

  <div class="card">
    <h2>Sample Subdomains</h2>
    <table>
      <tr><th>Subdomain</th></tr>
      ${top_subs_html}
    </table>
  </div>

  <div class="card">
    <h2>Nuclei Findings</h2>
    <table>
      <tr><th>Severity</th><th>Name</th><th>Matched</th><th>Template ID</th></tr>
      ${nuclei_rows_html}
    </table>
    <p class="small">Showing up to 100 findings.</p>
  </div>
</body>
</html>
EOF2

  echo
  echo "[*] Summary written to: ${SUMMARY_FILE}"
  echo "[*] HTML results page: ${HTML_FILE}"
}

main() {
  print_banner
  progress_bar 0 "$TOTAL_STEPS" "starting"
  check_deps
  prompt_for_target
  setup_dirs

  build_scope_file "${OUT_DIR}/input/${FILE_PREFIX}_roots.txt"

  echo "[*] Scope:"
  cat "${OUT_DIR}/input/${FILE_PREFIX}_roots.txt"

  run_subfinder
  run_dnsx
  run_httpx

  if [[ ! -s "${OUT_DIR}/http/${FILE_PREFIX}_live_urls.txt" ]]; then
    echo
    echo "[!] No live URLs found. Exiting."
    exit 1
  fi

  run_katana
  run_nuclei
  build_summary

  progress_bar "$TOTAL_STEPS" "$TOTAL_STEPS" "complete"

  echo
  echo "[*] Complete."
  echo "[*] Output folder: ${OUT_DIR}"
  echo "[*] Open HTML report in a browser:"
  echo "    file://${OUT_DIR}/reports/${FILE_PREFIX}_results.html"
}

main "$@"
