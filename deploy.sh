#!/usr/bin/env bash
#
# One-shot deploy for the WAF practice lab (Ubuntu / any Docker host).
#   ./deploy.sh
#
set -uo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR" || exit 1

if [ -f "$DIR/.env" ]; then
  set -a
  # shellcheck disable=SC1091
  . "$DIR/.env"
  set +a
fi

LAB_BIND="${LAB_BIND:-127.0.0.1}"
DVWA_PORT="${DVWA_PORT:-8080}"
WAF_PORT="${WAF_PORT:-8081}"
ECHO_PORT="${ECHO_PORT:-8082}"
WAF_ECHO_PORT="${WAF_ECHO_PORT:-8083}"
WEAK_PORT="${WEAK_PORT:-8084}"
WEAK_ECHO_PORT="${WEAK_ECHO_PORT:-8085}"

die() { printf '\n\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }
ok()  { printf '\033[1;32m[ok]\033[0m %s\n' "$*"; }

# ---------- prerequisites ----------
command -v docker >/dev/null 2>&1 || die "Docker not found. Install Docker first."
docker info >/dev/null 2>&1 \
  || die "Cannot talk to the Docker daemon. Try: sudo usermod -aG docker \$USER && newgrp docker"
docker compose version >/dev/null 2>&1 \
  || die "Docker Compose v2 not found. Install 'docker-compose-v2' (Ubuntu) or the docker compose plugin."
ok "Docker + Compose v2 available"

# ---------- port conflicts ----------
conflict=0
check_port() {
  local port="$1" name="$2"
  if ss -ltn 2>/dev/null | grep -qE "[:.]${port}[[:space:]]"; then
    printf '  CONFLICT  %-6s %s (already in use)\n' "$port" "$name"
    conflict=1
  fi
}
if docker compose ps --status running -q 2>/dev/null | grep -q .; then
  ok "Lab containers already running — skipping host port checks"
else
  echo "Checking host ports..."
  check_port "$DVWA_PORT"      "DVWA direct"
  check_port "$WAF_PORT"       "CRS WAF -> DVWA"
  check_port "$ECHO_PORT"      "echo direct"
  check_port "$WAF_ECHO_PORT"  "CRS WAF -> echo"
  check_port "$WEAK_PORT"      "WeakWAF -> DVWA"
  check_port "$WEAK_ECHO_PORT" "WeakWAF -> echo"

  if [ "$conflict" -ne 0 ]; then
    cat <<'EOF'

Port conflict detected. Fix by copying .env.example to .env and
changing the ports, for example:

    cp .env.example .env
    sed -i 's/^DVWA_PORT=8080/DVWA_PORT=9080/' .env
    sed -i 's/^WAF_PORT=8081/WAF_PORT=9081/' .env
    sed -i 's/^ECHO_PORT=8082/ECHO_PORT=9082/' .env
    sed -i 's/^WAF_ECHO_PORT=8083/WAF_ECHO_PORT=9083/' .env
    sed -i 's/^WEAK_PORT=8084/WEAK_PORT=9084/' .env
    sed -i 's/^WEAK_ECHO_PORT=8085/WEAK_ECHO_PORT=9085/' .env

Then re-run ./deploy.sh
EOF
    exit 1
  fi
  ok "All ports free"
fi

# ---------- start ----------
echo
echo "Starting lab (first run pulls images)..."
docker compose up -d || die "docker compose up failed"

echo
echo "Waiting for services..."
sleep 5
docker compose ps

echo
echo "Running setup + test matrix..."
exec ./check.sh
