#!/usr/bin/env bash
# Smoke-check a hosted demo after Caddy is live.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DOMAIN="${AGENT_BOM_HOSTED_DOMAIN:-demo.agent-bom.com}"
PUBLIC_URL="https://${DOMAIN}"
CHECK_LOCAL=1
CHECK_PUBLIC=1

usage() {
  cat <<'EOF'
Verify a hosted demo deployment.

Usage:
  scripts/deploy/verify-hosted-demo.sh [options]

Options:
  --domain HOST         Public hostname (default: demo.agent-bom.com)
  --public-only         Skip loopback API/UI checks
  --local-only          Skip HTTPS public checks (VM before DNS/TLS)
  -h, --help            Show this help
EOF
}

log() { printf "[%s] %s\n" "$(date +%H:%M:%S)" "$*"; }
die() { printf "[error] %s\n" "$*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain) DOMAIN="$2"; PUBLIC_URL="https://${DOMAIN}"; shift 2 ;;
    --public-only) CHECK_LOCAL=0; shift ;;
    --local-only) CHECK_PUBLIC=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

failures=0

check() {
  local label="$1"
  shift
  if "$@"; then
    log "OK  $label"
  else
    log "FAIL $label"
    failures=$((failures + 1))
  fi
}

if [[ "$CHECK_LOCAL" -eq 1 ]]; then
  check "loopback API /health" curl -fsS "http://127.0.0.1:8422/health" >/dev/null
  check "loopback UI responds" curl -fsS -o /dev/null "http://127.0.0.1:3000/"
fi

if [[ "$CHECK_PUBLIC" -eq 1 ]]; then
  check "public API /health via TLS" curl -fsS "${PUBLIC_URL}/health" >/dev/null
  check "public UI via TLS" curl -fsS -o /dev/null "${PUBLIC_URL}/"
fi

if [[ "$CHECK_LOCAL" -eq 1 ]]; then
  if command -v python3 >/dev/null 2>&1; then
    check "hosted preflight (skip compose)" \
      python3 "$ROOT_DIR/scripts/deploy/hosted_poc_preflight.py" --skip-compose
  else
    log "skip preflight — python3 not found"
  fi
fi

if [[ "$failures" -gt 0 ]]; then
  die "$failures check(s) failed for $DOMAIN"
fi

log "all checks passed for $DOMAIN"
