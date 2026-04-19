#!/usr/bin/env bash
# pilot-verify.sh — end-to-end smoke test for an agent-bom EKS pilot install.
#
# Usage:
#   ./scripts/pilot-verify.sh <base-url> <api-key>
#   ./scripts/pilot-verify.sh http://localhost:8080 "$AGENT_BOM_API_KEY"
#
# Exits non-zero on the first failed check. Designed for a pilot team to
# run after `helm install` and a `kubectl port-forward` so they can
# confirm the five capabilities scoped for the EKS MCP pilot:
#
#   1. Control plane health
#   2. Auth surface
#   3. Fleet ingest
#   4. Scan path
#   5. Compliance evidence bundle (fetch + verify signature)
#
# Non-destructive: only POSTs a tiny demo scan and a single fleet heartbeat.
# Works against any auth mode — pass the bearer token via $2.

set -euo pipefail

BASE_URL="${1:-${AGENT_BOM_BASE_URL:-http://localhost:8080}}"
API_KEY="${2:-${AGENT_BOM_API_KEY:-}}"
TENANT="${AGENT_BOM_TENANT_ID:-pilot-smoke}"

if [ -z "$API_KEY" ]; then
  echo "error: pass the API key as argv[2] or set AGENT_BOM_API_KEY" >&2
  exit 64
fi

bold() { printf "\033[1m%s\033[0m\n" "$*"; }
ok()   { printf "  \033[32m✓\033[0m %s\n" "$*"; }
fail() { printf "  \033[31m✗\033[0m %s\n" "$*" >&2; exit 1; }

hdrs=(-H "Authorization: Bearer ${API_KEY}" -H "X-Agent-Bom-Role: admin" -H "X-Agent-Bom-Tenant-ID: ${TENANT}")
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

bold "1/6 Health"
status=$(curl -sS -o "$tmp/health.json" -w "%{http_code}" "${BASE_URL}/healthz") || fail "control plane unreachable at ${BASE_URL}"
[ "$status" = "200" ] || fail "healthz returned ${status}"
ok "control plane reachable"

bold "2/6 Auth"
status=$(curl -sS -o "$tmp/auth.json" -w "%{http_code}" "${hdrs[@]}" "${BASE_URL}/v1/auth/debug") || fail "auth debug unreachable"
[ "$status" = "200" ] || fail "auth debug returned ${status}"
ok "auth resolved ($(jq -r '.method // "unknown"' "$tmp/auth.json"))"

bold "3/6 Fleet ingest"
status=$(curl -sS -o "$tmp/fleet.json" -w "%{http_code}" -X POST "${hdrs[@]}" \
  -H "Content-Type: application/json" \
  -d '{"endpoint_id":"pilot-smoke-1","hostname":"pilot-smoke","os":"linux","agents":[]}' \
  "${BASE_URL}/v1/fleet/sync") || fail "fleet sync unreachable"
case "$status" in
  200|201|202) ok "fleet heartbeat accepted (${status})" ;;
  *) fail "fleet sync returned ${status}" ;;
esac

bold "4/6 Scan"
status=$(curl -sS -o "$tmp/scan.json" -w "%{http_code}" -X POST "${hdrs[@]}" \
  -H "Content-Type: application/json" \
  -d '{"mode":"demo","offline":true}' \
  "${BASE_URL}/v1/scan") || fail "scan submit unreachable"
case "$status" in
  200|201|202) ok "scan submitted (${status})" ;;
  *) fail "scan submit returned ${status}" ;;
esac

bold "5/6 Verification key"
status=$(curl -sS -o "$tmp/key.json" -w "%{http_code}" "${hdrs[@]}" "${BASE_URL}/v1/compliance/verification-key") || fail "verification-key unreachable"
[ "$status" = "200" ] || fail "verification-key returned ${status}"
algo=$(jq -r '.algorithm' "$tmp/key.json")
ok "verification key exposed (algorithm=${algo})"
if [ "$algo" = "Ed25519" ]; then
  jq -r '.public_key_pem' "$tmp/key.json" > "$tmp/pub.pem"
  ok "public key pinned (key_id=$(jq -r '.key_id' "$tmp/key.json"))"
fi

bold "6/6 Compliance evidence bundle"
status=$(curl -sS -o "$tmp/bundle.json" -D "$tmp/headers.txt" -w "%{http_code}" "${hdrs[@]}" \
  "${BASE_URL}/v1/compliance/owasp-llm/report") || fail "compliance report unreachable"
[ "$status" = "200" ] || fail "compliance report returned ${status}"
control_count=$(jq -r '.scope.control_count' "$tmp/bundle.json")
[ "$control_count" != "null" ] && [ "$control_count" -gt 0 ] || fail "bundle has no controls"
bundle_algo=$(jq -r '.signature_algorithm' "$tmp/bundle.json")
ok "bundle returned (${control_count} controls, algorithm=${bundle_algo})"

if [ "$bundle_algo" = "Ed25519" ] && [ -s "$tmp/pub.pem" ]; then
  sig=$(awk 'tolower($1) ~ /^x-agent-bom-compliance-report-signature/ {print $2}' "$tmp/headers.txt" | tr -d '\r\n')
  [ -n "$sig" ] || fail "no signature header on the bundle"
  python3 - "$tmp/pub.pem" "$sig" "$tmp/bundle.json" <<'PY' || fail "Ed25519 verification failed"
import json, sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

pub_path, sig_hex, body_path = sys.argv[1:4]
pub = serialization.load_pem_public_key(open(pub_path).read().encode())
assert isinstance(pub, Ed25519PublicKey)
body = json.load(open(body_path))
canonical = json.dumps(body, sort_keys=True).encode()
pub.verify(bytes.fromhex(sig_hex), canonical)
PY
  ok "Ed25519 signature verified against pinned public key"
else
  ok "HMAC mode — skipping asymmetric verification (enable AGENT_BOM_COMPLIANCE_ED25519_PRIVATE_KEY_PEM for auditor-distributable signing)"
fi

bold "pilot verification passed"
echo "  base: ${BASE_URL}"
echo "  tenant: ${TENANT}"
echo "  signing: ${bundle_algo}"
