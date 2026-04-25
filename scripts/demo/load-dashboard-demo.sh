#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${1:-${AGENT_BOM_API_URL:-http://127.0.0.1:8422}}"
BASE_URL="${BASE_URL%/}"
PUSH_URL="${BASE_URL}/v1/results/push"
DASHBOARD_URL="${BASE_URL}/dashboard"
REPORT_PATH="$(mktemp "${TMPDIR:-/tmp}/agent-bom-demo-report.XXXXXX.json")"

cleanup() {
  rm -f "$REPORT_PATH"
}
trap cleanup EXIT

args=(
  agents
  --demo
  --offline
  --no-update-db
  --quiet
  -f json
  -o "$REPORT_PATH"
  --push-url "$PUSH_URL"
)

if [[ -n "${AGENT_BOM_PUSH_API_KEY:-${AGENT_BOM_API_KEY:-}}" ]]; then
  args+=(--push-api-key "${AGENT_BOM_PUSH_API_KEY:-${AGENT_BOM_API_KEY:-}}")
fi

agent-bom "${args[@]}"

echo "Demo results pushed to ${PUSH_URL}"
echo "Dashboard: ${DASHBOARD_URL}"
