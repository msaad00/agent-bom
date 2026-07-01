#!/usr/bin/env bash
set -euo pipefail

base_url="${ABOM_URL:-http://127.0.0.1:8422}"
token="${ABOM_API_TOKEN:-${AGENT_BOM_API_KEY:-}}"

if [[ -z "$token" ]]; then
  echo "Set ABOM_API_TOKEN or AGENT_BOM_API_KEY before running the live demo." >&2
  exit 2
fi

base_url="${base_url%/}"
auth_header="Authorization: Bearer ${token}"

request() {
  local label="$1"
  local path="$2"
  echo
  echo "== ${label} =="
  curl --fail --silent --show-error \
    --connect-timeout 3 \
    --max-time 15 \
    -H "$auth_header" \
    -H "Accept: application/json" \
    "${base_url}${path}" \
    | python -m json.tool
}

echo "agent-bom gateway/fleet live demo"
echo "API: ${base_url}"

request "Gateway stats" "/v1/gateway/stats"
request "Gateway feed KPIs" "/v1/gateway/feed/kpis"
request "Fleet stats" "/v1/fleet/stats"
request "Fleet agents" "/v1/fleet/agents"
request "Proxy status" "/v1/proxy/status"
request "Runtime production index" "/v1/runtime/production-index"
request "Top exposure paths" "/v1/graph/exposure-paths?limit=5"

echo
echo "Read-only walkthrough complete. Use the UI graph, fleet, gateway, and audit pages to narrate the same evidence."
