#!/usr/bin/env bash
set -euo pipefail

base_url="${AGENT_BOM_SMOKE_URL:-${NEXT_PUBLIC_API_URL:-}}"
api_key="${AGENT_BOM_SMOKE_API_KEY:-${AGENT_BOM_API_KEY:-}}"

if [[ -z "${base_url}" ]]; then
  echo "AGENT_BOM_SMOKE_URL or NEXT_PUBLIC_API_URL is required" >&2
  exit 1
fi
if [[ -z "${api_key}" ]]; then
  echo "AGENT_BOM_SMOKE_API_KEY or AGENT_BOM_API_KEY is required" >&2
  exit 1
fi

base_url="${base_url%/}"

request() {
  local method="$1"
  local path="$2"
  curl -fsS \
    -X "${method}" \
    -H "Authorization: Bearer ${api_key}" \
    -H "Content-Type: application/json" \
    "${base_url}${path}" >/dev/null
}

curl -fsS "${base_url}/health" >/dev/null
request GET /v1/auth/me
request GET /v1/overview
request GET /v1/jobs
request GET /v1/graph/snapshots
request GET /v1/compliance
request GET /v1/audit/integrity

if [[ -n "${AGENT_BOM_SMOKE_CONNECTION_ID:-}" ]]; then
  encoded_connection_id="${AGENT_BOM_SMOKE_CONNECTION_ID}"
  request POST "/v1/cloud/connections/${encoded_connection_id}/test"
  if [[ "${AGENT_BOM_SMOKE_RUN_CONNECTION_SCAN:-0}" =~ ^(1|true|yes|on)$ ]]; then
    request POST "/v1/cloud/connections/${encoded_connection_id}/scan"
  fi
fi

echo "Hosted POC smoke passed for ${base_url}"
