#!/usr/bin/env bash
# Reset hosted-demo tenant state (hub findings + cached totals).
#
# Usage:
#   scripts/deploy/demo-reset.sh https://agent-bom.example.com "$AGENT_BOM_API_KEY" [tenant_id]
#
# Requires an admin-scoped API key. Safe to run on a schedule via cron/Kubernetes
# CronJob for public demo estates.

set -euo pipefail

API_URL="${1:-}"
API_KEY="${2:-}"
TENANT="${3:-default}"

if [ -z "$API_URL" ] || [ -z "$API_KEY" ]; then
  echo "usage: $0 <control-plane-url> <admin-api-key> [tenant_id]" >&2
  exit 2
fi

BASE="${API_URL%/}"
HDR=( -H "Authorization: Bearer ${API_KEY}" -H "X-Agent-Bom-Tenant-ID: ${TENANT}" )

echo "Clearing hub findings for tenant=${TENANT} ..."
curl -fsS -X DELETE "${BASE}/v1/compliance/hub/findings" "${HDR[@]}" | cat
echo

if [ "${AGENT_BOM_DEMO_ESTATE:-0}" = "1" ]; then
  echo "Demo estate bootstrap will re-seed on next API restart."
fi

echo "Done."
