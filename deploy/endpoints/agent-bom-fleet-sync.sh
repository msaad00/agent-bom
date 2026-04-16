#!/usr/bin/env sh
set -eu

: "${AGENT_BOM_PUSH_URL:?set AGENT_BOM_PUSH_URL to your control-plane /v1/fleet/sync URL}"

if [ -n "${AGENT_BOM_PUSH_API_KEY:-}" ]; then
  exec agent-bom agents \
    --preset enterprise \
    --introspect \
    --push-url "${AGENT_BOM_PUSH_URL}" \
    --push-api-key "${AGENT_BOM_PUSH_API_KEY}" \
    "$@"
fi

exec agent-bom agents \
  --preset enterprise \
  --introspect \
  --push-url "${AGENT_BOM_PUSH_URL}" \
  "$@"
