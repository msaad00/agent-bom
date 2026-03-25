#!/usr/bin/env bash

set -euo pipefail

IMAGE_TAG="${AGENT_BOM_DEMO_IMAGE:-agent-bom:release-alpine-test}"
DB_SOURCE="${AGENT_BOM_DB_SOURCE:-$HOME/.agent-bom/db/vulns.db}"
DB_COPY="${AGENT_BOM_DEMO_DB:-/tmp/agent-bom-demo/vulns.db}"

mkdir -p "$(dirname "$DB_COPY")"
cp "$DB_SOURCE" "$DB_COPY"

docker_abom() {
  docker run --rm \
    -e AGENT_BOM_DB_PATH=/tmp/vulns.db \
    -e AGENT_BOM_LOG_LEVEL=error \
    -v "$DB_COPY:/tmp/vulns.db:ro" \
    "$IMAGE_TAG" \
    "$@"
}

run_step() {
  local visible="$1"
  shift

  printf '$ %s\n' "$visible"
  "$@" 2>&1
  printf '\n'
  sleep 1
}

run_step "agent-bom --version" docker_abom --version
run_step "agent-bom agents --demo --posture --offline" docker_abom agents --demo --posture --offline
run_step "agent-bom check flask==2.2.0 --ecosystem pypi" docker_abom check flask==2.2.0 --ecosystem pypi
