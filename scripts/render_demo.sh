#!/usr/bin/env bash

set -euo pipefail

DEMO_ENGINE="${AGENT_BOM_DEMO_ENGINE:-python}"
IMAGE_TAG="${AGENT_BOM_DEMO_IMAGE:-agent-bom:demo-current}"
DB_SOURCE="${AGENT_BOM_DB_SOURCE:-$HOME/.agent-bom/db/vulns.db}"

export AGENT_BOM_DEMO_ENGINE="$DEMO_ENGINE"
export AGENT_BOM_DEMO_IMAGE="$IMAGE_TAG"
export AGENT_BOM_DEMO_DB_SOURCE="$DB_SOURCE"
export AGENT_BOM_DEMO_REPO_ROOT="$PWD"
. "$(dirname "$0")/demo-env.sh"
export TERM=dumb

# Clear the launch command from the terminal so the asset starts with
# agent-bom output, not the demo harness invocation itself.
printf '\033[H\033[2J'

run_step() {
  local visible="$1"
  shift

  printf '$ %s\n' "$visible"
  if ! "$@" 2>&1; then
    true
  fi
  printf '\n'
  sleep 1
}

run_step "agent-bom agents --demo --posture --offline" agent-bom agents --demo --posture --offline
run_step "agent-bom check pillow@9.0.0 --ecosystem pypi" agent-bom check pillow@9.0.0 --ecosystem pypi
run_step "agent-bom check express@4.17.1 --ecosystem npm" agent-bom check express@4.17.1 --ecosystem npm
