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

# Clear screen for clean recording
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

# ── Demo flow: scan → check → verify ──
# Shows three core workflows in sequence

# 1. Full agent scan — blast radius, credentials, remediation
run_step "agent-bom agents --demo --offline" agent-bom agents --demo --offline

# 2. Pre-install check — catch vulns before they land
run_step "agent-bom check pillow@9.0.0" agent-bom check pillow@9.0.0 --ecosystem pypi

# 3. Package integrity verification
run_step "agent-bom verify requests@2.33.0" agent-bom verify requests@2.33.0 --ecosystem pypi
