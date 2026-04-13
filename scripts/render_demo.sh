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

# Rich colors but no live spinners/progress (clean for GIF recording)
export TERM=xterm-256color
export AGENT_BOM_LOG_LEVEL=error

# Clear screen for clean recording
printf '\033[H\033[2J'

run_step() {
  local visible="$1"
  shift

  printf '\033[1;36m$ %s\033[0m\n' "$visible"
  if ! "$@" 2>&1; then
    true
  fi
  printf '\n'
  sleep 1
}

# ── Demo: blast radius → quick package gate ──

# 1. Full agent scan — blast radius, severity, remediation
run_step "agent-bom agents --demo --offline" agent-bom agents --demo --offline

# 2. Pre-install CVE gate
run_step "agent-bom check pillow@9.0.0" agent-bom check pillow@9.0.0 --ecosystem pypi --quiet
