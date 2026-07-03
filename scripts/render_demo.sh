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

print_section() {
  local label="$1"
  printf '\033[38;5;151m━━ %s ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m\n' "$label"
}

run_step() {
  local label="$1"
  local visible="$2"
  shift 2

  print_section "$label"
  printf '\033[1;36m$ %s\033[0m\n' "$visible"
  if ! "$@" 2>&1; then
    true
  fi
  printf '\n'
  sleep 1
}

# ── Demo: posture-led scan → findings queue → package gate ──

# 1. Full agent scan — posture grade, findings table, fix-first remediation
run_step "Agent blast-radius scan" "agent-bom agents --demo --offline -f console" agent-bom agents --demo --offline -f console

# 2. Pre-install CVE gate (offline, deterministic for GIF)
run_step "Pre-install package gate" "agent-bom check pillow@9.0.0 --ecosystem pypi --offline" agent-bom check pillow@9.0.0 --ecosystem pypi --offline
