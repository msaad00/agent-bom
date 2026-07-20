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

DEMO_TMP_FILES=()
cleanup_demo_files() {
  local file
  for file in "${DEMO_TMP_FILES[@]}"; do
    rm -f -- "$file"
  done
}
trap cleanup_demo_files EXIT INT TERM

# Clear screen for clean recording
printf '\033[H\033[2J'

print_section() {
  local label="$1"
  printf '\033[38;5;151m━━ %s ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m\n' "$label"
}

run_step() {
  local label="$1"
  local visible="$2"
  local output_file
  local command_status
  shift 2

  print_section "$label"
  printf '\033[1;36m$ %s\033[0m\n' "$visible"
  printf '\033[2mRunning the real offline command; stable output follows.\033[0m\n'
  output_file="$(mktemp "${TMPDIR:-/tmp}/agent-bom-demo.XXXXXX")"
  DEMO_TMP_FILES+=("$output_file")
  # Record the real command without Rich's live-region redraws. Replaying the
  # stable output line-by-line keeps summary, findings, and remediation frames
  # readable in VHS while preserving the command's exact text and exit result.
  set +e
  TERM=dumb "$@" >"$output_file" 2>&1
  command_status=$?
  set -e
  while IFS= read -r line || [[ -n "$line" ]]; do
    printf '%s\n' "$line"
    case "$line" in
      *"Summary"*|*"ANALYZE | Top Findings"*|*"PROTECT | Fix First"*) sleep 1 ;;
      *) sleep 0.018 ;;
    esac
  done <"$output_file"
  rm -f "$output_file"
  if [[ "$command_status" -ne 1 ]]; then
    printf '\033[1;31mUnexpected demo command exit: %s (expected security-gate exit 1)\033[0m\n' "$command_status" >&2
    return 2
  fi
  printf '\033[2m(expected security-gate exit: 1)\033[0m\n'
  printf '\n'
  sleep 1
}

# ── Demo: posture-led scan → findings queue → package gate ──

# 1. Full scan — posture grade, findings table, fix-first remediation
run_step "Agent blast-radius scan" "agent-bom scan --demo --offline -f console" agent-bom scan --demo --offline -f console

# 2. Pre-install CVE gate (offline, deterministic for GIF)
run_step "Pre-install package gate" "agent-bom check pillow@9.0.0 --ecosystem pypi --offline" agent-bom check pillow@9.0.0 --ecosystem pypi --offline
