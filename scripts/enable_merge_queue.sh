#!/usr/bin/env bash
# Inspect CI protection and print merge-queue guidance for `main`.
#
# Inspect live protection before an owner-controlled settings change.
# Workflow trigger support does not establish merge-queue availability.
#
# Usage:
#   scripts/enable_merge_queue.sh         # print guidance; does not change settings
#   scripts/enable_merge_queue.sh --check # inspect current rules and workflow state
#

set -euo pipefail

REPO="${GH_REPO:-$(gh repo view --json nameWithOwner --jq .nameWithOwner)}"
BRANCH="main"

if [ "${1:-}" = "--check" ]; then
  echo "Repo: ${REPO}@${BRANCH}"
  echo
  echo "Active rulesets touching '${BRANCH}':"
  gh api "repos/${REPO}/rules/branches/${BRANCH}" \
    --jq '[.[] | .type] // [] | unique' 2>/dev/null || echo "  (rules unavailable; check API access and repository settings)"
  echo
  echo "Branch-protection rule fields:"
  gh api "repos/${REPO}/branches/${BRANCH}/protection" \
    --jq '{strict: .required_status_checks.strict, contexts: .required_status_checks.contexts}' 2>/dev/null || echo "  (protection unavailable; check API access and repository settings)"
  echo
  echo "Auto-retrigger workflow status:"
  gh api "repos/${REPO}/actions/workflows/auto-retrigger-stranded.yml" \
    --jq '"  state=\(.state)"' 2>/dev/null || echo "  (workflow state unavailable; check API access and workflow configuration)"
  exit 0
fi

cat <<EOF
Merge queue is an optional owner-controlled repository setting.
Inspect live protection and repository availability before changing settings:

  scripts/enable_merge_queue.sh --check

The required contexts verified on 2026-09-27 were:
  Lint and Type Check, Test (Python 3.13), Build Package, Security Scan, CodeQL
Recheck the API output; do not substitute the post-merge full-correctness jobs.

The recovery workflow is .github/workflows/auto-retrigger-stranded.yml.
It responds to PR synchronization and main pushes, with a 15-minute scheduled
fallback. A dedicated AUTOMATION_GITHUB_TOKEN is needed for unattended branch
refresh/retrigger recovery; otherwise scripts/dispatch_required_ci.sh can
recover missing checks on already-current PR heads. Schedules can be delayed.

See docs/operations/CI_RUNBOOK.md. This command does not change settings.
EOF
