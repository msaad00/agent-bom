#!/usr/bin/env bash
# Print the supported path for enabling GitHub merge queue on `main`.
#
# Why this is no longer a one-shot script
# ───────────────────────────────────────
# As of 2026-04, GitHub returns HTTP 422 "Invalid rule 'merge_queue'" when
# a `merge_queue` rule is POSTed to repos/{owner}/{repo}/rulesets, even on
# personal repos with `repo`-scoped tokens. The legacy
# branches/{branch}/protection endpoint never exposed merge_queue at all.
# The Settings UI is the only supported toggle.
#
# For the recurring stranded-CI pain that motivated wanting merge queue,
# `.github/workflows/auto-retrigger-stranded.yml` is the practical fix:
# it polls open PRs every 5 minutes and runs scripts/retrigger_stranded_pr.sh
# against any whose current head SHA has zero check-runs. That neutralises
# the GITHUB_TOKEN-authored-merge anti-loop guard without needing
# repo-settings changes.
#
# Usage:
#   scripts/enable_merge_queue.sh         # print steps
#   scripts/enable_merge_queue.sh --check # print current ruleset/protection state
#

set -euo pipefail

REPO="${GH_REPO:-$(gh repo view --json nameWithOwner --jq .nameWithOwner)}"
BRANCH="main"

if [ "${1:-}" = "--check" ]; then
  echo "Repo: ${REPO}@${BRANCH}"
  echo
  echo "Active rulesets touching '${BRANCH}':"
  gh api "repos/${REPO}/rules/branches/${BRANCH}" \
    --jq '[.[] | .type] // [] | unique' 2>/dev/null || echo "  (none / 404)"
  echo
  echo "Branch-protection rule fields:"
  gh api "repos/${REPO}/branches/${BRANCH}/protection" \
    --jq 'keys' 2>/dev/null || echo "  (no legacy branch-protection rule)"
  echo
  echo "Auto-retrigger workflow status:"
  gh workflow view auto-retrigger-stranded.yml --json state 2>/dev/null \
    --jq '"  state=\(.state)"' || echo "  (workflow not present on default branch yet)"
  exit 0
fi

cat <<EOF
Merge queue cannot currently be enabled via REST on this repo's auth path.

Supported steps (one-time):

  1. https://github.com/${REPO}/settings/branches
  2. Edit the rule for '${BRANCH}' (or add one if absent)
  3. Check  ✅  Require merge queue
  4. Set the merge method to Squash and the same required status checks
     used today (Lint and Type Check, Test (Python 3.11/3.13/3.14),
     Build Package, Security Scan, CodeQL)
  5. Save

Verify with:

  scripts/enable_merge_queue.sh --check

Until the toggle is on, the practical fix for stranded PRs is the
scheduled workflow at .github/workflows/auto-retrigger-stranded.yml,
which auto-runs scripts/retrigger_stranded_pr.sh every 5 minutes. No
operator action needed once it's on the default branch.
EOF
