#!/usr/bin/env bash
# Enable GitHub merge queue on `main` so PRs stop getting stranded by
# GITHUB_TOKEN-authored "Update branch" pushes.
#
# Background: the legacy branches/{branch}/protection REST endpoint does not
# expose merge_queue config. Merge queue is configured via the repository
# rulesets API (or the Settings UI). This script writes a ruleset whose
# required_status_checks match the current branch-protection rule.
#
# Usage:
#   scripts/enable_merge_queue.sh --dry-run   # preview the payload
#   GH_TOKEN=<admin-pat> scripts/enable_merge_queue.sh
#
# Requires: gh CLI authenticated against the repo with admin scope (the
# default user token from `gh auth login` lacks `administration:write` on
# org repos; use a fine-grained PAT if needed).

set -euo pipefail

DRY_RUN="false"
if [ "${1:-}" = "--dry-run" ]; then
  DRY_RUN="true"
fi

REPO="${GH_REPO:-$(gh repo view --json nameWithOwner --jq .nameWithOwner)}"
BRANCH="main"

# These are the canonical required checks today. Keep this list in sync with
# the branch-protection rule until both move to the same source of truth
# (the ruleset itself once merge queue is on).
REQUIRED_CHECKS=(
  "Lint and Type Check"
  "Test (Python 3.11)"
  "Test (Python 3.13)"
  "Test (Python 3.14)"
  "Build Package"
  "Security Scan"
  "CodeQL"
)

# Build the JSON checks array.
CHECKS_JSON="$(printf '%s\n' "${REQUIRED_CHECKS[@]}" | jq -R . | jq -s 'map({context: ., integration_id: null})')"

PAYLOAD="$(jq -n \
  --arg name "merge-queue-${BRANCH}" \
  --arg ref "refs/heads/${BRANCH}" \
  --argjson checks "${CHECKS_JSON}" \
  '{
    name: $name,
    target: "branch",
    enforcement: "active",
    conditions: { ref_name: { include: [$ref], exclude: [] } },
    rules: [
      { type: "deletion" },
      { type: "non_fast_forward" },
      { type: "required_signatures" },
      { type: "pull_request",
        parameters: {
          required_approving_review_count: 1,
          dismiss_stale_reviews_on_push: false,
          require_code_owner_review: false,
          require_last_push_approval: false,
          required_review_thread_resolution: false
        }
      },
      { type: "required_status_checks",
        parameters: {
          strict_required_status_checks_policy: false,
          required_status_checks: $checks
        }
      },
      { type: "merge_queue",
        parameters: {
          check_response_timeout_minutes: 60,
          grouping_strategy: "ALLGREEN",
          max_entries_to_build: 5,
          max_entries_to_merge: 5,
          merge_method: "SQUASH",
          min_entries_to_merge: 1,
          min_entries_to_merge_wait_minutes: 5
        }
      }
    ]
  }')"

if [ "${DRY_RUN}" = "true" ]; then
  printf "Would POST the following ruleset to repos/%s/rulesets:\n\n%s\n" \
    "${REPO}" "${PAYLOAD}"
  exit 0
fi

if [ -z "${GH_TOKEN:-}" ]; then
  echo "GH_TOKEN is required (admin-scope PAT). Run with --dry-run to preview." >&2
  exit 64
fi

echo "Creating merge-queue ruleset on ${REPO}@${BRANCH}…"
echo "${PAYLOAD}" | gh api \
  --method POST \
  -H "Accept: application/vnd.github+json" \
  "repos/${REPO}/rulesets" \
  --input -

echo
echo "Done. Verify in Settings → Rules → Rulesets, or with:"
echo "  gh api repos/${REPO}/rulesets --jq '.[] | select(.name == \"merge-queue-${BRANCH}\")'"
echo
echo "Note: if a legacy branch-protection rule on '${BRANCH}' is still active,"
echo "either delete it (Settings → Branches) or trust the ruleset to take over."
