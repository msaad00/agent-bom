#!/usr/bin/env bash
# Retrigger required CI on a PR whose head SHA was advanced by a
# GITHUB_TOKEN-authored push (auto-merge "Update branch", merge bots).
# Such pushes do not fire `pull_request` workflows, so the PR can sit in
# `mergeable_state: blocked` with missing or cancelled required checks on
# the current head.
#
# This script:
#   1. Reads the PR's current head SHA.
#   2. Checks whether the canonical required check ("Lint and Type Check") is
#      attached to that SHA and is either pending/running/successful.
#   3. If missing or terminally stale, closes + reopens the PR — the
#      `reopened` action fires `pull_request` workflows again from scratch.
#
# Usage:
#   scripts/retrigger_stranded_pr.sh <PR_NUMBER>
#
# Requires: gh CLI authenticated against the repo.

set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <PR_NUMBER>" >&2
  exit 64
fi

PR="$1"
REQUIRED_CHECK="${REQUIRED_CHECK:-Lint and Type Check}"
REPO="${GH_REPO:-$(gh repo view --json nameWithOwner --jq .nameWithOwner)}"

HEAD_SHA="$(gh api "repos/${REPO}/pulls/${PR}" --jq .head.sha)"
if [ -z "${HEAD_SHA}" ]; then
  echo "could not resolve head SHA for PR #${PR}" >&2
  exit 1
fi

CHECK_STATE="$(
  gh api "repos/${REPO}/commits/${HEAD_SHA}/check-runs" \
    --jq "[
      .check_runs[]
      | select(.name == \"${REQUIRED_CHECK}\")
      | {status, conclusion}
    ]"
)"

CHECK_HITS="$(jq 'length' <<< "${CHECK_STATE}")"
ACTIVE_HITS="$(jq '[.[] | select(.status != "completed")] | length' <<< "${CHECK_STATE}")"
SUCCESS_HITS="$(jq '[.[] | select(.conclusion == "success")] | length' <<< "${CHECK_STATE}")"
STALE_HITS="$(jq '[.[] | select(.conclusion == "cancelled" or .conclusion == "timed_out" or .conclusion == "startup_failure" or .conclusion == "stale" or .conclusion == "skipped")] | length' <<< "${CHECK_STATE}")"
FAILED_HITS="$(jq '[.[] | select(.conclusion == "failure")] | length' <<< "${CHECK_STATE}")"

if [ "${ACTIVE_HITS}" -gt 0 ]; then
  echo "PR #${PR}: '${REQUIRED_CHECK}' is already active on head ${HEAD_SHA}. No retrigger needed."
  exit 0
fi

if [ "${SUCCESS_HITS}" -gt 0 ]; then
  echo "PR #${PR}: head ${HEAD_SHA} already has successful '${REQUIRED_CHECK}'. No retrigger needed."
  exit 0
fi

if [ "${FAILED_HITS}" -gt 0 ] && [ "${STALE_HITS}" -eq 0 ]; then
  echo "PR #${PR}: '${REQUIRED_CHECK}' failed on head ${HEAD_SHA}. Not retriggering a real failure."
  exit 0
fi

if [ "${CHECK_HITS}" -eq 0 ]; then
  reason="required CI did not attach"
else
  reason="required CI is terminally stale (${STALE_HITS}/${CHECK_HITS} stale runs)"
fi

echo "PR #${PR}: ${reason} for '${REQUIRED_CHECK}' on head ${HEAD_SHA}. Closing + reopening to retrigger required workflows."
gh pr close "${PR}" --comment "auto-retrigger: ${reason} for '${REQUIRED_CHECK}' on head ${HEAD_SHA} (likely a GITHUB_TOKEN-authored 'Update branch' merge or cancelled required context). Reopening to re-run checks."

# `gh pr close` returns before GitHub has propagated the state change to
# the PR resource. Reopening too soon races: the reopen API call lands
# while the PR is still considered open and silently no-ops, leaving the
# PR closed without the `pull_request reopened` event we depend on.
# Poll the API until the close is observable, then reopen.
for attempt in 1 2 3 4 5 6 7 8 9 10; do
  state="$(gh api "repos/${REPO}/pulls/${PR}" --jq .state 2>/dev/null || echo unknown)"
  if [ "${state}" = "closed" ]; then
    break
  fi
  if [ "${attempt}" -eq 10 ]; then
    echo "warning: PR #${PR} did not register as closed within 10 polls; reopening anyway." >&2
  fi
  sleep 1
done

gh pr reopen "${PR}" --comment "reopened to retrigger required checks against the up-to-date head."
echo "PR #${PR}: retrigger requested. Workflows should appear in ~10s."
