#!/usr/bin/env bash
# Retrigger required CI on a PR whose head SHA was advanced by a
# GITHUB_TOKEN-authored push (auto-merge "Update branch", merge bots).
# Such pushes do not fire `pull_request` workflows, so the PR sits in
# `mergeable_state: blocked` with zero check runs on the current head.
#
# This script:
#   1. Reads the PR's current head SHA.
#   2. Checks whether the canonical required check ("Lint and Type Check")
#      has run against that SHA.
#   3. If not, closes + reopens the PR — the `reopened` action fires
#      `pull_request` workflows again from scratch.
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

CHECK_HITS="$(
  gh api "repos/${REPO}/commits/${HEAD_SHA}/check-runs" \
    --jq "[.check_runs[] | select(.name == \"${REQUIRED_CHECK}\")] | length"
)"

if [ "${CHECK_HITS}" -gt 0 ]; then
  echo "PR #${PR}: head ${HEAD_SHA} already has '${REQUIRED_CHECK}' (count=${CHECK_HITS}). No retrigger needed."
  exit 0
fi

echo "PR #${PR}: head ${HEAD_SHA} has 0 '${REQUIRED_CHECK}' runs. Closing + reopening to retrigger required workflows."
gh pr close "${PR}" --comment "auto-retrigger: required CI did not fire on head ${HEAD_SHA} (likely a GITHUB_TOKEN-authored 'Update branch' merge). Reopening to re-run checks."

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
