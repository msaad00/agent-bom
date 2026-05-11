#!/usr/bin/env bash
# Retrigger required CI on a PR whose head SHA was advanced by a
# GITHUB_TOKEN-authored push (auto-merge "Update branch", merge bots).
# Such pushes do not fire `pull_request` workflows, so the PR can sit in
# `mergeable_state: blocked` with missing or cancelled required checks on
# the current head.
#
# This script:
#   1. Reads the PR's current head SHA.
#   2. Checks whether all canonical required checks are attached to that SHA
#      and are either pending/running/successful.
#   3. If any required checks are still active, waits for the current run
#      instead of retriggering while downstream jobs have not been created yet.
#   4. If checks are missing or terminally stale after the run is idle, closes
#      + reopens the PR. This must use a GitHub App token or PAT; GITHUB_TOKEN
#      close/reopen events do not start pull_request workflows.
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
REQUIRED_CHECKS="${REQUIRED_CHECKS:-${REQUIRED_CHECK}}"
REPO="${GH_REPO:-$(gh repo view --json nameWithOwner --jq .nameWithOwner)}"

HEAD_SHA="$(gh api "repos/${REPO}/pulls/${PR}" --jq .head.sha)"
if [ -z "${HEAD_SHA}" ]; then
  echo "could not resolve head SHA for PR #${PR}" >&2
  exit 1
fi

CHECK_RUNS="$(
  gh api "repos/${REPO}/commits/${HEAD_SHA}/check-runs?per_page=100" --jq '.check_runs' || printf '[]'
)"
if [ -z "${CHECK_RUNS}" ]; then
  CHECK_RUNS="[]"
fi

IFS=',' read -r -a REQUIRED_CHECK_LIST <<< "${REQUIRED_CHECKS}"
missing=()
stale=()
active=()
successful=()
failed=()

for raw_check in "${REQUIRED_CHECK_LIST[@]}"; do
  check="$(xargs <<< "${raw_check}")"
  [ -n "${check}" ] || continue

  check_state="$(jq --arg name "${check}" '[.[] | select(.name == $name) | {status, conclusion}]' <<< "${CHECK_RUNS}")"
  check_hits="$(jq 'length' <<< "${check_state}")"
  active_hits="$(jq '[.[] | select(.status != "completed")] | length' <<< "${check_state}")"
  success_hits="$(jq '[.[] | select(.conclusion == "success" or .conclusion == "neutral")] | length' <<< "${check_state}")"
  stale_hits="$(jq '[.[] | select(.conclusion == "cancelled" or .conclusion == "timed_out" or .conclusion == "startup_failure" or .conclusion == "stale" or .conclusion == "skipped")] | length' <<< "${check_state}")"
  failed_hits="$(jq '[.[] | select(.conclusion == "failure" or .conclusion == "action_required")] | length' <<< "${check_state}")"

  if [ "${active_hits}" -gt 0 ]; then
    active+=("${check}")
  elif [ "${success_hits}" -gt 0 ]; then
    successful+=("${check}")
  elif [ "${failed_hits}" -gt 0 ] && [ "${stale_hits}" -eq 0 ]; then
    failed+=("${check}")
  elif [ "${check_hits}" -eq 0 ]; then
    missing+=("${check}")
  else
    stale+=("${check}")
  fi
done

if [ "${#failed[@]}" -gt 0 ]; then
  printf "PR #%s: required check(s) failed on head %s: %s. Not retriggering real failures.\n" \
    "${PR}" "${HEAD_SHA}" "$(IFS=', '; echo "${failed[*]}")"
  exit 0
fi

if [ "${#active[@]}" -gt 0 ]; then
  printf "PR #%s: required checks are active on head %s (%s active, %s successful, %s missing, %s stale). Not retriggering an in-flight run.\n" \
    "${PR}" "${HEAD_SHA}" "${#active[@]}" "${#successful[@]}" "${#missing[@]}" "${#stale[@]}"
  exit 0
fi

if [ "${#missing[@]}" -eq 0 ] && [ "${#stale[@]}" -eq 0 ]; then
  printf "PR #%s: required checks are attached on head %s (%s successful, %s active). No retrigger needed.\n" \
    "${PR}" "${HEAD_SHA}" "${#successful[@]}" "${#active[@]}"
  exit 0
fi

reason_parts=()
if [ "${#missing[@]}" -gt 0 ]; then
  reason_parts+=("missing: $(IFS=', '; echo "${missing[*]}")")
fi
if [ "${#stale[@]}" -gt 0 ]; then
  reason_parts+=("stale: $(IFS=', '; echo "${stale[*]}")")
fi
reason="$(IFS='; '; echo "${reason_parts[*]}")"

echo "PR #${PR}: required CI is stranded on head ${HEAD_SHA} (${reason}). Closing + reopening to retrigger required workflows."
gh pr close "${PR}" --comment "auto-retrigger: required CI is stranded on head ${HEAD_SHA} (${reason}). Reopening to re-run checks."

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
