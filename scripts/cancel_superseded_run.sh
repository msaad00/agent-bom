#!/usr/bin/env bash
# Cancel an already-vetted superseded workflow run, escalating only when the
# normal GitHub cancellation request does not complete within a short grace.
# Callers must first constrain the target to an old head SHA on the exact PR
# branch and to a required workflow.

set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <OWNER/REPO> <RUN_ID>" >&2
  exit 64
fi

REPO="$1"
RUN_ID="$2"

if ! gh run cancel "${RUN_ID}" --repo "${REPO}"; then
  # The run can finish between the caller listing it as active and this
  # request landing; GitHub then rejects the cancel ("Cannot cancel a
  # workflow run that is completed"). That is the end state we wanted, so
  # only a still-active run is worth escalating — or failing — over.
  status="$(
    gh run view "${RUN_ID}" --repo "${REPO}" --json status --jq .status \
      2>/dev/null || printf 'unknown'
  )"
  if [ "${status}" = "completed" ]; then
    exit 0
  fi
  echo "cancel request for workflow run ${RUN_ID} was rejected (status: ${status}); escalating."
fi

run_status() {
  gh run view "${RUN_ID}" --repo "${REPO}" --json status --jq .status \
    2>/dev/null || printf 'unknown'
}

# Poll for a bounded grace period; succeed as soon as the run is completed.
wait_until_completed() {
  for attempt in 1 2 3 4 5; do
    status="$(run_status)"
    if [ "${status}" = "completed" ]; then
      return 0
    fi
    if [ "${attempt}" -lt 5 ]; then
      sleep "${CANCEL_POLL_SECONDS:-2}"
    fi
  done
  return 1
}

if wait_until_completed; then
  exit 0
fi

echo "workflow run ${RUN_ID} did not stop after normal cancellation; requesting force-cancel."
if gh api --method POST "repos/${REPO}/actions/runs/${RUN_ID}/force-cancel" >/dev/null; then
  exit 0
fi

# GitHub rejects force-cancel (HTTP 409 "not in progress") while a normal
# cancellation is already winding the run down, and the status API can still
# report in_progress for a few seconds after that. Wait out that window
# before calling the cancellation failed.
echo "force-cancel for workflow run ${RUN_ID} was rejected; waiting for the pending cancellation."
if wait_until_completed; then
  exit 0
fi

echo "failed to cancel superseded workflow run ${RUN_ID} (status: ${status})." >&2
exit 1
