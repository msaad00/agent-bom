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

gh run cancel "${RUN_ID}" --repo "${REPO}"

for attempt in 1 2 3 4 5; do
  status="$(
    gh run view "${RUN_ID}" --repo "${REPO}" --json status --jq .status \
      2>/dev/null || printf 'unknown'
  )"
  if [ "${status}" = "completed" ]; then
    exit 0
  fi
  if [ "${attempt}" -lt 5 ]; then
    sleep "${CANCEL_POLL_SECONDS:-2}"
  fi
done

echo "workflow run ${RUN_ID} did not stop after normal cancellation; requesting force-cancel."
if gh api --method POST "repos/${REPO}/actions/runs/${RUN_ID}/force-cancel" >/dev/null; then
  exit 0
fi

# The run can complete between the last poll and the force-cancel request.
status="$(
  gh run view "${RUN_ID}" --repo "${REPO}" --json status --jq .status \
    2>/dev/null || printf 'unknown'
)"
if [ "${status}" = "completed" ]; then
  exit 0
fi

echo "failed to cancel superseded workflow run ${RUN_ID} (status: ${status})." >&2
exit 1
