#!/usr/bin/env bash
# Keep approved auto-merge PRs moving when `main` advances.
#
# Branch protection requires PR branches to be up to date with `main`. GitHub's
# auto-merge does not always refresh queued PRs promptly, and the UI "Update
# branch" path can leave canceled or missing checks. This script updates stale
# same-repo PR heads and then invokes the stranded-check retrigger so required
# checks attach to the new head.
#
# Usage:
#   scripts/refresh_ready_prs.sh
#   PR_NUMBER=2321 scripts/refresh_ready_prs.sh
#   DRY_RUN=true scripts/refresh_ready_prs.sh

set -euo pipefail

REPO="${GH_REPO:-$(gh repo view --json nameWithOwner --jq .nameWithOwner)}"
BASE_BRANCH="${BASE_BRANCH:-main}"
PR_NUMBER="${PR_NUMBER:-}"
MIN_AGE_MINUTES="${MIN_AGE_MINUTES:-3}"
REQUIRE_AUTO_MERGE="${REQUIRE_AUTO_MERGE:-true}"
DRY_RUN="${DRY_RUN:-false}"
REQUIRED_CHECK="${REQUIRED_CHECK:-Lint and Type Check}"
MAX_POLLS="${MAX_POLLS:-12}"
POLL_SECONDS="${POLL_SECONDS:-5}"

if ! command -v gh >/dev/null 2>&1; then
  echo "gh is required" >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required" >&2
  exit 1
fi

now_epoch() {
  date -u +%s
}

date_epoch() {
  local value="$1"
  date -u -d "$value" +%s 2>/dev/null || date -u -j -f "%Y-%m-%dT%H:%M:%SZ" "$value" +%s
}

list_prs() {
  if [ -n "${PR_NUMBER}" ]; then
    printf '%s\n' "${PR_NUMBER}"
    return
  fi

  gh pr list \
    --repo "${REPO}" \
    --state open \
    --base "${BASE_BRANCH}" \
    --limit 100 \
    --json number,isDraft \
    --jq '.[] | select(.isDraft == false) | .number'
}

base_sha() {
  gh api "repos/${REPO}/git/ref/heads/${BASE_BRANCH}" --jq .object.sha
}

commits_missing_from_head() {
  local head_sha="$1"
  local base_sha="$2"
  gh api "repos/${REPO}/compare/${head_sha}...${base_sha}" --jq .ahead_by
}

poll_head_change() {
  local pr="$1"
  local old_sha="$2"
  local attempt
  local new_sha

  for ((attempt = 1; attempt <= MAX_POLLS; attempt++)); do
    new_sha="$(gh api "repos/${REPO}/pulls/${pr}" --jq .head.sha)"
    if [ "${new_sha}" != "${old_sha}" ]; then
      printf '%s\n' "${new_sha}"
      return 0
    fi
    sleep "${POLL_SECONDS}"
  done

  printf '%s\n' "${old_sha}"
}

refresh_pr() {
  local pr="$1"
  local info
  local is_draft base_ref head_owner updated_at age_seconds auto_merge review head_sha head_ref
  local repo_owner missing output updated_sha now updated_epoch

  info="$(gh pr view "${pr}" \
    --repo "${REPO}" \
    --json number,isDraft,baseRefName,headRefName,headRefOid,headRepositoryOwner,updatedAt,reviewDecision,autoMergeRequest,url)"

  is_draft="$(jq -r '.isDraft' <<< "${info}")"
  base_ref="$(jq -r '.baseRefName' <<< "${info}")"
  head_owner="$(jq -r '.headRepositoryOwner.login' <<< "${info}")"
  updated_at="$(jq -r '.updatedAt' <<< "${info}")"
  auto_merge="$(jq -r '.autoMergeRequest != null' <<< "${info}")"
  review="$(jq -r '.reviewDecision' <<< "${info}")"
  head_sha="$(jq -r '.headRefOid' <<< "${info}")"
  head_ref="$(jq -r '.headRefName' <<< "${info}")"
  repo_owner="${REPO%%/*}"

  if [ "${is_draft}" = "true" ]; then
    echo "PR #${pr}: draft, skipping."
    return 0
  fi

  if [ "${base_ref}" != "${BASE_BRANCH}" ]; then
    echo "PR #${pr}: targets ${base_ref}, not ${BASE_BRANCH}; skipping."
    return 0
  fi

  if [ "${head_owner}" != "${repo_owner}" ]; then
    echo "PR #${pr}: fork-owned branch (${head_owner}/${head_ref}), skipping."
    return 0
  fi

  if [ "${REQUIRE_AUTO_MERGE}" = "true" ] && [ "${auto_merge}" != "true" ]; then
    echo "PR #${pr}: auto-merge not enabled, skipping."
    return 0
  fi

  now="$(now_epoch)"
  updated_epoch="$(date_epoch "${updated_at}")"
  age_seconds=$((now - updated_epoch))
  if [ "${age_seconds}" -lt $((60 * MIN_AGE_MINUTES)) ]; then
    echo "PR #${pr}: updated ${age_seconds}s ago, skipping until it settles."
    return 0
  fi

  missing="$(commits_missing_from_head "${head_sha}" "$(base_sha)")"
  if [ "${missing}" -eq 0 ]; then
    echo "PR #${pr}: already contains current ${BASE_BRANCH}; checking for stranded CI."
    REQUIRED_CHECK="${REQUIRED_CHECK}" scripts/retrigger_stranded_pr.sh "${pr}"
    return 0
  fi

  echo "PR #${pr}: ${missing} ${BASE_BRANCH} commit(s) missing; refreshing ${head_ref}."
  if [ "${DRY_RUN}" = "true" ]; then
    echo "PR #${pr}: dry-run, would run gh pr update-branch."
    return 0
  fi

  if output="$(gh pr update-branch "${pr}" --repo "${REPO}" 2>&1)"; then
    printf '%s\n' "${output}"
  else
    if grep -qi "update.*already.*progress" <<< "${output}"; then
      echo "PR #${pr}: branch update already in progress; next run will verify CI."
      return 0
    fi
    printf '%s\n' "${output}" >&2
    return 1
  fi

  updated_sha="$(poll_head_change "${pr}" "${head_sha}")"
  if [ "${updated_sha}" = "${head_sha}" ]; then
    echo "PR #${pr}: head did not advance after update request; next run will retry."
    return 0
  fi

  echo "PR #${pr}: head advanced ${head_sha} -> ${updated_sha}; ensuring required checks attach."
  REQUIRED_CHECK="${REQUIRED_CHECK}" scripts/retrigger_stranded_pr.sh "${pr}"

  if [ "${review}" != "APPROVED" ]; then
    echo "PR #${pr}: refreshed, but review decision is ${review}; auto-merge will wait for review."
  fi
}

checked=0
refreshed=0

while IFS= read -r pr; do
  [ -n "${pr}" ] || continue
  checked=$((checked + 1))
  if refresh_pr "${pr}"; then
    refreshed=$((refreshed + 1))
  else
    echo "PR #${pr}: refresh failed, continuing." >&2
  fi
done < <(list_prs)

echo
echo "Summary: ${checked} PR(s) inspected, ${refreshed} completed without fatal errors."
