#!/usr/bin/env bash
# Dispatch required workflows for a PR whose current head is missing required
# status contexts, without closing/reopening the PR.
#
# This is the safe fallback for repositories where AUTOMATION_GITHUB_TOKEN is
# not configured. It can only help when the PR branch already contains current
# main. If the branch is stale, a signed refresh still needs the dedicated
# automation token path in scripts/refresh_ready_prs.sh.
#
# Usage:
#   scripts/dispatch_required_ci.sh <PR_NUMBER>

set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <PR_NUMBER>" >&2
  exit 64
fi

PR="$1"
REQUIRED_CHECKS="${REQUIRED_CHECKS:-Lint and Type Check,Test (Python 3.11),Test (Python 3.13),Build Package,Security Scan,CodeQL,Test (Python 3.14)}"
REPO="${GH_REPO:-$(gh repo view --json nameWithOwner --jq .nameWithOwner)}"

pr_json="$(
  gh pr view "${PR}" \
    --repo "${REPO}" \
    --json baseRefName,headRefName,headRefOid,headRepositoryOwner,isCrossRepository,isDraft
)"

is_draft="$(jq -r '.isDraft' <<< "${pr_json}")"
is_cross_repo="$(jq -r '.isCrossRepository' <<< "${pr_json}")"
head_owner="$(jq -r '.headRepositoryOwner.login' <<< "${pr_json}")"
head_ref="$(jq -r '.headRefName' <<< "${pr_json}")"
head_sha="$(jq -r '.headRefOid' <<< "${pr_json}")"
base_ref="$(jq -r '.baseRefName' <<< "${pr_json}")"
repo_owner="${REPO%%/*}"

if [ "${is_draft}" = "true" ]; then
  echo "PR #${PR}: draft, skipping fallback dispatch."
  exit 0
fi

if [ "${is_cross_repo}" = "true" ] || [ "${head_owner}" != "${repo_owner}" ]; then
  echo "PR #${PR}: fork-owned branch (${head_owner}/${head_ref}), skipping fallback dispatch."
  exit 0
fi

base_sha="$(gh api "repos/${REPO}/git/ref/heads/${base_ref}" --jq .object.sha)"
missing_from_head="$(gh api "repos/${REPO}/compare/${head_sha}...${base_sha}" --jq .ahead_by)"
if [ "${missing_from_head}" -gt 0 ]; then
  echo "PR #${PR}: ${missing_from_head} ${base_ref} commit(s) missing; fallback dispatch cannot refresh stale branches."
  exit 0
fi

check_runs="$(
  gh api "repos/${REPO}/commits/${head_sha}/check-runs?per_page=100" --jq '.check_runs' || printf '[]'
)"
if [ -z "${check_runs}" ]; then
  check_runs="[]"
fi

IFS=',' read -r -a required_check_list <<< "${REQUIRED_CHECKS}"
missing=()
stale=()
active=()
successful=()
failed=()

for raw_check in "${required_check_list[@]}"; do
  check="$(xargs <<< "${raw_check}")"
  [ -n "${check}" ] || continue

  check_state="$(jq --arg name "${check}" '[.[] | select(.name == $name) | {status, conclusion}]' <<< "${check_runs}")"
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
  printf "PR #%s: required check(s) failed on head %s: %s. Not dispatching over real failures.\n" \
    "${PR}" "${head_sha}" "$(IFS=', '; echo "${failed[*]}")"
  exit 0
fi

if [ "${#active[@]}" -gt 0 ]; then
  printf "PR #%s: required checks are active on head %s (%s active, %s successful, %s missing, %s stale). Not dispatching a duplicate run.\n" \
    "${PR}" "${head_sha}" "${#active[@]}" "${#successful[@]}" "${#missing[@]}" "${#stale[@]}"
  exit 0
fi

if [ "${#missing[@]}" -eq 0 ] && [ "${#stale[@]}" -eq 0 ]; then
  printf "PR #%s: required checks are attached on head %s (%s successful). No fallback dispatch needed.\n" \
    "${PR}" "${head_sha}" "${#successful[@]}"
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

echo "PR #${PR}: dispatching required workflows for head ${head_sha} (${reason})."
gh workflow run ci.yml --repo "${REPO}" --ref "${head_ref}"

if printf '%s\n' "${missing[@]}" "${stale[@]}" | grep -qx "CodeQL"; then
  gh workflow run codeql.yml --repo "${REPO}" --ref "${head_ref}"
fi

echo "PR #${PR}: required workflow dispatch requested."
