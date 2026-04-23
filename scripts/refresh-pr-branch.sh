#!/usr/bin/env bash
set -euo pipefail

if ! command -v git >/dev/null 2>&1; then
  echo "git is required" >&2
  exit 1
fi

BRANCH="${1:-$(git branch --show-current)}"
BASE_REF="${2:-origin/main}"

if [[ -z "${BRANCH}" ]]; then
  echo "usage: scripts/refresh-pr-branch.sh <branch> [base-ref]" >&2
  exit 1
fi

if [[ -n "$(git status --porcelain)" ]]; then
  echo "working tree is not clean; commit or stash changes first" >&2
  exit 1
fi

CURRENT_BRANCH="$(git branch --show-current)"

cleanup() {
  if [[ -n "${CURRENT_BRANCH}" && "$(git branch --show-current)" != "${CURRENT_BRANCH}" ]]; then
    git checkout "${CURRENT_BRANCH}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

echo "Fetching latest refs..."
git fetch origin

echo "Checking out ${BRANCH}..."
git checkout "${BRANCH}"

echo "Rebasing ${BRANCH} onto ${BASE_REF}..."
git rebase "${BASE_REF}"

echo "Pushing refreshed head with force-with-lease..."
git push --force-with-lease origin "${BRANCH}"

echo
echo "Safe refresh complete."
echo "- branch: ${BRANCH}"
echo "- base: ${BASE_REF}"
echo "- new head: $(git rev-parse HEAD)"
echo
echo "Do not click GitHub 'Update branch' after this push."
