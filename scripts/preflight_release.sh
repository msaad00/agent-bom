#!/usr/bin/env bash
# Release pre-flight: run BEFORE pushing a release tag. Catches the failure
# classes that abort a tagged release run at startup (no logs) plus version
# drift. Exits non-zero on the first failure so a bad state never reaches a tag.
#
#   scripts/preflight_release.sh [VERSION]
#
# If VERSION is given, asserts every managed file is already bumped to it.
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${1:-}"
fail=0
step() { printf '\n=== %s ===\n' "$1"; }

step "actionlint (workflow syntax + needs/context typing)"
if command -v actionlint >/dev/null 2>&1; then
  actionlint .github/workflows/release.yml .github/workflows/docs.yml \
    .github/workflows/deploy-mcp-sse.yml || fail=1
else
  echo "WARNING: actionlint not installed — install it (brew install actionlint) for full coverage"
fi

step "release workflow call-graph lint (reusable-workflow permission parity + needs)"
python scripts/lint_release_workflow.py .github/workflows/release.yml || fail=1

step "version bump consistency"
if [ -n "$VERSION" ]; then
  python scripts/bump-version.py "$VERSION" --check || fail=1
fi
python scripts/check_release_consistency.py || fail=1
python scripts/check_product_surface_contract.py || fail=1
python scripts/export_openapi.py --check || fail=1

if [ "$fail" -ne 0 ]; then
  printf '\nPRE-FLIGHT FAILED — do NOT push a release tag.\n' >&2
  exit 1
fi
printf '\nPre-flight OK — safe to tag.\n'
