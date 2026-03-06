#!/usr/bin/env bash
# Bump agent-bom version, commit, tag, and optionally push.
#
# Usage:
#   ./scripts/bump-version.sh 0.59.0           # bump + commit + tag
#   ./scripts/bump-version.sh 0.59.0 --push    # … and push to origin
#   ./scripts/bump-version.sh 0.59.0 --dry-run # preview only
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

VERSION="${1:-}"
PUSH=false
DRY_RUN=false

shift || true
for arg in "$@"; do
    case "$arg" in
        --push) PUSH=true ;;
        --dry-run) DRY_RUN=true ;;
        *) echo "Unknown flag: $arg"; exit 1 ;;
    esac
done

if [ -z "$VERSION" ]; then
    echo "Usage: $0 <version> [--push] [--dry-run]"
    echo "  e.g. $0 0.59.0 --push"
    exit 1
fi

if ! echo "$VERSION" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'; then
    echo "ERROR: Invalid semver: $VERSION"
    exit 1
fi

echo "==> Bumping to v${VERSION}..."

if [ "$DRY_RUN" = true ]; then
    python "$ROOT/scripts/bump-version.py" "$VERSION" --dry-run
    exit 0
fi

# Run the Python bump script
python "$ROOT/scripts/bump-version.py" "$VERSION"

# Stage + commit + tag
cd "$ROOT"
git add -A
git commit -m "$(cat <<EOF
chore: bump version to ${VERSION}
EOF
)"
git tag "v${VERSION}"

echo "==> Tagged v${VERSION}"

if [ "$PUSH" = true ]; then
    echo "==> Pushing to origin..."
    git push origin HEAD "v${VERSION}"
    echo "==> Done! v${VERSION} pushed."
else
    echo ""
    echo "Next steps:"
    echo "  git push origin HEAD v${VERSION}"
fi
