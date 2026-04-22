#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/build-pkg.sh --bundle-dir <dir> --output <path> [--identifier id] [--version v] [--signing-identity name] [--dry-run]

Packages a generated `agent-bom proxy-bootstrap` bundle into a macOS installer payload.
EOF
}

BUNDLE_DIR=""
OUTPUT_PATH=""
IDENTIFIER="io.agentbom.endpoint"
VERSION="0.0.0"
SIGNING_IDENTITY=""
DRY_RUN=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bundle-dir) BUNDLE_DIR="$2"; shift 2 ;;
    --output) OUTPUT_PATH="$2"; shift 2 ;;
    --identifier) IDENTIFIER="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    --signing-identity) SIGNING_IDENTITY="$2"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown arg: $1" >&2; usage; exit 1 ;;
  esac
done

[[ -n "$BUNDLE_DIR" ]] || { echo "--bundle-dir is required" >&2; exit 1; }
[[ -n "$OUTPUT_PATH" ]] || { echo "--output is required" >&2; exit 1; }

PKGROOT="${TMPDIR:-/tmp}/agent-bom-pkgroot"
SCRIPTS_DIR="${TMPDIR:-/tmp}/agent-bom-pkg-scripts"
rm -rf "$PKGROOT" "$SCRIPTS_DIR"
mkdir -p "$PKGROOT/usr/local/share/agent-bom-endpoint" "$SCRIPTS_DIR"
cp -R "$BUNDLE_DIR"/. "$PKGROOT/usr/local/share/agent-bom-endpoint/"

cat >"$SCRIPTS_DIR/postinstall" <<'EOF'
#!/bin/sh
set -eu
if [ -x /usr/local/share/agent-bom-endpoint/install-agent-bom-endpoint.sh ]; then
  /usr/local/share/agent-bom-endpoint/install-agent-bom-endpoint.sh || true
fi
EOF
chmod 755 "$SCRIPTS_DIR/postinstall"

PKGBUILD_CMD=(
  pkgbuild
  --root "$PKGROOT"
  --identifier "$IDENTIFIER"
  --version "$VERSION"
  --scripts "$SCRIPTS_DIR"
  "${OUTPUT_PATH%.pkg}.unsigned.pkg"
)
PRODUCTBUILD_CMD=(productbuild --package "${OUTPUT_PATH%.pkg}.unsigned.pkg" "$OUTPUT_PATH")
if [[ -n "$SIGNING_IDENTITY" ]]; then
  PRODUCTBUILD_CMD=(productbuild --sign "$SIGNING_IDENTITY" --package "${OUTPUT_PATH%.pkg}.unsigned.pkg" "$OUTPUT_PATH")
fi

printf '+ %q ' "${PKGBUILD_CMD[@]}"; printf '\n'
printf '+ %q ' "${PRODUCTBUILD_CMD[@]}"; printf '\n'

if [[ "$DRY_RUN" -eq 1 ]]; then
  exit 0
fi

"${PKGBUILD_CMD[@]}"
"${PRODUCTBUILD_CMD[@]}"
