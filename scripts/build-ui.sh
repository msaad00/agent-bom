#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

echo "Building dashboard..."
cd "$ROOT_DIR/ui"
npm ci --silent
NEXT_EXPORT=1 npm run build

echo "Copying static output to package..."
# Setuptools copies incrementally; retire chunks removed by the new UI build.
rm -rf "$ROOT_DIR/build/lib/agent_bom/ui_dist"
rm -rf "$ROOT_DIR/src/agent_bom/ui_dist"
cp -r out "$ROOT_DIR/src/agent_bom/ui_dist"
uv run python "$ROOT_DIR/scripts/generate_ui_csp_hashes.py" "$ROOT_DIR/src/agent_bom/ui_dist"

echo "Dashboard bundled → src/agent_bom/ui_dist/"
