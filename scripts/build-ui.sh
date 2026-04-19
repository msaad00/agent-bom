#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

echo "Building dashboard..."
cd "$ROOT_DIR/ui"
npm ci --silent
NEXT_EXPORT=1 npm run build

echo "Copying static output to package..."
rm -rf "$ROOT_DIR/src/agent_bom/ui_dist"
cp -r out "$ROOT_DIR/src/agent_bom/ui_dist"

echo "Dashboard bundled → src/agent_bom/ui_dist/"
