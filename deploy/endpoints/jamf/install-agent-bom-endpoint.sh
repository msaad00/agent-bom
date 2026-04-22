#!/bin/sh
set -eu

BUNDLE_ROOT="/Library/Application Support/agent-bom-endpoint"
mkdir -p "$BUNDLE_ROOT"
cp "$(dirname "$0")/../install-agent-bom-endpoint.sh" "$BUNDLE_ROOT/install-agent-bom-endpoint.sh"
chmod 755 "$BUNDLE_ROOT/install-agent-bom-endpoint.sh"
"$BUNDLE_ROOT/install-agent-bom-endpoint.sh"
