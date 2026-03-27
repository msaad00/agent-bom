#!/usr/bin/env bash

set -euo pipefail

DEMO_ENGINE="${AGENT_BOM_DEMO_ENGINE:-python}"
IMAGE_TAG="${AGENT_BOM_DEMO_IMAGE:-agent-bom:demo-current}"
DB_SOURCE="${AGENT_BOM_DEMO_DB_SOURCE:?Set AGENT_BOM_DEMO_DB_SOURCE to a local agent-bom DB copy}"
DEMO_TEMP_ROOT="${AGENT_BOM_DEMO_TEMP_ROOT:-$(python -c 'import tempfile; print(tempfile.gettempdir())')}"
DEMO_DIR="${AGENT_BOM_DEMO_DIR:-$DEMO_TEMP_ROOT/agent-bom-demo-cache}"
DEMO_BIN_DIR="${AGENT_BOM_DEMO_BIN_DIR:-.demo-bin}"
CONTAINER_DB_PATH="${AGENT_BOM_DEMO_CONTAINER_DB:-/workspace/vulns.db}"
REPO_ROOT="${AGENT_BOM_DEMO_REPO_ROOT:-$PWD}"
DEMO_DB_PATH="$DEMO_DIR/vulns.db"
DEMO_SCAN_CACHE_PATH="$DEMO_DIR/scan_cache.db"

mkdir -p "$DEMO_DIR" "$DEMO_BIN_DIR"
cp "$DB_SOURCE" "$DEMO_DB_PATH"

if [[ "$DEMO_ENGINE" == "docker" ]]; then
  cat > "$DEMO_BIN_DIR/agent-bom" <<EOF
#!/usr/bin/env bash
set -euo pipefail
docker run --rm \
  -e AGENT_BOM_DB_PATH="$CONTAINER_DB_PATH" \
  -e AGENT_BOM_SCAN_CACHE="/workspace/scan_cache.db" \
  -e AGENT_BOM_LOG_LEVEL=error \
  -v "$DEMO_DB_PATH:$CONTAINER_DB_PATH:ro" \
  -v "$DEMO_SCAN_CACHE_PATH:/workspace/scan_cache.db" \
  "$IMAGE_TAG" \
  "\$@"
EOF
else
  cat > "$DEMO_BIN_DIR/agent-bom" <<EOF
#!/usr/bin/env bash
set -euo pipefail
export AGENT_BOM_DB_PATH="$DEMO_DB_PATH"
export AGENT_BOM_SCAN_CACHE="$DEMO_SCAN_CACHE_PATH"
export AGENT_BOM_LOG_LEVEL=error
export PYTHONPATH="$REPO_ROOT/src\${PYTHONPATH:+:\$PYTHONPATH}"
exec python -c 'from agent_bom.cli import main; main()' "\$@"
EOF
fi

chmod +x "$DEMO_BIN_DIR/agent-bom"
export PATH="$PWD/$DEMO_BIN_DIR:$PATH"
