#!/usr/bin/env bash
# Bundle a pre-synced agent-bom vulnerability database for air-gapped import.
#
# First command (connected bastion):
#   agent-bom db update
# Next artifact:
#   scripts/release/bundle-vuln-db.sh dist/airgap
# Next step on the disconnected host:
#   verify sha256sums.txt, copy the bundle to the runtime path, set
#   AGENT_BOM_DB_PATH and AGENT_BOM_VULN_DB_OFFLINE=1 — see
#   docs/ENTERPRISE_DEPLOYMENT.md and docs/RELEASE_VERIFICATION.md.
set -euo pipefail

SOURCE="${AGENT_BOM_DB_SOURCE:-${HOME}/.agent-bom/db/vulns.db}"
OUTPUT_DIR="${1:-dist/airgap}"

KEV_URL="${AGENT_BOM_KEV_FEED_URL:-https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json}"
EPSS_URL="${AGENT_BOM_EPSS_FEED_URL:-https://epss.empiricalsecurity.com/epss_scores-current.csv.gz}"

KEV_FILE="known_exploited_vulnerabilities.json"
EPSS_FILE="epss_scores-current.csv.gz"

if [[ ! -f "$SOURCE" ]]; then
  echo "error: vulnerability DB not found at ${SOURCE}" >&2
  echo "Run 'agent-bom db update' on a connected host first." >&2
  exit 1
fi

mkdir -p "$OUTPUT_DIR"
DEST="$OUTPUT_DIR/vulns.db"
cp "$SOURCE" "$DEST"

echo "Downloading CISA KEV catalog …"
curl -fsSL "$KEV_URL" -o "$OUTPUT_DIR/$KEV_FILE"

echo "Downloading FIRST EPSS bulk export …"
curl -fsSL "$EPSS_URL" -o "$OUTPUT_DIR/$EPSS_FILE"

if command -v agent-bom >/dev/null 2>&1; then
  agent-bom db status --path "$DEST"
elif command -v uv >/dev/null 2>&1 && [[ -f pyproject.toml ]]; then
  uv run agent-bom db status --path "$DEST"
else
  echo "Bundled ${DEST} ($(wc -c <"$DEST" | tr -d ' ') bytes)"
fi

(
  cd "$OUTPUT_DIR"
  sha256sum vulns.db "$KEV_FILE" "$EPSS_FILE" > sha256sums.txt
  sha256sum vulns.db > sha256sums-vulns.db.txt
)
echo "Wrote ${DEST}, ${OUTPUT_DIR}/${KEV_FILE}, ${OUTPUT_DIR}/${EPSS_FILE}, and ${OUTPUT_DIR}/sha256sums.txt"
