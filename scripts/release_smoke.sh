#!/usr/bin/env bash
# release_smoke.sh — golden-path smoke for a release candidate.
#
# Proves install → curated demo scan → structured exports → optional API health.
# Run before tagging. Non-destructive; uses offline demo advisories only.
#
# Usage:
#   ./scripts/release_smoke.sh
#   AGENT_BOM_RELEASE_SMOKE_API_URL=http://127.0.0.1:8422 \
#     AGENT_BOM_API_KEY=... ./scripts/release_smoke.sh
#
# Exits non-zero on the first failed check.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

API_URL="${AGENT_BOM_RELEASE_SMOKE_API_URL:-}"
API_KEY="${AGENT_BOM_API_KEY:-}"
SKIP_UI="${AGENT_BOM_RELEASE_SMOKE_SKIP_UI:-0}"

bold() { printf "\033[1m%s\033[0m\n" "$*"; }
ok()   { printf "  \033[32m✓\033[0m %s\n" "$*"; }
fail() { printf "  \033[31m✗\033[0m %s\n" "$*" >&2; exit 1; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

bold "1/5 CLI install surface"
if command -v uv >/dev/null 2>&1; then
  AGENT_BOM_BIN=(uv run agent-bom)
else
  AGENT_BOM_BIN=(agent-bom)
fi
version="$("${AGENT_BOM_BIN[@]}" --version 2>/dev/null | head -n1 || true)"
[ -n "$version" ] || fail "agent-bom --version failed"
ok "CLI reachable ($version)"

bold "2/5 Curated demo scan (offline JSON)"
json_out="$tmp/demo-report.json"
set +e
"${AGENT_BOM_BIN[@]}" agents --demo --offline --quiet --no-auto-update-db -f json -o "$json_out"
scan_rc=$?
set -e
if [ "$scan_rc" -ne 0 ] && [ "$scan_rc" -ne 1 ]; then
  fail "demo offline scan failed"
fi
[ -s "$json_out" ] || fail "demo JSON report is empty"
agents="$(python3 - "$json_out" <<'PY'
import json, sys
report = json.load(open(sys.argv[1]))
print(len(report.get("agents") or []))
PY
)"
vulns="$(python3 - "$json_out" <<'PY'
import json, sys
report = json.load(open(sys.argv[1]))
findings = report.get("findings") or report.get("vulnerabilities") or []
print(len(findings))
PY
)"
if [ "$scan_rc" -eq 1 ]; then
  python3 - "$json_out" <<'PY' || fail "demo scan exited 1 without a malicious finding"
import json, sys

report = json.load(open(sys.argv[1]))
findings = report.get("findings") or []
if not any(row.get("is_malicious") for row in findings):
    raise SystemExit(1)
PY
fi
[ "$agents" -gt 0 ] || fail "demo scan returned zero agents"
[ "$vulns" -gt 0 ] || fail "demo scan returned zero findings"
ok "demo scan produced ${agents} agent(s) and ${vulns} finding(s)"

bold "3/5 CSV export"
csv_out="$tmp/demo-report.csv"
set +e
"${AGENT_BOM_BIN[@]}" agents --demo --offline --quiet --no-auto-update-db -f csv -o "$csv_out"
csv_rc=$?
set -e
if [ "$csv_rc" -ne 0 ] && [ "$csv_rc" -ne 1 ]; then
  fail "demo CSV export failed"
fi
[ -s "$csv_out" ] || fail "demo CSV export is empty"
head_row="$(head -n1 "$csv_out")"
[[ "$head_row" == *"id"* || "$head_row" == *"cve"* || "$head_row" == *"severity"* ]] \
  || fail "CSV header does not look like findings export"
ok "CSV export written"

bold "4/5 Compliance tag parity (when present)"
python3 - "$json_out" <<'PY' || fail "compliance tag smoke failed"
import json, sys

report = json.load(open(sys.argv[1]))
rows = report.get("findings") or report.get("blast_radius") or []
tagged = 0
for row in rows:
    tags = row.get("framework_tags") or row.get("compliance_tags") or []
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",") if t.strip()]
    if tags:
        tagged += 1
if not rows:
    raise SystemExit("no finding rows to inspect")
if tagged == 0:
    print("warn: no framework_tags on demo findings — skipping strict check")
else:
    print(f"ok: {tagged}/{len(rows)} rows carry framework tags")
PY
ok "compliance tag check complete"

if [ -n "$API_URL" ]; then
  bold "5/5 Optional API health"
  API_URL="${API_URL%/}"
  status="$(curl -sS -o "$tmp/health.json" -w "%{http_code}" "${API_URL}/healthz" || true)"
  [ "$status" = "200" ] || fail "healthz returned ${status}"
  ok "API healthz OK at ${API_URL}"
  if [ -n "$API_KEY" ]; then
  status="$(curl -sS -o "$tmp/auth.json" -w "%{http_code}" \
    -H "Authorization: Bearer ${API_KEY}" \
    -H "X-Agent-Bom-Role: admin" \
    "${API_URL}/v1/auth/debug" || true)"
    [ "$status" = "200" ] || fail "auth debug returned ${status}"
    ok "API auth debug OK"
  fi
else
  bold "5/5 Optional API health"
  ok "skipped (set AGENT_BOM_RELEASE_SMOKE_API_URL to enable)"
fi

if [ "$SKIP_UI" != "1" ] && [ -d "$ROOT/ui" ]; then
  bold "UI build (release smoke tail)"
  if command -v npm >/dev/null 2>&1; then
    (cd "$ROOT/ui" && npm run typecheck >/dev/null && npm run build >/dev/null) \
      || fail "UI typecheck/build failed"
    ok "UI typecheck + build passed"
  else
    ok "skipped (npm not installed)"
  fi
fi

if [ "${AGENT_BOM_RELEASE_SMOKE_FINDINGS_BENCH:-0}" = "1" ]; then
  bold "Findings read bench (hub limit=1)"
  if command -v uv >/dev/null 2>&1; then
    bench_db="$tmp/findings-bench.db"
    uv run python scripts/bench_findings_read.py \
      --mode api \
      --sqlite-db "$bench_db" \
      --count 10000 \
      --limit 1 \
      --p50-threshold-ms 500 \
      || fail "findings read bench failed"
    ok "findings read bench passed (10k rows, limit=1)"
  else
    fail "uv required for findings read bench"
  fi
fi

bold "release smoke passed"
echo "  version: ${version}"
echo "  findings: ${vulns}"
echo "  agents: ${agents}"
