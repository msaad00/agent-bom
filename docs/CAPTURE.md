# Screenshot capture protocol

Published screenshots in `docs/images/` must come from the live product
running against the bundled demo data, with the agent and scope chosen so
the resulting graph is actually informative. PR #1445 regressed
`mesh-live.png` to a near-empty graph because the captured agent
(`claude-code`) had no servers in the local data — this protocol exists so
that does not happen again.

## Canonical capture environment

1. Clean checkout on the release tag.
2. Fresh local DB with the bundled offline vuln catalog.
3. Build the bundled dashboard, then start the API against an empty SQLite
   path so only demo data is present:

   ```bash
   pip install -e ".[ui,api]"
   make build-ui
   AGENT_BOM_DB=/tmp/agent-bom-capture.db agent-bom serve
   ```

4. Generate the bundled demo report offline, then push that exact payload to
   the API so the stored job matches the terminal demo and does not pull in
   local workstation discovery:

   ```bash
   agent-bom agents --demo --offline -f json -o /tmp/agent-bom-demo-report.json
   curl -X POST -H 'content-type: application/json' \
     --data-binary @/tmp/agent-bom-demo-report.json \
     http://127.0.0.1:8422/v1/results/push
   ```

## Per-screenshot scope

| Asset | Page | Required scope | Rationale |
|---|---|---|---|
| `dashboard-live.png` | `/dashboard` (Risk overview) | All agents · scroll showing F-grade gauge, posture sub-scores, score breakdown, top attack paths | Captures the headline counters (actively exploited / credentials exposed / reachable tools / top-path risk), the security-posture grade, and the score breakdown — all in one frame |
| `mesh-live.png` | `/mesh` | Filter to `cursor` | Has 2 servers, 8 packages, 10+ CVEs, and richer tool + credential traversal than the smaller `claude-desktop` slice |
| `remediation-live.png` | `/remediation` | All frameworks tab | Shows the full prioritized fix list |

### Dashboard layout (current)

The Risk overview redesign (post-#1496 operator UX drilldown) replaced
the older single-column attack-path layout. The current frame contains:

1. **Header** — `Risk overview` title, scan count + agent count + package count + CVE count
2. **Top counters** — actively exploited · credentials exposed · reachable tools · top attack-path risk
3. **F-grade gauge** — 0-100 numeric score with letter grade
4. **Security posture card** — grade explanation + 6 sub-scores (policy + controls, open evidence × 2, packages + CVEs, reach + exposure, MCP configuration)
5. **Score breakdown** — per-driver progress bars with one-line evidence
6. **Top attack paths** — clickable rows linking to the security graph

A capture that misses any of those sections is incomplete. Re-shoot
with the page scrolled to top so the gauge + posture card both fit.

The `cursor` agent in `src/agent_bom/demo.py` is the best mesh hero shot in
the current demo inventory — it brings the filesystem and database servers,
multiple tools, reachable credentials, and the densest CVE cluster
(`pillow@9.0.0`, `cryptography@39.0.0`, `werkzeug@2.2.2`). Capturing under
an unscoped or lower-signal agent risks a flatter graph.

## Accuracy guardrail

`tests/test_demo_inventory_accuracy.py` enforces that:

- every demo package resolves to at least one real advisory in the
  bundled offline DB (or is on a small audited allowlist), and
- the demo always yields at least one HIGH or CRITICAL finding so the
  hero screenshot story stays credible.

If a future change to `src/agent_bom/demo.py` would publish a screenshot
claiming CVEs against a clean version, that test fails before the change
can land.
