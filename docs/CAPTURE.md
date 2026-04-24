# Screenshot capture protocol

Published screenshots in `docs/images/` must come from the live product
running against the bundled demo data, with the agent and scope chosen so
the resulting graph is actually informative. PR #1445 regressed
`mesh-live.png` to a near-empty graph because the captured agent
(`claude-code`) had no servers in the local data — this protocol exists so
that does not happen again.

The canonical published web UI is the packaged Next.js dashboard served by
`agent-bom serve`. Do not publish README or docs screenshots from archived
pre-Next.js views or from the Snowflake Streamlit compatibility surface.

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

   Use the packaged UI path for captures. Do not shoot screenshots from the
   Next.js dev server, or you risk the transient `Compiling...` badge showing
   up in published assets.

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
| `dashboard-live.png` | `/dashboard?capture=1` (Risk overview) | All agents · top crop showing the gauge, posture sub-scores, score breakdown, and the start of the attack-path list | The published README should not use one tall stitched dashboard asset when two shorter frames tell the story more clearly |
| `dashboard-paths-live.png` | `/dashboard?capture=1` (Risk overview) | All agents · mid-page crop showing the attack-path list, exposure KPI band, and the first backlog charts | Keeps the fix-first path list readable in GitHub while still proving the KPI / backlog context lives on the same page |
| `mesh-live.png` | `/mesh` | Filter to `cursor` | Has 2 servers, 8 packages, 10+ CVEs, and richer tool + credential traversal than the smaller `claude-desktop` slice |
| `remediation-live.png` | `/remediation` | All frameworks tab | Shows the full prioritized fix list |

### Dashboard layout (current)

The Risk overview redesign (post-#1496 operator UX drilldown) replaced
the older single-column attack-path layout. The published media now ships
as two dashboard frames rather than one stitched full-page export:

1. `dashboard-live.png`
   Header, top counters, F-grade gauge, security posture card, score breakdown, and the start of the attack-path list
2. `dashboard-paths-live.png`
   Top attack paths, exposure KPIs, severity/source charts, and the first compound-issue cards

A capture set that misses either frame is incomplete. Re-shoot from the
packaged UI and crop deliberately; do not publish another full-page stitched
dashboard asset unless the layout materially changes again.

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
