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
3. API and dashboard started against an empty SQLite path so only demo
   data is present:

   ```bash
   pip install -e ".[ui,api]"
   AGENT_BOM_DB=/tmp/agent-bom-capture.db agent-bom serve
   ```

4. Push the bundled demo inventory through the CLI so the API persists
   the agents, servers, packages, and findings the screenshots need:

   ```bash
   agent-bom agents --demo --offline \
     --push-url http://127.0.0.1:8422/v1/fleet/sync
   ```

## Per-screenshot scope

| Asset | Page | Required scope | Rationale |
|---|---|---|---|
| `dashboard-live.png` | `/dashboard` | All agents | Shows risk overview + top attack paths |
| `mesh-live.png` | `/mesh` | Filter to `claude-desktop` | Has 2 servers, 4 packages, 5+ CVEs — produces a rich graph |
| `remediation-live.png` | `/remediation` | All frameworks tab | Shows the full prioritized fix list |

The `claude-desktop` agent in `src/agent_bom/demo.py` is the one wired
for the mesh hero shot — it pulls in `axios@1.4.0` (7 CVEs) and
`certifi@2022.12.7` (2 CVEs), enough traversal to populate every column.
Capturing under any other agent risks the empty-graph regression.

## Accuracy guardrail

`tests/test_demo_inventory_accuracy.py` enforces that:

- every demo package resolves to at least one real advisory in the
  bundled offline DB (or is on a small audited allowlist), and
- the demo always yields at least one HIGH or CRITICAL finding so the
  hero screenshot story stays credible.

If a future change to `src/agent_bom/demo.py` would publish a screenshot
claiming CVEs against a clean version, that test fails before the change
can land.
