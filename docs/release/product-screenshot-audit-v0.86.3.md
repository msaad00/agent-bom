# Product Screenshot Audit v0.86.3

Date: 2026-05-11

## Capture Path

- Generated bundled demo data with `uv run agent-bom agents --demo --offline --no-auto-update-db -f json -o /tmp/agent-bom-demo-report.json`.
- Ran the local packaged API/dashboard on loopback with `AGENT_BOM_DB=/tmp/agent-bom-capture.db` and a capture-only local rate-limit override.
- Pushed the demo payload through `POST /v1/results/push`.
- Captured the current Next.js dashboard against that API for the README and docs product images.

## Refreshed Images

| Image | Page | Visible version |
|---|---|---|
| `docs/images/dashboard-live.png` | `/?capture=1` | `0.86.3` |
| `docs/images/dashboard-paths-live.png` | `/?capture=1` | `0.86.3` |
| `docs/images/remediation-live.png` | `/remediation` | `0.86.3` |
| `docs/images/mesh-live.png` | `/mesh?capture=1` | `0.86.3` |
| `docs/images/mesh-dark-live.png` | `/mesh?capture=1` | `0.86.3` |
| `docs/images/mesh-light-live.png` | `/mesh?capture=1` | `0.86.3` |
| `docs/images/security-graph-live.png` | `/security-graph?capture=1` | `0.86.3` |
| `docs/images/lineage-graph-live.png` | `/graph?capture=1&investigate=1&root=agent:analyst-agent&q=analyst-agent` | `0.86.3` |
| `docs/images/dependency-map-live.png` | `/insights?capture=1` | `0.86.3` |

The graph refresh keeps every published graph asset tied to a shipped product
route. Mesh remains a graph-backed dark/light product surface. Security Graph
shows the fix-first attack-path queue and evidence export controls. Lineage
uses the root-centered investigation workflow so the public image stays
bounded, readable, and data backed instead of publishing the raw expanded
topology. Insights shows the dependency risk map from the same pushed demo
scan.

For public evidence, the bundled demo payload is label-sanitized before the
push so screenshots use generic agent names while preserving the generated
inventory, findings, relationships, and graph traversal behavior.

## Guardrail

`scripts/check_release_consistency.py` now validates `docs/images/product-screenshots.json` so the screenshot manifest release version and visible image versions stay aligned with `pyproject.toml`.
