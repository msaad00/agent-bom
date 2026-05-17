# Product Screenshot Audit v0.87.0

Capture date: 2026-05-15

## Source

- Built the packaged Next.js dashboard with `make build-ui`.
- Served the packaged API/dashboard on loopback with
  `AGENT_BOM_DB=/tmp/agent-bom-capture-v087.db uv run agent-bom serve --host 127.0.0.1 --port 8422`.
- Generated deterministic bundled demo evidence with
  `uv run agent-bom agents --demo --offline --no-auto-update-db --quiet -f json -o /tmp/agent-bom-demo-report-v087.json`.
- Pushed the exact JSON payload to `POST /v1/results/push` on the capture API.
- Captured the published screenshot set with Playwright against the packaged
  product routes.

## Captures

| Asset | Route | Visible version |
|---|---|---|
| `docs/images/dashboard-live.png` | `/?capture=1` | `0.86.5` |
| `docs/images/dashboard-paths-live.png` | `/?capture=1` | `0.86.5` |
| `docs/images/mesh-live.png` | `/mesh?capture=1` | `0.86.5` |
| `docs/images/security-graph-live.png` | `/security-graph?capture=1` | `0.86.5` |
| `docs/images/lineage-graph-live.png` | `/graph?capture=1&investigate=1&root=agent:cursor&q=cursor` | `0.86.5` |
| `docs/images/dependency-map-live.png` | `/insights?capture=1` | `0.86.5` |
| `docs/images/remediation-live.png` | `/remediation` | `0.86.5` |

The visible version stays `0.86.5` because this PR refreshes proof from current
`main` before the release-version bump. The release bump PR should update
`docs/images/product-screenshots.json` and recapture only if the UI-visible
version changes.

## Claim Boundaries

- The screenshots show shipped product routes backed by the bundled demo
  payload, not mockups.
- The graph shots prove the focused ExposurePath and mesh workflows in the
  packaged dashboard. They do not claim unbounded 50k-node browser operations.
- Neptune remains an optional enterprise graph-backend lane; these screenshots
  use the default packaged local/API path.
