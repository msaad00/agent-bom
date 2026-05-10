# Product Screenshot Audit v0.86.3

Date: 2026-05-09

## Capture Path

- Generated bundled demo data with `uv run agent-bom agents --demo --offline -f json`.
- Ran the local API with `AGENT_BOM_DB=/tmp/agent-bom-capture.db uv run agent-bom serve --host 127.0.0.1 --port 8422`.
- Pushed the demo payload through `POST /v1/results/push`.
- Captured the current Next.js dashboard against that API for the README and docs product images.

## Refreshed Images

| Image | Page | Visible version |
|---|---|---|
| `docs/images/dashboard-live.png` | `/?capture=1` | `0.86.3` |
| `docs/images/dashboard-paths-live.png` | `/?capture=1` | `0.86.3` |
| `docs/images/remediation-live.png` | `/remediation` | `0.86.3` |
| `docs/images/mesh-live.png` | `/mesh` | `0.86.3` |
| `docs/images/mesh-dark-live.png` | `/mesh` | `0.86.3` |
| `docs/images/mesh-light-live.png` | `/mesh` | `0.86.3` |

The mesh refresh preserves `mesh-live.png` as the full graph-backed product
surface and adds dark/light captures from the same real `/mesh` route. The
packaged dashboard route was also validated so `/mesh` serves the real mesh
page rather than the root SPA fallback.

## Guardrail

`scripts/check_release_consistency.py` now validates `docs/images/product-screenshots.json` so the screenshot manifest release version and visible image versions stay aligned with `pyproject.toml`.
