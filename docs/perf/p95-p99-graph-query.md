# Graph Query p95/p99 Evidence

Evidence status: scaffold
Owner issue: #1806

## Claim

Graph search, selector, neighborhood, diff, and attack-path drilldown APIs stay
within the published operator SLOs for 1k / 5k / 10k agent estates when the UI
uses windowed selectors and bounded graph queries.

## Scope

- `GET /v1/graph`
- `GET /v1/graph/search`
- `GET /v1/graph/{node_id}`
- `GET /v1/graph/diff`
- materialized attack-path drilldowns

## Environment

Record the exact environment before publishing measured numbers:

- Hardware:
- CPU:
- Memory:
- Postgres version:
- Dataset shape:
- agent-bom commit:

## Commands

```bash
export AGENT_BOM_BASE_URL=https://agent-bom.internal.example.com
export AGENT_BOM_API_TOKEN=replace-me
export AGENT_BOM_GRAPH_SCAN_ID=replace-me

k6 run deploy/loadtest/k6-graph-api.js
```

## Results

Measured results are intentionally not filled in this scaffold PR.

| Estate size | Endpoint group | p95 | p99 | Target | Result artifact |
|---:|---|---:|---:|---:|---|
| 1k agents | graph search/selectors | TBD | TBD | TBD | TBD |
| 5k agents | graph search/selectors | TBD | TBD | TBD | TBD |
| 10k agents | graph search/selectors | TBD | TBD | TBD | TBD |

## EXPLAIN ANALYZE

Attach representative query plans for the hot Postgres graph paths:

- graph node search:
- node detail:
- attack-path drilldown:
- graph diff:

## Gaps

- Replace scaffold rows with measured values from a reproducible run.
- Attach raw k6 output or benchmark JSON under `docs/perf/results/`.
- Confirm whether the run includes local endpoint, Kubernetes, cloud/SaaS,
  MCP registry, package, vulnerability, model/dataset, and exposure-path
  objects.
