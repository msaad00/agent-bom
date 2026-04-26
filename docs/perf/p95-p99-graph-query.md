# Graph Query p95/p99 Evidence

Evidence status: measured
Owner issue: #1895
Parent issue: #1806
Raw result artifact: `docs/perf/results/scale-evidence-local-2026-04-26.json`

## Claim

Local synthetic graph search, selector, and bounded-neighborhood CPU paths stay
sub-millisecond at 1k / 5k / 10k agent-estate sizes when callers use bounded
selectors and bounded graph traversal. This page does not claim HTTP API,
Postgres, diff, or attack-path drilldown latency; those remain tracked in
#1806.

## Scope

- `GET /v1/graph/search`
- agent selector/filter path
- bounded neighborhood traversal via `UnifiedGraph.traverse_subgraph`
- synthetic graph sizes: 1k, 5k, and 10k agents

Excluded from this measured run:

- HTTP/API overhead
- Postgres graph-store persistence and SQL query plans
- graph diff API
- materialized attack-path drilldowns
- browser layout and interaction timings

## Environment

- Platform: macOS-26.4.1-arm64-arm-64bit-Mach-O
- Machine: arm64
- Processor: arm
- Python: 3.13.5
- Dataset shape: synthetic AIBOM report with 1 MCP server, 2 packages, and 1
  tool per agent; every tenth agent includes one credential and one
  vulnerability blast-radius row.
- agent-bom commit: generated from the PR branch that introduced
  `scripts/run_scale_evidence.py`

## Commands

```bash
uv run python scripts/run_scale_evidence.py
python scripts/check_scale_evidence.py
```

## Results

| Estate size | Nodes | Edges | Operation | p50 | p95 | p99 | Runs | Result artifact |
|---:|---:|---:|---|---:|---:|---:|---:|---|
| 1k agents | 5,201 | 5,200 | search | 0.087 ms | 0.096 ms | 0.102 ms | 30 | `results/scale-evidence-local-2026-04-26.json` |
| 1k agents | 5,201 | 5,200 | agent selector | 0.079 ms | 0.100 ms | 0.118 ms | 30 | `results/scale-evidence-local-2026-04-26.json` |
| 1k agents | 5,201 | 5,200 | bounded neighborhood | 0.001 ms | 0.004 ms | 0.011 ms | 30 | `results/scale-evidence-local-2026-04-26.json` |
| 5k agents | 26,001 | 26,000 | search | 0.087 ms | 0.094 ms | 0.108 ms | 30 | `results/scale-evidence-local-2026-04-26.json` |
| 5k agents | 26,001 | 26,000 | agent selector | 0.378 ms | 0.459 ms | 0.482 ms | 30 | `results/scale-evidence-local-2026-04-26.json` |
| 5k agents | 26,001 | 26,000 | bounded neighborhood | 0.001 ms | 0.003 ms | 0.012 ms | 30 | `results/scale-evidence-local-2026-04-26.json` |
| 10k agents | 52,001 | 52,000 | search | 0.086 ms | 0.096 ms | 0.109 ms | 30 | `results/scale-evidence-local-2026-04-26.json` |
| 10k agents | 52,001 | 52,000 | agent selector | 0.765 ms | 0.896 ms | 0.943 ms | 30 | `results/scale-evidence-local-2026-04-26.json` |
| 10k agents | 52,001 | 52,000 | bounded neighborhood | 0.001 ms | 0.003 ms | 0.012 ms | 30 | `results/scale-evidence-local-2026-04-26.json` |

## EXPLAIN ANALYZE

Not covered by this local synthetic run. Add representative Postgres query
plans under #1806 when the API/Postgres benchmark lane is measured:

- graph node search
- node detail
- attack-path drilldown
- graph diff

## Gaps

- Add API/k6 p95/p99 with auth, tenant, and network overhead.
- Add Postgres graph-store p95/p99 and `EXPLAIN ANALYZE` plans.
- Add graph diff and materialized attack-path drilldown measurements.
- Add browser/UI interaction and layout timing for large estates.
