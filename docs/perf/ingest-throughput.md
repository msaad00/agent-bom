# Graph Ingest Throughput Evidence

Evidence status: measured
Owner issue: #1895
Parent issue: #1806
Raw result artifact: `docs/perf/results/scale-evidence-local-2026-04-26.json`

## Claim

Local synthetic graph build throughput stays above 20k nodes/sec at 1k, 5k,
and 10k agent-estate sizes for the in-process graph-builder hot path. This
page does not claim SQLite/Postgres persistence throughput; persistence
batch-size evidence remains tracked in #1806.

## Scope

- `build_unified_graph_from_report`
- synthetic AIBOM graph construction from serialized report JSON
- node and edge construction for agents, MCP servers, packages, tools,
  credentials, and vulnerability blast-radius rows

Excluded from this measured run:

- SQLite graph-store persistence
- Postgres graph-store persistence
- search-row, attack-path, and interaction-risk persistence
- `AGENT_BOM_GRAPH_WRITE_BATCH_SIZE` sensitivity

## Environment

- Platform: macOS-26.4.1-arm64-arm-64bit-Mach-O
- Machine: arm64
- Processor: arm
- Python: 3.13.5
- Database backend: none; in-process graph-builder CPU path only
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

| Backend | Estate size | Nodes | Edges | Build wall time | Nodes/sec | Edges/sec | RSS delta | Result artifact |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| in-process builder | 1k agents | 5,201 | 5,200 | 236.100 ms | 22,028.78 | 22,024.54 | 45.016 MiB | `results/scale-evidence-local-2026-04-26.json` |
| in-process builder | 5k agents | 26,001 | 26,000 | 193.444 ms | 134,410.88 | 134,405.71 | 44.156 MiB | `results/scale-evidence-local-2026-04-26.json` |
| in-process builder | 10k agents | 52,001 | 52,000 | 446.970 ms | 116,341.21 | 116,338.97 | 60.703 MiB | `results/scale-evidence-local-2026-04-26.json` |

## Gaps

- Add SQLite and Postgres persistence throughput measurements.
- Add batch-size sensitivity for `AGENT_BOM_GRAPH_WRITE_BATCH_SIZE`.
- Add search-row, attack-path, and interaction-risk persistence throughput.
- Add EKS/RDS hardware profile results before using these numbers for hosted
  enterprise SLOs.
