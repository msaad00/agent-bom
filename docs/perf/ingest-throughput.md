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

## Postgres persistence — evidence status

Persistence throughput is **not measured** by the script above. The numbers in
the table cover only the in-process graph-builder CPU path
(`build_unified_graph_from_report`). They are the wrong baseline for sizing a
shared Postgres-backed control plane: real estates pay disk write latency,
network round-trip, and `ON CONFLICT` index maintenance per row.

Operators sizing Postgres for the listed estates should plan against the
graph-edge cardinalities below, not against the in-process build wall-time:

| Estate size | Nodes | Edges | Graph rows (nodes + edges) | Floor estimate (Postgres-only graph storage) |
|---|---:|---:|---:|---|
| 1k agents  |  5,201 |  5,200 |  10,401 | ~24 MiB at 2.4 KiB avg row + B-tree overhead |
| 5k agents  | 26,001 | 26,000 |  52,001 | ~120 MiB |
| 10k agents | 52,001 | 52,000 | 104,001 | ~240 MiB |

The floor estimates assume the current `graph_nodes` and `graph_edges`
schemas in `src/agent_bom/api/postgres_store.py` and exclude search-row,
attack-path, and interaction-risk tables. Multiply by retention factor and
add the audit log (`audit_events` is HMAC-chained, append-only) when sizing
total disk. Production sizing tables for the listed estates live in
[`docs/ENTERPRISE_DEPLOYMENT.md`](../ENTERPRISE_DEPLOYMENT.md).

A separate Postgres-backed scale evidence run is tracked in #1806; until it
publishes, treat the in-process numbers as a CPU-path floor and the row
counts above as the persistence-side estimate input.

## Gaps

- Publish Postgres persistence throughput against the row counts above.
- Add batch-size sensitivity for `AGENT_BOM_GRAPH_WRITE_BATCH_SIZE`.
- Add search-row, attack-path, and interaction-risk persistence throughput.
- Add EKS/RDS hardware profile results before using these numbers for hosted
  enterprise SLOs.
