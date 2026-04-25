# Graph Ingest Throughput Evidence

Evidence status: scaffold
Owner issue: #1806

## Claim

Graph save throughput remains bounded by batch/window size rather than total
graph size, and `AGENT_BOM_GRAPH_WRITE_BATCH_SIZE` gives operators one tuning
knob across SQLite and Postgres write paths.

## Scope

- SQLite graph store writes
- Postgres graph store writes
- node, edge, search-row, attack-path, and interaction-risk persistence
- batch-size sensitivity for small, default, and large batches

## Environment

Record the exact environment before publishing measured numbers:

- Hardware:
- CPU:
- Memory:
- Storage:
- Database backend:
- agent-bom commit:

## Commands

```bash
pytest tests/benchmarks/test_graph_hot_paths.py --benchmark-only
AGENT_BOM_GRAPH_WRITE_BATCH_SIZE=100 pytest tests/benchmarks/ --benchmark-only -k graph
AGENT_BOM_GRAPH_WRITE_BATCH_SIZE=1000 pytest tests/benchmarks/ --benchmark-only -k graph
AGENT_BOM_GRAPH_WRITE_BATCH_SIZE=5000 pytest tests/benchmarks/ --benchmark-only -k graph
```

## Results

Measured results are intentionally not filled in this scaffold PR.

| Backend | Batch size | Estate size | Nodes/sec | Edges/sec | Peak RSS | Result artifact |
|---|---:|---:|---:|---:|---:|---|
| SQLite | 100 | TBD | TBD | TBD | TBD | TBD |
| SQLite | 1,000 | TBD | TBD | TBD | TBD | TBD |
| Postgres | 1,000 | TBD | TBD | TBD | TBD | TBD |
| Postgres | 5,000 | TBD | TBD | TBD | TBD | TBD |

## Gaps

- Add write-path benchmark cases for persistence, not only graph build CPU.
- Replace scaffold rows with measured values from a reproducible run.
- Attach raw benchmark JSON under `docs/perf/results/`.
