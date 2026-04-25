# Fleet Reconciliation Evidence

Evidence status: scaffold
Owner issue: #1806

## Claim

Fleet and Kubernetes reconciliation can process repeated snapshots at 1k / 5k /
10k host or workload scale while preserving stable identity, added/changed/
missing/stale state, and control-plane ingest SLOs.

## Scope

- `agent-bom fleet reconcile-k8s`
- control-plane fleet snapshot push
- repeated snapshot deduplication
- added / changed / missing / stale reconciliation output
- graph selector/drilldown latency after fleet ingestion

## Environment

Record the exact environment before publishing measured numbers:

- Hardware:
- CPU:
- Memory:
- Kubernetes version:
- Postgres version:
- Dataset shape:
- agent-bom commit:

## Commands

```bash
agent-bom fleet reconcile-k8s --snapshot current.json --previous previous.json --format json
curl -X POST "$AGENT_BOM_BASE_URL/v1/fleet/sync" \
  -H "Authorization: Bearer $AGENT_BOM_API_TOKEN" \
  -H "Content-Type: application/json" \
  --data @current.json
```

## Results

Measured results are intentionally not filled in this scaffold PR.

| Estate size | Snapshot shape | Reconcile wall time | Push p95 | Push p99 | Dedup latency | Result artifact |
|---:|---|---:|---:|---:|---:|---|
| 1k hosts | TBD | TBD | TBD | TBD | TBD | TBD |
| 5k hosts | TBD | TBD | TBD | TBD | TBD | TBD |
| 10k hosts | TBD | TBD | TBD | TBD | TBD | TBD |

## Gaps

- Add or document fixture generation for 1k / 5k / 10k snapshots.
- Replace scaffold rows with measured values from a reproducible run.
- Attach raw benchmark JSON under `docs/perf/results/`.
