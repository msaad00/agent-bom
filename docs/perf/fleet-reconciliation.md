# Fleet Reconciliation Evidence

Evidence status: measured
Owner issue: #1895
Parent issue: #1806
Raw result artifact: `docs/perf/results/scale-evidence-local-2026-04-26.json`

## Claim

Local synthetic Kubernetes reconciliation can process repeated 1k / 5k / 10k
observation snapshots while preserving stable identity and added / changed /
missing / stale state. This page does not claim control-plane HTTP ingest,
Postgres persistence, or EKS scheduler latency; those remain tracked in #1806.

## Scope

- `agent-bom fleet reconcile-k8s`
- repeated snapshot deduplication
- added / changed / missing / stale reconciliation output
- synthetic Kubernetes inventory observations at 1k / 5k / 10k scale

Excluded from this measured run:

- control-plane fleet snapshot push
- Postgres persistence
- graph selector/drilldown latency after fleet ingestion
- live Kubernetes API list/watch latency

## Environment

- Platform: macOS-26.4.1-arm64-arm-64bit-Mach-O
- Machine: arm64
- Processor: arm
- Python: 3.13.5
- Kubernetes version: none; synthetic observation list only
- Postgres version: none; in-process reconciliation only
- Dataset shape: synthetic observations with stable tenant, cluster,
  namespace, workload, agent, server, image, endpoint, and node metadata.
- agent-bom commit: generated from the PR branch that introduced
  `scripts/run_scale_evidence.py`

## Commands

```bash
uv run python scripts/run_scale_evidence.py
python scripts/check_scale_evidence.py
```

## Results

| Estate size | Previous | Current | Changed | Missing | Unchanged | Wall time | Observations/sec | Result artifact |
|---:|---:|---:|---:|---:|---:|---:|---:|---|
| 1k observations | 1,000 | 965 | 56 | 35 | 909 | 26.670 ms | 73,677.83 | `results/scale-evidence-local-2026-04-26.json` |
| 5k observations | 5,000 | 4,827 | 284 | 173 | 4,543 | 138.489 ms | 70,958.47 | `results/scale-evidence-local-2026-04-26.json` |
| 10k observations | 10,000 | 9,655 | 568 | 345 | 9,087 | 304.328 ms | 64,585.00 | `results/scale-evidence-local-2026-04-26.json` |

## Gaps

- Add control-plane `/v1/fleet/sync` HTTP ingest p95/p99.
- Add Postgres-backed fleet-store persistence latency.
- Add live Kubernetes API discovery latency.
- Add graph selector/drilldown latency after fleet ingestion.
