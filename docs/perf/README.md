# Performance Evidence

This directory holds release-quality performance evidence for enterprise scale
claims. Pages here are intentionally separate from broad target-SLO guidance in
[`docs/PERFORMANCE_BENCHMARKS.md`](../PERFORMANCE_BENCHMARKS.md): a page in
this directory must include the command, environment, raw-result location, and
known gaps for the specific claim it supports.

Current evidence pages:

- [`p95-p99-graph-query.md`](p95-p99-graph-query.md) — graph query latency at
  1k / 5k / 10k estate sizes.
- [`ingest-throughput.md`](ingest-throughput.md) — graph save throughput and
  batch-size behavior.
- [`fleet-reconciliation.md`](fleet-reconciliation.md) — fleet and Kubernetes
  reconciliation latency.

Current raw result artifact:

- [`results/scale-evidence-local-2026-04-26.json`](results/scale-evidence-local-2026-04-26.json)
  — local synthetic graph build/query and Kubernetes reconciliation CPU-path
  run on macOS arm64 with Python 3.13.5.

Run the structure check before publishing release numbers:

```bash
python scripts/check_scale_evidence.py
```

Regenerate the local synthetic result set:

```bash
uv run python scripts/run_scale_evidence.py
```
