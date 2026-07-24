# Performance Evidence

This directory holds release-quality performance evidence for enterprise scale
claims. Pages here are intentionally separate from broad target-SLO guidance in
[`docs/PERFORMANCE_BENCHMARKS.md`](../PERFORMANCE_BENCHMARKS.md): a page in
this directory must include the command, environment, raw-result location, and
known gaps for the specific claim it supports.

Current evidence pages:

- [`p95-p99-graph-query.md`](p95-p99-graph-query.md) — graph query latency at
  1k / 5k / 10k estate sizes.
- [`graph-api-postgres-benchmark.md`](graph-api-postgres-benchmark.md) — dry-run
  scaffold for graph API benchmarks, skewed synthetic estates, and Postgres
  EXPLAIN artifacts tracked by #2145.
- [`ingest-throughput.md`](ingest-throughput.md) — graph save throughput and
  batch-size behavior.
- [`fleet-reconciliation.md`](fleet-reconciliation.md) — fleet and Kubernetes
  reconciliation latency.

- [`gateway-relay-latency.md`](gateway-relay-latency.md) — HTTP gateway JSON-RPC
  relay p50/p95/p99 + RSS under concurrency (Go-gate evidence for ADR-009).

Current raw result artifact:

- [`results/scale-evidence-local-2026-04-26.json`](results/scale-evidence-local-2026-04-26.json)
  — local synthetic graph build/query and Kubernetes reconciliation CPU-path
  run on macOS arm64 with Python 3.13.5.
- [`results/graph-benchmark-estate-sample.json`](results/graph-benchmark-estate-sample.json)
  — deterministic skewed-estate shape summary for graph API/Postgres benchmark
  inputs.
- [`results/graph-benchmark-estate-sample-report.json`](results/graph-benchmark-estate-sample-report.json)
  — small scanner-style synthetic estate used to prove the generator output
  shape.
- [`results/graph-api-benchmark-sample.json`](results/graph-api-benchmark-sample.json)
  — dry-run API request-plan artifact; it contains no measured latency.
- [`results/postgres-graph-explain-sample.json`](results/postgres-graph-explain-sample.json)
  — dry-run Postgres EXPLAIN artifact index; it contains no measured query
  plans.

- [`results/gateway-relay-baseline-2026-07-23.json`](results/gateway-relay-baseline-2026-07-23.json)
  — local gateway relay baseline (mock MCP upstream, concurrency ladder to 500).
- [`results/gateway-relay-tuned-2026-07-23.json`](results/gateway-relay-tuned-2026-07-23.json)
  — same fixture after uvloop + larger client httpx limits.
- [`results/gateway-relay-go-gate-2026-07-23.json`](results/gateway-relay-go-gate-2026-07-23.json)
  — Go-gate decision artifact (`gate_tripped`, next step).

Run the structure check before publishing release numbers:

```bash
python scripts/check_scale_evidence.py
```

Regenerate the local synthetic result set:

```bash
uv run python scripts/run_scale_evidence.py
```

Regenerate the graph API/Postgres scaffold artifacts:

```bash
uv run python scripts/generate_graph_benchmark_estate.py
uv run python scripts/run_graph_api_benchmark.py --dry-run
uv run python scripts/run_graph_postgres_explain.py --dry-run
```

Regenerate the gateway relay baseline / tuned measurements:

```bash
uv run python scripts/run_gateway_relay_benchmark.py --mode baseline --output docs/perf/results/gateway-relay-baseline-2026-07-23.json
uv run python scripts/run_gateway_relay_benchmark.py --mode tuned --output docs/perf/results/gateway-relay-tuned-2026-07-23.json
```
