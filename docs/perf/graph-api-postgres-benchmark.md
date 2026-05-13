# Graph API and Postgres Benchmark Scaffold

Evidence status: scaffolded, not measured
Owner issue: #2145
Raw result artifacts:

- `docs/perf/results/graph-benchmark-estate-sample.json`
- `docs/perf/results/graph-benchmark-estate-sample-report.json`
- `docs/perf/results/graph-api-benchmark-sample.json`
- `docs/perf/results/postgres-graph-explain-sample.json`
- `docs/perf/results/postgres-graph-explain-sample/*.sql`

## Claim

This page documents benchmark commands and checked-in scaffold artifacts for
graph API and Postgres evidence. The checked-in sample artifacts prove that the
harnesses and request/query plans exist; they do not claim API latency,
Postgres latency, Snowflake behavior, browser timing, or operator deployment
SLOs.

Measured local CPU graph timings remain in
[`p95-p99-graph-query.md`](p95-p99-graph-query.md). API, Postgres, and
operator-control-plane claims require live benchmark artifacts produced from the
commands below.

## Scope

Covered by the scaffold:

- skewed synthetic estate generation with local, CI, fleet, cloud, and
  operator-pushed source labels
- API request plan for `/v1/graph/search`, `/v1/graph/node/{id}`,
  `/v1/graph/paths`, `/v1/graph/diff`, and `/v1/graph/query`
- Postgres `EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)` SQL artifacts for node
  search, node detail, attack-path drilldown, graph diff, and bounded traversal
- target Postgres estate sizes of 10k / 50k / 100k edges

Excluded until live artifacts are attached:

- authenticated API p50/p95/p99
- Postgres p50/p95/p99 and actual query plans
- Snowflake or managed-operator deployment timings
- browser/UI interaction timing

## Environment

Checked-in sample artifacts were generated as dry-run/scaffold output. They are
environment-neutral and intentionally contain no latency numbers.

Live evidence must record:

- API base URL, auth mode, tenant, backend, and scan IDs
- Postgres version, DSN boundary, instance size, loaded edge count, and
  `EXPLAIN ANALYZE` output path
- client host CPU/OS/Python and network location relative to the API/database

## Commands

Generate a deterministic skewed estate report:

```bash
uv run python scripts/generate_graph_benchmark_estate.py \
  --agents 25 \
  --report-output docs/perf/results/graph-benchmark-estate-sample-report.json \
  --summary-output docs/perf/results/graph-benchmark-estate-sample.json
```

Validate the API benchmark plan without measuring:

```bash
uv run python scripts/run_graph_api_benchmark.py \
  --dry-run \
  --output docs/perf/results/graph-api-benchmark-sample.json
```

Run the API benchmark against a live control plane:

```bash
AGENT_BOM_API_TOKEN=... uv run python scripts/run_graph_api_benchmark.py \
  --base-url http://127.0.0.1:8000 \
  --tenant-id default \
  --scan-id graph-benchmark-estate-current \
  --old-scan-id graph-benchmark-estate-old \
  --new-scan-id graph-benchmark-estate-current \
  --source-node agent:agent-00000 \
  --detail-node package:langchain \
  --repeat 50 \
  --output docs/perf/results/graph-api-benchmark-live-$(date -u +%Y-%m-%d).json
```

Generate Postgres EXPLAIN SQL artifacts without measuring:

```bash
uv run python scripts/run_graph_postgres_explain.py \
  --dry-run \
  --output-dir docs/perf/results/postgres-graph-explain-sample \
  --summary-output docs/perf/results/postgres-graph-explain-sample.json
```

Run Postgres EXPLAIN ANALYZE against a loaded graph store:

```bash
AGENT_BOM_POSTGRES_DSN=postgresql://... uv run python scripts/run_graph_postgres_explain.py \
  --run \
  --scan-id graph-benchmark-estate-current \
  --old-scan-id graph-benchmark-estate-old \
  --source-node agent:agent-00000 \
  --detail-node package:langchain \
  --output-dir docs/perf/results/postgres-graph-explain-live-$(date -u +%Y-%m-%d) \
  --summary-output docs/perf/results/postgres-graph-explain-live-$(date -u +%Y-%m-%d).json
```

## Results

| Artifact | Status | What it supports |
|---|---|---|
| `graph-benchmark-estate-sample.json` | scaffold | deterministic skewed estate shape and source mix |
| `graph-api-benchmark-sample.json` | dry-run | API benchmark request coverage only |
| `postgres-graph-explain-sample.json` | dry-run | Postgres EXPLAIN artifact paths only |

No API or Postgres latency is claimed from these sample artifacts.

## SLOs

No API/Postgres SLO is declared by this scaffold. A future measured page should
publish p50/p95/p99 for each API operation and attach the matching Postgres
plans before making an operator or enterprise-pilot claim.

## Gaps

- Seed Postgres with matching 10k / 50k / 100k edge snapshots and check in
  measured `EXPLAIN ANALYZE` artifacts.
- Run the API benchmark under the intended auth mode and graph backend.
- Add browser interaction timing separately if UI scale claims are needed.
