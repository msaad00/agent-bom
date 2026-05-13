# Graph API and Postgres Benchmark Evidence

Evidence status: measured local API + Postgres EXPLAIN artifacts
Owner issue: #2145
Raw result artifacts:

- `docs/perf/results/graph-benchmark-estate-sample.json`
- `docs/perf/results/graph-benchmark-estate-sample-report.json`
- `docs/perf/results/graph-api-benchmark-sample.json`
- `docs/perf/results/postgres-graph-explain-sample.json`
- `docs/perf/results/postgres-graph-explain-sample/*.sql`
- `docs/perf/results/graph-benchmark-estate-live-2026-05-13.json`
- `docs/perf/results/graph-benchmark-estate-live-2026-05-13-report.json`
- `docs/perf/results/graph-benchmark-store-load-live-2026-05-13.json`
- `docs/perf/results/graph-benchmark-postgres-load-live-2026-05-13.json`
- `docs/perf/results/graph-api-benchmark-live-2026-05-13.json`
- `docs/perf/results/postgres-graph-explain-live-2026-05-13.json`
- `docs/perf/results/postgres-graph-explain-live-2026-05-13/*.sql`
- `docs/perf/results/postgres-graph-explain-live-2026-05-13/plans/*.txt`

## Claim

This page documents benchmark commands plus checked-in measured artifacts for a
local graph API run and a Docker Postgres `EXPLAIN ANALYZE` run. The measured
artifacts support local evidence for graph API p50/p95/p99 client timings and
database-local Postgres query plans on a deterministic synthetic estate.

These artifacts do not claim Snowflake behavior, browser timing, managed
operator deployment timing, or production SLOs. Measured local CPU graph
timings remain in [`p95-p99-graph-query.md`](p95-p99-graph-query.md).

## Scope

Covered by the checked-in evidence:

- skewed synthetic estate generation with local, CI, fleet, cloud, and
  operator-pushed source labels
- SQLite graph-store load for old/current snapshots with 11,242 current edges,
  10,479 current nodes, and 291 materialized attack paths
- API request plan for `/v1/graph/search`, `/v1/graph/node/{id}`,
  `/v1/graph/paths`, `/v1/graph/diff`, and `/v1/graph/query`
- local loopback API p50/p95/p99 client timings for each request above
- Docker Postgres graph-store load for the same old/current snapshots
- Postgres `EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)` plan artifacts for node
  search, node detail, attack-path drilldown, graph diff, and bounded traversal

Excluded from these local artifacts:

- authenticated remote API latency
- Postgres p50/p95/p99 repeated-run latency
- Snowflake or managed-operator deployment timings
- browser/UI interaction timing
- 50k / 100k edge Postgres runs

## Environment

The live artifacts were produced on 2026-05-13 with:

- API: `agent-bom api` loopback on `127.0.0.1:8429`, local unauthenticated
  mode, SQLite job store, SQLite graph store
- OS: Darwin 25.4.0 arm64
- Python: `uv run python --version` -> Python 3.13.5
- uv: 0.10.9
- Docker: 29.2.1
- Postgres: `postgres:16-alpine`, PostgreSQL 16.13
- Tenant: `default`
- Scan IDs: `graph-benchmark-estate-old` and
  `graph-benchmark-estate-current`

The API run uses local client wall-clock timing. The Postgres run uses
database-local `EXPLAIN ANALYZE`; it is plan evidence, not repeated p95/p99
Postgres latency evidence.

## Commands

Generate the checked-in sample estate report:

```bash
uv run python scripts/generate_graph_benchmark_estate.py \
  --agents 25 \
  --report-output docs/perf/results/graph-benchmark-estate-sample-report.json \
  --summary-output docs/perf/results/graph-benchmark-estate-sample.json
```

Generate the 2026-05-13 live estate shape:

```bash
uv run python scripts/generate_graph_benchmark_estate.py \
  --agents 250 \
  --report-output docs/perf/results/graph-benchmark-estate-live-2026-05-13-report.json \
  --summary-output docs/perf/results/graph-benchmark-estate-live-2026-05-13.json
```

Load old/current snapshots into a local SQLite graph store:

```bash
uv run python scripts/seed_graph_benchmark_store.py \
  --backend sqlite \
  --sqlite-db /tmp/agent-bom-graph-benchmark.db \
  --report docs/perf/results/graph-benchmark-estate-live-2026-05-13-report.json \
  --summary-output docs/perf/results/graph-benchmark-store-load-live-2026-05-13.json
```

Validate the API benchmark plan without measuring:

```bash
uv run python scripts/run_graph_api_benchmark.py \
  --dry-run \
  --output docs/perf/results/graph-api-benchmark-sample.json
```

Run the API benchmark against the loaded local control plane:

```bash
AGENT_BOM_GRAPH_DB=/tmp/agent-bom-graph-benchmark.db \
AGENT_BOM_DB=/tmp/agent-bom-api-benchmark.db \
uv run --extra api agent-bom api --host 127.0.0.1 --port 8429

uv run python scripts/run_graph_api_benchmark.py \
  --base-url http://127.0.0.1:8429 \
  --tenant-id default \
  --scan-id graph-benchmark-estate-current \
  --old-scan-id graph-benchmark-estate-old \
  --new-scan-id graph-benchmark-estate-current \
  --source-node agent:agent-00000 \
  --detail-node pkg:go:langchain@1.0.0 \
  --repeat 10 \
  --output docs/perf/results/graph-api-benchmark-live-2026-05-13.json
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
docker run --rm --name agent-bom-graph-bench-pg \
  -e POSTGRES_PASSWORD=agentbom \
  -e POSTGRES_DB=agentbom \
  -p 55432:5432 \
  -d postgres:16-alpine

AGENT_BOM_POSTGRES_URL=postgresql://postgres:agentbom@127.0.0.1:55432/agentbom \
uv run --extra postgres python scripts/seed_graph_benchmark_store.py \
  --backend postgres \
  --report docs/perf/results/graph-benchmark-estate-live-2026-05-13-report.json \
  --summary-output docs/perf/results/graph-benchmark-postgres-load-live-2026-05-13.json

cat >/tmp/psql <<'SH'
#!/bin/sh
file=""
args=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --file) shift; file="$1" ;;
    --file=*) file="${1#--file=}" ;;
    *) args="$args '$(printf '%s' "$1" | sed "s/'/'\\\\''/g")'" ;;
  esac
  shift
done
if [ -n "$file" ]; then
  eval "docker exec -i agent-bom-graph-bench-pg psql $args" < "$file"
else
  eval "docker exec -i agent-bom-graph-bench-pg psql $args"
fi
SH
chmod +x /tmp/psql

AGENT_BOM_POSTGRES_DSN=postgresql://postgres:agentbom@127.0.0.1:5432/agentbom \
uv run python scripts/run_graph_postgres_explain.py \
  --run \
  --psql-bin /tmp/psql \
  --scan-id graph-benchmark-estate-current \
  --old-scan-id graph-benchmark-estate-old \
  --source-node agent:agent-00000 \
  --detail-node pkg:go:langchain@1.0.0 \
  --output-dir docs/perf/results/postgres-graph-explain-live-2026-05-13 \
  --summary-output docs/perf/results/postgres-graph-explain-live-2026-05-13.json
```

## Results

| Artifact | Status | What it supports |
|---|---|---|
| `graph-benchmark-estate-sample.json` | scaffold | deterministic skewed estate shape and source mix |
| `graph-api-benchmark-sample.json` | dry-run | API benchmark request coverage only |
| `postgres-graph-explain-sample.json` | dry-run | Postgres EXPLAIN artifact paths only |
| `graph-benchmark-estate-live-2026-05-13.json` | generated | 250-agent estate with 604 servers, 3,475 tools, and 5,958 package instances |
| `graph-benchmark-store-load-live-2026-05-13.json` | measured load | SQLite graph store loaded old/current snapshots; current has 10,479 nodes, 11,242 edges, 291 attack paths |
| `graph-api-benchmark-live-2026-05-13.json` | measured API | loopback API p50/p95/p99 client timings across five graph hot paths |
| `graph-benchmark-postgres-load-live-2026-05-13.json` | measured load | Docker Postgres graph store loaded the same old/current snapshots |
| `postgres-graph-explain-live-2026-05-13.json` | measured plan | five Postgres `EXPLAIN ANALYZE` runs returned successfully with plan files |

API client timings from `graph-api-benchmark-live-2026-05-13.json`:

| Operation | Samples | p50 ms | p95 ms | p99 ms |
|---|---:|---:|---:|---:|
| graph search | 10 | 21.141 | 64.061 | 64.061 |
| node detail | 10 | 97.760 | 109.534 | 109.534 |
| attack-path drilldown | 10 | 1625.596 | 2146.839 | 2146.839 |
| graph diff | 10 | 208.873 | 338.559 | 338.559 |
| bounded traversal | 10 | 828.342 | 1179.635 | 1179.635 |

Top-level Postgres plan times from
`postgres-graph-explain-live-2026-05-13/plans/*.txt`:

| Query | Actual total time |
|---|---:|
| node search | 47.970 ms |
| node detail | 0.124 ms |
| attack-path drilldown | 0.177 ms |
| graph diff nodes | 38.421 ms |
| bounded traversal edges | 8.903 ms |

## SLOs

No production API/Postgres SLO is declared from this local run. A future SLO
page should repeat these measurements under the intended authenticated
deployment topology, include Postgres repeated-run p50/p95/p99, and attach
resource sizing before making an operator or enterprise-pilot latency claim.

## Gaps

- Run the API benchmark under the intended authenticated remote topology.
- Add repeated Postgres timing summaries in addition to single
  `EXPLAIN ANALYZE` plans.
- Add 50k / 100k edge Postgres artifacts.
- Add browser interaction timing separately if UI scale claims are needed.
