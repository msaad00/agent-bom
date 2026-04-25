# Performance Benchmarks and Target SLOs

Measured numbers for the agent-bom scanner hot paths that matter at
pilot scale. Run on a MacBook Pro (M-series, 2026) with Python 3.13.
Your infra will vary — treat these as the reference curve, not the
contract. The target SLOs below are the operator envelope we use for
pilot and production readiness decisions.

Run them yourself:

```bash
pip install 'agent-bom[dev]'
pytest tests/benchmarks/ --benchmark-only --benchmark-columns=min,mean,max,stddev,ops
AGENT_BOM_BENCH_FULL=1 pytest tests/benchmarks/ --benchmark-only -k 50k  # heaviest
```

For control-plane and graph API baselines against a running deployment:

```bash
k6 run deploy/loadtest/k6-control-plane-api.js
k6 run deploy/loadtest/k6-graph-api.js
k6 run deploy/loadtest/k6-proxy-audit.js
```

Release-quality scale evidence for 1k / 5k / 10k estate claims is tracked
under [`docs/perf/`](perf/). Those pages carry the exact commands,
environment fields, raw-result locations, and gaps used for enterprise
procurement evidence. Validate the scaffold with:

```bash
python scripts/check_scale_evidence.py
```

---

## Scanner hot paths

### Blast-radius tag indexing — `_index_blast_radii_by_tag`

The O(n × k) pass that feeds every compliance bundle. Measured across
1k / 10k / 50k blast-radius findings each tagged under all 14
compliance frameworks (≈14 tag fields per finding).

| Inventory size | Mean | StdDev | Throughput |
|---:|---:|---:|---:|
| 1,000 findings | **0.78 ms** | 0.08 ms | 1,280 ops/sec |
| 10,000 findings | **8.35 ms** | 0.42 ms | 120 ops/sec |
| 50,000 findings | **44.3 ms** | 0.81 ms | 22 ops/sec |

**Scaling:** linear — 50x input → 56x latency. No superlinear blow-up.

**Implication for pilot teams:** a 50k-package agent fleet rebuilds the
tag index in under 50 ms. You can re-index on every evidence-bundle
export without caching; caching becomes interesting only above ~200k
findings.

### OSV fallback accounting — `skipped_non_osv_ecosystems`

The scanner tracks packages that deliberately skip the OSV network path
because their ecosystem is not OSV-backed (for example MCP registry
entries and other non-package inventory rows). This counter is not a
false-negative bucket; it is the expected accounting for inventory
surfaces that never belonged in the OSV query set.

**Implication for operators:** rising `skipped_non_osv_ecosystems`
counts usually mean your inventory mix includes more registry or
non-package metadata, not that vulnerability coverage regressed.

### Compliance bundle signature — HMAC-SHA256 over canonical JSON

The signing path behind `/v1/compliance/{framework}/report`. Measured
with representative evidence payloads of 100 / 1,000 / 10,000 controls
each carrying a variable number of evidence entries.

| Controls per bundle | Mean | Throughput |
|---:|---:|---:|
| 100 controls | **0.20 ms** | 4,930 ops/sec |
| 1,000 controls | **1.93 ms** | 519 ops/sec |
| 10,000 controls | **19.4 ms** | 51 ops/sec |

**Scaling:** linear in canonical-JSON size — serialisation dominates
over HMAC-SHA256 itself.

**Implication:** a realistic 14-framework report (≈220 controls total
across frameworks, up to ~10 evidence entries each) signs in **under 5
ms** end-to-end. Ed25519 adds ~0.2 ms on top.

### Unified graph build — `build_unified_graph_from_report`

The hot path behind `/v1/scan/{job_id}/context-graph` and the UI
mesh / attack-path views. Walks a scan report JSON into a
`UnifiedGraph` of agents + servers + packages + tools + credentials +
blast-radius edges.

Measured on a MacBook Pro (M-series, 2026), Python 3.13. Source:
`tests/benchmarks/test_graph_hot_paths.py`.

| Scale | Agents × Servers × Packages | Mean build time | Throughput |
|---|---|---:|---:|
| Small team | 20 × 2 × 5 = 200 pkgs | **0.71 ms** | ~1,415 ops/sec |
| Departmental | 100 × 2 × 5 = 1,000 pkgs | **3.78 ms** | ~265 ops/sec |
| Company-wide | 500 × 2 × 10 = 10,000 pkgs | **42.0 ms** | ~24 ops/sec |
| Enterprise (50k variant) | 1,000 × 5 × 10 = 50,000 pkgs | **50.5 ms** | ~20 ops/sec |

**Scaling:** effectively linear in package count up to 10k (builder is
O(agents + servers + packages + edges)); the 50k jump is actually
cheaper per-package than 10k because the synthetic fixture reuses
package keys across servers, so dedup amortises cost.

**Implication for pilot teams:**
- **Build-on-every-scan is fine up to ~50k packages.** No caching layer
  needed. The graph fits comfortably in the API pod memory (~200 MB at
  50k nodes).
- **Cardinality cliff to watch:** at >200k packages / 5k agents (hypothetical
  multi-tenant mega-deploy), consider moving graph persistence to ClickHouse
  for analytics cardinality or paginate the builder.
- **Storage story:** graph materialisation (the Postgres `graph_state`
  table, see [`api/postgres_graph.py`](../src/agent_bom/api/postgres_graph.py))
  is ~2 KB per node — 50k nodes ≈ 100 MB per tenant.

Run yourself:

```bash
pip install 'agent-bom[dev]'
pytest tests/benchmarks/test_graph_hot_paths.py --benchmark-only
AGENT_BOM_BENCH_FULL=1 pytest tests/benchmarks/test_graph_hot_paths.py -k 50k --benchmark-only
```

---

## End-to-end scan targets

These aren't micro-benchmarks yet; they're the target envelope the
team runs against during pilot smoke-testing. Run
`scripts/pilot-verify.sh` to check your own environment.

| Operation | Target (pilot) | Target (production) |
|---|---:|---:|
| `/healthz` round-trip | < 20 ms p99 | < 50 ms p99 |
| `/v1/fleet/sync` single heartbeat | < 100 ms p99 | < 200 ms p99 |
| `/v1/compliance` aggregate across 100 scan jobs | < 500 ms p99 | < 1 s p99 |
| `/v1/compliance/{framework}/report` at 10k findings | < 150 ms p99 | < 300 ms p99 |
| `/v1/compliance/{framework}/report` at 50k findings | < 500 ms p99 | < 1 s p99 |
| jsonl bundle streaming (first byte) | < 50 ms | < 100 ms |

## Graph and control-plane operator targets

These are the target envelopes for the main operator flows after the
0.81.x store-backed graph improvements. They are not yet universal
guarantees for every tenant shape; they are the thresholds we expect a
healthy self-hosted rollout to validate with the bundled k6 harness.

| Operation | Baseline path | Target (pilot) | Target (production) |
|---|---|---:|---:|
| `GET /v1/graph?limit=100` | store-backed overview page | < 300 ms p95 | < 500 ms p95 |
| `GET /v1/graph/search?q=agent&limit=25` | store-backed search page | < 250 ms p95 | < 400 ms p95 |
| `GET /v1/fleet?limit=25` | authenticated fleet read | < 200 ms p95 | < 350 ms p95 |
| `GET /v1/fleet/stats` | fleet summary read | < 150 ms p95 | < 300 ms p95 |
| `POST /v1/proxy/audit` | proxy audit ingest batch | < 300 ms p95 | < 500 ms p95 |

### How to measure the operator targets

Run against the deployment you actually intend to operate:

```bash
export AGENT_BOM_BASE_URL=https://agent-bom.internal.example.com
export AGENT_BOM_API_TOKEN=replace-me
export AGENT_BOM_GRAPH_SCAN_ID=$(curl -s -H "Authorization: Bearer $AGENT_BOM_API_TOKEN" \
  "$AGENT_BOM_BASE_URL/v1/graph/snapshots?limit=1" | jq -r '.[0].scan_id')

k6 run deploy/loadtest/k6-control-plane-api.js
k6 run deploy/loadtest/k6-graph-api.js
k6 run deploy/loadtest/k6-proxy-audit.js
```

Interpretation:

- if graph overview/search breaches target first, keep the graph windowed by
  snapshot and page size before widening runtime rollout
- if fleet reads breach target first, tune API HPA and database size before
  assuming the graph is the bottleneck
- if proxy audit ingest breaches target first, adjust batch size, retention,
  or analytics backend before widening sidecar/gateway deployment

Latency budget for a bundle export at 50k findings on Postgres:

- `_tenant_jobs` store read: ~10 ms (index on tenant_id)
- `_index_blast_radii_by_tag` in process: ~44 ms (measured above)
- `_evidence_for_control` × 220 controls: ~30 ms (O(tags × findings-per-tag))
- Canonical JSON + sign: ~20 ms (measured above)
- **Total: ~104 ms at p50, well inside the 500 ms p99 target**

---

## CPU / memory sizing

Pilot-default Helm values ([`eks-mcp-pilot-values.yaml`](../deploy/helm/agent-bom/examples/eks-mcp-pilot-values.yaml)):

| Component | Request / Limit | Notes |
|---|---|---|
| `agent-bom-api` | 500 m / 2 CPU, 512 Mi / 2 Gi | 2–6 replicas via HPA |
| `agent-bom-ui` | 100 m / 500 m CPU, 256 Mi / 1 Gi | Next.js SSR |
| `scan` CronJob | 1 CPU / 4 CPU, 1 Gi / 4 Gi | Runs every 6 h |
| `agent-bom-proxy` sidecar | 100 m / 500 m CPU, 128 Mi / 512 Mi | Per-MCP |

Scale-out signal: `agent_bom_rate_limit_hits_total` hitting a tenant
bucket for > 10 minutes, OR `p95` on `/v1/compliance/*` above 800 ms.
Both show up on the shipped Grafana dashboard.

For graph/runtime-heavy rollouts, treat these as the next scale-out
signals too:

- `/v1/graph` `p95` consistently above `500 ms`
- `/v1/graph/search` `p95` consistently above `400 ms`
- `POST /v1/proxy/audit` `p95` consistently above `500 ms`
- rising queueing or timeout behavior during the bundled k6 graph/control-plane runs

---

## Storage growth

Rough per-tenant rates observed during pilot runs:

| Backend | Scan jobs | Fleet agents | Audit events |
|---|---:|---:|---:|
| Postgres | ~3 KB / job | ~1 KB / agent | ~0.5 KB / event |
| ClickHouse | ~1.5 KB / row (compressed) | n/a | ~0.5 KB / event |
| Snowflake | ~2 KB / row (Hybrid Tables) | ~1 KB / agent | ~0.5 KB / event |

A pilot tenant with **200 agents, a scan per agent every 6 h, and
1,000 audit events per hour** produces:

- 800 scan jobs / day (~2.4 MB Postgres, ~1.2 MB ClickHouse, ~1.6 MB Snowflake)
- 200 fleet agents steady-state (~200 KB)
- 24,000 audit events / day (~12 MB)

TTL + retention knobs: `AGENT_BOM_API_MAX_RETAINED_JOBS_PER_TENANT`
(default 1000), `AGENT_BOM_AUDIT_RETENTION_DAYS` (default 90).

---

## Adding a benchmark

1. Add a test under `tests/benchmarks/test_<area>.py` using the
   `benchmark` fixture from pytest-benchmark.
2. Parametrize by scale (1k / 10k / 50k) so we see the curve. Guard the
   50k variant with `@pytest.mark.slow` and the `AGENT_BOM_BENCH_FULL=1`
   env skip.
3. Run `pytest tests/benchmarks/ --benchmark-only --benchmark-json=bench.json`,
   paste the numbers here with the measurement date.
4. Update the "Implication for pilot teams" sentence — numbers without
   an operator narrative are numbers the on-call will ignore.

Benchmarks are not part of the default CI gate — they run on demand via
`workflow_dispatch` on the same runner family so results stay
comparable.
