# Graph reads during finding ingestion

Run a disposable, authenticated workload against a fresh synthetic SQLite
graph. Docker must be available and the source dependencies installed:

```bash
uv sync --frozen --extra api
uv run python scripts/run_graph_mixed_scale_evidence.py --output /tmp/graph-mixed-evidence
```

The output directory must not exist and must be outside the source checkout. The command creates an isolated API
container limited to two CPUs and 2 GiB, using the digest pinned in the script
with a hash-recorded private copy of the checkout's Python source mounted
read-only. Its proxy secret
is generated per run and passed through a private subprocess environment, never
written to evidence files or command arguments. Docker administrators can inspect
the container environment; use a trusted disposable Docker host. Cleanup removes
the container and its environment metadata. The API binds only to a dynamically assigned loopback port. Unsigned
proxy identities must be rejected before the workload begins.

The default fixture has four tenants, each with 250,000 vulnerability graph
nodes, 2,500 assets, 1,000 agents and 1,000 MCP servers. These are synthetic
**graph nodes**, not a million persisted finding-ledger records. One asset in
each tenant owns a quarter of the vulnerability relationships. Twelve clients
concurrently issue 100 ranked-page reads, 100 finding searches and 48 batches
of 100 finding-ledger writes across the four tenants.

Read `receipt.json` for the source revision, image digest, runtime SQLite
version, fixture counts, resource quota, CPU/memory readings, source and harness hashes, every request
outcome, response sizes, and nearest-rank p50/p95/p99. The receipt records
request start/end offsets and how many reads overlap ingestion, including
same-tenant overlap. These client request intervals do not prove simultaneous
database execution. Failed HTTP requests,
throttling, tenant mismatches and timeouts remain in the result and cause a
nonzero exit. Percentiles for all attempts and successful attempts are
separate. There is no warm-up exclusion; initial reads include cold caches.

For sustained overlap, keep each read and ingestion worker active to a common
deadline instead of exhausting a short write batch:

```bash
uv run python scripts/run_graph_mixed_scale_evidence.py \
  --output /tmp/graph-mixed-sustained --duration-seconds 120 --ingest-interval 1
```

Duration mode ignores the fixed read/batch counts. Each tenant has one page,
one search and one ingestion worker. Reads run sequentially per worker;
ingestion starts at most once per configured interval per tenant, without
adding artificial delay to an already slower request. No new request starts
after the deadline; in-flight requests finish under the request timeout.
Worker completion records and all outcomes remain in the receipt. Default rate
limits and backpressure remain enabled; any rejection fails the run. Actual
successful overlap still needs inspection. This is a closed-loop workload,
not proof of an independent offered request rate or saturation capacity.

For a short smoke run:

```bash
uv run python scripts/run_graph_mixed_scale_evidence.py \
  --output /tmp/graph-mixed-smoke --tenants 2 --findings-per-tenant 40 \
  --assets-per-tenant 3 --agents-per-tenant 2 --servers-per-tenant 2 \
  --read-requests 2 --ingest-batches 2 --batch-size 2
```

The manual **Perf Scale Evidence** workflow's `mixed_graph` option runs the
same fixture on an ephemeral Ubuntu runner and uploads the receipt and bounded,
sanitized server diagnostics, including failed runs. It does not upload the
database or container environment:

```bash
gh workflow run perf-scale-evidence.yml -f mixed_graph=true -f open_pr=false
```

Add `--ref <branch>` to qualify an unmerged candidate and `-f mixed_graph_seconds=120` for duration mode (maximum 600 seconds). The mixed workload is
opt-in; scheduled runs retain their existing lightweight scope.

Next, repeat on the same dedicated host with representative customer data
shape, sustained load, longer sampling and PostgreSQL before setting an SLO.
GitHub-hosted hardware can vary between runs. This bounded fixture does not
establish production capacity, tenant authorization coverage, customer
deployment success or cloud cost. Resource consumption can inform a later
cost model; it is not a cloud-price estimate.

For SQLite search-index upgrade and rollback instructions, see [search scope](sqlite-graph-search.md).
