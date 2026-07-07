# Agent-BOM Scale Runbook — GB→TB synthetic estates

This runbook takes you from an empty Postgres/RDS + EKS control plane to a
**TB-scale ingest+read latency number**, using two tools that live in this dir:

| Tool | Role |
| --- | --- |
| `generate_estate.py` | Produces arbitrarily large, **realistic** synthetic findings (weighted severity, real-looking CVE/GHSA ids, 8 ecosystems, cvss/epss/kev, reachability, compliance tags). Streams — never buffers the whole set. |
| `agent_bom_scale_bench.py` | Drives bulk ingest + keyset-read latency against a running control plane and reports flatness / regression. |

The generator **feeds** the bench (and any lake target). Keep them separate: the
generator makes data at scale; the bench measures the plane under that data.

---

## 0. Sizing cheat-sheet

The generator emits ~**990 bytes/finding** as compact NDJSON. So:

| Target (uncompressed NDJSON) | `--findings` (approx) | `--target-gb` |
| --- | --- | --- |
| 1 GB | ~1.08 M | `--target-gb 1` |
| 100 GB | ~108 M | `--target-gb 100` |
| 1 TB | ~1.08 B | `--target-gb 1024` |

Either pass `--findings N` directly or `--target-gb G` and let it compute `N`.
Postgres on-disk footprint will differ (indexes, TOAST, row overhead) — budget
**~1.5–2.5x** the NDJSON size for the `hub_findings` tables + sort indexes.

Everything is deterministic in `--seed`: the same seed reproduces the same
estate byte-for-byte, and generation is resumable (row `idx` never depends on
wall-clock), so a killed TB run can be re-pointed at the same seed.

---

## 1. Provision Postgres (RDS)

```bash
# RDS: a db.r6g.2xlarge (8 vCPU / 64 GB) comfortably holds a ~1 TB estate.
aws rds create-db-instance \
  --db-instance-identifier agentbom-scale \
  --engine postgres --engine-version 16 \
  --db-instance-class db.r6g.2xlarge \
  --allocated-storage 2000 --storage-type gp3 --iops 12000 \
  --master-username agentbom --manage-master-user-password \
  --backup-retention-period 0 --no-multi-az

# Grab the endpoint once it's "available":
aws rds describe-db-instances --db-instance-identifier agentbom-scale \
  --query 'DBInstances[0].Endpoint.Address' --output text
```

Local alternative (laptop smoke test before spending on RDS):

```bash
docker run -d --name agentbom-pg -e POSTGRES_PASSWORD=agentbom \
  -e POSTGRES_DB=agentbom -p 5432:5432 postgres:16
export DATABASE_URL=postgresql://postgres:agentbom@127.0.0.1:5432/agentbom
```

---

## 2. Deploy the control plane on EKS (or run it locally)

Point agent-bom at the RDS endpoint via `DATABASE_URL` and start the API. On EKS
you want the ingest pods and the generator pod in the **same AZ/VPC** as RDS so
the bench measures the plane, not the WAN.

```bash
# minimal local boot (same image you ship to EKS)
export DATABASE_URL=postgresql://agentbom:...@agentbom-scale.xxxx.rds.amazonaws.com:5432/agentbom
export AGENT_BOM_API_KEY=$(python3 -c "import secrets;print(secrets.token_urlsafe(32))")
docker run -d --name agentbom-api -p 8422:8422 \
  -e DATABASE_URL -e AGENT_BOM_API_KEY \
  ghcr.io/<org>/agent-bom:latest agent-bom serve --host 0.0.0.0 --port 8422

export AGENT_BOM_URL=http://127.0.0.1:8422   # or the EKS service DNS
curl -sf "$AGENT_BOM_URL/health"
```

On EKS, run the generator from a Job in-cluster:

```bash
kubectl run estate-gen --image=ghcr.io/<org>/agent-bom:latest --restart=Never -- \
  python3 /app/scripts/bench/generate_estate.py \
    --target-gb 1024 --out bulk --url http://agent-bom.default.svc:8422 \
    --api-key "$AGENT_BOM_API_KEY" --concurrency 16 --batch-size 1000
```

---

## 3. Generate + load the estate

### 3a. Stream straight into the plane (recommended for TB)

No intermediate file — the generator POSTs `/v1/findings/bulk` batches with a
deterministic `Idempotency-Key` per batch, so a retried/resumed run collapses
server-side instead of double-counting.

```bash
# 100 GB, 16-way concurrent ingest
python3 scripts/bench/generate_estate.py \
  --target-gb 100 \
  --out bulk --url "$AGENT_BOM_URL" --api-key "$AGENT_BOM_API_KEY" \
  --concurrency 16 --batch-size 1000 --seed 1337
```

Memory stays flat regardless of `--target-gb`: at most `--concurrency` batches
are ever in flight.

### 3b. Materialize a file first (reusable corpus / lake tests)

```bash
# NDJSON (streamed; '-' writes to stdout for piping)
python3 scripts/bench/generate_estate.py --target-gb 10 --out ndjson estate-10gb.jsonl

# Parquet matching agent-bom's 27-col finding schema (needs the `lake` extra)
pip install 'agent-bom[lake]'
python3 scripts/bench/generate_estate.py --findings 50000000 --out parquet estate.parquet
```

The parquet columns are byte-identical to
`src/agent_bom/output/parquet_fmt.py` (a test asserts this), so the file drops
straight into Athena/Trino/Snowflake/Iceberg lake pipelines.

### Estate-axis knobs (graph realism)

Defaults scale off the findings count; override to widen/narrow fan-in:

```
--agents N --servers N --packages N --cloud-resources N --identities N
```

Fewer agents/servers ⇒ higher findings-per-node fan-in ⇒ heavier blast-radius
rollups. Defaults: agents≈N/200, servers≈N/500, packages≈N/20,
cloud-resources≈N/100, identities≈N/50.

---

## 4. Run the latency bench

Once the estate is loaded, measure ingest flatness + keyset read latency at
depth (the bench's own trivial rows are fine for the *ingest* phase; the *read*
phase reads whatever is already in the plane — i.e. your synthetic estate):

```bash
# Read-only walk over the loaded estate (no new ingest)
PHASES=read TARGET=0 READ_PAGES=30 PAGE_LIMIT=500 \
  python3 scripts/bench/agent_bom_scale_bench.py

# Ingest-flatness under concurrency (first-10 vs last-10 batch latency ratio)
PHASES=ingest,idempotency INGEST_CONC=8 TARGET=1000000 BATCH=1000 \
  python3 scripts/bench/agent_bom_scale_bench.py
```

---

## 5. Read the results

The bench prints `[PASS]/[FAIL]` per check:

* **`ingest_flatness`** — `ratio = last10_mean / first10_mean`. Ratio near 1.0
  means ingest cost is independent of table size (good). A climbing ratio is the
  O(table-size) ingest regression to watch for at scale.
* **`keyset_walk`** — mean ms per keyset page and unique-id count. This is the
  sorted-read latency at depth; it should stay flat across pages if the sort
  indexes are healthy. A synthetic estate with a **real severity/cvss/epss
  distribution** (what this generator produces) is what actually exercises those
  indexes — uniform rows do not.
* **`first_page_count`** — exact vs approximate total latency; at TB scale the
  exact `COUNT(*)` is the expensive one, so confirm `approximate_total=true` is
  the fast path your UI uses.

**TB-scale number to report:** load `--target-gb 1024`, then record
`keyset_walk mean_ms` and the `ingest_flatness ratio` at that depth. That pair —
"sorted-read latency and ingest flatness at 1 TB / ~1 B findings on
db.r6g.2xlarge" — is the headline scale result.

---

## 6. Teardown

```bash
docker rm -f agentbom-api agentbom-pg 2>/dev/null || true
aws rds delete-db-instance --db-instance-identifier agentbom-scale \
  --skip-final-snapshot --delete-automated-backups
```
