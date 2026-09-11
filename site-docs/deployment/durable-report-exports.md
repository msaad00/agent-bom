# Durable report exports

Queue a findings export, poll its job ID, and download gzipped NDJSON:

```bash
curl --fail-with-body -H "Authorization: Bearer $AGENT_BOM_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"format":"ndjson","window_days":90}' \
  "$AGENT_BOM_URL/v1/reports"

curl --fail-with-body -H "Authorization: Bearer $AGENT_BOM_API_KEY" \
  "$AGENT_BOM_URL/v1/reports/$REPORT_JOB_ID"
```

A completed local job supplies a `download_url`, `download_token`, and
`download_token_header`. Send the token in `X-Agent-Bom-Download-Token`, along
with API authentication. S3 jobs supply a freshly signed download URL on each
authenticated status read. Do not put API keys or local download tokens in URLs.

## Storage and worker sizing

SQLite is the default durable job backend, selected through `AGENT_BOM_DB` or
`AGENT_BOM_STATE_DIR`. `AGENT_BOM_EPHEMERAL_STORE=1` explicitly discards job state
on restart. Configured Postgres takes precedence over ephemeral mode. Run the
Alembic migration through revision `20260911_01` before starting upgraded
Postgres replicas; runtime credentials perform no schema changes.

| Setting | Default | Effect |
|---|---|---|
| `AGENT_BOM_API_REPORT_WORKERS` | `2` | Concurrent exports per replica, separate from scan workers; `0` accepts queued jobs without executing them locally |
| `AGENT_BOM_API_REPORT_LEASE_SECONDS` | `60` | Claim lifetime; active workers renew before expiry |
| `AGENT_BOM_API_REPORT_MAX_ATTEMPTS` | `3` | Maximum claim attempts after worker loss |
| `AGENT_BOM_API_MAX_ACTIVE_REPORT_JOBS_PER_TENANT` | `5` | Atomic limit covering queued and running jobs across the shared database; nonpositive disables the cap |

A stopped worker's queued jobs remain available to another worker. Every
attempt uses a unique artifact name. Lease-token checks prevent a stale worker
from changing the completed job or overwriting the artifact chosen by a retry.
Postgres uses database time for leases and `FOR UPDATE SKIP LOCKED` for claims.
Application sessions remain tenant-bound; global dispatch requires the distinct
maintenance identity described in the Postgres deployment guide.

For multiple replicas, use Postgres plus either:

- `AGENT_BOM_REPORT_S3_BUCKET`, with the AWS SDK credential chain and `[aws]`
  installed; each worker needs upload access and each serving replica needs
  permission to sign downloads.
- A shared mounted `AGENT_BOM_REPORT_ARTIFACT_DIR`, with
  `AGENT_BOM_REPORT_ARTIFACT_SHARED=1` to acknowledge that all replicas see it.

Clustered exports reject admission with HTTP 503 when that storage contract is
missing. Database errors fail closed with a sanitized 503; there is no in-memory
fallback. HTTP 429 means the tenant's active-job quota is full.

## Recovery, observation and limits

Poll `/v1/reports/{job_id}` to distinguish pending, running, done, and failed
work. `/metrics` exposes `agent_bom_report_exports_total` with bounded outcomes
`claimed`, `lease_lost`, `completed`, and `failed`. Completed attempts and renderer/storage failures
also append audit events. Lease exhaustion is recorded in durable job status. Lost database access stops lease renewal and blocks
publication. After lease expiry another replica can claim the job; exhausted
claims become failed rather than retrying forever. Renderer or object-storage
errors mark the attempt failed; clients can submit a new job after remediation.

Graceful shutdown stops new claims and renews active work during the configured
drain period. Streaming checks stop a worker after it loses ownership. Threads
are not a process sandbox: blocking native/network operations cannot be forcibly
terminated by the pool. Size pod CPU/memory and network timeouts accordingly.

The requested lookback cutoff is anchored to admission time. Findings still
come from the current evidence store when the attempt runs; retries are not an
immutable database snapshot. Use a specific `scan_id` when that is the intended
scope.

Completed rows and winning local files are retained. Configure an operator
retention policy for the report table and artifact directory; configure a bucket
lifecycle for S3 objects, including abandoned attempt objects. Losing local
attempts are removed when the process can clean them up; abrupt process death
can leave orphaned files. A rolling application rollback preserves the additive
schema and rows, but old binaries cannot resume the new durable queue. Drain
exports before rolling back to an older application version.
