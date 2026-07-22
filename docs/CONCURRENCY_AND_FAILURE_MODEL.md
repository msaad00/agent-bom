# Concurrency and failure model

Short operator checklist for how agent-bom bounds concurrency, surfaces
failure, and cancels work. This is not a framework rewrite — it documents the
live contracts and the gaps that have been closed.

## Layers

| Layer | Mechanism | Contract |
|---|---|---|
| Job control | `JobStatus` (`pending` / `running` / `done` / `failed` / `cancelled`) + step status | `api/models.py`, `api/pipeline.py` |
| Evidence quality | `ScanOutcome` (`COMPLETE` / `PARTIAL` / `FAILED`) + `ScanRun` / `ScanIssue` | `evidence/scan_run.py` → SARIF / HTML / CLI |
| Driver contract | `ScannerExecutionState` + `ScannerFailureMode` | `scanners/base.py`, `registry.py`, `executor.py` |
| API concurrency | Bounded `ThreadPoolExecutor` (`API_SCAN_WORKERS`); optional distributed claim (`FOR UPDATE SKIP LOCKED`) | `pipeline.py`, `scan_queue.py` |
| IO resilience | HTTP retries + host breaker; enrichment circuits; MCP tool semaphores / timeouts | `http_client.py`, `enrichment_posture.py`, `mcp_server_runtime.py` |
| Overload | `adaptive_backpressure` → HTTP 429 + `Retry-After` | `backpressure.py` (process-local; pair with distributed queue / KEDA for multi-replica) |
| Multi-tenant races | RLS + Postgres advisory locks + tenant quota guard | graph / campaign / quota paths |
| Deploy | Helm CronJobs `concurrencyPolicy: Forbid`, `backoffLimit: 0` | chart templates |

## Failure modes

- **Fail-closed** — auth defaults, offline empty vuln DB, quota / RLS, registered
  `sca-vulnerability` after online retries (`apply_registered_failure_mode`).
- **Warn-and-continue** — most optional scanners, image/connector discovery soft
  catches, skill package verify (network miss → treat as exists to avoid false
  flags), batch skill scan / rescan sibling failures.
- **Skip-when-unavailable** — planned drivers and optional tooling (Semgrep
  missing, etc.).

## Cancel

- `POST /v1/scan/{job_id}/cancel` sets `JobStatus.CANCELLED` under the job lock
  and persists it.
- `_run_scan_sync` checks cancellation at pipeline phase boundaries
  (`_raise_if_cancelled`) and exits as `cancelled` (not `failed`).
- `DELETE /v1/scan/{job_id}` still discards the record; for pending/running jobs
  it requests cancel first so a finishing worker is less likely to resurrect a
  DONE result after discard.
- In-flight work is cooperative (no thread kill). Futures already running are
  not force-cancelled; shutdown still uses pool `cancel_futures` for queued work.

## Concurrent gather policy

Hot paths that fan out with `asyncio.gather` should pass
`return_exceptions=True` and handle per-item failures:

| Path | Policy on sibling failure |
|---|---|
| Skill package verify | Fail-open (treat as exists) |
| MCP health checks | Fail-open (unreachable + sanitized error) |
| `guard_install` | Fail-closed for the failed package (`scan_failed`) |
| Skills scan / catalog rescan | Warn-and-continue (unavailable entry) |
| Enrichment EPSS/KEV/NVD | Fail-open per source |

## Multi-replica honesty

Process-local backpressure and in-memory job maps are per replica. Multi-replica
deployments should enable the distributed scan queue (claim / lease) and scale
on the active-scan metric (KEDA / Helm). Do not assume `adaptive_backpressure`
alone coordinates across pods.

## Checklist (when changing this lane)

1. New scanner driver declares `failure_mode` + `execution_state` in the registry.
2. Live call sites that bypass `run_scanner_driver` consult
   `apply_registered_failure_mode` after retries for fail-closed drivers.
3. New `asyncio.gather` uses `return_exceptions=True` with an explicit per-item
   policy (fail-open vs fail-closed).
4. Long pipeline stages call `_raise_if_cancelled` at boundaries.
5. Document fail-open vs fail-closed on auth / runtime / proxy paths.
