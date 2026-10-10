# ADR-015: Materialized Scan Finding Snapshots

**Status:** Write path and guarded read qualification implemented; optimized reads and default-on proposed
**Date:** 2026-10-10

## Context

`GET /v1/findings` and the posture, compliance, export and MCP readers that
share its scan half build current scan findings by folding every retained,
completed scan job on every read (`api/findings_current.py`
`current_scan_findings`). For each job the fold:

- loads the full `job.result` document from the job store;
- rebuilds finding rows from it (`api/finding_collection.py`
  `collect_scan_findings`), including a per-job context graph for effective
  reach;
- derives the job's scan scope, evidence authority and incompleteness to decide
  which jobs supply current findings, which earlier findings stay as
  `unreconfirmed`, and which retire.

Request-scoped memoization (`api/finding_read_context.py`) removes repeats
within one read, but every read still pays for every retained job. Cost and
memory grow with scan history rather than with the size of the answer, and
every API replica repeats the same work.

The compliance hub's current-state table (`hub_findings_current`) is not a safe
home for these rows. It holds one row per `(tenant_id, canonical_id)` with
last-writer-wins payloads, and bulk-ingest reconciliation is scoped by ingest
source, not origin. Writing scan rows there could overwrite a bulk-ingested
finding's lifecycle or let an ingest batch resolve scan observations.

## Decision

Materialize each completed scan job's fold inputs once, at completion, and let
the fold read them instead of rebuilding them from job results. The fold's
selection and lifecycle semantics stay in Python and do not change.

Two tenant-scoped tables, written only after the job is durably `DONE`
(after the job store write in `api/pipeline.py` `_finalize` succeeds):

1. **Job fold metadata**, one row per job: tenant, job id, scan scope key,
   evidence authority key, authoritative-evidence flag, incompleteness reason
   codes, `completed_at`, and a row-schema version.
2. **Intrinsic finding rows**, one row per finding occurrence per job: tenant,
   job id, finding identity, canonical id, severity and sort keys, and the
   payload produced by `collect_scan_findings`. Phase 1 stores that intrinsic
   payload; the read-path phase must preserve existing job-derived enrichment
   such as effective reach and `last_observed` through differential parity tests.

Read-time state stays read-time. Runtime and workload evidence, triage owners,
suppressions and graph reachability projection keep being applied per read,
because they depend on mutable tenant state.

Rollout in three phases, each behind configuration and each independently
revertible:

1. **Write path.** Materialize on completion behind an opt-in setting
   (default off), with a backfill command for retained jobs and cleanup on job
   deletion and expiry. Reads are unchanged.
2. **Read path.** The initial guarded mode described below verifies snapshot
   candidates against the current collector. In the subsequent optimized mode,
   the fold will select jobs from the metadata table
   and fetches rows only for selected jobs. A job without a snapshot, or with a
   different row-schema version, falls back to rebuilding from its result. A
   differential test harness runs the existing current-findings semantics
   fixtures through both paths and requires identical output.
3. **Default on** after parity holds in CI and in a production-shaped
   benchmark; filtering and sorting of the scan half can then move into SQL.

Alternatives considered:

- **Write scan rows into `hub_findings_current`.** Rejected for the
  lifecycle-collision reasons above.
- **Cache fold output across requests.** Rejected: approvals, expiry, tenant
  filters and evidence must be re-evaluated on every read
  (`api/finding_read_context.py`).
- **Move the whole fold into SQL now.** Deferred: scope replacement,
  unreconfirmed marking and cross-scope authority dedupe have broad test
  coverage in Python. Moving them into SQL is only worth it once phase 2 shows
  where time is actually spent.

## Consequences

- After the read-path phase, read cost and memory are intended to track the
  jobs the fold selects and their rows, not all retained history. Replicas
  reading the same database return the same snapshot inputs.
- Opted-in completion gains a write. A materialization failure is logged without
  changing the durable job outcome. Phase 1 reads still use the retained result;
  the proposed read path must fall back to rebuilding when a snapshot is missing.
- Snapshots are derived data. They carry a row-schema version; a code change
  that alters intrinsic row derivation bumps the version, and stale snapshots
  are rebuilt or ignored rather than served.
- Postgres tables get the same row-level security policy as the other
  tenant-scoped stores; SQLite and in-memory backends follow the existing store
  selection.
- Deletion and TTL cleanup run even when new snapshot writes are disabled.
  Per-job cleanup is best effort after authoritative job deletion; failures are
  logged and TTL cleanup retries. Tenant erasure propagates snapshot purge
  failures instead of reporting successful erasure.

## Phase 1 operator path

Set `AGENT_BOM_SCAN_SNAPSHOTS=1` before starting the API to materialize newly
completed scans. To include retained jobs, run
`python -m agent_bom.api.scan_snapshot backfill --tenant <tenant_id>` with the
same storage configuration as the API. The JSON receipt reports materialized,
skipped and failed jobs; failed jobs make the command exit nonzero.

To stop new writes, unset the setting. Existing findings reads are unchanged.
`python -m agent_bom.api.scan_snapshot purge --tenant <tenant_id>` erases derived
snapshots for that tenant even with the setting off; retained job results remain
available for rebuilding. These are operator commands with access to the configured
database; the tenant argument is explicit scope, not caller authentication.


## Guarded read qualification

Set `AGENT_BOM_SCAN_SNAPSHOT_READS=1` on the API to qualify snapshot-backed
finding rows. This flag is independent of the write flag and defaults off.
With snapshots already populated, request `GET /v1/findings?origin=scan` using
the deployment's normal authentication. The response contract is unchanged.

For each selected retained job, the reader collects the current rows, loads
that tenant's snapshot, reapplies live enrichment, and compares the complete
ordered JSON row values (including value types) before the shared identifier, owner and suppression
projection. It returns the snapshot candidate only on exact equality. Missing
or old-schema snapshots, invalid row counts or ordinals, read errors and
mismatches use the current collector's rows. A current-collector error still
propagates; derived snapshots never conceal an authoritative read failure.
No snapshot payload or backend exception is written to qualification logs.

The `agent_bom.api.scan_snapshot_read` logger emits debug outcomes `match` and
`missing_or_stale`; warning outcomes `mismatch`, `invalid` and `unavailable`
identify fallback. These signals describe parity or availability, not a clean
security result. Inspect them while exercising findings, posture and exports;
unset the read flag to disable the extra work immediately. Writes and cleanup
continue according to their existing contracts.

This qualification mode adds a snapshot lookup and a second enrichment pass.
It still loads retained job results, uses their original history for first-seen
and SLA semantics, and builds effective reach from the retained report. It does
not establish lower read latency or history-independent memory use. Differential
coverage includes incomplete rescans, empty replacement, parent exclusion,
explicit and alternate scan IDs, history outside the display window, changed
runtime evidence and mixed representations. Enriching before versus after a
representation merge can differ; the parity gate preserves existing behavior
instead of serving that difference. Metadata-only selection and removing the
reference comparison require a later validated optimization.
