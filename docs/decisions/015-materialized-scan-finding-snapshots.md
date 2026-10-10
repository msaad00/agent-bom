# ADR-015: Materialized Scan Finding Snapshots

**Status:** Proposed
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
   payload produced by `collect_scan_findings` plus job-derived deterministic
   fields (effective reach, framework tags, normalized identifiers,
   `last_observed`).

Read-time state stays read-time. Runtime and workload evidence, triage owners,
suppressions and graph reachability projection keep being applied per read,
because they depend on mutable tenant state.

Rollout in three phases, each behind configuration and each independently
revertible:

1. **Write path.** Materialize on completion behind an opt-in setting
   (default off), with a backfill command for retained jobs and cleanup on job
   deletion and expiry. Reads are unchanged.
2. **Read path.** When enabled, the fold selects jobs from the metadata table
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

- Read cost and memory track the jobs the fold selects and their rows, not all
  retained history. Replicas reading the same database return the same
  snapshot inputs.
- Completion gains a write. A materialization failure is logged and recorded
  on the job like other post-completion side effects. The read path falls back
  to rebuilding, so a missed snapshot costs speed, not correctness.
- Snapshots are derived data. They carry a row-schema version; a code change
  that alters intrinsic row derivation bumps the version, and stale snapshots
  are rebuilt or ignored rather than served.
- Postgres tables get the same row-level security policy as the other
  tenant-scoped stores; SQLite and in-memory backends follow the existing store
  selection.
- Retention follows the owning job: snapshots are deleted with the job and
  expire under the job TTL, so no history outlives its source evidence.
