# ADR-015: Materialized Scan Finding Snapshots

**Status:** Opt-in per-job fast reads and differential qualification implemented; metadata-only history and default-on remain proposed
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


## Read modes and version 2 inputs

Write and backfill commands now store version 2: a private context envelope
followed by ordered, **unmerged** source representations. Readers enrich each
representation before the shared merge, preserving the authoritative unified
row, runtime evidence, framework tags, identities and supplementary backfill.
The envelope contains intrinsic effective reach, a SHA-256 digest of the entire
retained job (including JSON value types), and a digest of reach and ordered
representation payloads. It is never returned as a finding. Old versions need
backfill; storage-table migrations are unchanged.

Set `AGENT_BOM_SCAN_SNAPSHOT_FAST_READS=1` to use valid snapshots without running
the legacy collector or rebuilding its context graph. Runtime/workload evidence,
triage ownership and current suppressions are still evaluated at read time.
Two tenant-scoped store reads load metadata and the selected job's rows; no
per-finding database calls are added. The content digest and count/ordinal checks
reject incomplete or mixed replacements. A source digest mismatch, stale version,
missing rows, malformed payload or derived-store error rebuilds from the retained
job. Digests detect accidental damage and stale inputs, not an attacker controlling
both content and digest. Unsetting the fast flag restores legacy reads immediately.

Set `AGENT_BOM_SCAN_SNAPSHOT_READS=1` for explicit differential qualification.
This mode takes precedence over fast mode, collects the legacy result first,
and compares ordered canonical JSON including value types. A mismatch falls back
to the legacy result. Authoritative collector errors propagate. Both read flags
and the independent write flag default off. No finding payloads or exception
messages are written to the qualification logger.

With writes enabled, run the backfill command, then exercise authenticated
`GET /v1/findings?origin=scan`, exports and posture with qualification enabled.
Inspect `scan_snapshot_read` outcomes (`match`, `missing_or_stale`, `invalid`,
`mismatch`, `unavailable`). Disable qualification before measuring fast reads.
These signals describe parity and availability, not a clean security result.

## Remaining metadata-only history blocker

This fast path avoids per-selected-job reconstruction. It still loads full
retained job results and hashes the selected source. It does **not** make memory
or read cost independent of retained history. The current fold reads original
unified rows across retained history for first-seen dates and manual SLA policy,
including observations outside the display window. The current snapshot metadata
has neither that history projection nor a source revision tied atomically to the
authoritative job commit. Selecting only snapshot rows would lose history and
could accept stale inputs after same-ID updates or deletion.

A metadata-only rollout therefore requires a versioned, deletion-aware history
projection plus authoritative job revision/invalidation, and bounded queries for
selected identities. Until those gates are implemented and differentially tested,
the existing retained-history fold remains authoritative. Partial rescans, scope
selection, aggregate-parent exclusion and alternate IDs retain their current
behavior; no hidden snapshot-table history scan substitutes for it.
