"""Materialize completed scan jobs into finding snapshots (ADR-015, phase 1).

Phase 1 is write-only: completed jobs are materialized behind the opt-in
``AGENT_BOM_SCAN_SNAPSHOTS`` setting and nothing reads the snapshots yet. A
snapshot holds only what is intrinsic to the job — its fold metadata from
``findings_current`` and the rows ``collect_scan_findings`` derives from the
retained result. Runtime evidence, triage owners, suppressions and other
mutable tenant state stay read-time.

Rows are persisted as the collection produces them, exactly as the job store
already persists the full result; the public response projection
(``safe_finding_response_payload``) is applied when findings are served, so the
snapshot never widens what an API caller can see.

Backfill or purge retained jobs for one tenant::

    python -m agent_bom.api.scan_snapshot backfill --tenant <tenant_id>
    python -m agent_bom.api.scan_snapshot purge --tenant <tenant_id>
"""

from __future__ import annotations

import argparse
import json
import logging
import sqlite3
import sys
from collections.abc import Callable, Sequence
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from agent_bom.api.finding_collection import collect_scan_findings
from agent_bom.api.findings_current import (
    finding_identity,
    job_has_authoritative_scan_evidence,
    scan_collection_incomplete_reasons,
    scan_evidence_authority_key,
    scan_scope_key,
)
from agent_bom.api.models import JobStatus, ScanJob
from agent_bom.api.scan_snapshot_store import ScanSnapshotStore, get_scan_snapshot_store, purge_tenant_snapshots
from agent_bom.api.storage.job_backends import configured_job_store
from agent_bom.api.tenant_worker import run_tenant_bound
from agent_bom.config import scan_snapshots_enabled
from agent_bom.core.tenancy import require_explicit_tenant_id
from agent_bom.security import sanitize_error, sanitize_text

if TYPE_CHECKING:
    from agent_bom.api.scan_context import ScanContext

_logger = logging.getLogger(__name__)

# Bump when intrinsic row derivation changes; readers ignore other versions.
SCAN_SNAPSHOT_ROW_SCHEMA_VERSION = 1


def _utc(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return ""
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat()


def materialize_job_snapshot(job: ScanJob) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Derive one job's snapshot metadata and intrinsic finding rows.

    Uses the fold's own derivations so a later reader selects jobs exactly as
    ``current_scan_findings`` does. ``collect_scan_findings`` runs without an
    enrichment callback: nothing here reads mutable tenant state.
    """
    evidence_at, authority_completed_at, _ = scan_evidence_authority_key(job)
    rows: list[dict[str, Any]] = []
    for finding in collect_scan_findings(job):
        payload = json.loads(json.dumps(finding, default=str))
        rows.append(
            {
                "finding_identity": finding_identity(payload),
                "canonical_id": str(payload.get("canonical_id") or ""),
                "severity": str(payload.get("severity") or "").lower(),
                "payload": payload,
            }
        )
    meta = {
        "scope_key": scan_scope_key(job),
        "authority_evidence_at": evidence_at,
        "authority_completed_at": authority_completed_at,
        "authoritative": job_has_authoritative_scan_evidence(job),
        "incomplete_reasons": scan_collection_incomplete_reasons(job),
        "completed_at": _utc(job.completed_at) or _utc(job.created_at),
        "created_at": _utc(job.created_at),
        "row_schema_version": SCAN_SNAPSHOT_ROW_SCHEMA_VERSION,
        "row_count": len(rows),
        "materialized_at": datetime.now(timezone.utc).isoformat(),
    }
    return meta, rows


def snapshot_eligible(job: ScanJob) -> bool:
    """The fold's own eligibility: a ``DONE`` job with a result document.

    Non-authoritative attempts (skipped or failed outcomes) are materialized
    too, flagged ``authoritative=False``: the fold reads them to mark earlier
    findings unreconfirmed, so a reader needs their metadata.
    """
    return job.status == JobStatus.DONE and isinstance(job.result, dict)


def write_job_snapshot(job: ScanJob, store: ScanSnapshotStore | None = None) -> int:
    """Materialize and persist one eligible job; returns the stored row count."""
    meta, rows = materialize_job_snapshot(job)
    (store or get_scan_snapshot_store()).put_snapshot(require_explicit_tenant_id(job.tenant_id), job.job_id, meta, rows)
    return len(rows)


def record_job_snapshot(job: ScanJob, result: dict[str, Any] | None) -> bool:
    """Best-effort post-completion write; never changes the job's outcome.

    ``result`` is the document captured before the hot cache compacted the
    in-process job, so materialization reads what the job store persisted.
    """
    if not scan_snapshots_enabled():
        return False
    snapshot_job = job.model_copy(update={"result": result})
    if not snapshot_eligible(snapshot_job):
        return False
    try:
        write_job_snapshot(snapshot_job)
    except Exception as exc:  # broad-except: derived snapshot failures fall back to rebuilding; the job is already durably DONE
        _logger.warning("scan snapshot materialization failed job=%s: %s", sanitize_text(job.job_id), sanitize_text(exc))
        return False
    return True


def finalize_with_scan_snapshot(ctx: ScanContext, persist: Callable[..., tuple[Any, JobStatus]]) -> tuple[Any, JobStatus]:
    """Persist the final job state, then snapshot a durably ``DONE`` job.

    Materialization runs only after the job store accepted the final write and
    only for scans whose side effects are enabled (not dry-run / no-scan).
    """
    result = ctx.job.result
    store, terminal_status = persist(ctx.job, ctx.lock)
    if terminal_status is JobStatus.DONE and ctx.side_effects_enabled:
        record_job_snapshot(ctx.job, result if isinstance(result, dict) else None)
    return store, terminal_status


def backfill_tenant_snapshots(tenant_id: str, job_store: Any, store: ScanSnapshotStore | None = None) -> dict[str, int]:
    """Materialize every retained ``DONE`` job of one tenant, one job at a time."""
    counts = {"materialized": 0, "skipped": 0, "failed": 0}
    for summary in job_store.list_summary(tenant_id=tenant_id, status=JobStatus.DONE):
        job = job_store.get(str(summary.get("job_id") or ""), tenant_id=tenant_id)
        if job is None or not snapshot_eligible(job):
            counts["skipped"] += 1
            continue
        try:
            write_job_snapshot(job, store)
        except Exception as exc:  # broad-except: one unreadable job must not abort the remaining tenant backfill
            _logger.warning("scan snapshot backfill failed job=%s: %s", sanitize_text(job.job_id), sanitize_text(exc))
            counts["failed"] += 1
            continue
        counts["materialized"] += 1
    return counts


def _run(action: str, tenant_id: str) -> dict[str, Any]:
    if action == "purge":
        return {"removed": run_tenant_bound(tenant_id, purge_tenant_snapshots, tenant_id)}
    return run_tenant_bound(tenant_id, backfill_tenant_snapshots, tenant_id, configured_job_store())


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m agent_bom.api.scan_snapshot", description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("action", choices=("backfill", "purge"))
    parser.add_argument("--tenant", required=True, help="tenant whose retained scan jobs are materialized or purged")
    args = parser.parse_args(argv)
    if args.action == "backfill" and not scan_snapshots_enabled():
        sys.stderr.write("error: set AGENT_BOM_SCAN_SNAPSHOTS=1 to materialize scan snapshots\n")
        return 2
    try:
        tenant_id = require_explicit_tenant_id(args.tenant)
        receipt = _run(args.action, tenant_id)
    except (OSError, RuntimeError, ValueError, sqlite3.Error) as exc:
        sys.stderr.write(sanitize_error(exc, generic=True) + "\n")
        return 1
    sys.stdout.write(json.dumps({"tenant_id": tenant_id, "action": args.action, **receipt}, sort_keys=True) + "\n")
    return 1 if receipt.get("failed") else 0


if __name__ == "__main__":
    raise SystemExit(main())
