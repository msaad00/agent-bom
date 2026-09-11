"""Background worker for async findings report exports."""

from __future__ import annotations

import gzip
import json
import logging
import os
import secrets
import threading
from datetime import datetime, timezone
from pathlib import Path

from agent_bom.api.models import JobStatus, ReportJob
from agent_bom.api.report_artifact_store import publish_report_artifact
from agent_bom.api.report_job_store import ReportClaim, ReportJobStore, get_report_job_store
from agent_bom.security import sanitize_error, sanitize_text

_logger = logging.getLogger(__name__)


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def report_artifact_root() -> Path:
    raw = (os.environ.get("AGENT_BOM_REPORT_ARTIFACT_DIR") or "").strip()
    if raw:
        return Path(raw)
    return Path.home() / ".agent-bom" / "report-artifacts"


def _artifact_path(tenant_id: str, job_id: str) -> Path:
    safe_tenant = tenant_id.replace("/", "_").replace("\\", "_") or "default"
    return report_artifact_root() / safe_tenant / f"{job_id}.ndjson.gz"


def submit_report_job(job_id: str, tenant_id: str) -> None:
    """Wake bounded workers; admission already committed the durable queue row."""
    from agent_bom.api.report_queue import wake_report_worker

    wake_report_worker()


def _run_report_job_sync(job_id: str, tenant_id: str) -> None:
    """Run one targeted claim synchronously for embedded callers and tests."""
    store = get_report_job_store()
    claim = store.claim_next(60, 3, job_id=job_id, tenant_id=tenant_id)
    if claim:
        run_claimed_report(store, claim, threading.Event())


def run_claimed_report(store: ReportJobStore, claim: ReportClaim, lost: threading.Event) -> None:
    job = store.get(claim.job_id, claim.tenant_id)
    if job is None or job.status != JobStatus.RUNNING or lost.is_set():
        return
    path: Path | None = _artifact_path(job.tenant_id, f"{job.job_id}.{claim.token}")
    try:
        row_count, byte_count, download_token, path = _write_findings_artifact(job, claim.token, lost)
        if lost.is_set():
            return
        # Each attempt owns a distinct local path AND object key. A stale worker
        # cannot overwrite the artifact selected by a newer successful claim.
        published = publish_report_artifact(path, tenant_id=job.tenant_id, job_id=job.job_id, attempt=claim.token)
        job.status = JobStatus.DONE
        job.row_count = row_count
        job.byte_count = byte_count
        job.download_token = download_token
        job.artifact_backend = published.backend
        job.artifact_uri = published.artifact_uri
        job.presigned_download_url = None  # refreshed after authenticated reads
        job.completed_at = _now_iso()
        if lost.is_set() or not store.finish(job, claim):
            return
        path = None  # preserve the winning artifact
        _audit_report(job, "report.export_completed")
    except Exception as exc:  # noqa: BLE001
        safe = sanitize_error(exc, generic=True)
        _logger.warning("Report export failed: %s", sanitize_text(safe))
        job.status = JobStatus.FAILED
        job.completed_at = _now_iso()
        job.error = safe
        if not lost.is_set() and store.finish(job, claim):
            _audit_report(job, "report.export_failed")
    finally:
        if path is not None:
            path.unlink(missing_ok=True)


def _audit_report(job: ReportJob, action: str) -> None:
    from agent_bom.api.metrics import record_report_export

    record_report_export("completed" if job.status == JobStatus.DONE else "failed")
    try:
        from agent_bom.api.audit_log import log_action

        log_action(
            action,
            actor="system",
            tenant_id=job.tenant_id,
            details={
                "job_id": job.job_id,
                "row_count": job.row_count,
                "byte_count": job.byte_count,
                "format": job.format.value,
                "artifact_backend": job.artifact_backend,
            },
        )
    except Exception:  # noqa: BLE001
        _logger.warning("Report export audit append unavailable", exc_info=False)


def _write_findings_artifact(job: ReportJob, attempt: str, lost: threading.Event) -> tuple[int, int, str, Path]:
    from agent_bom.api import time_window
    from agent_bom.api.routes.scan import _canonical_scope_filters
    from agent_bom.export.runner import iter_current_findings

    resolved_window = time_window.normalize_window_days(job.window_days)
    since = time_window.window_since_iso(resolved_window, now=datetime.fromisoformat(job.created_at.replace("Z", "+00:00")))
    scope = _canonical_scope_filters(
        job.provider,
        job.account,
        job.environment,
        job.domain,
        job.finding_class,
        job.q,
        owner=job.owner,
        sla=job.sla,
    )

    path = _artifact_path(job.tenant_id, f"{job.job_id}.{attempt}")
    path.parent.mkdir(parents=True, exist_ok=True)

    row_count = 0
    with gzip.open(path, "wt", encoding="utf-8") as handle:
        for row in iter_current_findings(
            job.tenant_id,
            sort=job.sort,
            severity=job.severity,
            since=since,
            scan_id=job.scan_id,
            scope=scope,
            status=job.finding_status,
        ):
            if lost.is_set():
                raise RuntimeError("Report claim is no longer owned")
            handle.write(json.dumps(row, separators=(",", ":"), ensure_ascii=True))
            handle.write("\n")
            row_count += 1

    byte_count = path.stat().st_size
    return row_count, byte_count, secrets.token_urlsafe(32), path


def resolve_report_artifact(job: ReportJob) -> Path | None:
    if job.status != JobStatus.DONE:
        return None
    expected = _artifact_path(job.tenant_id, job.job_id)
    path = Path(job.artifact_uri) if job.artifact_backend == "local" and job.artifact_uri else expected
    if path.resolve().parent != expected.resolve().parent or not path.name.startswith(job.job_id + "."):
        return None
    return path if path.is_file() else None
