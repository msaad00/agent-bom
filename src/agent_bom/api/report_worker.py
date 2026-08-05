"""Background worker for async findings report exports."""

from __future__ import annotations

import gzip
import json
import logging
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path

from agent_bom.api.models import JobStatus, ReportJob
from agent_bom.api.pipeline import get_executor
from agent_bom.api.report_artifact_store import publish_report_artifact
from agent_bom.api.report_job_store import get_report_job_store
from agent_bom.api.tenant_worker import submit_tenant_bound
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
    """Queue a report export on the shared scan worker pool."""
    submit_tenant_bound(get_executor(), tenant_id, _run_report_job_sync, job_id, tenant_id)


def _run_report_job_sync(job_id: str, tenant_id: str) -> None:
    store = get_report_job_store()
    job = store.get(job_id, tenant_id)
    if job is None:
        return
    job.status = JobStatus.RUNNING
    job.started_at = _now_iso()
    store.update(job)

    try:
        row_count, byte_count, download_token, artifact_path = _write_findings_artifact(job)
        published = publish_report_artifact(artifact_path, tenant_id=tenant_id, job_id=job_id)
    except Exception as exc:  # noqa: BLE001
        safe = sanitize_error(exc)
        _logger.warning("Report job %s failed: %s", job_id, sanitize_text(safe))
        failed = store.get(job_id, tenant_id)
        if failed is None:
            return
        failed.status = JobStatus.FAILED
        failed.completed_at = _now_iso()
        failed.error = safe
        store.update(failed)
        try:
            from agent_bom.api.audit_log import log_action

            log_action(
                "report.export_failed",
                actor="system",
                tenant_id=tenant_id,
                details={"job_id": job_id, "error": safe},
            )
        except Exception:  # noqa: BLE001
            pass
        return

    done = store.get(job_id, tenant_id)
    if done is None:
        return
    done.status = JobStatus.DONE
    done.completed_at = _now_iso()
    done.row_count = row_count
    done.byte_count = byte_count
    done.download_token = download_token
    done.artifact_backend = published.backend
    done.artifact_uri = published.artifact_uri
    done.presigned_download_url = published.presigned_download_url
    store.update(done)
    try:
        from agent_bom.api.audit_log import log_action

        log_action(
            "report.export_completed",
            actor="system",
            tenant_id=tenant_id,
            details={
                "job_id": job_id,
                "row_count": row_count,
                "byte_count": byte_count,
                "format": done.format.value,
                "artifact_backend": published.backend,
                "artifact_uri": published.artifact_uri,
            },
        )
    except Exception:  # noqa: BLE001
        pass


def _write_findings_artifact(job: ReportJob) -> tuple[int, int, str, Path]:
    from agent_bom.api import time_window
    from agent_bom.api.routes.scan import _canonical_scope_filters
    from agent_bom.export.runner import iter_current_findings

    resolved_window = time_window.normalize_window_days(job.window_days)
    since = time_window.window_since_iso(resolved_window)
    scope = _canonical_scope_filters(
        job.provider,
        job.account,
        job.environment,
        job.domain,
        job.finding_class,
        job.q,
    )

    path = _artifact_path(job.tenant_id, job.job_id)
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
            handle.write(json.dumps(row, separators=(",", ":"), ensure_ascii=True))
            handle.write("\n")
            row_count += 1

    byte_count = path.stat().st_size
    return row_count, byte_count, secrets.token_urlsafe(32), path


def resolve_report_artifact(job: ReportJob) -> Path | None:
    if job.status != JobStatus.DONE:
        return None
    path = _artifact_path(job.tenant_id, job.job_id)
    return path if path.is_file() else None
