"""Background worker for async findings report exports."""

from __future__ import annotations

import gzip
import json
import logging
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path

from agent_bom.api.compliance_hub_store import get_compliance_hub_store
from agent_bom.api.models import JobStatus, ReportJob
from agent_bom.api.pipeline import get_executor
from agent_bom.api.report_job_store import get_report_job_store
from agent_bom.security import sanitize_error, sanitize_text

_logger = logging.getLogger(__name__)

_PAGE_SIZE = 500


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
    get_executor().submit(_run_report_job_sync, job_id, tenant_id)


def _run_report_job_sync(job_id: str, tenant_id: str) -> None:
    store = get_report_job_store()
    job = store.get(job_id, tenant_id)
    if job is None:
        return
    job.status = JobStatus.RUNNING
    job.started_at = _now_iso()
    store.update(job)

    try:
        row_count, byte_count, download_token = _write_findings_artifact(job)
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
    store.update(done)
    try:
        from agent_bom.api.audit_log import log_action

        log_action(
            "report.export_completed",
            actor="system",
            tenant_id=tenant_id,
            details={"job_id": job_id, "row_count": row_count, "byte_count": byte_count, "format": done.format.value},
        )
    except Exception:  # noqa: BLE001
        pass


def _write_findings_artifact(job: ReportJob) -> tuple[int, int, str]:
    hub = get_compliance_hub_store()
    list_page = getattr(hub, "list_current_page", None)
    if not callable(list_page):
        raise RuntimeError("Compliance hub store does not support current-state finding exports")

    path = _artifact_path(job.tenant_id, job.job_id)
    path.parent.mkdir(parents=True, exist_ok=True)

    row_count = 0
    cursor: str | None = None
    with gzip.open(path, "wt", encoding="utf-8") as handle:
        while True:
            page, _total, next_cursor = list_page(
                job.tenant_id,
                limit=_PAGE_SIZE,
                sort=job.sort,
                severity=job.severity,
                include_total=cursor is None,
                cursor=cursor,
            )
            for row in page:
                handle.write(json.dumps(row, separators=(",", ":"), ensure_ascii=True))
                handle.write("\n")
                row_count += 1
            if not next_cursor:
                break
            cursor = next_cursor

    byte_count = path.stat().st_size
    return row_count, byte_count, secrets.token_urlsafe(32)


def resolve_report_artifact(job: ReportJob) -> Path | None:
    if job.status != JobStatus.DONE:
        return None
    path = _artifact_path(job.tenant_id, job.job_id)
    return path if path.is_file() else None
