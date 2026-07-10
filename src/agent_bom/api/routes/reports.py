"""Async findings report export routes."""

from __future__ import annotations

import os
import secrets
import uuid
from typing import Annotated

from fastapi import APIRouter, Header, HTTPException, Query, Request
from fastapi.responses import FileResponse

from agent_bom.api.models import JobStatus, ReportJob, ReportJobRequest
from agent_bom.api.pipeline import _now
from agent_bom.api.report_job_store import get_report_job_store
from agent_bom.api.report_worker import resolve_report_artifact, submit_report_job
from agent_bom.api.tenancy import require_request_tenant_id
from agent_bom.config import API_MAX_ACTIVE_REPORT_JOBS_PER_TENANT

router = APIRouter()

# Downloading a completed report is authorized by a job-scoped token. The token
# is presented via this request header rather than the URL query string, so it
# never lands in access logs, browser history, or the Referer header.
DOWNLOAD_TOKEN_HEADER = "X-Agent-Bom-Download-Token"


def _tenant_id(request: Request) -> str:
    return require_request_tenant_id(request)


def _job_payload(job: ReportJob, *, request: Request) -> dict:
    payload = job.model_dump(mode="json")
    payload.pop("download_token", None)
    payload.pop("presigned_download_url", None)
    if job.status == JobStatus.DONE:
        if job.presigned_download_url:
            payload["download_url"] = job.presigned_download_url
        elif job.download_token:
            # Return the download URL WITHOUT the token in the query string.
            # The caller presents the token via the DOWNLOAD_TOKEN_HEADER header
            # (preferred) or, for backward compatibility, the ?token= query
            # param — but we never MINT a token-bearing URL here.
            payload["download_url"] = str(request.url_for("download_report_artifact", job_id=job.job_id))
            payload["download_token"] = job.download_token
            payload["download_token_header"] = DOWNLOAD_TOKEN_HEADER
    return payload


def _active_report_jobs_limit() -> int:
    raw = os.environ.get("AGENT_BOM_API_MAX_ACTIVE_REPORT_JOBS_PER_TENANT")
    if raw is not None and str(raw).strip():
        return int(raw)
    return API_MAX_ACTIVE_REPORT_JOBS_PER_TENANT


def _enforce_active_report_quota(tenant_id: str) -> None:
    limit = _active_report_jobs_limit()
    if limit <= 0:
        return
    active = sum(
        1
        for job in get_report_job_store().list_for_tenant(tenant_id)
        if job.status in (JobStatus.PENDING, JobStatus.RUNNING)
    )
    if active >= limit:
        raise HTTPException(
            status_code=429,
            detail=f"Active report export limit reached ({limit} pending or running jobs)",
        )


@router.post("/reports", tags=["reports"], status_code=202)
async def create_report_job(request: Request, body: ReportJobRequest) -> dict:
    """Enqueue an async findings export (gzipped NDJSON) instead of a synchronous body."""
    tenant_id = _tenant_id(request)
    _enforce_active_report_quota(tenant_id)
    job = ReportJob(
        job_id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        status=JobStatus.PENDING,
        format=body.format,
        sort=body.sort,
        severity=body.severity,
        created_at=_now(),
    )
    get_report_job_store().put(job)
    submit_report_job(job.job_id, tenant_id)
    return _job_payload(job, request=request)


@router.get("/reports/{job_id}", tags=["reports"])
async def get_report_job(request: Request, job_id: str) -> dict:
    """Return async report job status and download URL when complete."""
    tenant_id = _tenant_id(request)
    job = get_report_job_store().get(job_id, tenant_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Report job not found")
    return _job_payload(job, request=request)


@router.get("/reports/{job_id}/download", tags=["reports"], name="download_report_artifact")
async def download_report_artifact(
    request: Request,
    job_id: str,
    token: Annotated[str | None, Query(min_length=8, max_length=256)] = None,
    header_token: Annotated[str | None, Header(alias=DOWNLOAD_TOKEN_HEADER, min_length=8, max_length=256)] = None,
) -> FileResponse:
    """Download a completed report artifact using the job-scoped token.

    The token is presented via the ``X-Agent-Bom-Download-Token`` header
    (preferred, keeps it out of logs) or the legacy ``?token=`` query param.
    """
    tenant_id = _tenant_id(request)
    job = get_report_job_store().get(job_id, tenant_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Report job not found")
    if job.status != JobStatus.DONE or not job.download_token:
        raise HTTPException(status_code=409, detail="Report artifact is not ready")
    presented_token = header_token or token
    if not presented_token:
        raise HTTPException(status_code=401, detail=f"Missing download token; provide the {DOWNLOAD_TOKEN_HEADER} header")
    if not secrets.compare_digest(job.download_token, presented_token):
        raise HTTPException(status_code=403, detail="Invalid download token")
    path = resolve_report_artifact(job)
    if path is None:
        raise HTTPException(status_code=410, detail="Report artifact is unavailable")
    filename = f"findings-{job_id[:8]}.ndjson.gz"
    return FileResponse(path, media_type="application/gzip", filename=filename)
