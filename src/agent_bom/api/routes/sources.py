"""Hosted product source registry API routes."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request

from agent_bom.api.audit_log import log_action
from agent_bom.api.models import (
    ScanRequest,
    SourceCreate,
    SourceKind,
    SourceRecord,
    SourceStatus,
    SourceUpdate,
)
from agent_bom.api.routes.scan import enqueue_scan_job
from agent_bom.api.stores import _get_source_store, _get_store

router = APIRouter()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _tenant_id(request: Request) -> str:
    return getattr(request.state, "tenant_id", "default")


def _actor(request: Request) -> str:
    return getattr(request.state, "api_key_name", "") or getattr(request.state, "auth_method", "") or "system"


def _source_for_request(request: Request, source_id: str) -> SourceRecord:
    source = _get_source_store().get(source_id)
    tenant_id = _tenant_id(request)
    if source is None or source.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail=f"Source {source_id} not found")
    return source


def _apply_update(source: SourceRecord, body: SourceUpdate) -> SourceRecord:
    for field in (
        "display_name",
        "description",
        "owner",
        "connector_name",
        "credential_mode",
        "credential_ref",
        "enabled",
        "status",
        "config",
    ):
        value = getattr(body, field)
        if value is not None:
            setattr(source, field, value)
    source.updated_at = _now()
    if not source.enabled:
        source.status = SourceStatus.DISABLED
    elif source.status == SourceStatus.DISABLED:
        source.status = SourceStatus.CONFIGURED
    return source


def _request_for_source(source: SourceRecord) -> ScanRequest:
    config = dict(source.config or {})
    if "scan_request" in config and isinstance(config["scan_request"], dict):
        config = dict(config["scan_request"])

    if source.kind in (
        SourceKind.CONNECTOR_CLOUD_READ_ONLY,
        SourceKind.CONNECTOR_REGISTRY,
        SourceKind.CONNECTOR_WAREHOUSE,
    ):
        connector_name = source.connector_name or str(config.get("connector_name") or "").strip()
        if not connector_name:
            raise HTTPException(status_code=409, detail="Connector-backed sources require connector_name to run")
        config.setdefault("connectors", [connector_name])

    if source.kind in (SourceKind.INGEST_FLEET_SYNC, SourceKind.INGEST_TRACE_PUSH, SourceKind.INGEST_RESULT_PUSH):
        raise HTTPException(status_code=409, detail="Push-driven sources do not support Run now; they ingest from external producers")

    if source.kind in (SourceKind.RUNTIME_PROXY, SourceKind.RUNTIME_GATEWAY):
        raise HTTPException(status_code=409, detail="Runtime sources are audited by proxy/gateway traffic, not by direct scan jobs")

    return ScanRequest.model_validate(config)


@router.post("/v1/sources", tags=["sources"], status_code=201)
async def create_source(request: Request, body: SourceCreate) -> dict:
    tenant_id = _tenant_id(request)
    if body.tenant_id not in ("default", tenant_id):
        raise HTTPException(status_code=403, detail="Forbidden — tenant_id must match the authenticated tenant")

    now = _now()
    source = SourceRecord(
        source_id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        display_name=body.display_name,
        kind=body.kind,
        description=body.description,
        owner=body.owner,
        connector_name=body.connector_name,
        credential_mode=body.credential_mode,
        credential_ref=body.credential_ref,
        enabled=body.enabled,
        status=SourceStatus.CONFIGURED if body.enabled else SourceStatus.DISABLED,
        config=body.config,
        created_at=now,
        updated_at=now,
    )
    _get_source_store().put(source)
    log_action(
        "source.create",
        actor=_actor(request),
        resource=f"source/{source.source_id}",
        tenant_id=tenant_id,
        kind=source.kind.value,
        connector_name=source.connector_name,
    )
    return source.model_dump()


@router.get("/v1/sources", tags=["sources"])
async def list_sources(request: Request) -> dict:
    tenant_id = _tenant_id(request)
    sources = [source.model_dump() for source in _get_source_store().list_all(tenant_id=tenant_id)]
    return {"sources": sources, "count": len(sources)}


@router.get("/v1/sources/{source_id}", tags=["sources"])
async def get_source(request: Request, source_id: str) -> dict:
    return _source_for_request(request, source_id).model_dump()


@router.put("/v1/sources/{source_id}", tags=["sources"])
async def update_source(request: Request, source_id: str, body: SourceUpdate) -> dict:
    source = _apply_update(_source_for_request(request, source_id), body)
    _get_source_store().put(source)
    log_action(
        "source.update",
        actor=_actor(request),
        resource=f"source/{source_id}",
        tenant_id=source.tenant_id,
        enabled=source.enabled,
        status=source.status.value,
    )
    return source.model_dump()


@router.delete("/v1/sources/{source_id}", tags=["sources"], status_code=204)
async def delete_source(request: Request, source_id: str) -> None:
    source = _source_for_request(request, source_id)
    _get_source_store().delete(source_id)
    log_action(
        "source.delete",
        actor=_actor(request),
        resource=f"source/{source_id}",
        tenant_id=source.tenant_id,
        kind=source.kind.value,
    )


@router.post("/v1/sources/{source_id}/test", tags=["sources"])
async def test_source(request: Request, source_id: str) -> dict:
    source = _source_for_request(request, source_id)
    message = "Configuration recorded"
    status = SourceStatus.CONFIGURED

    if (
        source.kind
        in (
            SourceKind.CONNECTOR_CLOUD_READ_ONLY,
            SourceKind.CONNECTOR_REGISTRY,
            SourceKind.CONNECTOR_WAREHOUSE,
        )
        and source.connector_name
    ):
        from agent_bom.connectors import check_connector_health

        connector_status = check_connector_health(source.connector_name)
        status = SourceStatus.HEALTHY if connector_status.state.value == "healthy" else SourceStatus.DEGRADED
        message = connector_status.message
    elif source.kind in (SourceKind.RUNTIME_PROXY, SourceKind.RUNTIME_GATEWAY):
        message = "Runtime source is configured. Health comes from proxy/gateway audit and alert streams."
        status = SourceStatus.CONFIGURED
    elif source.kind in (SourceKind.INGEST_FLEET_SYNC, SourceKind.INGEST_TRACE_PUSH, SourceKind.INGEST_RESULT_PUSH):
        message = "Push-driven source is configured. Evidence arrives through authenticated ingest routes."
        status = SourceStatus.CONFIGURED
    else:
        _request_for_source(source)
        message = "Direct scan source is valid and can be launched from the control plane."
        status = SourceStatus.CONFIGURED

    source.last_tested_at = _now()
    source.last_test_status = status.value
    source.last_test_message = message
    if source.enabled:
        source.status = status
    source.updated_at = _now()
    _get_source_store().put(source)
    log_action(
        "source.test",
        actor=_actor(request),
        resource=f"source/{source_id}",
        tenant_id=source.tenant_id,
        status=status.value,
    )
    return {
        "source_id": source.source_id,
        "status": status.value,
        "message": message,
        "tested_at": source.last_tested_at,
    }


@router.post("/v1/sources/{source_id}/run", tags=["sources"], status_code=202)
async def run_source(request: Request, source_id: str) -> dict:
    source = _source_for_request(request, source_id)
    if not source.enabled:
        raise HTTPException(status_code=409, detail="Source is disabled")
    job = enqueue_scan_job(
        tenant_id=source.tenant_id,
        triggered_by=f"{_actor(request)}:source:{source.source_id}",
        request_body=_request_for_source(source),
        source_id=source.source_id,
    )
    source.last_run_at = _now()
    source.last_run_status = job.status.value
    source.last_job_id = job.job_id
    source.updated_at = _now()
    _get_source_store().put(source)
    log_action(
        "source.run",
        actor=_actor(request),
        resource=f"source/{source_id}",
        tenant_id=source.tenant_id,
        job_id=job.job_id,
    )
    return {"source_id": source.source_id, "job_id": job.job_id, "status": job.status.value}


@router.get("/v1/sources/{source_id}/jobs", tags=["sources"])
async def list_source_jobs(request: Request, source_id: str) -> dict:
    source = _source_for_request(request, source_id)
    jobs = [job.model_dump() for job in _get_store().list_all(tenant_id=source.tenant_id) if job.source_id == source.source_id]
    return {"source_id": source.source_id, "jobs": jobs, "count": len(jobs)}
