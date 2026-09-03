"""Hosted product source registry API routes."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Annotated
from urllib.parse import urlsplit

import anyio.to_thread
from fastapi import APIRouter, Header, HTTPException, Query, Request
from pydantic import ValidationError

from agent_bom.api.audit_log import log_action
from agent_bom.api.correlation_cohort_receipts import (
    CorrelationCohortReceiptError,
    issue_correlation_cohort_child_receipt,
)
from agent_bom.api.idempotency_store import IdempotencyConflictError, idempotency_request_fingerprint
from agent_bom.api.models import (
    CredentialRefStatus,
    ScanRequest,
    SourceCohortRunRequest,
    SourceCohortRunResponse,
    SourceCreate,
    SourceCredentialMode,
    SourceKind,
    SourceRecord,
    SourceStatus,
    SourceUpdate,
)
from agent_bom.api.routes.scan import (
    _sanitize_scan_request_paths,
    correlation_cohort_id,
    enqueue_correlation_cohort,
    enqueue_scan_job,
)
from agent_bom.api.scan_batches import scan_request_targets
from agent_bom.api.stores import (
    _get_credential_ref_store,
    _get_idempotency_store,
    _get_schedule_store,
    _get_source_store,
    _get_store,
)
from agent_bom.api.tenancy import require_body_tenant_match, require_request_tenant_id
from agent_bom.api.tenant_quota import enforce_active_scan_quota, enforce_retained_jobs_quota, tenant_quota_guard
from agent_bom.security import sanitize_error, sanitize_text

router = APIRouter()

_RUNNABLE_SOURCE_KINDS = frozenset(
    {
        SourceKind.SCAN_REPO,
        SourceKind.SCAN_IMAGE,
        SourceKind.SCAN_IAC,
        SourceKind.SCAN_CLOUD,
        SourceKind.SCAN_MCP_CONFIG,
        SourceKind.INGEST_ARTIFACT_IMPORT,
        SourceKind.CONNECTOR_CLOUD_READ_ONLY,
        SourceKind.CONNECTOR_REGISTRY,
        SourceKind.CONNECTOR_WAREHOUSE,
    }
)
_COHORT_EXTERNAL_SOURCE_KINDS = frozenset(
    {
        SourceKind.INGEST_RESULT_PUSH,
        SourceKind.RUNTIME_PROXY,
        SourceKind.RUNTIME_GATEWAY,
    }
)


def _safe_validation_errors(exc: ValidationError) -> list[dict[str, object]]:
    """Return actionable validation metadata without echoing config values."""
    return [
        {
            "type": error.get("type", "value_error"),
            "loc": list(error.get("loc", ())),
            "msg": error.get("msg", "Invalid scan request"),
        }
        for error in exc.errors()
    ]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _tenant_id(request: Request) -> str:
    return require_request_tenant_id(request)


def _actor(request: Request) -> str:
    return getattr(request.state, "api_key_name", "") or getattr(request.state, "auth_method", "") or "system"


def _source_for_request(request: Request, source_id: str) -> SourceRecord:
    source = _get_source_store().get(source_id)
    tenant_id = _tenant_id(request)
    if source is None or source.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail=f"Source {source_id} not found")
    return source


def _validate_credential_ref(request: Request, source: SourceRecord) -> None:
    _validate_credential_ref_for_tenant(_tenant_id(request), source)


def _validate_credential_ref_for_tenant(tenant_id: str, source: SourceRecord) -> None:
    credential_mode = source.credential_mode or SourceCredentialMode.NONE
    if not source.credential_ref:
        if credential_mode == SourceCredentialMode.REFERENCE:
            raise HTTPException(status_code=422, detail="credential_mode=reference requires credential_ref")
        return
    if credential_mode != SourceCredentialMode.REFERENCE:
        raise HTTPException(status_code=422, detail="credential_ref requires credential_mode=reference")
    credential = _get_credential_ref_store().get(source.credential_ref, tenant_id=tenant_id)
    if credential is None or credential.tenant_id != tenant_id:
        raise HTTPException(status_code=409, detail="Source credential_ref is not available in this tenant")
    if not credential.enabled or credential.status in (CredentialRefStatus.DISABLED, CredentialRefStatus.RETIRED):
        raise HTTPException(status_code=409, detail="Source credential_ref is disabled or retired")
    if source.kind in _RUNNABLE_SOURCE_KINDS:
        raise HTTPException(
            status_code=409,
            detail=(
                "credential_ref is governance metadata and is not an executable credential binding; "
                "use a brokered cloud connection or server-configured connector credentials"
            ),
        )


def _apply_update(source: SourceRecord, body: SourceUpdate) -> SourceRecord:
    # Stores may return a live object reference. Validate a detached candidate
    # so a rejected update cannot mutate the persisted source in place.
    source = source.model_copy(deep=True)
    nullable_fields = {"connector_name", "credential_ref"}
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
        if field not in body.model_fields_set:
            continue
        value = getattr(body, field)
        if value is not None or field in nullable_fields:
            setattr(source, field, value)
    source.updated_at = _now()
    if not source.enabled:
        source.status = SourceStatus.DISABLED
    elif source.status == SourceStatus.DISABLED:
        source.status = SourceStatus.CONFIGURED
    return source


def _require_source_target(source: SourceRecord, request: ScanRequest) -> None:
    """Reject a runnable source that would otherwise launch a default scan."""
    has_target = True
    required = ""
    if source.kind == SourceKind.SCAN_REPO:
        has_target = bool(
            (request.repo_url or "").strip() or request.agent_projects or request.gha_path or request.sbom or request.filesystem_paths
        )
        required = "repo_url, agent_projects, gha_path, sbom, or filesystem_paths"
    elif source.kind == SourceKind.SCAN_IMAGE:
        has_target = bool(request.images)
        required = "images"
    elif source.kind == SourceKind.SCAN_IAC:
        has_target = bool((request.repo_url or "").strip() or request.tf_dirs or request.k8s)
        required = "repo_url, tf_dirs, or k8s"
    elif source.kind == SourceKind.SCAN_CLOUD:
        has_target = bool(request.connectors or request.inventory)
        required = "connectors or inventory"
    elif source.kind == SourceKind.SCAN_MCP_CONFIG:
        has_target = bool((request.repo_url or "").strip() or request.inventory or request.agent_projects or request.discover_host)
        required = "repo_url, inventory, agent_projects, or discover_host"
    elif source.kind == SourceKind.INGEST_ARTIFACT_IMPORT:
        has_target = bool(request.inventory or request.sbom or request.external_scan or request.vex)
        required = "inventory, sbom, external_scan, or vex"

    if not has_target:
        raise HTTPException(
            status_code=422,
            detail=f"{source.kind.value} source requires {required} in config.scan_request",
        )


def _validate_source_repo_url(request: ScanRequest) -> ScanRequest:
    """Reject unsafe stored repo targets without performing network I/O."""
    if not request.repo_url:
        return request
    repo_url = request.repo_url.strip()
    try:
        parts = urlsplit(repo_url)
        safe = (
            parts.scheme in {"http", "https"}
            and bool(parts.hostname)
            and parts.username is None
            and parts.password is None
            and not any(ord(char) < 0x20 or char.isspace() for char in repo_url)
        )
    except ValueError:
        safe = False
    if not safe:
        raise HTTPException(status_code=422, detail="repo_url must be an HTTP(S) URL without embedded credentials")
    return request.model_copy(update={"repo_url": repo_url})


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
        config.pop("connector_name", None)
        config.setdefault("connectors", [connector_name])

    if source.kind in (SourceKind.INGEST_FLEET_SYNC, SourceKind.INGEST_TRACE_PUSH, SourceKind.INGEST_RESULT_PUSH):
        raise HTTPException(status_code=409, detail="Push-driven sources do not support Run now; they ingest from external producers")

    if source.kind in (SourceKind.RUNTIME_PROXY, SourceKind.RUNTIME_GATEWAY):
        raise HTTPException(status_code=409, detail="Runtime sources are audited by proxy/gateway traffic, not by direct scan jobs")

    try:
        request = ScanRequest.model_validate(config)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=_safe_validation_errors(exc)) from exc
    request = _validate_source_repo_url(request)
    _require_source_target(source, request)
    # Source runs enqueue directly rather than entering POST /v1/scan. Apply
    # the identical local-path jail before either Test or Run can accept the
    # source configuration.
    return _sanitize_scan_request_paths(request)


@router.post("/sources", tags=["sources"], status_code=201)
async def create_source(request: Request, body: SourceCreate) -> dict:
    tenant_id = _tenant_id(request)
    require_body_tenant_match(body.tenant_id, tenant_id)

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
    with tenant_quota_guard(tenant_id):
        _validate_credential_ref_for_tenant(tenant_id, source)
        if source.kind in _RUNNABLE_SOURCE_KINDS:
            _request_for_source(source)
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


@router.get("/sources", tags=["sources"])
async def list_sources(
    request: Request,
    # cap pagination so hostile callers cannot probe an
    # entire tenant's source registry in a single request.
    limit: Annotated[int, Query(ge=1, le=1000)] = 1000,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict:
    tenant_id = _tenant_id(request)
    all_sources = [source.model_dump() for source in _get_source_store().list_all(tenant_id=tenant_id)]
    total = len(all_sources)
    page = all_sources[offset : offset + limit]
    return {
        # schema_version on terminal list response.
        "schema_version": "v1",
        "sources": page,
        "count": len(page),
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/sources/{source_id}", tags=["sources"])
async def get_source(request: Request, source_id: str) -> dict:
    return _source_for_request(request, source_id).model_dump()


@router.put("/sources/{source_id}", tags=["sources"])
async def update_source(request: Request, source_id: str, body: SourceUpdate) -> dict:
    tenant_id = _tenant_id(request)
    with tenant_quota_guard(tenant_id):
        source = _apply_update(_source_for_request(request, source_id), body)
        _validate_credential_ref_for_tenant(tenant_id, source)
        if source.kind in _RUNNABLE_SOURCE_KINDS:
            _request_for_source(source)
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


@router.delete("/sources/{source_id}", tags=["sources"], status_code=204)
async def delete_source(request: Request, source_id: str) -> None:
    tenant_id = _tenant_id(request)
    with tenant_quota_guard(tenant_id):
        source = _source_for_request(request, source_id)
        schedule_store = _get_schedule_store()
        linked_schedules = [
            schedule
            for schedule in schedule_store.list_all(tenant_id=tenant_id)
            if str(schedule.scan_config.get("source_id") or "") == source_id
        ]
        # Disable first so any backend failure after source removal remains
        # fail-safe: a retained cleanup record cannot launch another scan.
        for schedule in linked_schedules:
            schedule.enabled = False
            schedule.next_run = None
            schedule.updated_at = _now()
            schedule_store.put(schedule)
        if not _get_source_store().delete(source_id):
            raise HTTPException(status_code=409, detail="Source changed while it was being deleted; retry")
        for schedule in linked_schedules:
            schedule_store.delete(schedule.schedule_id, tenant_id=tenant_id)
    log_action(
        "source.delete",
        actor=_actor(request),
        resource=f"source/{source_id}",
        tenant_id=source.tenant_id,
        kind=source.kind.value,
        linked_schedules=len(linked_schedules),
    )


@router.post("/sources/{source_id}/test", tags=["sources"])
async def test_source(request: Request, source_id: str) -> dict:
    tenant_id = _tenant_id(request)
    source = _source_for_request(request, source_id).model_copy(deep=True)
    _validate_credential_ref(request, source)
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

        connector_status = await anyio.to_thread.run_sync(check_connector_health, source.connector_name)
        status = SourceStatus.HEALTHY if connector_status.state.value == "healthy" else SourceStatus.DEGRADED
        message = sanitize_text(connector_status.message)
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

    with tenant_quota_guard(tenant_id):
        current = _source_for_request(request, source_id)
        if current != source:
            raise HTTPException(status_code=409, detail="Source changed while the health check was running; retry")
        _validate_credential_ref_for_tenant(tenant_id, current)
        current.last_tested_at = _now()
        current.last_test_status = status.value
        current.last_test_message = message
        if current.enabled:
            current.status = status
        current.updated_at = _now()
        _get_source_store().put(current)
        source = current
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


@router.post("/sources/{source_id}/run", tags=["sources"], status_code=202)
async def run_source(request: Request, source_id: str) -> dict:
    tenant_id = _tenant_id(request)
    source = _source_for_request(request, source_id).model_copy(deep=True)
    if not source.enabled:
        raise HTTPException(status_code=409, detail="Source is disabled")
    _validate_credential_ref(request, source)
    _request_for_source(source)
    with tenant_quota_guard(tenant_id):
        current = _source_for_request(request, source_id)
        if current != source:
            raise HTTPException(status_code=409, detail="Source changed while the scan was being prepared; retry")
        if not current.enabled:
            raise HTTPException(status_code=409, detail="Source is disabled")
        _validate_credential_ref_for_tenant(tenant_id, current)
        request_body = _request_for_source(current)
        target_count = len(scan_request_targets(request_body))
        attempted_jobs = target_count + 1 if target_count > 1 else 1
        enforce_active_scan_quota(tenant_id, attempted=attempted_jobs)
        enforce_retained_jobs_quota(tenant_id, attempted=attempted_jobs)
        job = enqueue_scan_job(
            tenant_id=current.tenant_id,
            triggered_by=f"{_actor(request)}:source:{current.source_id}",
            request_body=request_body,
            source_id=current.source_id,
            quota_guarded=True,
        )
        current.last_run_at = _now()
        current.last_run_status = job.status.value
        current.last_job_id = job.job_id
        current.updated_at = _now()
        _get_source_store().put(current)
        source = current
    log_action(
        "source.run",
        actor=_actor(request),
        resource=f"source/{source_id}",
        tenant_id=source.tenant_id,
        job_id=job.job_id,
    )
    return {"source_id": source.source_id, "job_id": job.job_id, "status": job.status.value}


@router.post(
    "/sources/run-cohort",
    tags=["sources"],
    status_code=202,
    response_model=SourceCohortRunResponse,
)
async def run_source_cohort(
    request: Request,
    body: SourceCohortRunRequest,
    idempotency_key: Annotated[str, Header(alias="Idempotency-Key", min_length=1, max_length=200)],
) -> SourceCohortRunResponse:
    """Run exact registered sources and auto-correlate their immutable scan outputs."""

    tenant_id = _tenant_id(request)
    idempotency_key = idempotency_key.strip()
    if not idempotency_key:
        raise HTTPException(status_code=422, detail="Idempotency-Key header is required")
    if len(idempotency_key) > 200:
        raise HTTPException(status_code=422, detail="Idempotency-Key must be at most 200 characters")

    request_hash = idempotency_request_fingerprint(body)
    try:
        cached = _get_idempotency_store().get(
            "/v1/sources/run-cohort",
            tenant_id,
            "source-cohort",
            idempotency_key,
            request_hash=request_hash,
        )
    except IdempotencyConflictError as exc:
        raise HTTPException(status_code=409, detail=sanitize_error(exc)) from exc
    if cached is not None:
        return SourceCohortRunResponse.model_validate(cached)

    sources: list[SourceRecord] = []
    source_requests: list[tuple[str, ScanRequest]] = []
    external_sources: list[tuple[str, str]] = []
    for source_id in body.source_ids:
        source = _source_for_request(request, source_id).model_copy(deep=True)
        if not source.enabled:
            raise HTTPException(status_code=409, detail=f"Source {source_id} is disabled")
        _validate_credential_ref(request, source)
        if source.kind in _COHORT_EXTERNAL_SOURCE_KINDS:
            external_sources.append((source_id, source.kind.value))
        else:
            source_request = _request_for_source(source)
            if len(scan_request_targets(source_request)) != 1:
                raise HTTPException(
                    status_code=422,
                    detail=f"Source {source_id} must resolve to exactly one scan target for a correlation cohort",
                )
            source_requests.append((source_id, source_request))
        sources.append(source)

    cohort_id = correlation_cohort_id(tenant_id=tenant_id, idempotency_key=idempotency_key)
    try:
        parent = enqueue_correlation_cohort(
            tenant_id=tenant_id,
            triggered_by=f"{_actor(request)}:source-cohort",
            correlation_cohort_id=cohort_id,
            source_requests=source_requests,
            external_sources=external_sources,
            max_age_hours=body.max_age_hours,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=409,
            detail="Correlation cohort conflicts with persisted immutable state",
        ) from exc

    now = _now()
    for source, child_job_id in zip(sources, parent.child_job_ids, strict=True):
        source.last_run_at = now
        source.last_run_status = "pending"
        source.last_job_id = child_job_id
        source.updated_at = now
        _get_source_store().put(source)

    decision = (parent.result or {}).get("auto_correlation") if isinstance(parent.result, dict) else None
    child_receipts = []
    source_by_id = {source.source_id: source for source in sources}
    try:
        for child_job_id in parent.child_job_ids:
            child = _get_store().get(child_job_id, tenant_id=tenant_id)
            if child is None or not child.source_id:
                raise CorrelationCohortReceiptError("invalid_cohort_state")
            source = source_by_id[child.source_id]
            if source.kind in _COHORT_EXTERNAL_SOURCE_KINDS:
                child_receipts.append(
                    issue_correlation_cohort_child_receipt(
                        parent=parent,
                        child=child,
                        source_kind=source.kind.value,
                    )
                )
    except (CorrelationCohortReceiptError, KeyError) as exc:
        raise HTTPException(status_code=409, detail="Correlation cohort receipt could not be issued") from exc

    response = SourceCohortRunResponse(
        correlation_cohort_id=cohort_id,
        cohort_manifest_hash=parent.correlation_cohort_manifest_hash or "",
        parent_job_id=parent.job_id,
        child_job_ids=list(parent.child_job_ids),
        source_ids=list(body.source_ids),
        max_age_hours=body.max_age_hours,
        status=parent.status,
        auto_correlation=decision if isinstance(decision, dict) else None,
        child_receipts=child_receipts,
    )
    response_payload = response.model_dump(mode="json")
    _get_idempotency_store().put(
        "/v1/sources/run-cohort",
        tenant_id,
        "source-cohort",
        idempotency_key,
        response_payload,
        request_hash=request_hash,
    )
    log_action(
        "source.cohort.run",
        actor=_actor(request),
        resource=f"correlation-cohort/{cohort_id}",
        tenant_id=tenant_id,
        source_count=len(sources),
        max_age_hours=body.max_age_hours,
        parent_job_id=parent.job_id,
    )
    return response


@router.get("/sources/{source_id}/jobs", tags=["sources"])
async def list_source_jobs(request: Request, source_id: str) -> dict:
    def _load() -> dict:
        source = _source_for_request(request, source_id)
        jobs = [job.model_dump() for job in _get_store().list_all(tenant_id=source.tenant_id) if job.source_id == source.source_id]
        return {"source_id": source.source_id, "jobs": jobs, "count": len(jobs)}

    return await anyio.to_thread.run_sync(_load)
