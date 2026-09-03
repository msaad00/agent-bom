"""Tenant-scoped API for immutable graph correlation runs."""

from __future__ import annotations

import asyncio
import uuid
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Header, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from agent_bom import config as agent_config
from agent_bom.api import stores as api_stores
from agent_bom.api.audit_log import log_action
from agent_bom.api.tenancy import require_request_tenant_id
from agent_bom.graph.correlation import CorrelationRunStatus, GraphCorrelationRun
from agent_bom.graph.correlation_receipts import (
    CorrelationReceiptError,
    configured_receipt_signing_key,
    correlation_run_receipt_payload,
)
from agent_bom.graph.correlation_service import (
    CorrelationRequest,
    CorrelationServiceError,
    GraphCorrelationService,
    get_graph_correlation_service,
)
from agent_bom.runtime.correlation_facts import RuntimeFactsBundleError, create_runtime_facts_bundle_from_correlation
from agent_bom.security import sanitize_error

router = APIRouter()

_MAX_IDEMPOTENCY_KEY_LENGTH = 200
_DEFAULT_FACTS_TTL_SECONDS = 300


class GraphCorrelationCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=160)
    scan_ids: list[str] = Field(min_length=2, max_length=32)
    max_age_hours: int = Field(ge=1, le=8760)
    allow_stale: bool = False


class GraphCorrelationReceiptSignature(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str
    algorithm: str
    key_id: str = ""
    value: str


class GraphCorrelationReceipt(BaseModel):
    model_config = ConfigDict(extra="allow")

    scan_id: str
    created_at: str = ""
    digest: str = ""
    node_count: int = 0
    edge_count: int = 0
    source_kinds: list[str] = Field(default_factory=list)
    freshness: str = ""
    age_hours: float = 0.0
    signature: GraphCorrelationReceiptSignature | None = None
    verification: str = "legacy_hash_bound"


class GraphCorrelationReceiptVerification(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: str
    verified: int = 0
    legacy_hash_bound: int = 0
    invalid: int = 0
    verification_key_unavailable: int = 0
    total: int = 0


class GraphCorrelationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    correlation_id: str
    tenant_id: str
    idempotency_key: str
    name: str
    status: str
    max_age_hours: int
    allow_stale: bool
    input_manifest: list[GraphCorrelationReceipt]
    receipt_verification: GraphCorrelationReceiptVerification
    result_manifest: dict[str, Any] = Field(default_factory=dict)
    manifest_sha256: str = ""
    output_scan_id: str = ""
    failure_code: str = ""
    created_at: str = ""
    started_at: str = ""
    completed_at: str = ""


class GraphCorrelationList(BaseModel):
    items: list[GraphCorrelationResponse]
    count: int


def _actor(request: Request) -> str:
    return str(getattr(request.state, "api_key_name", "") or "system")


def _run_payload(run: GraphCorrelationRun) -> GraphCorrelationResponse:
    try:
        signing_key = configured_receipt_signing_key()
    except CorrelationReceiptError:
        signing_key = None
    return GraphCorrelationResponse.model_validate(
        correlation_run_receipt_payload(run.to_dict(), signing_key=signing_key)
    )


async def _correlation_service(tenant_id: str) -> GraphCorrelationService:
    store = api_stores._get_graph_store()
    return await get_graph_correlation_service(store, tenant_id)


def _error_status(code: str) -> int:
    if code in {"input_snapshot_not_found", "correlation_not_found"}:
        return 404
    if code in {"queue_capacity_exceeded"}:
        return 429
    if code in {"correlation_wait_timeout"}:
        return 408
    if code in {"stale_input", "nested_correlation_unsupported", "empty_input_snapshot"}:
        return 409
    return 422


def _signing_key() -> bytes:
    key_file = agent_config.RUNTIME_FACTS_HMAC_KEY_FILE.strip()
    raw = b""
    if key_file:
        try:
            raw = Path(key_file).expanduser().read_bytes()[:4097]
        except OSError as exc:
            raise RuntimeFactsBundleError("signing_key_unavailable") from exc
        if len(raw) > 4096:
            raise RuntimeFactsBundleError("invalid_signing_key")
        raw = raw.strip()
    if not raw:
        raw = agent_config.RUNTIME_FACTS_HMAC_KEY.encode("utf-8")
    if not raw:
        raise RuntimeFactsBundleError("signing_key_not_configured")
    return raw


def _facts_ttl_seconds() -> int:
    try:
        value = int(agent_config.RUNTIME_FACTS_TTL_SECONDS or _DEFAULT_FACTS_TTL_SECONDS)
    except ValueError as exc:
        raise RuntimeFactsBundleError("invalid_ttl") from exc
    if not 1 <= value <= 86400:
        raise RuntimeFactsBundleError("invalid_ttl")
    return value


@router.post(
    "/graph/correlations",
    status_code=202,
    response_model=GraphCorrelationResponse,
    tags=["graph-correlations"],
)
async def create_graph_correlation(
    request: Request,
    body: GraphCorrelationCreate,
    idempotency_key: Annotated[str, Header(alias="Idempotency-Key", min_length=1, max_length=_MAX_IDEMPOTENCY_KEY_LENGTH)],
) -> GraphCorrelationResponse:
    tenant_id = require_request_tenant_id(request)
    correlation_id = str(uuid.uuid4())
    service = await _correlation_service(tenant_id)
    try:
        run = await service.submit(
            CorrelationRequest(
                correlation_id=correlation_id,
                tenant_id=tenant_id,
                idempotency_key=idempotency_key,
                name=body.name.strip(),
                scan_ids=tuple(body.scan_ids),
                max_age_hours=body.max_age_hours,
                allow_stale=body.allow_stale,
            )
        )
    except CorrelationServiceError as exc:
        raise HTTPException(status_code=_error_status(exc.code), detail=exc.code) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail="idempotency_key_conflict") from exc
    log_action(
        "graph.correlation.create",
        actor=_actor(request),
        resource=f"graph/correlation/{run.correlation_id}",
        tenant_id=tenant_id,
        source_count=len(run.input_manifest),
        max_age_hours=run.max_age_hours,
        allow_stale=run.allow_stale,
    )
    return _run_payload(run)


@router.get("/graph/correlations", response_model=GraphCorrelationList, tags=["graph-correlations"])
async def list_graph_correlations(
    request: Request,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> GraphCorrelationList:
    tenant_id = require_request_tenant_id(request)
    await _correlation_service(tenant_id)
    runs = await asyncio.to_thread(api_stores._get_graph_store().list_correlation_runs, tenant_id=tenant_id, limit=limit)
    log_action(
        "graph.correlation.list",
        actor=_actor(request),
        resource="graph/correlations",
        tenant_id=tenant_id,
        result_count=len(runs),
    )
    return GraphCorrelationList(items=[_run_payload(run) for run in runs], count=len(runs))


def _get_run(tenant_id: str, correlation_id: str) -> GraphCorrelationRun:
    run = api_stores._get_graph_store().get_correlation_run(
        tenant_id=tenant_id,
        correlation_id=correlation_id,
    )
    if run is None:
        raise HTTPException(status_code=404, detail="correlation_not_found")
    return run


@router.get(
    "/graph/correlations/{correlation_id}",
    response_model=GraphCorrelationResponse,
    tags=["graph-correlations"],
)
async def get_graph_correlation(request: Request, correlation_id: str) -> GraphCorrelationResponse:
    tenant_id = require_request_tenant_id(request)
    await _correlation_service(tenant_id)
    run = await asyncio.to_thread(_get_run, tenant_id, correlation_id)
    log_action(
        "graph.correlation.read",
        actor=_actor(request),
        resource=f"graph/correlation/{correlation_id}",
        tenant_id=tenant_id,
        status=run.status.value,
    )
    return _run_payload(run)


@router.get("/graph/correlations/{correlation_id}/runtime-facts", tags=["graph-correlations"])
async def get_graph_correlation_runtime_facts(request: Request, correlation_id: str) -> dict[str, Any]:
    tenant_id = require_request_tenant_id(request)
    run = await asyncio.to_thread(_get_run, tenant_id, correlation_id)
    if run.status is not CorrelationRunStatus.COMPLETE:
        raise HTTPException(status_code=409, detail="correlation_not_complete")
    store = api_stores._get_graph_store()
    snapshot_rows = await asyncio.to_thread(
        store.snapshots_by_ids,
        tenant_id=tenant_id,
        scan_ids={correlation_id},
    )
    snapshot_metadata = snapshot_rows[0] if snapshot_rows else None
    graph = await asyncio.to_thread(
        store.load_graph,
        tenant_id=tenant_id,
        scan_id=correlation_id,
    )
    try:
        bundle = create_runtime_facts_bundle_from_correlation(
            run,
            graph,
            snapshot_metadata=snapshot_metadata,
            signing_key=_signing_key(),
            ttl_seconds=_facts_ttl_seconds(),
            key_id=agent_config.RUNTIME_FACTS_KEY_ID.strip(),
        )
    except RuntimeFactsBundleError as exc:
        status_code = 503 if exc.code in {"signing_key_not_configured", "signing_key_unavailable"} else 409
        raise HTTPException(status_code=status_code, detail=exc.code) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=sanitize_error(exc, generic=True)) from exc
    log_action(
        "graph.correlation.runtime_facts.read",
        actor=_actor(request),
        resource=f"graph/correlation/{correlation_id}/runtime-facts",
        tenant_id=tenant_id,
        manifest_sha256=run.manifest_sha256,
    )
    return bundle
