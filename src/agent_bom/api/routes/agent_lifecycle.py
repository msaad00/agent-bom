"""Authenticated lifecycle registration and exact immutable BOM references."""

from __future__ import annotations

from typing import Annotated, Any, Literal, cast

from fastapi import APIRouter, HTTPException, Query, Request
from starlette.concurrency import run_in_threadpool

from agent_bom.api.agent_identity_store import get_agent_identity_store
from agent_bom.api.lifecycle_store import LifecycleConflictError, get_lifecycle_store
from agent_bom.api.tenancy import require_request_tenant_id
from agent_bom.evidence.agent_bom import AgentBomDocument
from agent_bom.evidence.lifecycle import (
    CaptureSnapshot,
    LifecyclePage,
    LifecycleRecord,
    RecordKind,
    RegisterDeployment,
    RegisterInstance,
    RegisterRun,
    composition_digest,
)
from agent_bom.rbac import require_authenticated_permission
from agent_bom.security import sanitize_text

router = APIRouter(prefix="/agent-lifecycle", tags=["Agent lifecycle"])
_READ = cast(Any, require_authenticated_permission("read"))
_WRITE = cast(Any, require_authenticated_permission("config"))
IdQuery = Annotated[str, Query(min_length=1, max_length=512)]


def _actor(request: Request) -> str:
    return sanitize_text(str(getattr(request.state, "actor", None) or getattr(request.state, "api_key_name", None) or "api"), max_len=200)


async def _call(method: str, tenant: str, *args: Any, **kwargs: Any) -> Any:
    def call() -> Any:
        return getattr(get_lifecycle_store(), method)(tenant, *args, **kwargs)

    try:
        return await run_in_threadpool(call)
    except LifecycleConflictError as exc:
        raise HTTPException(
            status_code=409, detail="Lifecycle reference is unavailable, inactive, or conflicts with an immutable binding"
        ) from exc
    except Exception as exc:
        # Storage can contain credentials in connection failures; fail closed.
        raise HTTPException(status_code=503, detail="Lifecycle storage unavailable") from exc


async def _record(tenant: str, kind: RecordKind, record_id: str) -> LifecycleRecord:
    record = await _call("get", tenant, kind, record_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Lifecycle record not found")
    return cast(LifecycleRecord, record)


async def _live_identity(tenant: str, identity_id: str, agent_id: str) -> None:
    def verify() -> bool:
        identity = get_agent_identity_store().get(identity_id, tenant_id=tenant)
        return identity is not None and identity.agent_id == agent_id and identity.is_live()

    try:
        valid = await run_in_threadpool(verify)
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Identity verification unavailable") from exc
    if not valid:
        raise HTTPException(status_code=409, detail="A live managed identity bound to this exact agent is required")


@router.post("/snapshots", response_model=LifecycleRecord, dependencies=[_WRITE])
async def capture_snapshot(request: Request, body: CaptureSnapshot) -> LifecycleRecord:
    """Retain one completed scan export and register its observed logical agent.

    No producer JSON or name-based join is accepted. Registration records an
    operator action; it does not upgrade the exported identity to verified.
    """
    from agent_bom.api.routes.scan import get_scan_agent_bom

    document = await get_scan_agent_bom(request, body.scan_id, body.agent_id)
    return cast(LifecycleRecord, await _call("capture", require_request_tenant_id(request), document, _actor(request)))


@router.get("/snapshots/export", response_model=AgentBomDocument, dependencies=[_READ])
async def export_snapshot(request: Request, snapshot_id: IdQuery) -> AgentBomDocument:
    document = await _call("snapshot", require_request_tenant_id(request), snapshot_id)
    if document is None:
        raise HTTPException(status_code=404, detail="BOM snapshot not found")
    return cast(AgentBomDocument, document)


@router.get("/snapshots/compare", dependencies=[_READ])
async def compare_snapshots(request: Request, before: IdQuery, after: IdQuery) -> dict[str, Any]:
    left = await export_snapshot(request, before)
    right = await export_snapshot(request, after)
    if left.content.subject.agent_id != right.content.subject.agent_id:
        raise HTTPException(status_code=409, detail="Snapshots must belong to the same exact agent")
    left_composition, right_composition = composition_digest(left), composition_digest(right)
    return {
        "agent_id": left.content.subject.agent_id,
        "before": left.snapshot_id,
        "after": right.snapshot_id,
        "snapshot_changed": left.snapshot_id != right.snapshot_id,
        "composition_changed": left_composition != right_composition,
        "evidence_changed": left.content.evidence != right.content.evidence,
        "coverage_changed": left.content.coverage != right.content.coverage,
        "subject_changed": left.content.subject != right.content.subject,
        "before_composition_digest": left_composition,
        "after_composition_digest": right_composition,
    }


@router.post("/deployments", response_model=LifecycleRecord, dependencies=[_WRITE])
async def register_deployment(request: Request, body: RegisterDeployment) -> LifecycleRecord:
    return cast(LifecycleRecord, await _call("deployment", require_request_tenant_id(request), body, _actor(request)))


@router.post("/instances", response_model=LifecycleRecord, dependencies=[_WRITE])
async def register_instance(request: Request, body: RegisterInstance) -> LifecycleRecord:
    tenant = require_request_tenant_id(request)
    deployment = await _record(tenant, "deployment", body.deployment_id)
    await _live_identity(tenant, body.identity_id, deployment.agent_id)
    return cast(LifecycleRecord, await _call("instance", tenant, body, _actor(request), identity_agent_id=deployment.agent_id))


@router.post("/runs", response_model=LifecycleRecord, dependencies=[_WRITE])
async def register_run(request: Request, body: RegisterRun) -> LifecycleRecord:
    tenant = require_request_tenant_id(request)
    instance = await _record(tenant, "instance", body.instance_id)
    await _live_identity(tenant, instance.identity_id or "", instance.agent_id)
    return cast(LifecycleRecord, await _call("run", tenant, body, _actor(request)))


@router.post("/retire", response_model=LifecycleRecord, dependencies=[_WRITE])
async def retire_record(request: Request, kind: Literal["agent", "deployment", "instance"], record_id: IdQuery) -> LifecycleRecord:
    return cast(LifecycleRecord, await _call("retire", require_request_tenant_id(request), kind, record_id, _actor(request)))


@router.get("/records", response_model=LifecycleRecord, dependencies=[_READ])
async def get_record(request: Request, kind: RecordKind, record_id: IdQuery) -> LifecycleRecord:
    return await _record(require_request_tenant_id(request), kind, record_id)


@router.get("/history", response_model=LifecyclePage, dependencies=[_READ])
async def get_history(
    request: Request,
    agent_id: IdQuery,
    kind: RecordKind = "snapshot",
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=10000)] = 0,
) -> LifecyclePage:
    """Bounded oldest-first pages of metadata; BOM payloads use exact export."""
    return cast(LifecyclePage, await _call("history", require_request_tenant_id(request), kind, agent_id, limit=limit, offset=offset))
