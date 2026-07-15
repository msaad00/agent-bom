"""AI-system blueprint API routes: persisted blueprints + versioning + approval.

Read/list/get are viewer-readable; authoring a blueprint or a draft version and
submitting it for approval is a contributor (``scan``) action; approving or
rejecting a version is an admin (``config``) action — the accountable-approver
gate. Every route is tenant-scoped via the middleware-established tenant id, and
the mandatory-approver invariant is enforced in the lifecycle layer (an approval
with no accountable owner is a 400), independent of the RBAC gate.
"""

from __future__ import annotations

import logging
from typing import Any, cast

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from agent_bom.api.blueprint_store import (
    BlueprintApprovalError,
    BlueprintComposition,
    approve_version,
    create_blueprint,
    create_draft_version,
    diff_versions,
    get_blueprint_store,
    reject_version,
    seed_blueprints_from_archetypes,
    submit_version_for_approval,
)
from agent_bom.api.tenancy import require_request_tenant_id
from agent_bom.rbac import require_authenticated_permission
from agent_bom.security import sanitize_error

router = APIRouter(tags=["governance"])
logger = logging.getLogger(__name__)

_SCHEMA = "governance.blueprints.v1"


def _dep(permission: str) -> Any:
    return cast(Any, require_authenticated_permission(permission))


def _tenant(request: Request) -> str:
    return require_request_tenant_id(request)


def _actor(request: Request) -> str:
    return getattr(getattr(request, "state", None), "actor", None) or getattr(
        getattr(request, "state", None), "api_key_name", None
    ) or "api"


class CompositionModel(BaseModel):
    agents: list[str] = Field(default_factory=list)
    models: list[str] = Field(default_factory=list)
    tools: list[str] = Field(default_factory=list)
    datasets: list[str] = Field(default_factory=list)
    identities: list[str] = Field(default_factory=list)
    owners: list[str] = Field(default_factory=list)
    guardrails: list[str] = Field(default_factory=list)

    def to_composition(self) -> BlueprintComposition:
        return BlueprintComposition(
            agents=list(self.agents),
            models=list(self.models),
            tools=list(self.tools),
            datasets=list(self.datasets),
            identities=list(self.identities),
            owners=list(self.owners),
            guardrails=list(self.guardrails),
        )


class CreateBlueprintBody(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    owner: str = Field(min_length=1, max_length=200)
    owner_type: str = Field(default="", max_length=60)
    description: str = Field(default="", max_length=1000)
    composition: CompositionModel = Field(default_factory=CompositionModel)


class DraftVersionBody(BaseModel):
    composition: CompositionModel = Field(default_factory=CompositionModel)


class DecisionBody(BaseModel):
    note: str = Field(default="", max_length=1000)


@router.get("/governance/blueprints", dependencies=[_dep("read")])
async def list_blueprints(request: Request, limit: int = 50, offset: int = 0) -> dict[str, object]:
    """List persisted AI-system blueprints for the active tenant (paginated)."""
    tenant_id = _tenant(request)
    bounded = max(1, min(limit, 200))
    page = get_blueprint_store().list_blueprints(tenant_id, limit=bounded, offset=max(0, offset))
    return {
        "schema_version": _SCHEMA,
        "tenant_id": tenant_id,
        "count": len(page.blueprints),
        "next_offset": page.next_offset,
        "blueprints": [b.to_dict() for b in page.blueprints],
    }


@router.post("/governance/blueprints", dependencies=[_dep("scan")], status_code=201)
async def create_blueprint_route(request: Request, body: CreateBlueprintBody) -> dict[str, object]:
    """Create a new AI-system blueprint with an initial draft version 1."""
    tenant_id = _tenant(request)
    blueprint, version = create_blueprint(
        get_blueprint_store(),
        tenant_id=tenant_id,
        name=body.name,
        owner=body.owner,
        owner_type=body.owner_type,
        description=body.description,
        composition=body.composition.to_composition(),
        created_by=_actor(request),
    )
    return {
        "schema_version": _SCHEMA,
        "tenant_id": tenant_id,
        "blueprint": blueprint.to_dict(),
        "version": version.to_dict(),
    }


@router.post("/governance/blueprints/seed", dependencies=[_dep("scan")])
async def seed_blueprints_route(request: Request) -> dict[str, object]:
    """Seed the tenant's blueprints from the canonical role archetypes (idempotent)."""
    tenant_id = _tenant(request)
    created = seed_blueprints_from_archetypes(get_blueprint_store(), tenant_id=tenant_id)
    return {
        "schema_version": _SCHEMA,
        "tenant_id": tenant_id,
        "seeded_count": len(created),
        "blueprints": [b.to_dict() for b in created],
    }


@router.get("/governance/blueprints/{blueprint_id}", dependencies=[_dep("read")])
async def get_blueprint_route(request: Request, blueprint_id: str) -> dict[str, object]:
    """Return one blueprint plus its full version history and approval state."""
    tenant_id = _tenant(request)
    store = get_blueprint_store()
    blueprint = store.get_blueprint(tenant_id, blueprint_id)
    if blueprint is None:
        raise HTTPException(status_code=404, detail="Blueprint not found")
    versions = store.list_versions(tenant_id, blueprint_id, limit=200)
    return {
        "schema_version": _SCHEMA,
        "tenant_id": tenant_id,
        "blueprint": blueprint.to_dict(),
        "versions": [v.to_dict() for v in versions],
    }


@router.get("/governance/blueprints/{blueprint_id}/versions", dependencies=[_dep("read")])
async def list_versions_route(request: Request, blueprint_id: str, limit: int = 200) -> dict[str, object]:
    """List a blueprint's immutable versions, newest first."""
    tenant_id = _tenant(request)
    store = get_blueprint_store()
    if store.get_blueprint(tenant_id, blueprint_id) is None:
        raise HTTPException(status_code=404, detail="Blueprint not found")
    versions = store.list_versions(tenant_id, blueprint_id, limit=max(1, min(limit, 500)))
    return {
        "schema_version": _SCHEMA,
        "tenant_id": tenant_id,
        "blueprint_id": blueprint_id,
        "count": len(versions),
        "versions": [v.to_dict() for v in versions],
    }


@router.get("/governance/blueprints/{blueprint_id}/versions/{version}", dependencies=[_dep("read")])
async def get_version_route(request: Request, blueprint_id: str, version: int) -> dict[str, object]:
    """Return one blueprint version (its composition snapshot + approval state)."""
    tenant_id = _tenant(request)
    record = get_blueprint_store().get_version(tenant_id, blueprint_id, version)
    if record is None:
        raise HTTPException(status_code=404, detail="Blueprint version not found")
    return {"schema_version": _SCHEMA, "tenant_id": tenant_id, "version": record.to_dict()}


@router.get("/governance/blueprints/{blueprint_id}/diff", dependencies=[_dep("read")])
async def diff_versions_route(request: Request, blueprint_id: str, from_version: int, to_version: int) -> dict[str, object]:
    """Diff two versions' compositions (added / removed / persistent per axis)."""
    tenant_id = _tenant(request)
    diff = diff_versions(
        get_blueprint_store(),
        tenant_id=tenant_id,
        blueprint_id=blueprint_id,
        from_version=from_version,
        to_version=to_version,
    )
    if diff is None:
        raise HTTPException(status_code=404, detail="Blueprint version not found")
    return {"schema_version": _SCHEMA, "tenant_id": tenant_id, "diff": diff}


@router.post("/governance/blueprints/{blueprint_id}/versions", dependencies=[_dep("scan")], status_code=201)
async def create_draft_version_route(request: Request, blueprint_id: str, body: DraftVersionBody) -> dict[str, object]:
    """Open a new draft version from an edited composition (approved versions are immutable)."""
    tenant_id = _tenant(request)
    version = create_draft_version(
        get_blueprint_store(),
        tenant_id=tenant_id,
        blueprint_id=blueprint_id,
        composition=body.composition.to_composition(),
        created_by=_actor(request),
    )
    if version is None:
        raise HTTPException(status_code=404, detail="Blueprint not found")
    return {"schema_version": _SCHEMA, "tenant_id": tenant_id, "version": version.to_dict()}


@router.post("/governance/blueprints/{blueprint_id}/versions/{version}/submit", dependencies=[_dep("scan")])
async def submit_version_route(request: Request, blueprint_id: str, version: int) -> dict[str, object]:
    """Submit a draft version for approval (draft → pending)."""
    tenant_id = _tenant(request)
    try:
        record = submit_version_for_approval(
            get_blueprint_store(),
            tenant_id=tenant_id,
            blueprint_id=blueprint_id,
            version=version,
            submitted_by=_actor(request),
        )
    except BlueprintApprovalError as exc:
        raise HTTPException(status_code=400, detail=sanitize_error(exc)) from exc
    if record is None:
        raise HTTPException(status_code=404, detail="Blueprint version not found")
    return {"schema_version": _SCHEMA, "tenant_id": tenant_id, "version": record.to_dict()}


@router.post("/governance/blueprints/{blueprint_id}/versions/{version}/approve", dependencies=[_dep("config")])
async def approve_version_route(request: Request, blueprint_id: str, version: int, body: DecisionBody | None = None) -> dict[str, object]:
    """Approve a pending version (admin only). Records the accountable approver."""
    tenant_id = _tenant(request)
    note = (body.note if body else "") or ""
    try:
        record = approve_version(
            get_blueprint_store(),
            tenant_id=tenant_id,
            blueprint_id=blueprint_id,
            version=version,
            approver=_actor(request),
            note=note,
        )
    except BlueprintApprovalError as exc:
        raise HTTPException(status_code=400, detail=sanitize_error(exc)) from exc
    if record is None:
        raise HTTPException(status_code=404, detail="Blueprint version not found")
    _emit_decision_event(tenant_id, "blueprint.version.approved", record.to_dict())
    return {"schema_version": _SCHEMA, "tenant_id": tenant_id, "version": record.to_dict()}


@router.post("/governance/blueprints/{blueprint_id}/versions/{version}/reject", dependencies=[_dep("config")])
async def reject_version_route(request: Request, blueprint_id: str, version: int, body: DecisionBody | None = None) -> dict[str, object]:
    """Reject a pending version (admin only). Records the accountable reviewer."""
    tenant_id = _tenant(request)
    note = (body.note if body else "") or ""
    try:
        record = reject_version(
            get_blueprint_store(),
            tenant_id=tenant_id,
            blueprint_id=blueprint_id,
            version=version,
            approver=_actor(request),
            note=note,
        )
    except BlueprintApprovalError as exc:
        raise HTTPException(status_code=400, detail=sanitize_error(exc)) from exc
    if record is None:
        raise HTTPException(status_code=404, detail="Blueprint version not found")
    _emit_decision_event(tenant_id, "blueprint.version.rejected", record.to_dict())
    return {"schema_version": _SCHEMA, "tenant_id": tenant_id, "version": record.to_dict()}


def _emit_decision_event(tenant_id: str, event_type: str, version: dict[str, Any]) -> None:
    """Emit a governance webhook event for an approval decision. Never raises."""
    try:
        from agent_bom.api.webhook_store import emit_governance_event

        emit_governance_event(
            event_type=event_type,
            tenant_id=tenant_id,
            source="governance.blueprints",
            subject_id=str(version.get("version_id") or ""),
            payload={
                "blueprint_id": version.get("blueprint_id"),
                "version": version.get("version"),
                "status": version.get("status"),
                "approver": version.get("approver"),
                "decided_at": version.get("decided_at"),
            },
        )
    except Exception:  # noqa: BLE001
        logger.warning("blueprint decision event emit failed", exc_info=True)
