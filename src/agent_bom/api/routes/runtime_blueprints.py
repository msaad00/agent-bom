"""Runtime role/profile blueprint API routes."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, cast

from fastapi import APIRouter, HTTPException, Request

from agent_bom.api.drift_incident_store import get_drift_incident_store, record_drift_if_detected
from agent_bom.api.tenancy import require_request_tenant_id
from agent_bom.rbac import require_authenticated_permission
from agent_bom.runtime_blueprints import evaluate_runtime_blueprint_drift, runtime_role_blueprint, runtime_role_blueprints

router = APIRouter(tags=["runtime"])
logger = logging.getLogger(__name__)


def _dep(permission: str) -> Any:
    return cast(Any, require_authenticated_permission(permission))


def _request_tenant_id(request: Request) -> str:
    return require_request_tenant_id(request)


def _actor(request: Request) -> str:
    return getattr(getattr(request, "state", None), "actor", None) or "api"


@router.get("/runtime/blueprints", dependencies=[_dep("read")])
async def list_runtime_blueprints(request: Request) -> dict[str, object]:
    """Return canonical role/profile blueprints for runtime policy design."""
    return {
        "schema_version": "runtime.blueprints.v1",
        "tenant_id": _request_tenant_id(request),
        "blueprints": runtime_role_blueprints(),
    }


@router.get("/runtime/blueprints/{blueprint_id}", dependencies=[_dep("read")])
async def get_runtime_blueprint(request: Request, blueprint_id: str) -> dict[str, object]:
    """Return one canonical role/profile blueprint by ID."""
    blueprint = runtime_role_blueprint(blueprint_id)
    if blueprint is None:
        raise HTTPException(status_code=404, detail="Runtime blueprint not found")
    return {
        "schema_version": "runtime.blueprints.v1",
        "tenant_id": _request_tenant_id(request),
        "blueprint": blueprint,
    }


@router.get("/runtime/blueprints/{blueprint_id}/drift", dependencies=[_dep("read")])
async def get_runtime_blueprint_drift(request: Request, blueprint_id: str) -> dict[str, object]:
    """Evaluate current runtime posture against one role/profile blueprint."""
    from agent_bom.api.routes.proxy import _build_runtime_production_index, _load_proxy_alerts, _runtime_metrics_for_tenant

    tenant_id = _request_tenant_id(request)
    try:
        production_index = _build_runtime_production_index(tenant_id, _runtime_metrics_for_tenant(tenant_id), _load_proxy_alerts(tenant_id))
        result = evaluate_runtime_blueprint_drift(blueprint_id, production_index, tenant_id=tenant_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Runtime blueprint not found") from exc
    # Close the loop: a drift_detected evaluation becomes a durable, resolvable
    # incident so blueprints act as enforced contracts, not advisory reports.
    # Incident persistence must never break the read — degrade to the evaluation.
    try:
        incident = record_drift_if_detected(get_drift_incident_store(), result)
        if incident is not None:
            result["incident_id"] = incident.incident_id
            from agent_bom.api.webhook_store import emit_governance_event

            emit_governance_event(
                event_type="drift.detected",
                tenant_id=tenant_id,
                source="runtime.drift",
                subject_id=incident.incident_id,
                payload={
                    "incident_id": incident.incident_id,
                    "blueprint_id": incident.blueprint_id,
                    "drift_score": incident.drift_score,
                    "violation_count": incident.violation_count,
                    "occurrences": incident.occurrences,
                },
            )
    except Exception:  # noqa: BLE001
        logger.warning("drift incident persistence failed", exc_info=True)
    return result


@router.get("/runtime/drift/incidents", dependencies=[_dep("read")])
async def list_drift_incidents(request: Request, include_resolved: bool = False, limit: int = 200) -> dict[str, object]:
    """List open (or all) blueprint-drift incidents for the active tenant."""
    tenant_id = _request_tenant_id(request)
    bounded = max(1, min(limit, 1000))
    incidents = get_drift_incident_store().list(tenant_id, include_resolved=include_resolved, limit=bounded)
    return {
        "schema_version": "runtime.drift_incidents.v1",
        "tenant_id": tenant_id,
        "count": len(incidents),
        "open_count": sum(1 for i in incidents if not i.resolved),
        "incidents": [i.to_dict() for i in incidents],
    }


@router.post("/runtime/drift/incidents/{incident_id}/resolve", dependencies=[_dep("config")])
async def resolve_drift_incident(request: Request, incident_id: str, body: dict | None = None) -> dict[str, object]:
    """Resolve a drift incident once the blueprint/agent has been reconciled."""
    tenant_id = _request_tenant_id(request)
    note = str((body or {}).get("note", "") or "")[:500]
    resolved = get_drift_incident_store().resolve(
        tenant_id,
        incident_id,
        by=_actor(request),
        note=note,
        at=datetime.now(timezone.utc).isoformat(),
    )
    if resolved is None:
        raise HTTPException(status_code=404, detail="Drift incident not found")
    return {"schema_version": "runtime.drift_incidents.v1", "tenant_id": tenant_id, "resolved": True, "incident": resolved.to_dict()}
