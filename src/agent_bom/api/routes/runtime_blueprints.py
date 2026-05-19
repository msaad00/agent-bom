"""Runtime role/profile blueprint API routes."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from agent_bom.runtime_blueprints import evaluate_runtime_blueprint_drift, runtime_role_blueprint, runtime_role_blueprints

router = APIRouter(tags=["runtime"])


def _request_tenant_id(request: Request) -> str:
    return str(getattr(request.state, "tenant_id", "default") or "default")


@router.get("/v1/runtime/blueprints")
async def list_runtime_blueprints(request: Request) -> dict[str, object]:
    """Return canonical role/profile blueprints for runtime policy design."""
    return {
        "schema_version": "runtime.blueprints.v1",
        "tenant_id": _request_tenant_id(request),
        "blueprints": runtime_role_blueprints(),
    }


@router.get("/v1/runtime/blueprints/{blueprint_id}")
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


@router.get("/v1/runtime/blueprints/{blueprint_id}/drift")
async def get_runtime_blueprint_drift(request: Request, blueprint_id: str) -> dict[str, object]:
    """Evaluate current runtime posture against one role/profile blueprint."""
    from agent_bom.api.routes.proxy import _build_runtime_production_index, _load_proxy_alerts, _runtime_metrics_for_tenant

    tenant_id = _request_tenant_id(request)
    try:
        production_index = _build_runtime_production_index(tenant_id, _runtime_metrics_for_tenant(tenant_id), _load_proxy_alerts(tenant_id))
        return evaluate_runtime_blueprint_drift(blueprint_id, production_index, tenant_id=tenant_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Runtime blueprint not found") from exc
