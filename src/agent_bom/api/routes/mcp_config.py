"""Served MCP-client-config distribution API routes (#3908).

Composes chosen connectors + an assigned profile (runtime role blueprint) into
ONE governed, tenant-scoped, read-only ``.mcp.json`` document a client consumes
from a single URL.

Endpoints:
    POST /v1/mcp-config/assignments               assign a profile → yields a config URL (config-gated)
    GET  /v1/mcp-config/assignments               list assignments for the tenant (read)
    GET  /v1/mcp-config/assignments/{config_id}   one assignment (read)
    POST /v1/mcp-config/assignments/{config_id}/revoke   revoke an assignment (config-gated)
    GET  /v1/mcp-config/{config_id}/mcp.json      serve the composed read-only config (read)

Security: the served document references connectors' credential env-vars and
cloud connections by *handle* only — it never embeds secret material. Access is
RBAC-gated and tenant-scoped; a cross-tenant fetch is a 404.
"""

from __future__ import annotations

from typing import Any, cast

from fastapi import APIRouter, HTTPException, Request

from agent_bom.api.audit_log import log_action
from agent_bom.api.mcp_config_store import (
    McpClientConfigAssignment,
    build_served_mcp_config,
    create_assignment,
    get_mcp_config_store,
    revoke_assignment,
)
from agent_bom.api.tenancy import require_request_tenant_id
from agent_bom.api.versioning import API_V1_PREFIX
from agent_bom.rbac import require_authenticated_permission
from agent_bom.runtime_blueprints import runtime_role_blueprint

router = APIRouter(tags=["mcp-config"])


def _dep(permission: str) -> Any:
    return cast(Any, require_authenticated_permission(permission))


def _tenant(request: Request) -> str:
    return require_request_tenant_id(request)


def _actor(request: Request) -> str:
    return getattr(getattr(request, "state", None), "actor", None) or getattr(
        getattr(request, "state", None), "api_key_name", None
    ) or "api"


def _str_list(body: dict, key: str, *, max_items: int = 200, max_len: int = 200) -> list[str]:
    raw = body.get(key, [])
    if raw in (None, ""):
        return []
    if not isinstance(raw, list):
        raise HTTPException(status_code=400, detail=f"'{key}' must be a list of strings")
    return [str(v).strip()[:max_len] for v in raw if str(v).strip()][:max_items]


def _registry() -> list[dict[str, Any]]:
    from agent_bom.api.routes.connectors import _load_registry

    return _load_registry()


def _tenant_connections(tenant_id: str) -> list[dict[str, Any]]:
    """Non-secret public dicts for the tenant's cloud connections (or empty)."""
    try:
        from agent_bom.api.connection_store import get_connection_store

        return [r.to_public_dict() for r in get_connection_store().list_for_tenant(tenant_id)]
    except Exception:  # noqa: BLE001
        return []


def _config_url(config_id: str) -> str:
    return f"{API_V1_PREFIX}/mcp-config/{config_id}/mcp.json"


@router.post("/mcp-config/assignments", status_code=201, dependencies=[_dep("config")])
async def create_mcp_config_assignment(request: Request, body: dict) -> dict[str, object]:
    """Assign a profile + connectors, yielding one distributable read-only config URL."""
    tenant_id = _tenant(request)
    name = str(body.get("name", "") or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="'name' is required")
    profile_id = str(body.get("profile_id", "") or "").strip()
    if not profile_id:
        raise HTTPException(status_code=400, detail="'profile_id' is required")
    if runtime_role_blueprint(profile_id) is None:
        raise HTTPException(status_code=400, detail="Unknown profile_id")

    connector_ids = _str_list(body, "connector_ids")
    if not connector_ids:
        raise HTTPException(status_code=400, detail="'connector_ids' must list at least one connector")
    known = {str(e.get("id")) for e in _registry()}
    unknown = [c for c in connector_ids if c not in known]
    if unknown:
        raise HTTPException(status_code=400, detail="One or more connector_ids are not in the registry")

    connection_ids = _str_list(body, "connection_ids")
    if connection_ids:
        owned = {str(c.get("id")) for c in _tenant_connections(tenant_id)}
        if any(cid not in owned for cid in connection_ids):
            raise HTTPException(status_code=404, detail="One or more connection_ids are not available for this tenant")

    assignment = create_assignment(
        get_mcp_config_store(),
        tenant_id=tenant_id,
        name=name,
        profile_id=profile_id,
        connector_ids=connector_ids,
        connection_ids=connection_ids,
        created_by=_actor(request),
    )
    log_action(
        "mcp_config.assignment_created",
        actor=_actor(request),
        resource=f"mcp-config/{assignment.config_id}",
        tenant_id=tenant_id,
        profile_id=profile_id,
        connector_count=len(connector_ids),
    )
    return {
        "schema_version": "mcp.client.config.v1",
        "assignment": assignment.to_public_dict(),
        "config_url": _config_url(assignment.config_id),
    }


@router.get("/mcp-config/assignments", dependencies=[_dep("read")])
async def list_mcp_config_assignments(request: Request, include_revoked: bool = False, limit: int = 200) -> dict[str, object]:
    """List MCP-client-config assignments for the active tenant."""
    tenant_id = _tenant(request)
    bounded = max(1, min(limit, 1000))
    rows = get_mcp_config_store().list_for_tenant(tenant_id, include_revoked=include_revoked, limit=bounded)
    return {
        "schema_version": "mcp.client.config.v1",
        "tenant_id": tenant_id,
        "count": len(rows),
        "assignments": [
            {**r.to_public_dict(), "config_url": _config_url(r.config_id)} for r in rows
        ],
    }


def _assignment_for_tenant(request: Request, config_id: str) -> McpClientConfigAssignment:
    assignment = get_mcp_config_store().get(_tenant(request), config_id)
    if assignment is None:
        raise HTTPException(status_code=404, detail="MCP-client-config assignment not found")
    return assignment


@router.get("/mcp-config/assignments/{config_id}", dependencies=[_dep("read")])
async def get_mcp_config_assignment(request: Request, config_id: str) -> dict[str, object]:
    """Return one MCP-client-config assignment (metadata)."""
    assignment = _assignment_for_tenant(request, config_id)
    return {
        "schema_version": "mcp.client.config.v1",
        "assignment": assignment.to_public_dict(),
        "config_url": _config_url(assignment.config_id),
    }


@router.post("/mcp-config/assignments/{config_id}/revoke", dependencies=[_dep("config")])
async def revoke_mcp_config_assignment(request: Request, config_id: str) -> dict[str, object]:
    """Revoke an assignment; its served config URL then 404s."""
    _assignment_for_tenant(request, config_id)
    assignment = revoke_assignment(get_mcp_config_store(), tenant_id=_tenant(request), config_id=config_id)
    if assignment is None:
        raise HTTPException(status_code=404, detail="MCP-client-config assignment not found")
    log_action(
        "mcp_config.assignment_revoked",
        actor=_actor(request),
        resource=f"mcp-config/{assignment.config_id}",
        tenant_id=assignment.tenant_id,
    )
    return {"schema_version": "mcp.client.config.v1", "assignment": assignment.to_public_dict()}


@router.get("/mcp-config/{config_id}/mcp.json", dependencies=[_dep("read")])
async def serve_mcp_client_config(request: Request, config_id: str) -> dict[str, object]:
    """Serve the composed, read-only ``.mcp.json`` document for a tenant + config.

    References connectors/secrets by handle only — never embeds secret material.
    Cross-tenant or revoked assignments 404 (fail-closed).
    """
    tenant_id = _tenant(request)
    assignment = get_mcp_config_store().get(tenant_id, config_id)
    if assignment is None or assignment.revoked:
        raise HTTPException(status_code=404, detail="MCP-client-config not found")
    profile = runtime_role_blueprint(assignment.profile_id)
    connections = [c for c in _tenant_connections(tenant_id) if str(c.get("id")) in set(assignment.connection_ids)]
    return build_served_mcp_config(assignment, registry=_registry(), profile=profile, connections=connections)
