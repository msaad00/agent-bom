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

from dataclasses import replace
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, cast

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator

from agent_bom.api.audit_log import log_action
from agent_bom.api.mcp_config_store import (
    McpClientConfigAssignment,
    McpConfigConflictError,
    McpConfigRevisionConflictError,
    _now_iso,
    build_served_mcp_config,
    create_assignment,
    get_mcp_config_store,
    revoke_assignment,
)
from agent_bom.api.tenancy import require_request_tenant_id
from agent_bom.api.versioning import API_V1_PREFIX
from agent_bom.rbac import require_authenticated_permission
from agent_bom.runtime_blueprints import runtime_role_blueprint

if TYPE_CHECKING:
    from agent_bom.api.agent_identity_store import AgentIdentity

router = APIRouter(tags=["mcp-config"])


def _normalize_string_list(values: list[str]) -> list[str]:
    normalized: list[str] = []
    for value in values:
        item = str(value).strip()
        if not item:
            continue
        if len(item) > 200:
            raise ValueError("list items must be at most 200 characters")
        if item not in normalized:
            normalized.append(item)
    return normalized


def _normalize_expiry_value(value: str) -> str:
    if not value:
        return ""
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("expires_at must include a timezone")
    return parsed.astimezone(timezone.utc).isoformat()


class McpConfigAssignmentCreate(BaseModel):
    """Strict, secret-free client-profile assignment request."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    name: str = Field(min_length=1, max_length=200)
    profile_id: str = Field(min_length=1, max_length=200)
    connector_ids: list[str] = Field(min_length=1, max_length=200)
    connection_ids: list[str] = Field(default_factory=list, max_length=200)
    identity_id: str = Field(default="", max_length=200)
    issuer: str = Field(default="", max_length=500)
    environment: str = Field(default="", max_length=120)
    allowed_tools: list[str] = Field(default_factory=list, max_length=200)
    required_scopes: list[str] = Field(default_factory=list, max_length=200)
    policy_ids: list[str] = Field(default_factory=list, max_length=200)
    expires_at: str = Field(default="", max_length=80)

    @field_validator("connector_ids", "connection_ids", "allowed_tools", "required_scopes", "policy_ids")
    @classmethod
    def _normalize_list(cls, values: list[str]) -> list[str]:
        return _normalize_string_list(values)

    @field_validator("expires_at")
    @classmethod
    def _normalize_expiry(cls, value: str) -> str:
        return _normalize_expiry_value(value)


class McpConfigAssignmentUpdate(BaseModel):
    """Full profile replacement guarded by an optimistic revision."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    expected_revision: int = Field(ge=1)
    name: str = Field(min_length=1, max_length=200)
    profile_id: str = Field(min_length=1, max_length=200)
    connector_ids: list[str] = Field(min_length=1, max_length=200)
    connection_ids: list[str] = Field(default_factory=list, max_length=200)
    environment: str = Field(default="", max_length=120)
    allowed_tools: list[str] = Field(default_factory=list, max_length=200)
    required_scopes: list[str] = Field(default_factory=list, max_length=200)
    policy_ids: list[str] = Field(default_factory=list, max_length=200)
    expires_at: str = Field(default="", max_length=80)

    @field_validator("connector_ids", "connection_ids", "allowed_tools", "required_scopes", "policy_ids")
    @classmethod
    def _normalize_list(cls, values: list[str]) -> list[str]:
        return _normalize_string_list(values)

    @field_validator("expires_at")
    @classmethod
    def _normalize_expiry(cls, value: str) -> str:
        return _normalize_expiry_value(value)


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


def _validate_references(*, tenant_id: str, profile_id: str, connector_ids: list[str], connection_ids: list[str]) -> None:
    if runtime_role_blueprint(profile_id) is None:
        raise HTTPException(status_code=400, detail="Unknown profile_id")
    known = {str(entry.get("id")) for entry in _registry()}
    if any(connector_id not in known for connector_id in connector_ids):
        raise HTTPException(status_code=400, detail="One or more connector_ids are not in the registry")
    if connection_ids:
        owned = {str(connection.get("id")) for connection in _tenant_connections(tenant_id)}
        if any(connection_id not in owned for connection_id in connection_ids):
            raise HTTPException(status_code=404, detail="One or more connection_ids are not available for this tenant")


def _bound_identity(*, tenant_id: str, identity_id: str, profile_id: str) -> AgentIdentity | None:
    if not identity_id:
        return None
    from agent_bom.api.agent_identity_store import get_agent_identity_store

    identity = get_agent_identity_store().get(identity_id, tenant_id=tenant_id)
    if identity is None:
        raise HTTPException(status_code=404, detail="Managed identity not found")
    expected_blueprint = identity.blueprint_id.strip().lower().replace("-", "_")
    requested_blueprint = profile_id.strip().lower().replace("-", "_")
    if expected_blueprint != requested_blueprint:
        raise HTTPException(status_code=400, detail="Managed identity blueprint does not match profile_id")
    return identity


@router.post("/mcp-config/assignments", status_code=201, dependencies=[_dep("config")])
async def create_mcp_config_assignment(request: Request, body: McpConfigAssignmentCreate) -> dict[str, object]:
    """Assign a profile + connectors, yielding one distributable read-only config URL."""
    tenant_id = _tenant(request)
    _validate_references(
        tenant_id=tenant_id,
        profile_id=body.profile_id,
        connector_ids=body.connector_ids,
        connection_ids=body.connection_ids,
    )
    identity = _bound_identity(tenant_id=tenant_id, identity_id=body.identity_id, profile_id=body.profile_id)
    if identity is not None:
        if body.issuer not in ("", "agent-bom"):
            raise HTTPException(status_code=400, detail="Managed identities use the agent-bom issuer")
        if not body.environment:
            raise HTTPException(status_code=400, detail="environment is required for a managed identity binding")
    elif any((body.issuer, body.environment, body.allowed_tools, body.required_scopes, body.policy_ids, body.expires_at)):
        raise HTTPException(status_code=400, detail="Runtime profile constraints require identity_id")

    try:
        assignment = create_assignment(
            get_mcp_config_store(),
            tenant_id=tenant_id,
            name=body.name,
            profile_id=body.profile_id,
            connector_ids=body.connector_ids,
            connection_ids=body.connection_ids,
            created_by=_actor(request),
            identity_id=body.identity_id,
            issuer="agent-bom" if identity is not None else "",
            environment=body.environment,
            allowed_tools=body.allowed_tools,
            required_scopes=body.required_scopes,
            policy_ids=body.policy_ids,
            owner=(identity.owner if identity is not None else "") or _actor(request),
            expires_at=body.expires_at,
        )
    except McpConfigConflictError as exc:
        raise HTTPException(status_code=409, detail="Managed identity already has an active client profile") from exc
    log_action(
        "mcp_config.assignment_created",
        actor=_actor(request),
        resource=f"mcp-config/{assignment.config_id}",
        tenant_id=tenant_id,
        profile_id=body.profile_id,
        identity_id=body.identity_id,
        connector_count=len(body.connector_ids),
    )
    return {
        "schema_version": "mcp.client.config.v1",
        "assignment": assignment.to_public_dict(),
        "config_url": _config_url(assignment.config_id),
    }


@router.put("/mcp-config/assignments/{config_id}", dependencies=[_dep("config")])
async def update_mcp_config_assignment(
    request: Request,
    config_id: str,
    body: McpConfigAssignmentUpdate,
) -> dict[str, object]:
    """Replace a profile contract atomically when the expected revision matches."""
    current = _assignment_for_tenant(request, config_id)
    if current.revoked:
        raise HTTPException(status_code=409, detail="Revoked MCP-client-config assignments cannot be updated")
    # Reject a stale caller before validating replacement details. The store
    # repeats this check atomically, closing the race after this fast path.
    if current.revision != body.expected_revision:
        raise HTTPException(status_code=409, detail="MCP-client-config assignment revision is stale")
    tenant_id = _tenant(request)
    _validate_references(
        tenant_id=tenant_id,
        profile_id=body.profile_id,
        connector_ids=body.connector_ids,
        connection_ids=body.connection_ids,
    )
    identity = _bound_identity(tenant_id=tenant_id, identity_id=current.identity_id, profile_id=body.profile_id)
    if identity is not None and not body.environment:
        raise HTTPException(status_code=400, detail="environment is required for a managed identity binding")
    if identity is None and any(
        (body.environment, body.allowed_tools, body.required_scopes, body.policy_ids, body.expires_at)
    ):
        raise HTTPException(status_code=400, detail="Runtime profile constraints require identity_id")
    candidate = replace(
        current,
        name=body.name,
        profile_id=body.profile_id,
        connector_ids=body.connector_ids,
        connection_ids=body.connection_ids,
        environment=body.environment,
        allowed_tools=body.allowed_tools,
        required_scopes=body.required_scopes,
        policy_ids=body.policy_ids,
        expires_at=body.expires_at,
        updated_at=_now_iso(),
    )
    try:
        assignment = get_mcp_config_store().compare_and_swap(candidate, expected_revision=body.expected_revision)
    except McpConfigRevisionConflictError as exc:
        raise HTTPException(status_code=409, detail="MCP-client-config assignment revision is stale") from exc
    except McpConfigConflictError as exc:
        raise HTTPException(status_code=409, detail="MCP-client-config assignment conflicts with an active binding") from exc
    log_action(
        "mcp_config.assignment_updated",
        actor=_actor(request),
        resource=f"mcp-config/{assignment.config_id}",
        tenant_id=tenant_id,
        profile_id=assignment.profile_id,
        identity_id=assignment.identity_id,
        revision=assignment.revision,
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
