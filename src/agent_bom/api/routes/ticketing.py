"""Per-tenant ITSM ticketing plane — connect once, then file/sync through it.

Manages the stored, encrypted, tenant-scoped ticketing connection and the
finding→ticket actions that run **through** it. No endpoint ever accepts a
credential, token, or base URL for an *action*: creating a ticket takes a
finding + target project and resolves auth/endpoint from the stored connection
(the platform connect-once invariant). The connection's secret is encrypted at
rest and never returned.

Endpoints:
    POST   /v1/ticketing/connections            create a connection (seals the secret once)
    GET    /v1/ticketing/connections            list this tenant's connections
    GET    /v1/ticketing/connections/{id}       one connection (non-secret metadata)
    DELETE /v1/ticketing/connections/{id}       revoke a connection
    POST   /v1/ticketing/tickets                file a ticket for a finding via a connection
    GET    /v1/ticketing/tickets                list this tenant's filed tickets
    POST   /v1/ticketing/tickets/{id}/sync      refresh a ticket's status from its ITSM

The primary transport is MCP-client (agent-bom drives a configured ITSM MCP
server). A direct-REST Jira adapter (API token / OAuth bearer) is available
behind the same interface. OAuth 3LO browser connect, ServiceNow REST, and the
UI action button are tracked follow-ups (see #4004).
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from agent_bom.api.audit_log import log_action
from agent_bom.api.connection_crypto import ConnectionSecretError, connections_key_configured, encrypt_secret
from agent_bom.api.tenancy import require_request_tenant_id
from agent_bom.rbac import require_authenticated_permission
from agent_bom.security import sanitize_error, validate_url
from agent_bom.ticketing.connection_store import get_ticketing_store
from agent_bom.ticketing.models import (
    AUTH_API_TOKEN,
    AUTH_MCP,
    STATUS_ACTIVE,
    SUPPORTED_TICKETING_PROVIDERS,
    TRANSPORT_MCP,
    TRANSPORT_REST,
    TicketingConnectionRecord,
)
from agent_bom.ticketing.service import TicketingError, create_ticket_for_finding, sync_ticket_status

router = APIRouter(tags=["ticketing"])
_logger = logging.getLogger(__name__)

_READ_DEP = require_authenticated_permission("read")
_WRITE_DEP = require_authenticated_permission("scan")

_MAX_AUTH_PARAMS = 20
_MAX_PARAM_LEN = 1024
# Connect-time auth methods accepted by this endpoint. OAuth (3LO) is connected
# through the dedicated browser flow (follow-up), not by posting a token here.
_ACCEPTED_AUTH_METHODS = (AUTH_MCP, AUTH_API_TOKEN)

# Map a service error code to an HTTP status.
_ERROR_STATUS = {
    "no_connection": 409,
    "ambiguous_connection": 409,
    "not_found": 404,
    "missing_project": 400,
    "missing_finding_id": 400,
    "secret_unavailable": 503,
    "transport_error": 502,
}


class TicketingConnectionCreate(BaseModel):
    """Create a connect-once ITSM connection. ``secret`` is write-only.

    ``transport=mcp`` (primary): ``endpoint`` is the ITSM MCP server URL and
    ``secret`` (optional) is its bearer token. ``transport=rest`` +
    ``auth_method=api_token``: ``endpoint`` is the site URL, ``secret`` is the
    API token, and ``auth_params.email`` is the account email.
    """

    model_config = ConfigDict(extra="forbid")

    provider: str
    transport: str = TRANSPORT_MCP
    auth_method: str = AUTH_MCP
    display_name: str = Field(min_length=1, max_length=200)
    endpoint: str = Field(min_length=1, max_length=2048)
    secret: str = Field(default="", max_length=8192)
    auth_params: dict[str, str] = Field(default_factory=dict)


class TicketCreate(BaseModel):
    """File a ticket for a finding through a stored connection.

    Deliberately carries NO credential, token, or base-URL/link field — auth and
    endpoint come only from the stored connection.
    """

    model_config = ConfigDict(extra="forbid")

    connection_id: str = ""
    finding_id: str = ""
    project: str = ""
    issue_type: str = ""
    source_url: str = Field(default="", max_length=2048)
    finding: dict[str, Any] = Field(default_factory=dict)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _tenant(request: Request) -> str:
    return require_request_tenant_id(request)


def _actor(request: Request) -> str:
    return getattr(request.state, "api_key_name", "") or getattr(request.state, "auth_method", "") or "system"


def _validate_auth_params(auth_params: dict[str, str]) -> dict[str, str]:
    if not auth_params:
        return {}
    if len(auth_params) > _MAX_AUTH_PARAMS:
        raise HTTPException(status_code=400, detail=f"Too many auth_params (max {_MAX_AUTH_PARAMS}).")
    cleaned: dict[str, str] = {}
    for key, value in auth_params.items():
        key_str = str(key).strip()
        if not key_str:
            continue
        value_str = str(value).strip()
        if len(value_str) > _MAX_PARAM_LEN:
            raise HTTPException(status_code=400, detail=f"auth_params value too long (max {_MAX_PARAM_LEN}).")
        cleaned[key_str] = value_str
    return cleaned


@router.post("/ticketing/connections", status_code=201)
async def create_connection(request: Request, body: TicketingConnectionCreate, _role: Any = _WRITE_DEP) -> dict[str, Any]:
    """Create a connect-once ITSM connection for the tenant (seals the secret)."""
    tenant_id = _tenant(request)
    provider = body.provider.strip().lower()
    transport = body.transport.strip().lower()
    auth_method = body.auth_method.strip().lower()
    if provider not in SUPPORTED_TICKETING_PROVIDERS:
        raise HTTPException(
            status_code=400, detail=f"Unsupported provider '{body.provider}'. Use one of: {', '.join(SUPPORTED_TICKETING_PROVIDERS)}."
        )
    if transport not in (TRANSPORT_MCP, TRANSPORT_REST):
        raise HTTPException(status_code=400, detail=f"Unsupported transport '{body.transport}'. Use 'mcp' or 'rest'.")
    if auth_method not in _ACCEPTED_AUTH_METHODS:
        raise HTTPException(
            status_code=400,
            detail="Unsupported auth_method here. Use 'mcp' or 'api_token'; OAuth (3LO) connects via the dedicated flow.",
        )

    endpoint = body.endpoint.strip()
    try:
        validate_url(endpoint)
    except Exception as exc:  # noqa: BLE001 - SSRF/format rejection
        raise HTTPException(status_code=400, detail=f"Invalid endpoint URL: {sanitize_error(exc)}") from exc

    auth_params = _validate_auth_params(body.auth_params)
    if transport == TRANSPORT_REST and auth_method == AUTH_API_TOKEN:
        if not auth_params.get("email"):
            raise HTTPException(status_code=400, detail="A REST api_token connection requires auth_params.email.")
        if not body.secret.strip():
            raise HTTPException(status_code=400, detail="A REST api_token connection requires a secret (the API token).")

    secret_encrypted = ""
    if body.secret.strip():
        if not connections_key_configured():
            raise HTTPException(
                status_code=503,
                detail="Connection secret encryption is not configured (AGENT_BOM_CONNECTIONS_KEY unset); refusing to store a secret.",
            )
        try:
            secret_encrypted = encrypt_secret(body.secret.strip())
        except ConnectionSecretError as exc:
            _logger.warning("Ticketing secret encryption unavailable")
            raise HTTPException(status_code=503, detail=sanitize_error(exc, generic=True)) from exc

    now = _now()
    record = TicketingConnectionRecord(
        id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        provider=provider,
        transport=transport,
        auth_method=auth_method,
        display_name=body.display_name.strip(),
        endpoint=endpoint,
        secret_encrypted=secret_encrypted,
        auth_params=auth_params,
        status=STATUS_ACTIVE,
        created_at=now,
        updated_at=now,
    )
    get_ticketing_store().put_connection(record)
    log_action(
        "ticketing_connection.create",
        actor=_actor(request),
        resource=f"ticketing-connection/{record.id}",
        tenant_id=tenant_id,
        provider=record.provider,
        transport=record.transport,
    )
    return record.to_public_dict()


@router.get("/ticketing/connections")
async def list_connections(request: Request, _role: Any = _READ_DEP) -> dict[str, Any]:
    """List the tenant's ticketing connections (non-secret metadata only)."""
    tenant_id = _tenant(request)
    records = get_ticketing_store().list_connections(tenant_id)
    return {
        "schema_version": "ticketing.connections.v1",
        "tenant_id": tenant_id,
        "connections": [r.to_public_dict() for r in records],
        "count": len(records),
    }


@router.get("/ticketing/connections/{connection_id}")
async def get_connection(request: Request, connection_id: str, _role: Any = _READ_DEP) -> dict[str, Any]:
    """Return one ticketing connection's non-secret metadata (tenant-scoped)."""
    tenant_id = _tenant(request)
    record = get_ticketing_store().get_connection(tenant_id, connection_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"Connection {connection_id} not found")
    return record.to_public_dict()


@router.delete("/ticketing/connections/{connection_id}", status_code=204)
async def delete_connection(request: Request, connection_id: str, _role: Any = _WRITE_DEP) -> None:
    """Revoke a ticketing connection owned by the tenant."""
    tenant_id = _tenant(request)
    store = get_ticketing_store()
    record = store.get_connection(tenant_id, connection_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"Connection {connection_id} not found")
    store.delete_connection(tenant_id, connection_id)
    log_action(
        "ticketing_connection.delete",
        actor=_actor(request),
        resource=f"ticketing-connection/{connection_id}",
        tenant_id=tenant_id,
        provider=record.provider,
    )


@router.post("/ticketing/tickets", status_code=201)
async def create_ticket(request: Request, body: TicketCreate, _role: Any = _WRITE_DEP) -> dict[str, Any]:
    """File a ticket for a finding through the stored connection (idempotent)."""
    tenant_id = _tenant(request)
    if not body.finding:
        raise HTTPException(status_code=400, detail="A 'finding' object is required to file a ticket.")
    try:
        return await create_ticket_for_finding(
            tenant_id=tenant_id,
            connection_id=body.connection_id.strip(),
            finding=body.finding,
            project=body.project.strip(),
            finding_id=body.finding_id.strip(),
            issue_type=body.issue_type.strip(),
            source_url=body.source_url.strip(),
            actor=_actor(request),
        )
    except TicketingError as exc:
        raise HTTPException(status_code=_ERROR_STATUS.get(exc.code, 400), detail=str(exc)) from exc


@router.get("/ticketing/tickets")
async def list_tickets(request: Request, _role: Any = _READ_DEP) -> dict[str, Any]:
    """List the tenant's filed tickets (finding→ticket links + last status)."""
    tenant_id = _tenant(request)
    links = get_ticketing_store().list_ticket_links(tenant_id)
    return {
        "schema_version": "ticketing.tickets.v1",
        "tenant_id": tenant_id,
        "tickets": [link.to_public_dict() for link in links],
        "count": len(links),
    }


@router.post("/ticketing/tickets/{ticket_id}/sync")
async def sync_ticket(request: Request, ticket_id: str, _role: Any = _WRITE_DEP) -> dict[str, Any]:
    """Refresh a filed ticket's status from its ITSM, through the connection."""
    tenant_id = _tenant(request)
    try:
        return await sync_ticket_status(tenant_id=tenant_id, ticket_id=ticket_id, actor=_actor(request))
    except TicketingError as exc:
        raise HTTPException(status_code=_ERROR_STATUS.get(exc.code, 400), detail=str(exc)) from exc
