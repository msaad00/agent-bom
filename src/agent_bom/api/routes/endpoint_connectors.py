"""Authenticated endpoint connection lifecycle using the shared collection service."""

from __future__ import annotations

from typing import Any, cast

from fastapi import APIRouter, HTTPException, Query, Request

from agent_bom.api.audit_log import log_action
from agent_bom.api.connection_crypto import ConnectionSecretError
from agent_bom.api.tenancy import require_request_tenant_id
from agent_bom.connectors.endpoints.models import (
    AgentBinding,
    Connection,
    ConnectionCreate,
    ConnectionList,
    ConnectionUpdate,
    DevicePage,
    SyncRequest,
    SyncState,
)
from agent_bom.connectors.endpoints.service import connection_list, create_connection, device_page, sync_connection
from agent_bom.connectors.endpoints.store import EndpointStore
from agent_bom.connectors.endpoints.transport import CollectionError
from agent_bom.rbac import require_authenticated_permission

router = APIRouter(prefix="/endpoint-connectors", tags=["endpoint-connectors"])


def _permission(name: str) -> Any:
    return cast(Any, require_authenticated_permission(name))


def _audit(request: Request, action: str, connection_id: str, **details: object) -> None:
    log_action(
        action,
        tenant_id=require_request_tenant_id(request),
        actor=getattr(request.state, "api_key_name", "") or "api",
        resource=f"endpoint-connector/{connection_id}",
        **details,
    )


@router.get("", response_model=ConnectionList, dependencies=[_permission("read")])
def list_connections(request: Request) -> dict:
    return connection_list(EndpointStore(), require_request_tenant_id(request))


@router.post("", status_code=201, response_model=Connection, dependencies=[_permission("config")])
def connect(request: Request, body: ConnectionCreate) -> Connection:
    try:
        result = create_connection(EndpointStore(), require_request_tenant_id(request), body)
    except ConnectionSecretError:
        raise HTTPException(status_code=503, detail="Connection encryption is unavailable") from None
    except CollectionError as exc:
        raise HTTPException(status_code=409, detail=exc.args[0]) from None
    _audit(request, "endpoint_connector.created", result.id, provider=result.provider)
    return result


@router.post("/{connection_id}/sync", response_model=SyncState, dependencies=[_permission("config")])
def sync(request: Request, connection_id: str, body: SyncRequest) -> SyncState:
    try:
        result = sync_connection(EndpointStore(), require_request_tenant_id(request), connection_id, body)
    except CollectionError as exc:
        raise HTTPException(status_code=404 if exc.args[0] == "connection_not_found" else 409, detail=exc.args[0]) from None
    except ConnectionSecretError:
        raise HTTPException(status_code=503, detail="Connection encryption is unavailable") from None
    _audit(request, "endpoint_connector.synced", connection_id, status=result.status, count=result.device_count, gap=result.gap)
    return result


@router.get("/{connection_id}/devices", response_model=DevicePage, dependencies=[_permission("read")])
def devices(request: Request, connection_id: str, limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)) -> dict:
    try:
        return device_page(EndpointStore(), require_request_tenant_id(request), connection_id, limit=limit, offset=offset)
    except CollectionError:
        raise HTTPException(status_code=404, detail="Endpoint connection not found") from None


@router.patch("/{connection_id}", response_model=Connection, dependencies=[_permission("config")])
def update(request: Request, connection_id: str, body: ConnectionUpdate) -> Connection:
    from agent_bom.api.connection_crypto import encrypt_secret

    store = EndpointStore()
    tenant = require_request_tenant_id(request)
    record = store.get(tenant, connection_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Endpoint connection not found")
    connection, encrypted = record
    try:
        if body.client_secret is not None:
            encrypted = encrypt_secret(body.client_secret.get_secret_value())
        if body.enabled is not None:
            connection.enabled = body.enabled
        store.update(connection, encrypted)
    except ConnectionSecretError:
        raise HTTPException(status_code=503, detail="Connection encryption is unavailable") from None
    except CollectionError:
        raise HTTPException(status_code=409, detail="Wait for the active sync before updating credentials or connection state") from None
    _audit(request, "endpoint_connector.updated", connection_id, enabled=connection.enabled, secret_rotated=body.client_secret is not None)
    return connection


@router.put("/devices/{device_id}/agent-binding", dependencies=[_permission("config")])
def bind_agent(request: Request, device_id: str, body: AgentBinding) -> dict:
    from agent_bom.api.stores import _get_fleet_store
    from agent_bom.connectors.endpoints.models import now

    store = EndpointStore()
    tenant = require_request_tenant_id(request)
    signal = store.current_device(tenant, device_id)
    agent = _get_fleet_store().get(body.agent_id, tenant_id=tenant)
    if signal is None or agent is None:
        raise HTTPException(status_code=404, detail="Current device evidence or fleet agent not found in this tenant")
    binding = {
        "agent_id": agent.agent_id,
        "canonical_id": agent.canonical_id,
        "active": body.active,
        "assurance": "operator_recorded",
        "recorded_at": now(),
    }
    try:
        store.bind_agent(tenant, device_id, agent.agent_id, binding)
    except CollectionError as exc:
        raise HTTPException(status_code=409, detail=exc.args[0]) from None
    _audit(
        request,
        "endpoint_connector.agent_binding_recorded",
        str(signal.attributes["connection_id"]),
        device_id=device_id,
        agent_id=agent.agent_id,
        active=body.active,
        assurance="operator_recorded",
    )
    return binding
