"""Per-tenant cloud connections plane — CRUD over read-only cloud connections.

A *connection* is a stored, encrypted, tenant-scoped record of how the control
plane reaches a customer's cloud account in read-only mode: the role it assumes
plus the encrypted ``ExternalId`` (or provider equivalent) the credential broker
presents. These endpoints manage that record; the secret is encrypted at rest
and is **never** returned in any response.

Every endpoint enforces the same gate the sibling cloud routes use:
``require_request_tenant_id`` plus the ``scan`` permission ({admin, analyst})
via the shared RBAC dependency, so there is no unauthenticated access and an
under-privileged role is rejected with 403. Reads and deletes are tenant-scoped:
a tenant can only see or remove its own connections.

Endpoints:
    POST   /v1/cloud/connections        create a connection (encrypts the secret)
    GET    /v1/cloud/connections        list this tenant's connections
    GET    /v1/cloud/connections/{id}   one connection (non-secret metadata)
    DELETE /v1/cloud/connections/{id}   remove a connection
"""

from __future__ import annotations

import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from agent_bom.api.audit_log import log_action
from agent_bom.api.connection_crypto import ConnectionSecretError, connections_key_configured, encrypt_secret
from agent_bom.api.connection_store import (
    STATUS_PENDING,
    SUPPORTED_PROVIDERS,
    CloudConnectionRecord,
    get_connection_store,
)
from agent_bom.api.tenancy import require_request_tenant_id
from agent_bom.rbac import require_authenticated_permission

router = APIRouter(tags=["cloud-connections"])
_logger = logging.getLogger(__name__)

# Same RBAC gate the sibling cloud scan routes use — a scan-class action.
_SCAN_DEP = require_authenticated_permission("scan")

_REGION_RE = re.compile(r"[a-z]{2}(-gov)?-[a-z]+-\d{1,2}")
_MAX_REGIONS = 50


class CloudConnectionCreate(BaseModel):
    """Request body for creating a connection. ``external_id`` is write-only."""

    model_config = ConfigDict(extra="forbid")

    provider: str
    display_name: str = Field(min_length=1, max_length=200)
    role_ref: str = Field(min_length=1, max_length=2048)
    external_id: str = Field(min_length=1, max_length=1024)
    regions: list[str] = Field(default_factory=list)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _tenant(request: Request) -> str:
    return require_request_tenant_id(request)


def _actor(request: Request) -> str:
    return getattr(request.state, "api_key_name", "") or getattr(request.state, "auth_method", "") or "system"


def _validate_regions(regions: list[str]) -> list[str]:
    cleaned = [r.strip() for r in regions if r.strip()]
    if len(cleaned) > _MAX_REGIONS:
        raise HTTPException(status_code=400, detail=f"Too many regions (max {_MAX_REGIONS}).")
    for region in cleaned:
        if not _REGION_RE.fullmatch(region):
            raise HTTPException(status_code=400, detail=f"Invalid region format: {region}")
    return cleaned


@router.post("/v1/cloud/connections", status_code=201)
async def create_connection(request: Request, body: CloudConnectionCreate, _role: Any = _SCAN_DEP) -> dict[str, Any]:
    """Create a read-only cloud connection for the authenticated tenant.

    The ``external_id`` secret is encrypted at rest before persistence and is
    never echoed back. If no encryption key is configured the request fails
    closed with 503 rather than storing the secret in plaintext.
    """
    tenant_id = _tenant(request)
    provider = body.provider.strip().lower()
    if provider not in SUPPORTED_PROVIDERS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported provider '{body.provider}'. Use one of: {', '.join(SUPPORTED_PROVIDERS)}.",
        )

    regions = _validate_regions(body.regions)

    # Fail closed before doing anything if the store cannot encrypt the secret.
    if not connections_key_configured():
        raise HTTPException(
            status_code=503,
            detail="Connection secret encryption is not configured (AGENT_BOM_CONNECTIONS_KEY unset); refusing to store a secret.",
        )
    try:
        external_id_encrypted = encrypt_secret(body.external_id.strip())
    except ConnectionSecretError as exc:
        # Never echo the secret or key detail — only the failure mode.
        _logger.warning("Connection secret encryption unavailable")
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    now = _now()
    record = CloudConnectionRecord(
        id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        provider=provider,
        display_name=body.display_name.strip(),
        role_ref=body.role_ref.strip(),
        external_id_encrypted=external_id_encrypted,
        regions=regions,
        status=STATUS_PENDING,
        status_detail="",
        created_at=now,
        updated_at=now,
        last_scan_at=None,
    )
    get_connection_store().put(record)
    log_action(
        "cloud_connection.create",
        actor=_actor(request),
        resource=f"cloud-connection/{record.id}",
        tenant_id=tenant_id,
        provider=record.provider,
    )
    return record.to_public_dict()


@router.get("/v1/cloud/connections")
async def list_connections(request: Request, _role: Any = _SCAN_DEP) -> dict[str, Any]:
    """List the authenticated tenant's connections (non-secret metadata only)."""
    tenant_id = _tenant(request)
    records = get_connection_store().list_for_tenant(tenant_id)
    return {
        "schema_version": "cloud.connections.v1",
        "tenant_id": tenant_id,
        "connections": [r.to_public_dict() for r in records],
        "count": len(records),
    }


def _require_connection(request: Request, connection_id: str) -> CloudConnectionRecord:
    tenant_id = _tenant(request)
    record = get_connection_store().get(tenant_id, connection_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"Connection {connection_id} not found")
    return record


@router.get("/v1/cloud/connections/{connection_id}")
async def get_connection(request: Request, connection_id: str, _role: Any = _SCAN_DEP) -> dict[str, Any]:
    """Return one connection's non-secret metadata (tenant-scoped)."""
    return _require_connection(request, connection_id).to_public_dict()


@router.delete("/v1/cloud/connections/{connection_id}", status_code=204)
async def delete_connection(request: Request, connection_id: str, _role: Any = _SCAN_DEP) -> None:
    """Delete a connection owned by the authenticated tenant."""
    record = _require_connection(request, connection_id)
    get_connection_store().delete(record.tenant_id, record.id)
    log_action(
        "cloud_connection.delete",
        actor=_actor(request),
        resource=f"cloud-connection/{record.id}",
        tenant_id=record.tenant_id,
        provider=record.provider,
    )
