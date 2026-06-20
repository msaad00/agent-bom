"""Credential reference registry API routes."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Query, Request

from agent_bom.api.audit_log import log_action
from agent_bom.api.credential_rotation import build_credential_rotation_governance
from agent_bom.api.models import (
    CredentialRefCreate,
    CredentialRefRecord,
    CredentialRefStatus,
    CredentialRefUpdate,
)
from agent_bom.api.stores import _get_credential_ref_store
from agent_bom.api.tenancy import require_request_tenant_id

router = APIRouter()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _tenant_id(request: Request) -> str:
    return require_request_tenant_id(request)


def _actor(request: Request) -> str:
    return getattr(request.state, "api_key_name", "") or getattr(request.state, "auth_method", "") or "system"


def _credential_for_request(request: Request, credential_ref_id: str) -> CredentialRefRecord:
    credential = _get_credential_ref_store().get(credential_ref_id)
    tenant_id = _tenant_id(request)
    if credential is None or credential.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail=f"Credential reference {credential_ref_id} not found")
    return credential


def _apply_update(credential: CredentialRefRecord, body: CredentialRefUpdate) -> CredentialRefRecord:
    for field in (
        "display_name",
        "provider",
        "mode",
        "external_ref",
        "description",
        "owner",
        "scopes",
        "credential_class",
        "last_rotated_at",
        "expires_at",
        "rotation_interval_days",
        "max_age_days",
        "expiry_warning_days",
        "enabled",
        "status",
    ):
        value = getattr(body, field)
        if value is not None:
            setattr(credential, field, value)
    credential.updated_at = _now()
    if not credential.enabled:
        credential.status = CredentialRefStatus.DISABLED
    elif credential.status == CredentialRefStatus.DISABLED:
        credential.status = CredentialRefStatus.CONFIGURED
    return credential


@router.post("/v1/credentials", tags=["credentials"], status_code=201)
async def create_credential_ref(request: Request, body: CredentialRefCreate) -> dict:
    tenant_id = _tenant_id(request)
    if body.tenant_id not in ("default", tenant_id):
        raise HTTPException(status_code=403, detail="Forbidden — tenant_id must match the authenticated tenant")

    now = _now()
    credential = CredentialRefRecord(
        credential_ref_id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        display_name=body.display_name,
        provider=body.provider,
        mode=body.mode,
        external_ref=body.external_ref,
        description=body.description,
        owner=body.owner,
        scopes=body.scopes,
        credential_class=body.credential_class,
        last_rotated_at=body.last_rotated_at,
        expires_at=body.expires_at,
        rotation_interval_days=body.rotation_interval_days,
        max_age_days=body.max_age_days,
        expiry_warning_days=body.expiry_warning_days,
        enabled=body.enabled,
        status=CredentialRefStatus.CONFIGURED if body.enabled else CredentialRefStatus.DISABLED,
        created_at=now,
        updated_at=now,
    )
    _get_credential_ref_store().put(credential)
    log_action(
        "credential_ref.create",
        actor=_actor(request),
        resource=f"credential/{credential.credential_ref_id}",
        tenant_id=tenant_id,
        provider=credential.provider,
        mode=credential.mode,
    )
    return credential.model_dump()


@router.get("/v1/credentials", tags=["credentials"])
async def list_credential_refs(
    request: Request,
    limit: int = Query(1000, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> dict:
    tenant_id = _tenant_id(request)
    all_credentials = [credential.model_dump() for credential in _get_credential_ref_store().list_all(tenant_id=tenant_id)]
    total = len(all_credentials)
    page = all_credentials[offset : offset + limit]
    return {
        "schema_version": "v1",
        "credentials": page,
        "count": len(page),
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/v1/credentials/posture", tags=["credentials"])
async def get_credential_rotation_posture(request: Request) -> dict:
    tenant_id = _tenant_id(request)
    credentials = _get_credential_ref_store().list_all(tenant_id=tenant_id)
    return build_credential_rotation_governance(credentials, tenant_id=tenant_id)


@router.get("/v1/credentials/{credential_ref_id}", tags=["credentials"])
async def get_credential_ref(request: Request, credential_ref_id: str) -> dict:
    return _credential_for_request(request, credential_ref_id).model_dump()


@router.put("/v1/credentials/{credential_ref_id}", tags=["credentials"])
async def update_credential_ref(request: Request, credential_ref_id: str, body: CredentialRefUpdate) -> dict:
    credential = _apply_update(_credential_for_request(request, credential_ref_id), body)
    _get_credential_ref_store().put(credential)
    log_action(
        "credential_ref.update",
        actor=_actor(request),
        resource=f"credential/{credential_ref_id}",
        tenant_id=credential.tenant_id,
        enabled=credential.enabled,
        status=credential.status.value,
    )
    return credential.model_dump()


@router.post("/v1/credentials/{credential_ref_id}/test", tags=["credentials"])
async def test_credential_ref(request: Request, credential_ref_id: str) -> dict:
    credential = _credential_for_request(request, credential_ref_id)
    status = CredentialRefStatus.CONFIGURED if credential.enabled else CredentialRefStatus.DISABLED
    message = "Credential reference metadata recorded; secret material remains in the customer-managed store."
    credential.last_validated_at = _now()
    credential.last_validation_status = status.value
    credential.last_validation_message = message
    credential.status = status
    credential.updated_at = _now()
    _get_credential_ref_store().put(credential)
    log_action(
        "credential_ref.test",
        actor=_actor(request),
        resource=f"credential/{credential_ref_id}",
        tenant_id=credential.tenant_id,
        status=status.value,
    )
    return {
        "credential_ref_id": credential.credential_ref_id,
        "status": status.value,
        "message": message,
        "validated_at": credential.last_validated_at,
    }


@router.delete("/v1/credentials/{credential_ref_id}", tags=["credentials"], status_code=204)
async def delete_credential_ref(request: Request, credential_ref_id: str) -> None:
    credential = _credential_for_request(request, credential_ref_id)
    _get_credential_ref_store().delete(credential_ref_id)
    log_action(
        "credential_ref.delete",
        actor=_actor(request),
        resource=f"credential/{credential_ref_id}",
        tenant_id=credential.tenant_id,
        provider=credential.provider,
    )
