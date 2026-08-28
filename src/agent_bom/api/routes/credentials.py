"""Credential reference registry API routes."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Query, Request

from agent_bom.api.audit_log import log_action
from agent_bom.api.credential_ref_validation import validate_credential_ref
from agent_bom.api.credential_rotation import build_credential_rotation_governance
from agent_bom.api.models import (
    CredentialRefCreate,
    CredentialRefRecord,
    CredentialRefStatus,
    CredentialRefUpdate,
)
from agent_bom.api.stores import _get_credential_ref_store, _get_source_store
from agent_bom.api.tenancy import require_body_tenant_match, require_request_tenant_id
from agent_bom.api.tenant_quota import tenant_quota_guard
from agent_bom.security import value_looks_like_secret

router = APIRouter()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _tenant_id(request: Request) -> str:
    return require_request_tenant_id(request)


def _actor(request: Request) -> str:
    return getattr(request.state, "api_key_name", "") or getattr(request.state, "auth_method", "") or "system"


def _credential_for_request(request: Request, credential_ref_id: str) -> CredentialRefRecord:
    tenant_id = _tenant_id(request)
    credential = _get_credential_ref_store().get(credential_ref_id, tenant_id=tenant_id)
    if credential is None or credential.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail=f"Credential reference {credential_ref_id} not found")
    return credential


def _public_credential(credential: CredentialRefRecord) -> dict:
    payload = credential.model_dump()
    if value_looks_like_secret(credential.external_ref):
        payload["external_ref"] = "<redacted-secret-reference>"
    return payload


def _validate_external_ref(external_ref: str | None) -> None:
    if external_ref is not None and value_looks_like_secret(external_ref):
        raise HTTPException(
            status_code=422,
            detail="external_ref must identify customer-managed credential metadata, never credential material",
        )


def _apply_update(credential: CredentialRefRecord, body: CredentialRefUpdate) -> CredentialRefRecord:
    credential = credential.model_copy(deep=True)
    nullable_lifecycle_fields = {
        "external_ref",
        "last_rotated_at",
        "expires_at",
        "rotation_interval_days",
        "max_age_days",
        "expiry_warning_days",
    }
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
        if field not in body.model_fields_set:
            continue
        value = getattr(body, field)
        if value is not None or field in nullable_lifecycle_fields:
            setattr(credential, field, value)
    credential.updated_at = _now()
    if not credential.enabled:
        credential.status = CredentialRefStatus.DISABLED
    elif credential.status == CredentialRefStatus.DISABLED:
        credential.status = CredentialRefStatus.CONFIGURED
    return credential


@router.post("/credentials", tags=["credentials"], status_code=201)
async def create_credential_ref(request: Request, body: CredentialRefCreate) -> dict:
    tenant_id = _tenant_id(request)
    require_body_tenant_match(body.tenant_id, tenant_id)
    _validate_external_ref(body.external_ref)

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
    with tenant_quota_guard(tenant_id):
        _get_credential_ref_store().put(credential)
    log_action(
        "credential_ref.create",
        actor=_actor(request),
        resource=f"credential/{credential.credential_ref_id}",
        tenant_id=tenant_id,
        provider=credential.provider,
        mode=credential.mode,
    )
    return _public_credential(credential)


@router.get("/credentials", tags=["credentials"])
async def list_credential_refs(
    request: Request,
    limit: int = Query(1000, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> dict:
    tenant_id = _tenant_id(request)
    all_credentials = [_public_credential(credential) for credential in _get_credential_ref_store().list_all(tenant_id=tenant_id)]
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


@router.get("/credentials/posture", tags=["credentials"], deprecated=True)
async def get_credential_rotation_posture(request: Request) -> dict:
    """Credential rotation posture rollup for the request tenant.

    Soft-deprecated: no UI/CLI/MCP product consumer (#3666 Phase 2).
    """
    tenant_id = _tenant_id(request)
    credentials = _get_credential_ref_store().list_all(tenant_id=tenant_id)
    return build_credential_rotation_governance(credentials, tenant_id=tenant_id)


@router.get("/credentials/{credential_ref_id}", tags=["credentials"])
async def get_credential_ref(request: Request, credential_ref_id: str) -> dict:
    return _public_credential(_credential_for_request(request, credential_ref_id))


@router.put("/credentials/{credential_ref_id}", tags=["credentials"])
async def update_credential_ref(request: Request, credential_ref_id: str, body: CredentialRefUpdate) -> dict:
    tenant_id = _tenant_id(request)
    _validate_external_ref(body.external_ref if "external_ref" in body.model_fields_set else None)
    if body.status == CredentialRefStatus.RETIRED:
        raise HTTPException(status_code=422, detail="Use DELETE to retire a credential reference")
    with tenant_quota_guard(tenant_id):
        current = _credential_for_request(request, credential_ref_id)
        if current.status == CredentialRefStatus.RETIRED:
            raise HTTPException(status_code=409, detail="Retired credential references are immutable")
        credential = _apply_update(current, body)
        _get_credential_ref_store().put(credential)
    log_action(
        "credential_ref.update",
        actor=_actor(request),
        resource=f"credential/{credential_ref_id}",
        tenant_id=credential.tenant_id,
        enabled=credential.enabled,
        status=credential.status.value,
    )
    return _public_credential(credential)


@router.post("/credentials/{credential_ref_id}/test", tags=["credentials"])
async def test_credential_ref(request: Request, credential_ref_id: str) -> dict:
    tenant_id = _tenant_id(request)
    with tenant_quota_guard(tenant_id):
        credential = _credential_for_request(request, credential_ref_id)
        if credential.status == CredentialRefStatus.RETIRED:
            raise HTTPException(status_code=409, detail="Retired credential references cannot be tested")
        status, message = validate_credential_ref(credential)
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


@router.delete("/credentials/{credential_ref_id}", tags=["credentials"], status_code=204)
async def delete_credential_ref(request: Request, credential_ref_id: str) -> None:
    tenant_id = _tenant_id(request)
    already_retired = False
    retired_legacy_secret_purged = False
    with tenant_quota_guard(tenant_id):
        credential = _credential_for_request(request, credential_ref_id)
        if credential.status == CredentialRefStatus.RETIRED:
            already_retired = True
            if value_looks_like_secret(credential.external_ref):
                credential.external_ref = None
                credential.updated_at = _now()
                _get_credential_ref_store().put(credential)
                retired_legacy_secret_purged = True
        else:
            attached_sources = [
                source
                for source in _get_source_store().list_all(tenant_id=credential.tenant_id)
                if source.credential_ref == credential_ref_id
            ]
            if attached_sources:
                count = len(attached_sources)
                noun = "source" if count == 1 else "sources"
                raise HTTPException(
                    status_code=409,
                    detail=f"Credential reference is attached to {count} {noun}; detach it before retiring the reference",
                )
            credential.enabled = False
            credential.status = CredentialRefStatus.RETIRED
            # Older releases could persist credential material in this metadata
            # field. Retirement is terminal, so scrub detected legacy material
            # before making the record immutable; otherwise no later API call can
            # remove the secret from durable storage.
            if value_looks_like_secret(credential.external_ref):
                credential.external_ref = None
            credential.updated_at = _now()
            _get_credential_ref_store().put(credential)
    if already_retired:
        if retired_legacy_secret_purged:
            log_action(
                "credential_ref.retired_legacy_secret_purge",
                actor=_actor(request),
                resource=f"credential/{credential_ref_id}",
                tenant_id=credential.tenant_id,
                provider=credential.provider,
            )
        return
    log_action(
        "credential_ref.retire",
        actor=_actor(request),
        resource=f"credential/{credential_ref_id}",
        tenant_id=credential.tenant_id,
        provider=credential.provider,
    )
