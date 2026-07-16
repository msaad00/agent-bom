"""Per-tenant model-provider key broker plane (#3907).

The model-key analogue of the cloud-connection broker. An operator registers a
*real* model-provider credential (OpenAI, Anthropic, Azure OpenAI, Bedrock, …)
**once**; agent-bom then mints **virtual keys** that map to it without ever
exposing it, are scoped (holder + optional model allowlist), time-boxed, and
independently revocable. Usage is attributed to the holding virtual key.

Security contract (identical posture to the connection broker):
    - The real provider key is write-only: sealed at rest with the shared
      connection-secret crypto and **never** returned in any response or log.
    - A virtual key's raw ``abvk_`` token is returned exactly once at mint time;
      only its hash is stored.
    - Resolution to the real key happens **server-side** only. The public
      ``/authorize`` endpoint validates scope + revocation + expiry and returns an
      authorization DECISION (provider, holder, provider-key id) — never the real
      key. It is the only surface that touches the real key, and it strips it.
    - Every endpoint is tenant-scoped and RBAC-gated. Reads require ``read``;
      mutations (register / mint / revoke / delete / authorize) require ``scan``.
    - Every mutation is audit-logged (secret-free).

Endpoints:
    POST   /v1/model-keys/providers                          register a real provider key
    GET    /v1/model-keys/providers                          list registered provider keys
    GET    /v1/model-keys/providers/{id}                     one provider key (non-secret)
    DELETE /v1/model-keys/providers/{id}                     delete a provider key
    POST   /v1/model-keys/providers/{id}/virtual-keys        mint a scoped virtual key
    GET    /v1/model-keys/virtual-keys                        list virtual keys
    POST   /v1/model-keys/virtual-keys/{id}/revoke           revoke a virtual key
    POST   /v1/model-keys/authorize                          authorize a virtual key (decision only)
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from agent_bom.api.audit_log import log_action
from agent_bom.api.model_key_broker import (
    DEFAULT_VK_TTL_SECONDS,
    MAX_VK_TTL_SECONDS,
    MIN_VK_TTL_SECONDS,
    SUPPORTED_MODEL_PROVIDERS,
    ModelKeyBrokerError,
    get_model_key_broker_store,
    mint_virtual_key,
    register_provider_key,
    resolve_virtual_key,
    revoke_virtual_key,
)
from agent_bom.api.tenancy import require_request_tenant_id
from agent_bom.rbac import require_authenticated_permission
from agent_bom.security import sanitize_error

router = APIRouter(tags=["model-keys"])
_logger = logging.getLogger(__name__)

_READ_DEP = require_authenticated_permission("read")
_SCAN_DEP = require_authenticated_permission("scan")

_MAX_ALLOWED_MODELS = 50
_MAX_MODEL_LEN = 128

# Resolution-failure reason -> HTTP status. Unknown/wrong-tenant is a 404; scope,
# revocation, and expiry are 403 (the caller is authenticated but not authorized
# for this call); a broken underlying provider key is a 409/502.
_RESOLVE_STATUS: dict[str, int] = {
    "not_found": 404,
    "revoked": 403,
    "expired": 403,
    "provider_mismatch": 403,
    "model_not_allowed": 403,
    "holder_mismatch": 403,
    "provider_key_missing": 409,
    "provider_key_disabled": 409,
    "sealing_failed": 502,
}


class ProviderKeyCreate(BaseModel):
    """Register a real provider key. ``api_key`` is write-only."""

    model_config = ConfigDict(extra="forbid")

    provider: str
    display_name: str = Field(min_length=1, max_length=200)
    api_key: str = Field(min_length=1, max_length=8192)
    owner: str = Field(default="", max_length=200)
    owner_type: str = Field(default="", max_length=60)


class VirtualKeyMint(BaseModel):
    """Mint a scoped virtual key against a registered provider key."""

    model_config = ConfigDict(extra="forbid")

    holder_id: str = Field(min_length=1, max_length=200)
    holder_type: str = Field(default="", max_length=60)
    allowed_models: list[str] = Field(default_factory=list)
    ttl_seconds: int = DEFAULT_VK_TTL_SECONDS
    owner: str = Field(default="", max_length=200)
    owner_type: str = Field(default="", max_length=60)


class VirtualKeyRevoke(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(default="", max_length=500)


class VirtualKeyAuthorize(BaseModel):
    """Authorize a virtual key for a specific provider/model call (decision only)."""

    model_config = ConfigDict(extra="forbid")

    virtual_key: str = Field(min_length=1, max_length=4096)
    provider: str = Field(min_length=1, max_length=64)
    model: str = Field(min_length=1, max_length=_MAX_MODEL_LEN)
    holder_id: str = Field(default="", max_length=200)


def _tenant(request: Request) -> str:
    return require_request_tenant_id(request)


def _actor(request: Request) -> str:
    return getattr(request.state, "api_key_name", "") or getattr(request.state, "auth_method", "") or "system"


def _validate_models(models: list[str]) -> list[str]:
    cleaned = [m.strip() for m in models if m and m.strip()]
    if len(cleaned) > _MAX_ALLOWED_MODELS:
        raise HTTPException(status_code=400, detail=f"Too many allowed_models (max {_MAX_ALLOWED_MODELS}).")
    for model in cleaned:
        if len(model) > _MAX_MODEL_LEN:
            raise HTTPException(status_code=400, detail=f"allowed_models entry too long (max {_MAX_MODEL_LEN}).")
    return cleaned


@router.post("/model-keys/providers", status_code=201)
async def create_provider_key(request: Request, body: ProviderKeyCreate, _role: Any = _SCAN_DEP) -> dict[str, Any]:
    """Register (seal) a real provider key for the authenticated tenant.

    The ``api_key`` is encrypted at rest and never echoed back. Fails closed with
    503 when no sealing key is configured, rather than storing plaintext.
    """
    tenant_id = _tenant(request)
    try:
        record = register_provider_key(
            get_model_key_broker_store(),
            tenant_id=tenant_id,
            provider=body.provider,
            display_name=body.display_name,
            api_key=body.api_key,
            owner=body.owner,
            owner_type=body.owner_type,
        )
    except ModelKeyBrokerError as exc:
        status = 503 if exc.reason in ("sealing_unconfigured", "sealing_failed") else 400
        raise HTTPException(status_code=status, detail=sanitize_error(exc, generic=False)) from exc

    log_action(
        "model_key.provider.register",
        actor=_actor(request),
        resource=f"model-provider-key/{record.provider_key_id}",
        tenant_id=tenant_id,
        provider=record.provider,
    )
    return record.to_public_dict()


@router.get("/model-keys/providers")
async def list_provider_keys(request: Request, _role: Any = _READ_DEP) -> dict[str, Any]:
    """List the tenant's registered provider keys (non-secret metadata only)."""
    tenant_id = _tenant(request)
    records = get_model_key_broker_store().list_provider_keys(tenant_id)
    return {
        "schema_version": "model_keys.providers.v1",
        "tenant_id": tenant_id,
        "provider_keys": [r.to_public_dict() for r in records],
        "count": len(records),
        "supported_providers": list(SUPPORTED_MODEL_PROVIDERS),
    }


@router.get("/model-keys/providers/{provider_key_id}")
async def get_provider_key(request: Request, provider_key_id: str, _role: Any = _READ_DEP) -> dict[str, Any]:
    """Return one provider key's non-secret metadata (tenant-scoped)."""
    tenant_id = _tenant(request)
    record = get_model_key_broker_store().get_provider_key(provider_key_id, tenant_id=tenant_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"Provider key {provider_key_id} not found")
    return record.to_public_dict()


@router.delete("/model-keys/providers/{provider_key_id}", status_code=204)
async def delete_provider_key(request: Request, provider_key_id: str, _role: Any = _SCAN_DEP) -> None:
    """Delete a provider key. Its virtual keys then fail resolution closed."""
    tenant_id = _tenant(request)
    deleted = get_model_key_broker_store().delete_provider_key(provider_key_id, tenant_id=tenant_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Provider key {provider_key_id} not found")
    log_action(
        "model_key.provider.delete",
        actor=_actor(request),
        resource=f"model-provider-key/{provider_key_id}",
        tenant_id=tenant_id,
    )


@router.post("/model-keys/providers/{provider_key_id}/virtual-keys", status_code=201)
async def mint_virtual_key_route(
    request: Request,
    provider_key_id: str,
    body: VirtualKeyMint,
    _role: Any = _SCAN_DEP,
) -> dict[str, Any]:
    """Mint a scoped, time-boxed virtual key. The raw token is returned once here."""
    tenant_id = _tenant(request)
    if not (MIN_VK_TTL_SECONDS <= body.ttl_seconds <= MAX_VK_TTL_SECONDS):
        raise HTTPException(
            status_code=400,
            detail=f"ttl_seconds must be between {MIN_VK_TTL_SECONDS} and {MAX_VK_TTL_SECONDS}.",
        )
    allowed_models = _validate_models(body.allowed_models)
    try:
        vk, raw_token = mint_virtual_key(
            get_model_key_broker_store(),
            tenant_id=tenant_id,
            provider_key_id=provider_key_id,
            holder_id=body.holder_id,
            holder_type=body.holder_type,
            allowed_models=allowed_models,
            ttl_seconds=body.ttl_seconds,
            owner=body.owner,
            owner_type=body.owner_type,
        )
    except ModelKeyBrokerError as exc:
        status = 404 if exc.reason == "provider_key_missing" else 409 if exc.reason == "provider_key_disabled" else 400
        raise HTTPException(status_code=status, detail=sanitize_error(exc, generic=False)) from exc

    log_action(
        "model_key.virtual.mint",
        actor=_actor(request),
        resource=f"model-virtual-key/{vk.virtual_key_id}",
        tenant_id=tenant_id,
        provider=vk.provider,
        holder_id=vk.holder_id,
    )
    # The raw token is surfaced exactly once, alongside the non-secret record.
    return {
        "schema_version": "model_keys.virtual_key.v1",
        "virtual_key": raw_token,
        "virtual_key_record": vk.to_public_dict(),
    }


@router.get("/model-keys/virtual-keys")
async def list_virtual_keys(
    request: Request,
    provider_key_id: str | None = None,
    include_inactive: bool = False,
    _role: Any = _READ_DEP,
) -> dict[str, Any]:
    """List the tenant's virtual keys (never carries the token/hash)."""
    tenant_id = _tenant(request)
    records = get_model_key_broker_store().list_virtual_keys(tenant_id, provider_key_id=provider_key_id, include_inactive=include_inactive)
    return {
        "schema_version": "model_keys.virtual_keys.v1",
        "tenant_id": tenant_id,
        "virtual_keys": [r.to_public_dict() for r in records],
        "count": len(records),
    }


@router.post("/model-keys/virtual-keys/{virtual_key_id}/revoke")
async def revoke_virtual_key_route(
    request: Request,
    virtual_key_id: str,
    body: VirtualKeyRevoke,
    _role: Any = _SCAN_DEP,
) -> dict[str, Any]:
    """Immediately revoke a virtual key; further resolution fails closed."""
    tenant_id = _tenant(request)
    vk = revoke_virtual_key(get_model_key_broker_store(), virtual_key_id, tenant_id=tenant_id, reason=body.reason)
    if vk is None:
        raise HTTPException(status_code=404, detail=f"Virtual key {virtual_key_id} not found")
    log_action(
        "model_key.virtual.revoke",
        actor=_actor(request),
        resource=f"model-virtual-key/{vk.virtual_key_id}",
        tenant_id=tenant_id,
        provider=vk.provider,
        outcome="revoked",
    )
    return {"schema_version": "model_keys.virtual_key.v1", "virtual_key_record": vk.to_public_dict()}


@router.post("/model-keys/authorize")
async def authorize_virtual_key(request: Request, body: VirtualKeyAuthorize, _role: Any = _SCAN_DEP) -> dict[str, Any]:
    """Authorize a virtual key for a provider/model call — decision only, no secret.

    Resolves the virtual key server-side (enforcing scope, revocation, expiry, and
    tenant), records usage, and returns an authorization decision. The real
    provider key is unsealed only in-process to prove it is resolvable and is
    **never** included in the response.
    """
    tenant_id = _tenant(request)
    try:
        resolved = resolve_virtual_key(
            get_model_key_broker_store(),
            tenant_id=tenant_id,
            raw_token=body.virtual_key,
            provider=body.provider,
            model=body.model,
            holder_id=body.holder_id or None,
        )
    except ModelKeyBrokerError as exc:
        status = _RESOLVE_STATUS.get(exc.reason, 403)
        log_action(
            "model_key.virtual.authorize",
            actor=_actor(request),
            resource="model-virtual-key/authorize",
            tenant_id=tenant_id,
            provider=(body.provider or "").strip().lower(),
            outcome="denied",
            reason=exc.reason,
        )
        raise HTTPException(status_code=status, detail=sanitize_error(exc, generic=False)) from exc

    log_action(
        "model_key.virtual.authorize",
        actor=_actor(request),
        resource=f"model-virtual-key/{resolved.virtual_key_id}",
        tenant_id=tenant_id,
        provider=resolved.provider,
        model=resolved.model,
        holder_id=resolved.holder_id,
        outcome="authorized",
    )
    # Decision only — the real key (resolved.api_key) is deliberately omitted.
    return {
        "schema_version": "model_keys.authorize.v1",
        "authorized": True,
        "virtual_key_id": resolved.virtual_key_id,
        "provider": resolved.provider,
        "model": resolved.model,
        "provider_key_id": resolved.provider_key_id,
        "holder_id": resolved.holder_id,
    }
