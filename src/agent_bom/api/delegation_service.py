"""Tenant-bound delegation authority checked against the live source identity.

Cryptographic verification alone cannot establish current lifecycle authority.
This service fails closed when the source is absent, inactive, narrowed, or
unavailable. Low-level tokens without a source identity require reissuance.
"""

from __future__ import annotations

from datetime import datetime, timezone

from agent_bom.api.agent_identity_store import AgentIdentity, AgentIdentityStore
from agent_bom.api.delegation_token import (
    DelegationToken,
    DelegationTokenError,
    issue_delegation_token,
    propagate_delegation_token,
    verify_delegation_token,
)
from agent_bom.core.tenancy import require_explicit_tenant_id


class DelegationSourceMissingError(DelegationTokenError):
    """The source identity is absent from the authorized tenant."""


class DelegationStoreUnavailableError(DelegationTokenError):
    """Current authority cannot be established because storage is unavailable."""


def _source(store: AgentIdentityStore, identity_id: str, tenant_id: str) -> AgentIdentity:
    tenant_id = require_explicit_tenant_id(tenant_id)
    if not identity_id:
        raise DelegationSourceMissingError("delegation source identity is required")
    try:
        identity = store.get(identity_id, tenant_id=tenant_id)
    except Exception as exc:  # noqa: BLE001 — storage adapter boundary, no raw error exposed
        raise DelegationStoreUnavailableError("delegation authority is unavailable") from exc
    if identity is None or identity.tenant_id != tenant_id or identity.identity_id != identity_id:
        raise DelegationSourceMissingError("delegation source identity not found")
    return identity


def _authority_expiry(identity: AgentIdentity, scopes: list[str], now: datetime) -> int:
    try:
        expiry = datetime.fromisoformat(identity.expires_at)
        live = identity.is_live(at=now) and expiry.tzinfo is not None and expiry > now
    except (TypeError, ValueError):
        live = False
    if not live:
        raise DelegationTokenError("delegation source identity is not active")
    if any(not identity.tool_allowed(scope) for scope in scopes):
        raise DelegationTokenError("delegation exceeds source identity tool authority")
    return int(expiry.timestamp())


def issue_identity_delegation(
    store: AgentIdentityStore,
    *,
    tenant_id: str,
    identity_id: str,
    delegatee: str,
    scopes: list[str],
    ttl_seconds: int,
    chain: list[str] | None = None,
) -> tuple[str, DelegationToken]:
    """Issue only within the current source's lifecycle and tool ceiling."""
    identity = _source(store, identity_id, tenant_id)
    now = datetime.now(timezone.utc)
    expiry = _authority_expiry(identity, scopes, now)
    ttl = min(ttl_seconds, expiry - int(now.timestamp()))
    if ttl <= 0:
        raise DelegationTokenError("delegation source identity is expired")
    return issue_delegation_token(
        tenant_id=identity.tenant_id,
        source_identity_id=identity.identity_id,
        delegator=identity.agent_id or identity.identity_id,
        delegatee=delegatee,
        scopes=scopes,
        ttl_seconds=ttl,
        chain=chain,
        at=now,
    )


def verify_identity_delegation(
    store: AgentIdentityStore,
    token: str,
    *,
    tenant_id: str,
    required_scope: str | None = None,
) -> DelegationToken:
    """Recheck the exact source ID, including for every propagated descendant."""
    tenant_id = require_explicit_tenant_id(tenant_id)
    now = datetime.now(timezone.utc)
    claims = verify_delegation_token(token, tenant_id=tenant_id, required_scope=required_scope, at=now)
    identity = _source(store, claims.source_identity_id, tenant_id)
    _authority_expiry(identity, claims.scopes, now)
    return claims


def propagate_identity_delegation(
    store: AgentIdentityStore,
    token: str,
    *,
    tenant_id: str,
    next_delegatee: str,
    scopes: list[str] | None = None,
) -> tuple[str, DelegationToken]:
    """Preserve the root identity and narrow a currently authorized parent."""
    verify_identity_delegation(store, token, tenant_id=tenant_id)
    return propagate_delegation_token(token, next_delegatee=next_delegatee, scopes=scopes, tenant_id=tenant_id)
