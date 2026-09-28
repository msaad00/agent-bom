"""Tenant-bound just-in-time grants and lifecycle service contract."""

from __future__ import annotations

import secrets
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

from agent_bom.core.tenancy import require_explicit_tenant_id


def identity_expiry(ttl_seconds: int, *, at: datetime | None = None) -> str:
    base = at or datetime.now(timezone.utc)
    return (base + timedelta(seconds=max(60, int(ttl_seconds)))).isoformat()


@dataclass
class AgentJITGrant:
    """A time-bound access grant for one identity and one tool."""

    grant_id: str
    identity_id: str
    agent_id: str
    tenant_id: str
    tool_name: str
    status: str  # requested | active | denied | revoked
    requested_at: str
    requested_by: str = ""
    approved_at: str = ""
    approved_by: str = ""
    starts_at: str = ""
    expires_at: str = ""
    reason: str = ""
    ticket_id: str = ""
    revoked_at: str = ""
    revoked_reason: str = ""
    denied_at: str = ""
    denied_reason: str = ""

    def is_live(self, *, at: datetime | None = None) -> bool:
        if self.status != "active":
            return False
        now = at or datetime.now(timezone.utc)
        try:
            if self.starts_at and now < datetime.fromisoformat(self.starts_at):
                return False
            if not self.expires_at or now > datetime.fromisoformat(self.expires_at):
                return False
        except ValueError:
            return False
        return True

    def to_public_dict(self) -> dict[str, Any]:
        return asdict(self)


class JITGrantStore(Protocol):
    """Every exact-ID read and write carries explicit tenant authority."""

    def put_jit_grant(self, grant: AgentJITGrant, *, tenant_id: str) -> None: ...
    def get_jit_grant(self, grant_id: str, *, tenant_id: str) -> AgentJITGrant | None: ...


def require_grant_tenant(grant: AgentJITGrant, tenant_id: str) -> str:
    tenant = require_explicit_tenant_id(tenant_id)
    if grant.tenant_id != tenant:
        raise ValueError("JIT grant tenant does not match authorized tenant")
    return tenant


def _grant_for_tenant(store: JITGrantStore, grant_id: str, tenant_id: str) -> AgentJITGrant | None:
    tenant = require_explicit_tenant_id(tenant_id)
    grant = store.get_jit_grant(grant_id, tenant_id=tenant)
    if grant is not None:
        require_grant_tenant(grant, tenant)
        if grant.grant_id != grant_id:
            raise ValueError("JIT grant record identity does not match")
    return grant


def request_jit_grant(
    store: JITGrantStore,
    *,
    identity_id: str,
    agent_id: str,
    tenant_id: str,
    tool_name: str,
    requested_by: str = "",
    reason: str = "",
    ticket_id: str = "",
) -> AgentJITGrant:
    """Create a pending JIT request. It does not authorize a tool call."""
    tenant_id = require_explicit_tenant_id(tenant_id)
    now = datetime.now(timezone.utc)
    grant = AgentJITGrant(
        grant_id=f"jit_{secrets.token_hex(8)}",
        identity_id=identity_id,
        agent_id=agent_id,
        tenant_id=tenant_id,
        tool_name=tool_name,
        status="requested",
        requested_at=now.isoformat(),
        requested_by=requested_by[:120],
        reason=reason[:1000],
        ticket_id=ticket_id[:120],
    )
    store.put_jit_grant(grant, tenant_id=tenant_id)
    return grant


def approve_jit_grant(
    store: JITGrantStore,
    grant_id: str,
    *,
    tenant_id: str,
    ttl_seconds: int,
    approved_by: str = "",
    starts_at: datetime | None = None,
) -> AgentJITGrant | None:
    """Activate a pending JIT request for a bounded TTL."""
    grant = _grant_for_tenant(store, grant_id, tenant_id)
    if grant is None or grant.status in {"revoked", "denied"}:
        return None
    now = datetime.now(timezone.utc)
    start = starts_at or now
    grant.status = "active"
    grant.approved_at = now.isoformat()
    grant.approved_by = approved_by[:120]
    grant.starts_at = start.isoformat()
    grant.expires_at = identity_expiry(ttl_seconds, at=start)
    store.put_jit_grant(grant, tenant_id=tenant_id)
    return grant


def issue_jit_grant(
    store: JITGrantStore,
    *,
    identity_id: str,
    agent_id: str,
    tenant_id: str,
    tool_name: str,
    ttl_seconds: int,
    approved_by: str = "",
    reason: str = "",
    ticket_id: str = "",
) -> AgentJITGrant:
    """Create and immediately approve a time-bound JIT grant."""
    grant = request_jit_grant(
        store,
        identity_id=identity_id,
        agent_id=agent_id,
        tenant_id=tenant_id,
        tool_name=tool_name,
        requested_by=approved_by,
        reason=reason,
        ticket_id=ticket_id,
    )
    approved = approve_jit_grant(store, grant.grant_id, tenant_id=tenant_id, ttl_seconds=ttl_seconds, approved_by=approved_by)
    assert approved is not None
    return approved


def deny_jit_grant(store: JITGrantStore, grant_id: str, *, tenant_id: str, reason: str = "") -> AgentJITGrant | None:
    grant = _grant_for_tenant(store, grant_id, tenant_id)
    if grant is None or grant.status in {"revoked", "denied"}:
        return None
    grant.status = "denied"
    grant.denied_at = datetime.now(timezone.utc).isoformat()
    grant.denied_reason = reason[:500]
    store.put_jit_grant(grant, tenant_id=tenant_id)
    return grant


def revoke_jit_grant(store: JITGrantStore, grant_id: str, *, tenant_id: str, reason: str = "") -> AgentJITGrant | None:
    grant = _grant_for_tenant(store, grant_id, tenant_id)
    if grant is None or grant.status in {"revoked", "denied"}:
        return None
    grant.status = "revoked"
    grant.revoked_at = datetime.now(timezone.utc).isoformat()
    grant.revoked_reason = reason[:500]
    store.put_jit_grant(grant, tenant_id=tenant_id)
    return grant
