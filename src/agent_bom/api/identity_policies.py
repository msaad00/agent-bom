"""Conditional-access policy model, evaluation, and tenant-bound services."""

from __future__ import annotations

import ipaddress
import secrets
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol

from agent_bom.core.tenancy import require_explicit_tenant_id

_VALID_CONDITIONAL_EFFECTS = ("require", "deny")


@dataclass
class AccessContext:
    """The request-time context a conditional-access policy is evaluated against."""

    identity_id: str = ""
    agent_id: str = ""
    tool_name: str = ""
    environment: str = ""
    source_ip: str = ""
    # Device / group / client attributes (ABAC): the calling workstation or
    # service identity (``device_id``), the caller's directory groups
    # (``groups``), and the MCP client application making the call
    # (``client_id``). Empty means "not supplied" — a policy that constrains one
    # of these fails closed when the request cannot prove it.
    device_id: str = ""
    groups: list[str] = field(default_factory=list)
    client_id: str = ""
    # Device posture (ABAC), enriched from EDR/MDM signals
    # (:mod:`agent_bom.device_posture`). ``None`` means "not supplied / unknown"
    # — a ``require_device_*`` policy fails closed on an unknown device rather
    # than waving it through.
    device_managed: bool | None = None
    device_compliant: bool | None = None
    device_disk_encrypted: bool | None = None
    at: datetime | None = None


@dataclass
class ConditionalAccessPolicy:
    """A context-aware access rule evaluated at the gateway decision point.

    A policy *applies* to a request when its scope (identities / agents / tools)
    matches. An applying ``require`` policy permits the call only when every
    configured condition holds; an applying ``deny`` policy blocks the call when
    every configured condition holds. Deny wins over require. Empty scope or
    condition lists mean "any", so an active ``deny`` policy with no conditions
    is an unconditional block for its scope, and a ``require`` policy with one
    condition is a guardrail that denies whenever that condition is not met.
    """

    policy_id: str
    tenant_id: str
    name: str
    effect: str  # require | deny
    status: str  # active | disabled
    created_at: str
    priority: int = 100
    # Scope: which requests this policy governs (empty list = any; "*" = all).
    identity_ids: list[str] = field(default_factory=list)
    agent_ids: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    # Conditions: context attributes that must hold (empty list = unconstrained).
    allowed_environments: list[str] = field(default_factory=list)
    allowed_hours_utc: list[int] = field(default_factory=list)  # 0..23 UTC
    allowed_weekdays: list[int] = field(default_factory=list)  # 0=Mon .. 6=Sun
    allowed_source_cidrs: list[str] = field(default_factory=list)
    # Device / group / client conditions (ABAC). Empty list = unconstrained; a
    # populated list requires the request context to match (membership for
    # groups, exact for device/client) or the condition fails closed.
    allowed_devices: list[str] = field(default_factory=list)
    allowed_groups: list[str] = field(default_factory=list)
    allowed_clients: list[str] = field(default_factory=list)
    # Device-posture conditions (ABAC), evaluated against EDR/MDM-enriched
    # context. Each defaults off; when set, the request must prove the posture
    # attribute is True or the condition fails closed (unknown/False → not met).
    require_device_managed: bool = False
    require_device_compliant: bool = False
    require_device_disk_encrypted: bool = False
    updated_at: str = ""
    description: str = ""

    @staticmethod
    def _scope_match(allowed: list[str], value: str) -> bool:
        if not allowed:
            return True
        return "*" in allowed or value in allowed

    def applies_to(self, ctx: "AccessContext") -> bool:
        """True when this policy governs ``ctx`` (scope match only)."""
        return (
            self._scope_match(self.identity_ids, ctx.identity_id)
            and self._scope_match(self.agent_ids, ctx.agent_id)
            and self._scope_match(self.tools, ctx.tool_name)
        )

    def conditions_met(self, ctx: "AccessContext") -> bool:
        """True when every configured condition holds for ``ctx``.

        A condition over an attribute the request did not supply fails closed —
        an unprovable "in prod" or "from this CIDR" condition is treated as not
        met, so a ``require`` guardrail denies rather than waving the call through.
        """
        now = ctx.at or datetime.now(timezone.utc)
        if self.allowed_environments and ctx.environment.strip().lower() not in {e.strip().lower() for e in self.allowed_environments}:
            return False
        if self.allowed_hours_utc and now.hour not in set(self.allowed_hours_utc):
            return False
        if self.allowed_weekdays and now.weekday() not in set(self.allowed_weekdays):
            return False
        if self.allowed_source_cidrs and not _ip_in_any_cidr(ctx.source_ip, self.allowed_source_cidrs):
            return False
        # Device: exact match against an allow-list. A request that supplies no
        # device id cannot satisfy a device condition — fail closed.
        if self.allowed_devices and (not ctx.device_id or ctx.device_id not in set(self.allowed_devices)):
            return False
        # Group: membership. The caller must belong to at least one allowed
        # group; no groups supplied fails closed.
        if self.allowed_groups and not (set(ctx.groups) & set(self.allowed_groups)):
            return False
        # Client: exact match against the allowed MCP client applications.
        if self.allowed_clients and (not ctx.client_id or ctx.client_id not in set(self.allowed_clients)):
            return False
        # Device posture (EDR/MDM enriched). A required posture attribute must be
        # proven True; an unknown (None) or False posture fails closed.
        if self.require_device_managed and ctx.device_managed is not True:
            return False
        if self.require_device_compliant and ctx.device_compliant is not True:
            return False
        if self.require_device_disk_encrypted and ctx.device_disk_encrypted is not True:
            return False
        return True

    def to_public_dict(self) -> dict[str, Any]:
        return asdict(self)


def _ip_in_any_cidr(source_ip: str, cidrs: list[str]) -> bool:
    if not source_ip:
        return False
    try:
        addr = ipaddress.ip_address(source_ip.strip())
    except ValueError:
        return False
    for cidr in cidrs:
        try:
            if addr in ipaddress.ip_network(cidr.strip(), strict=False):
                return True
        except ValueError:
            continue
    return False


def evaluate_conditional_access(
    policies: list[ConditionalAccessPolicy],
    ctx: AccessContext,
) -> tuple[bool, str, str]:
    """Evaluate active conditional-access policies for ``ctx``.

    Returns ``(allowed, reason, policy_id)``. Deny precedence: any applying
    ``deny`` policy whose conditions hold blocks the call; otherwise any applying
    ``require`` policy whose conditions are not met blocks it. An empty policy
    list (or no applying policy) allows.
    """
    applicable = sorted(
        (p for p in policies if p.status == "active" and p.applies_to(ctx)),
        key=lambda p: (p.priority, p.policy_id),
    )
    for policy in applicable:
        if policy.effect == "deny" and policy.conditions_met(ctx):
            return False, f"blocked by conditional-access policy '{policy.name}'", policy.policy_id
    for policy in applicable:
        if policy.effect == "require" and not policy.conditions_met(ctx):
            return False, f"context fails conditional-access policy '{policy.name}'", policy.policy_id
    return True, "", ""


class ConditionalPolicyStore(Protocol):
    def put_conditional_policy(self, policy: ConditionalAccessPolicy, *, tenant_id: str) -> None: ...
    def get_conditional_policy(self, policy_id: str, *, tenant_id: str) -> ConditionalAccessPolicy | None: ...
    def list_conditional_policies(
        self, tenant_id: str, *, include_disabled: bool = False, limit: int = 200
    ) -> list[ConditionalAccessPolicy]: ...


def require_policy_tenant(policy: ConditionalAccessPolicy, tenant_id: str) -> str:
    tenant = require_explicit_tenant_id(tenant_id)
    if policy.tenant_id != tenant:
        raise ValueError("Conditional policy tenant does not match authorized tenant")
    return tenant


def create_conditional_policy(
    store: ConditionalPolicyStore,
    *,
    tenant_id: str,
    name: str,
    effect: str = "require",
    priority: int = 100,
    identity_ids: list[str] | None = None,
    agent_ids: list[str] | None = None,
    tools: list[str] | None = None,
    allowed_environments: list[str] | None = None,
    allowed_hours_utc: list[int] | None = None,
    allowed_weekdays: list[int] | None = None,
    allowed_source_cidrs: list[str] | None = None,
    allowed_devices: list[str] | None = None,
    allowed_groups: list[str] | None = None,
    allowed_clients: list[str] | None = None,
    require_device_managed: bool = False,
    require_device_compliant: bool = False,
    require_device_disk_encrypted: bool = False,
    description: str = "",
) -> ConditionalAccessPolicy:
    """Create an active conditional-access policy for ``tenant_id``."""
    tenant_id = require_explicit_tenant_id(tenant_id)
    if effect not in _VALID_CONDITIONAL_EFFECTS:
        raise ValueError(f"effect must be one of {_VALID_CONDITIONAL_EFFECTS}")
    now = datetime.now(timezone.utc).isoformat()
    policy = ConditionalAccessPolicy(
        policy_id=f"cap_{secrets.token_hex(8)}",
        tenant_id=tenant_id,
        name=name[:200],
        effect=effect,
        status="active",
        created_at=now,
        priority=int(priority),
        identity_ids=list(identity_ids or []),
        agent_ids=list(agent_ids or []),
        tools=list(tools or []),
        allowed_environments=list(allowed_environments or []),
        allowed_hours_utc=sorted({h for h in (allowed_hours_utc or []) if 0 <= int(h) <= 23}),
        allowed_weekdays=sorted({d for d in (allowed_weekdays or []) if 0 <= int(d) <= 6}),
        allowed_source_cidrs=list(allowed_source_cidrs or []),
        allowed_devices=list(allowed_devices or []),
        allowed_groups=list(allowed_groups or []),
        allowed_clients=list(allowed_clients or []),
        require_device_managed=bool(require_device_managed),
        require_device_compliant=bool(require_device_compliant),
        require_device_disk_encrypted=bool(require_device_disk_encrypted),
        updated_at=now,
        description=description[:1000],
    )
    store.put_conditional_policy(policy, tenant_id=tenant_id)
    return policy


def set_conditional_policy_status(
    store: ConditionalPolicyStore, policy_id: str, *, tenant_id: str, status: str
) -> ConditionalAccessPolicy | None:
    """Enable (``active``) or disable (``disabled``) a conditional-access policy."""
    tenant_id = require_explicit_tenant_id(tenant_id)
    if status not in ("active", "disabled"):
        raise ValueError("status must be 'active' or 'disabled'")
    policy = store.get_conditional_policy(policy_id, tenant_id=tenant_id)
    if policy is None:
        return None
    require_policy_tenant(policy, tenant_id)
    if policy.policy_id != policy_id:
        raise ValueError("Conditional policy record identity does not match")
    policy.status = status
    policy.updated_at = datetime.now(timezone.utc).isoformat()
    store.put_conditional_policy(policy, tenant_id=tenant_id)
    return policy


def evaluate_conditional_access_for_request(
    store: ConditionalPolicyStore,
    *,
    tenant_id: str,
    ctx: AccessContext,
) -> tuple[bool, str, str]:
    """Load active policies for ``tenant_id`` and evaluate them against ``ctx``."""
    tenant_id = require_explicit_tenant_id(tenant_id)
    policies = store.list_conditional_policies(tenant_id, include_disabled=False, limit=500)
    for policy in policies:
        require_policy_tenant(policy, tenant_id)
    return evaluate_conditional_access(policies, ctx)
