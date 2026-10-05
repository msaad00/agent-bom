"""Operator authorization and attributable invitation provisioning receipts."""

from fastapi import HTTPException, Request

from agent_bom.api import audit_log
from agent_bom.api.auth import ApiKey, Role, get_key_store, scopes_allow
from agent_bom.api.tenancy import require_request_tenant_id


def require_invitation_delegation(request: Request) -> None:
    """An invitation grants a wildcard key, so only an unrestricted admin can delegate it."""
    if getattr(request.state, "api_key_role", None) != Role.ADMIN.value:
        raise HTTPException(status_code=403, detail="Invitation provisioning requires an authenticated admin")
    scopes = list(getattr(request.state, "api_key_scopes", []) or [])
    if not scopes_allow(scopes, "*"):
        raise HTTPException(status_code=403, detail="Cannot delegate API key scopes outside the caller scope ceiling")


def provision_invited_key(request: Request, key: ApiKey, *, team_name: str) -> None:
    """Require durable authorization receipts before provisioning a fresh tenant.

    Authorization receipts describe an attempted write, not proof that a key was
    created. Independent audit and key stores are not a distributed transaction:
    failed provisioning retains the attempt history and returns no credential.
    """
    actor_tenant = require_request_tenant_id(request)
    actor = getattr(request.state, "api_key_name", "") or "operator"
    details = {
        "actor_tenant_id": actor_tenant,
        "actor_key_id": getattr(request.state, "api_key_id", None),
        "destination_tenant_id": key.tenant_id,
        "key_id": key.key_id,
        "role": key.role.value,
        "expires_at": key.expires_at,
    }
    try:
        for tenant in (actor_tenant, key.tenant_id):
            audit_log.log_action("auth.invitation_authorized", actor=actor, resource=f"tenant/{key.tenant_id}", tenant_id=tenant, **details)
    except Exception:  # broad-except: Pluggable audit backends must fail closed before any tenant provisioning.
        raise HTTPException(status_code=503, detail="Invitation audit evidence unavailable; no tenant was provisioned") from None
    try:
        get_key_store().provision_tenant_key(key, team_name=team_name)
    except Exception:  # broad-except: Key-store backends expose different errors; never return a credential after a failed write.
        raise HTTPException(status_code=503, detail="Invitation provisioning unavailable") from None
