"""Tenant helpers for authenticated API request handlers."""

from __future__ import annotations

from fastapi import HTTPException, Request

from agent_bom.platform_invariants import normalize_tenant_id


def require_request_tenant_id(request: Request) -> str:
    """Return the middleware-established tenant id for an API request.

    Route handlers should not silently invent the default tenant. The API
    middleware owns that fallback so a missing request tenant fails closed
    instead of crossing into the single-tenant bucket by accident.
    """
    if not hasattr(request.state, "tenant_id"):
        raise HTTPException(status_code=500, detail="Authenticated tenant context is unavailable")
    return normalize_tenant_id(str(request.state.tenant_id))


# Legacy SDK bodies carry the schema default rather than a real tenant. Treat it
# as "unset" so an untouched client field is not read as a cross-tenant request.
_UNSET_BODY_TENANTS = frozenset({"", "default"})


def require_body_tenant_match(body_tenant_id: object, request_tenant_id: str) -> None:
    """Fail closed when a write body names a tenant the caller is not authenticated for.

    Eight write routes accept a ``tenant_id`` in the request body for legacy SDK
    compatibility. None of them ever routed the write to it — the authenticated
    tenant has always been authoritative — but they disagreed on the answer:
    three returned 403, three ignored it and appended a response warning, two
    ignored it silently. A caller asking to write into another tenant gets one
    answer everywhere, and it is the fail-closed one.

    Passing the caller's own tenant (or leaving the field at its schema default)
    stays valid, so conforming clients are unaffected.
    """
    if body_tenant_id is None:
        return
    candidate = str(body_tenant_id).strip()
    if candidate in _UNSET_BODY_TENANTS:
        return
    if normalize_tenant_id(candidate) == request_tenant_id:
        return
    raise HTTPException(
        status_code=403,
        detail="Forbidden — tenant_id in the request body must match the authenticated tenant",
    )
