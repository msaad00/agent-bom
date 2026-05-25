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
