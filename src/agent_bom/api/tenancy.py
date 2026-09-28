"""Tenant helpers for authenticated API request handlers."""

from __future__ import annotations

import os
from collections.abc import Awaitable, Callable

from fastapi import HTTPException, Request
from starlette.middleware.base import RequestResponseEndpoint
from starlette.responses import JSONResponse, Response

from agent_bom.core.tenancy import require_explicit_tenant_id
from agent_bom.platform_invariants import normalize_tenant_id


def require_request_tenant_id(request: Request) -> str:
    """Return the middleware-established tenant id for an API request.

    Route handlers should not silently invent the default tenant. The API
    middleware owns that fallback so a missing request tenant fails closed
    instead of crossing into the single-tenant bucket by accident.
    """
    try:
        return require_explicit_tenant_id(getattr(request.state, "tenant_id", None))
    except ValueError as exc:
        raise HTTPException(status_code=500, detail="Authenticated tenant context is unavailable") from exc


async def call_with_request_tenant(
    request: Request, call_next: RequestResponseEndpoint, *, authenticate: Callable[..., Awaitable[Response]] | None = None
) -> Response:
    """Reject incomplete identity before dispatch and restore database context."""
    try:
        tenant_id = require_request_tenant_id(request)
    except HTTPException:
        return JSONResponse(status_code=500, content={"detail": "Authenticated tenant context is unavailable"})
    request.state.tenant_id = tenant_id
    if authenticate is not None:
        from agent_bom.api.stream_authorization import bind_http_stream_authorization

        bind_http_stream_authorization(request, authenticate)
    if not os.environ.get("AGENT_BOM_POSTGRES_URL"):
        return await call_next(request)

    from agent_bom.api.postgres_store import reset_current_tenant, set_current_tenant

    token = set_current_tenant(tenant_id)
    try:
        return await call_next(request)
    finally:
        reset_current_tenant(token)


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
