"""A full-tenant cursor walk must not be 429'd by the default read budget.

The default read budget was 5x the scan budget (3000 rpm) for every caller.
A connector or SIEM doing a full sync of a large tenant through the public API
walks the cursor thousands of times per minute and got cut off partway. The
authenticated budget is now higher; the anonymous/flood caps are unchanged, so
raising it does not widen the pre-auth abuse surface.
"""

from __future__ import annotations

from starlette.applications import Starlette
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse as StarletteJSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from agent_bom.api.middleware import (
    DEFAULT_AUTHENTICATED_READ_RATE_LIMIT_RPM,
    DEFAULT_GLOBAL_IP_RATE_LIMIT_RPM,
    DEFAULT_READ_RATE_LIMIT_RPM,
    DEFAULT_SCAN_RATE_LIMIT_RPM,
    RateLimitMiddleware,
)

# 500k rows at limit=500 is 1000 requests; a connector re-walking a couple of
# large tenants in the same minute is the case that was getting cut off.
FULL_SYNC_REQUESTS_PER_MINUTE = 5000


def test_authenticated_read_budget_covers_a_full_tenant_cursor_walk() -> None:
    assert DEFAULT_AUTHENTICATED_READ_RATE_LIMIT_RPM >= FULL_SYNC_REQUESTS_PER_MINUTE


def test_anonymous_read_budget_is_unchanged() -> None:
    """The pre-auth flood caps must not move when the authenticated one does."""
    assert DEFAULT_READ_RATE_LIMIT_RPM == DEFAULT_SCAN_RATE_LIMIT_RPM * 5
    assert DEFAULT_GLOBAL_IP_RATE_LIMIT_RPM == DEFAULT_READ_RATE_LIMIT_RPM * 4


def test_write_budget_is_unchanged() -> None:
    """Raising the read budget must not loosen the ingest/scan door."""
    assert DEFAULT_SCAN_RATE_LIMIT_RPM == 600


def test_authenticated_read_budget_stays_under_the_global_ip_ceiling() -> None:
    """The coarse per-IP backstop must still bound a single source address."""
    assert DEFAULT_AUTHENTICATED_READ_RATE_LIMIT_RPM < DEFAULT_GLOBAL_IP_RATE_LIMIT_RPM


class _BindIdentity(BaseHTTPMiddleware):
    """Stand in for APIKeyMiddleware: mark the request as tenant-authenticated."""

    async def dispatch(self, request, call_next):
        request.state.tenant_id = "acme-corp"
        request.state.auth_method = "api_key"
        return await call_next(request)


def _app(*, authenticated: bool, scan_rpm: int = 10, read_rpm: int = 20, authenticated_read_rpm: int = 50):
    async def dummy(request):
        return StarletteJSONResponse({"ok": True})

    app = Starlette(routes=[Route("/v1/findings", dummy), Route("/v1/scan", dummy, methods=["POST"])])
    # add_middleware inserts outermost-last, so register the limiter first and
    # the identity binder second: the binder must run before the limiter reads
    # request.state.
    app.add_middleware(
        RateLimitMiddleware,
        scan_rpm=scan_rpm,
        read_rpm=read_rpm,
        authenticated_read_rpm=authenticated_read_rpm,
    )
    if authenticated:
        app.add_middleware(_BindIdentity)
    return app


def test_authenticated_reads_get_the_higher_budget() -> None:
    client = TestClient(_app(authenticated=True))
    response = client.get("/v1/findings")
    assert response.status_code == 200
    assert response.headers["x-ratelimit-limit"] == "50"


def test_anonymous_reads_keep_the_lower_budget() -> None:
    client = TestClient(_app(authenticated=False))
    response = client.get("/v1/findings")
    assert response.status_code == 200
    assert response.headers["x-ratelimit-limit"] == "20"


def test_authenticated_writes_still_use_the_scan_budget() -> None:
    """The higher read budget must not leak into the ingest/scan door."""
    client = TestClient(_app(authenticated=True))
    response = client.post("/v1/scan")
    assert response.status_code == 200
    assert response.headers["x-ratelimit-limit"] == "10"


def test_anonymous_flood_is_still_cut_off_at_the_lower_budget() -> None:
    client = TestClient(_app(authenticated=False, read_rpm=3))
    statuses = [client.get("/v1/findings").status_code for _ in range(6)]
    assert 429 in statuses
    assert statuses.index(429) == 3
