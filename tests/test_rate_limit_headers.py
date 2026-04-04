"""Tests for X-RateLimit-* headers and X-API-Version response header (Issue #530)."""

from starlette.applications import Starlette
from starlette.responses import JSONResponse as StarletteJSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from agent_bom.api.middleware import RateLimitMiddleware, TrustHeadersMiddleware


def _make_app(scan_rpm: int = 10, read_rpm: int = 20):
    async def dummy(request):
        return StarletteJSONResponse({"ok": True})

    app = Starlette(routes=[Route("/v1/data", dummy), Route("/health", dummy)])
    app.add_middleware(RateLimitMiddleware, scan_rpm=scan_rpm, read_rpm=read_rpm)
    return app


def test_rate_limit_headers_present_on_success():
    """Successful responses should include X-RateLimit-Limit header."""
    client = TestClient(_make_app(read_rpm=20))
    resp = client.get("/v1/data")
    assert resp.status_code == 200
    assert "x-ratelimit-limit" in resp.headers
    assert resp.headers["x-ratelimit-limit"] == "20"


def test_rate_limit_remaining_decreases():
    """X-RateLimit-Remaining should decrease with each request."""
    client = TestClient(_make_app(read_rpm=20))

    resp1 = client.get("/v1/data")
    assert resp1.status_code == 200
    remaining1 = int(resp1.headers["x-ratelimit-remaining"])

    resp2 = client.get("/v1/data")
    assert resp2.status_code == 200
    remaining2 = int(resp2.headers["x-ratelimit-remaining"])

    assert remaining2 < remaining1


def test_rate_limit_reset_header_present():
    """Successful responses should include X-RateLimit-Reset header with a timestamp."""
    import time

    client = TestClient(_make_app(read_rpm=20))
    resp = client.get("/v1/data")
    assert resp.status_code == 200
    assert "x-ratelimit-reset" in resp.headers
    reset_val = int(resp.headers["x-ratelimit-reset"])
    # Reset should be within a 60-second window from now
    now = int(time.time())
    assert now <= reset_val <= now + 70


def test_rate_limit_remaining_hits_zero_at_limit():
    """Remaining count should reach zero on the last allowed request."""
    client = TestClient(_make_app(read_rpm=2))
    resp1 = client.get("/v1/data")
    assert resp1.status_code == 200
    assert resp1.headers["x-ratelimit-remaining"] == "1"

    resp2 = client.get("/v1/data")
    assert resp2.status_code == 200
    assert resp2.headers["x-ratelimit-remaining"] == "0"


def test_x_api_version_header():
    """TrustHeadersMiddleware should add X-API-Version: v1 to every response."""

    async def dummy(request):
        return StarletteJSONResponse({"ok": True})

    app = Starlette(routes=[Route("/health", dummy)])
    app.add_middleware(TrustHeadersMiddleware)

    client = TestClient(app)
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.headers.get("x-api-version") == "v1"
