"""Tests for rate-limit, version, and request tracing headers."""

from starlette.applications import Starlette
from starlette.responses import JSONResponse as StarletteJSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from agent_bom.api.middleware import RateLimitMiddleware, TrustHeadersMiddleware
from agent_bom.api.tracing import parse_traceparent


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


def test_tracing_headers_present():
    """TrustHeadersMiddleware should add request tracing headers."""

    async def dummy(request):
        return StarletteJSONResponse({"trace_id": request.state.trace_id})

    app = Starlette(routes=[Route("/health", dummy)])
    app.add_middleware(TrustHeadersMiddleware)

    client = TestClient(app)
    resp = client.get("/health")
    assert resp.status_code == 200
    assert "x-trace-id" in resp.headers
    assert "x-span-id" in resp.headers
    assert "traceparent" in resp.headers
    parsed = parse_traceparent(resp.headers["traceparent"])
    assert parsed is not None
    assert resp.headers["x-trace-id"] == parsed["trace_id"]
    assert resp.headers["x-span-id"] == parsed["parent_span_id"]
    assert resp.json()["trace_id"] == parsed["trace_id"]


def test_tracing_preserves_incoming_trace_id():
    """Valid incoming traceparent should preserve the trace ID and expose parent span."""

    async def dummy(request):
        return StarletteJSONResponse(
            {
                "trace_id": request.state.trace_id,
                "parent_span_id": request.state.parent_span_id,
            }
        )

    app = Starlette(routes=[Route("/health", dummy)])
    app.add_middleware(TrustHeadersMiddleware)

    incoming = "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"
    client = TestClient(app)
    resp = client.get("/health", headers={"traceparent": incoming})
    assert resp.status_code == 200
    parsed = parse_traceparent(resp.headers["traceparent"])
    assert parsed is not None
    assert parsed["trace_id"] == "0123456789abcdef0123456789abcdef"
    assert parsed["parent_span_id"] != "0123456789abcdef"
    assert resp.json()["parent_span_id"] == "0123456789abcdef"
    assert resp.headers["x-parent-span-id"] == "0123456789abcdef"


def test_tracing_preserves_tracestate():
    """Incoming tracestate should be preserved for downstream collectors/proxies."""

    async def dummy(request):
        return StarletteJSONResponse({"trace_id": request.state.trace_id, "tracestate": request.state.tracestate})

    app = Starlette(routes=[Route("/health", dummy)])
    app.add_middleware(TrustHeadersMiddleware)

    client = TestClient(app)
    resp = client.get(
        "/health",
        headers={
            "traceparent": "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01",
            "tracestate": "vendor-a=foo,vendor-b=bar",
        },
    )
    assert resp.status_code == 200
    assert resp.headers["tracestate"] == "vendor-a=foo,vendor-b=bar"
    assert resp.json()["tracestate"] == "vendor-a=foo,vendor-b=bar"


def test_tracing_preserves_baggage():
    """Incoming bounded W3C baggage should be preserved for downstream systems."""

    async def dummy(request):
        return StarletteJSONResponse({"trace_id": request.state.trace_id, "baggage": request.state.baggage})

    app = Starlette(routes=[Route("/health", dummy)])
    app.add_middleware(TrustHeadersMiddleware)

    client = TestClient(app)
    resp = client.get(
        "/health",
        headers={
            "traceparent": "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01",
            "baggage": "tenant=acme,release=v0.76.0",
        },
    )
    assert resp.status_code == 200
    assert resp.headers["baggage"] == "tenant=acme,release=v0.76.0"
    assert resp.json()["baggage"] == "tenant=acme,release=v0.76.0"


def test_tracing_invalid_traceparent_falls_back_to_new_trace():
    """Invalid traceparent headers should not break requests."""

    async def dummy(request):
        return StarletteJSONResponse({"trace_id": request.state.trace_id})

    app = Starlette(routes=[Route("/health", dummy)])
    app.add_middleware(TrustHeadersMiddleware)

    client = TestClient(app)
    resp = client.get("/health", headers={"traceparent": "broken"})
    assert resp.status_code == 200
    parsed = parse_traceparent(resp.headers["traceparent"])
    assert parsed is not None
    assert resp.json()["trace_id"] == parsed["trace_id"]


def test_rate_limit_headers_present_on_429():
    """Throttled responses should still include the rate-limit contract."""
    client = TestClient(_make_app(read_rpm=1))
    ok = client.get("/v1/data")
    assert ok.status_code == 200

    limited = client.get("/v1/data")
    assert limited.status_code == 429
    assert limited.headers["x-ratelimit-limit"] == "1"
    assert limited.headers["x-ratelimit-remaining"] == "0"
    assert "x-ratelimit-reset" in limited.headers
    assert "retry-after" in limited.headers
