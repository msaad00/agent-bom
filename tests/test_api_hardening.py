"""Tests for API server hardening — auth, rate limiting, CORS, body size."""

from starlette.testclient import TestClient

from agent_bom.api.server import (
    APIKeyMiddleware,
    MaxBodySizeMiddleware,
    RateLimitMiddleware,
    app,
)


def test_health_no_auth():
    """Health endpoint should be accessible without authentication."""
    client = TestClient(app)
    resp = client.get("/health")
    assert resp.status_code == 200


def test_trust_headers_present():
    """Every response should include read-only trust headers."""
    client = TestClient(app)
    resp = client.get("/health")
    assert resp.headers.get("x-agent-bom-read-only") == "true"
    assert resp.headers.get("x-agent-bom-no-credential-storage") == "true"


def test_api_key_middleware_blocks_without_key():
    """Requests without API key should get 401 when middleware is active."""
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse as StarletteJSONResponse
    from starlette.routing import Route

    async def dummy(request):
        return StarletteJSONResponse({"ok": True})

    test_app = Starlette(routes=[Route("/v1/test", dummy), Route("/health", dummy)])
    test_app.add_middleware(APIKeyMiddleware, api_key="test-key-123")

    client = TestClient(test_app)
    resp = client.get("/v1/test")
    assert resp.status_code == 401


def test_api_key_middleware_bearer():
    """Bearer token should authenticate successfully."""
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse as StarletteJSONResponse
    from starlette.routing import Route

    async def dummy(request):
        return StarletteJSONResponse({"ok": True})

    test_app = Starlette(routes=[Route("/v1/test", dummy)])
    test_app.add_middleware(APIKeyMiddleware, api_key="test-key-123")

    client = TestClient(test_app)
    resp = client.get("/v1/test", headers={"Authorization": "Bearer test-key-123"})
    assert resp.status_code == 200


def test_api_key_middleware_x_api_key():
    """X-API-Key header should authenticate successfully."""
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse as StarletteJSONResponse
    from starlette.routing import Route

    async def dummy(request):
        return StarletteJSONResponse({"ok": True})

    test_app = Starlette(routes=[Route("/v1/test", dummy)])
    test_app.add_middleware(APIKeyMiddleware, api_key="test-key-123")

    client = TestClient(test_app)
    resp = client.get("/v1/test", headers={"X-API-Key": "test-key-123"})
    assert resp.status_code == 200


def test_api_key_middleware_wrong_key():
    """Wrong API key should get 401."""
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse as StarletteJSONResponse
    from starlette.routing import Route

    async def dummy(request):
        return StarletteJSONResponse({"ok": True})

    test_app = Starlette(routes=[Route("/v1/test", dummy)])
    test_app.add_middleware(APIKeyMiddleware, api_key="correct-key")

    client = TestClient(test_app)
    resp = client.get("/v1/test", headers={"Authorization": "Bearer wrong-key"})
    assert resp.status_code == 401


def test_api_key_middleware_health_exempt():
    """Health endpoint should be exempt from auth."""
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse as StarletteJSONResponse
    from starlette.routing import Route

    async def dummy(request):
        return StarletteJSONResponse({"ok": True})

    test_app = Starlette(routes=[Route("/health", dummy)])
    test_app.add_middleware(APIKeyMiddleware, api_key="test-key-123")

    client = TestClient(test_app)
    resp = client.get("/health")
    assert resp.status_code == 200


def test_rate_limit_middleware():
    """Should return 429 when rate limit exceeded."""
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse as StarletteJSONResponse
    from starlette.routing import Route

    async def dummy(request):
        return StarletteJSONResponse({"ok": True})

    test_app = Starlette(routes=[Route("/v1/scan", dummy, methods=["POST"])])
    test_app.add_middleware(RateLimitMiddleware, scan_rpm=3, read_rpm=10)

    client = TestClient(test_app)
    # First 3 should succeed
    for _ in range(3):
        resp = client.post("/v1/scan")
        assert resp.status_code == 200

    # 4th should be rate limited
    resp = client.post("/v1/scan")
    assert resp.status_code == 429
    assert "Retry-After" in resp.headers


def test_max_body_size_middleware():
    """Should reject requests with Content-Length > max."""
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse as StarletteJSONResponse
    from starlette.routing import Route

    async def dummy(request):
        return StarletteJSONResponse({"ok": True})

    test_app = Starlette(routes=[Route("/v1/scan", dummy, methods=["POST"])])
    test_app.add_middleware(MaxBodySizeMiddleware, max_bytes=100)

    client = TestClient(test_app)
    resp = client.post("/v1/scan", headers={"Content-Length": "200"}, content=b"x" * 200)
    assert resp.status_code == 413


def test_max_concurrent_jobs():
    """Should return 429 when max concurrent jobs exceeded."""
    from agent_bom.api.server import _MAX_CONCURRENT_JOBS, JobStatus, ScanJob, ScanRequest, _jobs

    # Create fake jobs up to the limit
    original_jobs = dict(_jobs)
    try:
        _jobs.clear()
        dummy_request = ScanRequest()
        for i in range(_MAX_CONCURRENT_JOBS):
            _jobs[f"fake-{i}"] = ScanJob(
                job_id=f"fake-{i}",
                status=JobStatus.RUNNING,
                created_at="2026-01-01T00:00:00Z",
                request=dummy_request,
                progress=[],
            )

        client = TestClient(app)
        resp = client.post("/v1/scan", json={"images": [], "k8s": False, "tf_dirs": [], "agent_projects": [], "enrich": False})
        assert resp.status_code == 429
        assert "concurrent" in resp.json()["detail"].lower()
    finally:
        _jobs.clear()
        _jobs.update(original_jobs)
