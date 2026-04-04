"""Tests for API server hardening — auth, rate limiting, CORS, body size."""

from unittest.mock import MagicMock, patch

from starlette.testclient import TestClient

from agent_bom.api.auth import KeyStore, Role, create_api_key, get_key_store, set_key_store
from agent_bom.api.oidc import OIDCConfig
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


def test_api_key_middleware_exception_create_allows_analyst_role():
    """Analyst API keys should keep write access to exception creation paths."""
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse as StarletteJSONResponse
    from starlette.routing import Route

    async def dummy(request):
        return StarletteJSONResponse({"tenant_id": getattr(request.state, "tenant_id", "default"), "role": request.state.api_key_role})

    original_store = get_key_store()
    store = KeyStore()
    raw_key, analyst = create_api_key("analyst", Role.ANALYST, tenant_id="tenant-alpha")
    store.add(analyst)
    set_key_store(store)
    try:
        test_app = Starlette(routes=[Route("/v1/exceptions", dummy, methods=["POST"])])
        test_app.add_middleware(APIKeyMiddleware, api_key="test-key-123")
        client = TestClient(test_app)
        resp = client.post("/v1/exceptions", headers={"Authorization": f"Bearer {raw_key}"})
        assert resp.status_code == 200
        assert resp.json() == {"tenant_id": "tenant-alpha", "role": "analyst"}
    finally:
        set_key_store(original_store)


def test_api_key_middleware_auth_key_list_requires_admin_role():
    """Viewer API keys should not be able to list API keys."""
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse as StarletteJSONResponse
    from starlette.routing import Route

    async def dummy(request):
        return StarletteJSONResponse({"ok": True})

    original_store = get_key_store()
    store = KeyStore()
    raw_key, viewer = create_api_key("viewer", Role.VIEWER, tenant_id="tenant-alpha")
    store.add(viewer)
    set_key_store(store)
    try:
        test_app = Starlette(routes=[Route("/v1/auth/keys", dummy)])
        test_app.add_middleware(APIKeyMiddleware, api_key="test-key-123")
        client = TestClient(test_app)
        resp = client.get("/v1/auth/keys", headers={"Authorization": f"Bearer {raw_key}"})
        assert resp.status_code == 403
        assert "requires admin role" in resp.json()["detail"]
    finally:
        set_key_store(original_store)


def test_api_key_middleware_oidc_sets_tenant_from_custom_claim():
    """OIDC tenant scoping should honor AGENT_BOM_OIDC_TENANT_CLAIM semantics."""
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse as StarletteJSONResponse
    from starlette.routing import Route

    async def dummy(request):
        return StarletteJSONResponse({"tenant_id": request.state.tenant_id, "role": request.state.api_key_role})

    test_app = Starlette(routes=[Route("/v1/test", dummy)])
    test_app.add_middleware(APIKeyMiddleware, api_key="test-key-123")

    cfg = OIDCConfig(issuer="https://corp.okta.com", tenant_claim="org_slug")
    with (
        patch("agent_bom.api.oidc.OIDCConfig.from_env", return_value=cfg),
        patch(
            "agent_bom.api.oidc.verify_oidc_token",
            return_value={"sub": "u1", "email": "alice@corp.com", "agent_bom_role": "analyst", "org_slug": "tenant-zeta"},
        ),
    ):
        client = TestClient(test_app)
        resp = client.get("/v1/test", headers={"Authorization": "Bearer oidc.jwt"})

    assert resp.status_code == 200
    assert resp.json() == {"tenant_id": "tenant-zeta", "role": "analyst"}


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


def test_rate_limit_middleware_uses_postgres_store_when_available(monkeypatch):
    """Postgres-backed limiter should be selected when AGENT_BOM_POSTGRES_URL is set."""
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse as StarletteJSONResponse
    from starlette.routing import Route

    async def dummy(request):
        return StarletteJSONResponse({"ok": True})

    fake_store = MagicMock()
    fake_store.hit.return_value = (1, 1_700_000_060)

    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgresql://example/test")
    with patch("agent_bom.api.middleware.PostgresRateLimitStore", return_value=fake_store):
        test_app = Starlette(routes=[Route("/v1/test", dummy)])
        test_app.add_middleware(RateLimitMiddleware, scan_rpm=3, read_rpm=10)
        client = TestClient(test_app)
        resp = client.get("/v1/test")

    assert resp.status_code == 200
    fake_store.hit.assert_called_once()


def test_rate_limit_middleware_falls_back_when_postgres_store_unavailable(monkeypatch):
    """Limiter should keep serving requests if shared Postgres state cannot initialize."""
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse as StarletteJSONResponse
    from starlette.routing import Route

    async def dummy(request):
        return StarletteJSONResponse({"ok": True})

    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgresql://example/test")
    with patch("agent_bom.api.middleware.PostgresRateLimitStore", side_effect=RuntimeError("boom")):
        test_app = Starlette(routes=[Route("/v1/test", dummy)])
        test_app.add_middleware(RateLimitMiddleware, scan_rpm=3, read_rpm=10)
        client = TestClient(test_app)
        resp = client.get("/v1/test")

    assert resp.status_code == 200


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
    from agent_bom.api.server import _MAX_CONCURRENT_JOBS, JobStatus, ScanJob, ScanRequest, _get_store, set_job_store
    from agent_bom.api.store import InMemoryJobStore

    # Use a fresh in-memory store filled with running jobs
    original_store = _get_store()
    fake_store = InMemoryJobStore()
    dummy_request = ScanRequest()
    for i in range(_MAX_CONCURRENT_JOBS):
        fake_store.put(
            ScanJob(
                job_id=f"fake-{i}",
                status=JobStatus.RUNNING,
                created_at="2026-01-01T00:00:00Z",
                request=dummy_request,
                progress=[],
            )
        )

    set_job_store(fake_store)
    try:
        client = TestClient(app)
        resp = client.post("/v1/scan", json={"images": [], "k8s": False, "tf_dirs": [], "agent_projects": [], "enrich": False})
        assert resp.status_code == 429
        assert "concurrent" in resp.json()["detail"].lower()
    finally:
        set_job_store(original_store)
