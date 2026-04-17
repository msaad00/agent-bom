"""Tests for API server hardening — auth, rate limiting, CORS, body size."""

import time
from unittest.mock import MagicMock, patch

from starlette.testclient import TestClient

from agent_bom.api.auth import KeyStore, Role, create_api_key, get_key_store, set_key_store
from agent_bom.api.middleware import InMemoryRateLimitStore
from agent_bom.api.oidc import OIDCConfig
from agent_bom.api.server import (
    APIKeyMiddleware,
    MaxBodySizeMiddleware,
    RateLimitMiddleware,
    app,
    configure_api,
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


def test_configure_api_refreshes_cors_policy():
    """configure_api() should update the live CORS middleware, not just a module variable."""
    configure_api(cors_allow_all=True)
    client = TestClient(app)
    resp = client.get("/health", headers={"Origin": "http://127.0.0.1:3001"})
    assert resp.status_code == 200
    assert resp.headers.get("access-control-allow-origin") == "*"

    configure_api(cors_origins=["http://127.0.0.1:3000"])
    client = TestClient(app)
    resp = client.get("/health", headers={"Origin": "http://127.0.0.1:3001"})
    assert resp.status_code == 200
    assert resp.headers.get("access-control-allow-origin") is None


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

    cfg = OIDCConfig(issuer="https://corp.okta.com", audience="agent-bom", tenant_claim="org_slug")
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


def test_api_key_middleware_oidc_requires_explicit_role_claim_when_enabled():
    """Strict OIDC mode should reject tokens that lack a mapped role signal."""
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse as StarletteJSONResponse
    from starlette.routing import Route

    async def dummy(request):
        return StarletteJSONResponse({"ok": True})

    test_app = Starlette(routes=[Route("/v1/test", dummy)])
    test_app.add_middleware(APIKeyMiddleware, api_key="test-key-123")

    cfg = OIDCConfig(
        issuer="https://corp.okta.com",
        audience="agent-bom",
        require_role_claim=True,
    )
    with (
        patch("agent_bom.api.oidc.OIDCConfig.from_env", return_value=cfg),
        patch(
            "agent_bom.api.oidc.verify_oidc_token",
            return_value={"sub": "u1", "email": "alice@corp.com"},
        ),
    ):
        client = TestClient(test_app)
        resp = client.get("/v1/test", headers={"Authorization": "Bearer oidc.jwt"})

    assert resp.status_code == 401
    assert "invalid API key" in resp.json()["detail"]


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


def test_rate_limit_middleware_can_fail_closed_when_shared_store_required(monkeypatch):
    """Production-style deployments should be able to refuse startup without shared limiter state."""
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse as StarletteJSONResponse
    from starlette.routing import Route

    async def dummy(request):
        return StarletteJSONResponse({"ok": True})

    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgresql://example/test")
    monkeypatch.setenv("AGENT_BOM_REQUIRE_SHARED_RATE_LIMIT", "1")
    with patch("agent_bom.api.middleware.PostgresRateLimitStore", side_effect=RuntimeError("boom")):
        test_app = Starlette(routes=[Route("/v1/test", dummy)])
        test_app.add_middleware(RateLimitMiddleware, scan_rpm=3, read_rpm=10)
        client = TestClient(test_app)
        try:
            client.get("/v1/test")
            raise AssertionError("expected shared rate-limit initialization to fail")
        except RuntimeError as exc:
            assert "AGENT_BOM_REQUIRE_SHARED_RATE_LIMIT" in str(exc)


def test_rate_limit_middleware_scopes_by_auth_credential():
    """Different API credentials behind one shared IP should not starve each other."""
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse as StarletteJSONResponse
    from starlette.routing import Route

    async def dummy(request):
        return StarletteJSONResponse({"ok": True})

    test_app = Starlette(routes=[Route("/v1/test", dummy)])
    test_app.add_middleware(RateLimitMiddleware, scan_rpm=3, read_rpm=2)

    client = TestClient(test_app)
    assert client.get("/v1/test", headers={"X-API-Key": "alpha"}).status_code == 200
    assert client.get("/v1/test", headers={"X-API-Key": "alpha"}).status_code == 200
    assert client.get("/v1/test", headers={"X-API-Key": "beta"}).status_code == 200


def test_rate_limit_middleware_scopes_api_keys_by_tenant():
    """Different API keys for the same tenant should share one tenant-wide bucket."""
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse as StarletteJSONResponse
    from starlette.routing import Route

    async def dummy(request):
        return StarletteJSONResponse({"ok": True})

    original_store = get_key_store()
    store = KeyStore()
    raw_alpha, alpha = create_api_key("alpha", Role.ADMIN, tenant_id="tenant-alpha")
    raw_beta, beta = create_api_key("beta", Role.ANALYST, tenant_id="tenant-alpha")
    store.add(alpha)
    store.add(beta)
    set_key_store(store)
    try:
        test_app = Starlette(routes=[Route("/v1/test", dummy)])
        test_app.add_middleware(APIKeyMiddleware, api_key="unused-static-key")
        test_app.add_middleware(RateLimitMiddleware, scan_rpm=3, read_rpm=2)

        client = TestClient(test_app)
        assert client.get("/v1/test", headers={"Authorization": f"Bearer {raw_alpha}"}).status_code == 200
        assert client.get("/v1/test", headers={"Authorization": f"Bearer {raw_beta}"}).status_code == 200
        assert client.get("/v1/test", headers={"Authorization": f"Bearer {raw_alpha}"}).status_code == 429
    finally:
        set_key_store(original_store)


def test_in_memory_rate_limit_store_prunes_oldest_entries_instead_of_clearing_all():
    """Overflow should evict oldest buckets, not reset every limiter bucket at once."""
    store = InMemoryRateLimitStore(window_seconds=60)
    now = time.time()
    store._hits = {f"bucket-{idx}": [now - 1] for idx in range(store._MAX_ENTRIES)}
    store._hits["important"] = [now - 1]
    store._last_cleanup = 0

    count, _ = store.hit("important", now)

    assert count == 2
    assert "important" in store._hits
    assert len(store._hits) <= store._MAX_ENTRIES


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
