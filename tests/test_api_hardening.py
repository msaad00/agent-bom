"""Tests for API server hardening — auth, rate limiting, CORS, body size."""

import base64
import json
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from fastapi import Response
from starlette.testclient import TestClient

from agent_bom.api.auth import KeyStore, Role, create_api_key, get_key_store, set_key_store
from agent_bom.api.browser_session import (
    CSRF_COOKIE_NAME,
    CSRF_HEADER_NAME,
    SESSION_COOKIE_NAME,
    BrowserSessionError,
    create_browser_session_token,
    revoke_browser_session_token,
)
from agent_bom.api.middleware import InMemoryRateLimitStore
from agent_bom.api.oidc import OIDCConfig
from agent_bom.api.server import (
    APIKeyMiddleware,
    MaxBodySizeMiddleware,
    RateLimitMiddleware,
    app,
    configure_api,
)


def _unsigned_test_jwt(claims: dict[str, str]) -> str:
    header = base64.urlsafe_b64encode(json.dumps({"alg": "none"}).encode()).decode().rstrip("=")
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"{header}.{payload}."


def test_health_no_auth():
    """Health endpoint should be accessible without authentication."""
    client = TestClient(app)
    resp = client.get("/health")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_browser_session_exchange_has_targeted_rate_limit(monkeypatch):
    from fastapi import HTTPException

    from agent_bom.api.routes import enterprise
    from agent_bom.api.shared_auth_state import reset_auth_state_for_tests

    reset_auth_state_for_tests()
    monkeypatch.setenv("AGENT_BOM_AUTH_SESSION_ATTEMPTS_PER_MINUTE", "2")
    monkeypatch.setenv("AGENT_BOM_API_KEY", "valid-key")
    request = SimpleNamespace(headers={}, client=SimpleNamespace(host="203.0.113.10"))

    with pytest.raises(HTTPException) as first:
        await enterprise.create_browser_session(request, Response(), enterprise.BrowserSessionRequest(api_key="bad-1"))
    assert first.value.status_code == 401
    with pytest.raises(HTTPException) as second:
        await enterprise.create_browser_session(request, Response(), enterprise.BrowserSessionRequest(api_key="bad-2"))
    assert second.value.status_code == 401
    with pytest.raises(HTTPException) as error:
        await enterprise.create_browser_session(request, Response(), enterprise.BrowserSessionRequest(api_key="valid-key"))

    assert error.value.status_code == 429


def test_browser_session_cookies_use_strict_samesite(monkeypatch):
    from agent_bom.api.routes import enterprise

    monkeypatch.setenv("AGENT_BOM_BROWSER_SESSION_SIGNING_KEY", "test-browser-session-signing-key")
    request = SimpleNamespace(headers={}, url=SimpleNamespace(scheme="https"))
    response = Response()

    enterprise._set_browser_session_cookie(
        response,
        request,
        subject="dashboard-user",
        role="admin",
        tenant_id="tenant-alpha",
        auth_method="browser_session_static_api_key",
    )

    set_cookie_values = [value.decode("latin-1") for key, value in response.raw_headers if key.lower() == b"set-cookie"]
    assert len(set_cookie_values) == 2
    assert all("SameSite=strict" in value for value in set_cookie_values)
    assert any("HttpOnly" in value and SESSION_COOKIE_NAME in value for value in set_cookie_values)
    assert any(CSRF_COOKIE_NAME in value for value in set_cookie_values)


def test_browser_session_requires_persistent_key_when_clustered(monkeypatch):
    monkeypatch.delenv("AGENT_BOM_BROWSER_SESSION_SIGNING_KEY", raising=False)
    monkeypatch.setenv("AGENT_BOM_CONTROL_PLANE_REPLICAS", "2")

    with pytest.raises(BrowserSessionError, match="BROWSER_SESSION_SIGNING_KEY is required"):
        create_browser_session_token(
            subject="dashboard-user",
            role="admin",
            tenant_id="tenant-alpha",
            auth_method="browser_session",
            max_age_seconds=300,
        )


@pytest.mark.asyncio
async def test_static_browser_session_exchange_fails_closed_when_clustered(monkeypatch):
    from fastapi import HTTPException

    from agent_bom.api.routes import enterprise
    from agent_bom.api.shared_auth_state import reset_auth_state_for_tests

    reset_auth_state_for_tests()
    monkeypatch.setenv("AGENT_BOM_API_KEY", "valid-key")
    monkeypatch.setenv("AGENT_BOM_BROWSER_SESSION_SIGNING_KEY", "stable-browser-session-key")
    monkeypatch.setenv("AGENT_BOM_CONTROL_PLANE_REPLICAS", "2")
    request = SimpleNamespace(headers={}, client=SimpleNamespace(host="203.0.113.20"))

    with pytest.raises(HTTPException) as error:
        await enterprise.create_browser_session(request, Response(), enterprise.BrowserSessionRequest(api_key="valid-key"))

    assert error.value.status_code == 503
    assert "static-key auth is disabled" in error.value.detail


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


def test_api_key_middleware_exempts_packaged_dashboard_assets():
    """Dashboard shell assets must load before browser auth/bootstrap completes."""
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse as StarletteJSONResponse
    from starlette.routing import Route

    async def dummy(request):
        return StarletteJSONResponse({"ok": True})

    test_app = Starlette(
        routes=[
            Route("/_next/static/app.js", dummy),
            Route("/agents/index.html", dummy),
            Route("/vulns.html", dummy),
            Route("/admin.js", dummy),
            Route("/v1/test.js", dummy),
        ]
    )
    test_app.add_middleware(APIKeyMiddleware, api_key="test-key-123")

    client = TestClient(test_app)
    assert client.get("/_next/static/app.js").status_code == 200
    assert client.get("/agents/index.html").status_code == 200
    assert client.get("/vulns.html").status_code == 200
    assert client.get("/admin.js").status_code == 401
    assert client.get("/v1/test.js").status_code == 401


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


def test_configure_api_orders_auth_before_rate_limit_for_tenant_scoping(monkeypatch):
    """Auth must populate tenant state before rate limiting resolves buckets."""
    from agent_bom.api.server import app, configure_api

    original = list(app.user_middleware)
    try:
        monkeypatch.delenv("AGENT_BOM_OIDC_ISSUER", raising=False)
        configure_api(api_key="test-key-123", rate_limit_rpm=10)
        order = [middleware.cls for middleware in app.user_middleware]
        assert order.index(MaxBodySizeMiddleware) < order.index(APIKeyMiddleware) < order.index(RateLimitMiddleware)
    finally:
        app.user_middleware = original
        if app.middleware_stack is not None:
            app.middleware_stack = app.build_middleware_stack()


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


def test_api_key_middleware_accepts_signed_browser_session(monkeypatch):
    """Signed httpOnly-cookie sessions authenticate browsers without raw key reuse."""
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse as StarletteJSONResponse
    from starlette.routing import Route

    monkeypatch.setenv("AGENT_BOM_BROWSER_SESSION_SIGNING_KEY", "test-browser-session-signing-key")

    async def dummy(request):
        return StarletteJSONResponse(
            {
                "ok": True,
                "role": request.state.api_key_role,
                "tenant": request.state.tenant_id,
                "method": request.state.auth_method,
            }
        )

    token, csrf = create_browser_session_token(
        subject="dashboard-user",
        role="admin",
        tenant_id="tenant-alpha",
        auth_method="browser_session_static_api_key",
        max_age_seconds=300,
    )
    test_app = Starlette(routes=[Route("/v1/scan", dummy, methods=["POST"])])
    test_app.add_middleware(APIKeyMiddleware, api_key="static-key")

    client = TestClient(test_app)
    resp = client.post(
        "/v1/scan",
        headers={CSRF_HEADER_NAME: csrf},
        cookies={SESSION_COOKIE_NAME: token, CSRF_COOKIE_NAME: csrf},
    )
    assert resp.status_code == 200
    assert resp.json() == {
        "ok": True,
        "role": "admin",
        "tenant": "tenant-alpha",
        "method": "browser_session_static_api_key",
    }


def test_static_api_key_middleware_fails_closed_when_clustered(monkeypatch):
    """The static key shortcut must not pin all tenants to default in clustered mode."""
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse as StarletteJSONResponse
    from starlette.routing import Route

    async def dummy(request):
        return StarletteJSONResponse({"ok": True})

    monkeypatch.setenv("AGENT_BOM_CONTROL_PLANE_REPLICAS", "2")
    test_app = Starlette(routes=[Route("/v1/test", dummy)])
    test_app.add_middleware(APIKeyMiddleware, api_key="static-key")
    client = TestClient(test_app)

    with pytest.raises(RuntimeError, match="static-key auth is disabled"):
        client.get("/v1/test", headers={"Authorization": "Bearer static-key"})


def test_api_key_middleware_rejects_browser_session_without_csrf(monkeypatch):
    """Unsafe browser-session requests need the CSRF cookie/header pair."""
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse as StarletteJSONResponse
    from starlette.routing import Route

    monkeypatch.setenv("AGENT_BOM_BROWSER_SESSION_SIGNING_KEY", "test-browser-session-signing-key")

    async def dummy(request):
        return StarletteJSONResponse({"ok": True})

    token, csrf = create_browser_session_token(
        subject="dashboard-user",
        role="admin",
        tenant_id="tenant-alpha",
        auth_method="browser_session_static_api_key",
        max_age_seconds=300,
    )
    test_app = Starlette(routes=[Route("/v1/scan", dummy, methods=["POST"])])
    test_app.add_middleware(APIKeyMiddleware, api_key="static-key")

    client = TestClient(test_app)
    resp = client.post("/v1/scan", cookies={SESSION_COOKIE_NAME: token, CSRF_COOKIE_NAME: csrf})
    assert resp.status_code == 403
    assert resp.json()["detail"] == "Forbidden — missing or invalid CSRF token"


def test_api_key_middleware_rejects_csrf_from_another_session(monkeypatch):
    """CSRF tokens are bound to the signed browser-session nonce."""
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse as StarletteJSONResponse
    from starlette.routing import Route

    monkeypatch.setenv("AGENT_BOM_BROWSER_SESSION_SIGNING_KEY", "test-browser-session-signing-key")

    async def dummy(request):
        return StarletteJSONResponse({"ok": True})

    token_a, _csrf_a = create_browser_session_token(
        subject="dashboard-user",
        role="admin",
        tenant_id="tenant-alpha",
        auth_method="browser_session_static_api_key",
        max_age_seconds=300,
    )
    _token_b, csrf_b = create_browser_session_token(
        subject="dashboard-user",
        role="admin",
        tenant_id="tenant-alpha",
        auth_method="browser_session_static_api_key",
        max_age_seconds=300,
    )
    test_app = Starlette(routes=[Route("/v1/scan", dummy, methods=["POST"])])
    test_app.add_middleware(APIKeyMiddleware, api_key="static-key")

    client = TestClient(test_app)
    resp = client.post(
        "/v1/scan",
        headers={CSRF_HEADER_NAME: csrf_b},
        cookies={SESSION_COOKIE_NAME: token_a, CSRF_COOKIE_NAME: csrf_b},
    )
    assert resp.status_code == 403


def test_api_key_middleware_rejects_revoked_browser_session(monkeypatch):
    """Logout-side nonce revocation should invalidate a live signed session."""
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse as StarletteJSONResponse
    from starlette.routing import Route

    monkeypatch.setenv("AGENT_BOM_BROWSER_SESSION_SIGNING_KEY", "test-browser-session-signing-key")

    async def dummy(request):
        return StarletteJSONResponse({"ok": True})

    token, csrf = create_browser_session_token(
        subject="dashboard-user",
        role="admin",
        tenant_id="tenant-alpha",
        auth_method="browser_session_static_api_key",
        max_age_seconds=300,
    )
    assert revoke_browser_session_token(token) is True
    test_app = Starlette(routes=[Route("/v1/scan", dummy, methods=["POST"])])
    test_app.add_middleware(APIKeyMiddleware, api_key="static-key")

    client = TestClient(test_app)
    resp = client.post(
        "/v1/scan",
        headers={CSRF_HEADER_NAME: csrf},
        cookies={SESSION_COOKIE_NAME: token, CSRF_COOKIE_NAME: csrf},
    )
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


def test_api_key_middleware_proxy_headers_authenticate_when_enabled(monkeypatch):
    """Trusted proxy headers should satisfy auth when explicitly enabled."""
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse as StarletteJSONResponse
    from starlette.routing import Route

    async def dummy(request):
        return StarletteJSONResponse(
            {
                "role": request.state.api_key_role,
                "tenant_id": request.state.tenant_id,
                "method": request.state.auth_method,
            }
        )

    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH", "1")
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH_SECRET", "test-proxy-secret-with-32-plus-bytes")
    test_app = Starlette(routes=[Route("/v1/test", dummy)])
    test_app.add_middleware(APIKeyMiddleware, api_key="")

    client = TestClient(test_app)
    resp = client.get(
        "/v1/test",
        headers={
            "X-Agent-Bom-Role": "analyst",
            "X-Agent-Bom-Tenant-ID": "tenant-alpha",
            "X-Agent-Bom-Proxy-Secret": "test-proxy-secret-with-32-plus-bytes",
            "X-Agent-Bom-Subject": "alice@corp.example",
        },
    )
    assert resp.status_code == 200
    assert resp.json() == {"role": "analyst", "tenant_id": "tenant-alpha", "method": "proxy_header"}


def test_api_key_middleware_proxy_headers_require_tenant(monkeypatch):
    """Trusted proxy auth must fail closed when the tenant header is missing."""
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse as StarletteJSONResponse
    from starlette.routing import Route

    async def dummy(request):
        return StarletteJSONResponse({"ok": True})

    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH", "1")
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH_SECRET", "test-proxy-secret-with-32-plus-bytes")
    test_app = Starlette(routes=[Route("/v1/test", dummy)])
    test_app.add_middleware(APIKeyMiddleware, api_key="")

    client = TestClient(test_app)
    resp = client.get(
        "/v1/test",
        headers={"X-Agent-Bom-Role": "viewer", "X-Agent-Bom-Proxy-Secret": "test-proxy-secret-with-32-plus-bytes"},
    )
    assert resp.status_code == 401
    assert "X-Agent-Bom-Tenant-ID" in resp.json()["detail"]


def test_api_key_middleware_proxy_headers_reject_weak_secret(monkeypatch):
    """Trusted proxy auth must fail closed when attestation secret is too weak."""
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse as StarletteJSONResponse
    from starlette.routing import Route

    async def dummy(request):
        return StarletteJSONResponse({"ok": True})

    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH", "1")
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH_SECRET", "short")
    test_app = Starlette(routes=[Route("/v1/test", dummy)])
    test_app.add_middleware(APIKeyMiddleware, api_key="")

    client = TestClient(test_app)
    resp = client.get(
        "/v1/test",
        headers={
            "X-Agent-Bom-Role": "viewer",
            "X-Agent-Bom-Tenant-ID": "tenant-alpha",
            "X-Agent-Bom-Proxy-Secret": "short",
        },
    )
    assert resp.status_code == 503


def test_api_key_middleware_proxy_headers_require_pinned_issuer(monkeypatch):
    """When configured, trusted proxy auth must bind to the expected upstream issuer."""
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse as StarletteJSONResponse
    from starlette.routing import Route

    async def dummy(request):
        return StarletteJSONResponse({"ok": True})

    secret = "test-proxy-secret-with-32-plus-bytes"
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH", "1")
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH_SECRET", secret)
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH_ISSUER", "corp-oidc-proxy")
    test_app = Starlette(routes=[Route("/v1/test", dummy)])
    test_app.add_middleware(APIKeyMiddleware, api_key="")

    client = TestClient(test_app)
    resp = client.get(
        "/v1/test",
        headers={
            "X-Agent-Bom-Role": "viewer",
            "X-Agent-Bom-Tenant-ID": "tenant-alpha",
            "X-Agent-Bom-Proxy-Secret": secret,
            "X-Agent-Bom-Auth-Issuer": "other-proxy",
        },
    )
    assert resp.status_code == 401


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


def test_api_key_middleware_auth_key_rotate_requires_admin_role():
    """Analyst API keys must not be able to rotate enterprise API keys."""
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse as StarletteJSONResponse
    from starlette.routing import Route

    async def dummy(request):
        return StarletteJSONResponse({"ok": True})

    original_store = get_key_store()
    store = KeyStore()
    raw_key, analyst = create_api_key("analyst", Role.ANALYST, tenant_id="tenant-alpha")
    store.add(analyst)
    set_key_store(store)
    try:
        test_app = Starlette(routes=[Route("/v1/auth/keys/key-123/rotate", dummy, methods=["POST"])])
        test_app.add_middleware(APIKeyMiddleware, api_key="test-key-123")
        client = TestClient(test_app)
        resp = client.post("/v1/auth/keys/key-123/rotate", headers={"Authorization": f"Bearer {raw_key}"})
        assert resp.status_code == 403
        assert "requires admin role" in resp.json()["detail"]
    finally:
        set_key_store(original_store)


def test_api_key_middleware_exception_approve_requires_admin_role():
    """Analyst API keys must not be able to approve exceptions."""
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse as StarletteJSONResponse
    from starlette.routing import Route

    async def dummy(request):
        return StarletteJSONResponse({"ok": True})

    original_store = get_key_store()
    store = KeyStore()
    raw_key, analyst = create_api_key("analyst", Role.ANALYST, tenant_id="tenant-alpha")
    store.add(analyst)
    set_key_store(store)
    try:
        test_app = Starlette(routes=[Route("/v1/exceptions/exc-1/approve", dummy, methods=["PUT"])])
        test_app.add_middleware(APIKeyMiddleware, api_key="test-key-123")
        client = TestClient(test_app)
        resp = client.put("/v1/exceptions/exc-1/approve", headers={"Authorization": f"Bearer {raw_key}"})
        assert resp.status_code == 403
        assert "requires admin role" in resp.json()["detail"]
    finally:
        set_key_store(original_store)


def test_api_key_middleware_graph_preset_mutation_requires_analyst_role():
    """Viewer API keys must not be able to create graph presets."""
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
        test_app = Starlette(routes=[Route("/v1/graph/presets", dummy, methods=["POST"])])
        test_app.add_middleware(APIKeyMiddleware, api_key="test-key-123")
        client = TestClient(test_app)
        resp = client.post("/v1/graph/presets", headers={"Authorization": f"Bearer {raw_key}"})
        assert resp.status_code == 403
        assert "requires analyst role" in resp.json()["detail"]
    finally:
        set_key_store(original_store)


def test_api_key_middleware_enforces_scopes_when_present():
    """Scoped keys should be denied when the route needs a missing scope."""
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse as StarletteJSONResponse
    from starlette.routing import Route

    async def dummy(request):
        return StarletteJSONResponse({"ok": True})

    original_store = get_key_store()
    store = KeyStore()
    raw_key, analyst = create_api_key("analyst", Role.ANALYST, tenant_id="tenant-alpha", scopes=["graph.preset:write"])
    store.add(analyst)
    set_key_store(store)
    try:
        test_app = Starlette(routes=[Route("/v1/scan", dummy, methods=["POST"])])
        test_app.add_middleware(APIKeyMiddleware, api_key="test-key-123")
        client = TestClient(test_app)
        resp = client.post("/v1/scan", headers={"Authorization": f"Bearer {raw_key}"})
        assert resp.status_code == 403
        assert "requires scope scan:write" in resp.json()["detail"]
    finally:
        set_key_store(original_store)


def test_api_key_middleware_empty_scopes_keep_legacy_access():
    """Keys without scopes should preserve the legacy unrestricted behavior."""
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse as StarletteJSONResponse
    from starlette.routing import Route

    async def dummy(request):
        return StarletteJSONResponse({"ok": True})

    original_store = get_key_store()
    store = KeyStore()
    raw_key, analyst = create_api_key("analyst", Role.ANALYST, tenant_id="tenant-alpha")
    store.add(analyst)
    set_key_store(store)
    try:
        test_app = Starlette(routes=[Route("/v1/scan", dummy, methods=["POST"])])
        test_app.add_middleware(APIKeyMiddleware, api_key="test-key-123")
        client = TestClient(test_app)
        resp = client.post("/v1/scan", headers={"Authorization": f"Bearer {raw_key}"})
        assert resp.status_code == 200
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


def test_api_key_middleware_oidc_routes_token_to_tenant_bound_issuer():
    """Tenant-bound OIDC config should resolve issuer-specific tenant context."""
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse as StarletteJSONResponse
    from starlette.routing import Route

    async def dummy(request):
        return StarletteJSONResponse({"tenant_id": request.state.tenant_id, "role": request.state.api_key_role})

    test_app = Starlette(routes=[Route("/v1/test", dummy)])
    test_app.add_middleware(APIKeyMiddleware, api_key="test-key-123")

    cfg = OIDCConfig(
        tenant_providers={
            "tenant-alpha": OIDCConfig(
                issuer="https://alpha.okta.example",
                audience="agent-bom",
                tenant_id="tenant-alpha",
                require_tenant_claim=True,
            )
        }
    )
    token = _unsigned_test_jwt({"iss": "https://alpha.okta.example"})
    with (
        patch("agent_bom.api.oidc.OIDCConfig.from_env", return_value=cfg),
        patch(
            "agent_bom.api.oidc.verify_oidc_token",
            return_value={"iss": "https://alpha.okta.example", "sub": "u1", "agent_bom_role": "analyst", "tenant_id": "tenant-alpha"},
        ),
    ):
        client = TestClient(test_app)
        resp = client.get("/v1/test", headers={"Authorization": f"Bearer {token}"})

    assert resp.status_code == 200
    assert resp.json() == {"tenant_id": "tenant-alpha", "role": "analyst"}


def test_configure_api_enables_auth_middleware_for_oidc(monkeypatch):
    """OIDC-only deployments still need the auth middleware installed."""
    monkeypatch.setenv("AGENT_BOM_OIDC_ISSUER", "https://corp.okta.com")
    monkeypatch.setenv("AGENT_BOM_OIDC_AUDIENCE", "agent-bom")
    configure_api(api_key=None)
    try:
        assert any(m.cls is APIKeyMiddleware for m in app.user_middleware)
    finally:
        monkeypatch.delenv("AGENT_BOM_OIDC_ISSUER", raising=False)
        monkeypatch.delenv("AGENT_BOM_OIDC_AUDIENCE", raising=False)
        configure_api(api_key=None)


def test_configure_api_enables_auth_middleware_for_tenant_bound_oidc(monkeypatch):
    """Tenant-bound OIDC issuer maps should also install auth middleware."""
    monkeypatch.setenv(
        "AGENT_BOM_OIDC_TENANT_PROVIDERS_JSON",
        '{"tenant-alpha":{"issuer":"https://alpha.okta.example","audience":"agent-bom"}}',
    )
    configure_api(api_key=None)
    try:
        assert any(m.cls is APIKeyMiddleware for m in app.user_middleware)
    finally:
        monkeypatch.delenv("AGENT_BOM_OIDC_TENANT_PROVIDERS_JSON", raising=False)
        configure_api(api_key=None)


def test_configure_api_enables_auth_middleware_for_trusted_proxy(monkeypatch):
    """Trusted-proxy browser auth must also install the auth middleware."""
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH", "1")
    configure_api(api_key=None)
    try:
        assert any(m.cls is APIKeyMiddleware for m in app.user_middleware)
    finally:
        monkeypatch.delenv("AGENT_BOM_TRUST_PROXY_AUTH", raising=False)
        configure_api(api_key=None)


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


def test_rate_limit_middleware_fails_closed_when_postgres_store_unavailable(monkeypatch):
    """Configured shared Postgres state must not silently downgrade to local buckets."""
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
        with pytest.raises(RuntimeError, match="Configured Postgres rate limiter could not initialize"):
            client.get("/v1/test")


def test_rate_limit_middleware_can_fail_closed_when_shared_store_required(monkeypatch):
    """Production-style deployments should be able to refuse startup without shared limiter state."""
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse as StarletteJSONResponse
    from starlette.routing import Route

    async def dummy(request):
        return StarletteJSONResponse({"ok": True})

    monkeypatch.setenv("AGENT_BOM_CONTROL_PLANE_REPLICAS", "2")
    test_app = Starlette(routes=[Route("/v1/test", dummy)])
    test_app.add_middleware(RateLimitMiddleware, scan_rpm=3, read_rpm=10)
    client = TestClient(test_app)
    try:
        client.get("/v1/test")
        raise AssertionError("expected shared rate-limit initialization to fail")
    except RuntimeError as exc:
        assert "Shared rate limiting is required" in str(exc)


def test_rate_limit_middleware_respects_explicit_shared_rate_limit_requirement(monkeypatch):
    """The explicit fail-closed flag should reject startup without Postgres too."""
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse as StarletteJSONResponse
    from starlette.routing import Route

    async def dummy(request):
        return StarletteJSONResponse({"ok": True})

    monkeypatch.setenv("AGENT_BOM_REQUIRE_SHARED_RATE_LIMIT", "1")
    with patch("agent_bom.api.middleware.PostgresRateLimitStore", side_effect=RuntimeError("boom")):
        test_app = Starlette(routes=[Route("/v1/test", dummy)])
        test_app.add_middleware(RateLimitMiddleware, scan_rpm=3, read_rpm=10)
        client = TestClient(test_app)
        try:
            client.get("/v1/test")
            raise AssertionError("expected shared rate-limit initialization to fail")
        except RuntimeError as exc:
            assert "Shared rate limiting is required" in str(exc)


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


def test_rate_limit_middleware_ignores_untrusted_tenant_state():
    """Forged tenant state must not move unauthenticated requests into fresh buckets."""
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse as StarletteJSONResponse
    from starlette.routing import Route

    async def dummy(request):
        request.state.tenant_id = request.headers.get("X-Agent-Bom-Tenant-ID", "default")
        return StarletteJSONResponse({"ok": True})

    test_app = Starlette(routes=[Route("/v1/test", dummy)])
    limiter = RateLimitMiddleware(test_app, scan_rpm=3, read_rpm=2)
    client = TestClient(limiter)

    assert client.get("/v1/test", headers={"X-Agent-Bom-Tenant-ID": "tenant-a"}).status_code == 200
    assert client.get("/v1/test", headers={"X-Agent-Bom-Tenant-ID": "tenant-b"}).status_code == 200
    assert client.get("/v1/test", headers={"X-Agent-Bom-Tenant-ID": "tenant-c"}).status_code == 429


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


def test_in_memory_rate_limit_store_is_thread_safe_for_same_bucket():
    """Concurrent hits on one bucket should not lose updates."""
    store = InMemoryRateLimitStore(window_seconds=60)
    now = time.time()

    def _hit() -> int:
        count, _ = store.hit("shared-bucket", now)
        return count

    with ThreadPoolExecutor(max_workers=16) as pool:
        counts = list(pool.map(lambda _: _hit(), range(64)))

    assert len(store._hits["shared-bucket"]) == 64
    assert max(counts) == 64


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
    """Should return 429 when the tenant's active scan quota is exceeded."""
    from agent_bom.api.server import JobStatus, ScanJob, ScanRequest, _get_store, set_job_store
    from agent_bom.api.store import InMemoryJobStore
    from agent_bom.config import API_MAX_ACTIVE_SCAN_JOBS_PER_TENANT

    # Use a fresh in-memory store filled with running jobs
    original_store = _get_store()
    fake_store = InMemoryJobStore()
    dummy_request = ScanRequest()
    for i in range(API_MAX_ACTIVE_SCAN_JOBS_PER_TENANT):
        fake_store.put(
            ScanJob(
                job_id=f"fake-{i}",
                status=JobStatus.RUNNING,
                created_at="2026-01-01T00:00:00Z",
                request=dummy_request,
                progress=[],
                tenant_id="default",
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


def test_api_key_middleware_rejects_request_when_tenant_rls_bypass_is_active(monkeypatch):
    """Defence-in-depth guard at middleware.py:805-810.

    When `AGENT_BOM_POSTGRES_URL` is set and a request enters with the RLS
    bypass context still active (a code path that should never reach the HTTP
    boundary because `bypass_tenant_rls()` is `with`-scoped), the middleware
    must reject the request with 500 rather than serve tenant data with the
    bypass flag still true. Locks the guard so a future refactor can't quietly
    drop it.
    """
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse as StarletteJSONResponse
    from starlette.routing import Route

    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgresql://stub")

    async def dummy(request):
        return StarletteJSONResponse({"ok": True})

    # Stub `is_tenant_rls_bypassed` so the test does not require a live
    # Postgres connection — the bypass flag itself is a process-local
    # contextvar, which makes it cheap and safe to monkeypatch.
    import agent_bom.api.middleware as middleware_module
    import agent_bom.api.postgres_store as postgres_store_module

    monkeypatch.setattr(postgres_store_module, "is_tenant_rls_bypassed", lambda: True)

    test_app = Starlette(routes=[Route("/v1/test", dummy)])
    test_app.add_middleware(middleware_module.APIKeyMiddleware, api_key="test-key-123")

    client = TestClient(test_app)
    resp = client.get("/v1/test", headers={"Authorization": "Bearer test-key-123"})

    assert resp.status_code == 500
    assert "Tenant isolation guard" in resp.json()["detail"]


def test_api_key_middleware_does_not_check_rls_bypass_when_postgres_disabled(monkeypatch):
    """Reverse case: with no Postgres configured the guard short-circuits.

    Without `AGENT_BOM_POSTGRES_URL` set, the request must not even import
    the postgres_store helper — the `if os.environ.get(...)` gate keeps the
    SQLite-only path off the postgres dependency.
    """
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse as StarletteJSONResponse
    from starlette.routing import Route

    monkeypatch.delenv("AGENT_BOM_POSTGRES_URL", raising=False)

    async def dummy(request):
        return StarletteJSONResponse({"ok": True})

    import agent_bom.api.middleware as middleware_module

    test_app = Starlette(routes=[Route("/v1/test", dummy)])
    test_app.add_middleware(middleware_module.APIKeyMiddleware, api_key="test-key-123")

    client = TestClient(test_app)
    resp = client.get("/v1/test", headers={"Authorization": "Bearer test-key-123"})

    assert resp.status_code == 200
