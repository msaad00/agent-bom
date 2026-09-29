"""Only explicitly public HTTP operations may skip authentication."""

import pytest
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from agent_bom.api.middleware import APIKeyMiddleware


# Exercise actual middleware with a handler spy: adding an operation alongside
# a public health or login route must not silently make it anonymous.
@pytest.mark.parametrize(
    "method,path",
    [
        ("POST", "/health"),
        ("DELETE", "/healthz"),
        ("PUT", "/version"),
        ("PATCH", "/"),
        ("POST", "/docs"),
        ("POST", "/openapi.json"),
        ("GET", "/v1/auth/session"),
        ("PUT", "/v1/auth/session"),
        ("DELETE", "/v1/auth/dev-session"),
        ("POST", "/v1/auth/oidc/callback"),
        ("GET", "/v1/auth/saml/login"),
        ("DELETE", "/v1/auth/trial/oidc/start"),
    ],
)
def test_new_operation_on_public_path_requires_authentication(monkeypatch, method, path):
    monkeypatch.delenv("AGENT_BOM_ALLOW_UNAUTHENTICATED_API", raising=False)
    monkeypatch.delenv("AGENT_BOM_TRUST_PROXY_AUTH", raising=False)
    calls = []

    async def handler(request):
        calls.append(request.method)
        return JSONResponse({"accepted": True})

    app = Starlette(routes=[Route(path, handler, methods=[method])])
    app.add_middleware(APIKeyMiddleware, api_key="public-operation-test-key")
    response = TestClient(app).request(method, path)
    assert response.status_code == 401
    assert calls == []


@pytest.mark.parametrize(
    "method,path",
    [
        ("GET", "/health"),
        ("HEAD", "/health"),
        ("GET", "/docs"),
        ("POST", "/v1/auth/session"),
        ("DELETE", "/v1/auth/session"),
        ("POST", "/v1/auth/dev-session"),
        ("GET", "/v1/auth/oidc/callback"),
        ("POST", "/v1/auth/saml/login"),
        ("POST", "/v1/auth/saml/relay-state"),
        ("GET", "/v1/auth/saml/metadata"),
        ("POST", "/v1/auth/trial/oidc/start-form"),
    ],
)
def test_declared_public_operation_reaches_its_handler(method, path):
    async def handler(request):
        return JSONResponse({"accepted": True})

    app = Starlette(routes=[Route(path, handler, methods=[method])])
    app.add_middleware(APIKeyMiddleware, api_key="public-operation-test-key")
    assert TestClient(app).request(method, path).status_code == 200


def test_public_operation_inventory_matches_mounted_handlers():
    from agent_bom.api.route_policy import PUBLIC_OPERATIONS, public_operation
    from agent_bom.api.server import app

    try:
        from fastapi.routing import iter_route_contexts
    except ImportError:
        routes = [(route.path, getattr(route, "methods", ())) for route in app.routes]
    else:
        routes = [(ctx.path, getattr(ctx.route, "methods", ())) for ctx in iter_route_contexts(app.routes)]
    mounted = {(method, path) for path, methods in routes for method in methods or ()}
    assert PUBLIC_OPERATIONS <= mounted
    for method, path in mounted:
        if path in APIKeyMiddleware._EXEMPT_PATHS:
            assert public_operation(method, path), (method, path)
