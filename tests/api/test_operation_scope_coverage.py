"""Scope ceilings apply to reads, writes, streams and key-backed sessions."""

from __future__ import annotations

import re

import pytest
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from agent_bom.api.auth import KeyStore, Role, create_api_key, get_key_store, set_key_store
from agent_bom.api.browser_session import CSRF_COOKIE_NAME, CSRF_HEADER_NAME, SESSION_COOKIE_NAME, create_browser_session_token
from agent_bom.api.middleware import APIKeyMiddleware


@pytest.fixture(autouse=True)
def isolated_keys(monkeypatch):
    for name in ("AGENT_BOM_API_KEY", "AGENT_BOM_OIDC_ISSUER", "AGENT_BOM_TRUST_PROXY_AUTH", "AGENT_BOM_DEMO_ESTATE"):
        monkeypatch.delenv(name, raising=False)
    original = get_key_store()
    set_key_store(KeyStore())
    yield
    set_key_store(original)


def client_for(method, path):
    async def handler(request):
        return JSONResponse({"role": request.state.api_key_role, "scopes": request.state.api_key_scopes})

    app = Starlette(routes=[Route(path, handler, methods=method if isinstance(method, list) else [method])])
    app.add_middleware(APIKeyMiddleware, api_key="")
    return TestClient(app)


def authenticate(client, mode, *, scopes, role=Role.ADMIN):
    raw, key = create_api_key(name="scope-contract", role=role, tenant_id="scope-tenant", scopes=scopes)
    get_key_store().add(key)
    if mode == "key":
        client.headers["X-API-Key"] = raw
    else:
        token, csrf = create_browser_session_token(
            subject=key.name,
            role=role.value,
            tenant_id=key.tenant_id,
            auth_method="api_key",
            key_id=key.key_id,
            scopes=scopes,
            max_age_seconds=300,
        )
        client.cookies.set(SESSION_COOKIE_NAME, token)
        client.cookies.set(CSRF_COOKIE_NAME, csrf)
        client.headers[CSRF_HEADER_NAME] = csrf
        client.headers["Origin"] = "http://testserver"
    return key


CASES = [
    ("GET", "/v1/audit/export", "audit:read"),
    ("GET", "/v1/scan/job/stream", "scan:read"),
    ("GET", "/v1/sources", "source:read"),
    ("POST", "/v1/sources", "source:write"),
    ("PUT", "/v1/fleet/agent", "fleet:write"),
    ("POST", "/v1/findings/bulk", "finding:write"),
    ("GET", "/v1/posture", "posture:read"),
    ("GET", "/v1/compliance", "compliance:read"),
    ("POST", "/v1/results/push", "scan:write"),
    ("POST", "/v1/identities", "identity:write"),
    ("GET", "/v1/gateway/feed/stream", "gateway:read"),
    ("GET", "/metrics", "observability:read"),
]


@pytest.mark.parametrize("mode", ["key", "session"])
@pytest.mark.parametrize("method,path,scope", CASES)
def test_unrelated_scope_denied_before_handler(mode, method, path, scope):
    client = client_for(method, path)
    authenticate(client, mode, scopes=["unrelated:read"])
    assert client.request(method, path).status_code == 403


@pytest.mark.parametrize("mode", ["key", "session"])
@pytest.mark.parametrize("method,path,scope", CASES)
def test_matching_scope_reaches_handler(mode, method, path, scope):
    client = client_for(method, path)
    authenticate(client, mode, scopes=[scope])
    assert client.request(method, path).status_code == 200


@pytest.mark.parametrize("mode", ["key", "session"])
@pytest.mark.parametrize("method", ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
@pytest.mark.parametrize("scopes", [[], ["*"], ["scan:write"]])
def test_unclassified_operation_fails_closed_for_scoped_identity(mode, method, scopes):
    path = "/v1/unclassified-operation"
    client = client_for(method, path)
    authenticate(client, mode, scopes=scopes)
    assert client.request(method, path).status_code == 403


@pytest.mark.parametrize("mode", ["key", "session"])
@pytest.mark.parametrize("scopes", [[], ["*"], ["source:*"], ["source:read"]])
def test_legacy_unrestricted_and_family_scopes_remain_supported(mode, scopes):
    client = client_for("GET", "/v1/sources")
    authenticate(client, mode, scopes=scopes)
    assert client.get("/v1/sources").status_code == 200


@pytest.mark.parametrize("role", [Role.VIEWER, Role.ANALYST])
def test_matching_scope_never_overrides_role_floor(role):
    client = client_for("PUT", "/v1/fleet/agent")
    authenticate(client, "key", scopes=["fleet:write"], role=role)
    assert client.put("/v1/fleet/agent").status_code == 403


@pytest.mark.parametrize("mode", ["key", "session"])
@pytest.mark.parametrize("state", ["revoked", "expired"])
def test_matching_scope_never_overrides_credential_lifecycle(mode, state):
    client = client_for("GET", "/v1/sources")
    key = authenticate(client, mode, scopes=["source:read"])
    if state == "revoked":
        key.revoked_at = "2000-01-01T00:00:00+00:00"
    else:
        key.expires_at = "2000-01-01T00:00:00+00:00"
    assert client.get("/v1/sources").status_code == 401


def test_session_observes_live_key_role_downgrade():
    client = client_for("GET", "/v1/auth/keys")
    key = authenticate(client, "session", scopes=["auth.keys:read"])
    key.role = Role.VIEWER
    assert client.get("/v1/auth/keys").status_code == 403


def test_session_exposes_live_narrowed_scopes_to_delegation():
    client = client_for("GET", "/v1/auth/me")
    key = authenticate(client, "session", scopes=["auth.keys:write", "scan:read"])
    key.scopes = ["scan:read"]
    assert client.get("/v1/auth/me").json()["scopes"] == ["scan:read"]


def test_existing_session_cannot_gain_new_key_scope():
    client = client_for("POST", "/v1/scan")
    key = authenticate(client, "session", scopes=["scan:read"])
    key.scopes = ["scan:read", "scan:write"]
    assert client.post("/v1/scan").status_code == 403


@pytest.mark.parametrize("path", ["/ws/proxy/metrics", "/ws/proxy/alerts"])
@pytest.mark.parametrize("transport", ["header", "first-message"])
def test_websocket_rejects_unrelated_scope(monkeypatch, path, transport):
    from starlette.websockets import WebSocketDisconnect

    from agent_bom.api.server import app, configure_api
    from agent_bom.api.websocket_auth import _ws_auth_from_token

    monkeypatch.delenv("AGENT_BOM_ALLOW_UNAUTHENTICATED_API", raising=False)
    configure_api(api_key=None, allow_unauthenticated=False)
    raw, key = create_api_key(name="ws-limited", role=Role.ADMIN, scopes=["scan:read"])
    get_key_store().add(key)
    # Pin the handshake decision before entering an unbounded live stream.
    assert _ws_auth_from_token(raw, bearer=transport == "header") is None
    headers = {"Authorization": f"Bearer {raw}"} if transport == "header" else {}
    with pytest.raises(WebSocketDisconnect) as exc:
        with TestClient(app).websocket_connect(path, headers=headers) as ws:
            if transport == "first-message":
                ws.send_json({"type": "auth", "token": raw})
            message = ws.receive_json()
            pytest.fail(f"Out-of-scope stream returned data: {message.keys()}")
    assert exc.value.code == 4001


def test_viewer_summary_does_not_advertise_audit_access():
    from agent_bom.rbac import summarize_role

    summary = summarize_role(Role.VIEWER)
    assert "audit" not in summary["description"]
    assert all("audit" not in text for text in summary["can_see"])
    assert "audit.read" not in summary["capabilities"]
    assert "audit.read" in summarize_role(Role.ANALYST)["capabilities"]


def mounted_operations():
    from agent_bom.api.route_policy import public_operation
    from agent_bom.api.server import app

    # New FastAPI versions retain lazy included routers; old supported versions
    # flatten them. Inspect effective paths in either representation.
    try:
        from fastapi.routing import iter_route_contexts
    except ImportError:
        operations = [(route.path, getattr(route, "methods", set())) for route in app.routes]
    else:
        operations = [(ctx.path, getattr(ctx.route, "methods", set())) for ctx in iter_route_contexts(app.routes)]
    return [
        (method, path)
        for path, methods in operations
        for method in methods or ()
        if not public_operation(method, path) and path not in {"/v1/auth/me", "/docs/oauth2-redirect"} and path != "/{path:path}"
    ]


def test_mounted_http_operations_have_scope_policy():
    from agent_bom.api.route_policy import required_scope

    operations = mounted_operations()
    assert len(operations) > 400  # Catch lazy-router traversal regressions.
    missing = [(method, path) for method, path in operations if required_scope(method, path) is None]
    assert not missing, missing


@pytest.mark.parametrize("role", list(Role))
def test_every_mounted_protected_http_operation_enforces_role_and_scope(role):
    from agent_bom.api.route_policy import required_role, required_scope
    from agent_bom.rbac import role_rank

    client = client_for(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"], "/{path:path}")
    key = authenticate(client, "key", scopes=["unrelated:read"], role=role)
    for method, template in mounted_operations():
        path = re.sub(r"\{[^}]+\}", "scope-probe", template)
        key.scopes = ["unrelated:read"]
        # SCIM deliberately accepts only its dedicated provisioning bearer.
        denial = 401 if path.startswith("/scim/") else 403
        assert client.request(method, path).status_code == denial, (method, template, role)
        key.scopes = [required_scope(method, template)]
        expected = (
            401 if path.startswith("/scim/") else (200 if role_rank(role) >= role_rank(Role(required_role(method, template))) else 403)
        )
        assert client.request(method, path).status_code == expected, (method, template, role)


@pytest.mark.parametrize(
    "original,current,expected",
    [
        (["auth.*"], ["auth.keys:*"], ["auth.keys:*"]),
        (["scan:*"], ["scan:read"], ["scan:read"]),
        (["scan:read"], ["scan:*"], ["scan:read"]),
        ([], ["scan:read"], ["scan:read"]),
        (["scan:read"], [], ["scan:read"]),
        ([], [], []),
        (["*"], ["scan:read"], ["scan:read"]),
        (["scan:read"], ["*"], ["scan:read"]),
        (["auth.*"], ["auth:*"], None),
        (["scan:read"], ["finding:read"], None),
    ],
)
def test_session_grant_intersection_never_turns_disjoint_grants_into_unrestricted(original, current, expected):
    from agent_bom.api.session_authorization import intersect_session_scopes

    assert intersect_session_scopes(original, current) == expected


@pytest.mark.parametrize("mode", ["key", "session"])
@pytest.mark.parametrize("path", ["/v1/auth/me-extra", "/v1/auth/me/child", "/v1/sources-extra", "/v1/sources%2Dextra"])
def test_scope_rules_do_not_authorize_sibling_or_identity_subpaths(mode, path):
    client = client_for("GET", "/{path:path}")
    authenticate(client, mode, scopes=["source:read"])
    assert client.get(path).status_code == 403


@pytest.mark.parametrize("scopes", [[], ["*"], ["runtime:*"], ["runtime:read"]])
def test_websocket_accepts_runtime_read_authority(scopes):
    from agent_bom.api.websocket_auth import _ws_auth_from_token

    raw, key = create_api_key(name="ws-reader", role=Role.VIEWER, scopes=scopes, tenant_id="scope-tenant")
    get_key_store().add(key)
    context = _ws_auth_from_token(raw)
    assert context is not None
    assert context.tenant_id == "scope-tenant"


@pytest.mark.parametrize("mode", ["key", "session"])
@pytest.mark.parametrize(
    "path,scope",
    [
        ("/v1/graph/query", "graph:read"),
        ("/v1/graph/compromise", "graph:read"),
        ("/v1/graph/should-i-deploy", "graph:read"),
        ("/v1/runtime/profiles/evaluate", "runtime:read"),
        ("/v1/audit/export/verify", "audit:read"),
        ("/v1/intel/match", "intel:read"),
        ("/v1/intel/daily-brief", "intel:read"),
        ("/v1/traces/attack-paths", "runtime:read"),
    ],
)
def test_post_read_scope_is_limited_to_the_declared_operation(mode, path, scope):
    client = client_for("POST", "/{path:path}")
    authenticate(client, mode, scopes=[scope])
    assert client.post(path).status_code == 200
    assert client.post(path + "/mutate").status_code == 403
    assert client.post(path + "-admin").status_code == 403
