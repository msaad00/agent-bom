"""The operator-visible route policy must agree with request enforcement."""

import pytest

from agent_bom.api.middleware import APIKeyMiddleware


@pytest.mark.parametrize(
    "method,path", [("POST", "/v1/cloud/connections"), ("PATCH", "/v1/cloud/connections/"), ("DELETE", "/v1/cloud/connections/")]
)
def test_scope_catalog_reports_the_enforced_role(method, path):
    policy = APIKeyMiddleware(app=None, api_key="")
    entry = next(row for row in policy.scope_catalog() if row["method"] == method and row["path_prefix"] == path)
    assert entry["required_role"] == policy._required_role(method, path) == "admin"


@pytest.mark.parametrize("path", ["/v1/scan-admin", "/v1/intel/match-admin", "/v1/sources-admin"])
def test_similar_prefix_does_not_inherit_a_less_privileged_mutation_rule(path):
    policy = APIKeyMiddleware(app=None, api_key="")
    assert policy._required_role("POST", path) == "admin"
    assert policy._required_scope("POST", path) is None


def test_scope_normalizes_http_method_like_role_resolution():
    policy = APIKeyMiddleware(app=None, api_key="")
    assert policy._required_scope("get", "/v1/auth/keys") == "auth.keys:read"
    assert policy._required_scope("head", "/v1/auth/keys") == "auth.keys:read"


@pytest.mark.parametrize("role,expected", [("viewer", 403), ("analyst", 403), ("admin", 403)])
def test_sibling_mutation_rule_is_enforced_at_http_boundary(monkeypatch, role, expected):
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse
    from starlette.routing import Route
    from starlette.testclient import TestClient

    async def handler(request):
        return JSONResponse({"accepted": True})

    secret = "route-policy-test-proxy-secret-32-characters"
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH", "1")
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH_SECRET", secret)
    app = Starlette(routes=[Route("/v1/scan-admin", handler, methods=["POST"])])
    app.add_middleware(APIKeyMiddleware, api_key="")
    response = TestClient(app).post(
        "/v1/scan-admin",
        headers={
            "X-Agent-Bom-Role": role,
            "X-Agent-Bom-Tenant-ID": "policy-test",
            "X-Agent-Bom-Proxy-Secret": secret,
        },
    )
    assert response.status_code == expected


def test_scope_catalog_matches_enforcement_for_every_row():
    policy = APIKeyMiddleware(app=None, api_key="")
    for row in policy.scope_catalog():
        assert row["required_role"] == policy._required_role(row["method"], row["path_prefix"])
        assert row["scope"] == policy._required_scope(row["method"], row["path_prefix"])
        if row["method"] == "GET":
            assert row["scope"] == policy._required_scope("HEAD", row["path_prefix"])


def test_source_bound_ingest_admission_does_not_require_cloud_write():
    from agent_bom.api.route_policy import request_scopes_allow, required_scope

    path = "/v1/cloud/runtime-evidence/ingest"
    assert required_scope("POST", path) == "runtime:ingest:*"
    assert request_scopes_allow(["runtime:ingest:edr-1"], "POST", path)
    for scopes in (["cloud:write"], ["scan:write"], ["runtime:ingest:"]):
        assert not request_scopes_allow(scopes, "POST", path)
    for other in (path + "/child", path + "-other"):
        assert required_scope("POST", other) == "cloud:write"
        assert not request_scopes_allow(["runtime:ingest:edr-1"], "POST", other)


@pytest.mark.parametrize("mode", ["key", "session", "proxy", "static", "oidc", "anonymous"])
@pytest.mark.parametrize("method", ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
def test_unclassified_operation_denied_after_every_authentication_path(monkeypatch, mode, method):
    from types import SimpleNamespace

    from starlette.applications import Starlette
    from starlette.responses import JSONResponse
    from starlette.routing import Route
    from starlette.testclient import TestClient

    from agent_bom.api.auth import KeyStore, Role, create_api_key, get_key_store, set_key_store
    from agent_bom.api.browser_session import CSRF_COOKIE_NAME, CSRF_HEADER_NAME, SESSION_COOKIE_NAME, create_browser_session_token
    from agent_bom.api.oidc import OIDCConfig

    for name in ("AGENT_BOM_API_KEY", "AGENT_BOM_OIDC_ISSUER", "AGENT_BOM_TRUST_PROXY_AUTH", "AGENT_BOM_DEMO_ESTATE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AGENT_BOM_NO_AUTH_ROLE", "admin")
    secret = "unclassified-test-proxy-attestation-32-characters"
    if mode == "proxy":
        monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH", "1")
        monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH_SECRET", secret)
    if mode == "oidc":
        config = SimpleNamespace(
            enabled=True, verify=lambda token: ({"sub": "operator"}, "admin"), resolve_tenant=lambda claims: "tenant-a"
        )
        monkeypatch.setattr(OIDCConfig, "from_env", classmethod(lambda cls: config))
    reached = []

    async def handler(request):
        reached.append(request.url.path)
        return JSONResponse({"accepted": True})

    previous = get_key_store()
    set_key_store(KeyStore())
    try:
        app = Starlette(routes=[Route("/{path:path}", handler, methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])])
        app.add_middleware(
            APIKeyMiddleware, api_key="static-test-key" if mode == "static" else "", allow_unauthenticated=mode == "anonymous"
        )
        client = TestClient(app)
        if mode in {"key", "session"}:
            raw, key = create_api_key(name="operator", role=Role.ADMIN, tenant_id="tenant-a", scopes=[])
            get_key_store().add(key)
            if mode == "key":
                client.headers["X-API-Key"] = raw
            else:
                token, csrf = create_browser_session_token(
                    subject=key.name,
                    role="admin",
                    tenant_id=key.tenant_id,
                    auth_method="api_key",
                    key_id=key.key_id,
                    scopes=[],
                    max_age_seconds=300,
                )
                client.cookies.set(SESSION_COOKIE_NAME, token)
                client.cookies.set(CSRF_COOKIE_NAME, csrf)
                client.headers[CSRF_HEADER_NAME] = csrf
        elif mode == "proxy":
            client.headers.update({"X-Agent-Bom-Role": "admin", "X-Agent-Bom-Tenant-ID": "tenant-a", "X-Agent-Bom-Proxy-Secret": secret})
        elif mode == "static":
            client.headers["X-API-Key"] = "static-test-key"
        elif mode == "oidc":
            client.headers["Authorization"] = "Bearer test.token.value"
        assert client.get("/v1/fleet").status_code == 200
        reached.clear()
        assert client.request(method, "/v1/unclassified-operation").status_code == 403
        assert reached == []
    finally:
        set_key_store(previous)


@pytest.mark.parametrize(
    "path,scope",
    [
        ("/v1/graph/query", "graph:read"),
        ("/v1/graph/should-i-deploy", "graph:read"),
        ("/v1/runtime/profiles/evaluate", "runtime:read"),
        ("/v1/audit/export/verify", "audit:read"),
        ("/v1/intel/match", "intel:read"),
        ("/v1/intel/daily-brief", "intel:read"),
        ("/v1/traces/attack-paths", "runtime:read"),
    ],
)
def test_post_read_grants_do_not_authorize_future_child_operations(path, scope):
    from agent_bom.api.route_policy import request_scopes_allow

    assert request_scopes_allow([scope], "POST", path)
    assert not request_scopes_allow([scope], "POST", path + "/mutate")
    assert not request_scopes_allow([scope], "POST", path + "-admin")
