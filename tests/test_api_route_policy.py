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


@pytest.mark.parametrize("role,expected", [("viewer", 403), ("analyst", 403), ("admin", 200)])
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
