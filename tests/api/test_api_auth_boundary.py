"""Regression tests for control-plane auth boundary bypasses."""

from starlette.testclient import TestClient

from agent_bom.api.middleware import APIKeyMiddleware
from agent_bom.api.scim_store import InMemorySCIMStore, SCIMUser
from agent_bom.api.server import app
from agent_bom.api.stores import set_scim_store

PROXY_SECRET = "test-proxy-secret-with-32-plus-bytes"


def _configure_trusted_proxy_with_scim(monkeypatch) -> None:
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH", "1")
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH_SECRET", PROXY_SECRET)
    monkeypatch.setenv("AGENT_BOM_SCIM_BEARER_TOKEN", "scim-secret")

    from agent_bom.api import server as api_server

    api_server.configure_api(api_key=None)


def _proxy_headers(*, subject: str, role: str = "viewer", tenant_id: str = "tenant-alpha") -> dict[str, str]:
    return {
        "X-Agent-Bom-Role": role,
        "X-Agent-Bom-Subject": subject,
        "X-Agent-Bom-Tenant-ID": tenant_id,
        "X-Agent-Bom-Proxy-Secret": PROXY_SECRET,
    }


def test_gateway_policy_create_rejects_spoofed_role_without_attestation() -> None:
    client = TestClient(app)
    response = client.post(
        "/v1/gateway/policies",
        json={"name": "spoofed", "mode": "enforce", "rules": [{"id": "r1", "action": "block", "block_tools": ["exec"]}]},
        headers={"X-Agent-Bom-Role": "admin", "X-Agent-Bom-Tenant-ID": "tenant-alpha"},
    )

    assert response.status_code == 401


def test_enterprise_read_routes_reject_spoofed_proxy_headers_without_attestation() -> None:
    client = TestClient(app)
    headers = {"X-Agent-Bom-Role": "viewer", "X-Agent-Bom-Tenant-ID": "tenant-alpha"}

    assert client.get("/v1/posture", headers=headers).status_code == 401
    assert client.get("/metrics", headers=headers).status_code == 401
    assert client.get("/v1/compliance/owasp-llm/report", headers=headers).status_code == 401


def test_attested_proxy_headers_are_accepted_when_explicitly_enabled(monkeypatch) -> None:
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH", "1")
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH_SECRET", PROXY_SECRET)
    client = TestClient(app)

    response = client.get(
        "/v1/posture",
        headers={
            "X-Agent-Bom-Role": "viewer",
            "X-Agent-Bom-Tenant-ID": "tenant-alpha",
            "X-Agent-Bom-Proxy-Secret": PROXY_SECRET,
        },
    )

    assert response.status_code == 200


def test_attested_proxy_headers_reject_wrong_secret(monkeypatch) -> None:
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH", "1")
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH_SECRET", PROXY_SECRET)
    client = TestClient(app)

    response = client.get(
        "/v1/posture",
        headers={
            "X-Agent-Bom-Role": "viewer",
            "X-Agent-Bom-Tenant-ID": "tenant-alpha",
            "X-Agent-Bom-Proxy-Secret": "wrong",
        },
    )

    assert response.status_code == 401


def test_unmatched_v1_mutating_route_requires_admin_by_default(monkeypatch) -> None:
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse as StarletteJSONResponse
    from starlette.routing import Route

    async def dummy(request):
        return StarletteJSONResponse({"ok": True})

    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH", "1")
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH_SECRET", PROXY_SECRET)
    test_app = Starlette(routes=[Route("/v1/unmatched-enterprise-write", dummy, methods=["POST"])])
    test_app.add_middleware(APIKeyMiddleware, api_key="")
    client = TestClient(test_app)

    denied = client.post(
        "/v1/unmatched-enterprise-write",
        json={"name": "new-route"},
        headers=_proxy_headers(subject="viewer@example.com", role="viewer"),
    )
    allowed = client.post(
        "/v1/unmatched-enterprise-write",
        json={"name": "new-route"},
        headers=_proxy_headers(subject="admin@example.com", role="admin"),
    )

    assert denied.status_code == 403
    assert "requires admin role" in denied.json()["detail"]
    assert allowed.status_code == 200


def test_scim_role_can_authorize_attested_proxy_subject(monkeypatch) -> None:
    _configure_trusted_proxy_with_scim(monkeypatch)
    store = InMemorySCIMStore()
    store.put_user(SCIMUser(tenant_id="tenant-alpha", user_name="alice@example.com", roles=["admin"]))
    set_scim_store(store)
    client = TestClient(app)

    response = client.get("/v1/auth/policy", headers=_proxy_headers(subject="alice@example.com", role="viewer"))

    assert response.status_code == 200


def test_scim_role_is_tenant_scoped_for_attested_proxy_subject(monkeypatch) -> None:
    _configure_trusted_proxy_with_scim(monkeypatch)
    store = InMemorySCIMStore()
    store.put_user(SCIMUser(tenant_id="tenant-beta", user_name="alice@example.com", roles=["admin"]))
    set_scim_store(store)
    client = TestClient(app)

    response = client.get("/v1/auth/policy", headers=_proxy_headers(subject="alice@example.com", role="viewer", tenant_id="tenant-alpha"))

    assert response.status_code == 403


def test_scim_role_downgrades_attested_proxy_role_when_subject_matches(monkeypatch) -> None:
    _configure_trusted_proxy_with_scim(monkeypatch)
    store = InMemorySCIMStore()
    store.put_user(SCIMUser(tenant_id="tenant-alpha", user_name="alice@example.com", roles=["viewer"]))
    set_scim_store(store)
    client = TestClient(app)

    response = client.get("/v1/auth/policy", headers=_proxy_headers(subject="alice@example.com", role="admin"))

    assert response.status_code == 403


def test_inactive_scim_user_rejects_attested_proxy_subject(monkeypatch) -> None:
    _configure_trusted_proxy_with_scim(monkeypatch)
    store = InMemorySCIMStore()
    store.put_user(SCIMUser(tenant_id="tenant-alpha", user_name="alice@example.com", active=False, roles=["admin"]))
    set_scim_store(store)
    client = TestClient(app)

    response = client.get("/v1/auth/policy", headers=_proxy_headers(subject="alice@example.com", role="admin"))

    assert response.status_code == 401


def test_scim_role_does_not_downgrade_regular_service_api_key(monkeypatch) -> None:
    monkeypatch.setenv("AGENT_BOM_SCIM_BEARER_TOKEN", "scim-secret")
    from agent_bom.api import server as api_server
    from agent_bom.api.auth import KeyStore, Role, create_api_key, get_key_store, set_key_store

    api_server.configure_api(api_key=None)
    scim_store = InMemorySCIMStore()
    scim_store.put_user(SCIMUser(tenant_id="tenant-alpha", user_name="alice@example.com", roles=["viewer"]))
    set_scim_store(scim_store)
    original_key_store = get_key_store()
    key_store = KeyStore()
    raw_key, api_key = create_api_key("alice@example.com", Role.ADMIN, tenant_id="tenant-alpha")
    key_store.add(api_key)
    set_key_store(key_store)
    client = TestClient(app)

    try:
        response = client.get("/v1/auth/policy", headers={"Authorization": f"Bearer {raw_key}"})
    finally:
        set_key_store(original_key_store)

    assert response.status_code == 200


def test_read_shaped_posts_stay_viewer_reachable() -> None:
    """The mutating-route admin fallback must not lock viewers out of
    read-shaped POSTs (bounded query / deploy decision / audit verify).

    Regression guard: these return no key material and were viewer-reachable
    before the unmatched-mutating-route admin fallback was added.
    """
    middleware = APIKeyMiddleware(app, api_key="")
    for path in (
        "/v1/graph/query",
        "/v1/graph/should-i-deploy",
        "/v1/audit/export/verify",
    ):
        assert middleware._required_role("POST", path) == "viewer", path
    # The fallback itself still defends genuinely-unlisted mutating routes.
    assert middleware._required_role("POST", "/v1/auth/keys") == "admin"


def test_head_inherits_get_route_role() -> None:
    """A HEAD request must inherit the required role of the matching GET route.

    Regression guard: keying the role lookup on the literal "HEAD" method would
    miss every GET rule and fall through to the viewer default, letting an
    anonymous HEAD reach an admin GET handler under ALLOW_UNAUTHENTICATED_API.
    """
    middleware = APIKeyMiddleware(app, api_key="")
    for path in ("/v1/auth/policy", "/v1/auth/keys", "/v1/entitlements"):
        assert middleware._required_role("GET", path) == "admin", path
        assert middleware._required_role("HEAD", path) == "admin", path
    # Scope lookup normalizes HEAD too.
    assert middleware._required_scope("HEAD", "/v1/auth/keys") == middleware._required_scope("GET", "/v1/auth/keys")


def test_anonymous_head_on_admin_route_is_gated(monkeypatch) -> None:
    """With anonymous access enabled, an anonymous HEAD on an admin GET route
    must be gated exactly like GET (403), not fall through to viewer access."""
    from starlette.applications import Starlette
    from starlette.responses import PlainTextResponse
    from starlette.routing import Route

    # Pin the anonymous identity to viewer so the admin gate is observable
    # (the test harness defaults NO_AUTH_ROLE to admin).
    monkeypatch.setenv("AGENT_BOM_NO_AUTH_ROLE", "viewer")

    async def dummy(_request):  # noqa: ANN001, ANN202
        return PlainTextResponse("ok")

    # /v1/auth/policy requires admin; expose it for both GET and HEAD.
    test_app = Starlette(routes=[Route("/v1/auth/policy", dummy, methods=["GET", "HEAD"])])
    test_app.add_middleware(APIKeyMiddleware, api_key="", allow_unauthenticated=True)
    client = TestClient(test_app)

    get_status = client.get("/v1/auth/policy").status_code
    head_status = client.head("/v1/auth/policy").status_code
    assert get_status == 403
    assert head_status == get_status, "HEAD must be gated like GET, not fall through to viewer"
