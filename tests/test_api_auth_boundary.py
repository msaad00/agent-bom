"""Regression tests for control-plane auth boundary bypasses."""

from starlette.testclient import TestClient

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
