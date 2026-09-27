"""The endpoint connector API enforces auth, tenant isolation and write-only secrets."""

from __future__ import annotations

import pytest
from cryptography.fernet import Fernet
from starlette.testclient import TestClient

from agent_bom.api import connection_crypto
from agent_bom.connectors.endpoints.store import EndpointStore

SECRET = "fixture-secret-do-not-return"
PROXY = "endpoint-test-trusted-proxy-secret-32bytes"
BODY = {
    "name": "Test Jamf",
    "provider": "jamf",
    "account_id": "acme.jamfcloud.com",
    "jamf_url": "https://acme.jamfcloud.com",
    "client_id": "fixture-client",
    "client_secret": SECRET,
}


def headers(role="admin", tenant="tenant-a"):
    return {"X-Agent-Bom-Role": role, "X-Agent-Bom-Tenant-ID": tenant, "X-Agent-Bom-Proxy-Secret": PROXY}


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.delenv("AGENT_BOM_ALLOW_UNAUTHENTICATED_API", raising=False)
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH", "1")
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH_SECRET", PROXY)
    monkeypatch.setenv("AGENT_BOM_CONNECTIONS_KEY", Fernet.generate_key().decode())
    monkeypatch.delenv("AGENT_BOM_CONNECTIONS_KEY_PROVIDER", raising=False)
    connection_crypto.reset_key_cache()
    store = EndpointStore(str(tmp_path / "endpoints.db"))
    monkeypatch.setattr("agent_bom.api.routes.endpoint_connectors.EndpointStore", lambda: store)
    from agent_bom.api.server import app

    yield TestClient(app)
    connection_crypto.reset_key_cache()


def test_anonymous_and_viewer_cannot_connect_or_sync(client):
    assert client.get("/v1/endpoint-connectors").status_code == 401
    for path, body in [("/v1/endpoint-connectors", BODY), ("/v1/endpoint-connectors/unknown/sync", {})]:
        assert client.post(path, json=body).status_code == 401
        assert client.post(path, json=body, headers=headers("viewer")).status_code == 403
        assert client.post(path, json=body, headers=headers("analyst")).status_code == 403


def test_create_list_tenant_bound_devices_and_rotation(client):
    result = client.post("/v1/endpoint-connectors", json=BODY, headers=headers())
    assert result.status_code == 201, result.text
    id = result.json()["id"]
    assert SECRET not in result.text and "client_secret" not in result.json()
    assert len(client.get("/v1/endpoint-connectors", headers=headers("viewer")).json()["connections"]) == 1
    assert client.get("/v1/endpoint-connectors", headers=headers(tenant="tenant-b")).json()["connections"] == []
    for path in [f"/v1/endpoint-connectors/{id}/devices"]:
        assert client.get(path, headers=headers(tenant="tenant-b")).status_code == 404
        response = client.get(path, headers=headers())
        assert response.status_code == 200 and response.json()["sync"] is None
    assert client.post(f"/v1/endpoint-connectors/{id}/sync", json={}, headers=headers(tenant="tenant-b")).status_code == 404
    changed = client.patch(f"/v1/endpoint-connectors/{id}", json={"client_secret": "rotated", "enabled": False}, headers=headers())
    assert changed.status_code == 200 and changed.json()["enabled"] is False
    assert "rotated" not in changed.text
    assert client.post(f"/v1/endpoint-connectors/{id}/sync", json={}, headers=headers()).status_code == 409


@pytest.mark.parametrize(
    "extra", [{"tenant_id": "tenant-b"}, {"jamf_url": "https://evil.test"}, {"provider": "fake"}, {"client_secret": ""}]
)
def test_validation_never_echoes_credentials(client, extra):
    response = client.post("/v1/endpoint-connectors", json={**BODY, **extra}, headers=headers())
    assert response.status_code == 422
    assert SECRET not in response.text


def test_no_plaintext_fallback_without_encryption(client, monkeypatch):
    monkeypatch.delenv("AGENT_BOM_CONNECTIONS_KEY")
    connection_crypto.reset_key_cache()
    response = client.post("/v1/endpoint-connectors", json=BODY, headers=headers())
    assert response.status_code == 503
    assert client.get("/v1/endpoint-connectors", headers=headers()).json()["connections"] == []


def test_openapi_has_shared_models_and_closed_inputs(client):
    schema = client.get("/openapi.json", headers=headers()).json()
    # Some deployments serve only version-prefixed docs. Inspect the actual app schema instead.
    from agent_bom.api.server import app

    schema = app.openapi()
    assert "/v1/endpoint-connectors/{connection_id}/sync" in schema["paths"]
    assert schema["components"]["schemas"]["ConnectionCreate"]["additionalProperties"] is False


def test_agent_association_requires_both_exact_ids_in_tenant(client, monkeypatch):
    from datetime import datetime, timezone

    import httpx

    from agent_bom.api.fleet_store import FleetAgent, InMemoryFleetStore
    from agent_bom.api.routes.endpoint_connectors import EndpointStore
    from agent_bom.connectors.endpoints import service
    from agent_bom.connectors.endpoints.models import SyncRequest
    from agent_bom.connectors.endpoints.transport import EndpointClient

    fleet = InMemoryFleetStore()
    fleet.put(FleetAgent(agent_id="a", name="Agent", agent_type="custom", tenant_id="tenant-a"))
    fleet.put(FleetAgent(agent_id="b", name="Agent", agent_type="custom", tenant_id="tenant-b"))
    monkeypatch.setattr("agent_bom.api.stores._get_fleet_store", lambda: fleet)
    id = client.post("/v1/endpoint-connectors", json=BODY, headers=headers()).json()["id"]

    def handler(request):
        if request.method == "POST":
            return httpx.Response(200, json={"access_token": "token", "expires_in": 120})
        return httpx.Response(
            200, json={"totalCount": 1, "results": [{"id": "1", "general": {"reportDate": datetime.now(timezone.utc).isoformat()}}]}
        )

    monkeypatch.setattr(
        service, "EndpointClient", lambda conn, secret: EndpointClient(conn, secret, transport=httpx.MockTransport(handler))
    )
    state = service.sync_connection(EndpointStore(), "tenant-a", id, SyncRequest())
    device = EndpointStore().devices("tenant-a", id, state.run_id)[0]
    path = f"/v1/endpoint-connectors/devices/{device.device_id}/agent-binding"
    assert client.put(path, json={"agent_id": "b"}, headers=headers()).status_code == 404
    assert client.put(path, json={"agent_id": "a"}, headers=headers("viewer")).status_code == 403
    result = client.put(path, json={"agent_id": "a"}, headers=headers())
    assert result.status_code == 200 and result.json()["assurance"] == "operator_recorded"
    evidence = client.get(f"/v1/endpoint-connectors/{id}/devices", headers=headers()).json()
    assert evidence["devices"][0]["attributes"]["agent_bindings"][0]["agent_id"] == "a"


@pytest.mark.parametrize(
    "method,path,scope,expected",
    [
        ("GET", "/v1/endpoint-connectors", "connectors:read", 200),
        ("GET", "/v1/endpoint-connectors", "scan:read", 403),
        ("POST", "/v1/endpoint-connectors", "connectors:read", 403),
        ("POST", "/v1/endpoint-connectors/unknown/sync", "connectors:read", 403),
        ("PATCH", "/v1/endpoint-connectors/unknown", "connectors:read", 403),
        ("PUT", "/v1/endpoint-connectors/devices/unknown/agent-binding", "connectors:read", 403),
        ("POST", "/v1/endpoint-connectors", "connectors:write", 201),
    ],
)
def test_scoped_admin_key_enforced_at_http_boundary(client, monkeypatch, method, path, scope, expected):
    from agent_bom.api.auth import KeyStore, Role, create_api_key
    from agent_bom.api.route_policy import required_scope, scope_catalog

    raw, key = create_api_key(name="endpoint-scope-test", role=Role.ADMIN, scopes=[scope], tenant_id="tenant-a")
    store = KeyStore()
    store.add(key)
    monkeypatch.setattr("agent_bom.api.auth.get_key_store", lambda: store)
    monkeypatch.setattr("agent_bom.api.middleware.get_key_store", lambda: store)
    response = client.request(method, path, json=BODY, headers={"Authorization": f"Bearer {raw}"})
    assert response.status_code == expected, response.text
    needed = "connectors:read" if method == "GET" else "connectors:write"
    assert required_scope(method, path) == needed
    assert any(row["scope"] == needed and row["method"] == method for row in scope_catalog())
