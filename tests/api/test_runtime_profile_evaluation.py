"""Operator profile previews must use the same fail-closed resolver as relay."""

import pytest
from starlette.testclient import TestClient

from agent_bom.api.agent_identity_store import InMemoryAgentIdentityStore, set_agent_identity_store
from agent_bom.api.mcp_config_store import InMemoryMcpConfigStore, set_mcp_config_store
from agent_bom.api.server import app, configure_api
from tests.test_runtime_profile_resolution import _assignment, _identity

URL = "/v1/runtime/profiles/evaluate"
SECRET = "runtime-profile-preview-secret-at-least-32-bytes"
HEADERS = {"X-Agent-Bom-Role": "viewer", "X-Agent-Bom-Tenant-ID": "tenant-a", "X-Agent-Bom-Proxy-Secret": SECRET}
CONTEXT = {"config_id": "client-profile-finance-prod", "issuer": "agent-bom", "environment": "prod", "granted_scopes": ["tools:read"]}


@pytest.fixture(autouse=True)
def stores(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH", "1")
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH_SECRET", SECRET)
    configure_api(api_key=None)
    identities = InMemoryAgentIdentityStore()
    identities.put(_identity())
    profiles = InMemoryMcpConfigStore()
    profiles.put(_assignment())
    set_agent_identity_store(identities)
    set_mcp_config_store(profiles)
    yield profiles, identities
    set_agent_identity_store(None)
    set_mcp_config_store(None)
    configure_api(api_key=None)


def test_profile_preview_is_metadata_only_and_not_a_gateway_authorization():
    response = TestClient(app).post(URL, headers=HEADERS, json={**CONTEXT, "upstream": "filesystem", "tool": "read_file"})
    assert response.status_code == 200
    body = response.json()
    assert body["profile_allowed"] is True
    assert body["executed"] is False
    assert body["scope"] == "profile_contract_only"
    assert body["profile"]["client_profile_id"] == "client-profile-finance-prod"
    assert body["profile"]["blueprint_id"] == "finance"
    assert "token_hash" not in response.text
    assert "must-never-leave" not in response.text


@pytest.mark.parametrize(
    "context,reason",
    [
        ({"environment": "dev"}, "environment_mismatch"),
        ({"issuer": "foreign"}, "issuer_mismatch"),
        ({"granted_scopes": []}, "insufficient_scope"),
        ({"upstream": "other", "tool": "read_file"}, "upstream_not_allowed"),
        ({"upstream": "filesystem", "tool": "delete_all"}, "tool_not_allowed"),
    ],
)
def test_profile_preview_denies_scope_and_binding_mismatches(context, reason):
    response = TestClient(app).post(URL, headers=HEADERS, json={**CONTEXT, **context})
    assert response.status_code == 200
    assert response.json()["profile_allowed"] is False
    assert response.json()["reason_code"] == reason


def test_revoked_profile_cannot_preview_a_replacement_assignment(stores):
    profiles, _ = stores
    profiles.revoke("tenant-a", "client-profile-finance-prod")
    profiles.put(_assignment(config_id="replacement", revision=1))
    response = TestClient(app).post(URL, headers=HEADERS, json=CONTEXT)
    assert response.status_code == 200
    assert response.json()["profile_allowed"] is False
    assert response.json()["profile"] is None


def test_cross_tenant_and_anonymous_previews_are_denied(monkeypatch):
    client = TestClient(app)
    assert client.post(URL, headers={**HEADERS, "X-Agent-Bom-Tenant-ID": "tenant-b"}, json=CONTEXT).status_code == 404
    monkeypatch.delenv("AGENT_BOM_TRUST_PROXY_AUTH")
    monkeypatch.delenv("AGENT_BOM_TRUST_PROXY_AUTH_SECRET")
    assert client.post(URL, json=CONTEXT).status_code == 401


def test_profile_preview_store_outage_is_sanitized(stores, monkeypatch):
    _, identities = stores

    def fail(*args, **kwargs):
        raise RuntimeError("postgres://secret@private-db")

    monkeypatch.setattr(identities, "get", fail)
    response = TestClient(app).post(URL, headers=HEADERS, json=CONTEXT)
    assert response.status_code == 503
    assert "secret" not in response.text


def test_profile_preview_rejects_raw_arguments_and_incomplete_tool_target():
    client = TestClient(app)
    assert client.post(URL, headers=HEADERS, json={**CONTEXT, "arguments": {"password": "secret"}}).status_code == 422
    assert client.post(URL, headers=HEADERS, json={**CONTEXT, "tool": "read_file"}).status_code == 422
