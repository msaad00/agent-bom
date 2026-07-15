"""Served, governed MCP-client-config distribution (#3908)."""

from __future__ import annotations

import json

import pytest
from starlette.testclient import TestClient

from agent_bom.api.mcp_config_store import (
    InMemoryMcpConfigStore,
    build_served_mcp_config,
    create_assignment,
    set_mcp_config_store,
)


@pytest.fixture()
def store():
    s = InMemoryMcpConfigStore()
    set_mcp_config_store(s)
    try:
        yield s
    finally:
        set_mcp_config_store(None)


@pytest.fixture()
def client(store):
    from agent_bom.api.server import app

    return TestClient(app)


def _first_connector_id(client) -> str:
    servers = client.get("/v1/registry").json()["servers"]
    assert servers, "registry should not be empty"
    return servers[0]["id"]


# ── Composition: reference-only, no secrets ──────────────────────────────────────


def test_build_served_config_has_no_secret_values():
    registry = [
        {
            "id": "modelcontextprotocol/github",
            "name": "GitHub",
            "transport": "stdio",
            "publisher": "modelcontextprotocol",
            "credential_env_vars": ["GITHUB_TOKEN"],
            "packages": [{"name": "server-github", "ecosystem": "npm"}],
        }
    ]
    assignment = create_assignment(
        InMemoryMcpConfigStore(),
        tenant_id="t1",
        name="dev-config",
        profile_id="developer",
        connector_ids=["modelcontextprotocol/github"],
    )
    doc = build_served_mcp_config(
        assignment,
        registry=registry,
        profile={"blueprint_id": "developer"},
        connections=[{"id": "conn-1", "provider": "aws", "display_name": "prod", "has_external_id": True}],
    )
    server = doc["mcpServers"]["GitHub"]
    # Credential is a reference placeholder, never a value.
    assert server["env"]["GITHUB_TOKEN"]["value"] == "${GITHUB_TOKEN}"
    assert server["env"]["GITHUB_TOKEN"]["source"] == "reference"
    # Connection referenced by handle + presence flag only.
    assert doc["connections"][0]["has_secret"] is True
    assert doc["connections"][0]["handle"] == "connection:conn-1"
    # Airtight: the serialized doc contains no obvious secret material.
    blob = json.dumps(doc)
    assert "external_id" not in blob
    assert "role_ref" not in blob
    assert doc["read_only"] is True


# ── API: assign → serve → tenant isolation ───────────────────────────────────────


def test_assign_profile_yields_read_only_config_url(client):
    connector_id = _first_connector_id(client)
    resp = client.post(
        "/v1/mcp-config/assignments",
        json={"name": "sec-analyst", "profile_id": "security_analyst", "connector_ids": [connector_id]},
    )
    assert resp.status_code == 201, resp.text
    config_url = resp.json()["config_url"]
    assert config_url.endswith("/mcp.json")

    served = client.get(config_url)
    assert served.status_code == 200, served.text
    doc = served.json()
    assert doc["read_only"] is True
    assert doc["profile"]["blueprint_id"] == "security_analyst"
    assert list(doc["mcpServers"].keys()), "served config should list the selected connector"
    # No secret material in the served document.
    assert "external_id_encrypted" not in json.dumps(doc)


def test_serve_rejects_unknown_profile(client):
    connector_id = _first_connector_id(client)
    resp = client.post(
        "/v1/mcp-config/assignments",
        json={"name": "x", "profile_id": "not-a-profile", "connector_ids": [connector_id]},
    )
    assert resp.status_code == 400


def test_serve_rejects_unknown_connector(client):
    resp = client.post(
        "/v1/mcp-config/assignments",
        json={"name": "x", "profile_id": "developer", "connector_ids": ["totally/unknown-server"]},
    )
    assert resp.status_code == 400


def test_revoked_config_404s(client):
    connector_id = _first_connector_id(client)
    created = client.post(
        "/v1/mcp-config/assignments",
        json={"name": "x", "profile_id": "developer", "connector_ids": [connector_id]},
    ).json()
    config_id = created["assignment"]["config_id"]
    assert client.get(created["config_url"]).status_code == 200
    assert client.post(f"/v1/mcp-config/assignments/{config_id}/revoke").status_code == 200
    assert client.get(created["config_url"]).status_code == 404


def test_cross_tenant_access_denied(store):
    # The tenant boundary is enforced at the store: a fetch scoped to a
    # different tenant is a miss (Postgres additionally enforces this with RLS).
    assignment = create_assignment(
        store,
        tenant_id="tenant-a",
        name="a-config",
        profile_id="developer",
        connector_ids=["modelcontextprotocol/github"],
    )
    assert store.get("tenant-a", assignment.config_id) is not None
    assert store.get("tenant-b", assignment.config_id) is None


def test_served_config_route_is_tenant_scoped(client, store):
    # An assignment stored under a foreign tenant is not served to the request's
    # (default) tenant — the serve route calls store.get(tenant_id, config_id).
    foreign = create_assignment(
        store,
        tenant_id="some-other-tenant",
        name="foreign",
        profile_id="developer",
        connector_ids=["modelcontextprotocol/github"],
    )
    assert client.get(f"/v1/mcp-config/{foreign.config_id}/mcp.json").status_code == 404
