"""Reading /v1/agents never writes tenant state and never leaks host agents.

A GET is a read: it must not persist MCP observations into the caller's tenant.
Live discovery of the API host (or the curated demo inventory standing in for
it) is served only to the tenant the operator bound it to; every other tenant
gets its own scanned estate.
"""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi", reason="fastapi not installed")

from fastapi.testclient import TestClient

import agent_bom.api.routes.discovery as discovery
from agent_bom.api.mcp_observation_store import InMemoryMCPObservationStore
from agent_bom.api.server import app
from agent_bom.api.store import InMemoryJobStore
from agent_bom.api.stores import set_job_store
from agent_bom.models import Agent, AgentType, MCPServer
from tests._host_discovery import host_bound_to
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers


@pytest.fixture()
def observations(monkeypatch: pytest.MonkeyPatch):
    for name in (
        "AGENT_BOM_DEMO_ESTATE",
        "AGENT_BOM_API_HOST_DISCOVERY_TENANT",
        "AGENT_BOM_API_LOCAL_PATH_SCANS",
        "AGENT_BOM_ENABLE_LOCAL_PATH_SCANS",
    ):
        monkeypatch.delenv(name, raising=False)
    discovery._clear_agents_response_cache_for_tests()
    set_job_store(InMemoryJobStore())
    store = InMemoryMCPObservationStore()
    monkeypatch.setattr(discovery, "_get_mcp_observation_store", lambda: store)
    enable_trusted_proxy_env()
    yield store
    disable_trusted_proxy_env()
    discovery._clear_agents_response_cache_for_tests()


def _host_agent() -> Agent:
    return Agent(
        name="claude-code",
        agent_type=AgentType.CLAUDE_CODE,
        config_path="/home/op/.claude.json",
        mcp_servers=[MCPServer(name="github", command="npx", args=["-y", "@modelcontextprotocol/server-github"])],
    )


def _all_rows(store: InMemoryMCPObservationStore, *tenants: str) -> list:
    return [row for tenant in tenants for row in store.list_by_tenant(tenant)]


def test_demo_inventory_is_not_served_to_or_written_into_another_tenant(observations, monkeypatch) -> None:
    monkeypatch.setenv("AGENT_BOM_DEMO_ESTATE", "1")
    monkeypatch.setattr("agent_bom.discovery.discover_all", lambda: pytest.fail("host discovery must not run"))
    client = TestClient(app)

    response = client.get("/v1/agents", headers=proxy_headers(role="viewer", tenant="tenant-b"))

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["scope"] == "scanned_estate"
    assert body["agents"] == []
    assert observations.list_by_tenant("tenant-b") == []


def test_unbound_tenant_gets_no_host_agents_and_no_rows(observations, monkeypatch) -> None:
    for key, value in host_bound_to("tenant-a").items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr("agent_bom.discovery.discover_all", lambda: [_host_agent()])
    client = TestClient(app)

    response = client.get("/v1/agents", headers=proxy_headers(role="viewer", tenant="tenant-b"))

    assert response.status_code == 200, response.text
    assert response.json()["scope"] == "scanned_estate"
    assert response.json()["agents"] == []
    assert _all_rows(observations, "tenant-a", "tenant-b") == []


@pytest.mark.parametrize("path", ["/v1/agents?refresh=true", "/v1/agents/mesh", "/v1/agents/claude-code"])
def test_bound_tenant_reads_host_discovery_without_persisting(observations, monkeypatch, path: str) -> None:
    for key, value in host_bound_to("tenant-a").items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr("agent_bom.discovery.discover_all", lambda: [_host_agent()])
    client = TestClient(app)

    response = client.get(path, headers=proxy_headers(role="viewer", tenant="tenant-a"))

    assert response.status_code == 200, response.text
    assert _all_rows(observations, "tenant-a", "tenant-b") == []


def test_bound_tenant_still_sees_local_discovery_provenance(observations, monkeypatch) -> None:
    for key, value in host_bound_to("tenant-a").items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr("agent_bom.discovery.discover_all", lambda: [_host_agent()])

    body = TestClient(app).get("/v1/agents", headers=proxy_headers(role="viewer", tenant="tenant-a")).json()

    assert body["scope"] == "local_discovery"
    assert [agent["name"] for agent in body["agents"]] == ["claude-code"]
    provenance = body["agents"][0]["mcp_servers"][0]["provenance"]
    assert provenance["observed_via"] == ["local_discovery"]
    assert provenance["configured_locally"] is True
