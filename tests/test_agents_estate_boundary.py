"""/v1/agents never shows the API host's own AI clients to a tenant by default.

Ambient host discovery reads the API process's configuration (the container's
own venv, the operator's ~/.claude). The scan pipeline already fails closed on it
unless an operator binds the host to one tenant; /v1/agents must honour the same
boundary and otherwise report the tenant's scanned estate, deduplicated by
canonical agent identity exactly like /v1/inventory.
"""

from __future__ import annotations

import uuid

import pytest

pytest.importorskip("fastapi", reason="fastapi not installed")

from fastapi.testclient import TestClient

import agent_bom.api.routes.discovery as discovery
from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.server import app
from agent_bom.api.store import InMemoryJobStore
from agent_bom.api.stores import set_job_store
from agent_bom.models import Agent, AgentType
from tests._clock_helpers import recent

TENANT = "default"


def _agent(name: str, canonical_id: str) -> dict:
    return {
        "name": name,
        "agent_type": "custom",
        "config_path": f"/work/{name}",
        "source": "project",
        "canonical_id": canonical_id,
        "stable_id": canonical_id,
        "mcp_servers": [
            {
                "name": "github",
                "command": "npx",
                "surface": "mcp-server",
                "packages": [{"name": "form-data", "version": "4.0.0", "ecosystem": "npm"}],
                "tools": [{"name": "create_issue"}],
                "credential_env_vars": ["GITHUB_PERSONAL_ACCESS_TOKEN"],
            }
        ],
    }


def _seed(store: InMemoryJobStore, day: int, agents: list[dict], *, tenant: str = TENANT) -> None:
    store.put(
        ScanJob(
            job_id=str(uuid.uuid4()),
            tenant_id=tenant,
            status=JobStatus.DONE,
            created_at=recent(f"2026-07-{day:02d}T00:00:00Z"),
            completed_at=recent(f"2026-07-{day:02d}T00:01:00Z"),
            request=ScanRequest(offline=True),
            result={"agents": agents, "blast_radius": []},
        )
    )


@pytest.fixture()
def estate(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("AGENT_BOM_DEMO_ESTATE", raising=False)
    monkeypatch.delenv("AGENT_BOM_API_HOST_DISCOVERY_TENANT", raising=False)
    monkeypatch.delenv("AGENT_BOM_API_LOCAL_PATH_SCANS", raising=False)
    monkeypatch.delenv("AGENT_BOM_ENABLE_LOCAL_PATH_SCANS", raising=False)
    discovery._agents_response_cache.clear()
    store = InMemoryJobStore()
    set_job_store(store)
    # The same project rescanned twice plus a second project: two agents.
    _seed(store, 1, [_agent("project:sampleapp", "agent-a")])
    _seed(store, 2, [_agent("project:sampleapp", "agent-a"), _agent("project:other", "agent-b")])
    _seed(store, 3, [_agent("project:foreign", "agent-z")], tenant="tenant-b")
    yield store
    discovery._agents_response_cache.clear()


def _host_discovery_forbidden(*_args, **_kwargs):
    pytest.fail("host discovery must not run for a tenant the host is not bound to")


def test_agents_reports_the_scanned_estate_not_the_api_host(estate, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("agent_bom.discovery.discover_all", _host_discovery_forbidden)

    body = TestClient(app).get("/v1/agents").json()

    assert body["scope"] == "scanned_estate"
    assert sorted(agent["name"] for agent in body["agents"]) == ["project:other", "project:sampleapp"]
    assert body["count"] == 2
    assert body["count_by_class"] == {"client": 0, "background": 2}


def test_inventory_counts_each_canonical_agent_once_across_rescans(estate) -> None:
    body = TestClient(app).get("/v1/inventory").json()

    assert body["total"] == 2
    assert sorted(agent["name"] for agent in body["agents"]) == ["project:other", "project:sampleapp"]


def test_agents_and_inventory_agree_on_the_agent_count(estate, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("agent_bom.discovery.discover_all", _host_discovery_forbidden)
    client = TestClient(app)

    assert client.get("/v1/agents").json()["count"] == client.get("/v1/inventory").json()["total"]


def test_agent_detail_resolves_from_the_scanned_estate(estate, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("agent_bom.discovery.discover_all", _host_discovery_forbidden)

    response = TestClient(app).get("/v1/agents/agent-a")

    assert response.status_code == 200
    body = response.json()
    assert body["agent"]["name"] == "project:sampleapp"
    assert body["summary"]["total_servers"] == 1
    assert body["summary"]["total_packages"] == 1
    assert body["summary"]["total_tools"] == 1
    assert body["credentials"] == ["GITHUB_PERSONAL_ACCESS_TOKEN"]
    assert TestClient(app).get("/v1/agents/agent-z").status_code == 404


def test_operator_bound_host_still_gets_live_host_discovery(estate, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_API_LOCAL_PATH_SCANS", "enabled")
    monkeypatch.setenv("AGENT_BOM_API_HOST_DISCOVERY_TENANT", TENANT)
    monkeypatch.setattr(
        "agent_bom.discovery.discover_all",
        lambda: [Agent(name="claude-code", agent_type=AgentType.CLAUDE_CODE, config_path="/home/op/.claude.json")],
    )

    body = TestClient(app).get("/v1/agents").json()

    assert body["scope"] == "local_discovery"
    assert [agent["name"] for agent in body["agents"]] == ["claude-code"]
