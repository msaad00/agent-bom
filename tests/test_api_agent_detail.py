"""Tests for agent detail and lifecycle API endpoints."""

from unittest.mock import patch

import pytest
from starlette.testclient import TestClient

from agent_bom.api import stores as _stores
from agent_bom.api.fleet_store import FleetAgent, FleetLifecycleState, InMemoryFleetStore
from agent_bom.api.mcp_observation_store import InMemoryMCPObservationStore, MCPObservation
from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.server import app
from agent_bom.api.store import InMemoryJobStore
from agent_bom.models import Agent, AgentType, MCPServer, MCPTool, Package, TransportType


def _mock_agents():
    """Return a list with one test agent for mocking discover_all."""
    srv = MCPServer(
        name="test-server",
        command="npx",
        args=["-y", "test-server"],
        env={"API_KEY": "sk-test", "DEBUG": "1"},
        transport=TransportType.SSE,
        url="https://mcp.example.internal/sse",
        packages=[
            Package(name="express", version="4.18.2", ecosystem="npm"),
        ],
        tools=[
            MCPTool(name="read_file", description="Read file contents"),
            MCPTool(name="write_file", description="Write file contents"),
        ],
    )
    return [
        Agent(
            name="test-agent",
            agent_type=AgentType.CLAUDE_DESKTOP,
            config_path="/tmp/test-config.json",
            mcp_servers=[srv],
        ),
    ]


def _mock_fleet_store() -> InMemoryFleetStore:
    store = InMemoryFleetStore()
    store.put(
        FleetAgent(
            agent_id="fleet-1",
            name="test-agent",
            agent_type="claude_desktop",
            config_path="/tmp/test-config.json",
            lifecycle_state=FleetLifecycleState.APPROVED,
            trust_score=87.5,
            tenant_id="default",
            last_discovery="2026-04-22T12:00:00Z",
            last_scan="2026-04-22T12:05:00Z",
            created_at="2026-04-22T12:00:00Z",
            updated_at="2026-04-22T12:05:00Z",
        )
    )
    return store


def _mock_job_store() -> InMemoryJobStore:
    store = InMemoryJobStore()
    job = ScanJob(
        job_id="job-1",
        tenant_id="default",
        status=JobStatus.DONE,
        created_at="2026-04-22T11:58:00Z",
        completed_at="2026-04-22T12:06:00Z",
        request=ScanRequest(),
    )
    job.result = {
        "scan_id": "scan-1",
        "scan_sources": ["fleet_sync", "mcp_config"],
        "agents": [
            {
                "name": "test-agent",
                "servers": [
                    {
                        "name": "test-server",
                        "url": "https://mcp.example.internal/sse",
                        "transport": "sse",
                    }
                ],
            }
        ],
    }
    store.put(job)
    return store


def _mock_observation_store() -> InMemoryMCPObservationStore:
    store = InMemoryMCPObservationStore()
    store.put(
        MCPObservation(
            tenant_id="default",
            observation_id="test-agent:test-server:npx",
            server_stable_id="test-server:npx",
            server_fingerprint="fp-1",
            server_name="test-server",
            agent_name="test-agent",
            transport="sse",
            url="https://mcp.example.internal/sse",
            auth_mode="env-credentials",
            command="npx",
            args=["-y", "test-server"],
            credential_env_vars=["API_KEY"],
            security_blocked=True,
            security_intelligence=[
                {
                    "entry_id": "intel-a",
                    "title": "Persisted intelligence",
                    "confidence": "confirmed_malicious",
                    "default_recommendation": "block",
                    "matched_value": "npx bad --token raw-secret",
                    "references": ["https://example.com/advisory", "javascript:alert(1)"],
                }
            ],
            observed_via=["fleet_sync", "scan_result"],
            observed_scopes=["endpoint", "scan"],
            scan_sources=["fleet_sync"],
            source_agents=["test-agent"],
            configured_locally=False,
            fleet_present=True,
            gateway_registered=True,
            runtime_observed=False,
            first_seen="2026-04-22T11:58:00Z",
            last_seen="2026-04-22T12:01:00Z",
            last_synced="2026-04-22T12:05:00Z",
        )
    )
    return store


def test_merge_observations_preserves_persisted_provenance_contract():
    existing = MCPObservation(
        tenant_id="default",
        observation_id="test-agent:test-server:npx",
        server_stable_id="test-server:npx",
        server_fingerprint="fp-1",
        server_name="test-server",
        agent_name="test-agent",
        observed_via=["fleet_sync", "scan_result"],
        observed_scopes=["endpoint", "scan"],
        scan_sources=["fleet_sync"],
        source_agents=["test-agent"],
        configured_locally=False,
        fleet_present=True,
        gateway_registered=True,
        first_seen="2026-04-22T11:58:00Z",
        last_seen="2026-04-22T12:01:00Z",
        last_synced="2026-04-22T12:05:00Z",
    )
    incoming = MCPObservation(
        tenant_id="default",
        observation_id="test-agent:test-server:npx",
        server_stable_id="test-server:npx",
        server_fingerprint="fp-1",
        server_name="test-server",
        agent_name="test-agent",
        observed_via=["local_discovery"],
        observed_scopes=["endpoint"],
        scan_sources=["mcp_config"],
        source_agents=[],
        configured_locally=True,
        fleet_present=False,
        gateway_registered=False,
        first_seen=None,
        last_seen="2026-04-22T12:00:00Z",
        last_synced=None,
    )
    from agent_bom.api.mcp_observation_store import merge_observations

    merged = merge_observations(existing, incoming)
    assert merged.configured_locally is False
    assert merged.fleet_present is True
    assert merged.gateway_registered is True
    assert merged.observed_via == ["fleet_sync", "local_discovery", "scan_result"]
    assert merged.scan_sources == ["fleet_sync", "mcp_config"]
    assert merged.first_seen == "2026-04-22T11:58:00Z"
    assert merged.last_seen == "2026-04-22T12:01:00Z"
    assert merged.last_synced == "2026-04-22T12:05:00Z"


def test_merge_observations_rejects_tenant_mismatch():
    existing = MCPObservation(
        tenant_id="tenant-alpha",
        observation_id="test-agent:test-server:npx",
        server_stable_id="test-server:npx",
        server_name="test-server",
    )
    incoming = MCPObservation(
        tenant_id="tenant-beta",
        observation_id="test-agent:test-server:npx",
        server_stable_id="test-server:npx",
        server_name="test-server",
    )
    from agent_bom.api.mcp_observation_store import merge_observations

    with pytest.raises(ValueError, match="tenant mismatch"):
        merge_observations(existing, incoming)


@patch("agent_bom.discovery.discover_all", side_effect=_mock_agents)
@patch("agent_bom.api.routes.discovery._get_fleet_store", side_effect=_mock_fleet_store)
def test_agent_detail_found(_fleet, _mock):
    """GET /v1/agents/{name} returns 200 with agent detail."""
    client = TestClient(app)
    resp = client.get("/v1/agents/test-agent")
    assert resp.status_code == 200
    data = resp.json()
    assert data["agent"]["name"] == "test-agent"
    assert data["summary"]["total_servers"] == 1
    assert data["summary"]["total_tools"] == 2
    assert data["summary"]["total_credentials"] >= 1
    assert "blast_radius" in data
    assert "credentials" in data
    assert data["fleet"]["lifecycle_state"] == "approved"
    assert data["fleet"]["trust_score"] == 87.5


@patch("agent_bom.discovery.discover_all", return_value=[])
def test_agent_detail_not_found(_mock):
    """GET /v1/agents/{name} returns 404 for unknown agent."""
    client = TestClient(app)
    resp = client.get("/v1/agents/nonexistent-agent")
    assert resp.status_code == 404


@patch("agent_bom.discovery.discover_all", side_effect=_mock_agents)
def test_agent_lifecycle_nodes_edges(_mock):
    """GET /v1/agents/{name}/lifecycle returns React Flow graph structure."""
    client = TestClient(app)
    resp = client.get("/v1/agents/test-agent/lifecycle")
    assert resp.status_code == 200
    data = resp.json()
    assert "nodes" in data
    assert "edges" in data
    assert "stats" in data
    # Should have at least: agent + server + 2 tools + 1 credential + 1 package = 6 nodes
    assert len(data["nodes"]) >= 5
    assert len(data["edges"]) >= 4
    # Check node types
    node_types = {n["data"]["nodeType"] for n in data["nodes"]}
    assert "agent" in node_types
    assert "server" in node_types
    assert "tool" in node_types
    assert "package" in node_types


@patch("agent_bom.discovery.discover_all", return_value=[])
def test_agent_lifecycle_not_found(_mock):
    """GET /v1/agents/{name}/lifecycle returns 404 for unknown agent."""
    client = TestClient(app)
    resp = client.get("/v1/agents/nonexistent-agent/lifecycle")
    assert resp.status_code == 404


@patch("agent_bom.discovery.discover_all", side_effect=_mock_agents)
def test_agent_detail_credential_detection(_mock):
    """Agent detail correctly identifies credential env vars."""
    client = TestClient(app)
    resp = client.get("/v1/agents/test-agent")
    data = resp.json()
    # API_KEY should be detected as credential, DEBUG should not
    assert "API_KEY" in data["credentials"]
    assert "DEBUG" not in data["credentials"]
    server = data["agent"]["mcp_servers"][0]
    assert server["command"] == "npx"
    assert server["auth_mode"] == "env-credentials"


@patch("agent_bom.discovery.discover_all", side_effect=_mock_agents)
@patch("agent_bom.api.routes.discovery._get_fleet_store", side_effect=_mock_fleet_store)
def test_agent_detail_exposes_server_provenance(_fleet, _mock):
    prev_store = _stores._store
    prev_observation_store = getattr(_stores, "_mcp_observation_store", None)
    _stores._store = _mock_job_store()
    _stores._mcp_observation_store = _mock_observation_store()
    try:
        client = TestClient(app)
        resp = client.get("/v1/agents/test-agent")
        assert resp.status_code == 200
        server = resp.json()["agent"]["mcp_servers"][0]
        assert server["security_blocked"] is True
        assert server["security_intelligence"][0]["entry_id"] == "intel-a"
        assert "raw-secret" not in server["security_intelligence"][0]["matched_value"]
        assert server["security_intelligence"][0]["references"] == ["https://example.com/advisory"]
        provenance = server["provenance"]
        assert provenance["configured_locally"] is False
        assert provenance["fleet_present"] is True
        assert provenance["gateway_registered"] is True
        assert provenance["runtime_observed"] is False
        assert provenance["source_agents"] == ["test-agent"]
        assert provenance["scan_sources"] == ["fleet_sync", "mcp_config"]
        assert "local_discovery" in provenance["observed_via"]
        assert "scan_result" in provenance["observed_via"]
        assert "fleet_sync" in provenance["observed_via"]
        assert "gateway_discovery" in provenance["observed_via"]
        assert provenance["first_seen"] == "2026-04-22T11:58:00Z"
        assert provenance["last_seen"] == "2026-04-22T12:01:00Z"
        assert provenance["last_synced"] == "2026-04-22T12:05:00Z"
    finally:
        _stores._store = prev_store
        _stores._mcp_observation_store = prev_observation_store


@patch("agent_bom.discovery.discover_all", side_effect=_mock_agents)
def test_agent_lifecycle_edge_structure(_mock):
    """Lifecycle edges have correct source/target and styling."""
    client = TestClient(app)
    resp = client.get("/v1/agents/test-agent/lifecycle")
    data = resp.json()
    # All edges should have required fields
    for edge in data["edges"]:
        assert "id" in edge
        assert "source" in edge
        assert "target" in edge
        assert "type" in edge
        assert edge["type"] == "smoothstep"
