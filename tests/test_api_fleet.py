"""Tests for fleet API endpoints (/v1/fleet/*)."""

from datetime import datetime, timezone
from unittest.mock import patch

from starlette.testclient import TestClient

from agent_bom.api.fleet_store import (
    FleetAgent,
    FleetLifecycleState,
    InMemoryFleetStore,
)
from agent_bom.api.server import app, set_fleet_store
from agent_bom.models import Agent, AgentType, MCPServer, MCPTool, Package


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _make(
    agent_id: str = "a-1",
    name: str = "test-agent",
    state: FleetLifecycleState = FleetLifecycleState.DISCOVERED,
    trust_score: float = 75.0,
    **kw,
) -> FleetAgent:
    ts = _now()
    return FleetAgent(
        agent_id=agent_id,
        name=name,
        agent_type="claude-desktop",
        lifecycle_state=state,
        trust_score=trust_score,
        created_at=ts,
        updated_at=ts,
        **kw,
    )


def _fresh_client() -> tuple[TestClient, InMemoryFleetStore]:
    store = InMemoryFleetStore()
    set_fleet_store(store)
    return TestClient(app), store


def _mock_agents():
    srv = MCPServer(
        name="test-server",
        command="npx",
        args=["-y", "test-server"],
        env={"API_KEY": "sk-test"},
        packages=[Package(name="express", version="4.18.2", ecosystem="npm")],
        tools=[MCPTool(name="read_file", description="Read")],
        registry_verified=True,
    )
    return [
        Agent(
            name="agent-alpha",
            agent_type=AgentType.CLAUDE_DESKTOP,
            config_path="/tmp/alpha.json",
            mcp_servers=[srv],
            version="1.0",
        ),
    ]


# ── List ──────────────────────────────────────────────────────────────────────


def test_list_empty():
    client, _ = _fresh_client()
    resp = client.get("/v1/fleet")
    assert resp.status_code == 200
    data = resp.json()
    assert data["agents"] == []
    assert data["count"] == 0


def test_list_with_agents():
    client, store = _fresh_client()
    store.put(_make(agent_id="a-1", name="one"))
    store.put(_make(agent_id="a-2", name="two"))
    resp = client.get("/v1/fleet")
    assert resp.json()["count"] == 2


def test_list_filter_state():
    client, store = _fresh_client()
    store.put(_make(agent_id="a-1", state=FleetLifecycleState.APPROVED))
    store.put(_make(agent_id="a-2", state=FleetLifecycleState.QUARANTINED))
    resp = client.get("/v1/fleet?state=approved")
    assert resp.json()["count"] == 1
    assert resp.json()["agents"][0]["lifecycle_state"] == "approved"


def test_list_filter_min_trust():
    client, store = _fresh_client()
    store.put(_make(agent_id="a-1", trust_score=30.0))
    store.put(_make(agent_id="a-2", trust_score=80.0))
    resp = client.get("/v1/fleet?min_trust=50")
    assert resp.json()["count"] == 1


# ── Get ───────────────────────────────────────────────────────────────────────


def test_get_agent():
    client, store = _fresh_client()
    store.put(_make(agent_id="a-1", name="alpha"))
    resp = client.get("/v1/fleet/a-1")
    assert resp.status_code == 200
    assert resp.json()["name"] == "alpha"


def test_get_agent_not_found():
    client, _ = _fresh_client()
    resp = client.get("/v1/fleet/missing")
    assert resp.status_code == 404


# ── Sync ──────────────────────────────────────────────────────────────────────


@patch("agent_bom.discovery.discover_all", side_effect=_mock_agents)
def test_sync_creates_agents(_mock):
    client, store = _fresh_client()
    resp = client.post("/v1/fleet/sync")
    assert resp.status_code == 200
    data = resp.json()
    assert data["synced"] == 1
    assert data["new"] == 1
    assert data["updated"] == 0
    agents = store.list_all()
    assert len(agents) == 1
    assert agents[0].name == "agent-alpha"
    assert agents[0].trust_score > 0


@patch("agent_bom.discovery.discover_all", side_effect=_mock_agents)
def test_sync_updates_existing(_mock):
    client, store = _fresh_client()
    # First sync creates
    client.post("/v1/fleet/sync")
    # Second sync updates
    resp = client.post("/v1/fleet/sync")
    data = resp.json()
    assert data["new"] == 0
    assert data["updated"] == 1
    assert len(store.list_all()) == 1


# ── State update ──────────────────────────────────────────────────────────────


def test_update_state():
    client, store = _fresh_client()
    store.put(_make(agent_id="a-1"))
    resp = client.put("/v1/fleet/a-1/state", json={"state": "approved"})
    assert resp.status_code == 200
    assert resp.json()["lifecycle_state"] == "approved"
    assert store.get("a-1").lifecycle_state == FleetLifecycleState.APPROVED


def test_update_state_invalid():
    client, store = _fresh_client()
    store.put(_make(agent_id="a-1"))
    resp = client.put("/v1/fleet/a-1/state", json={"state": "bogus"})
    assert resp.status_code == 400


def test_update_state_not_found():
    client, _ = _fresh_client()
    resp = client.put("/v1/fleet/missing/state", json={"state": "approved"})
    assert resp.status_code == 404


# ── Metadata update ──────────────────────────────────────────────────────────


def test_update_metadata():
    client, store = _fresh_client()
    store.put(_make(agent_id="a-1"))
    resp = client.put(
        "/v1/fleet/a-1",
        json={"owner": "alice", "environment": "production", "tags": ["critical"]},
    )
    assert resp.status_code == 200
    agent = store.get("a-1")
    assert agent.owner == "alice"
    assert agent.environment == "production"
    assert agent.tags == ["critical"]


def test_update_metadata_not_found():
    client, _ = _fresh_client()
    resp = client.put("/v1/fleet/missing", json={"owner": "bob"})
    assert resp.status_code == 404


# ── Stats ─────────────────────────────────────────────────────────────────────


def test_stats_empty():
    client, _ = _fresh_client()
    resp = client.get("/v1/fleet/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 0
    assert data["avg_trust_score"] == 0.0


def test_stats_populated():
    client, store = _fresh_client()
    store.put(_make(agent_id="a-1", state=FleetLifecycleState.APPROVED, trust_score=90.0))
    store.put(_make(agent_id="a-2", state=FleetLifecycleState.APPROVED, trust_score=40.0))
    store.put(_make(agent_id="a-3", state=FleetLifecycleState.QUARANTINED, trust_score=20.0))
    resp = client.get("/v1/fleet/stats")
    data = resp.json()
    assert data["total"] == 3
    assert data["by_state"]["approved"] == 2
    assert data["by_state"]["quarantined"] == 1
    assert data["low_trust_count"] == 2  # 40 and 20 are < 50
    assert data["avg_trust_score"] == 50.0
