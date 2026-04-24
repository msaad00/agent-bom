"""Tests for fleet API endpoints (/v1/fleet/*)."""

from datetime import datetime, timezone
from unittest.mock import patch

from starlette.testclient import TestClient

from agent_bom.api import tenant_quota as tenant_quota_module
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
    store.put(_make(agent_id="a-1", trust_score=10.0))
    store.put(_make(agent_id="a-2", trust_score=90.0))
    resp = client.get("/v1/fleet?min_trust=50")
    data = resp.json()
    assert data["count"] == 1, f"Expected 1 agent with trust >= 50, got {data['count']}: {[a.get('trust_score') for a in data['agents']]}"
    assert data["agents"][0]["agent_id"] == "a-2"


def test_list_uses_server_side_search_and_pagination():
    client, store = _fresh_client()
    for idx in range(12):
        store.put(
            _make(
                agent_id=f"a-{idx:02d}",
                name=f"agent-{idx:02d}",
                owner="platform" if idx % 2 == 0 else "security",
                environment="prod" if idx % 3 == 0 else "dev",
                tags=["critical"] if idx == 10 else [],
            )
        )

    resp = client.get("/v1/fleet?search=platform&limit=3&offset=3")
    data = resp.json()

    assert resp.status_code == 200
    assert data["count"] == 3
    assert data["total"] == 6
    assert data["limit"] == 3
    assert data["offset"] == 3
    assert data["has_more"] is False
    assert [agent["name"] for agent in data["agents"]] == ["agent-06", "agent-08", "agent-10"]


def test_list_falls_back_for_legacy_fleet_store_without_query_api():
    import agent_bom.api.stores as api_stores

    class LegacyFleetStore:
        def __init__(self) -> None:
            self.agents = [
                _make(agent_id="a-1", name="agent-01", owner="platform", environment="prod"),
                _make(agent_id="a-2", name="agent-02", owner="security", environment="prod"),
                _make(agent_id="a-3", name="agent-03", owner="platform", environment="dev"),
                _make(agent_id="a-4", name="agent-04", owner="platform", environment="prod"),
            ]

        def list_by_tenant(self, tenant_id: str):
            return [agent for agent in self.agents if agent.tenant_id == tenant_id]

    store = LegacyFleetStore()
    original = api_stores._fleet_store
    try:
        set_fleet_store(store)
        client = TestClient(app)

        resp = client.get("/v1/fleet?search=platform&limit=2&offset=1")
        data = resp.json()

        assert resp.status_code == 200
        assert data["count"] == 2
        assert data["total"] == 3
        assert data["has_more"] is False
        assert [agent["agent_id"] for agent in data["agents"]] == ["a-3", "a-4"]
    finally:
        set_fleet_store(original)


def test_list_explicit_quarantined_state_is_not_hidden_by_default_exclusion():
    client, store = _fresh_client()
    store.put(_make(agent_id="a-1", state=FleetLifecycleState.QUARANTINED))
    store.put(_make(agent_id="a-2", state=FleetLifecycleState.APPROVED))

    all_resp = client.get("/v1/fleet")
    quarantined_resp = client.get("/v1/fleet?state=quarantined")

    assert all_resp.json()["total"] == 1
    assert quarantined_resp.json()["total"] == 1
    assert quarantined_resp.json()["agents"][0]["lifecycle_state"] == "quarantined"


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


def test_get_agent_passes_tenant_to_store():
    import agent_bom.api.stores as api_stores

    class RecordingFleetStore:
        def __init__(self) -> None:
            self.calls: list[tuple[str, str | None]] = []

        def get(self, agent_id: str, tenant_id: str | None = None):
            self.calls.append((agent_id, tenant_id))
            return _make(agent_id=agent_id, name="alpha", tenant_id=tenant_id or "default")

        def list_by_tenant(self, tenant_id: str):
            return []

    store = RecordingFleetStore()
    original = api_stores._fleet_store
    try:
        set_fleet_store(store)
        client = TestClient(app)

        resp = client.get("/v1/fleet/a-tenant-check")

        assert resp.status_code == 200
        assert store.calls == [("a-tenant-check", "default")]
    finally:
        set_fleet_store(original)


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


def test_sync_accepts_endpoint_push_payload():
    client, store = _fresh_client()
    resp = client.post(
        "/v1/fleet/sync",
        json={
            "source_id": "laptop-a",
            "agents": [
                {
                    "name": "cursor",
                    "agent_type": "cursor",
                    "trust_score": 82.5,
                    "trust_factors": {"registry": 20},
                    "mcp_servers": [
                        {
                            "name": "filesystem",
                            "packages": [{"name": "express", "version": "4.18.2"}],
                            "credential_names": ["OPENAI_API_KEY"],
                            "total_vulnerabilities": 2,
                        }
                    ],
                }
            ],
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["source_id"] == "laptop-a"
    assert data["new"] == 1
    agents = store.list_all()
    assert len(agents) == 1
    assert agents[0].name == "cursor"
    assert agents[0].server_count == 1
    assert agents[0].package_count == 1
    assert agents[0].credential_count == 1
    assert agents[0].vuln_count == 2


def test_sync_persists_endpoint_identity_metadata():
    client, store = _fresh_client()
    resp = client.post(
        "/v1/fleet/sync",
        json={
            "source_id": "device-acme-001",
            "agents": [
                {
                    "name": "cursor",
                    "agent_type": "cursor",
                    "source_id": "device-acme-001",
                    "enrollment_name": "corp-laptop-rollout",
                    "owner": "platform-security",
                    "environment": "production",
                    "tags": ["developer-endpoint", "mdm"],
                    "mdm_provider": "jamf",
                    "trust_score": 82.5,
                    "mcp_servers": [],
                }
            ],
        },
    )
    assert resp.status_code == 200
    agent = store.list_all()[0]
    assert agent.source_id == "device-acme-001"
    assert agent.enrollment_name == "corp-laptop-rollout"
    assert agent.owner == "platform-security"
    assert agent.environment == "production"
    assert agent.tags == ["developer-endpoint", "mdm"]
    assert agent.mdm_provider == "jamf"


def test_sync_endpoint_push_is_idempotent():
    client, store = _fresh_client()
    payload = {
        "source_id": "laptop-a",
        "idempotency_key": "fleet-sync-1",
        "agents": [
            {
                "name": "cursor",
                "agent_type": "cursor",
                "trust_score": 82.5,
                "mcp_servers": [],
            }
        ],
    }
    first = client.post("/v1/fleet/sync", json=payload)
    second = client.post("/v1/fleet/sync", json=payload)
    assert first.status_code == 200
    assert second.status_code == 200
    assert second.json()["idempotent_replay"] is True
    assert len(store.list_all()) == 1


def test_sync_endpoint_push_enforces_fleet_quota(monkeypatch):
    client, store = _fresh_client()
    store.put(_make(agent_id="a-1", name="existing"))
    monkeypatch.setattr(tenant_quota_module, "API_MAX_FLEET_AGENTS_PER_TENANT", 1)

    resp = client.post(
        "/v1/fleet/sync",
        json={
            "source_id": "laptop-a",
            "agents": [
                {
                    "name": "cursor",
                    "agent_type": "cursor",
                    "trust_score": 82.5,
                    "mcp_servers": [],
                }
            ],
        },
    )
    assert resp.status_code == 429
    assert "fleet_agents" in resp.json()["detail"]
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
