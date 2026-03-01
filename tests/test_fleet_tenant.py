"""Tests for multi-tenant fleet management."""

import os
import tempfile

import pytest

from agent_bom.api.fleet_store import (
    FleetAgent,
    FleetLifecycleState,
    InMemoryFleetStore,
    SQLiteFleetStore,
)


def _make_agent(agent_id: str, name: str, tenant_id: str = "default") -> FleetAgent:
    return FleetAgent(
        agent_id=agent_id,
        name=name,
        agent_type="claude_desktop",
        tenant_id=tenant_id,
        lifecycle_state=FleetLifecycleState.DISCOVERED,
        updated_at="2026-01-01T00:00:00Z",
        created_at="2026-01-01T00:00:00Z",
    )


# ─── FleetAgent tenant_id ────────────────────────────────────────────────────


def test_fleet_agent_default_tenant():
    agent = FleetAgent(agent_id="a1", name="test", agent_type="cursor", updated_at="2026-01-01T00:00:00Z")
    assert agent.tenant_id == "default"


def test_fleet_agent_custom_tenant():
    agent = _make_agent("a1", "test", tenant_id="team-security")
    assert agent.tenant_id == "team-security"


def test_fleet_agent_tenant_serialization():
    agent = _make_agent("a1", "test", tenant_id="team-a")
    data = agent.model_dump_json()
    restored = FleetAgent.model_validate_json(data)
    assert restored.tenant_id == "team-a"


# ─── InMemoryFleetStore ──────────────────────────────────────────────────────


def test_in_memory_list_by_tenant():
    store = InMemoryFleetStore()
    store.put(_make_agent("a1", "agent1", "team-a"))
    store.put(_make_agent("a2", "agent2", "team-b"))
    store.put(_make_agent("a3", "agent3", "team-a"))

    team_a = store.list_by_tenant("team-a")
    assert len(team_a) == 2
    assert all(a.tenant_id == "team-a" for a in team_a)


def test_in_memory_list_by_tenant_empty():
    store = InMemoryFleetStore()
    store.put(_make_agent("a1", "agent1", "team-a"))
    assert store.list_by_tenant("team-b") == []


def test_in_memory_list_tenants():
    store = InMemoryFleetStore()
    store.put(_make_agent("a1", "agent1", "team-a"))
    store.put(_make_agent("a2", "agent2", "team-b"))
    store.put(_make_agent("a3", "agent3", "team-a"))

    tenants = store.list_tenants()
    assert len(tenants) == 2
    ta = next(t for t in tenants if t["tenant_id"] == "team-a")
    assert ta["agent_count"] == 2
    tb = next(t for t in tenants if t["tenant_id"] == "team-b")
    assert tb["agent_count"] == 1


def test_in_memory_list_tenants_empty():
    store = InMemoryFleetStore()
    assert store.list_tenants() == []


# ─── SQLiteFleetStore ────────────────────────────────────────────────────────


@pytest.fixture()
def sqlite_store():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    store = SQLiteFleetStore(db_path=path)
    yield store
    os.unlink(path)


def test_sqlite_list_by_tenant(sqlite_store):
    sqlite_store.put(_make_agent("a1", "agent1", "team-a"))
    sqlite_store.put(_make_agent("a2", "agent2", "team-b"))
    sqlite_store.put(_make_agent("a3", "agent3", "team-a"))

    team_a = sqlite_store.list_by_tenant("team-a")
    assert len(team_a) == 2
    assert all(a.tenant_id == "team-a" for a in team_a)


def test_sqlite_list_by_tenant_empty(sqlite_store):
    sqlite_store.put(_make_agent("a1", "agent1", "team-a"))
    assert sqlite_store.list_by_tenant("nonexistent") == []


def test_sqlite_list_tenants(sqlite_store):
    sqlite_store.put(_make_agent("a1", "agent1", "team-a"))
    sqlite_store.put(_make_agent("a2", "agent2", "team-b"))
    sqlite_store.put(_make_agent("a3", "agent3", "team-a"))

    tenants = sqlite_store.list_tenants()
    assert len(tenants) == 2
    ta = next(t for t in tenants if t["tenant_id"] == "team-a")
    assert ta["agent_count"] == 2


def test_sqlite_tenant_preserved_on_update(sqlite_store):
    sqlite_store.put(_make_agent("a1", "agent1", "team-x"))
    sqlite_store.update_state("a1", FleetLifecycleState.APPROVED)
    agent = sqlite_store.get("a1")
    assert agent is not None
    assert agent.tenant_id == "team-x"
    assert agent.lifecycle_state == FleetLifecycleState.APPROVED


def test_sqlite_batch_put_preserves_tenant(sqlite_store):
    agents = [
        _make_agent("a1", "agent1", "team-a"),
        _make_agent("a2", "agent2", "team-b"),
    ]
    sqlite_store.batch_put(agents)
    assert sqlite_store.list_by_tenant("team-a")[0].tenant_id == "team-a"
    assert sqlite_store.list_by_tenant("team-b")[0].tenant_id == "team-b"


# ─── Cross-tenant isolation ──────────────────────────────────────────────────


def test_cross_tenant_isolation():
    store = InMemoryFleetStore()
    store.put(_make_agent("a1", "agent1", "tenant-alpha"))
    store.put(_make_agent("a2", "agent2", "tenant-beta"))

    alpha = store.list_by_tenant("tenant-alpha")
    beta = store.list_by_tenant("tenant-beta")
    assert len(alpha) == 1
    assert len(beta) == 1
    assert alpha[0].agent_id != beta[0].agent_id
