"""Tests for fleet store batch_put — InMemory and SQLite backends."""

from __future__ import annotations

from agent_bom.api.fleet_store import (
    FleetAgent,
    FleetLifecycleState,
    InMemoryFleetStore,
    SQLiteFleetStore,
)


def _make_agent(agent_id: str, name: str = "test") -> FleetAgent:
    return FleetAgent(
        agent_id=agent_id,
        name=name,
        agent_type="test",
        lifecycle_state=FleetLifecycleState.DISCOVERED,
        trust_score=0.5,
        updated_at="2026-01-01T00:00:00Z",
    )


# ── InMemoryFleetStore ──────────────────────────────────────────────────────


class TestInMemoryBatchPut:
    def test_empty(self):
        store = InMemoryFleetStore()
        assert store.batch_put([]) == 0

    def test_single(self):
        store = InMemoryFleetStore()
        assert store.batch_put([_make_agent("a1")]) == 1
        assert store.get("a1") is not None

    def test_multiple(self):
        store = InMemoryFleetStore()
        agents = [_make_agent(f"a{i}") for i in range(5)]
        assert store.batch_put(agents) == 5
        assert len(store.list_all()) == 5

    def test_upsert(self):
        store = InMemoryFleetStore()
        store.put(_make_agent("a1", name="old"))
        store.batch_put([_make_agent("a1", name="new")])
        assert store.get("a1").name == "new"


# ── SQLiteFleetStore ────────────────────────────────────────────────────────


class TestSQLiteBatchPut:
    def test_empty(self, tmp_path):
        store = SQLiteFleetStore(str(tmp_path / "test.db"))
        assert store.batch_put([]) == 0

    def test_single(self, tmp_path):
        store = SQLiteFleetStore(str(tmp_path / "test.db"))
        assert store.batch_put([_make_agent("a1")]) == 1
        assert store.get("a1") is not None

    def test_multiple(self, tmp_path):
        store = SQLiteFleetStore(str(tmp_path / "test.db"))
        agents = [_make_agent(f"a{i}") for i in range(10)]
        assert store.batch_put(agents) == 10
        assert len(store.list_all()) == 10

    def test_upsert(self, tmp_path):
        store = SQLiteFleetStore(str(tmp_path / "test.db"))
        store.put(_make_agent("a1", name="old"))
        store.batch_put([_make_agent("a1", name="new")])
        assert store.get("a1").name == "new"
