"""Tests for agent_bom.api.fleet_store — fleet registry storage."""

import tempfile
from datetime import datetime, timezone
from pathlib import Path

from agent_bom.api.fleet_store import (
    FleetAgent,
    FleetLifecycleState,
    InMemoryFleetStore,
    SQLiteFleetStore,
)


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


# ── InMemoryFleetStore ────────────────────────────────────────────────────────


def test_put_and_get():
    store = InMemoryFleetStore()
    store.put(_make())
    assert store.get("a-1") is not None
    assert store.get("a-1").name == "test-agent"


def test_get_missing():
    store = InMemoryFleetStore()
    assert store.get("nope") is None


def test_get_by_name():
    store = InMemoryFleetStore()
    store.put(_make(agent_id="a-1", name="alpha"))
    store.put(_make(agent_id="a-2", name="beta"))
    assert store.get_by_name("beta").agent_id == "a-2"
    assert store.get_by_name("gamma") is None


def test_delete():
    store = InMemoryFleetStore()
    store.put(_make())
    assert store.delete("a-1") is True
    assert store.get("a-1") is None
    assert store.delete("a-1") is False


def test_list_all():
    store = InMemoryFleetStore()
    store.put(_make(agent_id="a-1", name="one"))
    store.put(_make(agent_id="a-2", name="two"))
    assert len(store.list_all()) == 2


def test_list_summary():
    store = InMemoryFleetStore()
    store.put(_make(agent_id="a-1", name="one", trust_score=90.0))
    summaries = store.list_summary()
    assert len(summaries) == 1
    assert summaries[0]["name"] == "one"
    assert summaries[0]["trust_score"] == 90.0


def test_update_state():
    store = InMemoryFleetStore()
    store.put(_make())
    assert store.update_state("a-1", FleetLifecycleState.APPROVED) is True
    assert store.get("a-1").lifecycle_state == FleetLifecycleState.APPROVED


def test_update_state_missing():
    store = InMemoryFleetStore()
    assert store.update_state("nope", FleetLifecycleState.APPROVED) is False


# ── SQLiteFleetStore ──────────────────────────────────────────────────────────


def _sqlite_store():
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    return SQLiteFleetStore(tmp.name), Path(tmp.name)


def test_sqlite_put_get():
    store, path = _sqlite_store()
    try:
        store.put(_make())
        assert store.get("a-1") is not None
        assert store.get("a-1").name == "test-agent"
    finally:
        path.unlink(missing_ok=True)


def test_sqlite_get_by_name():
    store, path = _sqlite_store()
    try:
        store.put(_make(agent_id="a-1", name="alpha"))
        store.put(_make(agent_id="a-2", name="beta"))
        assert store.get_by_name("alpha").agent_id == "a-1"
        assert store.get_by_name("missing") is None
    finally:
        path.unlink(missing_ok=True)


def test_sqlite_delete():
    store, path = _sqlite_store()
    try:
        store.put(_make())
        assert store.delete("a-1") is True
        assert store.get("a-1") is None
        assert store.delete("a-1") is False
    finally:
        path.unlink(missing_ok=True)


def test_sqlite_list_and_summary():
    store, path = _sqlite_store()
    try:
        store.put(_make(agent_id="a-1", name="one"))
        store.put(_make(agent_id="a-2", name="two"))
        assert len(store.list_all()) == 2
        summaries = store.list_summary()
        assert len(summaries) == 2
    finally:
        path.unlink(missing_ok=True)


def test_sqlite_update_state():
    store, path = _sqlite_store()
    try:
        store.put(_make())
        assert store.update_state("a-1", FleetLifecycleState.QUARANTINED) is True
        assert store.get("a-1").lifecycle_state == FleetLifecycleState.QUARANTINED
        assert store.update_state("nope", FleetLifecycleState.APPROVED) is False
    finally:
        path.unlink(missing_ok=True)


def test_sqlite_upsert():
    store, path = _sqlite_store()
    try:
        agent = _make()
        store.put(agent)
        agent.owner = "alice"
        store.put(agent)
        assert store.get("a-1").owner == "alice"
        assert len(store.list_all()) == 1
    finally:
        path.unlink(missing_ok=True)
