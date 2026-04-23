"""Tests for agent_bom.api.mcp_observation_store invariants."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from agent_bom.api.mcp_observation_store import (
    InMemoryMCPObservationStore,
    MCPObservation,
    SQLiteMCPObservationStore,
    merge_observations,
)


def _make_observation(**overrides) -> MCPObservation:
    base = {
        "observation_id": "obs-1",
        "server_stable_id": "stable-1",
        "server_name": "sqlite-mcp",
        "tenant_id": "tenant-a",
        "first_seen": "2026-04-23T11:00:00Z",
        "last_seen": "2026-04-23T11:05:00-04:00",
        "last_synced": "2026-04-23T15:06:00",
    }
    base.update(overrides)
    return MCPObservation(**base)


def _sqlite_store() -> tuple[SQLiteMCPObservationStore, Path]:
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    return SQLiteMCPObservationStore(tmp.name), Path(tmp.name)


def test_observation_normalizes_tenant_and_timestamps() -> None:
    observation = _make_observation(tenant_id="  tenant-a  ")
    assert observation.tenant_id == "tenant-a"
    assert observation.first_seen == "2026-04-23T11:00:00+00:00"
    assert observation.last_seen == "2026-04-23T15:05:00+00:00"
    assert observation.last_synced == "2026-04-23T15:06:00+00:00"


def test_merge_rejects_tenant_mismatch() -> None:
    existing = _make_observation(tenant_id="tenant-a")
    incoming = _make_observation(tenant_id="tenant-b")
    with pytest.raises(ValueError, match="tenant mismatch"):
        merge_observations(existing, incoming)


def test_inmemory_store_revalidates_observation_before_write() -> None:
    store = InMemoryMCPObservationStore()
    observation = _make_observation()
    observation.tenant_id = "  tenant-a  "
    observation.last_seen = "2026-04-23T11:05:00"
    store.put(observation)
    stored = store.get("tenant-a", "obs-1")
    assert stored is not None
    assert stored.tenant_id == "tenant-a"
    assert stored.last_seen == "2026-04-23T11:05:00+00:00"


def test_sqlite_store_revalidates_observation_before_write() -> None:
    store, path = _sqlite_store()
    try:
        observation = _make_observation(tenant_id=" tenant-a ", updated_at="2026-04-23T12:00:00Z")
        store.put(observation)
        stored = store.get("tenant-a", "obs-1")
        assert stored is not None
        assert stored.tenant_id == "tenant-a"
        assert stored.updated_at == "2026-04-23T12:00:00+00:00"
    finally:
        path.unlink(missing_ok=True)
