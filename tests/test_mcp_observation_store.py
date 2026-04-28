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
    assert observation.first_seen == "2026-04-23T11:00:00Z"
    assert observation.last_seen == "2026-04-23T15:05:00Z"
    assert observation.last_synced == "2026-04-23T15:06:00Z"


def test_merge_rejects_tenant_mismatch() -> None:
    existing = _make_observation(tenant_id="tenant-a")
    incoming = _make_observation(tenant_id="tenant-b")
    with pytest.raises(ValueError, match="tenant mismatch"):
        merge_observations(existing, incoming)


def test_merge_preserves_blocked_state_and_structured_intelligence() -> None:
    existing = _make_observation(
        security_blocked=False,
        security_intelligence=[{"entry_id": "intel-a", "matched_value": "mcp-a", "default_recommendation": "review"}],
    )
    incoming = _make_observation(
        security_blocked=True,
        security_intelligence=[
            {"entry_id": "intel-a", "matched_value": "mcp-a", "default_recommendation": "review"},
            {"entry_id": "intel-b", "matched_value": "mcp-b", "default_recommendation": "block"},
        ],
    )

    merged = merge_observations(existing, incoming)

    assert merged.security_blocked is True
    assert [item["entry_id"] for item in merged.security_intelligence] == ["intel-a", "intel-b"]


def test_observation_sanitizes_security_intelligence() -> None:
    observation = _make_observation(
        security_intelligence=[
            {
                "entry_id": "intel-a",
                "matched_value": "npx bad --token raw-secret callback=https://user:pass@example.com/path?token=secret",
                "references": ["https://example.com/advisory#fragment", "javascript:alert(1)"],
            }
        ],
    )

    intel = observation.security_intelligence[0]
    assert "raw-secret" not in str(intel["matched_value"])
    assert "user:pass" not in str(intel["matched_value"])
    assert intel["references"] == ["https://example.com/advisory"]


def test_inmemory_store_revalidates_observation_before_write() -> None:
    store = InMemoryMCPObservationStore()
    observation = _make_observation()
    observation.tenant_id = "  tenant-a  "
    observation.last_seen = "2026-04-23T11:05:00"
    store.put(observation)
    stored = store.get("tenant-a", "obs-1")
    assert stored is not None
    assert stored.tenant_id == "tenant-a"
    assert stored.last_seen == "2026-04-23T11:05:00Z"


def test_sqlite_store_revalidates_observation_before_write() -> None:
    store, path = _sqlite_store()
    try:
        observation = _make_observation(tenant_id=" tenant-a ", updated_at="2026-04-23T12:00:00Z")
        store.put(observation)
        stored = store.get("tenant-a", "obs-1")
        assert stored is not None
        assert stored.tenant_id == "tenant-a"
        assert stored.updated_at == "2026-04-23T12:00:00Z"
    finally:
        path.unlink(missing_ok=True)
