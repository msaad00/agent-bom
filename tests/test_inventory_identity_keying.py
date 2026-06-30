"""Regression tests: fleet/discovery joins must key by canonical_id, not bare name.

Two agents that share a bare ``name`` but have distinct ``source_id`` values are
distinct entities (FleetAgent identity is ``(source_id, name)`` / ``canonical_id``).
Keying join/index dicts by ``.name`` collapses them into a single slot, so distinct
records get mis-enriched, clobbered, or dropped.  These tests pin the canonical-id
keying for the three call sites.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from agent_bom.api.fleet_store import FleetAgent, FleetLifecycleState, InMemoryFleetStore
from agent_bom.api.pipeline import _sync_scan_agents_to_fleet
from agent_bom.api.routes import discovery as discovery_routes
from agent_bom.api.routes import fleet as fleet_routes
from agent_bom.api.stores import set_fleet_store
from agent_bom.models import Agent, AgentType, MCPServer


def _request(tenant_id: str) -> SimpleNamespace:
    return SimpleNamespace(state=SimpleNamespace(tenant_id=tenant_id, api_key_name="tenant-actor"))


def _local_claude() -> Agent:
    # Locally discovered agent: canonical_id == agent_type + name (no source_id).
    return Agent(
        name="claude",
        agent_type=AgentType.CLAUDE_DESKTOP,
        config_path="/tmp/claude.json",
        mcp_servers=[MCPServer(name="fs", command="npx")],
    )


def test_sync_scan_does_not_clobber_same_name_record_with_different_source() -> None:
    """pipeline._sync_scan_agents_to_fleet keys the existing index by canonical_id."""
    store = InMemoryFleetStore()
    # MDM-managed record sharing the bare name "claude" but a distinct source_id.
    mdm = FleetAgent(
        agent_id="mdm-id",
        name="claude",
        agent_type="claude-desktop",
        source_id="mdmX",
        lifecycle_state=FleetLifecycleState.APPROVED,
        server_count=99,
        tenant_id="default",
    )
    store.put(mdm)
    mdm_canonical = mdm.canonical_id

    local = _local_claude()
    assert local.canonical_id != mdm_canonical

    with patch("agent_bom.api.pipeline._get_fleet_store", return_value=store):
        _sync_scan_agents_to_fleet([local])

    # The distinct MDM-managed record must be left untouched (not clobbered to 1).
    survived = store.get_by_canonical_id(mdm_canonical, "default")
    assert survived is not None
    assert survived.agent_id == "mdm-id"
    assert survived.server_count == 99
    # The local agent becomes its own fleet record rather than overwriting the MDM one.
    local_record = store.get_by_canonical_id(local.canonical_id, "default")
    assert local_record is not None
    assert local_record.agent_id != "mdm-id"
    assert len(store.list_by_tenant("default")) == 2


@pytest.mark.asyncio
async def test_fleet_sync_discovery_keys_existing_by_canonical_id() -> None:
    """fleet.sync_fleet discover_all() branch keys the existing index by canonical_id."""
    store = InMemoryFleetStore()
    set_fleet_store(store)
    mdm = FleetAgent(
        agent_id="mdm-id",
        name="claude",
        agent_type="claude-desktop",
        source_id="mdmX",
        lifecycle_state=FleetLifecycleState.APPROVED,
        server_count=99,
        tenant_id="default",
    )
    store.put(mdm)
    mdm_canonical = mdm.canonical_id

    local = _local_claude()

    with patch("agent_bom.discovery.discover_all", return_value=[local]):
        resp = await fleet_routes.sync_fleet(_request("default"))

    # A genuinely new identity -> one record created, MDM record untouched.
    assert resp["new"] == 1
    assert resp["updated"] == 0
    survived = store.get_by_canonical_id(mdm_canonical, "default")
    assert survived is not None and survived.server_count == 99
    assert store.get_by_canonical_id(local.canonical_id, "default") is not None
    assert len(store.list_by_tenant("default")) == 2


def test_build_agents_response_enriches_from_matching_source_record() -> None:
    """discovery._build_agents_response joins fleet records by canonical_id, not name."""
    store = InMemoryFleetStore()
    set_fleet_store(store)
    local = _local_claude()
    # Matching record: carries the same canonical_id as the locally discovered
    # agent (as a prior scan-sync would have persisted it).
    match = FleetAgent(
        agent_id="match-id",
        name="claude",
        agent_type="claude-desktop",
        canonical_id=local.canonical_id,
        tenant_id="default",
        updated_at="2026-06-01T00:00:00+00:00",
    )
    # Same bare name, different source_id -> distinct canonical_id. Inserted last so a
    # name-keyed index would (wrongly) resolve "claude" to this record.
    other = FleetAgent(
        agent_id="other-id",
        name="claude",
        agent_type="claude-desktop",
        source_id="mdmX",
        tenant_id="default",
        updated_at="2099-01-01T00:00:00+00:00",
    )
    store.put(match)
    store.put(other)
    assert match.canonical_id != other.canonical_id

    assert local.canonical_id == match.canonical_id

    with (
        patch("agent_bom.discovery.discover_all", return_value=[local]),
        patch("agent_bom.parsers.extract_packages", return_value=[]),
        patch.object(discovery_routes, "_persist_agent_observations", lambda *a, **k: None),
        patch.object(discovery_routes, "_build_scan_history_index", return_value={}),
        patch.object(discovery_routes, "_build_gateway_index", return_value={}),
        patch.object(discovery_routes, "_observation_index", return_value={}),
    ):
        response = discovery_routes._build_agents_response("default")

    provenance = response["agents"][0]["mcp_servers"][0]["provenance"]
    # Enrichment must come from the matching empty-source record, not the mdmX one.
    assert provenance["fleet_present"] is True
    assert provenance["last_synced"] == match.updated_at
