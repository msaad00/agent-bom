"""The AI BOM page must not read zero on a populated estate.

``/v1/agent-bom/manifest`` is built from exactly two stores: the fleet registry
and the MCP observation store. The demo bootstrap seeded the graph, the findings
and the identities — but neither of those — so the AI BOM rendered
``0 agents / 0 MCP servers`` while the estate held 48 agents and 25 servers. The
page's own promise is "live inventory from connected agents … not a static
upload", and it was showing nothing at all.

Asserted through ``build_control_plane_agent_manifest`` — the function the route
calls — rather than on the seeder's return value, because the seeder reporting
"48 seeded" is exactly what was true while the page still showed zero.
"""

from __future__ import annotations

from collections import Counter

import pytest


@pytest.fixture()
def seeded_stores(monkeypatch: pytest.MonkeyPatch, tmp_path):
    monkeypatch.setenv("AGENT_BOM_DEMO_ESTATE", "1")
    monkeypatch.setenv("AGENT_BOM_DB", str(tmp_path / "demo.db"))
    monkeypatch.setenv("AGENT_BOM_GRAPH_DB", str(tmp_path / "graph.db"))
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path))

    from agent_bom.api import stores as api_stores
    from agent_bom.demo_estate.showcase_graph import SHOWCASE_TENANT, seed_showcase_fleet_and_runtime

    api_stores._store = None
    seed_showcase_fleet_and_runtime(tenant_id=SHOWCASE_TENANT)
    yield SHOWCASE_TENANT


def _manifest(tenant_id: str) -> dict:
    from agent_bom.agent_manifest import build_control_plane_agent_manifest
    from agent_bom.api.stores import _get_fleet_store, _get_mcp_observation_store

    return build_control_plane_agent_manifest(
        _get_fleet_store().list_by_tenant(tenant_id),
        _get_mcp_observation_store().list_by_tenant(tenant_id),
        tenant_id=tenant_id,
    )


def test_ai_bom_manifest_reports_the_estates_agents_and_servers(seeded_stores: str) -> None:
    manifest = _manifest(seeded_stores)
    summary = manifest.get("summary") or {}

    assert summary.get("agents", 0) > 0, "the AI BOM reports zero agents on a populated estate"
    assert summary.get("mcp_servers", 0) > 0, "the AI BOM reports zero MCP servers on a populated estate"
    assert len(manifest.get("agents") or []) == summary["agents"]
    assert len(manifest.get("mcp_servers") or []) == summary["mcp_servers"]


def test_fleet_is_not_all_one_lifecycle_state(seeded_stores: str) -> None:
    """A governed fleet has a distribution, not one repeated value.

    Every agent sharing a lifecycle state is the tell that nothing is actually
    being governed — it reads as seeded, which is the impression the estate
    exists to avoid.
    """
    manifest = _manifest(seeded_stores)
    spread = Counter(agent["status"] for agent in manifest["agents"])

    assert len(spread) >= 3, f"fleet lifecycle has no variety: {dict(spread)}"
    # The majority should be the healthy state; a demo where most agents are
    # quarantined is as unrealistic as one where none are.
    assert spread.most_common(1)[0][0] == "approved", dict(spread)


def test_agents_and_servers_carry_operator_context(seeded_stores: str) -> None:
    """Rows must be readable, not bare identifiers.

    An inventory of unnamed rows cannot be reasoned about, and the estate has
    real names — the failure mode is dropping them on the way to the page.
    """
    manifest = _manifest(seeded_stores)

    for agent in manifest["agents"][:10]:
        assert agent["name"], agent
        assert agent["environment"], f"{agent['name']} has no environment"
        assert agent["owner"], f"{agent['name']} has no owner"
        assert isinstance(agent["trust_score"], (int, float))

    for server in manifest["mcp_servers"][:10]:
        assert server["name"], server
        assert server["transport"], f"{server['name']} has no transport"
        assert server["auth_mode"], f"{server['name']} has no auth mode"


def test_seeding_twice_does_not_duplicate_the_fleet(seeded_stores: str) -> None:
    """The bootstrap runs on every start; a second pass must be a no-op."""
    from agent_bom.demo_estate.showcase_graph import seed_showcase_fleet_and_runtime

    before = _manifest(seeded_stores)["summary"]["agents"]
    result = seed_showcase_fleet_and_runtime(tenant_id=seeded_stores)
    after = _manifest(seeded_stores)["summary"]["agents"]

    assert result["seeded"] is False, result
    assert after == before, (before, after)
