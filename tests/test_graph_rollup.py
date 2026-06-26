"""Tests for estate-scale graph roll-up (CONTAINS) + drill-down + endpoint."""

from __future__ import annotations

import copy

from starlette.testclient import TestClient

from agent_bom.api import server as api_server
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.server import app
from agent_bom.api.stores import set_graph_store
from agent_bom.graph import UnifiedEdge, UnifiedGraph, UnifiedNode
from agent_bom.graph.container import AttackPath
from agent_bom.graph.rollup import (
    RollupFilters,
    attack_path_view,
    drill_down,
    rollup_view,
)
from agent_bom.graph.types import EntityType, RelationshipType

# ── Synthetic graph builders ─────────────────────────────────────────────


def _contains(graph: UnifiedGraph, parent: str, child: str) -> None:
    graph.add_edge(UnifiedEdge(source=parent, target=child, relationship=RelationshipType.CONTAINS))


def _deep_estate() -> UnifiedGraph:
    """org -> account -> app -> {server, server} -> {package(crit), package(low)}."""
    g = UnifiedGraph(scan_id="estate-scan", tenant_id="default")
    g.add_node(UnifiedNode(id="org:acme", entity_type=EntityType.ORG, label="Acme"))
    g.add_node(UnifiedNode(id="account:prod", entity_type=EntityType.ACCOUNT, label="prod"))
    g.add_node(UnifiedNode(id="app:web", entity_type=EntityType.APPLICATION, label="web"))
    g.add_node(
        UnifiedNode(
            id="server:s1",
            entity_type=EntityType.SERVER,
            label="s1",
            attributes={"internet_exposed": True},
        )
    )
    g.add_node(UnifiedNode(id="server:s2", entity_type=EntityType.SERVER, label="s2"))
    g.add_node(
        UnifiedNode(
            id="pkg:crit",
            entity_type=EntityType.PACKAGE,
            label="crit-pkg",
            severity="critical",
            attributes={"toxic_exposed_vulnerable": True},
        )
    )
    g.add_node(UnifiedNode(id="pkg:low", entity_type=EntityType.PACKAGE, label="low-pkg", severity="low"))

    _contains(g, "org:acme", "account:prod")
    _contains(g, "account:prod", "app:web")
    _contains(g, "app:web", "server:s1")
    _contains(g, "app:web", "server:s2")
    _contains(g, "server:s1", "pkg:crit")
    _contains(g, "server:s2", "pkg:low")
    return g


def _large_estate(accounts: int = 10, apps: int = 10, pkgs: int = 12) -> UnifiedGraph:
    """One org over many accounts/apps/packages — >1000 nodes, one CONTAINS root."""
    g = UnifiedGraph(scan_id="large-scan", tenant_id="default")
    g.add_node(UnifiedNode(id="org:root", entity_type=EntityType.ORG, label="root"))
    for a in range(accounts):
        acc = f"account:{a}"
        g.add_node(UnifiedNode(id=acc, entity_type=EntityType.ACCOUNT, label=f"acct-{a}"))
        _contains(g, "org:root", acc)
        for p in range(apps):
            app_id = f"app:{a}-{p}"
            g.add_node(UnifiedNode(id=app_id, entity_type=EntityType.APPLICATION, label=f"app-{a}-{p}"))
            _contains(g, acc, app_id)
            for k in range(pkgs):
                pkg = f"pkg:{a}-{p}-{k}"
                sev = "critical" if k == 0 else "low"
                g.add_node(UnifiedNode(id=pkg, entity_type=EntityType.PACKAGE, label=pkg, severity=sev))
                _contains(g, app_id, pkg)
    return g


# ── Roll-up ──────────────────────────────────────────────────────────────


def test_rollup_collapses_deep_contains_tree_with_aggregate_counts() -> None:
    view = rollup_view(_deep_estate())
    assert view["mode"] == "rollup"
    # A 7-node estate collapses to a single top-level container (the org root).
    assert view["summary"]["top_level_count"] == 1
    top = view["top_level"][0]
    assert top["id"] == "org:acme"
    agg = top["aggregate"]
    # 6 descendants under the org (account, app, 2 servers, 2 packages).
    assert agg["descendant_count"] == 6
    assert agg["by_type"]["package"] == 2
    assert agg["by_type"]["server"] == 2
    assert agg["worst_severity"] == "critical"
    assert agg["severity_counts"]["critical"] == 1
    assert agg["severity_counts"]["low"] == 1
    # Exposure + toxic flags roll up from descendants.
    assert agg["internet_exposed"] is True
    assert agg["toxic_combo"] is True


def test_rollup_is_deterministic() -> None:
    g = _deep_estate()
    assert rollup_view(g) == rollup_view(g)


def test_rollup_does_not_mutate_source_graph() -> None:
    g = _deep_estate()
    before_nodes = copy.deepcopy(g.nodes)
    before_edges = [e.to_dict() for e in g.edges]
    rollup_view(g)
    drill_down(g, "app:web")
    attack_path_view(g, [])
    assert g.nodes == before_nodes
    assert [e.to_dict() for e in g.edges] == before_edges


# ── Large-graph scale ──────────────────────────────────────────────────────


def test_large_graph_rolls_up_to_small_top_level() -> None:
    g = _large_estate(accounts=10, apps=10, pkgs=12)
    # 1 org + 10 accounts + 100 apps + 1200 packages = 1311 nodes.
    assert len(g.nodes) > 1000
    view = rollup_view(g)
    # The whole estate collapses to exactly one readable top-level container.
    assert view["summary"]["top_level_count"] == 1
    top = view["top_level"][0]
    assert top["id"] == "org:root"
    assert top["aggregate"]["descendant_count"] == len(g.nodes) - 1
    # 10 accounts * 10 apps = 100 critical packages roll up.
    assert top["aggregate"]["severity_counts"]["critical"] == 100


def test_drill_down_is_one_level() -> None:
    g = _large_estate(accounts=10, apps=10, pkgs=12)
    res = drill_down(g, "org:root")
    assert res["mode"] == "drilldown"
    assert res["summary"]["direct_child_count"] == 10
    assert {c["id"] for c in res["children"]} == {f"account:{a}" for a in range(10)}
    # Each child still carries its own rolled-up aggregate (1 app-level + ...).
    for child in res["children"]:
        assert child["has_children"] is True
        assert child["aggregate"]["descendant_count"] == 10 + 10 * 12


def test_drill_down_unknown_node_returns_empty() -> None:
    res = drill_down(_deep_estate(), "does-not-exist")
    assert res["node"] is None
    assert res["children"] == []


# ── Filters ────────────────────────────────────────────────────────────────


def test_min_severity_filter_restricts_aggregates() -> None:
    view = rollup_view(_deep_estate(), filters=RollupFilters(min_severity="high"))
    top = view["top_level"][0]
    # Only the one critical package survives a high-severity floor.
    assert top["aggregate"]["descendant_count"] == 1
    assert top["aggregate"]["severity_counts"]["critical"] == 1
    assert top["aggregate"]["severity_counts"]["low"] == 0


def test_exposed_only_filter() -> None:
    view = rollup_view(_deep_estate(), filters=RollupFilters(exposed_only=True))
    top = view["top_level"][0]
    # server:s1 (internet_exposed) + pkg:crit (toxic_exposed_vulnerable).
    assert top["aggregate"]["descendant_count"] == 2
    assert top["aggregate"]["internet_exposed"] is True


def test_toxic_only_filter() -> None:
    view = rollup_view(_deep_estate(), filters=RollupFilters(toxic_only=True))
    top = view["top_level"][0]
    assert top["aggregate"]["descendant_count"] == 1
    assert top["aggregate"]["toxic_combo"] is True


# ── Attack-path-first mode ─────────────────────────────────────────────────


def test_attack_path_view_surfaces_path_nodes_first() -> None:
    g = _deep_estate()
    path = AttackPath(
        source="server:s1",
        target="pkg:crit",
        hops=["server:s1", "pkg:crit"],
        edges=["contains"],
        composite_risk=92.0,
        summary="exposed server reaches critical package",
    )
    view = attack_path_view(g, [path])
    assert view["mode"] == "attack_path"
    assert view["summary"]["path_count"] == 1
    assert {n["id"] for n in view["path_nodes"]} == {"server:s1", "pkg:crit"}
    assert view["summary"]["path_edge_count"] == 1
    # The org root is collapsed (off-path), not expanded into the path view.
    assert any(c["id"] == "org:acme" for c in view["collapsed"])
    assert "server:s1" not in {c["id"] for c in view["collapsed"]}


def test_attack_path_view_with_no_paths_collapses_everything() -> None:
    view = attack_path_view(_deep_estate(), [])
    assert view["summary"]["path_count"] == 0
    assert view["path_nodes"] == []
    assert view["summary"]["collapsed_count"] >= 1


# ── Endpoint ───────────────────────────────────────────────────────────────


def test_rollup_endpoint_returns_top_level(tmp_path) -> None:
    store = SQLiteGraphStore(tmp_path / "graph.db")
    store.save_graph(_deep_estate())
    from agent_bom.api import stores as api_stores

    original = api_stores._graph_store
    try:
        set_graph_store(store)
        client = TestClient(app)
        resp = client.get("/v1/graph/rollup?scan_id=estate-scan")
        assert resp.status_code == 200
        body = resp.json()
        assert body["mode"] == "rollup"
        assert body["summary"]["top_level_count"] == 1
        assert body["top_level"][0]["id"] == "org:acme"

        drill = client.get("/v1/graph/rollup?scan_id=estate-scan&node=app:web")
        assert drill.status_code == 200
        assert {c["id"] for c in drill.json()["children"]} == {"server:s1", "server:s2"}
    finally:
        set_graph_store(original)


def test_rollup_endpoint_rejects_bad_severity(tmp_path) -> None:
    store = SQLiteGraphStore(tmp_path / "graph.db")
    store.save_graph(_deep_estate())
    from agent_bom.api import stores as api_stores

    original = api_stores._graph_store
    try:
        set_graph_store(store)
        client = TestClient(app)
        resp = client.get("/v1/graph/rollup?scan_id=estate-scan&min_severity=bogus")
        assert resp.status_code == 422
    finally:
        set_graph_store(original)


def test_rollup_endpoint_requires_auth_when_key_configured(monkeypatch) -> None:
    # With an API key configured, an unauthenticated request must be rejected
    # by the same middleware that guards the sibling graph routes.
    api_server.configure_api(api_key="rollup-secret-key")
    try:
        client = TestClient(app)
        resp = client.get("/v1/graph/rollup", headers={"X-Agent-Bom-Tenant-ID": "tenant-alpha"})
        assert resp.status_code == 401
        # No exception detail or stack leaks into the body.
        assert "Traceback" not in resp.text
    finally:
        api_server.configure_api(api_key=None)
        api_server._runtime_api_key_seeded = False
