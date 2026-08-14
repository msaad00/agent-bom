"""``seed_showcase_graph_if_empty`` must be *stale-aware*, not merely empty-aware.

Regression coverage for #3964: a polluted graph DB (25 accumulated snapshots +
an out-of-date demo seed) must not shadow a fresh scan, and a stale showcase
seed must be refreshed on ``--demo-estate`` boot instead of early-returning.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.demo_estate.showcase_graph import (
    SHOWCASE_BASELINE_SCAN_ID,
    SHOWCASE_CURRENT_CREATED_AT,
    SHOWCASE_SCAN_ID,
    SHOWCASE_TENANT,
    seed_showcase_graph_if_empty,
)
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType


@pytest.fixture()
def store(tmp_path: Path) -> SQLiteGraphStore:
    return SQLiteGraphStore(db_path=tmp_path / "graph.db")


def _snapshot_created_at(store: SQLiteGraphStore) -> dict[str, str]:
    return {row["scan_id"]: row["created_at"] for row in store.list_snapshots(tenant_id=SHOWCASE_TENANT)}


def _minimal_graph(*, scan_id: str, created_at: str) -> UnifiedGraph:
    graph = UnifiedGraph(scan_id=scan_id, tenant_id=SHOWCASE_TENANT, created_at=created_at)
    graph.add_node(UnifiedNode(id="agent:probe", entity_type=EntityType.AGENT, label="Probe"))
    return graph


def test_seeds_when_empty(store: SQLiteGraphStore) -> None:
    assert seed_showcase_graph_if_empty(store) is True

    created = _snapshot_created_at(store)
    assert created.get(SHOWCASE_SCAN_ID) == SHOWCASE_CURRENT_CREATED_AT
    assert SHOWCASE_BASELINE_SCAN_ID in created
    assert store.latest_snapshot_id(tenant_id=SHOWCASE_TENANT) == SHOWCASE_SCAN_ID


def test_showcase_snapshot_stamps_are_never_future_dated() -> None:
    """A seeded demo must not present tomorrow's snapshot as observed evidence."""
    from agent_bom.demo_estate.showcase_graph import SHOWCASE_BASELINE_CREATED_AT

    now = datetime.now(timezone.utc)
    assert datetime.fromisoformat(SHOWCASE_BASELINE_CREATED_AT) <= now
    assert datetime.fromisoformat(SHOWCASE_CURRENT_CREATED_AT) <= now


def test_persisted_finding_nodes_serve_prose_not_a_python_repr(store: SQLiteGraphStore) -> None:
    """Read the attribute back out of the store, not off the in-memory graph.

    The projection is where the value is chosen, but the store is where it stops
    being checkable: ``json.dumps(..., default=str)`` accepts any object and
    freezes its Python ``repr`` into the snapshot, so a projection bug survives
    persistence as a plausible-looking string. Assert on what a reader is
    actually served.
    """
    assert seed_showcase_graph_if_empty(store) is True

    graph = store.load_graph(scan_id=SHOWCASE_SCAN_ID, tenant_id=SHOWCASE_TENANT)
    estate_findings = [
        node for node in graph.nodes.values() if node.entity_type is EntityType.MISCONFIGURATION and node.attributes.get("estate_id")
    ]
    assert len(estate_findings) >= 439, len(estate_findings)
    for node in estate_findings:
        recommendation = node.attributes.get("recommendation")
        assert isinstance(recommendation, str) and recommendation, node.id
        assert "RemediationFix(" not in recommendation, f"{node.id} serves a Python repr as remediation: {recommendation[:80]!r}"


def test_a_seed_predating_this_build_is_treated_as_stale(store: SQLiteGraphStore) -> None:
    """A deployed demo must pick up projection fixes without an operator reset.

    ``seed_showcase_graph_if_empty`` early-returns when both snapshots carry the
    expected ``created_at``, so a change to what the projection *writes* only
    reaches an existing database if the stamp moved with it. Pin the stamps that
    shipped with the repr defect: leaving either in place means every already-
    running demo keeps serving the old snapshot forever.
    """
    from agent_bom.demo_estate.showcase_graph import SHOWCASE_BASELINE_CREATED_AT

    shipped_with_the_defect = {
        SHOWCASE_SCAN_ID: "2026-08-08T12:00:00+00:00",
        SHOWCASE_BASELINE_SCAN_ID: "2026-08-01T12:00:00+00:00",
    }
    assert (
        SHOWCASE_CURRENT_CREATED_AT != shipped_with_the_defect[SHOWCASE_SCAN_ID]
        or SHOWCASE_BASELINE_CREATED_AT != shipped_with_the_defect[SHOWCASE_BASELINE_SCAN_ID]
    ), "the seed stamp did not move, so a deployed demo keeps the old snapshot"

    # And the mechanism still does its job for that exact pair of stamps.
    store.save_graph(_minimal_graph(scan_id=SHOWCASE_SCAN_ID, created_at=shipped_with_the_defect[SHOWCASE_SCAN_ID]))
    store.save_graph(
        _minimal_graph(
            scan_id=SHOWCASE_BASELINE_SCAN_ID,
            created_at=shipped_with_the_defect[SHOWCASE_BASELINE_SCAN_ID],
        )
    )
    assert seed_showcase_graph_if_empty(store) is True
    assert _snapshot_created_at(store).get(SHOWCASE_SCAN_ID) == SHOWCASE_CURRENT_CREATED_AT


def test_idempotent_when_current(store: SQLiteGraphStore) -> None:
    assert seed_showcase_graph_if_empty(store) is True
    # A fresh seed is not re-written on the next boot.
    assert seed_showcase_graph_if_empty(store) is False
    scan_ids = [row["scan_id"] for row in store.list_snapshots(tenant_id=SHOWCASE_TENANT)]
    assert scan_ids.count(SHOWCASE_SCAN_ID) == 1
    assert scan_ids.count(SHOWCASE_BASELINE_SCAN_ID) == 1


def test_reseeds_when_stale(store: SQLiteGraphStore) -> None:
    # A stale demo seed: right scan id, mismatched created_at (an older build's
    # timestamp), no baseline. Recent enough to survive retention purge.
    store.save_graph(_minimal_graph(scan_id=SHOWCASE_SCAN_ID, created_at="2026-07-13T00:00:00+00:00"))
    assert store.list_snapshots(tenant_id=SHOWCASE_TENANT), "precondition: stale seed present"

    assert seed_showcase_graph_if_empty(store) is True

    created = _snapshot_created_at(store)
    assert created.get(SHOWCASE_SCAN_ID) == SHOWCASE_CURRENT_CREATED_AT
    assert SHOWCASE_BASELINE_SCAN_ID in created


def test_does_not_shadow_a_real_scan(store: SQLiteGraphStore) -> None:
    # A real scan lands with a non-showcase scan id and a current timestamp.
    store.save_graph(_minimal_graph(scan_id="aws-scan-2026-07-14", created_at="2026-07-14T09:00:00+00:00"))

    assert seed_showcase_graph_if_empty(store) is False

    scan_ids = {row["scan_id"] for row in store.list_snapshots(tenant_id=SHOWCASE_TENANT)}
    assert scan_ids == {"aws-scan-2026-07-14"}
    assert scan_ids.isdisjoint({SHOWCASE_SCAN_ID, SHOWCASE_BASELINE_SCAN_ID})
    # The fresh scan remains the graph the read path defaults to.
    assert store.latest_snapshot_id(tenant_id=SHOWCASE_TENANT) == "aws-scan-2026-07-14"


def test_seeded_estate_is_isolated_per_tenant(store: SQLiteGraphStore) -> None:
    """Two tenants seed the SAME node ids; neither may drop or leak.

    The projected estate reuses its own ``asset_id`` values as graph node ids, so
    every tenant seeds an identical id set. A dedup key that omitted the tenant
    would silently drop the second tenant's rows and leave its graph reading as
    the first tenant's — the isolation defect class the 2026-07-28 audit found in
    the governance chain.
    """
    assert seed_showcase_graph_if_empty(store, tenant_id="tenant-a") is True
    assert seed_showcase_graph_if_empty(store, tenant_id="tenant-b") is True

    probe = "cloud_resource:aws:iam:role:member-copilot-prod"
    for tenant in ("tenant-a", "tenant-b"):
        graph = store.load_graph(tenant_id=tenant, scan_id=SHOWCASE_SCAN_ID)
        assert len(graph.nodes) > 2500, (tenant, len(graph.nodes))
        assert probe in graph.nodes, tenant
        assert graph.tenant_id == tenant

    # A third tenant that was never seeded sees nothing at all.
    empty = store.load_graph(tenant_id="tenant-c", scan_id=SHOWCASE_SCAN_ID)
    assert not empty.nodes


def test_estate_projection_is_idempotent_on_one_graph() -> None:
    """Re-projecting must merge, never duplicate.

    ``seed_showcase_graph_if_empty`` projects once per snapshot today, but the
    projection is a public entry point and a duplicated attack path or edge is
    invisible until it double-counts on a screen.
    """
    from agent_bom.demo_estate.showcase_graph import project_estate_onto_showcase

    graph = UnifiedGraph(scan_id=SHOWCASE_SCAN_ID, tenant_id=SHOWCASE_TENANT)
    project_estate_onto_showcase(graph, tenant_id=SHOWCASE_TENANT, profile="current")
    first = (len(graph.nodes), len(graph.edges), len(graph.attack_paths))

    project_estate_onto_showcase(graph, tenant_id=SHOWCASE_TENANT, profile="current")
    assert (len(graph.nodes), len(graph.edges), len(graph.attack_paths)) == first


def test_baseline_snapshot_carries_inventory_without_the_collection_window() -> None:
    """Baseline predates the evidence window: inventory yes, posture no.

    That is what makes the drift lens show posture *arriving* between the two
    snapshots rather than relabelling the same set.

    Asserted as the relationship between the two snapshots rather than against
    two frozen totals. The contract is that baseline and current inventory the
    SAME estate and differ only in evidence; pinning the literal asset count
    made this a size test, so growing the estate failed it while the property it
    names held perfectly.
    """
    from agent_bom.demo_estate.showcase_graph import project_estate_onto_showcase

    baseline = UnifiedGraph(scan_id=SHOWCASE_BASELINE_SCAN_ID, tenant_id=SHOWCASE_TENANT)
    summary = project_estate_onto_showcase(baseline, tenant_id=SHOWCASE_TENANT, profile="baseline")
    assert summary["assets"] > 0
    assert summary["findings"] == 0
    assert summary["chain_edges"] == 0
    assert not [n for n in baseline.nodes.values() if n.entity_type is EntityType.MISCONFIGURATION]

    current = UnifiedGraph(scan_id=SHOWCASE_SCAN_ID, tenant_id=SHOWCASE_TENANT)
    current_summary = project_estate_onto_showcase(current, tenant_id=SHOWCASE_TENANT, profile="current")
    # Same inventory in both snapshots — only the evidence window differs.
    assert current_summary["assets"] == summary["assets"]
    assert current_summary["findings"] > 0
    assert len(current.nodes) > len(baseline.nodes)
