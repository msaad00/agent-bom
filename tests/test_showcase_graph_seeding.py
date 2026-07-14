"""``seed_showcase_graph_if_empty`` must be *stale-aware*, not merely empty-aware.

Regression coverage for #3964: a polluted graph DB (25 accumulated snapshots +
an out-of-date demo seed) must not shadow a fresh scan, and a stale showcase
seed must be refreshed on ``--demo-estate`` boot instead of early-returning.
"""

from __future__ import annotations

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
    return {
        row["scan_id"]: row["created_at"]
        for row in store.list_snapshots(tenant_id=SHOWCASE_TENANT)
    }


def _minimal_graph(*, scan_id: str, created_at: str) -> UnifiedGraph:
    graph = UnifiedGraph(scan_id=scan_id, tenant_id=SHOWCASE_TENANT, created_at=created_at)
    graph.add_node(
        UnifiedNode(id="agent:probe", entity_type=EntityType.AGENT, label="Probe")
    )
    return graph


def test_seeds_when_empty(store: SQLiteGraphStore) -> None:
    assert seed_showcase_graph_if_empty(store) is True

    created = _snapshot_created_at(store)
    assert created.get(SHOWCASE_SCAN_ID) == SHOWCASE_CURRENT_CREATED_AT
    assert SHOWCASE_BASELINE_SCAN_ID in created
    assert store.latest_snapshot_id(tenant_id=SHOWCASE_TENANT) == SHOWCASE_SCAN_ID


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
    store.save_graph(
        _minimal_graph(scan_id=SHOWCASE_SCAN_ID, created_at="2026-07-13T00:00:00+00:00")
    )
    assert store.list_snapshots(tenant_id=SHOWCASE_TENANT), "precondition: stale seed present"

    assert seed_showcase_graph_if_empty(store) is True

    created = _snapshot_created_at(store)
    assert created.get(SHOWCASE_SCAN_ID) == SHOWCASE_CURRENT_CREATED_AT
    assert SHOWCASE_BASELINE_SCAN_ID in created


def test_does_not_shadow_a_real_scan(store: SQLiteGraphStore) -> None:
    # A real scan lands with a non-showcase scan id and a current timestamp.
    store.save_graph(
        _minimal_graph(scan_id="aws-scan-2026-07-14", created_at="2026-07-14T09:00:00+00:00")
    )

    assert seed_showcase_graph_if_empty(store) is False

    scan_ids = {row["scan_id"] for row in store.list_snapshots(tenant_id=SHOWCASE_TENANT)}
    assert scan_ids == {"aws-scan-2026-07-14"}
    assert scan_ids.isdisjoint({SHOWCASE_SCAN_ID, SHOWCASE_BASELINE_SCAN_ID})
    # The fresh scan remains the graph the read path defaults to.
    assert store.latest_snapshot_id(tenant_id=SHOWCASE_TENANT) == "aws-scan-2026-07-14"
