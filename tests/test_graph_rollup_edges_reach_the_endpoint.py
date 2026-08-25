"""The roll-up's aggregated relationships must survive the endpoint's own fetch.

#4706 taught the roll-up to aggregate every **non-containment** edge onto the
containers its endpoints roll up into, so the collapsed estate renders as a
topology instead of a grid of disconnected cards. Every test it shipped built a
:class:`UnifiedGraph` in memory and called ``rollup_view`` directly, so all of
them passed.

The endpoint never gave that code anything to aggregate. ``/v1/graph/rollup``
loads the snapshot with ``relationship_types=ROLLUP_CONTAINMENT_RELATIONSHIPS``
— precisely the edges ``cross_container_edges`` is documented to discard — and
the drill-down walks the subtree with the same filter. So on every real request
the aggregation ran over an empty set, ``edges`` came back ``[]``, and the
canvas drew the grid the feature existed to remove. On the demo estate: 22,959
edges in the snapshot, 6,697 fetched, **0** rendered.

These tests exercise the *endpoint*, against a persisted snapshot, which is the
only place the defect was ever observable.
"""

from __future__ import annotations

import pytest

from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.rollup import rollup_view
from agent_bom.graph.types import EntityType, RelationshipType

# The tenant the API middleware establishes for an unauthenticated test request.
API_TENANT = "default"
SCAN = "rollup-edges-scan"


def _estate(tenant: str = API_TENANT) -> UnifiedGraph:
    """org -> account -> app -> resource, with relationships that cross containers.

    Three non-containment shapes, one per thing that must survive the fetch:

    * ``res-a-1 -> res-b-1`` (``USES``) — two resources in *different* accounts,
      so it aggregates to ``acct-a -> acct-b`` at the top level and to
      ``app-a-1 -> app-a-2`` nowhere; it is the estate-scale relationship a
      reviewer is looking for.
    * ``app-a-1 -> app-a-2`` (``USES``) — inside one account, so the top level
      collapses it into a self-edge and drops it, while a drill-down into
      ``acct-a`` is exactly where it becomes visible.
    * ``agent-0 -> res-a-1`` (``USES``) — from an orphan outside the containment
      tree, so it joins a top-level orphan card to a container.
    """
    graph = UnifiedGraph(scan_id=SCAN, tenant_id=tenant)

    def node(node_id: str, entity_type: EntityType, **attrs: object) -> None:
        graph.add_node(UnifiedNode(id=node_id, entity_type=entity_type, label=node_id, **attrs))  # type: ignore[arg-type]

    def edge(source: str, target: str, relationship: RelationshipType) -> None:
        graph.add_edge(UnifiedEdge(source=source, target=target, relationship=relationship))

    node("org-0", EntityType.ORG)
    node("agent-0", EntityType.AGENT, severity="high")
    for account in ("a", "b"):
        acct = f"acct-{account}"
        node(acct, EntityType.ACCOUNT)
        edge("org-0", acct, RelationshipType.CONTAINS)
        for app_index in (1, 2):
            app = f"app-{account}-{app_index}"
            node(app, EntityType.APPLICATION)
            edge(acct, app, RelationshipType.CONTAINS)
            res = f"res-{account}-{app_index}"
            node(res, EntityType.CLOUD_RESOURCE, severity="critical" if app_index == 1 else "low")
            edge(app, res, RelationshipType.CONTAINS)

    edge("res-a-1", "res-b-1", RelationshipType.USES)
    edge("app-a-1", "app-a-2", RelationshipType.USES)
    edge("agent-0", "res-a-1", RelationshipType.USES)
    return graph


@pytest.fixture
def api_store(tmp_path) -> SQLiteGraphStore:
    backend = SQLiteGraphStore(db_path=tmp_path / "rollup-edges.db")
    graph = _estate()
    backend.save_graph_streaming(
        scan_id=SCAN,
        tenant_id=API_TENANT,
        nodes=iter(list(graph.nodes.values())),
        edges=iter(list(graph.edges)),
    )
    return backend


@pytest.fixture
def client(api_store):
    from starlette.testclient import TestClient

    from agent_bom.api import stores as api_stores
    from agent_bom.api.server import app
    from agent_bom.api.stores import set_graph_store

    original = api_stores._graph_store
    set_graph_store(api_store)
    try:
        yield TestClient(app)
    finally:
        set_graph_store(original)


def _edge_pairs(payload: dict) -> set[tuple[str, str]]:
    return {(edge["source"], edge["target"]) for edge in payload["edges"]}


class TestTopLevelRollup:
    def test_the_response_carries_the_aggregated_relationships(self, client):
        response = client.get("/v1/graph/rollup", params={"scan_id": SCAN})
        assert response.status_code == 200, response.text
        payload = response.json()

        assert payload["edges"], "the collapsed estate came back with no relationships to draw"
        assert ("agent-0", "org-0") in _edge_pairs(payload)
        assert all(edge["relationships"] == ["uses"] for edge in payload["edges"])
        assert payload["edge_count_metadata"]["returned"] == len(payload["edges"])
        assert payload["edge_count_metadata"]["source_total"] == len(payload["edges"])
        assert payload["edge_count_metadata"]["truncated"] is False
        assert payload["completeness"]["complete"] is True

    def test_containment_is_still_never_drawn_as_a_relationship(self, client):
        payload = client.get("/v1/graph/rollup", params={"scan_id": SCAN}).json()
        relationships = {name for edge in payload["edges"] for name in edge["relationships"]}
        assert relationships.isdisjoint({"contains", "hosts", "owns"})

    def test_the_answer_matches_a_full_in_memory_materialisation(self, client):
        """The endpoint must not be a narrower view of the estate than the graph is."""
        expected = rollup_view(_estate())
        payload = client.get("/v1/graph/rollup", params={"scan_id": SCAN}).json()
        assert payload["edges"] == expected["edges"]

    def test_the_summary_reports_the_snapshot_edge_count_not_the_fetched_one(self, client):
        """``total_edges`` is what the estate holds; a fetch filter must not shrink it."""
        payload = client.get("/v1/graph/rollup", params={"scan_id": SCAN}).json()
        assert payload["summary"]["total_edges"] == len(_estate().edges)


class TestDrillDown:
    def test_drilling_into_a_container_carries_its_children_relationships(self, client):
        response = client.get("/v1/graph/rollup", params={"scan_id": SCAN, "node": "acct-a"})
        assert response.status_code == 200, response.text
        payload = response.json()

        assert payload["edges"], "the drill-down came back with no relationships to draw"
        assert ("app-a-1", "app-a-2") in _edge_pairs(payload)
        assert payload["edge_count_metadata"]["returned"] == len(payload["edges"])
        assert payload["edge_count_metadata"]["truncated"] is False

    def test_a_relationship_leaving_the_drilled_container_is_not_drawn(self, client):
        """``res-a-1 -> res-b-1`` leaves ``acct-a``; nothing at this level stands for it."""
        payload = client.get("/v1/graph/rollup", params={"scan_id": SCAN, "node": "acct-a"}).json()
        assert all(target in {"app-a-1", "app-a-2"} for _source, target in _edge_pairs(payload))
