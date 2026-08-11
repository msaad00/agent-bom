"""`GET /v1/graph` must not return the same edge twice.

Measured on the demo estate: the response carried **23,387** edges while
``stats`` declared **22,993** — 394 more edges than the snapshot contains. The
extra ones are not new relationships; they are the same relationships listed a
second time, which inflates every count a client derives from the payload and
makes an edge look like corroborating evidence for itself.

The mechanism is in `_containment_ancestors`. On its first level it walks
``frontier_edges = known_edges`` with ``frontier = set(node_ids)`` and keeps any
edge where ``edge.target in frontier and edge.source not in node_ids`` — a
containment edge reaching into the page from a parent outside it. But
``known_edges`` *is* the page's own edge list, fetched by ``edges_for_node_ids``,
which returns every edge touching a page node regardless of which end is on the
page. So every such edge is already in ``paged_edges``, and the route then
serialises ``[*paged_edges, *ancestor_edges]`` — a plain concatenation.

`UnifiedGraph.add_edge` already settles what makes an edge the same edge:
the ``(source, target, relationship)`` triple. The response join now applies
that same key rather than a second, looser judgement.

Note this is only reachable when the page has a containment parent outside it,
which is why it grows with estate size and was invisible on small fixtures.
"""

from __future__ import annotations

from collections import Counter

from fastapi.testclient import TestClient

from tests.test_demo_estate_bootstrap import VIEWER, demo_estate_client  # noqa: F401


def edge_key(edge: dict) -> tuple[str, str, str]:
    return (str(edge.get("source")), str(edge.get("target")), str(edge.get("relationship")))


def test_no_edge_is_listed_twice(demo_estate_client: TestClient) -> None:  # noqa: F811
    payload = demo_estate_client.get("/v1/graph", headers=VIEWER).json()
    edges = payload.get("edges") or []
    assert edges, "the demo estate returned no edges, so this proves nothing"

    duplicates = {key: count for key, count in Counter(edge_key(e) for e in edges).items() if count > 1}
    assert not duplicates, (
        f"{len(edges) - len(set(edge_key(e) for e in edges))} duplicate edges in the page; first few: {list(duplicates.items())[:3]}"
    )


def test_returned_edges_do_not_exceed_the_snapshot(demo_estate_client: TestClient) -> None:  # noqa: F811
    """A page is a subset of the estate. It can never hold *more* than all of it."""
    payload = demo_estate_client.get("/v1/graph", headers=VIEWER).json()
    edges = payload.get("edges") or []
    total_edges = (payload.get("stats") or {}).get("total_edges")
    if not isinstance(total_edges, int) or total_edges <= 0:
        return  # the fixture does not report a snapshot edge total; the test above still binds
    assert len(edges) <= total_edges, f"page returned {len(edges)} edges of a {total_edges}-edge snapshot"


def test_containment_parents_still_reach_the_page(demo_estate_client: TestClient) -> None:  # noqa: F811
    """Deduplicating must not drop the ancestor context it was added to carry.

    Every node in the payload that is not on the ranked page is there because a
    containment edge reached it; that edge must still be present, or the
    ancestor renders as an orphan.
    """
    payload = demo_estate_client.get("/v1/graph", headers=VIEWER).json()
    completeness = payload.get("completeness") or {}
    context_nodes = completeness.get("context_nodes") or 0
    if not context_nodes:
        return  # no ancestors were added for this page

    node_ids = {str(n.get("id")) for n in payload.get("nodes") or []}
    connected = {str(e.get("source")) for e in payload.get("edges") or []} | {str(e.get("target")) for e in payload.get("edges") or []}
    orphans = node_ids - connected
    assert not orphans, f"{len(orphans)} nodes have no edge in the payload: {sorted(orphans)[:3]}"
