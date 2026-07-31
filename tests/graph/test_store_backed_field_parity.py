"""StoreBackedUnifiedGraph must expose every graph-level field the base declares.

The subclass deliberately skips the ``@dataclass`` ``__init__`` so it can back
``nodes`` / ``edges`` / ``adjacency`` with the workspace store. The cost is that
each graph-level field the base class declares exists on an instance ONLY if
the subclass repeats it by hand — and one that is missed raises
``AttributeError`` at the first read, which for ``completeness`` was inside
``to_dict()``.

This asserts the mirror is complete, so the next field added to UnifiedGraph
fails here rather than in whatever code path first happens to read it.
"""

from __future__ import annotations

import dataclasses

import pytest

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.store_backed import open_store_backed_unified_graph

# Fields whose storage the subclass intentionally replaces with a store-backed
# property rather than an instance attribute.
STORE_BACKED_FIELDS = {"nodes", "edges", "adjacency", "reverse_adjacency", "_edge_keys"}


@pytest.fixture
def store_backed_graph():
    graph = open_store_backed_unified_graph(tenant_id="t", scan_id="s", backend="sqlite")
    try:
        yield graph
    finally:
        close = getattr(graph, "close", None)
        if close is not None:
            close()


def test_every_declared_graph_field_is_present(store_backed_graph):
    missing = [
        field.name
        for field in dataclasses.fields(UnifiedGraph)
        if field.name not in STORE_BACKED_FIELDS and not hasattr(store_backed_graph, field.name)
    ]
    assert missing == [], f"StoreBackedUnifiedGraph does not mirror {missing}"


def test_completeness_defaults_to_an_untruncated_snapshot(store_backed_graph):
    assert store_backed_graph.completeness.truncated is False
    assert store_backed_graph.stats()["total_nodes_source"] == store_backed_graph.stats()["total_nodes"]
