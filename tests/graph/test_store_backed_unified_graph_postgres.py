"""Real-Postgres contract for the store-backed live UnifiedGraph (#4075 PR-3).

Requires ``AGENT_BOM_POSTGRES_URL`` (skipped otherwise). Proves the store-backed
container is byte-identical to the in-RAM graph on the shared PG workspace, that
in-place mutation persists, and — the PG-specific hazard — that mid-iteration
write-back does **not** collide with an open server-side read cursor: the keyset-
paged iterators run one bounded, self-contained query per page, freeing the
connection for write-back between pages. Small ``capacity`` + ``page_size`` force
many pages and many evictions during a single ``values()`` sweep.
"""

from __future__ import annotations

import os
import uuid

import pytest

_DSN = os.environ.get("AGENT_BOM_POSTGRES_URL", "").strip()
pytestmark = pytest.mark.skipif(not _DSN, reason="AGENT_BOM_POSTGRES_URL not set")

from test_store_backed_unified_graph import (  # noqa: E402  (sibling module; tests/graph is not a package)
    _bidir_graph,
    _dumps,
    _replay,
    _synthetic_graph,
)

from agent_bom.graph.build_workspace import _PostgresWorkspaceBackend  # noqa: E402
from agent_bom.graph.node import UnifiedNode  # noqa: E402
from agent_bom.graph.store_backed import StoreBackedUnifiedGraph  # noqa: E402
from agent_bom.graph.types import EntityType  # noqa: E402


def _pg_store(**kwargs) -> StoreBackedUnifiedGraph:
    wsid = f"sbg-{uuid.uuid4().hex}"
    backend = _PostgresWorkspaceBackend(_DSN, wsid)
    kwargs.setdefault("owns_backend", True)
    return StoreBackedUnifiedGraph(backend, **kwargs)


def test_pg_to_dict_byte_identical_on_synthetic() -> None:
    graph = _synthetic_graph("s", 500)
    store = _pg_store(tenant_id="t1", scan_id="s", created_at=graph.created_at, capacity=32, page_size=64)
    try:
        _replay(graph, store)
        assert _dumps(store) == _dumps(graph)
    finally:
        store.close()


def test_pg_values_iteration_mutation_persists_without_cursor_conflict() -> None:
    graph = _synthetic_graph("s", 500)
    # capacity(16) and page_size(50) << 500 => many keyset pages + many dirty
    # evictions (write-back) DURING the sweep. On a single PG connection this only
    # works because each page is a closed query, not an open server-side cursor.
    store = _pg_store(tenant_id="t1", scan_id="s", created_at=graph.created_at, capacity=16, page_size=50)
    try:
        _replay(graph, store)
        for node in graph.nodes.values():
            node.attributes["swept"] = 1
        for node in store.nodes.values():
            node.attributes["swept"] = 1
        assert _dumps(store) == _dumps(graph)
    finally:
        store.close()


def test_pg_bidirectional_adjacency_matches_in_ram() -> None:
    from agent_bom.graph.container import UnifiedGraph

    g = UnifiedGraph(scan_id="s", tenant_id="t1", created_at="2026-07-20T00:00:00Z")
    _bidir_graph(g)
    store = _pg_store(tenant_id="t1", scan_id="s", created_at="2026-07-20T00:00:00Z", capacity=2, page_size=2)
    try:
        _bidir_graph(store)
        assert _dumps(store) == _dumps(g)
        for nid in ("a", "b", "c"):
            got = sorted((e.source, e.target, e.relationship.value) for e in store.adjacency.get(nid, []))
            want = sorted((e.source, e.target, e.relationship.value) for e in g.adjacency.get(nid, []))
            assert got == want, nid
        assert store.reachable_from("a") == g.reachable_from("a")
    finally:
        store.close()


def test_pg_tenant_isolation_on_shared_backend() -> None:
    wsid = f"sbg-iso-{uuid.uuid4().hex}"
    backend = _PostgresWorkspaceBackend(_DSN, wsid)
    try:
        alpha = StoreBackedUnifiedGraph(backend, tenant_id="alpha", scan_id="a", created_at="2026-07-20T00:00:00Z")
        beta = StoreBackedUnifiedGraph(backend, tenant_id="beta", scan_id="b", created_at="2026-07-20T00:00:00Z")
        for graph, extra in ((alpha, "vuln:alpha-only"), (beta, "vuln:beta-only")):
            graph.add_node(UnifiedNode(id="shared:1", entity_type=EntityType.AGENT, label="agent"))
            graph.add_node(UnifiedNode(id=extra, entity_type=EntityType.VULNERABILITY, label="v", severity="high"))
        assert alpha.has_node("vuln:alpha-only") and not alpha.has_node("vuln:beta-only")
        assert beta.has_node("vuln:beta-only") and not beta.has_node("vuln:alpha-only")
        assert {n.id for n in alpha.nodes.values()} == {"shared:1", "vuln:alpha-only"}
    finally:
        backend.close()  # DELETE by workspace_id clears both tenants' rows
