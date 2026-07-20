"""Real-Postgres contract for the graph build workspace (#4075, PR-1).

Requires ``AGENT_BOM_POSTGRES_URL`` (skipped otherwise). Exercises the shared,
cross-process backend: byte-identical parity vs the direct streamed save, tenant
isolation on the shared tables, bounded server-side streaming, and a
**cross-process writer race** — two OS processes writing the same workspace must
land every row exactly once with no loss, no duplicate, and no PK crash
(idempotent last-write-wins on a shared key).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import uuid

import pytest

_DSN = os.environ.get("AGENT_BOM_POSTGRES_URL", "").strip()
pytestmark = pytest.mark.skipif(not _DSN, reason="AGENT_BOM_POSTGRES_URL not set")

from agent_bom.graph import RelationshipType, UnifiedEdge  # noqa: E402
from agent_bom.graph.build_workspace import (  # noqa: E402
    GraphBuildWorkspace,
    _PostgresWorkspaceBackend,
)
from agent_bom.graph.container import UnifiedGraph  # noqa: E402
from agent_bom.graph.node import UnifiedNode  # noqa: E402
from agent_bom.graph.types import EntityType  # noqa: E402


def _graph(n: int, tenant: str = "t1") -> UnifiedGraph:
    g = UnifiedGraph(scan_id="s", tenant_id=tenant)
    for i in range(n):
        g.add_node(
            UnifiedNode(
                id=f"n:{i}",
                entity_type=EntityType.VULNERABILITY,
                label=f"L{i}",
                severity="high",
                # No canonical_id in attributes — stresses the from_dict drift.
                attributes={"cvss_score": 7.0, "blob": "v" * 24},
            )
        )
    for i in range(0, n - 1, 2):
        g.add_edge(UnifiedEdge(source=f"n:{i}", target=f"n:{i + 1}", relationship=RelationshipType.DEPENDS_ON))
    return g


def _persist_node_tuple(n: UnifiedNode):
    # Mirrors the exact serialised form save_graph_streaming persists per node.
    et = n.entity_type.value if hasattr(n.entity_type, "value") else n.entity_type
    st = n.status.value if hasattr(n.status, "value") else n.status
    return (
        n.id,
        et,
        n.label,
        n.category_uid,
        n.class_uid,
        n.type_uid,
        st,
        n.risk_score,
        n.severity,
        int(n.severity_id),
        n.first_seen,
        n.last_seen,
        json.dumps(n.attributes, default=str),
        json.dumps(n.compliance_tags),
        json.dumps(n.data_sources),
        json.dumps(n.dimensions.to_dict()),
    )


def _persist_edge_tuple(e: UnifiedEdge):
    rel = e.relationship.value if hasattr(e.relationship, "value") else str(e.relationship)
    return (
        e.source,
        e.target,
        rel,
        e.direction,
        e.weight,
        e.traversable,
        e.first_seen,
        e.last_seen,
        e.valid_from,
        e.valid_to,
        e.confidence,
        json.dumps(e.provenance, default=str),
        e.source_run_id,
        json.dumps(e.evidence, default=str),
        e.activity_id,
    )


def _open(workspace_id: str, tenant: str) -> GraphBuildWorkspace:
    return GraphBuildWorkspace(_PostgresWorkspaceBackend(_DSN, workspace_id), tenant_id=tenant, batch_size=100)


def test_postgres_workspace_roundtrip_is_byte_identical() -> None:
    graph = _graph(400)
    wsid = f"parity-{uuid.uuid4().hex}"

    # Baseline: the exact per-item serialised form the persist path writes,
    # taken straight from the original in-memory nodes/edges.
    want_nodes = sorted((_persist_node_tuple(n) for n in graph.nodes.values()), key=lambda t: t[0])
    want_edges = sorted((_persist_edge_tuple(e) for e in graph.edges), key=lambda t: (t[0], t[1], t[2]))

    with _open(wsid, "t1") as ws:
        ws.add_nodes(graph.nodes.values())
        ws.add_edges(graph.edges)
        assert ws.node_count() == len(graph.nodes)
        assert ws.edge_count() == len(graph.edges)
        got_nodes = sorted((_persist_node_tuple(n) for n in ws.iter_nodes()), key=lambda t: t[0])
        got_edges = sorted((_persist_edge_tuple(e) for e in ws.iter_edges()), key=lambda t: (t[0], t[1], t[2]))

    # Every persisted field survives the Postgres round-trip byte-for-byte,
    # including attributes (the canonical_id-injection drift is neutralised).
    assert got_nodes == want_nodes
    assert got_edges == want_edges


def test_postgres_random_access_parity() -> None:
    """The store's random-access reads mirror the in-RAM graph accessors (PG).

    Same differential oracle as the SQLite suite: byte-identical payloads from
    ``get_node_payload`` / ``iter_node_payloads_by_type`` /
    ``iter_edge_payloads_by_source`` / ``iter_edge_payloads_by_target`` versus
    the fully-materialised graph's ``get_node`` / ``nodes_by_type`` /
    ``edges_from`` / ``edges_to``. The graph is directed-only, so the store
    (populated from canonical ``graph.edges``) equals the in-RAM adjacency.
    """
    graph = _graph(400)
    wsid = f"ra-{uuid.uuid4().hex}"
    tenant = "t1"
    backend = _PostgresWorkspaceBackend(_DSN, wsid)
    ws = GraphBuildWorkspace(backend, tenant_id=tenant, batch_size=64)
    try:
        ws.add_nodes(graph.nodes.values())
        ws.add_edges(graph.edges)

        for nid, node in graph.nodes.items():
            payload = backend.get_node_payload(tenant, nid)
            assert payload is not None, f"node {nid} not retrievable by id"
            assert json.loads(payload) == node.to_dict()
            assert payload == json.dumps(node.to_dict(), default=str), "get_node_payload not byte-identical"
        assert backend.get_node_payload(tenant, "no-such-node") is None

        for et in {n.entity_type for n in graph.nodes.values()}:
            got = [json.loads(p) for p in backend.iter_node_payloads_by_type(tenant, et.value, 32)]
            want = [n.to_dict() for n in graph.nodes_by_type(et)]
            assert got == want, f"nodes_by_type parity diverged for {et}"
        assert list(backend.iter_node_payloads_by_type(tenant, "not-a-real-type", 32)) == []

        for s in {e.source for e in graph.edges}:
            got = [json.loads(p) for p in backend.iter_edge_payloads_by_source(tenant, s, 32)]
            want = [e.to_dict() for e in graph.edges_from(s)]
            assert got == want, f"edges_from parity diverged for source {s}"
        for t in {e.target for e in graph.edges}:
            got = [json.loads(p) for p in backend.iter_edge_payloads_by_target(tenant, t, 32)]
            want = [e.to_dict() for e in graph.edges_to(t)]
            assert got == want, f"edges_to parity diverged for target {t}"
    finally:
        backend.close()


def test_postgres_random_access_reads_are_tenant_scoped() -> None:
    wsid = f"ra-iso-{uuid.uuid4().hex}"
    backend = _PostgresWorkspaceBackend(_DSN, wsid)
    alpha = GraphBuildWorkspace(backend, tenant_id="alpha")
    beta = GraphBuildWorkspace(backend, tenant_id="beta")
    try:
        alpha.add_nodes([UnifiedNode(id="shared:1", entity_type=EntityType.AGENT, label="alpha-agent")])
        beta.add_nodes([UnifiedNode(id="shared:1", entity_type=EntityType.AGENT, label="beta-agent")])
        alpha.add_edges([UnifiedEdge(source="shared:1", target="a2", relationship=RelationshipType.DEPENDS_ON)])
        beta.add_edges([UnifiedEdge(source="shared:1", target="b2", relationship=RelationshipType.DEPENDS_ON)])

        assert json.loads(backend.get_node_payload("alpha", "shared:1"))["label"] == "alpha-agent"
        assert json.loads(backend.get_node_payload("beta", "shared:1"))["label"] == "beta-agent"

        a_by_type = [json.loads(p) for p in backend.iter_node_payloads_by_type("alpha", EntityType.AGENT.value, 8)]
        assert [n["label"] for n in a_by_type] == ["alpha-agent"]
        a_edges = [json.loads(p) for p in backend.iter_edge_payloads_by_source("alpha", "shared:1", 8)]
        assert [e["target"] for e in a_edges] == ["a2"]
        b_edges = [json.loads(p) for p in backend.iter_edge_payloads_by_target("beta", "b2", 8)]
        assert [e["source"] for e in b_edges] == ["shared:1"]
    finally:
        backend.close()  # DELETE by workspace_id clears both tenants' rows


def test_postgres_workspace_tenant_isolation() -> None:
    wsid = f"iso-{uuid.uuid4().hex}"
    backend_a = _PostgresWorkspaceBackend(_DSN, wsid)
    alpha = GraphBuildWorkspace(backend_a, tenant_id="alpha")
    beta = GraphBuildWorkspace(_PostgresWorkspaceBackend(_DSN, wsid), tenant_id="beta")
    try:
        alpha.add_nodes([UnifiedNode(id="shared:1", entity_type=EntityType.AGENT, label="alpha-agent")])
        alpha.add_nodes([UnifiedNode(id="a-only", entity_type=EntityType.VULNERABILITY, label="a")])
        beta.add_nodes([UnifiedNode(id="shared:1", entity_type=EntityType.AGENT, label="beta-agent")])

        alpha_nodes = {n.id: n.label for n in alpha.iter_nodes()}
        beta_nodes = {n.id: n.label for n in beta.iter_nodes()}
        assert alpha_nodes["shared:1"] == "alpha-agent"
        assert beta_nodes["shared:1"] == "beta-agent"
        assert "a-only" in alpha_nodes and "a-only" not in beta_nodes
    finally:
        alpha.close()  # DELETE by workspace_id clears both tenants' rows


_CHILD_WRITER = """
import os, sys
from agent_bom.graph.build_workspace import GraphBuildWorkspace, _PostgresWorkspaceBackend
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType

dsn = os.environ["AGENT_BOM_POSTGRES_URL"]
wsid, tenant, lo, hi = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
ws = GraphBuildWorkspace(_PostgresWorkspaceBackend(dsn, wsid), tenant_id=tenant, batch_size=50)
# NOTE: no ws.close() — close() drops the workspace rows; the parent reads them.
ws.add_nodes(
    UnifiedNode(id=f"n:{i}", entity_type=EntityType.VULNERABILITY, label=f"L{i}", severity="high")
    for i in range(lo, hi)
)
ws._backend._conn.close()
"""


def test_postgres_workspace_cross_process_writers() -> None:
    wsid = f"xproc-{uuid.uuid4().hex}"
    tenant = "t1"
    env = {**os.environ, "AGENT_BOM_POSTGRES_URL": _DSN}

    # Two separate OS processes write disjoint node ranges to the SAME workspace,
    # plus an overlapping id ("n:500") both write to (idempotency under a race).
    procs = [
        subprocess.Popen([sys.executable, "-c", _CHILD_WRITER, wsid, tenant, "0", "501"], env=env),
        subprocess.Popen([sys.executable, "-c", _CHILD_WRITER, wsid, tenant, "500", "1000"], env=env),
    ]
    rcs = [p.wait(timeout=120) for p in procs]
    assert rcs == [0, 0], f"child writers failed: {rcs}"

    reader = _PostgresWorkspaceBackend(_DSN, wsid)
    read = GraphBuildWorkspace(reader, tenant_id=tenant, batch_size=100)
    try:
        ids = [n.id for n in read.iter_nodes()]
        # Every row lands exactly once — no loss, no duplicate/fork under the
        # concurrent cross-process write to a shared key.
        assert len(ids) == len(set(ids)), "duplicate rows: concurrent writers forked the workspace"
        assert set(ids) == {f"n:{i}" for i in range(1000)}, "cross-process writes lost or leaked rows"
        assert read.node_count() == 1000
    finally:
        reader.close()
