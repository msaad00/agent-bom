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
