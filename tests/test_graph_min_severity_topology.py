"""A `min_severity` floor must narrow findings without dropping topology.

Only finding-like nodes (vulnerabilities, misconfigurations, drift incidents)
carry a severity. A severity floor should drop the low-severity findings while
keeping the context graph around them — agents, servers, packages, resources,
identities — so the operator still sees the paths that lead to the high-severity
findings instead of a scatter of disconnected dots. Regression guard for the
SQL paging/stats path, which previously applied ``severity_id >= floor`` to
every node and collapsed a populated estate to a single node.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.graph import EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode


def _estate(scan_id: str = "sev-topo") -> UnifiedGraph:
    g = UnifiedGraph(scan_id=scan_id, tenant_id="default")
    g.add_node(UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="billing-agent"))
    g.add_node(UnifiedNode(id="server:fs", entity_type=EntityType.SERVER, label="mcp-fs"))
    g.add_node(UnifiedNode(id="pkg:express", entity_type=EntityType.PACKAGE, label="express@4"))
    g.add_node(UnifiedNode(id="cloud:bucket", entity_type=EntityType.CLOUD_RESOURCE, label="pii-bucket"))
    # findings carry severity
    g.add_node(UnifiedNode(id="vuln:crit", entity_type=EntityType.VULNERABILITY, label="CVE-CRIT", severity="critical", risk_score=9.5))
    g.add_node(UnifiedNode(id="vuln:low", entity_type=EntityType.VULNERABILITY, label="CVE-LOW", severity="low", risk_score=2.0))
    g.add_edge(UnifiedEdge(source="agent:a", target="server:fs", relationship=RelationshipType.USES))
    g.add_edge(UnifiedEdge(source="server:fs", target="pkg:express", relationship=RelationshipType.DEPENDS_ON))
    g.add_edge(UnifiedEdge(source="pkg:express", target="vuln:crit", relationship=RelationshipType.VULNERABLE_TO))
    g.add_edge(UnifiedEdge(source="pkg:express", target="vuln:low", relationship=RelationshipType.VULNERABLE_TO))
    return g


@pytest.fixture
def store(tmp_path: Path) -> SQLiteGraphStore:
    s = SQLiteGraphStore(tmp_path / "graph.db")
    s.save_graph(_estate())
    return s


def test_page_nodes_keeps_topology_above_severity_floor(store: SQLiteGraphStore):
    # high floor (rank 4) — keep the critical finding, drop the low one,
    # keep every non-finding context node.
    _scan, _created, nodes, total, _cursor = store.page_nodes(tenant_id="default", min_severity_rank=4, limit=100)
    ids = {n.id for n in nodes}
    assert total == len(nodes)
    # topology preserved
    assert {"agent:a", "server:fs", "pkg:express", "cloud:bucket"} <= ids
    # high-severity finding kept, low-severity finding dropped
    assert "vuln:crit" in ids
    assert "vuln:low" not in ids


def test_page_nodes_no_floor_returns_everything(store: SQLiteGraphStore):
    _scan, _created, nodes, _total, _cursor = store.page_nodes(tenant_id="default", min_severity_rank=0, limit=100)
    assert {"vuln:crit", "vuln:low"} <= {n.id for n in nodes}


def test_snapshot_stats_reflect_topology_under_floor(store: SQLiteGraphStore):
    stats = store.snapshot_stats(tenant_id="default", min_severity_rank=4)
    node_types = stats["node_types"]
    # context node types survive the floor
    assert node_types.get("agent") == 1
    assert node_types.get("server") == 1
    assert node_types.get("cloud_resource") == 1
    # only the high-severity finding remains
    assert node_types.get("vulnerability") == 1
