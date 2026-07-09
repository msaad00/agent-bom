from __future__ import annotations

from agent_bom.db import graph_store as sqlite_graph_store
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType


def test_load_graph_can_filter_edges_for_rollup(tmp_path) -> None:
    """Rollup only needs containment edges — skip the long tail at load time."""
    db = tmp_path / "rollup-load.db"
    with sqlite_graph_store.open_graph_db(db) as conn:
        g = UnifiedGraph(scan_id="rollup-load", tenant_id="default")
        g.add_node(UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="agent-a"))
        g.add_node(UnifiedNode(id="server:s", entity_type=EntityType.SERVER, label="server-s"))
        g.add_node(UnifiedNode(id="pkg:p", entity_type=EntityType.PACKAGE, label="pkg-p"))
        g.add_edge(UnifiedEdge(source="agent:a", target="server:s", relationship=RelationshipType.USES))
        g.add_edge(UnifiedEdge(source="server:s", target="pkg:p", relationship=RelationshipType.DEPENDS_ON))
        g.add_edge(UnifiedEdge(source="agent:a", target="server:s", relationship=RelationshipType.CONTAINS))
        sqlite_graph_store.save_graph(conn, g)
        conn.commit()

        full = sqlite_graph_store.load_graph(conn, tenant_id="default", scan_id="rollup-load")
        assert len(full.edges) == 3

        containment = sqlite_graph_store.load_graph(
            conn,
            tenant_id="default",
            scan_id="rollup-load",
            relationship_types=frozenset(
                {
                    RelationshipType.CONTAINS.value,
                    RelationshipType.HOSTS.value,
                    RelationshipType.OWNS.value,
                }
            ),
        )
        assert len(containment.edges) == 1
        assert containment.edges[0].relationship == RelationshipType.CONTAINS
        assert not containment.attack_paths

        g2 = UnifiedGraph(scan_id="rollup-owns", tenant_id="default")
        g2.add_node(UnifiedNode(id="account:aws:1", entity_type=EntityType.ACCOUNT, label="prod"))
        g2.add_node(
            UnifiedNode(id="cloud:aws:s3:b", entity_type=EntityType.CLOUD_RESOURCE, label="bucket")
        )
        g2.add_edge(
            UnifiedEdge(
                source="account:aws:1",
                target="cloud:aws:s3:b",
                relationship=RelationshipType.OWNS,
            )
        )
        sqlite_graph_store.save_graph(conn, g2)
        conn.commit()

        owns_only = sqlite_graph_store.load_graph(
            conn,
            tenant_id="default",
            scan_id="rollup-owns",
            relationship_types=frozenset(
                {
                    RelationshipType.CONTAINS.value,
                    RelationshipType.HOSTS.value,
                    RelationshipType.OWNS.value,
                }
            ),
        )
        assert len(owns_only.edges) == 1
        assert owns_only.edges[0].relationship == RelationshipType.OWNS
