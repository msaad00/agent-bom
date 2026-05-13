"""Add benchmark-backed indexes for Postgres graph hot paths."""

from __future__ import annotations

from alembic import op

# revision identifiers, used by Alembic.
revision = "20260513_01"
down_revision = "20260416_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_pg_graph_nodes_scan_id_cover
        ON graph_nodes(tenant_id, scan_id, id) INCLUDE (attributes)
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_pg_graph_edges_scan_source_traversable
        ON graph_edges(tenant_id, scan_id, source_id)
        WHERE traversable = 1
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_pg_attack_paths_source_risk
        ON attack_paths(tenant_id, scan_id, source_node, composite_risk DESC, target_node)
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_pg_graph_node_search_trgm
        ON graph_node_search USING gin (search_text gin_trgm_ops)
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_pg_graph_node_search_lower_trgm
        ON graph_node_search USING gin (LOWER(search_text) gin_trgm_ops)
        """
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_pg_graph_node_search_lower_trgm")
    op.execute("DROP INDEX IF EXISTS idx_pg_graph_node_search_trgm")
    op.execute("DROP INDEX IF EXISTS idx_pg_attack_paths_source_risk")
    op.execute("DROP INDEX IF EXISTS idx_pg_graph_edges_scan_source_traversable")
    op.execute("DROP INDEX IF EXISTS idx_pg_graph_nodes_scan_id_cover")
