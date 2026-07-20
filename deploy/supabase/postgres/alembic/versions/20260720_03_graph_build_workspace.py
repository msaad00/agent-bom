"""Provision the bounded graph build workspace for DML-only runtimes.

Revision ID: 20260720_03
Revises: 20260720_02
"""

from __future__ import annotations

from alembic import op

revision = "20260720_03"
down_revision = "20260720_02"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # TEXT preserves the exact serialized JSON bytes used by the graph parity
    # contract; JSONB would normalize key ordering during the round-trip.
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS graph_build_workspace_nodes (
            workspace_id TEXT NOT NULL,
            tenant_id TEXT NOT NULL,
            node_id TEXT NOT NULL,
            seq BIGSERIAL,
            payload TEXT NOT NULL,
            entity_type TEXT NOT NULL DEFAULT '',
            PRIMARY KEY (workspace_id, tenant_id, node_id)
        )
        """
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS graph_build_workspace_edges (
            workspace_id TEXT NOT NULL,
            tenant_id TEXT NOT NULL,
            edge_key TEXT NOT NULL,
            seq BIGSERIAL,
            payload TEXT NOT NULL,
            source_id TEXT NOT NULL DEFAULT '',
            target_id TEXT NOT NULL DEFAULT '',
            PRIMARY KEY (workspace_id, tenant_id, edge_key)
        )
        """
    )
    for statement in (
        "CREATE INDEX IF NOT EXISTS idx_gbw_nodes_seq ON graph_build_workspace_nodes (workspace_id, tenant_id, seq)",
        "CREATE INDEX IF NOT EXISTS idx_gbw_edges_seq ON graph_build_workspace_edges (workspace_id, tenant_id, seq)",
        "CREATE INDEX IF NOT EXISTS idx_gbw_nodes_type ON graph_build_workspace_nodes (workspace_id, tenant_id, entity_type, seq)",
        "CREATE INDEX IF NOT EXISTS idx_gbw_edges_source ON graph_build_workspace_edges (workspace_id, tenant_id, source_id, seq)",
        "CREATE INDEX IF NOT EXISTS idx_gbw_edges_target ON graph_build_workspace_edges (workspace_id, tenant_id, target_id, seq)",
    ):
        op.execute(statement)


def downgrade() -> None:
    # Workspace rows are disposable, but dropping shared tables during rollback
    # could destroy an in-flight build. Retain the schema and require explicit
    # operator cleanup if a deployment truly needs removal.
    raise NotImplementedError("Graph build workspace tables are retained on downgrade.")
