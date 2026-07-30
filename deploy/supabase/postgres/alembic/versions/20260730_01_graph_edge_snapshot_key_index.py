"""Index complete edge identities within a tenant snapshot.

The reconciliation path joins consecutive snapshots by the three edge identity
columns while tenant and scan RLS predicates remain active.  The historical
primary key starts with the identity columns, and the existing tenant/scan
indexes cover only one endpoint, so neither gives the planner one exact lookup
path for the full predicate.

Revision ID: 20260730_01
Revises: 20260729_03
"""

from __future__ import annotations

from alembic import op

revision = "20260730_01"
down_revision = "20260729_03"
branch_labels = None
depends_on = None


def upgrade() -> None:
    relation = op.get_bind().exec_driver_sql("SELECT to_regclass('public.graph_edges')").scalar()
    if relation is None:
        return

    with op.get_context().autocommit_block():
        op.execute(
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_pg_graph_edges_snapshot_key "
            "ON graph_edges(tenant_id, scan_id, source_id, target_id, relationship)"
        )


def downgrade() -> None:
    with op.get_context().autocommit_block():
        op.execute("DROP INDEX CONCURRENTLY IF EXISTS idx_pg_graph_edges_snapshot_key")
