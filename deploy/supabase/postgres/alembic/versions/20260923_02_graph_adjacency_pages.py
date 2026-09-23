"""Index bounded incident-edge keyset pages in both recorded directions.

Revision ID: 20260923_02
Revises: 20260923_01
"""

from alembic import op

revision = "20260923_02"
down_revision = "20260923_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_pg_adjacency_out ON graph_edges "
        '(tenant_id, scan_id, source_id COLLATE "C", target_id COLLATE "C", relationship COLLATE "C")'
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_pg_adjacency_in ON graph_edges "
        '(tenant_id, scan_id, target_id COLLATE "C", source_id COLLATE "C", relationship COLLATE "C")'
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_pg_adjacency_in")
    op.execute("DROP INDEX IF EXISTS idx_pg_adjacency_out")
