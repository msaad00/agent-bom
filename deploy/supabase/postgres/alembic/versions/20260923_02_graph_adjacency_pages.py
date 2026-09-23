"""Persist snapshot generations and index bounded incident-edge pages.

Revision ID: 20260923_02
Revises: 20260923_01
"""

from alembic import op

revision = "20260923_02"
down_revision = "20260923_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE graph_snapshots ADD COLUMN IF NOT EXISTS snapshot_generation TEXT NOT NULL DEFAULT ''")
    op.execute("UPDATE graph_snapshots SET snapshot_generation = replace(gen_random_uuid()::text, '-', '') WHERE snapshot_generation = ''")
    op.execute(
        "INSERT INTO control_plane_schema_versions(component,version,updated_at) VALUES ('graph',5,now()) "
        "ON CONFLICT(component) DO UPDATE SET "
        "version=GREATEST(control_plane_schema_versions.version,excluded.version),updated_at=excluded.updated_at"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_pg_adjacency_out ON graph_edges "
        '(tenant_id, scan_id, source_id COLLATE "C", target_id COLLATE "C", relationship COLLATE "C")'
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_pg_adjacency_in ON graph_edges "
        '(tenant_id, scan_id, target_id COLLATE "C", source_id COLLATE "C", relationship COLLATE "C")'
    )


def downgrade() -> None:
    op.execute("ALTER TABLE graph_snapshots DROP COLUMN IF EXISTS snapshot_generation")
    op.execute("UPDATE control_plane_schema_versions SET version=4,updated_at=now() WHERE component='graph' AND version=5")
    op.execute("DROP INDEX IF EXISTS idx_pg_adjacency_in")
    op.execute("DROP INDEX IF EXISTS idx_pg_adjacency_out")
