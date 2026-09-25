"""Persist optional metadata for comparable trend history.

Revision ID: 20260924_01
Revises: 20260923_02
"""

from alembic import op

revision = "20260924_01"
down_revision = "20260923_02"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        DO $$ BEGIN
            IF to_regclass('public.trend_history') IS NOT NULL THEN
                ALTER TABLE trend_history ADD COLUMN IF NOT EXISTS comparison_metadata TEXT NOT NULL DEFAULT '{}';
                UPDATE control_plane_schema_versions SET version=2,updated_at=now()
                WHERE component='trend_history' AND version=1;
            END IF;
        END $$
    """)


def downgrade() -> None:
    op.execute("ALTER TABLE IF EXISTS trend_history DROP COLUMN IF EXISTS comparison_metadata")
    op.execute("UPDATE control_plane_schema_versions SET version=1,updated_at=now() WHERE component='trend_history' AND version=2")
