"""Separate committed read revisions from retry/rollback ownership tokens.

Revision ID: 20260930_01
Revises: 20260929_04
"""

from alembic import op

revision = "20260930_01"
down_revision = "20260929_04"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        DO $$
        DECLARE previous_bypass TEXT := current_setting('app.bypass_rls', true);
        BEGIN
            IF to_regclass('public.graph_snapshots') IS NOT NULL THEN
                ALTER TABLE graph_snapshots ADD COLUMN IF NOT EXISTS read_revision TEXT NOT NULL DEFAULT '';
                PERFORM set_config('app.bypass_rls', '1', true);
                UPDATE graph_snapshots SET read_revision = replace(gen_random_uuid()::text, '-', '') WHERE read_revision = '';
                PERFORM set_config('app.bypass_rls', COALESCE(previous_bypass, '0'), true);
                UPDATE control_plane_schema_versions SET version=6,updated_at=now()
                    WHERE component='graph' AND version=5;
            END IF;
        END
        $$
    """)


def downgrade() -> None:
    op.execute("ALTER TABLE IF EXISTS graph_snapshots DROP COLUMN IF EXISTS read_revision")
    op.execute("UPDATE control_plane_schema_versions SET version=5,updated_at=now() WHERE component='graph' AND version=6")
