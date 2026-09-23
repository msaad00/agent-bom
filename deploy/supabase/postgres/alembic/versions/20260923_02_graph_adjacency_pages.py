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
    # Minimal stamped legacy deployments may own only queue tables. Graph DDL
    # belongs to the baseline: do not synthesize a partial graph or promote its
    # readiness marker when that baseline is absent.
    op.execute("""
        DO $$
        DECLARE previous_bypass TEXT := current_setting('app.bypass_rls', true);
        BEGIN
            IF to_regclass('public.graph_snapshots') IS NOT NULL THEN
                ALTER TABLE graph_snapshots ADD COLUMN IF NOT EXISTS snapshot_generation TEXT NOT NULL DEFAULT '';
                -- FORCE RLS applies to the non-superuser migration owner too.
                -- The trusted maintenance role is still required by the policy.
                PERFORM set_config('app.bypass_rls', '1', true);
                UPDATE graph_snapshots SET snapshot_generation = replace(gen_random_uuid()::text, '-', '')
                    WHERE snapshot_generation = '';
                PERFORM set_config('app.bypass_rls', COALESCE(previous_bypass, '0'), true);
            END IF;
            IF to_regclass('public.graph_edges') IS NOT NULL THEN
                CREATE INDEX IF NOT EXISTS idx_pg_adjacency_out ON graph_edges
                    (tenant_id, scan_id, source_id COLLATE "C", target_id COLLATE "C", relationship COLLATE "C");
                CREATE INDEX IF NOT EXISTS idx_pg_adjacency_in ON graph_edges
                    (tenant_id, scan_id, target_id COLLATE "C", source_id COLLATE "C", relationship COLLATE "C");
            END IF;
            IF to_regclass('public.graph_snapshots') IS NOT NULL AND to_regclass('public.graph_edges') IS NOT NULL THEN
                UPDATE control_plane_schema_versions SET version=5,updated_at=now()
                WHERE component='graph' AND version>=4 AND version<5;
            END IF;
        END
        $$
    """)


def downgrade() -> None:
    op.execute("ALTER TABLE IF EXISTS graph_snapshots DROP COLUMN IF EXISTS snapshot_generation")
    op.execute("UPDATE control_plane_schema_versions SET version=4,updated_at=now() WHERE component='graph' AND version=5")
    op.execute("DROP INDEX IF EXISTS idx_pg_adjacency_in")
    op.execute("DROP INDEX IF EXISTS idx_pg_adjacency_out")
