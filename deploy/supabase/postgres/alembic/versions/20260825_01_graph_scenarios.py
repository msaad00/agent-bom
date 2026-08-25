"""Add tenant-scoped proposed graph scenarios.

Revision ID: 20260825_01
Revises: 20260823_01
"""

from __future__ import annotations

from alembic import op

revision = "20260825_01"
down_revision = "20260823_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS graph_scenarios (
            id TEXT NOT NULL,
            tenant_id TEXT NOT NULL,
            base_scan_id TEXT NOT NULL,
            revision INTEGER NOT NULL CHECK (revision >= 1),
            name TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            operations JSONB NOT NULL,
            assumptions JSONB NOT NULL DEFAULT '[]'::jsonb,
            created_by TEXT NOT NULL DEFAULT '',
            provenance JSONB NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (id, tenant_id)
        )
        """
    )
    op.execute(
        """CREATE INDEX IF NOT EXISTS idx_graph_scenarios_tenant_updated
           ON graph_scenarios(tenant_id, updated_at DESC, id DESC)"""
    )
    op.execute("ALTER TABLE graph_scenarios ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE graph_scenarios FORCE ROW LEVEL SECURITY")
    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_policies
                WHERE schemaname = 'public'
                  AND tablename = 'graph_scenarios'
                  AND policyname = 'graph_scenarios_tenant_isolation'
            ) THEN
                CREATE POLICY graph_scenarios_tenant_isolation ON graph_scenarios
                    USING (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant())
                    WITH CHECK (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant());
            END IF;
        END
        $$
        """
    )
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_bom_app') THEN
                GRANT SELECT, INSERT, UPDATE, DELETE ON graph_scenarios TO agent_bom_app;
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_bom_rls_maintenance') THEN
                GRANT SELECT, INSERT, UPDATE, DELETE ON graph_scenarios TO agent_bom_rls_maintenance;
            END IF;
        END
        $$
        """
    )
    op.execute(
        """
        INSERT INTO control_plane_schema_versions(component, version, updated_at)
        VALUES ('graph_scenarios', 1, now())
        ON CONFLICT(component) DO UPDATE SET
            version = EXCLUDED.version,
            updated_at = EXCLUDED.updated_at
        """
    )


def downgrade() -> None:
    # Customer-authored architecture scenarios are retained across rollback.
    return
