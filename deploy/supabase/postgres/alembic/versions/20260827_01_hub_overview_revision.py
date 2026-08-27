"""Add durable tenant revisions for compliance Overview snapshots.

Revision ID: 20260827_01
Revises: 20260825_01
"""

from __future__ import annotations

from alembic import op

revision = "20260827_01"
down_revision = "20260825_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS hub_overview_revisions (
            tenant_id TEXT PRIMARY KEY,
            revision BIGINT NOT NULL DEFAULT 0
        )
        """
    )
    op.execute("ALTER TABLE hub_overview_revisions ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE hub_overview_revisions FORCE ROW LEVEL SECURITY")
    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_policies
                WHERE schemaname = current_schema()
                  AND tablename = 'hub_overview_revisions'
                  AND policyname = 'hub_overview_revisions_tenant_isolation'
            ) THEN
                CREATE POLICY hub_overview_revisions_tenant_isolation ON hub_overview_revisions
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
                GRANT SELECT, INSERT, UPDATE, DELETE ON hub_overview_revisions TO agent_bom_app;
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_bom_rls_maintenance') THEN
                GRANT SELECT, INSERT, UPDATE, DELETE ON hub_overview_revisions TO agent_bom_rls_maintenance;
            END IF;
        END
        $$
        """
    )
    op.execute(
        """
        INSERT INTO control_plane_schema_versions(component, version, updated_at)
        VALUES ('compliance_hub', 2, now())
        ON CONFLICT(component) DO UPDATE SET
            version = GREATEST(control_plane_schema_versions.version, EXCLUDED.version),
            updated_at = EXCLUDED.updated_at
        """
    )


def downgrade() -> None:
    # Retain the revision row/table across rolling downgrades. Older application
    # versions ignore it; deleting it would reintroduce stale multi-worker reads.
    return
