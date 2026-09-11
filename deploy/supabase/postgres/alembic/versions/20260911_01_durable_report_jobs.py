"""Persist fenced report claims with tenant RLS and atomic admission.

Revision ID: 20260911_01
Revises: 20260908_01
"""

from alembic import op

revision = "20260911_01"
down_revision = "20260908_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS report_jobs (
            job_id TEXT NOT NULL, tenant_id TEXT NOT NULL, status TEXT NOT NULL,
            created_at TEXT NOT NULL, started_at TEXT, completed_at TEXT,
            lease_token TEXT, lease_expires_at DOUBLE PRECISION,
            attempts INTEGER NOT NULL DEFAULT 0, error TEXT, data TEXT NOT NULL, PRIMARY KEY (tenant_id, job_id)
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_report_tenant_status ON report_jobs(tenant_id, status)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_report_claim ON report_jobs(status, lease_expires_at, created_at)")
    op.execute("ALTER TABLE report_jobs ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE report_jobs FORCE ROW LEVEL SECURITY")
    op.execute("""
        CREATE POLICY report_jobs_tenant_isolation ON report_jobs
        USING (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant())
        WITH CHECK (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant())
    """)
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON report_jobs TO agent_bom_rls_maintenance")
    op.execute("""
        DO $$ BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_bom_app') THEN
                GRANT SELECT, INSERT, UPDATE, DELETE ON report_jobs TO agent_bom_app;
            END IF;
        END $$;
    """)
    op.execute("""
        INSERT INTO control_plane_schema_versions(component, version, updated_at)
        VALUES ('report_jobs', 1, NOW()) ON CONFLICT(component) DO UPDATE
        SET version = GREATEST(control_plane_schema_versions.version, EXCLUDED.version), updated_at = NOW()
    """)


def downgrade() -> None:
    # Additive migration: preserve queued work and completed artifacts on rollback.
    return
