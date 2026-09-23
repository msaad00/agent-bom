"""Persist tenant-scoped export destinations on Postgres."""

from alembic import op

revision = "20260923_01"
down_revision = "20260911_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
CREATE TABLE IF NOT EXISTS export_destinations (
 id TEXT NOT NULL, tenant_id TEXT NOT NULL, kind TEXT NOT NULL,
 display_name TEXT NOT NULL, config JSONB NOT NULL DEFAULT '{}'::jsonb,
 secret_encrypted TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'pending',
 status_detail TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
 last_run_at TEXT, last_run_status TEXT, PRIMARY KEY (tenant_id, id)
);
CREATE INDEX IF NOT EXISTS idx_export_dest_tenant ON export_destinations(tenant_id, created_at);
    """)
    op.execute("ALTER TABLE export_destinations ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE export_destinations FORCE ROW LEVEL SECURITY")
    op.execute("""
    DO $$ BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname=current_schema()
        AND tablename='export_destinations' AND policyname='export_destinations_tenant_isolation') THEN
        CREATE POLICY export_destinations_tenant_isolation ON export_destinations
          USING (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant())
          WITH CHECK (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant());
      END IF;
      IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='agent_bom_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON export_destinations TO agent_bom_app;
      END IF;
      IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='agent_bom_rls_maintenance') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON export_destinations TO agent_bom_rls_maintenance;
      END IF;
      IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='agent_bom_readonly') THEN
        GRANT SELECT ON export_destinations TO agent_bom_readonly;
      END IF;
    END $$;
    """)
    op.execute("""INSERT INTO control_plane_schema_versions(component,version)
                  VALUES ('export_destinations',1)
                  ON CONFLICT(component) DO UPDATE SET version=excluded.version,updated_at=now()""")


def downgrade() -> None:
    # Preserve encrypted destination configuration on downgrade.
    pass
