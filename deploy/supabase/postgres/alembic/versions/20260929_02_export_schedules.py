"""Persist tenant-scoped export schedules on Postgres."""

from alembic import op

revision = "20260929_02"
down_revision = "20260929_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
CREATE TABLE IF NOT EXISTS export_schedules (
 schedule_id TEXT NOT NULL, tenant_id TEXT NOT NULL,
 enabled BOOLEAN NOT NULL DEFAULT TRUE, next_run TEXT, data JSONB NOT NULL,
 PRIMARY KEY (tenant_id, schedule_id)
);
CREATE INDEX IF NOT EXISTS idx_export_sched_due ON export_schedules(enabled, next_run, schedule_id);
    """)
    op.execute("ALTER TABLE export_schedules ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE export_schedules FORCE ROW LEVEL SECURITY")
    op.execute("""
    DO $$ BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname=current_schema()
        AND tablename='export_schedules' AND policyname='export_schedules_tenant_isolation') THEN
        CREATE POLICY export_schedules_tenant_isolation ON export_schedules
          USING (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant())
          WITH CHECK (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant());
      END IF;
      IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='agent_bom_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON export_schedules TO agent_bom_app;
      END IF;
      IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='agent_bom_rls_maintenance') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON export_schedules TO agent_bom_rls_maintenance;
      END IF;
      IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='agent_bom_readonly') THEN
        GRANT SELECT ON export_schedules TO agent_bom_readonly;
      END IF;
    END $$;
    """)
    op.execute("""INSERT INTO control_plane_schema_versions(component,version)
                  VALUES ('export_schedules',1)
                  ON CONFLICT(component) DO UPDATE SET version=excluded.version,updated_at=now()""")


def downgrade() -> None:
    # Preserve scheduled-export configuration and outcomes on downgrade.
    pass
