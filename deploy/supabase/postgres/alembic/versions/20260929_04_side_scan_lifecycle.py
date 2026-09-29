"""Provision side-scan lifecycle state without runtime DDL privileges."""

from alembic import op

revision = "20260929_04"
down_revision = "20260929_03"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
CREATE TABLE IF NOT EXISTS side_scan_execution_state (
    execution_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, provider TEXT NOT NULL,
    account_id TEXT NOT NULL, target_id TEXT NOT NULL, idempotency_key TEXT NOT NULL,
    state_version INTEGER NOT NULL, cleanup_status TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL, payload_json TEXT NOT NULL,
    UNIQUE (tenant_id, provider, account_id, target_id, idempotency_key)
);
CREATE INDEX IF NOT EXISTS idx_side_scan_cleanup ON side_scan_execution_state (tenant_id, cleanup_status, updated_at);
CREATE INDEX IF NOT EXISTS idx_side_scan_recent ON side_scan_execution_state (tenant_id, updated_at DESC, execution_id DESC);
ALTER TABLE side_scan_execution_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE side_scan_execution_state FORCE ROW LEVEL SECURITY;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname='public'
                   AND tablename='side_scan_execution_state' AND policyname='side_scan_execution_state_tenant_isolation') THEN
        CREATE POLICY side_scan_execution_state_tenant_isolation ON side_scan_execution_state
            USING (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant())
            WITH CHECK (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant());
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='agent_bom_app') THEN
        GRANT SELECT, INSERT, UPDATE ON side_scan_execution_state TO agent_bom_app;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='agent_bom_rls_maintenance') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON side_scan_execution_state TO agent_bom_rls_maintenance;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='agent_bom_readonly') THEN
        GRANT SELECT ON side_scan_execution_state TO agent_bom_readonly;
    END IF;
END $$;
INSERT INTO control_plane_schema_versions(component,version,updated_at)
VALUES ('side_scan_lifecycle',1,now())
ON CONFLICT(component) DO UPDATE SET
    version=GREATEST(control_plane_schema_versions.version,excluded.version), updated_at=excluded.updated_at;
    """)


def downgrade() -> None:
    # Keep execution and cleanup evidence when application code is rolled back.
    pass
