"""Retain agent BOM history and immutable lifecycle references.

Revision ID: 20260927_01
Revises: 20260924_01
"""

from alembic import op

revision = "20260927_01"
down_revision = "20260924_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
CREATE TABLE IF NOT EXISTS agent_lifecycle_records (
    tenant_id TEXT NOT NULL, kind TEXT NOT NULL, record_id TEXT NOT NULL,
    agent_id TEXT NOT NULL, recorded_at TEXT NOT NULL, data TEXT NOT NULL,
    PRIMARY KEY (tenant_id, kind, record_id)
);
CREATE INDEX IF NOT EXISTS idx_agent_lifecycle_history
    ON agent_lifecycle_records (tenant_id, kind, agent_id, recorded_at, record_id);
CREATE TABLE IF NOT EXISTS agent_bom_snapshots (
    tenant_id TEXT NOT NULL, snapshot_id TEXT NOT NULL, document TEXT NOT NULL,
    PRIMARY KEY (tenant_id, snapshot_id)
);
ALTER TABLE agent_lifecycle_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_lifecycle_records FORCE ROW LEVEL SECURITY;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname='public'
                   AND tablename='agent_lifecycle_records' AND policyname='agent_lifecycle_records_tenant_isolation') THEN
        CREATE POLICY agent_lifecycle_records_tenant_isolation ON agent_lifecycle_records
            USING (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant())
            WITH CHECK (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant());
    END IF;
END $$;
ALTER TABLE agent_bom_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_bom_snapshots FORCE ROW LEVEL SECURITY;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname='public'
                   AND tablename='agent_bom_snapshots' AND policyname='agent_bom_snapshots_tenant_isolation') THEN
        CREATE POLICY agent_bom_snapshots_tenant_isolation ON agent_bom_snapshots
            USING (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant())
            WITH CHECK (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant());
    END IF;
END $$;
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='agent_bom_app') THEN
        GRANT SELECT, INSERT, UPDATE ON agent_lifecycle_records TO agent_bom_app;
        GRANT SELECT, INSERT ON agent_bom_snapshots TO agent_bom_app;
        REVOKE DELETE ON agent_lifecycle_records FROM agent_bom_app;
        REVOKE UPDATE, DELETE ON agent_bom_snapshots FROM agent_bom_app;
    END IF;
END $$;
INSERT INTO control_plane_schema_versions(component,version,updated_at)
VALUES ('agent_lifecycle',1,now())
ON CONFLICT(component) DO UPDATE SET
    version=GREATEST(control_plane_schema_versions.version,excluded.version),
    updated_at=excluded.updated_at;
    """)


def downgrade() -> None:
    # Evidence-preserving rollback: older binaries ignore these additive tables.
    # Do not drop retained snapshots or immutable run references on rollback.
    pass
