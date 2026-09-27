"""Retain tenant-scoped endpoint connections, collection receipts and device evidence."""

from alembic import op

revision = "20260927_03"
down_revision = "20260927_02"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
CREATE TABLE IF NOT EXISTS endpoint_connections (
    tenant_id TEXT NOT NULL, id TEXT NOT NULL, data TEXT NOT NULL, secret TEXT NOT NULL,
    owner TEXT NOT NULL DEFAULT '', lease_until DOUBLE PRECISION NOT NULL DEFAULT 0,
    PRIMARY KEY(tenant_id,id)
);
CREATE TABLE IF NOT EXISTS endpoint_syncs (
    tenant_id TEXT NOT NULL, connection_id TEXT NOT NULL, run_id TEXT NOT NULL,
    started_at TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY(tenant_id,connection_id,run_id)
);
CREATE INDEX IF NOT EXISTS idx_endpoint_sync_latest ON endpoint_syncs(tenant_id,connection_id,started_at);
CREATE TABLE IF NOT EXISTS endpoint_devices (
    tenant_id TEXT NOT NULL, connection_id TEXT NOT NULL, run_id TEXT NOT NULL,
    device_id TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY(tenant_id,connection_id,run_id,device_id)
);
CREATE INDEX IF NOT EXISTS idx_endpoint_device_lookup ON endpoint_devices(tenant_id,device_id,connection_id,run_id);
CREATE TABLE IF NOT EXISTS endpoint_sync_events (
    tenant_id TEXT NOT NULL, connection_id TEXT NOT NULL, event_id TEXT NOT NULL,
    recorded_at TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY(tenant_id,connection_id,event_id)
);
CREATE INDEX IF NOT EXISTS idx_endpoint_sync_events ON endpoint_sync_events(tenant_id,connection_id,recorded_at);
CREATE TABLE IF NOT EXISTS endpoint_agent_bindings (
    tenant_id TEXT NOT NULL, device_id TEXT NOT NULL, agent_id TEXT NOT NULL,
    data TEXT NOT NULL, PRIMARY KEY(tenant_id,device_id,agent_id)
);
DO $$ DECLARE tab TEXT; BEGIN
    FOREACH tab IN ARRAY ARRAY[
        'endpoint_connections','endpoint_syncs','endpoint_devices','endpoint_sync_events','endpoint_agent_bindings'
    ] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', tab);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', tab);
        IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname='public' AND tablename=tab AND policyname=tab||'_tenant_isolation') THEN
            EXECUTE format('CREATE POLICY %I ON %I USING (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant()) '
                || 'WITH CHECK (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant())', tab||'_tenant_isolation', tab);
        END IF;
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='agent_bom_app') THEN
            EXECUTE format('GRANT SELECT, INSERT, UPDATE ON %I TO agent_bom_app', tab);
            EXECUTE format('REVOKE DELETE ON %I FROM agent_bom_app', tab);
            IF tab='endpoint_sync_events' THEN
                REVOKE UPDATE ON endpoint_sync_events FROM agent_bom_app;
            END IF;
        END IF;
    END LOOP;
END $$;
INSERT INTO control_plane_schema_versions(component,version,updated_at) VALUES ('endpoint_connectors',1,now())
ON CONFLICT(component) DO UPDATE SET version=GREATEST(control_plane_schema_versions.version,1),updated_at=now();
    """)


def downgrade() -> None:
    raise RuntimeError("Endpoint evidence retention requires an operator-reviewed export and migration; automatic deletion is disabled")
