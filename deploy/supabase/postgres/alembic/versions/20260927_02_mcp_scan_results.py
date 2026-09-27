"""Persist bounded MCP scan results with tenant RLS.

Revision ID: 20260927_02
Revises: 20260927_01
"""

from alembic import op

revision = "20260927_02"
down_revision = "20260927_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
CREATE TABLE IF NOT EXISTS mcp_scan_results (
    tenant_id TEXT NOT NULL, result_id TEXT NOT NULL, owner_digest TEXT NOT NULL,
    created_at DOUBLE PRECISION NOT NULL, expires_at DOUBLE PRECISION NOT NULL,
    data TEXT NOT NULL, PRIMARY KEY (tenant_id, result_id)
);
CREATE INDEX IF NOT EXISTS idx_mcp_result_expiry
    ON mcp_scan_results (tenant_id, expires_at, result_id);
CREATE INDEX IF NOT EXISTS idx_mcp_result_order
    ON mcp_scan_results (tenant_id, created_at DESC, result_id DESC);
ALTER TABLE mcp_scan_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE mcp_scan_results FORCE ROW LEVEL SECURITY;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname='public'
                   AND tablename='mcp_scan_results' AND policyname='mcp_scan_results_tenant_isolation') THEN
        CREATE POLICY mcp_scan_results_tenant_isolation ON mcp_scan_results
            USING (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant())
            WITH CHECK (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant());
    END IF;
END $$;
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='agent_bom_app') THEN
        GRANT SELECT, INSERT, DELETE ON mcp_scan_results TO agent_bom_app;
    END IF;
END $$;
INSERT INTO control_plane_schema_versions(component,version,updated_at)
VALUES ('mcp_scan_results',1,now())
ON CONFLICT(component) DO UPDATE SET
    version=GREATEST(control_plane_schema_versions.version,excluded.version),
    updated_at=excluded.updated_at;
    """)


def downgrade() -> None:
    # Additive rollback: retain cached results for compatible server replicas.
    pass
