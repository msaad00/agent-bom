"""Make managed-identity profile bindings migration-owned and unambiguous.

Revision ID: 20260728_01
Revises: 20260727_01
"""

from __future__ import annotations

from alembic import op

revision = "20260728_01"
down_revision = "20260727_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Legacy distribution-only configurations remain deliberately unbound.
    # New profile-aware writers persist the lookup fields beside the JSON
    # document so tenant/identity resolution is indexed and enforceable by the
    # database rather than a capped presentation-list scan.
    op.execute("ALTER TABLE mcp_client_configs ADD COLUMN IF NOT EXISTS identity_id TEXT")
    op.execute("ALTER TABLE mcp_client_configs ADD COLUMN IF NOT EXISTS issuer TEXT NOT NULL DEFAULT ''")
    op.execute("ALTER TABLE mcp_client_configs ADD COLUMN IF NOT EXISTS environment TEXT NOT NULL DEFAULT ''")
    op.execute("ALTER TABLE mcp_client_configs ADD COLUMN IF NOT EXISTS status TEXT")
    op.execute("ALTER TABLE mcp_client_configs ADD COLUMN IF NOT EXISTS revision INTEGER")
    op.execute("ALTER TABLE mcp_client_configs ADD COLUMN IF NOT EXISTS updated_at TEXT")
    op.execute(
        """
        UPDATE mcp_client_configs
        SET identity_id = COALESCE(identity_id, ''),
            status = COALESCE(status, CASE WHEN revoked THEN 'revoked' ELSE 'active' END),
            revision = COALESCE(revision, 1),
            updated_at = COALESCE(updated_at, created_at)
        WHERE status IS NULL OR revision IS NULL OR updated_at IS NULL
        """
    )
    op.execute("ALTER TABLE mcp_client_configs ALTER COLUMN identity_id SET DEFAULT ''")
    op.execute("ALTER TABLE mcp_client_configs ALTER COLUMN identity_id SET NOT NULL")
    op.execute("ALTER TABLE mcp_client_configs ALTER COLUMN status SET DEFAULT 'active'")
    op.execute("ALTER TABLE mcp_client_configs ALTER COLUMN status SET NOT NULL")
    op.execute("ALTER TABLE mcp_client_configs ALTER COLUMN revision SET DEFAULT 1")
    op.execute("ALTER TABLE mcp_client_configs ALTER COLUMN revision SET NOT NULL")
    op.execute(
        "ALTER TABLE mcp_client_configs ALTER COLUMN updated_at "
        "SET DEFAULT to_char(now() AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')"
    )
    op.execute("ALTER TABLE mcp_client_configs ALTER COLUMN updated_at SET NOT NULL")
    op.execute(
        """
        DO $$
        BEGIN
          IF NOT EXISTS (
            SELECT 1 FROM pg_constraint
            WHERE conrelid = 'mcp_client_configs'::regclass
              AND conname = 'mcp_client_configs_status_valid'
          ) THEN
            ALTER TABLE mcp_client_configs
              ADD CONSTRAINT mcp_client_configs_status_valid
              CHECK (status IN ('active', 'disabled', 'revoked'));
          END IF;
          IF NOT EXISTS (
            SELECT 1 FROM pg_constraint
            WHERE conrelid = 'mcp_client_configs'::regclass
              AND conname = 'mcp_client_configs_revision_positive'
          ) THEN
            ALTER TABLE mcp_client_configs
              ADD CONSTRAINT mcp_client_configs_revision_positive
              CHECK (revision >= 1);
          END IF;
        END $$
        """
    )
    op.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_mcp_client_configs_active_identity
        ON mcp_client_configs (tenant_id, identity_id)
        WHERE identity_id IS NOT NULL AND btrim(identity_id) <> '' AND status = 'active' AND revoked = FALSE
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_mcp_client_configs_identity_history
        ON mcp_client_configs (tenant_id, identity_id, updated_at DESC)
        WHERE identity_id IS NOT NULL AND btrim(identity_id) <> ''
        """
    )

    # Reassert the existing security contract after widening the table. ALTER
    # TABLE preserves RLS and grants in Postgres; these idempotent statements
    # also repair pre-authority development databases before recording v2.
    op.execute("ALTER TABLE mcp_client_configs ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE mcp_client_configs FORCE ROW LEVEL SECURITY")
    op.execute(
        """
        DO $$
        BEGIN
          IF NOT EXISTS (
            SELECT 1 FROM pg_policies
            WHERE schemaname = current_schema()
              AND tablename = 'mcp_client_configs'
              AND policyname = 'mcp_client_configs_tenant_isolation'
          ) THEN
            CREATE POLICY mcp_client_configs_tenant_isolation ON mcp_client_configs
              USING (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant())
              WITH CHECK (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant());
          END IF;
        END $$
        """
    )
    op.execute(
        """
        DO $$
        BEGIN
          IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_bom_app') THEN
            GRANT SELECT, INSERT, UPDATE, DELETE ON mcp_client_configs TO agent_bom_app;
          END IF;
        END $$
        """
    )
    op.execute(
        """
        INSERT INTO control_plane_schema_versions(component, version, updated_at)
        VALUES ('mcp_client_configs', 2, now())
        ON CONFLICT(component) DO UPDATE SET
            version = EXCLUDED.version,
            updated_at = EXCLUDED.updated_at
        """
    )


def downgrade() -> None:
    # Profile bindings and revisions are customer governance records. Keep the
    # additive columns and uniqueness contract on rollback rather than destroy
    # them or make an older process accept ambiguous live bindings.
    raise NotImplementedError("MCP profile binding authority is additive and intentionally irreversible.")
