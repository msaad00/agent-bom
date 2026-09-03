"""Add durable owner-fenced execution leases.

Revision ID: 20260903_01
Revises: 20260901_01
"""

from alembic import op

revision = "20260903_01"
down_revision = "20260901_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Some long-lived installations were stamped at the baseline while runtime
    # bootstrap DDL was incomplete. Own the full table contract here before
    # advertising idempotency v2 so a fresh/rolling migration can never publish
    # a version marker for columns, RLS, or grants that do not exist.
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS idempotency_keys (
            endpoint TEXT NOT NULL,
            tenant_id TEXT NOT NULL,
            source_id TEXT NOT NULL,
            idempotency_key TEXT NOT NULL,
            request_hash TEXT NOT NULL DEFAULT '',
            response_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            reservation_owner TEXT NOT NULL DEFAULT '',
            lease_expires_at TEXT NOT NULL DEFAULT '',
            PRIMARY KEY (endpoint, tenant_id, source_id, idempotency_key)
        )
        """
    )
    op.execute("ALTER TABLE idempotency_keys ADD COLUMN IF NOT EXISTS reservation_owner TEXT NOT NULL DEFAULT ''")
    op.execute("ALTER TABLE idempotency_keys ADD COLUMN IF NOT EXISTS lease_expires_at TEXT NOT NULL DEFAULT ''")
    op.execute("CREATE INDEX IF NOT EXISTS idx_idempotency_created_at ON idempotency_keys(created_at)")
    op.execute("ALTER TABLE idempotency_keys ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE idempotency_keys FORCE ROW LEVEL SECURITY")
    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_policies
                WHERE schemaname = current_schema()
                  AND tablename = 'idempotency_keys'
                  AND policyname = 'idempotency_keys_tenant_isolation'
            ) THEN
                CREATE POLICY idempotency_keys_tenant_isolation ON idempotency_keys
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
                GRANT SELECT, INSERT, UPDATE, DELETE ON idempotency_keys TO agent_bom_app;
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_bom_rls_maintenance') THEN
                GRANT SELECT, INSERT, UPDATE, DELETE ON idempotency_keys TO agent_bom_rls_maintenance;
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_bom_readonly') THEN
                GRANT SELECT ON idempotency_keys TO agent_bom_readonly;
            END IF;
        END
        $$
        """
    )
    op.execute("ALTER TABLE graph_correlation_runs ADD COLUMN IF NOT EXISTS execution_owner TEXT NOT NULL DEFAULT ''")
    op.execute("ALTER TABLE graph_correlation_runs ADD COLUMN IF NOT EXISTS execution_lease_expires_at TEXT NOT NULL DEFAULT ''")
    op.execute(
        "INSERT INTO control_plane_schema_versions(component, version, updated_at) VALUES "
        "('idempotency', 2, NOW()), ('graph', 4, NOW()) "
        "ON CONFLICT(component) DO UPDATE SET "
        "version = GREATEST(control_plane_schema_versions.version, EXCLUDED.version), updated_at = EXCLUDED.updated_at"
    )


def downgrade() -> None:
    return
