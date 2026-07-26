"""Make ticketing persistence migration-owned and tenant-isolated.

Revision ID: 20260726_01
Revises: 20260724_03
"""

from __future__ import annotations

from alembic import op

revision = "20260726_01"
down_revision = "20260724_03"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS ticketing_connections (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            provider TEXT NOT NULL,
            transport TEXT NOT NULL,
            auth_method TEXT NOT NULL,
            display_name TEXT NOT NULL,
            endpoint TEXT NOT NULL DEFAULT '',
            secret_encrypted TEXT NOT NULL DEFAULT '',
            auth_params TEXT NOT NULL DEFAULT '{}',
            status TEXT NOT NULL DEFAULT 'pending',
            status_detail TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS ticket_links (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            connection_id TEXT NOT NULL,
            dedupe_key TEXT NOT NULL,
            provider TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'open',
            external_id TEXT NOT NULL DEFAULT '',
            key TEXT NOT NULL DEFAULT '',
            url TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE (tenant_id, connection_id, dedupe_key)
        )
        """
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_ticketing_connections_tenant "
        "ON ticketing_connections(tenant_id, created_at)"
    )
    op.execute("CREATE INDEX IF NOT EXISTS idx_ticket_links_tenant ON ticket_links(tenant_id, created_at)")
    op.execute("ALTER TABLE ticketing_connections ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE ticketing_connections FORCE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE ticket_links ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE ticket_links FORCE ROW LEVEL SECURITY")
    op.execute(
        """
        DO $$
        BEGIN
          IF NOT EXISTS (
            SELECT 1 FROM pg_policies
            WHERE schemaname = current_schema()
              AND tablename = 'ticketing_connections'
              AND policyname = 'ticketing_connections_tenant_isolation'
          ) THEN
            CREATE POLICY ticketing_connections_tenant_isolation ON ticketing_connections
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
          IF NOT EXISTS (
            SELECT 1 FROM pg_policies
            WHERE schemaname = current_schema()
              AND tablename = 'ticket_links'
              AND policyname = 'ticket_links_tenant_isolation'
          ) THEN
            CREATE POLICY ticket_links_tenant_isolation ON ticket_links
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
            GRANT SELECT, INSERT, UPDATE, DELETE ON ticketing_connections TO agent_bom_app;
            GRANT SELECT, INSERT, UPDATE, DELETE ON ticket_links TO agent_bom_app;
          END IF;
        END $$
        """
    )
    op.execute(
        """
        INSERT INTO control_plane_schema_versions(component, version, updated_at)
        VALUES ('ticketing_connections', 1, now())
        ON CONFLICT(component) DO UPDATE SET
            version = EXCLUDED.version,
            updated_at = EXCLUDED.updated_at
        """
    )


def downgrade() -> None:
    # Connections and ticket links are customer records. Preserve them on rollback.
    pass
