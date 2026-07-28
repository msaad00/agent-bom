"""Add the tenant-scoped durable gateway activity ledger.

Revision ID: 20260728_02
Revises: 20260728_01
"""

from __future__ import annotations

from alembic import op

revision = "20260728_02"
down_revision = "20260728_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS gateway_activity_events (
            tenant_id TEXT NOT NULL,
            event_id TEXT NOT NULL,
            ingest_ordinal BIGINT NOT NULL,
            event_timestamp TIMESTAMPTZ NOT NULL,
            ingested_at TIMESTAMPTZ NOT NULL,
            event_digest TEXT NOT NULL,
            data TEXT NOT NULL,
            PRIMARY KEY (tenant_id, event_id)
        )
        """
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS gateway_activity_sequences (
            tenant_id TEXT PRIMARY KEY,
            next_ordinal BIGINT NOT NULL CHECK (next_ordinal >= 1)
        )
        """
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS gateway_activity_tombstones (
            tenant_id TEXT NOT NULL,
            event_id TEXT NOT NULL,
            event_digest TEXT NOT NULL,
            pruned_ordinal BIGINT NOT NULL,
            PRIMARY KEY (tenant_id, event_id)
        )
        """
    )
    op.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_gateway_activity_events_tenant_ordinal "
        "ON gateway_activity_events(tenant_id, ingest_ordinal)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_gateway_activity_tombstones_tenant_ordinal "
        "ON gateway_activity_tombstones(tenant_id, pruned_ordinal)"
    )

    op.execute("ALTER TABLE gateway_activity_events ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE gateway_activity_events FORCE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE gateway_activity_sequences ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE gateway_activity_sequences FORCE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE gateway_activity_tombstones ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE gateway_activity_tombstones FORCE ROW LEVEL SECURITY")

    for table in (
        "gateway_activity_events",
        "gateway_activity_sequences",
        "gateway_activity_tombstones",
    ):
        op.execute(
            f"""
            DO $$
            BEGIN
              IF NOT EXISTS (
                SELECT 1 FROM pg_policies
                WHERE schemaname = current_schema()
                  AND tablename = '{table}'
                  AND policyname = '{table}_tenant_isolation'
              ) THEN
                CREATE POLICY {table}_tenant_isolation ON {table}
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
            GRANT SELECT, INSERT, UPDATE, DELETE ON gateway_activity_events TO agent_bom_app;
            GRANT SELECT, INSERT, UPDATE, DELETE ON gateway_activity_sequences TO agent_bom_app;
            GRANT SELECT, INSERT, UPDATE, DELETE ON gateway_activity_tombstones TO agent_bom_app;
          END IF;
        END $$
        """
    )
    op.execute(
        """
        INSERT INTO control_plane_schema_versions(component, version, updated_at)
        VALUES ('runtime_events', 2, now())
        ON CONFLICT(component) DO UPDATE SET
            version = EXCLUDED.version,
            updated_at = EXCLUDED.updated_at
        """
    )


def downgrade() -> None:
    # Gateway activity is governance evidence. Never destroy retained evidence
    # or its replay tombstones automatically during a binary rollback.
    raise NotImplementedError("Gateway activity ledger storage is additive and intentionally irreversible.")
