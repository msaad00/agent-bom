"""Persist tenant ingest counters in the ledger transaction.

Drain older writers before upgrading: they do not maintain durable counters.
Existing tenant counts bootstrap lazily on their first serialized ingest.
"""

from alembic import op

from agent_bom.api.storage.finding_ingest_state import INGEST_STATE_DDL

revision = "20260929_01"
down_revision = "20260928_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(INGEST_STATE_DDL)
    op.execute("ALTER TABLE hub_ledger_ingest_state ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE hub_ledger_ingest_state FORCE ROW LEVEL SECURITY")
    op.execute("DROP POLICY IF EXISTS hub_ledger_ingest_state_tenant_isolation ON hub_ledger_ingest_state")
    op.execute("""CREATE POLICY hub_ledger_ingest_state_tenant_isolation ON hub_ledger_ingest_state
        USING (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant())
        WITH CHECK (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant())""")
    op.execute("""DO $$ BEGIN
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_bom_app') THEN
            GRANT SELECT, INSERT, UPDATE, DELETE ON hub_ledger_ingest_state TO agent_bom_app;
        END IF;
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_bom_rls_maintenance') THEN
            GRANT SELECT, INSERT, UPDATE, DELETE ON hub_ledger_ingest_state TO agent_bom_rls_maintenance;
        END IF;
    END $$""")
    op.execute("""INSERT INTO control_plane_schema_versions(component, version, updated_at)
        VALUES ('compliance_hub', 3, now()) ON CONFLICT(component)
        DO UPDATE SET version=GREATEST(control_plane_schema_versions.version, 3), updated_at=now()""")


def downgrade() -> None:
    raise NotImplementedError("Ledger counters require compatible writers; restore a pre-upgrade backup for rollback")
