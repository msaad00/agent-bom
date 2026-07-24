"""Make runtime workload evidence migration-owned and tenant-isolated.

Revision ID: 20260724_01
Revises: 20260721_01
"""

from __future__ import annotations

from alembic import op

revision = "20260724_01"
down_revision = "20260721_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS runtime_workload_evidence (
            tenant_id TEXT NOT NULL,
            provider TEXT NOT NULL,
            account_id TEXT NOT NULL,
            workload_ref TEXT NOT NULL,
            dedup_key TEXT NOT NULL,
            workload_id TEXT NOT NULL,
            signal_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            observed_at TEXT NOT NULL,
            source_id TEXT NOT NULL,
            source_kind TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            PRIMARY KEY (tenant_id, provider, account_id, workload_ref, dedup_key)
        )
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_runtime_workload_evidence_tenant_observed_dedup
            ON runtime_workload_evidence (tenant_id, observed_at DESC, dedup_key DESC)
        """
    )
    op.execute("DROP INDEX IF EXISTS idx_runtime_workload_evidence_tenant_time")
    op.execute("ALTER TABLE runtime_workload_evidence ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE runtime_workload_evidence FORCE ROW LEVEL SECURITY")
    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_policies
                WHERE schemaname = 'public'
                  AND tablename = 'runtime_workload_evidence'
                  AND policyname = 'runtime_workload_evidence_tenant_isolation'
            ) THEN
                CREATE POLICY runtime_workload_evidence_tenant_isolation
                    ON runtime_workload_evidence
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
                GRANT SELECT, INSERT, UPDATE, DELETE ON runtime_workload_evidence TO agent_bom_app;
            END IF;
        END
        $$
        """
    )
    op.execute(
        """
        INSERT INTO control_plane_schema_versions(component, version, updated_at)
        VALUES ('runtime_workload_evidence', 1, now())
        ON CONFLICT(component) DO UPDATE SET
            version = EXCLUDED.version,
            updated_at = EXCLUDED.updated_at
        """
    )


def downgrade() -> None:
    raise NotImplementedError("Runtime workload evidence schema authority is additive and intentionally irreversible.")
