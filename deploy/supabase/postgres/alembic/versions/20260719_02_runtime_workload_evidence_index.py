"""Make the runtime workload-evidence tenant read sargable.

P1 (2026-07-19 audit): PostgresRuntimeWorkloadEvidenceStore created an index on
(tenant_id, workload_id, observed_at DESC), but list_for_tenant orders by
(observed_at DESC, dedup_key DESC) under a leading tenant predicate. The old
index could not satisfy that sort, so at scale every tenant read was a seq-scan +
sort. Replace it with (tenant_id, observed_at DESC, dedup_key DESC).

The table is created lazily by the store's init_schema (CREATE TABLE IF NOT
EXISTS), so it may not exist in a fresh migration-owned schema yet; guard every
DDL with to_regclass so this is a safe no-op until the store has run once.

Revision ID: 20260719_02
Revises: 20260719_01
"""

from __future__ import annotations

from alembic import op

revision = "20260719_02"
down_revision = "20260719_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        DO $$
        BEGIN
            IF to_regclass('public.runtime_workload_evidence') IS NOT NULL THEN
                CREATE INDEX IF NOT EXISTS idx_runtime_workload_evidence_tenant_observed_dedup
                    ON runtime_workload_evidence (tenant_id, observed_at DESC, dedup_key DESC);
                DROP INDEX IF EXISTS idx_runtime_workload_evidence_tenant_time;
            END IF;
        END $$;
        """
    )


def downgrade() -> None:
    op.execute(
        """
        DO $$
        BEGIN
            IF to_regclass('public.runtime_workload_evidence') IS NOT NULL THEN
                CREATE INDEX IF NOT EXISTS idx_runtime_workload_evidence_tenant_time
                    ON runtime_workload_evidence (tenant_id, workload_id, observed_at DESC);
                DROP INDEX IF EXISTS idx_runtime_workload_evidence_tenant_observed_dedup;
            END IF;
        END $$;
        """
    )
