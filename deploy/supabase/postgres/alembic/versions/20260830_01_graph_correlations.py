"""Add immutable graph correlation runs and snapshot provenance.

Revision ID: 20260830_01
Revises: 20260827_01
"""

from __future__ import annotations

from alembic import op

revision = "20260830_01"
down_revision = "20260827_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        DO $$
        BEGIN
            IF to_regclass('public.graph_snapshots') IS NOT NULL THEN
                ALTER TABLE public.graph_snapshots
                    ADD COLUMN IF NOT EXISTS snapshot_kind TEXT NOT NULL DEFAULT 'scan'
                    CHECK (snapshot_kind IN ('scan', 'correlation'));
                ALTER TABLE public.graph_snapshots
                    ADD COLUMN IF NOT EXISTS correlation_id TEXT DEFAULT NULL;
                ALTER TABLE public.graph_snapshots
                    ADD COLUMN IF NOT EXISTS evidence_manifest_sha256 TEXT NOT NULL DEFAULT '';
            END IF;
        END
        $$
        """
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS graph_correlation_runs (
            correlation_id TEXT NOT NULL,
            tenant_id TEXT NOT NULL DEFAULT 'default',
            idempotency_key TEXT NOT NULL,
            name TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL CHECK (status IN ('pending', 'running', 'complete', 'failed')),
            max_age_hours INTEGER NOT NULL CHECK (max_age_hours BETWEEN 1 AND 8760),
            allow_stale INTEGER NOT NULL DEFAULT 0 CHECK (allow_stale IN (0, 1)),
            input_manifest TEXT NOT NULL DEFAULT '[]',
            manifest_sha256 TEXT NOT NULL DEFAULT '',
            output_scan_id TEXT NOT NULL DEFAULT '',
            failure_code TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            started_at TEXT NOT NULL DEFAULT '',
            completed_at TEXT NOT NULL DEFAULT '',
            PRIMARY KEY (correlation_id, tenant_id),
            UNIQUE (tenant_id, idempotency_key)
        )
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS idx_pg_graph_correlation_runs_recent ON graph_correlation_runs(tenant_id, created_at DESC)")
    op.execute("ALTER TABLE graph_correlation_runs ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE graph_correlation_runs FORCE ROW LEVEL SECURITY")
    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_policies
                WHERE schemaname = current_schema()
                  AND tablename = 'graph_correlation_runs'
                  AND policyname = 'graph_correlation_runs_tenant_isolation'
            ) THEN
                CREATE POLICY graph_correlation_runs_tenant_isolation ON graph_correlation_runs
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
                GRANT SELECT, INSERT, UPDATE, DELETE ON graph_correlation_runs TO agent_bom_app;
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_bom_rls_maintenance') THEN
                GRANT SELECT, INSERT, UPDATE, DELETE ON graph_correlation_runs TO agent_bom_rls_maintenance;
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_bom_readonly') THEN
                GRANT SELECT ON graph_correlation_runs TO agent_bom_readonly;
            END IF;
        END
        $$
        """
    )
    op.execute(
        """
        INSERT INTO control_plane_schema_versions(component, version, updated_at)
        VALUES ('graph', 2, now())
        ON CONFLICT(component) DO UPDATE SET
            version = GREATEST(control_plane_schema_versions.version, EXCLUDED.version),
            updated_at = EXCLUDED.updated_at
        """
    )


def downgrade() -> None:
    # Retain immutable evidence across rolling downgrades. Older runtimes ignore
    # the additive table and snapshot columns.
    return
