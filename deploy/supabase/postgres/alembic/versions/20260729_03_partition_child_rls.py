"""Force tenant RLS on every existing tenant-scoped partition child.

Revision ID: 20260729_03
Revises: 20260729_02
"""

from __future__ import annotations

from alembic import op

revision = "20260729_03"
down_revision = "20260729_02"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        DO $migration$
        DECLARE
            child_record RECORD;
            tenant_column TEXT;
        BEGIN
            FOR child_record IN
                SELECT parent.relname AS parent_name, child.relname AS child_name
                FROM pg_inherits inh
                JOIN pg_class parent ON parent.oid = inh.inhparent
                JOIN pg_class child ON child.oid = inh.inhrelid
                JOIN pg_namespace n ON n.oid = parent.relnamespace
                WHERE n.nspname = current_schema()
                  AND parent.relname IN ('audit_log', 'hub_findings_current_observations')
            LOOP
                tenant_column := CASE
                    WHEN child_record.parent_name = 'audit_log' THEN 'team_id'
                    ELSE 'tenant_id'
                END;
                EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', child_record.child_name);
                EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', child_record.child_name);
                IF NOT EXISTS (
                    SELECT 1 FROM pg_policies
                    WHERE schemaname = current_schema()
                      AND tablename = child_record.child_name
                      AND policyname = child_record.child_name || '_tenant_isolation'
                ) THEN
                    EXECUTE format(
                        'CREATE POLICY %I ON %I USING (public.abom_rls_bypass() OR %I = public.abom_current_tenant()) '
                        'WITH CHECK (public.abom_rls_bypass() OR %I = public.abom_current_tenant())',
                        child_record.child_name || '_tenant_isolation',
                        child_record.child_name,
                        tenant_column,
                        tenant_column
                    );
                END IF;
            END LOOP;
        END
        $migration$;
        """
    )


def downgrade() -> None:
    # Deliberately irreversible: removing tenant isolation from direct child
    # tables would reopen a cross-tenant access path during rollback.
    pass
