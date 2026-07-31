"""Force tenant RLS on the ``teams`` FK root.

``teams`` was the only tenant-columned relation with ``relrowsecurity = f``,
while ``agent_bom_app`` holds ``DELETE,INSERT,SELECT,UPDATE`` on it and every
tenant table references it ``ON DELETE CASCADE``. An ordinary app-role session
bound to one tenant could therefore enumerate all tenants and delete another
tenant's root row, cascading its entire dataset away with no database backstop.

The maintenance purge in ``api/tenant_lifecycle`` already runs inside
``bypass_tenant_rls()`` + ``_maintenance_connection()``, so ``abom_rls_bypass()``
keeps that path working.

Revision ID: 20260730_02
Revises: 20260730_01
"""

from __future__ import annotations

from alembic import op

revision = "20260730_02"
down_revision = "20260730_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        DO $migration$
        BEGIN
            IF to_regclass('public.teams') IS NULL THEN
                RETURN;
            END IF;

            ALTER TABLE teams ENABLE ROW LEVEL SECURITY;
            ALTER TABLE teams FORCE ROW LEVEL SECURITY;

            IF NOT EXISTS (
                SELECT 1 FROM pg_policies
                WHERE schemaname = current_schema()
                  AND tablename = 'teams'
                  AND policyname = 'teams_tenant_isolation'
            ) THEN
                CREATE POLICY teams_tenant_isolation ON teams
                    USING (public.abom_rls_bypass() OR team_id = public.abom_current_tenant())
                    WITH CHECK (public.abom_rls_bypass() OR team_id = public.abom_current_tenant());
            END IF;
        END
        $migration$;
        """
    )


def downgrade() -> None:
    # Deliberately irreversible, matching 20260729_03: removing tenant isolation
    # from the FK root would reopen a cross-tenant destruction path during
    # rollback.
    pass
