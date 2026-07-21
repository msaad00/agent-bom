"""Enable FORCE RLS on graph build workspace staging tables.

Revision ID: 20260721_01
Revises: 20260720_03

The bounded graph producer stages nodes/edges in shared Postgres tables.
Application filters alone are not enough — enable the same tenant isolation
contract used by graph_nodes / graph_edges so a raw SELECT under tenant B
cannot read tenant A's workspace rows.
"""

from __future__ import annotations

from alembic import op

revision = "20260721_01"
down_revision = "20260720_03"
branch_labels = None
depends_on = None

_TABLES = (
    "graph_build_workspace_nodes",
    "graph_build_workspace_edges",
)


def upgrade() -> None:
    for table in _TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"""
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM pg_policies
                    WHERE schemaname = 'public'
                      AND tablename = '{table}'
                      AND policyname = '{table}_tenant_isolation'
                ) THEN
                    EXECUTE 'CREATE POLICY {table}_tenant_isolation ON {table}
                        USING (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant())
                        WITH CHECK (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant())';
                END IF;
            END
            $$;
            """
        )


def downgrade() -> None:
    for table in _TABLES:
        op.execute(f"DROP POLICY IF EXISTS {table}_tenant_isolation ON {table}")
        op.execute(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
