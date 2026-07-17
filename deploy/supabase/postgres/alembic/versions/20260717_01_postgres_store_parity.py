"""Restore full-scope cost-budget primary-key parity.

Revision ID: 20260717_01
Revises: 20260705_01
"""

from __future__ import annotations

from alembic import op

revision = "20260717_01"
down_revision = "20260705_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE llm_cost_budgets ADD COLUMN IF NOT EXISTS owner TEXT NOT NULL DEFAULT ''")
    op.execute("ALTER TABLE llm_cost_budgets ADD COLUMN IF NOT EXISTS workflow TEXT NOT NULL DEFAULT ''")
    op.execute("""
        DO $$
        DECLARE
            current_pk TEXT;
        BEGIN
            SELECT c.conname INTO current_pk
            FROM pg_constraint c
            JOIN pg_class t ON t.oid = c.conrelid
            JOIN pg_namespace n ON n.oid = t.relnamespace
            WHERE t.relname = 'llm_cost_budgets'
              AND n.nspname = current_schema()
              AND c.contype = 'p';

            IF NOT EXISTS (
                SELECT 1
                FROM pg_constraint c
                JOIN pg_class t ON t.oid = c.conrelid
                JOIN pg_namespace n ON n.oid = t.relnamespace
                WHERE t.relname = 'llm_cost_budgets'
                  AND n.nspname = current_schema()
                  AND c.contype = 'p'
                  AND pg_get_constraintdef(c.oid) =
                      'PRIMARY KEY (tenant_id, agent, cost_center, owner, workflow)'
            ) THEN
                IF current_pk IS NOT NULL THEN
                    EXECUTE format(
                        'ALTER TABLE llm_cost_budgets DROP CONSTRAINT %I',
                        current_pk
                    );
                END IF;
                ALTER TABLE llm_cost_budgets
                    ADD PRIMARY KEY (tenant_id, agent, cost_center, owner, workflow);
            END IF;
        END
        $$;
    """)
    op.execute("DROP INDEX IF EXISTS uq_llm_cost_budgets_scope")
    op.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_llm_cost_budgets_scope "
        "ON llm_cost_budgets(tenant_id, agent, cost_center, owner, workflow)"
    )
    op.execute("ALTER TABLE IF EXISTS cloud_connections ADD COLUMN IF NOT EXISTS last_scan_id TEXT")


def downgrade() -> None:
    raise NotImplementedError(
        "The canonical budget scope cannot be narrowed without losing valid sibling budgets."
    )
