"""Ship the attack_paths summary/exposure/technique columns in migrations.

P1 (2026-07-19 audit): ``api/postgres_graph.py`` reads and writes
``attack_paths.summary``, ``attack_paths.tool_exposure`` and
``attack_paths.technique_mappings``, but only the store's dev-mode bootstrap
DDL created them. Migration-owned deployments (AGENT_BOM_POSTGRES_URL set →
bootstrap DDL skipped) lacked the columns, so the first ``/v1/graph`` read
raised ``UndefinedColumn: column "summary" does not exist``.

Types and defaults mirror the store's own CREATE TABLE exactly (TEXT carrying
JSON text — the read path decodes TEXT and native JSONB alike). Each statement
is idempotent: development databases bootstrapped by the store already carry
the columns.

Revision ID: 20260719_03
Revises: 20260719_02
"""

from __future__ import annotations

from alembic import op

revision = "20260719_03"
down_revision = "20260719_02"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE IF EXISTS attack_paths ADD COLUMN IF NOT EXISTS summary TEXT DEFAULT ''")
    op.execute("ALTER TABLE IF EXISTS attack_paths ADD COLUMN IF NOT EXISTS tool_exposure TEXT DEFAULT '[]'")
    op.execute("ALTER TABLE IF EXISTS attack_paths ADD COLUMN IF NOT EXISTS technique_mappings TEXT DEFAULT '[]'")


def downgrade() -> None:
    # These columns are additive compatibility fields used by newer readers.
    # Dropping them during rollback would make an otherwise healthy database
    # unreadable by the current application, and can destroy persisted evidence.
    # Keep the downgrade intentionally non-destructive; a future maintenance
    # migration may remove columns only with an explicit data-retention plan.
    pass
