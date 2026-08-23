"""Persist attack-path reachability verdicts and their evidence basis.

Revision ID: 20260823_01
Revises: 20260819_01
"""

from __future__ import annotations

from alembic import op

revision = "20260823_01"
down_revision = "20260819_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE IF EXISTS attack_paths ADD COLUMN IF NOT EXISTS reachability TEXT DEFAULT 'unknown'")
    op.execute("ALTER TABLE IF EXISTS attack_paths ADD COLUMN IF NOT EXISTS reachability_basis TEXT DEFAULT '[]'")


def downgrade() -> None:
    # Additive compatibility columns are retained so a rolling downgrade does
    # not make a newer writer fail against an older application instance.
    return
