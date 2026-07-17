"""Persist per-snapshot graph-analysis execution status.

Revision ID: 20260717_02
Revises: 20260717_01
"""

from __future__ import annotations

from alembic import op

revision = "20260717_02"
down_revision = "20260717_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE graph_snapshots ADD COLUMN IF NOT EXISTS analysis_status JSONB NOT NULL DEFAULT '{}'::jsonb")


def downgrade() -> None:
    op.execute("ALTER TABLE graph_snapshots DROP COLUMN IF EXISTS analysis_status")
