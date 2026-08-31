"""Persist verified capability evidence for cloud connections.

Migration-owned Postgres deployments skip the runtime store's bootstrap DDL,
so both capability fields need an additive revision. Types and defaults match
the portable store contract and runtime-schema.sql exactly.

Revision ID: 20260830_03
Revises: 20260830_02
"""

from __future__ import annotations

from alembic import op

revision = "20260830_03"
down_revision = "20260830_02"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE IF EXISTS cloud_connections "
        "ADD COLUMN IF NOT EXISTS capability_probe_status TEXT NOT NULL DEFAULT 'not_run'"
    )
    op.execute(
        "ALTER TABLE IF EXISTS cloud_connections "
        "ADD COLUMN IF NOT EXISTS verified_capabilities TEXT NOT NULL DEFAULT '[]'"
    )
    op.execute(
        """
        INSERT INTO control_plane_schema_versions(component, version, updated_at)
        VALUES ('cloud_connections', 1, now())
        ON CONFLICT(component) DO UPDATE SET
            version = EXCLUDED.version,
            updated_at = EXCLUDED.updated_at
        """
    )


def downgrade() -> None:
    # These additive evidence columns are required by current readers. Keep
    # rolling downgrades non-destructive and compatible with mixed versions.
    return
