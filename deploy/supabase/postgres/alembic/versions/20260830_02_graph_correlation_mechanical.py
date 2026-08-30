"""Persist correlation manifests and per-hop attack-path evidence.

Revision ID: 20260830_02
Revises: 20260830_01
"""

from __future__ import annotations

from alembic import op

revision = "20260830_02"
down_revision = "20260830_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        DO $$
        BEGIN
            IF to_regclass('public.attack_paths') IS NOT NULL THEN
                ALTER TABLE public.attack_paths
                    ADD COLUMN IF NOT EXISTS hop_evidence TEXT DEFAULT '[]';
                ALTER TABLE public.attack_paths
                    ADD COLUMN IF NOT EXISTS analysis TEXT DEFAULT '{}';
            END IF;
        END
        $$
        """
    )
    op.execute(
        """
        DO $$
        BEGIN
            IF to_regclass('public.graph_correlation_runs') IS NOT NULL THEN
                ALTER TABLE public.graph_correlation_runs
                    ADD COLUMN IF NOT EXISTS result_manifest TEXT NOT NULL DEFAULT '{}';
            END IF;
        END
        $$
        """
    )
    op.execute(
        """
        INSERT INTO control_plane_schema_versions(component, version, updated_at)
        VALUES ('graph', 3, now())
        ON CONFLICT(component) DO UPDATE SET
            version = GREATEST(control_plane_schema_versions.version, EXCLUDED.version),
            updated_at = EXCLUDED.updated_at
        """
    )


def downgrade() -> None:
    # Retain provenance receipts across rolling downgrades. Older runtimes
    # ignore these additive columns.
    return
