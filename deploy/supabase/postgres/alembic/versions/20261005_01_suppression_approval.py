"""Record explicit suppression approval without activating legacy rows."""

from alembic import op

revision = "20261005_01"
down_revision = "20260930_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        DO $$
        BEGIN
            IF to_regclass('exceptions') IS NOT NULL THEN
                ALTER TABLE exceptions ADD COLUMN IF NOT EXISTS approval_version INTEGER NOT NULL DEFAULT 0;
                UPDATE control_plane_schema_versions SET version=2,updated_at=now()
                    WHERE component='exceptions' AND version < 2;
            END IF;
        END
        $$
    """)


def downgrade() -> None:
    raise NotImplementedError("Retain approval history; restore a reviewed backup for rollback")
