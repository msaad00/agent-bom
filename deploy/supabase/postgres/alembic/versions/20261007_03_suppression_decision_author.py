"""Record who asserted a suppression decision so four-eyes approval excludes them."""

from alembic import op

revision = "20261007_03"
down_revision = "20261007_02"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        DO $$
        BEGIN
            IF to_regclass('exceptions') IS NOT NULL THEN
                ALTER TABLE exceptions ADD COLUMN IF NOT EXISTS decided_by TEXT NOT NULL DEFAULT '';
                UPDATE control_plane_schema_versions SET version=3,updated_at=now()
                    WHERE component='exceptions' AND version < 3;
            END IF;
        END
        $$
    """)


def downgrade() -> None:
    raise NotImplementedError("Retain suppression decision authorship; restore a reviewed backup for rollback")
