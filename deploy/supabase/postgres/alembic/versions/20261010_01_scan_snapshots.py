"""Add tenant-scoped materialized scan finding snapshots (ADR-015)."""

from alembic import op

from agent_bom.api.postgres_scan_snapshot import POSTGRES_SCAN_SNAPSHOTS_V1

revision = "20261010_01"
down_revision = "20261007_03"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(POSTGRES_SCAN_SNAPSHOTS_V1)


def downgrade() -> None:
    raise NotImplementedError("Snapshots are derived data; disable AGENT_BOM_SCAN_SNAPSHOTS and restore a reviewed backup for rollback")
