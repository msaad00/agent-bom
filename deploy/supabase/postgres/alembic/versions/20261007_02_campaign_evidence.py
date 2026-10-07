"""Queue campaign reconciliation transactionally with source evidence."""

from alembic import op

from agent_bom.api.storage.campaign_schema import POSTGRES_CAMPAIGN_EVIDENCE_V1

revision = "20261007_02"
down_revision = "20261007_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(POSTGRES_CAMPAIGN_EVIDENCE_V1)


def downgrade() -> None:
    raise NotImplementedError("Preserve campaign evidence checkpoints; restore a reviewed backup for rollback")
