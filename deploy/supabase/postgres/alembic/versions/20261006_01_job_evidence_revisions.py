"""Track committed job evidence revisions across control-plane replicas."""

from alembic import op

from agent_bom.api.storage.job_revisions import POSTGRES_JOB_REVISIONS_V1

revision = "20261006_01"
down_revision = "20261005_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(POSTGRES_JOB_REVISIONS_V1)
    op.execute("UPDATE control_plane_schema_versions SET version=3,updated_at=now() WHERE component='scan_jobs' AND version < 3")


def downgrade() -> None:
    raise NotImplementedError("Retain durable evidence revisions; restore a reviewed backup for rollback")
