"""Scope jobs and every dependent job reference to its tenant.

Drain all writers/workers before migration: old ON CONFLICT(job_id) writers are
incompatible. Foreign-key validation fails closed on inconsistent child ownership.
The transaction preserves data, queue ownership/expiry, RLS and existing indexes.
"""

from alembic import op

from agent_bom.api.storage.jobs_schema import POSTGRES_TENANT_KEYS

revision = "20260928_01"
down_revision = "20260927_03"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(POSTGRES_TENANT_KEYS)
    op.execute("""INSERT INTO control_plane_schema_versions(component, version, updated_at)
        VALUES ('scan_jobs', 2, now()) ON CONFLICT(component)
        DO UPDATE SET version=GREATEST(control_plane_schema_versions.version, 2), updated_at=now()""")


def downgrade() -> None:
    raise NotImplementedError("Tenant job keys are forward-only; restoring a global key could discard tenant data")
