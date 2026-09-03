"""Add durable owner-fenced execution leases.

Revision ID: 20260903_01
Revises: 20260901_01
"""

from alembic import op

revision = "20260903_01"
down_revision = "20260901_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE idempotency_keys ADD COLUMN IF NOT EXISTS reservation_owner TEXT NOT NULL DEFAULT ''")
    op.execute("ALTER TABLE idempotency_keys ADD COLUMN IF NOT EXISTS lease_expires_at TEXT NOT NULL DEFAULT ''")
    op.execute("ALTER TABLE graph_correlation_runs ADD COLUMN IF NOT EXISTS execution_owner TEXT NOT NULL DEFAULT ''")
    op.execute("ALTER TABLE graph_correlation_runs ADD COLUMN IF NOT EXISTS execution_lease_expires_at TEXT NOT NULL DEFAULT ''")
    op.execute(
        "INSERT INTO control_plane_schema_versions(component, version, updated_at) VALUES "
        "('idempotency', 2, NOW()), ('graph', 4, NOW()) "
        "ON CONFLICT(component) DO UPDATE SET "
        "version = GREATEST(control_plane_schema_versions.version, EXCLUDED.version), updated_at = EXCLUDED.updated_at"
    )


def downgrade() -> None:
    return
