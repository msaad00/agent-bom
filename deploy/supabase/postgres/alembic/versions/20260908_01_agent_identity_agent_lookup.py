"""Persist the agent-keyed managed identity lookup used by runtime enforcement.

Revision ID: 20260908_01
Revises: 20260903_01
"""

from alembic import op

revision = "20260908_01"
down_revision = "20260903_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE agent_identities ADD COLUMN IF NOT EXISTS agent_id TEXT NOT NULL DEFAULT ''")
    op.execute(
        "UPDATE agent_identities SET agent_id = TRIM(data::jsonb ->> 'agent_id') "
        "WHERE agent_id = '' AND data::jsonb ->> 'agent_id' IS NOT NULL"
    )
    op.execute("CREATE INDEX IF NOT EXISTS idx_agent_identities_agent ON agent_identities(tenant_id, agent_id)")
    op.execute(
        "INSERT INTO control_plane_schema_versions(component, version, updated_at) VALUES ('agent_identities', 2, NOW()) "
        "ON CONFLICT(component) DO UPDATE SET "
        "version = GREATEST(control_plane_schema_versions.version, EXCLUDED.version), updated_at = EXCLUDED.updated_at"
    )


def downgrade() -> None:
    # Older clients ignore the additive lookup column. Preserve identity rows
    # and revocation evidence during an application rollback.
    return
