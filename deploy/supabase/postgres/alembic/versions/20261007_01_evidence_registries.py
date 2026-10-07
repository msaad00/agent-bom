"""Add shared tenant-scoped evidence registries."""

from alembic import op

from agent_bom.api.storage.registry_schema import registry_migration_ddl

revision = "20261007_01"
down_revision = "20261006_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(registry_migration_ddl())


def downgrade() -> None:
    raise NotImplementedError("Preserve registry evidence; restore a reviewed backup for rollback")
