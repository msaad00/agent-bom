"""Ship the cloud_connections scope / scan-mode columns in migrations.

``api/postgres_connection.py`` reads and writes ``inventory_scope``,
``scan_mode`` and ``auto_scan_on_create`` on every Connections list, get and
put, but only the store's dev-mode bootstrap DDL created them. On a
migration-owned deployment (``AGENT_BOM_POSTGRES_URL`` set →
``ensure_postgres_schema_version`` returns False → the bootstrap DDL is
skipped) the columns were absent, so the first Connections request raised
``UndefinedColumn: column "inventory_scope" does not exist``. Same class as the
``20260719_03`` attack_paths repair.

Types and defaults mirror the store's own CREATE TABLE and the now-corrected
``runtime-schema.sql`` exactly, so a fresh install and an upgraded one converge
on one shape. ``ADD COLUMN IF NOT EXISTS`` keeps each statement a no-op on
databases the runtime bootstrap already widened, and idempotent on rerun.

Revision ID: 20260724_02
Revises: 20260724_01
"""

from __future__ import annotations

from alembic import op

revision = "20260724_02"
down_revision = "20260724_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE IF EXISTS cloud_connections ADD COLUMN IF NOT EXISTS inventory_scope TEXT NOT NULL DEFAULT 'account'")
    op.execute("ALTER TABLE IF EXISTS cloud_connections ADD COLUMN IF NOT EXISTS scan_mode TEXT NOT NULL DEFAULT 'full'")
    op.execute("ALTER TABLE IF EXISTS cloud_connections ADD COLUMN IF NOT EXISTS auto_scan_on_create BOOLEAN NOT NULL DEFAULT TRUE")
    op.execute(
        """
        INSERT INTO control_plane_schema_versions(component, version, updated_at)
        VALUES ('cloud_connections', 1, now())
        ON CONFLICT(component) DO UPDATE SET
            version = EXCLUDED.version,
            updated_at = EXCLUDED.updated_at
        """
    )


def downgrade() -> None:
    # Additive compatibility columns the current readers depend on. Dropping
    # them on rollback would leave an otherwise healthy database unreadable by
    # the running application and would destroy per-connection scope and
    # cadence intent. Keep the downgrade non-destructive, matching 20260719_03.
    pass
