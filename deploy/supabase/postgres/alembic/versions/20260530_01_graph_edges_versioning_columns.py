"""Add graph_edges versioning + provenance columns to the migration path.

These six columns (schema v3) were only created by the application bootstrap in
``api/postgres_graph.py`` (``ALTER TABLE ... ADD COLUMN IF NOT EXISTS``). Fresh
Postgres deployments provisioned purely from ``init.sql`` plus Alembic — or any
read-only / migration-only path that never runs the app bootstrap — were missing
them, causing ``column "valid_from" does not exist`` on edge reads/writes.

``init.sql`` now defines them in the baseline; this migration covers databases
that were created before that change. All statements are idempotent.
"""

from __future__ import annotations

from alembic import op

# revision identifiers, used by Alembic.
revision = "20260530_01"
down_revision = "20260513_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE graph_edges ADD COLUMN IF NOT EXISTS valid_from TEXT DEFAULT ''")
    op.execute("ALTER TABLE graph_edges ADD COLUMN IF NOT EXISTS valid_to TEXT DEFAULT NULL")
    op.execute("ALTER TABLE graph_edges ADD COLUMN IF NOT EXISTS confidence DOUBLE PRECISION DEFAULT 1.0")
    op.execute("ALTER TABLE graph_edges ADD COLUMN IF NOT EXISTS provenance TEXT DEFAULT '{}'")
    op.execute("ALTER TABLE graph_edges ADD COLUMN IF NOT EXISTS source_scan_id TEXT DEFAULT ''")
    op.execute("ALTER TABLE graph_edges ADD COLUMN IF NOT EXISTS source_run_id TEXT DEFAULT ''")
    # Backfill: empty valid_from is interpreted as first_seen; source_scan_id
    # defaults to the owning scan. Mirrors api/postgres_graph.py bootstrap.
    op.execute("UPDATE graph_edges SET valid_from = first_seen WHERE valid_from = '' OR valid_from IS NULL")
    op.execute("UPDATE graph_edges SET source_scan_id = scan_id WHERE source_scan_id = '' OR source_scan_id IS NULL")
    op.execute("CREATE INDEX IF NOT EXISTS idx_pg_graph_edges_valid ON graph_edges(tenant_id, valid_from, valid_to)")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_pg_graph_edges_valid")
    op.execute("ALTER TABLE graph_edges DROP COLUMN IF EXISTS source_run_id")
    op.execute("ALTER TABLE graph_edges DROP COLUMN IF EXISTS source_scan_id")
    op.execute("ALTER TABLE graph_edges DROP COLUMN IF EXISTS provenance")
    op.execute("ALTER TABLE graph_edges DROP COLUMN IF EXISTS confidence")
    op.execute("ALTER TABLE graph_edges DROP COLUMN IF EXISTS valid_to")
    op.execute("ALTER TABLE graph_edges DROP COLUMN IF EXISTS valid_from")
