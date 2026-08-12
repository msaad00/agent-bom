"""Materialise the entity-type breakdown Postgres snapshot stats kept recomputing.

``graph_snapshots`` already carries ``node_count``, ``edge_count`` and
``risk_summary`` (the severity breakdown) from write time, and the SQLite
backend also carries ``node_type_counts`` and serves both breakdowns from the
row. Postgres had neither the column nor the lookup, so every unfiltered
``snapshot_stats`` — which ``GET /v1/graph`` calls on every page view — re-ran
two GROUP BYs over ``graph_nodes``, growing with the estate.

Additive and nullable on purpose: snapshots written before this migration read
NULL and fall back to the live GROUP BY, so no backfill is required and a
rollback loses only the cache.

Revision ID: 20260812_01
Revises: 20260810_01
"""

from __future__ import annotations

from alembic import op

revision = "20260812_01"
down_revision = "20260810_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE IF EXISTS graph_snapshots ADD COLUMN IF NOT EXISTS node_type_counts TEXT DEFAULT NULL")


def downgrade() -> None:
    # Non-destructive, matching 20260724_02: the snapshot writer inserts this
    # column on every save, so dropping it on rollback would leave an otherwise
    # healthy database unwritable by the running application. The reader already
    # treats NULL as "not cached" and falls back to the live GROUP BY, so
    # leaving the column costs nothing.
    return
