"""Restore the audit hash-chain fork-guard unique index in the migration-owned schema.

The runtime store's _init_tables() early-returns when Postgres is authoritative
(#4232), so PostgresAuditLog._ensure_fork_guard_index() no longer runs there and
UNIQUE(team_id, prev_signature) existed in no authoritative SQL. Without it,
PostgresAuditLog.append (which has no in-process lock) cannot reject a concurrent
chain fork across uvicorn --workers N, weakening audit tamper-evidence.

Revision ID: 20260719_01
Revises: 20260718_01
"""

from __future__ import annotations

from alembic import op

revision = "20260719_01"
down_revision = "20260718_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # IF NOT EXISTS so this is a no-op on fresh deployments that already applied
    # the index from runtime-schema.sql, and idempotent on rerun. Pre-existing
    # forks in older data would make creation fail; mirror the store's defensive
    # posture (append still retries) rather than aborting the migration.
    op.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS audit_log_team_prevsig_uniq "
        "ON audit_log (team_id, prev_signature)"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS audit_log_team_prevsig_uniq")
