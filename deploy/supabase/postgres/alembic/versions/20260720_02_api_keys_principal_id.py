"""Bind API keys to a stable principal id for id-based deprovision (#4274, item 4).

Deprovisioning a subject must revoke every key issued on its behalf, including a
differently-named CI token. The prior revocation heuristic matched on display
name / free-form owner, so a token bound to the subject only by a stable id
survived. This migration adds ``principal_id`` (indexed) to ``api_keys`` and
backfills it from the existing ``scim_subject_id``/``owner`` hints so pre-fix
rows become revocable by id. It mirrors PostgresKeyStore._init_tables and the
additive runtime-schema.sql; ADD COLUMN IF NOT EXISTS keeps it a no-op where the
runtime bootstrap already added the column, and idempotent on rerun.

Revision ID: 20260720_02
Revises: 20260720_01
"""

from __future__ import annotations

from alembic import op

revision = "20260720_02"
down_revision = "20260720_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS principal_id TEXT")
    # Backfill mirrors create_api_key_record precedence (scim_subject_id -> owner).
    # WHERE principal_id IS NULL keeps a rerun a no-op and never clobbers a value
    # already stamped by the runtime store.
    op.execute("UPDATE api_keys SET principal_id = COALESCE(NULLIF(scim_subject_id, ''), NULLIF(owner, '')) WHERE principal_id IS NULL")
    op.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_principal ON api_keys (team_id, principal_id)")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_api_keys_principal")
    op.execute("ALTER TABLE api_keys DROP COLUMN IF EXISTS principal_id")
