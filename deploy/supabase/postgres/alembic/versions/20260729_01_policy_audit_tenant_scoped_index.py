"""Make policy-audit deduplication tenant-safe without breaking old replicas.

Old application versions insert with ``ON CONFLICT (entry_id) DO NOTHING``.
Changing the unique index to ``(team_id, entry_id)`` would make those replicas
error during a rolling deployment because their conflict target no longer has a
matching unique index.  Instead, ``entry_id`` becomes an injective
tenant-derived physical key while ``logical_entry_id`` and the JSON payload
retain the caller-visible ID.  A database trigger applies the mapping for both
old and new application versions.

The migration takes an ACCESS EXCLUSIVE lock while it rewrites the small policy
audit ledger, so no insert can land between the backfill and index rebuild.  It
cannot recover rows discarded by the previous global index; it prevents future
loss.

Revision ID: 20260729_01
Revises: 20260728_03
"""

from __future__ import annotations

from alembic import op

revision = "20260729_01"
down_revision = "20260728_03"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE OR REPLACE FUNCTION public.abom_policy_audit_key(
            tenant_id TEXT,
            logical_id TEXT
        ) RETURNS TEXT
        LANGUAGE SQL
        IMMUTABLE
        STRICT
        PARALLEL SAFE
        AS $$
            SELECT octet_length(tenant_id)::TEXT || ':' || tenant_id || ':' || logical_id
        $$
        """
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION public.abom_policy_audit_set_key()
        RETURNS TRIGGER
        LANGUAGE plpgsql
        AS $$
        BEGIN
            NEW.logical_entry_id := COALESCE(NEW.logical_entry_id, NEW.entry_id);
            IF NEW.logical_entry_id IS NOT NULL THEN
                NEW.entry_id := public.abom_policy_audit_key(NEW.team_id, NEW.logical_entry_id);
            END IF;
            RETURN NEW;
        END
        $$
        """
    )
    op.execute(
        """
        DO $$
        DECLARE
            had_rls BOOLEAN;
            had_force_rls BOOLEAN;
        BEGIN
            IF to_regclass('public.policy_audit_log') IS NOT NULL THEN
                LOCK TABLE policy_audit_log IN ACCESS EXCLUSIVE MODE;

                SELECT relrowsecurity, relforcerowsecurity
                  INTO had_rls, had_force_rls
                  FROM pg_class
                 WHERE oid = 'public.policy_audit_log'::regclass;

                -- The migration owner must see every tenant while rewriting
                -- the physical key. The table lock prevents runtime access,
                -- and the prior RLS posture is restored before commit.
                IF had_rls THEN
                    ALTER TABLE policy_audit_log DISABLE ROW LEVEL SECURITY;
                END IF;

                ALTER TABLE policy_audit_log
                    ADD COLUMN IF NOT EXISTS logical_entry_id TEXT;

                DROP TRIGGER IF EXISTS policy_audit_set_key ON policy_audit_log;
                CREATE TRIGGER policy_audit_set_key
                    BEFORE INSERT OR UPDATE OF team_id, entry_id, logical_entry_id
                    ON policy_audit_log
                    FOR EACH ROW
                    EXECUTE FUNCTION public.abom_policy_audit_set_key();

                DROP INDEX IF EXISTS uq_policy_audit_log_entry;
                UPDATE policy_audit_log
                   SET logical_entry_id = COALESCE(logical_entry_id, entry_id),
                       entry_id = public.abom_policy_audit_key(
                           team_id,
                           COALESCE(logical_entry_id, entry_id)
                       )
                 WHERE entry_id IS NOT NULL;
                CREATE UNIQUE INDEX uq_policy_audit_log_entry
                    ON policy_audit_log(entry_id);
                COMMENT ON INDEX uq_policy_audit_log_entry IS
                    'agent-bom policy audit tenant key v2';

                COMMENT ON COLUMN policy_audit_log.entry_id IS
                    'Tenant-derived physical dedupe key; use logical_entry_id or data->>entry_id externally';
                COMMENT ON COLUMN policy_audit_log.logical_entry_id IS
                    'Caller-visible policy audit entry ID preserved across tenant-safe deduplication';

                IF had_rls THEN
                    ALTER TABLE policy_audit_log ENABLE ROW LEVEL SECURITY;
                END IF;
                IF had_force_rls THEN
                    ALTER TABLE policy_audit_log FORCE ROW LEVEL SECURITY;
                END IF;
            END IF;
        END
        $$
        """
    )


def downgrade() -> None:
    raise NotImplementedError(
        "Policy-audit tenant deduplication is forward-only: an application rollback is compatible, "
        "but the database migration cannot be reversed after cross-tenant logical IDs are accepted."
    )
