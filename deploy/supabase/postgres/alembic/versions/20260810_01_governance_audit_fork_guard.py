"""Give the governance audit chain the fork guard its sibling already has.

``PostgresGovernanceAuditLog.append`` reads the tenant's chain head, seals the
record against it, and inserts. Two writers that read the same head both seal
against it, so both rows claim the same predecessor and the chain forks. The
existing ``UNIQUE (tenant_id, action_id)`` prevents duplicate *actions*; it says
nothing about two different actions claiming one parent.

Measured on live Postgres before this migration: 6 processes x 8 appends
produced 48 rows over 15 distinct predecessors, and ``verify_chain`` reported
33 of 48 tampered. 16 threads in one process produced 16 rows over 5
predecessors. The module docstring claimed a single process "never forks a
chain" and framed the risk as cross-replica only; both halves were wrong.

The user-visible effect is a false alarm rather than data loss:
``GET /v1/self-posture`` reports ``governance.audit_chain_integrity`` as FAIL
("broken or forked") on healthy data for any multi-replica deployment, and the
NHI cleanup loop runs per-replica on a timer, so it fires in normal operation.

``audit_log`` — the table one file over — has carried
``audit_log_team_prevsig_uniq (team_id, prev_signature)`` plus a re-sign/retry
loop since 20260719_01. This is the same judgement applied to the second chain,
not a new one.

``prev_hash`` is promoted from the ``data`` JSON to its own column so the index
is a plain column index like its sibling, rather than an expression over a cast
of a TEXT column.

Revision ID: 20260810_01
Revises: 20260801_01
"""

from __future__ import annotations

from alembic import op

revision = "20260810_01"
down_revision = "20260801_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE governance_audit_log ADD COLUMN IF NOT EXISTS prev_hash TEXT NOT NULL DEFAULT ''")
    # Backfill from the sealed payload, which has always carried prev_hash —
    # it simply had no column of its own. Guarded so a malformed row cannot
    # abort the migration.
    op.execute(
        """
        UPDATE governance_audit_log
           SET prev_hash = COALESCE(data::jsonb ->> 'prev_hash', '')
         WHERE prev_hash = ''
           AND data IS NOT NULL
           AND jsonb_typeof(data::jsonb) = 'object'
        """
    )
    # IF NOT EXISTS keeps this idempotent and a no-op on deployments that
    # already took the index from runtime-schema.sql. Pre-existing forks in
    # older data would make creation fail; that mirrors 20260719_01's posture —
    # the store's append retries, so a deployment carrying historical forks is
    # not left unable to migrate.
    op.execute("CREATE UNIQUE INDEX IF NOT EXISTS governance_audit_log_tenant_prevhash_uniq ON governance_audit_log (tenant_id, prev_hash)")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS governance_audit_log_tenant_prevhash_uniq")
    op.execute("ALTER TABLE governance_audit_log DROP COLUMN IF EXISTS prev_hash")
