"""Backfill legacy audit-chain checkpoints from the audit_log links (#4294).

A tenant whose ``audit_log`` rows predate its first ``audit_chain_checkpoint``
upsert was seeded at ``entry_count=1`` rather than its true historical count:
the migration-owned schema creates ``audit_chain_checkpoint`` empty and the
runtime store never runs ``_hydrate_checkpoints`` on the authoritative path, so
a legacy tenant's first append seeds the checkpoint from scratch. This one-time,
idempotent reconciliation recomputes each tenant's ``entry_count`` (row count)
and ``head_signature`` (the successor-free chain tip, chain-order-correct
regardless of timestamp skew — #4284/#4293) directly from ``audit_log`` so
``verify_integrity``'s truncation check stops under-counting for those tenants.

The append seed path is fixed in the same change, so this only heals rows that
were already under-seeded before the fix shipped; rerunning is a no-op.

Revision ID: 20260720_01
Revises: 20260719_03
"""

from __future__ import annotations

from alembic import op

revision = "20260720_01"
down_revision = "20260719_03"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # audit_log (team_id) and audit_chain_checkpoint (tenant_id) both enforce
    # FORCE ROW LEVEL SECURITY, so this cross-tenant maintenance write runs under
    # the app.bypass_rls GUC the RLS policies honour (transaction-local). The
    # reconcile is a single idempotent INSERT ... SELECT ... ON CONFLICT: it
    # seeds missing checkpoints and overwrites under-seeded entry_count/head with
    # the values derived from the chain, matching the runtime store's
    # backfill_checkpoints().
    op.execute("SELECT set_config('app.bypass_rls', '1', true)")
    op.execute(
        """
        INSERT INTO audit_chain_checkpoint (tenant_id, entry_count, head_signature)
        SELECT a.team_id,
               COUNT(*),
               (
                   SELECT h.hmac_signature
                   FROM audit_log h
                   WHERE h.team_id = a.team_id
                     AND NOT EXISTS (
                         SELECT 1 FROM audit_log b
                         WHERE b.team_id = h.team_id
                           AND b.prev_signature = h.hmac_signature
                     )
                   ORDER BY h.hmac_signature
                   LIMIT 1
               )
        FROM audit_log a
        GROUP BY a.team_id
        ON CONFLICT (tenant_id) DO UPDATE SET
            entry_count = EXCLUDED.entry_count,
            head_signature = EXCLUDED.head_signature
        """
    )


def downgrade() -> None:
    # A data reconciliation has no meaningful inverse (the pre-backfill counts
    # were wrong); leave the corrected checkpoints in place.
    pass
