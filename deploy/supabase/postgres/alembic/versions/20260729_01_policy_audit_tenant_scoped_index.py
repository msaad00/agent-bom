"""Scope the policy audit uniqueness index by tenant.

``policy_audit_log`` carried ``UNIQUE (entry_id)`` with no tenant column, and the
writer used ``ON CONFLICT (entry_id) DO NOTHING``. Two tenants writing the same
logical ``entry_id`` collapsed to one row: the second write reported success and
silently vanished. Unique indexes are enforced below RLS, so FORCE ROW LEVEL
SECURITY does not protect against this.

An audit log that drops entries without erroring is worse than one that fails
loudly. The governance chain already scopes its equivalent index by tenant
(``uq_governance_audit_tenant_action``); this brings the policy chain in line.

Rebuilding the index cannot merge rows that were already lost — those writes
never landed. It only stops further loss.

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
    # A pre-existing duplicate across tenants is impossible: the old index made
    # it unrepresentable. So the tenant-scoped index can be built directly.
    op.execute("DROP INDEX IF EXISTS uq_policy_audit_log_entry")
    op.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_policy_audit_log_entry ON policy_audit_log(team_id, entry_id)")


def downgrade() -> None:
    # Narrowing back can fail if two tenants have since written the same
    # entry_id — which is exactly the data this migration exists to preserve.
    op.execute("DROP INDEX IF EXISTS uq_policy_audit_log_entry")
    op.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_policy_audit_log_entry ON policy_audit_log(entry_id)")
