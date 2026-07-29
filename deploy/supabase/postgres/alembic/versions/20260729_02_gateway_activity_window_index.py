"""Index exact gateway KPI windows by tenant and event time.

Revision ID: 20260729_02
Revises: 20260729_01
"""

from __future__ import annotations

from alembic import op

revision = "20260729_02"
down_revision = "20260729_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # A 0.98.2 deployment may have been stamped at the previous revision by
    # the legacy bootstrap path without provisioning the optional runtime
    # ledger.  Keep that supported forward-upgrade path non-destructive; the
    # runtime bootstrap creates this same index when it creates the ledger.
    relation = op.get_bind().exec_driver_sql(
        "SELECT to_regclass('public.gateway_activity_events')"
    ).scalar()
    if relation is None:
        return

    with op.get_context().autocommit_block():
        op.execute(
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_gateway_activity_events_tenant_event_time "
            "ON gateway_activity_events("
            "tenant_id, event_timestamp, "
            "((data::jsonb) ->> 'event_type'), ((data::jsonb) ->> 'reason_code')"
            ")"
        )


def downgrade() -> None:
    with op.get_context().autocommit_block():
        op.execute("DROP INDEX CONCURRENTLY IF EXISTS idx_gateway_activity_events_tenant_event_time")
