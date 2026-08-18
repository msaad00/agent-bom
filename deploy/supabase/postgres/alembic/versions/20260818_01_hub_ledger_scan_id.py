"""Materialise the Compliance Hub ledger scan key.

The SQLite ledger already stores and indexes the scan/batch identifier.  The
Postgres ledger still decoded ``payload`` for each filtered row, preventing an
index-backed scan view at scale.  Add and backfill the additive column, then
create the same partial tenant/scan index used by new installations.

Revision ID: 20260818_01
Revises: 20260812_01
"""

from __future__ import annotations

from alembic import op

revision = "20260818_01"
down_revision = "20260812_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE IF EXISTS compliance_hub_findings ADD COLUMN IF NOT EXISTS scan_id TEXT NOT NULL DEFAULT ''")
    op.execute(
        "UPDATE compliance_hub_findings SET scan_id = "
        "COALESCE(NULLIF(payload->>'batch_id', ''), payload->>'scan_id', '') "
        "WHERE scan_id = '' AND "
        "COALESCE(NULLIF(payload->>'batch_id', ''), payload->>'scan_id', '') <> ''"
    )
    op.execute("CREATE INDEX IF NOT EXISTS idx_hub_findings_tenant_scan ON compliance_hub_findings(tenant_id, scan_id) WHERE scan_id <> ''")
    # The original tenant policy named ``agent_bom_app`` before that optional
    # runtime role necessarily existed, so a pristine Alembic-only database
    # could fail mid-upgrade.  A role-neutral policy applies to every caller and
    # still enforces the same tenant predicate; the separately gated maintenance
    # policy remains the only bypass path.
    op.execute("DROP POLICY IF EXISTS scan_dispatch_queue_tenant_isolation ON scan_dispatch_queue")
    op.execute(
        "CREATE POLICY scan_dispatch_queue_tenant_isolation ON scan_dispatch_queue "
        "FOR ALL USING (tenant_id = public.abom_current_tenant()) "
        "WITH CHECK (tenant_id = public.abom_current_tenant())"
    )


def downgrade() -> None:
    # Additive and non-destructive: current writers address this column, so a
    # rollback must leave it present to keep the running application writable.
    return
