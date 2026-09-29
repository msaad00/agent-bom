"""Index the findings current-state sort orders by code point.

Findings pages order their text tie-breakers (``last_seen`` / ``first_seen``
then ``canonical_id``) with ``COLLATE "C"`` so SQLite, Postgres and Python
agree on one order whatever the database collation. A default-collation index
cannot serve that ORDER BY, so each sort index gets a ``COLLATE "C"`` twin.
The existing indexes stay in place; this migration only adds.

Revision ID: 20260929_03
Revises: 20260929_02
"""

from __future__ import annotations

from alembic import op

revision = "20260929_03"
down_revision = "20260929_02"
branch_labels = None
depends_on = None

_TIE = 'last_seen COLLATE "C" DESC, canonical_id COLLATE "C" ASC'

COLLATED_SORT_INDEXES = (
    "CREATE INDEX IF NOT EXISTS idx_hub_findings_current_tenant_reach_c "
    f"ON hub_findings_current(tenant_id, effective_reach_score DESC, {_TIE})",
    f"CREATE INDEX IF NOT EXISTS idx_hub_findings_current_tenant_cvss_c ON hub_findings_current(tenant_id, cvss_score DESC, {_TIE})",
    f"CREATE INDEX IF NOT EXISTS idx_hub_findings_current_tenant_severity_c ON hub_findings_current(tenant_id, severity_rank DESC, {_TIE})",
    "CREATE INDEX IF NOT EXISTS idx_hub_findings_current_tenant_origin_cvss_c "
    f"ON hub_findings_current(tenant_id, origin, cvss_score DESC, {_TIE})",
    "CREATE INDEX IF NOT EXISTS idx_hub_findings_current_tenant_ordinal_c "
    'ON hub_findings_current(tenant_id, ledger_ordinal ASC, first_seen COLLATE "C" ASC, canonical_id COLLATE "C" ASC)',
    "CREATE INDEX IF NOT EXISTS idx_hub_findings_current_tenant_severity_reach_c "
    f"ON hub_findings_current(tenant_id, LOWER(severity), effective_reach_score DESC, {_TIE}) WHERE severity <> ''",
    "CREATE INDEX IF NOT EXISTS idx_hub_findings_current_tenant_severity_cvss_c "
    f"ON hub_findings_current(tenant_id, LOWER(severity), cvss_score DESC, {_TIE}) WHERE severity <> ''",
    "CREATE INDEX IF NOT EXISTS idx_hub_findings_current_tenant_open_reach_c "
    f"ON hub_findings_current(tenant_id, effective_reach_score DESC, {_TIE}) WHERE status IN ('open', 'reopened')",
)


def _index_name(statement: str) -> str:
    return statement.split("IF NOT EXISTS ", 1)[1].split(" ", 1)[0]


def upgrade() -> None:
    # Minimal stamped deployments may not have created the current-state table
    # yet; the runtime schema creates these indexes with the table.
    relation = op.get_bind().exec_driver_sql("SELECT to_regclass('public.hub_findings_current')").scalar()
    if relation is None:
        return
    # CONCURRENTLY keeps ingest writing while a large table is indexed.
    with op.get_context().autocommit_block():
        for statement in COLLATED_SORT_INDEXES:
            op.execute(statement.replace("CREATE INDEX IF NOT EXISTS", "CREATE INDEX CONCURRENTLY IF NOT EXISTS", 1))


def downgrade() -> None:
    with op.get_context().autocommit_block():
        for statement in COLLATED_SORT_INDEXES:
            op.execute(f"DROP INDEX CONCURRENTLY IF EXISTS {_index_name(statement)}")
