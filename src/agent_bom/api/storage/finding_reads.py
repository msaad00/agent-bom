"""One tenant-bound ledger read path for SQLite and Postgres finding stores."""

from __future__ import annotations

from typing import Any

from agent_bom.api.hub_payload_codec import decode_hub_payload
from agent_bom.api.storage.finding_payloads import hydrate_ledger_rows
from agent_bom.api.storage.sql import Keyset, SqlBackend
from agent_bom.core.tenancy import require_explicit_tenant_id

FindingRows = list[dict[str, Any]]


def ledger_order(sort: str) -> Keyset:
    """Materialized score columns preserve index scans and ingest-order ties."""
    if sort == "ordinal":
        return Keyset(("ordinal",), numeric=frozenset({"ordinal"}))
    column = {"cvss": "cvss_score", "severity": "severity_rank"}.get(sort, "effective_reach_score")
    return Keyset((column, "ordinal"), numeric=frozenset({column, "ordinal"}), directions=(True, False))


class SqlFindingReads:
    """Counts, rows and reference hydration share a read-only transaction.

    This component owns ledger reads; lifecycle writes retain their existing
    atomic transactions. Tenant predicates apply on both engines, with Postgres
    additionally enforcing the application role's RLS context.
    """

    def __init__(self, backend: SqlBackend) -> None:
        self._backend = backend

    def list(self, tenant_id: str) -> FindingRows:
        tenant = require_explicit_tenant_id(tenant_id)
        with self._backend.transaction(read_only=True) as tx:
            rows = tx.execute("SELECT payload FROM compliance_hub_findings WHERE tenant_id = ? ORDER BY ordinal ASC", (tenant,)).fetchall()
            return hydrate_ledger_rows(tx, tenant, [decode_hub_payload(row[0]) for row in rows])

    def list_page(
        self,
        tenant_id: str,
        *,
        limit: int,
        offset: int = 0,
        sort: str = "effective_reach",
        severity: str | None = None,
        scan_id: str | None = None,
        origin: str | None = None,
        include_total: bool = True,
    ) -> tuple[FindingRows, int | None]:
        tenant = require_explicit_tenant_id(tenant_id)
        where = ["tenant_id = ?"]
        params: list[Any] = [tenant]
        if origin is not None:
            where.append("origin = ?")
            params.append(origin)
        if severity is not None:
            where.append("severity != '' AND LOWER(severity) = ?")
            params.append(severity.lower())
        if scan_id is not None:
            where.append("scan_id = ? AND scan_id != ''")
            params.append(scan_id)
        where_sql = " AND ".join(where)
        order = ledger_order(sort).order_by(self._backend.dialect)
        with self._backend.transaction(read_only=True) as tx:
            total: int | None = None
            if include_total:
                row = tx.execute(f"SELECT COUNT(*) FROM compliance_hub_findings WHERE {where_sql}", params).fetchone()  # nosec B608
                total = int(row[0]) if row else 0
            rows = tx.execute(
                f"SELECT payload FROM compliance_hub_findings WHERE {where_sql} ORDER BY {order} LIMIT ? OFFSET ?",  # nosec B608
                (*params, int(limit), int(offset)),
            ).fetchall()
            return hydrate_ledger_rows(tx, tenant, [decode_hub_payload(row[0]) for row in rows]), total

    def count(self, tenant_id: str) -> int:
        tenant = require_explicit_tenant_id(tenant_id)
        with self._backend.transaction(read_only=True) as tx:
            row = tx.execute("SELECT COUNT(*) FROM compliance_hub_findings WHERE tenant_id = ?", (tenant,)).fetchone()
        return int(row[0]) if row else 0

    def overview_evidence_revision(self, tenant_id: str) -> int:
        tenant = require_explicit_tenant_id(tenant_id)
        with self._backend.transaction(read_only=True) as tx:
            row = tx.execute("SELECT revision FROM hub_overview_revisions WHERE tenant_id = ?", (tenant,)).fetchone()
        return int(row[0]) if row else 0

    def severity_breakdown(self, tenant_id: str) -> dict[str, int]:
        tenant = require_explicit_tenant_id(tenant_id)
        with self._backend.transaction(read_only=True) as tx:
            rows = tx.execute(
                "SELECT LOWER(COALESCE(NULLIF(severity, ''), 'unknown')) AS sev, COUNT(*) "
                "FROM compliance_hub_findings WHERE tenant_id = ? GROUP BY sev",
                (tenant,),
            ).fetchall()
        counts = dict.fromkeys(("critical", "high", "medium", "low", "info", "unknown"), 0)
        for severity, count in rows:
            key = str(severity or "unknown").lower()
            counts[key] = counts.get(key, 0) + int(count)
        return counts
