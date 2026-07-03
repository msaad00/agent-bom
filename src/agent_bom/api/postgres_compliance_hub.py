"""Postgres-backed Compliance Hub store for clustered deployments.

Mirrors ``SQLiteComplianceHubStore`` but uses the same connection pool +
tenant-RLS pattern as ``PostgresSCIMStore``. Selected when
``AGENT_BOM_POSTGRES_URL`` is set so a clustered API deployment can
share ingested findings across replicas.
"""

from __future__ import annotations

import json
from typing import Any

from agent_bom.api.compliance_hub_store import (
    FindingPage,
    _frameworks_csv,
    _now_utc_iso,
    _postgres_order_clause,
    _redact_findings,
    compute_effective_reach_score,
)
from agent_bom.api.postgres_common import ConnectionPool, _ensure_tenant_rls, _get_pool, _tenant_connection
from agent_bom.api.storage_schema import ensure_postgres_schema_version


class PostgresComplianceHubStore:
    """Shared hub store backing multi-replica self-hosted deployments."""

    def __init__(self, pool: ConnectionPool | None = None) -> None:
        self._pool = pool or _get_pool()
        self._init_tables()

    def _init_tables(self) -> None:
        with self._pool.connection() as conn:
            ensure_postgres_schema_version(conn, "compliance_hub")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS compliance_hub_findings (
                    tenant_id TEXT NOT NULL,
                    finding_id TEXT NOT NULL,
                    ingested_at TEXT NOT NULL,
                    source TEXT NOT NULL,
                    applicable_frameworks_csv TEXT NOT NULL DEFAULT '',
                    payload JSONB NOT NULL,
                    ordinal BIGSERIAL NOT NULL,
                    effective_reach_score DOUBLE PRECISION NOT NULL DEFAULT 0,
                    origin TEXT NOT NULL DEFAULT '',
                    PRIMARY KEY (tenant_id, finding_id, ordinal)
                )
                """
            )
            conn.execute(
                "ALTER TABLE compliance_hub_findings ADD COLUMN IF NOT EXISTS effective_reach_score DOUBLE PRECISION NOT NULL DEFAULT 0"
            )
            conn.execute("ALTER TABLE compliance_hub_findings ADD COLUMN IF NOT EXISTS origin TEXT NOT NULL DEFAULT ''")
            # Backfill origin from the stored payload for pre-migration rows.
            conn.execute("UPDATE compliance_hub_findings SET origin = COALESCE(payload->>'origin', '') WHERE origin = ''")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_hub_findings_tenant_order ON compliance_hub_findings(tenant_id, ordinal)")
            conn.execute("DROP INDEX IF EXISTS idx_hub_findings_tenant_reach")
            # Backs the default effective_reach sort scoped by origin: an
            # index-ordered range scan + LIMIT (and a covering COUNT on the
            # (tenant_id, origin) prefix) instead of a full-tenant load +
            # Python sort (PR1 read-scale). See scripts/bench_findings_read.
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_hub_findings_tenant_origin_reach "
                "ON compliance_hub_findings(tenant_id, origin, effective_reach_score DESC, ordinal)"
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_hub_findings_tenant_origin ON compliance_hub_findings(tenant_id, origin)")
            _ensure_tenant_rls(conn, "compliance_hub_findings", "tenant_id")
            conn.commit()

    def add(self, tenant_id: str, findings: list[dict[str, Any]]) -> int:
        findings = _redact_findings(findings)
        if not findings:
            return self.count(tenant_id)
        now = _now_utc_iso()
        with _tenant_connection(self._pool) as conn:
            for payload in findings:
                conn.execute(
                    """
                    INSERT INTO compliance_hub_findings
                        (tenant_id, finding_id, ingested_at, source, applicable_frameworks_csv, payload, effective_reach_score, origin)
                    VALUES (%s, %s, %s, %s, %s, %s::jsonb, %s, %s)
                    """,
                    (
                        tenant_id,
                        str(payload.get("id") or f"hub-{now}-{id(payload)}"),
                        now,
                        str(payload.get("source") or ""),
                        _frameworks_csv(payload),
                        json.dumps(payload, sort_keys=True),
                        compute_effective_reach_score(payload),
                        str(payload.get("origin") or ""),
                    ),
                )
            conn.commit()
        return self.count(tenant_id)

    def list(self, tenant_id: str) -> list[dict[str, Any]]:
        with _tenant_connection(self._pool) as conn:
            rows = conn.execute(
                "SELECT payload FROM compliance_hub_findings WHERE tenant_id = %s ORDER BY ordinal ASC",
                (tenant_id,),
            ).fetchall()
        out: list[dict[str, Any]] = []
        for row in rows:
            raw = row[0]
            out.append(raw if isinstance(raw, dict) else json.loads(raw))
        return out

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
    ) -> FindingPage:
        where = ["tenant_id = %s"]
        params: list[Any] = [tenant_id]
        if origin is not None:
            where.append("origin = %s")
            params.append(origin)
        if severity is not None:
            where.append("LOWER(payload->>'severity') = %s")
            params.append(severity.lower())
        if scan_id is not None:
            where.append("payload->>'scan_id' = %s")
            params.append(scan_id)
        where_sql = " AND ".join(where)
        order_sql = _postgres_order_clause(sort)

        with _tenant_connection(self._pool) as conn:
            total: int | None
            if include_total:
                # ``where_sql`` is assembled only from fixed predicates above; all caller values
                # stay in ``params`` as psycopg bindings.
                total_row = conn.execute(
                    f"SELECT COUNT(*) FROM compliance_hub_findings WHERE {where_sql}",  # nosec B608
                    tuple(params),
                ).fetchone()
                total = int(total_row[0]) if total_row else 0
            else:
                total = None
            # ``order_sql`` comes from a closed sort allowlist; all caller values stay bound.
            rows = conn.execute(
                f"SELECT payload FROM compliance_hub_findings WHERE {where_sql} {order_sql} LIMIT %s OFFSET %s",  # nosec B608
                (*params, int(limit), int(offset)),
            ).fetchall()
        out: list[dict[str, Any]] = []
        for row in rows:
            raw = row[0]
            out.append(raw if isinstance(raw, dict) else json.loads(raw))
        return out, total

    def severity_breakdown(self, tenant_id: str) -> dict[str, int]:
        with _tenant_connection(self._pool) as conn:
            rows = conn.execute(
                """
                SELECT LOWER(COALESCE(payload->>'severity', 'unknown')) AS sev, COUNT(*)
                FROM compliance_hub_findings
                WHERE tenant_id = %s
                GROUP BY sev
                """,
                (tenant_id,),
            ).fetchall()
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}
        for sev, count in rows:
            key = str(sev or "unknown").lower()
            counts[key] = counts.get(key, 0) + int(count)
        return counts

    def framework_slug_counts(self, tenant_id: str) -> dict[str, int]:
        from agent_bom.compliance_coverage import normalize_framework_slug

        with _tenant_connection(self._pool) as conn:
            rows = conn.execute(
                "SELECT applicable_frameworks_csv FROM compliance_hub_findings WHERE tenant_id = %s",
                (tenant_id,),
            ).fetchall()
        counts: dict[str, int] = {}
        for (csv_value,) in rows:
            if not csv_value:
                continue
            for slug in str(csv_value).split(","):
                slug = slug.strip()
                if not slug:
                    continue
                canonical = normalize_framework_slug(slug)
                counts[canonical] = counts.get(canonical, 0) + 1
        return counts

    def count(self, tenant_id: str) -> int:
        with _tenant_connection(self._pool) as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM compliance_hub_findings WHERE tenant_id = %s",
                (tenant_id,),
            ).fetchone()
        return int(row[0]) if row else 0

    def clear(self, tenant_id: str) -> int:
        with _tenant_connection(self._pool) as conn:
            cur = conn.execute(
                "DELETE FROM compliance_hub_findings WHERE tenant_id = %s",
                (tenant_id,),
            )
            conn.commit()
        removed = cur.rowcount or 0
        if removed:
            from agent_bom.api.findings_count_cache import invalidate_tenant

            invalidate_tenant(tenant_id)
        return removed
