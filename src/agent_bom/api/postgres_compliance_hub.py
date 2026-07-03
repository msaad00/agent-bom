"""Postgres-backed Compliance Hub store for clustered deployments.

Mirrors ``SQLiteComplianceHubStore`` but uses the same connection pool +
tenant-RLS pattern as ``PostgresSCIMStore``. Selected when
``AGENT_BOM_POSTGRES_URL`` is set so a clustered API deployment can
share ingested findings across replicas.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

from agent_bom.api.compliance_hub_store import (
    FindingPage,
    _cvss_value,
    _frameworks_csv,
    _now_utc_iso,
    _postgres_order_clause,
    _redact_findings,
    _severity_rank,
    compute_effective_reach_score,
)
from agent_bom.api.postgres_common import ConnectionPool, _ensure_tenant_rls, _get_pool, _tenant_connection
from agent_bom.api.storage_schema import ensure_postgres_schema_version


def _migrate_lifecycle_observations_l2_postgres(conn: Any) -> None:
    """Upgrade L1 observation rows (PK on observed_at) to L2 (PK on scan_id)."""
    conn.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.tables
                WHERE table_schema = current_schema()
                  AND table_name = 'hub_findings_current_observations'
            ) THEN
                RETURN;
            END IF;
            IF EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_schema = current_schema()
                  AND table_name = 'hub_findings_current_observations'
                  AND column_name = 'scan_id'
            ) THEN
                RETURN;
            END IF;
            ALTER TABLE hub_findings_current_observations
                RENAME TO hub_findings_current_observations_l1;
            CREATE TABLE hub_findings_current_observations (
                tenant_id TEXT NOT NULL,
                canonical_id TEXT NOT NULL,
                scan_id TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, canonical_id, scan_id)
            );
            INSERT INTO hub_findings_current_observations
                (tenant_id, canonical_id, scan_id, observed_at)
            SELECT tenant_id, canonical_id, observed_at, observed_at
            FROM hub_findings_current_observations_l1;
            DROP TABLE hub_findings_current_observations_l1;
        END $$;
        """
    )


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
                    severity TEXT NOT NULL DEFAULT '',
                    severity_rank INTEGER NOT NULL DEFAULT 0,
                    cvss_score DOUBLE PRECISION NOT NULL DEFAULT 0,
                    PRIMARY KEY (tenant_id, finding_id)
                )
                """
            )
            conn.execute(
                "ALTER TABLE compliance_hub_findings ADD COLUMN IF NOT EXISTS effective_reach_score DOUBLE PRECISION NOT NULL DEFAULT 0"
            )
            conn.execute("ALTER TABLE compliance_hub_findings ADD COLUMN IF NOT EXISTS origin TEXT NOT NULL DEFAULT ''")
            # Backfill origin from the stored payload for pre-migration rows.
            conn.execute("UPDATE compliance_hub_findings SET origin = COALESCE(payload->>'origin', '') WHERE origin = ''")
            # Materialise severity/cvss sort keys so filtered severity/cvss
            # Materialise severity/cvss sort keys so filtered severity/cvss
            # sorts ride a composite index rather than a payload-expression
            # sort (#3192). Backfill extracts from payload for legacy rows.
            conn.execute("ALTER TABLE compliance_hub_findings ADD COLUMN IF NOT EXISTS severity TEXT NOT NULL DEFAULT ''")
            conn.execute("UPDATE compliance_hub_findings SET severity = COALESCE(payload->>'severity', '') WHERE severity = ''")
            conn.execute("ALTER TABLE compliance_hub_findings ADD COLUMN IF NOT EXISTS severity_rank INTEGER NOT NULL DEFAULT 0")
            conn.execute(
                "UPDATE compliance_hub_findings SET severity_rank = CASE LOWER(COALESCE(payload->>'severity', '')) "
                "WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 "
                "ELSE 0 END WHERE severity_rank = 0"
            )
            conn.execute("ALTER TABLE compliance_hub_findings ADD COLUMN IF NOT EXISTS cvss_score DOUBLE PRECISION NOT NULL DEFAULT 0")
            conn.execute(
                "UPDATE compliance_hub_findings SET cvss_score = COALESCE((payload->>'cvss_score')::float8, 0) WHERE cvss_score = 0"
            )
            self._migrate_primary_key(conn)
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
            # Back the filtered severity/cvss sorts with ordered composite
            # indexes so ORDER BY is an index range scan, not a sort of the
            # whole tenant — severity_rank preserves band ordering (#3192).
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_hub_findings_tenant_origin_severity "
                "ON compliance_hub_findings(tenant_id, origin, severity_rank DESC, ordinal)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_hub_findings_tenant_origin_cvss "
                "ON compliance_hub_findings(tenant_id, origin, cvss_score DESC, ordinal)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_hub_findings_tenant_origin_severity_cvss "
                "ON compliance_hub_findings(tenant_id, origin, severity_rank, cvss_score DESC, ordinal)"
            )
            _ensure_tenant_rls(conn, "compliance_hub_findings", "tenant_id")
            from agent_bom.api.finding_lifecycle import _CURRENT_LIFECYCLE_POSTGRES_DDL

            conn.execute(_CURRENT_LIFECYCLE_POSTGRES_DDL)
            _migrate_lifecycle_observations_l2_postgres(conn)
            _ensure_tenant_rls(conn, "hub_findings_current", "tenant_id")
            _ensure_tenant_rls(conn, "hub_findings_current_observations", "tenant_id")
            conn.commit()

    @staticmethod
    def _migrate_primary_key(conn: Any) -> None:
        """Collapse the primary key to ``(tenant_id, finding_id)`` (idempotent).

        Pre-idempotency deployments keyed on ``(tenant_id, finding_id, ordinal)``
        so every resend of the same finding appended a fresh row. Dedup existing
        duplicates (keep the lowest ordinal), then swap the primary key. Guarded
        so it is a no-op once the collapsed key is in place.
        """
        # Drop duplicates ahead of the unique key, keeping the original ingest.
        conn.execute(
            """
            DELETE FROM compliance_hub_findings a
            USING compliance_hub_findings b
            WHERE a.tenant_id = b.tenant_id
              AND a.finding_id = b.finding_id
              AND a.ordinal > b.ordinal
            """
        )
        conn.execute(
            """
            DO $$
            DECLARE
                pk_cols text;
                pk_name text;
            BEGIN
                SELECT string_agg(a.attname, ',' ORDER BY array_position(c.conkey, a.attnum)), c.conname
                  INTO pk_cols, pk_name
                  FROM pg_constraint c
                  JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = ANY(c.conkey)
                 WHERE c.conrelid = 'compliance_hub_findings'::regclass
                   AND c.contype = 'p'
                 GROUP BY c.conname;
                IF pk_cols IS DISTINCT FROM 'tenant_id,finding_id' THEN
                    IF pk_name IS NOT NULL THEN
                        EXECUTE 'ALTER TABLE compliance_hub_findings DROP CONSTRAINT ' || quote_ident(pk_name);
                    END IF;
                    ALTER TABLE compliance_hub_findings
                        ADD CONSTRAINT compliance_hub_findings_pkey PRIMARY KEY (tenant_id, finding_id);
                END IF;
            END$$;
            """
        )

    def add(self, tenant_id: str, findings: list[dict[str, Any]]) -> int:
        findings = _redact_findings(findings)
        if not findings:
            return self.count(tenant_id)
        now = _now_utc_iso()
        with _tenant_connection(self._pool) as conn:
            for payload in findings:
                # Idempotent ingest: a resend of the same (tenant_id, finding_id)
                # refreshes payload/metadata and keeps the original ``ordinal``
                # (the BIGSERIAL default only advances on genuine inserts).
                conn.execute(
                    """
                    INSERT INTO compliance_hub_findings
                        (tenant_id, finding_id, ingested_at, source, applicable_frameworks_csv, payload,
                         effective_reach_score, origin, severity, severity_rank, cvss_score)
                    VALUES (%s, %s, %s, %s, %s, %s::jsonb, %s, %s, %s, %s, %s)
                    ON CONFLICT (tenant_id, finding_id) DO UPDATE SET
                        ingested_at = EXCLUDED.ingested_at,
                        source = EXCLUDED.source,
                        applicable_frameworks_csv = EXCLUDED.applicable_frameworks_csv,
                        payload = EXCLUDED.payload,
                        effective_reach_score = EXCLUDED.effective_reach_score,
                        origin = EXCLUDED.origin,
                        severity = EXCLUDED.severity,
                        severity_rank = EXCLUDED.severity_rank,
                        cvss_score = EXCLUDED.cvss_score
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
                        str(payload.get("severity") or ""),
                        _severity_rank(payload),
                        _cvss_value(payload),
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
            from agent_bom.graph.severity import severity_policy_rank

            where.append("severity_rank = %s")
            params.append(severity_policy_rank(severity))
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
            conn.execute("DELETE FROM hub_findings_current WHERE tenant_id = %s", (tenant_id,))
            conn.execute("DELETE FROM hub_findings_current_observations WHERE tenant_id = %s", (tenant_id,))
            conn.commit()
        removed = cur.rowcount or 0
        if removed:
            from agent_bom.api.findings_count_cache import invalidate_tenant

            invalidate_tenant(tenant_id)
        return removed

    def upsert_current_batch(
        self,
        tenant_id: str,
        findings: Sequence[dict[str, Any]],
        *,
        observed_at: str,
        batch_id: str,
        source: str = "",
    ) -> None:
        from agent_bom.api.finding_lifecycle import (
            apply_observation_to_current,
            lifecycle_metrics,
            resolve_canonical_id,
        )

        clean = _redact_findings(findings)
        if not clean:
            return
        now = _now_utc_iso()
        with _tenant_connection(self._pool) as conn:
            for payload in clean:
                canonical = resolve_canonical_id(payload, source=source)
                metrics = lifecycle_metrics(payload)
                inserted = conn.execute(
                    """
                    INSERT INTO hub_findings_current_observations
                        (tenant_id, canonical_id, scan_id, observed_at)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT DO NOTHING
                    """,
                    (tenant_id, canonical, batch_id, observed_at),
                ).rowcount
                if not inserted:
                    continue
                existing_row = conn.execute(
                    """
                    SELECT canonical_id, first_seen, last_seen, status, severity, severity_rank,
                           cvss_score, effective_reach_score, scan_count, resolved_at, reopened_at,
                           updated_at, payload
                    FROM hub_findings_current
                    WHERE tenant_id = %s AND canonical_id = %s
                    """,
                    (tenant_id, canonical),
                ).fetchone()
                existing: dict[str, Any] | None
                if existing_row is None:
                    existing = None
                else:
                    raw_payload = existing_row[12]
                    existing = {
                        "canonical_id": existing_row[0],
                        "first_seen": existing_row[1],
                        "last_seen": existing_row[2],
                        "status": existing_row[3],
                        "severity": existing_row[4],
                        "severity_rank": existing_row[5],
                        "cvss_score": existing_row[6],
                        "effective_reach_score": existing_row[7],
                        "scan_count": existing_row[8],
                        "resolved_at": existing_row[9],
                        "reopened_at": existing_row[10],
                        "updated_at": existing_row[11],
                        "payload": raw_payload if isinstance(raw_payload, dict) else json.loads(raw_payload),
                    }
                merged = apply_observation_to_current(
                    existing,
                    canonical_id=canonical,
                    observed_at=observed_at,
                    metrics=metrics,
                    payload=payload,
                    updated_at=now,
                )
                conn.execute(
                    """
                    INSERT INTO hub_findings_current
                        (tenant_id, canonical_id, first_seen, last_seen, status, severity, severity_rank,
                         cvss_score, effective_reach_score, scan_count, resolved_at, reopened_at,
                         updated_at, payload)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb)
                    ON CONFLICT (tenant_id, canonical_id) DO UPDATE SET
                        first_seen = LEAST(hub_findings_current.first_seen, EXCLUDED.first_seen),
                        last_seen = GREATEST(hub_findings_current.last_seen, EXCLUDED.last_seen),
                        status = EXCLUDED.status,
                        severity = EXCLUDED.severity,
                        severity_rank = EXCLUDED.severity_rank,
                        cvss_score = EXCLUDED.cvss_score,
                        effective_reach_score = EXCLUDED.effective_reach_score,
                        scan_count = EXCLUDED.scan_count,
                        resolved_at = EXCLUDED.resolved_at,
                        reopened_at = EXCLUDED.reopened_at,
                        updated_at = EXCLUDED.updated_at,
                        payload = EXCLUDED.payload
                    """,
                    (
                        tenant_id,
                        canonical,
                        merged["first_seen"],
                        merged["last_seen"],
                        merged["status"],
                        merged["severity"],
                        merged["severity_rank"],
                        merged["cvss_score"],
                        merged["effective_reach_score"],
                        merged["scan_count"],
                        merged["resolved_at"],
                        merged["reopened_at"],
                        merged["updated_at"],
                        json.dumps(merged["payload"], sort_keys=True),
                    ),
                )
            conn.commit()

    def get_current(self, tenant_id: str, canonical_id: str) -> dict[str, Any] | None:
        with _tenant_connection(self._pool) as conn:
            row = conn.execute(
                """
                SELECT canonical_id, first_seen, last_seen, status, severity, severity_rank,
                       cvss_score, effective_reach_score, scan_count, resolved_at, reopened_at,
                       updated_at, payload
                FROM hub_findings_current
                WHERE tenant_id = %s AND canonical_id = %s
                """,
                (tenant_id, canonical_id),
            ).fetchone()
        if row is None:
            return None
        raw_payload = row[12]
        return {
            "canonical_id": row[0],
            "first_seen": row[1],
            "last_seen": row[2],
            "status": row[3],
            "severity": row[4],
            "severity_rank": row[5],
            "cvss_score": row[6],
            "effective_reach_score": row[7],
            "scan_count": row[8],
            "resolved_at": row[9],
            "reopened_at": row[10],
            "updated_at": row[11],
            "payload": raw_payload if isinstance(raw_payload, dict) else json.loads(raw_payload),
        }
