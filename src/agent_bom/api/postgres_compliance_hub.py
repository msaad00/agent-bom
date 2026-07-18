"""Postgres-backed Compliance Hub store for clustered deployments.

Mirrors ``SQLiteComplianceHubStore`` but uses the same connection pool +
tenant-RLS pattern as ``PostgresSCIMStore``. Selected when
``AGENT_BOM_POSTGRES_URL`` is set so a clustered API deployment can
share ingested findings across replicas.
"""

from __future__ import annotations

import threading
from collections.abc import Sequence
from typing import Any

from agent_bom.api.compliance_hub_store import (
    _LEDGER_ORDINAL_SENTINEL,
    RECONCILE_ABSENT_CHUNK,
    FindingCursorPage,
    FindingPage,
    _cvss_value,
    _frameworks_csv,
    _now_utc_iso,
    _postgres_current_order_clause,
    _postgres_order_clause,
    _redact_finding,
    _redact_findings,
    _severity_rank,
    compute_effective_reach_score,
)
from agent_bom.api.finding_cursor import (
    cursor_from_current_row,
    postgres_keyset_clause,
)
from agent_bom.api.hub_current_payload import (
    batch_ledger_payloads,
    current_state_overlay,
    hydrate_current_payload,
    resolve_ledger_finding_id,
)
from agent_bom.api.hub_payload_codec import decode_hub_payload, encode_hub_payload
from agent_bom.api.hub_reference_store import (
    ensure_postgres_reference_tables,
    hydrate_finding_payloads_postgres,
    persist_finding_references_postgres,
)
from agent_bom.api.postgres_common import ConnectionPool, _ensure_tenant_rls, _get_pool, _tenant_connection
from agent_bom.api.storage_schema import ensure_postgres_schema_version


def _kev_json_cond_postgres(col: str) -> str:
    """Postgres predicate: the CISA-KEV flag on a JSONB payload column."""
    return f"({col}->>'is_kev') IN ('true', 't', '1') OR ({col}->>'cisa_kev') IN ('true', 't', '1')"


def _invalidate_overview_severity(tenant_id: str) -> None:
    """Drop the memoised /v1/overview severity histogram after a ledger change.

    Any mutation of ``compliance_hub_findings`` (the ``severity_breakdown``
    source) must invalidate the per-tenant overview cache so the headline never
    goes stale relative to the ledger (wave-2 residual #3).
    """
    from agent_bom.api import hub_overview_cache

    hub_overview_cache.invalidate_tenant(tenant_id)


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


def _migrate_current_ledger_ref_postgres(conn: Any) -> None:
    conn.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_schema = current_schema()
                  AND table_name = 'hub_findings_current'
                  AND column_name = 'ledger_finding_id'
            ) THEN
                ALTER TABLE hub_findings_current ADD COLUMN ledger_finding_id TEXT;
            END IF;
        END $$;
        """
    )


def _migrate_current_ledger_ordinal_postgres(conn: Any) -> None:
    """Materialise the ledger ingest ``ordinal`` onto ``hub_findings_current``.

    Postgres mirror of the SQLite migration (#3984): promote ``sort=ordinal``
    off a per-row correlated ledger subquery onto a stored column backed by
    ``idx_hub_findings_current_tenant_ordinal``. The guarded ALTER seeds
    pre-existing rows with the ``MAX(bigint)`` sort sentinel; the one-shot
    backfill resolves the real ordinal for rows with a ledger pointer, matching
    the old ``COALESCE(subquery, 9223372036854775807)`` value. Idempotent: the
    backfill only runs while the column is freshly added and no-ops on empty
    tables. Requires ``ledger_finding_id`` to already exist.
    """
    conn.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_schema = current_schema()
                  AND table_name = 'hub_findings_current'
                  AND column_name = 'ledger_ordinal'
            ) THEN
                ALTER TABLE hub_findings_current
                    ADD COLUMN ledger_ordinal BIGINT NOT NULL DEFAULT 9223372036854775807;
                UPDATE hub_findings_current c SET ledger_ordinal = COALESCE(
                    (
                        SELECT f.ordinal FROM compliance_hub_findings f
                        WHERE f.tenant_id = c.tenant_id
                          AND f.finding_id = c.ledger_finding_id
                        LIMIT 1
                    ),
                    9223372036854775807
                )
                WHERE c.ledger_finding_id IS NOT NULL AND c.ledger_finding_id <> '';
            END IF;
        END $$;
        """
    )


def _resolve_current_ledger_ordinal_postgres(
    conn: Any,
    tenant_id: str,
    ledger_finding_id: str,
) -> int:
    """Return the ledger ingest ``ordinal`` for a current-state row's pointer.

    Point lookup on the ledger primary key ``(tenant_id, finding_id)``; the
    ledger row is always written (``add``) before the current batch upsert.
    Missing pointers fall back to the sort sentinel (``MAX(bigint)``).
    """
    if not ledger_finding_id:
        return _LEDGER_ORDINAL_SENTINEL
    row = conn.execute(
        "SELECT ordinal FROM compliance_hub_findings WHERE tenant_id = %s AND finding_id = %s",
        (tenant_id, ledger_finding_id),
    ).fetchone()
    return int(row[0]) if row else _LEDGER_ORDINAL_SENTINEL


def _fetch_ledger_ordinals_postgres(
    conn: Any,
    tenant_id: str,
    finding_ids: Sequence[str],
) -> dict[str, int]:
    """Bulk variant of :func:`_resolve_current_ledger_ordinal_postgres`.

    One ``= ANY`` lookup on the ledger primary key for a whole batch instead of a
    per-row point SELECT, so the current-state bulk upsert resolves every ledger
    ordinal in a single round-trip. Missing pointers simply stay out of the map;
    the caller falls back to the sort sentinel.
    """
    ids = [str(fid) for fid in finding_ids if fid]
    if not ids:
        return {}
    rows = conn.execute(
        "SELECT finding_id, ordinal FROM compliance_hub_findings WHERE tenant_id = %s AND finding_id = ANY(%s)",
        (tenant_id, ids),
    ).fetchall()
    return {str(finding_id): int(ordinal) for finding_id, ordinal in rows}


def _fetch_ledger_payloads_postgres(
    conn: Any,
    tenant_id: str,
    finding_ids: Sequence[str],
) -> dict[str, dict[str, Any]]:
    if not finding_ids:
        return {}
    rows = conn.execute(
        """
        SELECT finding_id, payload
        FROM compliance_hub_findings
        WHERE tenant_id = %s AND finding_id = ANY(%s)
        """,
        (tenant_id, list(finding_ids)),
    ).fetchall()
    if not rows:
        return {}
    ordered_ids = [str(finding_id) for finding_id, _raw in rows]
    payloads = [decode_hub_payload(raw) for _finding_id, raw in rows]
    hydrated = hydrate_finding_payloads_postgres(conn, tenant_id, payloads)
    return dict(zip(ordered_ids, hydrated))


def _postgres_current_row_from_db(row: tuple[Any, ...], *, has_ledger_col: bool) -> dict[str, Any]:
    raw_payload = row[12]
    current_row = {
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
        "payload": decode_hub_payload(raw_payload),
    }
    if has_ledger_col:
        current_row["ledger_finding_id"] = row[13]
        if len(row) > 14:
            current_row["ledger_ordinal"] = int(row[14])
    return current_row


def _hydrate_postgres_current_rows(
    conn: Any,
    tenant_id: str,
    current_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    ledger_map = batch_ledger_payloads(
        lambda ids: _fetch_ledger_payloads_postgres(conn, tenant_id, ids),
        [str(row.get("ledger_finding_id") or "") for row in current_rows],
    )
    hydrated: list[dict[str, Any]] = []
    for row in current_rows:
        hydrated_row = dict(row)
        hydrated_row["payload"] = hydrate_current_payload(row, ledger_payloads=ledger_map)
        hydrated.append(hydrated_row)
    return hydrated


def _ensure_backfill_marker_table(conn: Any) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS agent_bom_hub_backfills (
            name TEXT PRIMARY KEY,
            completed_at TEXT NOT NULL
        )
        """
    )


def _backfill_completed(conn: Any, name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM agent_bom_hub_backfills WHERE name = %s LIMIT 1",
        (name,),
    ).fetchone()
    return row is not None


def _mark_backfill_completed(conn: Any, name: str) -> None:
    conn.execute(
        "INSERT INTO agent_bom_hub_backfills (name, completed_at) VALUES (%s, %s) ON CONFLICT (name) DO NOTHING",
        (name, _now_utc_iso()),
    )


def _run_gated_backfill(conn: Any, name: str, update_sql: str) -> None:
    """Run a one-time column backfill exactly once across process restarts.

    Un-indexed backfill ``UPDATE``s re-ran on EVERY store init: full-table scans
    that blew the default 15s statement_timeout at scale (so reads and ingest
    500'd) and, for predicates like ``cvss_score = 0``, re-matched genuinely
    unrated rows forever (0->0 rewrites = MVCC bloat each boot). #3980 only
    guarded the primary-key migration. This gates every backfill behind a cheap
    marker lookup so an already-migrated (possibly multi-million-row) table pays
    a single indexed probe and issues no UPDATE. The ``update_sql`` itself is
    additionally refined to touch only rows whose materialised value actually
    differs from the payload, so even the one-time run is idempotent.
    """
    if _backfill_completed(conn, name):
        return
    conn.execute(update_sql)
    _mark_backfill_completed(conn, name)


def _postgres_current_has_ledger_col(conn: Any) -> bool:
    row = conn.execute(
        """
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = 'hub_findings_current'
          AND column_name = 'ledger_finding_id'
        LIMIT 1
        """
    ).fetchone()
    return row is not None


class PostgresComplianceHubStore:
    """Shared hub store backing multi-replica self-hosted deployments."""

    def __init__(self, pool: ConnectionPool | None = None) -> None:
        self._pool = pool or _get_pool()
        self._ingest_stats_lock = threading.Lock()
        self._finding_count_by_tenant: dict[str, int] = {}
        self._init_tables()

    def _reset_ingest_stats(self, tenant_id: str) -> None:
        with self._ingest_stats_lock:
            self._finding_count_by_tenant.pop(tenant_id, None)

    def _bootstrap_ingest_stats(self, conn: Any, tenant_id: str) -> None:
        with self._ingest_stats_lock:
            if tenant_id in self._finding_count_by_tenant:
                return
        row = conn.execute(
            "SELECT COUNT(*) FROM compliance_hub_findings WHERE tenant_id = %s",
            (tenant_id,),
        ).fetchone()
        with self._ingest_stats_lock:
            if tenant_id in self._finding_count_by_tenant:
                return
            self._finding_count_by_tenant[tenant_id] = int(row[0]) if row else 0

    @staticmethod
    def _existing_finding_ids(conn: Any, tenant_id: str, finding_ids: list[str]) -> set[str]:
        if not finding_ids:
            return set()
        rows = conn.execute(
            "SELECT finding_id FROM compliance_hub_findings WHERE tenant_id = %s AND finding_id = ANY(%s)",
            (tenant_id, finding_ids),
        ).fetchall()
        return {str(row[0]) for row in rows}

    def _init_tables(self) -> None:
        with self._pool.connection() as conn:
            ensure_postgres_schema_version(conn, "compliance_hub")
            _ensure_backfill_marker_table(conn)
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
            # Marker-gated + refined to only touch rows whose payload actually
            # carries a value the materialised column is missing (never re-match
            # correct rows or re-scan an already-migrated table on every boot).
            _run_gated_backfill(
                conn,
                "compliance_hub_findings.origin",
                "UPDATE compliance_hub_findings SET origin = COALESCE(payload->>'origin', '') "
                "WHERE origin = '' AND COALESCE(payload->>'origin', '') <> ''",
            )
            # Materialise severity/cvss sort keys so filtered severity/cvss
            # sorts ride a composite index rather than a payload-expression
            # sort (#3192). Backfill extracts from payload for legacy rows.
            conn.execute("ALTER TABLE compliance_hub_findings ADD COLUMN IF NOT EXISTS severity TEXT NOT NULL DEFAULT ''")
            _run_gated_backfill(
                conn,
                "compliance_hub_findings.severity",
                "UPDATE compliance_hub_findings SET severity = COALESCE(payload->>'severity', '') "
                "WHERE severity = '' AND COALESCE(payload->>'severity', '') <> ''",
            )
            conn.execute("ALTER TABLE compliance_hub_findings ADD COLUMN IF NOT EXISTS severity_rank INTEGER NOT NULL DEFAULT 0")
            _run_gated_backfill(
                conn,
                "compliance_hub_findings.severity_rank",
                # Mirror severity_policy_rank() so backfilled ranks match new
                # writes: info==low==1, none==0, everything unknown==-1 (#3192).
                # ``<> 0`` guard so 'none'/0-rank rows are not rewritten forever.
                "UPDATE compliance_hub_findings SET severity_rank = CASE LOWER(COALESCE(payload->>'severity', '')) "
                "WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 "
                "WHEN 'info' THEN 1 WHEN 'informational' THEN 1 WHEN 'none' THEN 0 "
                "ELSE -1 END WHERE severity_rank = 0 AND CASE LOWER(COALESCE(payload->>'severity', '')) "
                "WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 "
                "WHEN 'info' THEN 1 WHEN 'informational' THEN 1 WHEN 'none' THEN 0 "
                "ELSE -1 END <> 0",
            )
            conn.execute("ALTER TABLE compliance_hub_findings ADD COLUMN IF NOT EXISTS cvss_score DOUBLE PRECISION NOT NULL DEFAULT 0")
            # ``cvss_score = 0`` also matches genuinely-unrated rows, so without
            # the ``<> 0`` payload guard this rewrote them 0->0 on every boot
            # (MVCC bloat) and could never complete-skip. Refined + marker-gated.
            _run_gated_backfill(
                conn,
                "compliance_hub_findings.cvss_score",
                "UPDATE compliance_hub_findings SET cvss_score = COALESCE((payload->>'cvss_score')::float8, 0) "
                "WHERE cvss_score = 0 AND COALESCE((payload->>'cvss_score')::float8, 0) <> 0",
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
            # Non-origin covering sort indexes so the *unfiltered* default reads
            # (``WHERE tenant_id=? ORDER BY <col> DESC, ordinal``) ride an ordered
            # index range scan + LIMIT instead of a full-tenant sort — the
            # origin-scoped indexes cannot serve them (``origin`` is an
            # unconstrained middle column). Origin-scoped indexes are kept for the
            # filtered reads that need origin equality (#4049).
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_hub_findings_tenant_reach_all "
                "ON compliance_hub_findings(tenant_id, effective_reach_score DESC, ordinal)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_hub_findings_tenant_cvss_all "
                "ON compliance_hub_findings(tenant_id, cvss_score DESC, ordinal)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_hub_findings_tenant_severity_all "
                "ON compliance_hub_findings(tenant_id, severity_rank DESC, ordinal)"
            )
            # Back the severity GROUP BY (severity_breakdown) with a sargable
            # tenant/severity index so the overview aggregate scans the column
            # instead of decoding every payload (#3963). Partial on non-empty
            # severity for the same planner-shadowing reason as SQLite.
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_hub_findings_tenant_severity_ci "
                "ON compliance_hub_findings(tenant_id, LOWER(severity)) WHERE severity <> ''"
            )
            _ensure_tenant_rls(conn, "compliance_hub_findings", "tenant_id")
            from agent_bom.api.finding_lifecycle import (
                _CURRENT_LIFECYCLE_ORIGIN_INDEX_POSTGRES,
                _CURRENT_LIFECYCLE_POSTGRES_DDL,
                _CURRENT_LIFECYCLE_POSTGRES_OBSERVATIONS_LEGACY_DDL,
                _CURRENT_LIFECYCLE_SORT_INDEXES_POSTGRES,
            )
            from agent_bom.api.hub_observations_partition import (
                ensure_observation_partitions,
                is_observations_partitioned,
                observations_table_exists,
                partitioned_observations_parent_ddl,
            )

            conn.execute(_CURRENT_LIFECYCLE_POSTGRES_DDL)
            if not observations_table_exists(conn):
                conn.execute(partitioned_observations_parent_ddl())
                ensure_observation_partitions(conn)
            elif not is_observations_partitioned(conn):
                conn.execute(_CURRENT_LIFECYCLE_POSTGRES_OBSERVATIONS_LEGACY_DDL)
            else:
                ensure_observation_partitions(conn)
            _migrate_lifecycle_observations_l2_postgres(conn)
            _migrate_current_ledger_ref_postgres(conn)
            # Materialise the ledger ingest ordinal (needs ledger_finding_id) so
            # the sort indexes below can build on pre-existing tables (#3984).
            _migrate_current_ledger_ordinal_postgres(conn)
            _run_gated_backfill(
                conn,
                "hub_findings_current.cvss_score_null",
                "UPDATE hub_findings_current SET cvss_score = 0 WHERE cvss_score IS NULL",
            )
            # Promote origin to a materialised, indexed column so the exact
            # COUNT(*) rides the (tenant_id, origin) prefix instead of scanning
            # every row through payload->>'origin' (#3641). Idempotent guards.
            conn.execute("ALTER TABLE hub_findings_current ADD COLUMN IF NOT EXISTS origin TEXT NOT NULL DEFAULT ''")
            _run_gated_backfill(
                conn,
                "hub_findings_current.origin",
                "UPDATE hub_findings_current SET origin = COALESCE(payload->>'origin', '') "
                "WHERE origin = '' AND COALESCE(payload->>'origin', '') <> ''",
            )
            conn.execute(_CURRENT_LIFECYCLE_ORIGIN_INDEX_POSTGRES)
            # Materialise scan_id (default /v1/findings scan filter) so the read
            # and its COUNT(*) ride an index instead of a per-row payload->>
            # extract. Value mirrors the in-memory ``batch_id or scan_id`` key so
            # every backend agrees. Partial index (WHERE scan_id <> '') keeps the
            # common no-scan_id rows out so it cannot shadow the default read
            # (#3926). Idempotent guards.
            conn.execute("ALTER TABLE hub_findings_current ADD COLUMN IF NOT EXISTS scan_id TEXT NOT NULL DEFAULT ''")
            _run_gated_backfill(
                conn,
                "hub_findings_current.scan_id",
                "UPDATE hub_findings_current SET scan_id = "
                "COALESCE(NULLIF(payload->>'batch_id', ''), payload->>'scan_id', '') "
                "WHERE scan_id = '' AND COALESCE(NULLIF(payload->>'batch_id', ''), payload->>'scan_id', '') <> ''",
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_hub_findings_current_tenant_scan "
                "ON hub_findings_current(tenant_id, scan_id) WHERE scan_id <> ''"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_hub_findings_current_tenant_severity_ci "
                "ON hub_findings_current(tenant_id, LOWER(severity)) WHERE severity <> ''"
            )
            # Ordinal range-scan index + severity-composite sort indexes. Built
            # after the ledger_ordinal migration so pre-existing tables carry the
            # column first (#3984).
            for sort_index_sql in _CURRENT_LIFECYCLE_SORT_INDEXES_POSTGRES:
                conn.execute(sort_index_sql)
            _ensure_tenant_rls(conn, "hub_findings_current", "tenant_id")
            _ensure_tenant_rls(conn, "hub_findings_current_observations", "tenant_id")
            ensure_postgres_reference_tables(conn)
            _ensure_tenant_rls(conn, "hub_cve_intel", "tenant_id")
            _ensure_tenant_rls(conn, "hub_framework_refs", "tenant_id")
            conn.commit()

    @staticmethod
    def _migrate_primary_key(conn: Any) -> None:
        """Collapse the primary key to ``(tenant_id, finding_id)`` (true no-op once done).

        Pre-idempotency deployments keyed on ``(tenant_id, finding_id, ordinal)``
        so every resend of the same finding appended a fresh row. Dedup existing
        duplicates (keep the lowest ordinal), then swap the primary key.

        The dedup DELETE is a full-table self-join — O(n^2)-class on a large
        table — so we must never run it on an already-migrated store. Probe
        ``pg_constraint`` first and return early when the collapsed key is
        already in place: no DELETE, no DDL. Only a genuinely old-shape (or
        missing) primary key triggers the dedup + constraint swap. Without this
        guard the self-join ran on every store init and blew the default 15s
        ``statement_timeout`` at scale, so init 500'd on every request (#3980).
        """
        pk_row = conn.execute(
            """
            SELECT string_agg(a.attname, ',' ORDER BY array_position(c.conkey, a.attnum))
              FROM pg_constraint c
              JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = ANY(c.conkey)
             WHERE c.conrelid = 'compliance_hub_findings'::regclass
               AND c.contype = 'p'
            """
        ).fetchone()
        pk_cols = pk_row[0] if pk_row else None
        if pk_cols == "tenant_id,finding_id":
            # Already collapsed — skip the dedup DELETE + DDL entirely so an
            # already-migrated (possibly very large) table pays nothing at
            # init and cannot exceed statement_timeout (#3980).
            return
        # Old-shape or missing primary key: drop duplicates ahead of the unique
        # key, keeping the original ingest, then swap the primary key.
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

    def _write_ledger_batch(self, conn: Any, tenant_id: str, findings: list[dict[str, Any]]) -> int:
        """Append/refresh ledger rows on ``conn`` — no commit, no stats bump.

        Returns the count of genuinely-new rows so the caller can bump the
        cached tenant total AFTER the shared transaction commits. Bootstraps the
        ingest-stats counter (a read) inside the same connection. Shared by the
        committing :meth:`add` and the single-transaction :meth:`ingest_batch_atomic`.
        """
        self._bootstrap_ingest_stats(conn, tenant_id)
        if not findings:
            return 0
        now = _now_utc_iso()
        rows_to_insert: list[tuple[str, str, dict[str, Any]]] = []
        # Hoist the reference-table existence probe to once per batch (it is
        # otherwise two CREATE-IF-NOT-EXISTS round-trips per row).
        ensure_postgres_reference_tables(conn)
        for original in findings:
            if not isinstance(original, dict):
                continue
            frameworks_csv = _frameworks_csv(original)
            slim = persist_finding_references_postgres(conn, tenant_id, original, ensure_tables=False)
            payload = _redact_finding(slim)
            finding_id = str(payload.get("id") or f"hub-{now}-{id(original)}")
            rows_to_insert.append((finding_id, frameworks_csv, payload))
        existing_ids = self._existing_finding_ids(conn, tenant_id, [row[0] for row in rows_to_insert])
        new_rows = sum(1 for finding_id, _, _ in rows_to_insert if finding_id not in existing_ids)
        # Idempotent ingest: a resend of the same (tenant_id, finding_id) refreshes
        # payload/metadata and keeps the original ``ordinal`` (the BIGSERIAL default
        # only advances on genuine inserts). Batched via ``executemany`` (psycopg
        # pipelines the round-trips) so a connector initial-sync of millions is not
        # a per-row execute loop — same SQL, same ON CONFLICT idempotency, same
        # tenant scope, ~10x the row/s of the per-row loop (wave-2 residual #2).
        insert_params = [
            (
                tenant_id,
                finding_id,
                now,
                str(payload.get("source") or ""),
                frameworks_csv,
                encode_hub_payload(payload),
                compute_effective_reach_score(payload),
                str(payload.get("origin") or ""),
                str(payload.get("severity") or ""),
                _severity_rank(payload),
                _cvss_value(payload),
            )
            for finding_id, frameworks_csv, payload in rows_to_insert
        ]
        if insert_params:
            with conn.cursor() as cur:
                cur.executemany(
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
                    insert_params,
                )
        return new_rows

    def _bump_tenant_total(self, tenant_id: str, new_rows: int) -> int:
        """Advance the cached tenant total by ``new_rows`` (called post-commit)."""
        with self._ingest_stats_lock:
            if tenant_id in self._finding_count_by_tenant:
                self._finding_count_by_tenant[tenant_id] += new_rows
                return self._finding_count_by_tenant[tenant_id]
        return self.count(tenant_id)

    def add(self, tenant_id: str, findings: list[dict[str, Any]]) -> int:
        with _tenant_connection(self._pool) as conn:
            new_rows = self._write_ledger_batch(conn, tenant_id, findings)
            conn.commit()
        _invalidate_overview_severity(tenant_id)
        return self._bump_tenant_total(tenant_id, new_rows)

    def ingest_batch_atomic(
        self,
        tenant_id: str,
        findings: list[dict[str, Any]],
        *,
        observed_at: str,
        batch_id: str,
        source: str,
        reconcile_absent: bool,
        present_canonical_ids: set[str],
    ) -> tuple[int, int]:
        """Ledger append + current upsert (+ reconcile) in ONE transaction.

        Each write method used to open its own tenant connection and commit
        independently, so a failure between the ledger ``add`` and the
        current-state upsert left the ledger committed but current-state not:
        the ledger inflated while the findings stayed invisible (wave-2 residual
        #1). Threading a single ``_tenant_connection`` through all three writes
        and committing once makes a mid-batch failure roll BOTH back. The cached
        tenant total is bumped only after the commit succeeds so a rolled-back
        batch does not inflate it. Returns ``(new_total, reconciled)``.
        """
        with _tenant_connection(self._pool) as conn:
            new_rows = self._write_ledger_batch(conn, tenant_id, findings)
            self._write_current_batch(
                conn,
                tenant_id,
                findings,
                observed_at=observed_at,
                batch_id=batch_id,
                source=source,
            )
            reconciled = 0
            if reconcile_absent:
                reconciled = self._reconcile_current_absent_conn(
                    conn,
                    tenant_id,
                    present_canonical_ids=present_canonical_ids,
                    observed_at=observed_at,
                    scope_source=source,
                )
            conn.commit()
        _invalidate_overview_severity(tenant_id)
        from agent_bom.api.findings_count_cache import invalidate_tenant

        invalidate_tenant(tenant_id)
        new_total = self._bump_tenant_total(tenant_id, new_rows)
        return new_total, reconciled

    def list(self, tenant_id: str) -> list[dict[str, Any]]:
        with _tenant_connection(self._pool) as conn:
            rows = conn.execute(
                "SELECT payload FROM compliance_hub_findings WHERE tenant_id = %s ORDER BY ordinal ASC",
                (tenant_id,),
            ).fetchall()
            payloads = [decode_hub_payload(row[0]) for row in rows]
            return hydrate_finding_payloads_postgres(conn, tenant_id, payloads)

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
            # Filter on the materialised severity STRING (exact, lowercased) so
            # every backend agrees; ``severity_rank`` collapses info==low and is
            # kept for ORDER BY only (#3192).
            where.append("LOWER(severity) = %s")
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
            payloads = [decode_hub_payload(row[0]) for row in rows]
            out = hydrate_finding_payloads_postgres(conn, tenant_id, payloads)
        return out, total

    def severity_breakdown(self, tenant_id: str) -> dict[str, int]:
        with _tenant_connection(self._pool) as conn:
            # GROUP BY the materialised ``severity`` column (populated on ingest,
            # backed by the tenant/severity index) instead of an unindexed per-row
            # ``payload->>'severity'`` JSON decode (#3963).
            rows = conn.execute(
                """
                SELECT LOWER(COALESCE(NULLIF(severity, ''), 'unknown')) AS sev, COUNT(*)
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

    def current_severity_breakdown(
        self,
        tenant_id: str,
        *,
        origin: str | None = None,
        since: str | None = None,
    ) -> dict[str, int]:
        # GROUP BY the materialised ``severity`` on the current-state table with
        # the SAME tenant/since/origin predicates ``list_current_page`` counts on,
        # so the exec headline reconciles exactly with the ``/v1/findings``
        # drill-down and retired/aged ledger rows never inflate it (#3961/#4009).
        where = ["tenant_id = %s"]
        params: list[Any] = [tenant_id]
        if since:
            where.append("last_seen >= %s")
            params.append(since)
        if origin is not None:
            where.append("origin = %s")
            params.append(origin)
        where_sql = " AND ".join(where)
        with _tenant_connection(self._pool) as conn:
            rows = conn.execute(
                f"""
                SELECT LOWER(COALESCE(NULLIF(severity, ''), 'unknown')) AS sev, COUNT(*)
                FROM hub_findings_current
                WHERE {where_sql}
                GROUP BY sev
                """,  # nosec B608
                tuple(params),
            ).fetchall()
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}
        for sev, count in rows:
            key = str(sev or "unknown").lower()
            counts[key] = counts.get(key, 0) + int(count)
        return counts

    def current_kev_count(
        self,
        tenant_id: str,
        *,
        origin: str | None = None,
        since: str | None = None,
    ) -> int:
        # Same tenant/since/origin predicates as ``current_severity_breakdown``.
        # The KEV flag is not a current-state column, so resolve it from the
        # current payload, the joined ledger payload, and the CVE-intel reference
        # — the same places the drill hydrates it — so the exec KEV count
        # reconciles with the /v1/findings KEV rows (#3961).
        where = ["c.tenant_id = %s"]
        params: list[Any] = [tenant_id]
        if since:
            where.append("c.last_seen >= %s")
            params.append(since)
        if origin is not None:
            where.append("c.origin = %s")
            params.append(origin)
        where_sql = " AND ".join(where)
        kev_cond = " OR ".join(_kev_json_cond_postgres(col) for col in ("c.payload", "l.payload", "i.payload"))
        with _tenant_connection(self._pool) as conn:
            row = conn.execute(
                f"""
                SELECT COUNT(*)
                FROM hub_findings_current c
                LEFT JOIN compliance_hub_findings l
                    ON l.tenant_id = c.tenant_id AND l.finding_id = c.ledger_finding_id
                LEFT JOIN hub_cve_intel i
                    ON i.tenant_id = c.tenant_id AND i.cve_id = (l.payload->>'intel_ref')
                WHERE {where_sql} AND ({kev_cond})
                """,  # nosec B608
                tuple(params),
            ).fetchone()
        return int(row[0]) if row else 0

    def framework_slug_counts(self, tenant_id: str) -> dict[str, int]:
        from agent_bom.compliance_coverage import normalize_framework_slug

        # Unnest + aggregate the denormalised CSV IN SQL so the query returns
        # O(distinct slugs) rows instead of pulling every ledger row into Python
        # to count on the event loop (#3963). Raw tokens are folded to canonical
        # slugs (alias/underscore normalisation) over the handful of results.
        with _tenant_connection(self._pool) as conn:
            rows = conn.execute(
                """
                SELECT TRIM(token) AS slug, COUNT(*) AS n
                FROM compliance_hub_findings,
                     unnest(string_to_array(applicable_frameworks_csv, ',')) AS token
                WHERE tenant_id = %s AND applicable_frameworks_csv <> ''
                GROUP BY TRIM(token)
                HAVING TRIM(token) <> ''
                """,
                (tenant_id,),
            ).fetchall()
        counts: dict[str, int] = {}
        for slug, n in rows:
            canonical = normalize_framework_slug(str(slug))
            counts[canonical] = counts.get(canonical, 0) + int(n)
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
        self._reset_ingest_stats(tenant_id)
        _invalidate_overview_severity(tenant_id)
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
        with _tenant_connection(self._pool) as conn:
            self._write_current_batch(
                conn,
                tenant_id,
                findings,
                observed_at=observed_at,
                batch_id=batch_id,
                source=source,
            )
            conn.commit()

    def _write_current_batch(
        self,
        conn: Any,
        tenant_id: str,
        findings: Sequence[dict[str, Any]],
        *,
        observed_at: str,
        batch_id: str,
        source: str = "",
    ) -> None:
        """Upsert current-state rows on ``conn`` — no commit.

        Shared by the committing :meth:`upsert_current_batch` and the
        single-transaction :meth:`ingest_batch_atomic`.
        """
        from agent_bom.api.finding_lifecycle import (
            apply_observation_to_current,
            lifecycle_metrics,
            resolve_canonical_id,
        )

        clean = _redact_findings(findings)
        if not clean:
            return
        now = _now_utc_iso()
        # observed_at is batch-level: ensure its monthly partition exists once
        # per batch so a backdated bulk import (older than the pre-provisioned
        # behind=1 window) does not raise a raw CheckViolation -> 500. Out of
        # the bounded window raises ObservationPartitionRangeError -> 4xx.
        from agent_bom.api.hub_observations_partition import ensure_observation_partition_for

        ensure_observation_partition_for(conn, observed_at)
        # Probe the ledger column ONCE per batch/connection — the schema does
        # not change mid-batch. It was previously an information_schema query
        # per row, the dominant write-path amplifier at scale.
        has_ledger_col = _postgres_current_has_ledger_col(conn)
        payload_select = "payload, ledger_finding_id" if has_ledger_col else "payload"

        # ── Bulk current-state upsert (wave-2 residual #2) ───────────────────
        # The per-row loop issued up to four round-trips per finding (observation
        # insert, existing-current SELECT, ledger-ordinal SELECT, current upsert),
        # so a connector initial-sync of millions crawled. This batches each of
        # those into ONE round-trip while preserving the EXACT lifecycle
        # semantics: the observation ``ON CONFLICT DO NOTHING RETURNING`` yields
        # precisely the canonicals newly observed this batch (idempotent replay of
        # the same batch_id returns none), first-occurrence-per-canonical is kept
        # (later in-batch duplicates were skipped by the observation dedup), the
        # prior-batch current row still feeds ``apply_observation_to_current``, and
        # the final upsert is byte-identical SQL.
        row_meta: list[tuple[str, dict[str, Any], Any, str, dict[str, Any]]] = []
        obs_params: list[tuple[str, str, str, str]] = []
        for payload in clean:
            canonical = resolve_canonical_id(payload, source=source)
            metrics = lifecycle_metrics(payload)
            ledger_finding_id = resolve_ledger_finding_id(payload, canonical_id=canonical)
            overlay = current_state_overlay(payload) if ledger_finding_id else dict(payload)
            row_meta.append((canonical, payload, metrics, ledger_finding_id or "", overlay))
            obs_params.append((tenant_id, canonical, batch_id, observed_at))

        inserted_canonicals: set[str] = set()
        with conn.cursor() as obs_cur:
            obs_cur.executemany(
                """
                INSERT INTO hub_findings_current_observations
                    (tenant_id, canonical_id, scan_id, observed_at)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT DO NOTHING
                RETURNING canonical_id
                """,
                obs_params,
                returning=True,
            )
            while True:
                if obs_cur.pgresult is not None and obs_cur.pgresult.ntuples:
                    inserted_canonicals.update(str(row[0]) for row in obs_cur.fetchall())
                if not obs_cur.nextset():
                    break
        if not inserted_canonicals:
            return

        # First occurrence per newly-observed canonical, in ingest order — mirrors
        # the per-row loop that processed the first and skipped later duplicates.
        to_process: list[tuple[str, dict[str, Any], Any, str, dict[str, Any]]] = []
        seen_canonical: set[str] = set()
        for meta in row_meta:
            canonical = meta[0]
            if canonical not in inserted_canonicals or canonical in seen_canonical:
                continue
            seen_canonical.add(canonical)
            to_process.append(meta)

        # One SELECT for every prior-batch current row this batch touches, hydrated
        # in bulk, so ``apply_observation_to_current`` merges against real history.
        canonical_list = [meta[0] for meta in to_process]
        existing_rows = conn.execute(
            f"""
            SELECT canonical_id, first_seen, last_seen, status, severity, severity_rank,
                   cvss_score, effective_reach_score, scan_count, resolved_at, reopened_at,
                   updated_at, {payload_select}
            FROM hub_findings_current
            WHERE tenant_id = %s AND canonical_id = ANY(%s)
            """,  # nosec B608
            (tenant_id, canonical_list),
        ).fetchall()
        existing_map: dict[str, dict[str, Any]] = {}
        if existing_rows:
            parsed = [_postgres_current_row_from_db(row, has_ledger_col=has_ledger_col) for row in existing_rows]
            for hydrated in _hydrate_postgres_current_rows(conn, tenant_id, parsed):
                existing_map[str(hydrated["canonical_id"])] = hydrated

        # One lookup for every ledger ordinal pointer.
        ordinal_map: dict[str, int] = {}
        if has_ledger_col:
            ordinal_map = _fetch_ledger_ordinals_postgres(conn, tenant_id, [meta[3] for meta in to_process if meta[3]])

        ledger_upsert_params: list[tuple[Any, ...]] = []
        plain_upsert_params: list[tuple[Any, ...]] = []
        for canonical, payload, metrics, ledger_finding_id, overlay in to_process:
            existing = existing_map.get(canonical)
            merged = apply_observation_to_current(
                existing,
                canonical_id=canonical,
                observed_at=observed_at,
                metrics=metrics,
                payload=payload,
                updated_at=now,
            )
            origin_val = str(payload.get("origin") or "")
            # Canonical ``batch_id or scan_id`` scan filter key (#3926).
            scan_id_val = str(payload.get("batch_id") or payload.get("scan_id") or "")
            base = (
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
                encode_hub_payload(overlay),
            )
            if has_ledger_col:
                # Materialise the ledger ingest ordinal so ``sort=ordinal`` rides
                # idx_hub_findings_current_tenant_ordinal instead of a per-row
                # correlated ledger subquery (#3984).
                ledger_ordinal_val = ordinal_map.get(ledger_finding_id, _LEDGER_ORDINAL_SENTINEL)
                ledger_upsert_params.append((*base, ledger_finding_id or None, origin_val, scan_id_val, ledger_ordinal_val))
            else:
                plain_upsert_params.append((*base, origin_val, scan_id_val))

        if ledger_upsert_params:
            with conn.cursor() as up_cur:
                up_cur.executemany(
                    """
                    INSERT INTO hub_findings_current
                        (tenant_id, canonical_id, first_seen, last_seen, status, severity, severity_rank,
                         cvss_score, effective_reach_score, scan_count, resolved_at, reopened_at,
                         updated_at, payload, ledger_finding_id, origin, scan_id, ledger_ordinal)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s, %s, %s)
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
                        payload = EXCLUDED.payload,
                        ledger_finding_id = EXCLUDED.ledger_finding_id,
                        origin = EXCLUDED.origin,
                        scan_id = EXCLUDED.scan_id,
                        ledger_ordinal = EXCLUDED.ledger_ordinal
                    """,
                    ledger_upsert_params,
                )
        if plain_upsert_params:
            with conn.cursor() as up_cur:
                up_cur.executemany(
                    """
                    INSERT INTO hub_findings_current
                        (tenant_id, canonical_id, first_seen, last_seen, status, severity, severity_rank,
                         cvss_score, effective_reach_score, scan_count, resolved_at, reopened_at,
                         updated_at, payload, origin, scan_id)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s)
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
                        payload = EXCLUDED.payload,
                        origin = EXCLUDED.origin,
                        scan_id = EXCLUDED.scan_id
                    """,
                    plain_upsert_params,
                )

    def get_current(self, tenant_id: str, canonical_id: str) -> dict[str, Any] | None:
        with _tenant_connection(self._pool) as conn:
            has_ledger_col = _postgres_current_has_ledger_col(conn)
            payload_select = "payload, ledger_finding_id, ledger_ordinal" if has_ledger_col else "payload"
            row = conn.execute(
                f"""
                SELECT canonical_id, first_seen, last_seen, status, severity, severity_rank,
                       cvss_score, effective_reach_score, scan_count, resolved_at, reopened_at,
                       updated_at, {payload_select}
                FROM hub_findings_current
                WHERE tenant_id = %s AND canonical_id = %s
                """,  # nosec B608
                (tenant_id, canonical_id),
            ).fetchone()
            if row is None:
                return None
            current_row = _postgres_current_row_from_db(row, has_ledger_col=has_ledger_col)
            return _hydrate_postgres_current_rows(conn, tenant_id, [current_row])[0]

    def list_current_page(
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
        cursor: str | None = None,
        since: str | None = None,
    ) -> FindingCursorPage:
        from agent_bom.api.finding_lifecycle import enriched_finding_payload

        normalized_sort = sort if sort in ("effective_reach", "cvss", "severity", "ordinal") else "effective_reach"
        where = ["tenant_id = %s"]
        params: list[Any] = [tenant_id]
        if since:
            # Default read-window: bound to findings last observed within the
            # window so counts stay honestly "last Nd" at scale (#4009).
            where.append("last_seen >= %s")
            params.append(since)
        if origin is not None:
            # Materialised column (backfilled) so the exact COUNT(*) rides the
            # (tenant_id, origin, …) index prefix instead of scanning every row
            # through payload->>'origin' (#3641).
            where.append("origin = %s")
            params.append(origin)
        if severity is not None:
            # Match the materialised severity STRING (exact, lowercased) so all
            # backends agree; ``severity_rank`` stays ORDER-BY-only (#3192). The
            # ``severity <> ''`` guard lets the partial expression index
            # idx_hub_findings_current_tenant_severity_ci serve the filter (#3926).
            where.append("severity <> '' AND LOWER(severity) = %s")
            params.append(severity.lower())
        if scan_id is not None:
            # Materialised column (backfilled from batch_id|scan_id) so the scan
            # filter + COUNT(*) ride idx_hub_findings_current_tenant_scan instead
            # of a per-row payload->> extract. The ``scan_id <> ''`` guard lets the
            # partial index apply (a bound param is not provably non-empty) (#3926).
            where.append("scan_id <> '' AND scan_id = %s")
            params.append(scan_id)
        if cursor:
            keyset_sql, keyset_params = postgres_keyset_clause(normalized_sort, cursor)
            where.append(keyset_sql.removeprefix(" AND "))
            params.extend(keyset_params)
        where_sql = " AND ".join(where)
        order_sql = _postgres_current_order_clause(normalized_sort)
        page_limit = max(0, int(limit))
        fetch_limit = page_limit + 1 if page_limit >= 0 else page_limit

        with _tenant_connection(self._pool) as conn:
            total: int | None
            if include_total and not cursor:
                total_row = conn.execute(
                    f"SELECT COUNT(*) FROM hub_findings_current WHERE {where_sql}",  # nosec B608
                    tuple(params),
                ).fetchone()
                total = int(total_row[0]) if total_row else 0
            else:
                total = None
            has_ledger_col = _postgres_current_has_ledger_col(conn)
            payload_select = "payload, ledger_finding_id, ledger_ordinal" if has_ledger_col else "payload"
            if cursor:
                query_params: tuple[Any, ...] = (*params, fetch_limit)
                limit_sql = "LIMIT %s"
            else:
                query_params = (*params, fetch_limit, int(offset))
                limit_sql = "LIMIT %s OFFSET %s"
            rows = conn.execute(
                f"""
                SELECT canonical_id, first_seen, last_seen, status, severity, severity_rank,
                       cvss_score, effective_reach_score, scan_count, resolved_at, reopened_at,
                       updated_at, {payload_select}
                FROM hub_findings_current
                WHERE {where_sql} {order_sql} {limit_sql}
                """,  # nosec B608
                query_params,
            ).fetchall()
            current_rows = [_postgres_current_row_from_db(row, has_ledger_col=has_ledger_col) for row in rows]
            has_more = page_limit >= 0 and len(current_rows) > page_limit
            if has_more:
                current_rows = current_rows[:page_limit]
            hydrated_rows = _hydrate_postgres_current_rows(conn, tenant_id, current_rows)
        out: list[dict[str, Any]] = []
        for current_row in hydrated_rows:
            out.append(enriched_finding_payload(current_row))
        next_cursor = None
        if has_more and hydrated_rows:
            next_cursor = cursor_from_current_row(hydrated_rows[-1], sort=normalized_sort)
        return out, total, next_cursor

    def reconcile_current_absent(
        self,
        tenant_id: str,
        *,
        present_canonical_ids: set[str],
        observed_at: str,
        scope_source: str | None = None,
    ) -> int:
        with _tenant_connection(self._pool) as conn:
            total = self._reconcile_current_absent_conn(
                conn,
                tenant_id,
                present_canonical_ids=present_canonical_ids,
                observed_at=observed_at,
                scope_source=scope_source,
            )
            conn.commit()
        return total

    def _reconcile_current_absent_conn(
        self,
        conn: Any,
        tenant_id: str,
        *,
        present_canonical_ids: set[str],
        observed_at: str,
        scope_source: str | None = None,
    ) -> int:
        """Resolve open findings absent from the batch on ``conn`` — no commit.

        Shared by the committing :meth:`reconcile_current_absent` and the
        single-transaction :meth:`ingest_batch_atomic`.
        """
        now = _now_utc_iso()
        where = ["tenant_id = %s", "status IN ('open', 'reopened')"]
        params: list[Any] = [tenant_id]
        if scope_source is not None:
            where.append("payload->>'source' = %s")
            params.append(scope_source)
        where_sql = " AND ".join(where)
        total = 0
        rows = conn.execute(
            f"SELECT canonical_id FROM hub_findings_current WHERE {where_sql}",  # nosec B608
            tuple(params),
        ).fetchall()
        open_ids = {str(row[0]) for row in rows}
        absent = sorted(open_ids - present_canonical_ids)
        if not absent:
            return 0
        for offset in range(0, len(absent), RECONCILE_ABSENT_CHUNK):
            chunk = absent[offset : offset + RECONCILE_ABSENT_CHUNK]
            placeholders = ",".join("%s" for _ in chunk)
            cur = conn.execute(
                f"""
                UPDATE hub_findings_current
                SET status = 'resolved', resolved_at = %s, updated_at = %s
                WHERE {where_sql} AND canonical_id IN ({placeholders})
                """,  # nosec B608
                (observed_at, now, *params, *chunk),
            )
            total += int(cur.rowcount or 0)
        return total
