"""Postgres-backed Compliance Hub store for clustered deployments.

Mirrors ``SQLiteComplianceHubStore`` but uses the same connection pool +
tenant-RLS pattern as ``PostgresSCIMStore``. Selected when
``AGENT_BOM_POSTGRES_URL`` is set so a clustered API deployment can
share ingested findings across replicas.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from agent_bom.api.compliance_hub_store import (
    _LEDGER_ORDINAL_SENTINEL,
    _SCHEMA_VERSION,
    FindingCursorPage,
    FindingPage,
    _now_utc_iso,
    _redact_findings,
    status_sql_predicate,
)
from agent_bom.api.hub_current_payload import (
    batch_ledger_payloads,
    hydrate_current_payload,
)
from agent_bom.api.hub_payload_codec import decode_hub_payload
from agent_bom.api.hub_reference_store import (
    ensure_postgres_reference_tables,
    hydrate_finding_payloads_postgres,
)
from agent_bom.api.postgres_common import ConnectionPool, _ensure_tenant_rls, _get_pool, _tenant_connection
from agent_bom.api.storage.finding_current_reads import SqlCurrentFindingReads
from agent_bom.api.storage.finding_current_writes import reconcile_current, write_current_batch
from agent_bom.api.storage.finding_ingest_state import INGEST_STATE_DDL, LedgerIngestState, read_ingest_state, write_ingest_state
from agent_bom.api.storage.finding_ledger_writes import write_ledger_batch
from agent_bom.api.storage.finding_reads import SqlFindingReads
from agent_bom.api.storage.finding_write_session import finding_write_session
from agent_bom.api.storage.sql import PostgresBackend
from agent_bom.api.storage_schema import ensure_postgres_schema_version
from agent_bom.core.tenancy import require_explicit_tenant_id


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


def _bump_overview_revision_postgres(conn: Any, tenant_id: str) -> None:
    conn.execute(
        """INSERT INTO hub_overview_revisions (tenant_id, revision) VALUES (%s, 1)
        ON CONFLICT (tenant_id) DO UPDATE SET revision = hub_overview_revisions.revision + 1""",
        (tenant_id,),
    )


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


def _fetch_ledger_payloads_postgres(
    conn: Any,
    tenant_id: str,
    finding_ids: Sequence[str],
    *,
    for_update: bool = False,
) -> dict[str, dict[str, Any]]:
    if not finding_ids:
        return {}
    lock_clause = " FOR UPDATE" if for_update else ""
    rows = conn.execute(
        f"""
        SELECT finding_id, payload
        FROM compliance_hub_findings
        WHERE tenant_id = %s AND finding_id = ANY(%s)
        ORDER BY finding_id{lock_clause}
        """,  # nosec B608 — fixed internal lock clause; identifiers remain bound
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


def _ensure_ingest_support_tables(conn: Any) -> None:
    ensure_postgres_reference_tables(conn)
    conn.execute(INGEST_STATE_DDL)
    for table in ("hub_cve_intel", "hub_framework_refs", "hub_ledger_ingest_state"):
        _ensure_tenant_rls(conn, table, "tenant_id")


class PostgresComplianceHubStore:
    """Shared hub store backing multi-replica self-hosted deployments."""

    @property
    def _current_reads(self) -> SqlCurrentFindingReads:
        return SqlCurrentFindingReads(PostgresBackend(self._pool))

    @property
    def _ledger_reads(self) -> SqlFindingReads:
        return SqlFindingReads(PostgresBackend(self._pool))

    def __init__(self, pool: ConnectionPool | None = None) -> None:
        self._pool = pool or _get_pool()
        self._init_tables()

    def _init_tables(self) -> None:
        with self._pool.connection() as conn:
            if not ensure_postgres_schema_version(conn, "compliance_hub", _SCHEMA_VERSION):
                return
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
                    scan_id TEXT NOT NULL DEFAULT '',
                    PRIMARY KEY (tenant_id, finding_id)
                )
                """
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS hub_overview_revisions (
                tenant_id TEXT PRIMARY KEY, revision BIGINT NOT NULL DEFAULT 0
                )"""
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
            # Keep the append ledger filterable without decoding every JSONB
            # payload.  ``batch_id`` is the canonical ingest snapshot key; a
            # direct ``scan_id`` remains supported for scan-produced rows.
            conn.execute("ALTER TABLE compliance_hub_findings ADD COLUMN IF NOT EXISTS scan_id TEXT NOT NULL DEFAULT ''")
            _run_gated_backfill(
                conn,
                "compliance_hub_findings.scan_id",
                "UPDATE compliance_hub_findings SET scan_id = "
                "COALESCE(NULLIF(payload->>'batch_id', ''), payload->>'scan_id', '') "
                "WHERE scan_id = '' AND COALESCE(NULLIF(payload->>'batch_id', ''), payload->>'scan_id', '') <> ''",
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
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_hub_findings_tenant_scan ON compliance_hub_findings(tenant_id, scan_id) WHERE scan_id <> ''"
            )
            _ensure_tenant_rls(conn, "compliance_hub_findings", "tenant_id")
            _ensure_tenant_rls(conn, "hub_overview_revisions", "tenant_id")
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
            _ensure_ingest_support_tables(conn)
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
        tx = finding_write_session(conn, "postgres", tenant_id)
        state = read_ingest_state(tx, tenant_id)
        new_rows, _ = write_ledger_batch(tx, "postgres", tenant_id, findings)
        total = state.finding_count + new_rows
        write_ingest_state(tx, tenant_id, LedgerIngestState(total, state.next_ordinal))
        return total

    def add(self, tenant_id: str, findings: list[dict[str, Any]]) -> int:
        tenant_id = require_explicit_tenant_id(tenant_id)
        with _tenant_connection(self._pool) as conn:
            new_total = self._write_ledger_batch(conn, tenant_id, findings)
            if findings:
                _bump_overview_revision_postgres(conn, tenant_id)
            conn.commit()
        _invalidate_overview_severity(tenant_id)
        return new_total

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
        and committing once makes a mid-batch failure roll BOTH back. Durable
        tenant counts commit or roll back in that same transaction. Returns ``(new_total, reconciled)``.
        """
        tenant_id = require_explicit_tenant_id(tenant_id)
        with _tenant_connection(self._pool) as conn:
            new_total = self._write_ledger_batch(conn, tenant_id, findings)
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
            _bump_overview_revision_postgres(conn, tenant_id)
            conn.commit()
        _invalidate_overview_severity(tenant_id)
        from agent_bom.api.findings_count_cache import invalidate_tenant

        invalidate_tenant(tenant_id)
        return new_total, reconciled

    def list(self, tenant_id: str) -> list[dict[str, Any]]:
        return self._ledger_reads.list(tenant_id)

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
        return self._ledger_reads.list_page(
            tenant_id, limit=limit, offset=offset, sort=sort, severity=severity, scan_id=scan_id, origin=origin, include_total=include_total
        )

    def severity_breakdown(self, tenant_id: str) -> dict[str, int]:
        return self._ledger_reads.severity_breakdown(tenant_id)

    def current_severity_breakdown(
        self,
        tenant_id: str,
        *,
        origin: str | None = None,
        since: str | None = None,
        status: str | None = None,
    ) -> dict[str, int]:
        # GROUP BY the materialised ``severity`` on the current-state table with
        # the SAME tenant/since/origin/status predicates ``list_current_page``
        # counts on, so the exec headline reconciles exactly with the
        # ``/v1/findings`` drill-down and retired/aged/resolved rows never inflate
        # it (#3961/#4009).
        where = ["tenant_id = %s"]
        params: list[Any] = [tenant_id]
        if since:
            where.append("last_seen >= %s")
            params.append(since)
        if origin is not None:
            where.append("origin = %s")
            params.append(origin)
        status_sql, status_params = status_sql_predicate(status, placeholder="%s")
        if status_sql:
            where.append(status_sql)
            params.extend(status_params)
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
        status: str | None = None,
    ) -> int:
        # Same tenant/since/origin/status predicates as ``current_severity_breakdown``.
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
        status_sql, status_params = status_sql_predicate(status, placeholder="%s")
        if status_sql:
            where.append(status_sql.replace("status", "c.status", 1))
            params.extend(status_params)
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

    def current_failing_framework_slug_counts(
        self,
        tenant_id: str,
        *,
        origin: str | None = None,
        since: str | None = None,
        status: str | None = None,
    ) -> dict[str, int]:
        from agent_bom.compliance_coverage import normalize_framework_slug

        where = ["c.tenant_id = %s", "LOWER(c.severity) IN ('critical', 'high')"]
        params: list[Any] = [tenant_id]
        if since:
            where.append("c.last_seen >= %s")
            params.append(since)
        if origin is not None:
            where.append("c.origin = %s")
            params.append(origin)
        status_sql, status_params = status_sql_predicate(status, placeholder="%s")
        if status_sql:
            where.append(status_sql.replace("status", "c.status", 1))
            params.extend(status_params)
        with _tenant_connection(self._pool) as conn:
            rows = conn.execute(
                f"""
                SELECT TRIM(token), COUNT(*)
                FROM hub_findings_current c
                JOIN compliance_hub_findings l
                  ON l.tenant_id = c.tenant_id AND l.finding_id = c.ledger_finding_id
                CROSS JOIN LATERAL unnest(string_to_array(l.applicable_frameworks_csv, ',')) AS token
                WHERE {" AND ".join(where)} AND l.applicable_frameworks_csv <> ''
                GROUP BY TRIM(token)
                HAVING TRIM(token) <> ''
                """,  # nosec B608
                tuple(params),
            ).fetchall()
        counts: dict[str, int] = {}
        for slug, count in rows:
            canonical = normalize_framework_slug(str(slug))
            counts[canonical] = counts.get(canonical, 0) + int(count)
        return counts

    def overview_evidence_revision(self, tenant_id: str) -> int:
        return self._ledger_reads.overview_evidence_revision(tenant_id)

    def count(self, tenant_id: str) -> int:
        return self._ledger_reads.count(tenant_id)

    def clear(self, tenant_id: str) -> int:
        tenant_id = require_explicit_tenant_id(tenant_id)
        with _tenant_connection(self._pool) as conn:
            tx = finding_write_session(conn, "postgres", tenant_id)
            state = read_ingest_state(tx, tenant_id)
            cur = conn.execute(
                "DELETE FROM compliance_hub_findings WHERE tenant_id = %s",
                (tenant_id,),
            )
            conn.execute("DELETE FROM hub_findings_current WHERE tenant_id = %s", (tenant_id,))
            conn.execute("DELETE FROM hub_findings_current_observations WHERE tenant_id = %s", (tenant_id,))
            write_ingest_state(tx, tenant_id, LedgerIngestState(0, state.next_ordinal))
            _bump_overview_revision_postgres(conn, tenant_id)
            conn.commit()
        removed = cur.rowcount or 0
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
        tenant_id = require_explicit_tenant_id(tenant_id)
        with _tenant_connection(self._pool) as conn:
            self._write_current_batch(
                conn,
                tenant_id,
                findings,
                observed_at=observed_at,
                batch_id=batch_id,
                source=source,
            )
            if findings:
                _bump_overview_revision_postgres(conn, tenant_id)
            conn.commit()
        if findings:
            _invalidate_overview_severity(tenant_id)

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
        from agent_bom.api.hub_observations_partition import ensure_observation_partition_for

        tx = finding_write_session(conn, "postgres", tenant_id)
        clean = _redact_findings(findings)
        if clean:
            ensure_observation_partition_for(conn, observed_at)
            write_current_batch(
                tx,
                "postgres",
                tenant_id,
                clean,
                observed_at=observed_at,
                batch_id=batch_id,
                source=source,
                has_ledger=_postgres_current_has_ledger_col(conn),
            )

    def lookup_current_ids(
        self, tenant_id: str, canonical_ids: Sequence[str], *, scan_id: str | None = None, origin: str | None = None
    ) -> set[str]:
        return self._current_reads.lookup(tenant_id, canonical_ids, scan_id=scan_id, origin=origin)

    def get_current(self, tenant_id: str, canonical_id: str) -> dict[str, Any] | None:
        return self._current_reads.get(tenant_id, canonical_id)

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
        scope: Mapping[str, str] | None = None,
        status: str | None = None,
        scope_metadata: dict[str, Any] | None = None,
    ) -> FindingCursorPage:
        return self._current_reads.list_page(
            tenant_id,
            limit=limit,
            offset=offset,
            sort=sort,
            severity=severity,
            scan_id=scan_id,
            origin=origin,
            include_total=include_total,
            cursor=cursor,
            since=since,
            scope=scope,
            status=status,
            scope_metadata=scope_metadata,
        )

    def reconcile_current_absent(
        self,
        tenant_id: str,
        *,
        present_canonical_ids: set[str],
        observed_at: str,
        scope_source: str | None = None,
    ) -> int:
        tenant_id = require_explicit_tenant_id(tenant_id)
        with _tenant_connection(self._pool) as conn:
            total = self._reconcile_current_absent_conn(
                conn,
                tenant_id,
                present_canonical_ids=present_canonical_ids,
                observed_at=observed_at,
                scope_source=scope_source,
            )
            if total:
                _bump_overview_revision_postgres(conn, tenant_id)
            conn.commit()
        if total:
            _invalidate_overview_severity(tenant_id)
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
        tx = finding_write_session(conn, "postgres", tenant_id)
        return reconcile_current(
            tx, "postgres", tenant_id, present_canonical_ids=present_canonical_ids, observed_at=observed_at, scope_source=scope_source
        )
