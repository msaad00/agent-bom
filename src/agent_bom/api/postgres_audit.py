"""PostgreSQL-backed audit and trend stores."""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from agent_bom.api.audit_log import (
    _MAX_APPEND_RETRIES,
    AuditEntry,
    _AuditChainCheckpoint,
    _verify_audit_chain_with_checkpoint,
)
from agent_bom.api.storage_schema import ensure_postgres_schema_version
from agent_bom.baseline import TrendPoint
from agent_bom.security import sanitize_error

from .postgres_common import (
    ConnectionPool,
    _current_tenant,
    _ensure_tenant_rls,
    _get_pool,
    _tenant_connection,
    bypass_tenant_rls,
)

logger = logging.getLogger(__name__)

# Name of the per-tenant chain-head uniqueness guard. A concurrent fork violates
# it (SQLSTATE 23505), which `append` catches to re-read the head and re-link.
_AUDIT_FORK_GUARD_INDEX = "audit_log_team_prevsig_uniq"


# Callers deliberately swallow audit failures so audit side effects never block
# the request (e.g. "audit must not block auth"). Without a log here, a rejected
# INSERT would drop hash-chained events invisibly.
_APPEND_REJECT_WARN_INTERVAL_SECONDS = 60.0
_last_append_reject_warn_monotonic = float("-inf")


def _warn_append_rejected(action: str, tenant_id: str, exc: Exception) -> None:
    """Rate-limited visibility for audit appends the database rejected."""
    global _last_append_reject_warn_monotonic
    now = time.monotonic()
    if now - _last_append_reject_warn_monotonic < _APPEND_REJECT_WARN_INTERVAL_SECONDS:
        return
    _last_append_reject_warn_monotonic = now
    logger.warning(
        "Audit append rejected (action=%s tenant=%s): %s — the entry was NOT "
        "persisted; callers that swallow audit errors are losing audit events "
        "(further rejections are logged at most once per %.0fs)",
        action,
        tenant_id,
        sanitize_error(exc, generic=True),
        _APPEND_REJECT_WARN_INTERVAL_SECONDS,
    )


def _is_chain_fork_conflict(exc: Exception) -> bool:
    """True when ``exc`` is a unique violation on the chain fork-guard index."""
    if getattr(exc, "sqlstate", None) != "23505":
        return False
    diag = getattr(exc, "diag", None)
    constraint = getattr(diag, "constraint_name", None) if diag else None
    # entry_id is a fresh uuid4 per entry, so an unlabeled unique violation on
    # this INSERT path is a fork race on (team_id, prev_signature).
    return constraint in (None, "", _AUDIT_FORK_GUARD_INDEX)


class PostgresAuditLog:
    """PostgreSQL-backed append-only audit log."""

    def __init__(self, pool: ConnectionPool | None = None) -> None:
        self._pool = pool or _get_pool()
        self._last_sig_by_tenant: dict[str, str] = {}
        self._init_tables()
        self._hydrate_last_signatures()

    def _init_tables(self) -> None:
        with self._pool.connection() as conn:
            if not ensure_postgres_schema_version(conn, "audit_log"):
                return
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    entry_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    action TEXT NOT NULL,
                    actor TEXT NOT NULL DEFAULT '',
                    resource TEXT NOT NULL DEFAULT '',
                    team_id TEXT NOT NULL DEFAULT 'default',
                    details JSONB NOT NULL DEFAULT '{}'::jsonb,
                    prev_signature TEXT NOT NULL DEFAULT '',
                    hmac_signature TEXT NOT NULL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_ts ON audit_log(timestamp DESC)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_resource ON audit_log(resource)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_team_ts ON audit_log(team_id, timestamp DESC)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_team_action_ts ON audit_log(team_id, action, timestamp DESC)")
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_log_team_resource_ts ON audit_log(team_id, resource text_pattern_ops, timestamp DESC)"
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_chain_checkpoint (
                    tenant_id TEXT PRIMARY KEY,
                    entry_count INTEGER NOT NULL,
                    head_signature TEXT NOT NULL
                )
                """
            )
            _ensure_tenant_rls(conn, "audit_log", "team_id")
            # Parity with the ~47 other tenant tables: the checkpoint cache is a
            # per-tenant summary of the audit_log chain head, so it lives under
            # the same FORCE ROW LEVEL SECURITY backstop keyed on tenant_id. The
            # append path writes it under the request tenant context (the same
            # value it inserts into audit_log.team_id on the same connection, so
            # it passes WITH CHECK whenever the audit_log insert does); the
            # cross-tenant startup rebuild below runs under an explicit
            # bypass_tenant_rls maintenance context.
            _ensure_tenant_rls(conn, "audit_chain_checkpoint", "tenant_id")
            conn.commit()
        self._ensure_fork_guard_index()
        self._hydrate_checkpoints()

    def _ensure_fork_guard_index(self) -> None:
        """Serialize the hash chain at the DB via per-tenant head uniqueness.

        ``UNIQUE (team_id, prev_signature)`` lets at most one row link to any
        given predecessor (and exactly one genesis, ``prev_signature = ''``, per
        tenant — the column is ``NOT NULL DEFAULT ''`` so no NULL defeats it), so
        two writers across threadpool workers or ``uvicorn --workers N`` processes
        cannot fork the chain: the loser's INSERT is rejected and retried against
        the advanced head. Built defensively — pre-existing forks in older data
        would fail index creation, so we log rather than refuse to start; appends
        still retry, but forks cannot be rejected until the data is reconciled.
        """
        try:
            with self._pool.connection() as conn:
                conn.execute(f"CREATE UNIQUE INDEX IF NOT EXISTS {_AUDIT_FORK_GUARD_INDEX} ON audit_log (team_id, prev_signature)")
                conn.commit()
        except Exception:
            logger.warning(
                "Could not create audit_log fork-guard unique index %s "
                "(pre-existing chain forks?); appends will retry but forks cannot "
                "be rejected at the DB until the existing rows are reconciled",
                _AUDIT_FORK_GUARD_INDEX,
                exc_info=True,
            )

    def _hydrate_checkpoints(self) -> None:
        # Enumerating DISTINCT team_id spans every tenant, which FORCE ROW LEVEL
        # SECURITY on audit_log hides from a normally-scoped connection (a
        # NOSUPERUSER role would only ever see the 'default' tenant here). This
        # is a trusted startup rebuild, so bind the RLS bypass session for the
        # cross-tenant read and the per-tenant checkpoint upsert. Both audit_log
        # and audit_chain_checkpoint now enforce tenant RLS, so the bypass is
        # required for this maintenance write to every tenant's checkpoint row.
        with bypass_tenant_rls(audit=False), _tenant_connection(self._pool) as conn:
            row = conn.execute("SELECT COUNT(*) FROM audit_chain_checkpoint").fetchone()
            if row and int(row[0]) > 0:
                return
            tenants = conn.execute("SELECT DISTINCT team_id FROM audit_log").fetchall()
            for (tenant_id,) in tenants:
                count_row = conn.execute(
                    "SELECT COUNT(*) FROM audit_log WHERE team_id = %s",
                    (tenant_id,),
                ).fetchone()
                # The chain tip is the successor-free row (its hmac_signature is
                # no other row's prev_signature), NOT the max-timestamp row: a
                # legacy dataset written by the pre-#4284 append path can carry a
                # true tip whose wall-clock timestamp predates an earlier link, so
                # a timestamp-ordered bootstrap would bake a stale head into the
                # checkpoint that the append fast path now trusts. The fork-guard
                # UNIQUE (team_id, prev_signature) makes the NOT EXISTS an index
                # probe; this one-time startup rebuild is bounded by tenant size.
                head_row = conn.execute(
                    """
                    SELECT a.hmac_signature
                    FROM audit_log a
                    WHERE a.team_id = %s
                      AND NOT EXISTS (
                          SELECT 1 FROM audit_log b
                          WHERE b.team_id = a.team_id
                            AND b.prev_signature = a.hmac_signature
                      )
                    ORDER BY a.hmac_signature
                    LIMIT 1
                    """,
                    (tenant_id,),
                ).fetchone()
                if not count_row or not head_row:
                    continue
                conn.execute(
                    """
                    INSERT INTO audit_chain_checkpoint (tenant_id, entry_count, head_signature)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (tenant_id) DO UPDATE SET
                        entry_count = EXCLUDED.entry_count,
                        head_signature = EXCLUDED.head_signature
                    """,
                    (tenant_id, int(count_row[0]), str(head_row[0])),
                )
            conn.commit()

    def _get_checkpoint(self, tenant_id: str) -> _AuditChainCheckpoint | None:
        # audit_chain_checkpoint is under FORCE ROW LEVEL SECURITY keyed on
        # tenant_id, so bind the requested tenant on the connection rather than
        # relying on the ambient request context — otherwise a verify call for a
        # tenant other than the ambient one would resolve zero rows and silently
        # fall back to a full re-scan.
        token = _current_tenant.set(tenant_id)
        try:
            with _tenant_connection(self._pool) as conn:
                row = conn.execute(
                    "SELECT entry_count, head_signature FROM audit_chain_checkpoint WHERE tenant_id = %s",
                    (tenant_id,),
                ).fetchone()
        finally:
            _current_tenant.reset(token)
        if not row:
            return None
        if len(row) >= 3:
            return _AuditChainCheckpoint(entry_count=int(row[1]), head_signature=str(row[2]))
        return _AuditChainCheckpoint(entry_count=int(row[0]), head_signature=str(row[1]))

    def _upsert_checkpoint(self, conn: Any, tenant_id: str, head_signature: str) -> None:
        # First-seed entry_count is the tenant's TRUE audit_log row count, not a
        # hardcoded 1: a legacy tenant whose rows predate its first checkpoint
        # upsert (the migration-owned schema creates the table empty and never
        # runs _hydrate_checkpoints) would otherwise seed entry_count=1 while N
        # historical rows exist, so verify_integrity's truncation check
        # (len(entries) == checkpoint.entry_count) under-counts until N further
        # appends accrue (#4294). The COUNT runs in the SAME transaction as the
        # audit_log INSERT that precedes it (so it includes the just-inserted
        # row) and only on the INSERT branch; the steady-state ON CONFLICT path
        # stays an O(1) increment, correct because each append adds exactly one
        # row once the checkpoint is seeded true. A genuine genesis (0 prior
        # rows) still seeds 1 — the just-inserted row.
        conn.execute(
            """
            INSERT INTO audit_chain_checkpoint (tenant_id, entry_count, head_signature)
            VALUES (%s, (SELECT COUNT(*) FROM audit_log WHERE team_id = %s), %s)
            ON CONFLICT (tenant_id) DO UPDATE SET
                entry_count = audit_chain_checkpoint.entry_count + 1,
                head_signature = EXCLUDED.head_signature
            """,
            (tenant_id, tenant_id, head_signature),
        )

    def backfill_checkpoints(self) -> int:
        """Reconcile every tenant's checkpoint to its true chain state (#4294).

        Recomputes ``entry_count`` (the tenant's audit_log row count) and
        ``head_signature`` (the successor-free chain tip — chain-order-correct
        regardless of wall-clock timestamp skew, mirroring
        ``_chain_tip_signature_from_log`` and #4293's head derivation) directly
        from ``audit_log`` for every tenant, healing legacy checkpoints seeded at
        ``entry_count=1`` and seeding tenants that have none. Idempotent: rerunning
        yields the same rows. Runs under an RLS-bypass maintenance session because
        it spans every tenant (same trusted context as ``_hydrate_checkpoints``).
        Returns the number of tenant checkpoints reconciled.
        """
        with bypass_tenant_rls(audit=False), _tenant_connection(self._pool) as conn:
            result = conn.execute(
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
            reconciled = result.rowcount if result.rowcount is not None and result.rowcount >= 0 else 0
            conn.commit()
        return reconciled

    def _latest_signature_for_tenant(self, tenant_id: str) -> str:
        # The chain head is the LAST-COMMITTED row, NOT the row with the latest
        # wall-clock timestamp. `AuditEntry.timestamp` is stamped at entry
        # creation, so a retried append (a fork-guard loser) re-signs against the
        # advanced head yet commits later carrying its original, older timestamp.
        # ORDER BY timestamp then returns a non-tip row whose successor slot is
        # already taken, so every subsequent append re-links to that stale head,
        # violates the fork guard, and retries to exhaustion — a permanent
        # per-tenant livelock (#4284). `audit_chain_checkpoint.head_signature` is
        # bumped in the SAME transaction as each audit_log insert (and rolled
        # back with a rejected fork), so it is the authoritative commit-order tip
        # and an O(1) primary-key read. `_get_checkpoint` binds the requested
        # tenant on the connection so FORCE ROW LEVEL SECURITY returns that
        # tenant's own checkpoint row rather than the ambient tenant's.
        checkpoint = self._get_checkpoint(tenant_id)
        if checkpoint is not None:
            return checkpoint.head_signature
        # No checkpoint row yet. In a migration-owned deployment the checkpoint
        # table is created empty and never batch-backfilled, so a tenant whose
        # audit_log rows predate its first checkpoint upsert has none. Treating
        # that as an empty chain (genesis, prev='') would try to re-insert a
        # second genesis and livelock against the fork guard, so derive the true
        # tip directly from audit_log — the successor-free row (its
        # hmac_signature is no other row's prev_signature), NOT the max-timestamp
        # row (#4284). The very next append seeds the checkpoint from it.
        return self._chain_tip_signature_from_log(tenant_id)

    def _chain_tip_signature_from_log(self, tenant_id: str) -> str:
        """Return the tenant's chain tip derived from audit_log links (no checkpoint).

        The tip is the row whose ``hmac_signature`` is not referenced as any
        other row's ``prev_signature``. This is chain-order-correct regardless of
        wall-clock timestamp skew; the fork-guard UNIQUE (team_id, prev_signature)
        makes the NOT EXISTS an index probe. Returns ``""`` for a tenant with no
        rows (a genuine genesis). Binds the requested tenant so FORCE ROW LEVEL
        SECURITY returns that tenant's rows rather than the ambient tenant's.
        """
        token = _current_tenant.set(tenant_id)
        try:
            with _tenant_connection(self._pool) as conn:
                row = conn.execute(
                    """
                    SELECT a.hmac_signature
                    FROM audit_log a
                    WHERE a.team_id = %s
                      AND NOT EXISTS (
                          SELECT 1 FROM audit_log b
                          WHERE b.team_id = a.team_id
                            AND b.prev_signature = a.hmac_signature
                      )
                    ORDER BY a.hmac_signature
                    LIMIT 1
                    """,
                    (tenant_id,),
                ).fetchone()
        finally:
            _current_tenant.reset(token)
        return row[0] if row else ""

    def _hydrate_last_signatures(self) -> None:
        # Cross-tenant enumeration hidden by FORCE ROW LEVEL SECURITY; run under a
        # trusted RLS-bypass session so the per-tenant cache covers every tenant.
        with bypass_tenant_rls(audit=False), _tenant_connection(self._pool) as conn:
            rows = conn.execute(
                """
                SELECT DISTINCT ON (team_id) team_id, hmac_signature
                FROM audit_log
                ORDER BY team_id, timestamp DESC, entry_id DESC
                """
            ).fetchall()
        self._last_sig_by_tenant = {str(row[0]): str(row[1] or "") for row in rows}

    def append(self, entry: AuditEntry) -> None:
        tenant_id = str((entry.details or {}).get("tenant_id") or _current_tenant.get())
        # The head read and the INSERT run on separate connections, so nothing
        # serializes them in-process — and across `uvicorn --workers N` processes
        # nothing could. The DB-level UNIQUE (team_id, prev_signature) rejects a
        # fork: a writer that lost the race re-reads the advanced head, re-signs,
        # and re-inserts. Both statements share one transaction so a rejected
        # INSERT rolls back its checkpoint bump too.
        attempts = 0
        # Bind the entry's own tenant for the INSERT, not just the head read:
        # callers may emit audit events before installing the request tenant
        # context (e.g. proxy-header auth), leaving the ambient contextvar on
        # another tenant — the RLS WITH CHECK on audit_log/audit_chain_checkpoint
        # would then reject the row and the event would be lost.
        token = _current_tenant.set(tenant_id)
        try:
            while True:
                attempts += 1
                entry.prev_signature = self._latest_signature_for_tenant(tenant_id)
                entry.sign()
                try:
                    with _tenant_connection(self._pool) as conn:
                        conn.execute(
                            """INSERT INTO audit_log
                               (entry_id, timestamp, action, actor, resource, team_id, details, prev_signature, hmac_signature)
                               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                            (
                                entry.entry_id,
                                entry.timestamp,
                                entry.action,
                                entry.actor,
                                entry.resource,
                                tenant_id,
                                json.dumps(entry.details),
                                entry.prev_signature,
                                entry.hmac_signature,
                            ),
                        )
                        self._upsert_checkpoint(conn, tenant_id, entry.hmac_signature)
                        conn.commit()
                except Exception as exc:
                    if _is_chain_fork_conflict(exc) and attempts <= _MAX_APPEND_RETRIES:
                        continue
                    _warn_append_rejected(entry.action, tenant_id, exc)
                    raise
                break
        finally:
            _current_tenant.reset(token)
        self._last_sig_by_tenant[tenant_id] = entry.hmac_signature

    def list_entries(
        self,
        action: str | None = None,
        resource: str | None = None,
        since: str | None = None,
        limit: int = 100,
        offset: int = 0,
        tenant_id: str | None = None,
    ) -> list[AuditEntry]:
        clauses: list[str] = []
        params: list[object] = []
        if tenant_id is not None:
            clauses.append("team_id = %s")
            params.append(tenant_id)
        if action:
            clauses.append("action = %s")
            params.append(action)
        if resource:
            clauses.append("resource LIKE %s")
            params.append(f"{resource}%")
        if since:
            clauses.append("timestamp >= %s")
            params.append(since)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = (
            "SELECT entry_id, timestamp, action, actor, resource, details, prev_signature, hmac_signature "
            f"FROM audit_log{where} ORDER BY timestamp DESC LIMIT %s OFFSET %s"  # nosec B608
        )
        params.extend([limit, offset])
        with _tenant_connection(self._pool) as conn:
            rows = conn.execute(sql, tuple(params)).fetchall()
        return [
            AuditEntry(
                entry_id=row[0],
                timestamp=row[1],
                action=row[2],
                actor=row[3],
                resource=row[4],
                details=row[5] if isinstance(row[5], dict) else json.loads(row[5]),
                prev_signature=row[6],
                hmac_signature=row[7],
            )
            for row in rows
        ]

    def count(self, action: str | None = None, tenant_id: str | None = None) -> int:
        sql = "SELECT COUNT(*) FROM audit_log"
        clauses: list[str] = []
        params: list[object] = []
        if tenant_id is not None:
            clauses.append("team_id = %s")
            params.append(tenant_id)
        if action:
            clauses.append("action = %s")
            params.append(action)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        with _tenant_connection(self._pool) as conn:
            row = conn.execute(sql, tuple(params)).fetchone()
        return row[0] if row else 0

    def _list_entries_chronological(
        self,
        limit: int,
        tenant_id: str | None = None,
    ) -> list[AuditEntry]:
        # Walk the entries in true chain-link order (genesis first), NOT by
        # wall-clock timestamp. `AuditEntry.timestamp` is stamped at entry
        # creation, so a retried or clock-skewed append can commit out of step
        # with its chain position (#4284) — a timestamp-ordered walk then mis-
        # scores a perfectly valid chain as tampered (its `prev_signature` no
        # longer matches the timestamp-preceding row). Follow the hash links from
        # the genesis row (`prev_signature = ''`) instead, mirroring the SQLite
        # path's append-ordered (`rowid ASC`) walk. RLS scopes rows to the bound
        # tenant and the fork-guard UNIQUE (team_id, prev_signature) makes each
        # recursive step an index probe; content tampering is still caught by
        # `entry.verify()` and the checkpoint entry-count/head comparison.
        anchor_clause = ""
        params: list[object] = []
        if tenant_id is not None:
            anchor_clause = "AND a.team_id = %s"
            params.append(tenant_id)
        sql = f"""
            WITH RECURSIVE chain AS (
                SELECT a.entry_id, a.timestamp, a.action, a.actor, a.resource,
                       a.details, a.prev_signature, a.hmac_signature, a.team_id,
                       0 AS depth
                FROM audit_log a
                WHERE a.prev_signature = '' {anchor_clause}
                UNION ALL
                SELECT n.entry_id, n.timestamp, n.action, n.actor, n.resource,
                       n.details, n.prev_signature, n.hmac_signature, n.team_id,
                       c.depth + 1
                FROM audit_log n
                JOIN chain c
                  ON n.team_id = c.team_id AND n.prev_signature = c.hmac_signature
            )
            SELECT entry_id, timestamp, action, actor, resource, details,
                   prev_signature, hmac_signature
            FROM chain
            ORDER BY depth
            LIMIT %s
        """  # nosec B608 - anchor_clause is a constant; values are parameterized
        params.append(limit)
        with _tenant_connection(self._pool) as conn:
            rows = conn.execute(sql, tuple(params)).fetchall()
        return [
            AuditEntry(
                entry_id=row[0],
                timestamp=row[1],
                action=row[2],
                actor=row[3],
                resource=row[4],
                details=row[5] if isinstance(row[5], dict) else json.loads(row[5]),
                prev_signature=row[6],
                hmac_signature=row[7],
            )
            for row in rows
        ]

    def verify_integrity(self, limit: int = 1000, tenant_id: str | None = None) -> tuple[int, int]:
        tenant_key = tenant_id or "default"
        total = self.count(tenant_id=tenant_id)
        fetch_limit = total if total else limit
        entries = self._list_entries_chronological(limit=fetch_limit, tenant_id=tenant_id)
        checkpoint = self._get_checkpoint(tenant_key)
        return _verify_audit_chain_with_checkpoint(entries, checkpoint)


class PostgresTrendStore:
    """PostgreSQL-backed trend history persistence."""

    def __init__(self, pool: ConnectionPool | None = None) -> None:
        self._pool = pool or _get_pool()
        self._init_tables()

    def _init_tables(self) -> None:
        with self._pool.connection() as conn:
            if not ensure_postgres_schema_version(conn, "trend_history"):
                return
            conn.execute("""
                CREATE TABLE IF NOT EXISTS trend_history (
                    id BIGSERIAL PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    team_id TEXT NOT NULL DEFAULT 'default',
                    total_vulns INTEGER NOT NULL,
                    critical INTEGER NOT NULL DEFAULT 0,
                    high INTEGER NOT NULL DEFAULT 0,
                    medium INTEGER NOT NULL DEFAULT 0,
                    low INTEGER NOT NULL DEFAULT 0,
                    posture_score REAL NOT NULL DEFAULT 0,
                    posture_grade TEXT NOT NULL DEFAULT ''
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_trend_history_team_ts ON trend_history(team_id, timestamp DESC)")
            _ensure_tenant_rls(conn, "trend_history", "team_id")
            conn.commit()

    def record(self, point: TrendPoint) -> None:
        with _tenant_connection(self._pool) as conn:
            conn.execute(
                """INSERT INTO trend_history
                   (timestamp, team_id, total_vulns, critical, high, medium, low, posture_score, posture_grade)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                (
                    point.timestamp,
                    _current_tenant.get(),
                    point.total_vulns,
                    point.critical,
                    point.high,
                    point.medium,
                    point.low,
                    point.posture_score,
                    point.posture_grade,
                ),
            )
            conn.commit()

    def get_history(self, limit: int = 30, tenant_id: str | None = None) -> list[TrendPoint]:
        token = None
        if tenant_id is not None:
            token = _current_tenant.set(tenant_id)
        try:
            with _tenant_connection(self._pool) as conn:
                rows = conn.execute(
                    "SELECT timestamp, total_vulns, critical, high, medium, low, posture_score, posture_grade "
                    "FROM trend_history ORDER BY timestamp DESC LIMIT %s",
                    (limit,),
                ).fetchall()
        finally:
            if token is not None:
                _current_tenant.reset(token)
        return [
            TrendPoint(
                timestamp=row[0],
                total_vulns=row[1],
                critical=row[2],
                high=row[3],
                medium=row[4],
                low=row[5],
                posture_score=row[6],
                posture_grade=row[7],
                tenant_id=tenant_id or _current_tenant.get(),
            )
            for row in rows
        ]
