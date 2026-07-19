"""PostgreSQL-backed audit and trend stores."""

from __future__ import annotations

import json
import logging
from typing import Any

from agent_bom.api.audit_log import (
    _MAX_APPEND_RETRIES,
    AuditEntry,
    _AuditChainCheckpoint,
    _verify_audit_chain_with_checkpoint,
)
from agent_bom.api.storage_schema import ensure_postgres_schema_version
from agent_bom.baseline import TrendPoint

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
                conn.execute(
                    f"CREATE UNIQUE INDEX IF NOT EXISTS {_AUDIT_FORK_GUARD_INDEX} "
                    "ON audit_log (team_id, prev_signature)"
                )
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
                head_row = conn.execute(
                    "SELECT hmac_signature FROM audit_log WHERE team_id = %s ORDER BY timestamp DESC, entry_id DESC LIMIT 1",
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
        conn.execute(
            """
            INSERT INTO audit_chain_checkpoint (tenant_id, entry_count, head_signature)
            VALUES (%s, 1, %s)
            ON CONFLICT (tenant_id) DO UPDATE SET
                entry_count = audit_chain_checkpoint.entry_count + 1,
                head_signature = EXCLUDED.head_signature
            """,
            (tenant_id, head_signature),
        )

    def _latest_signature_for_tenant(self, tenant_id: str) -> str:
        # audit_log is under FORCE ROW LEVEL SECURITY, so a raw connection (no
        # tenant session) resolves abom_current_tenant() to 'default' and returns
        # zero rows for every other tenant — leaving prev_signature empty and
        # silently breaking the HMAC chain. Bind the requested tenant on a
        # tenant-scoped connection so RLS returns that tenant's real chain head.
        token = _current_tenant.set(tenant_id)
        try:
            with _tenant_connection(self._pool) as conn:
                row = conn.execute(
                    "SELECT hmac_signature FROM audit_log WHERE team_id = %s ORDER BY timestamp DESC, entry_id DESC LIMIT 1",
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
                raise
            break
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
        clauses: list[str] = []
        params: list[object] = []
        if tenant_id is not None:
            clauses.append("team_id = %s")
            params.append(tenant_id)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = (
            "SELECT entry_id, timestamp, action, actor, resource, details, prev_signature, hmac_signature "
            f"FROM audit_log{where} ORDER BY timestamp ASC, entry_id ASC LIMIT %s"  # nosec B608
        )
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
