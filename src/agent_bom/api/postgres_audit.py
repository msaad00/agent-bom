"""PostgreSQL-backed audit and trend stores."""

from __future__ import annotations

import json

from agent_bom.api.audit_log import AuditEntry
from agent_bom.baseline import TrendPoint

from .postgres_common import _current_tenant, _ensure_tenant_rls, _get_pool, _tenant_connection


class PostgresAuditLog:
    """PostgreSQL-backed append-only audit log."""

    def __init__(self, pool=None) -> None:
        self._pool = pool or _get_pool()
        self._last_sig_by_tenant: dict[str, str] = {}
        self._init_tables()
        self._hydrate_last_signatures()

    def _init_tables(self) -> None:
        with self._pool.connection() as conn:
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
            _ensure_tenant_rls(conn, "audit_log", "team_id")
            conn.commit()

    def _latest_signature_for_tenant(self, tenant_id: str) -> str:
        with self._pool.connection() as conn:
            row = conn.execute(
                "SELECT hmac_signature FROM audit_log WHERE team_id = %s ORDER BY timestamp DESC, entry_id DESC LIMIT 1",
                (tenant_id,),
            ).fetchone()
        return row[0] if row else ""

    def _hydrate_last_signatures(self) -> None:
        with self._pool.connection() as conn:
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
        prev_sig = self._last_sig_by_tenant.get(tenant_id)
        if not prev_sig:
            prev_sig = self._latest_signature_for_tenant(tenant_id)
        entry.prev_signature = prev_sig
        entry.sign()
        self._last_sig_by_tenant[tenant_id] = entry.hmac_signature
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
            conn.commit()

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

    def verify_integrity(self, limit: int = 1000, tenant_id: str | None = None) -> tuple[int, int]:
        entries = list(reversed(self.list_entries(limit=limit, tenant_id=tenant_id)))
        verified = 0
        tampered = 0
        prev_sig = entries[0].prev_signature if entries else ""
        for entry in entries:
            if entry.prev_signature != prev_sig or not entry.verify():
                tampered += 1
            else:
                verified += 1
            prev_sig = entry.hmac_signature
        return verified, tampered


class PostgresTrendStore:
    """PostgreSQL-backed trend history persistence."""

    def __init__(self, pool=None) -> None:
        self._pool = pool or _get_pool()
        self._init_tables()

    def _init_tables(self) -> None:
        with self._pool.connection() as conn:
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
