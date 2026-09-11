"""Durable report admission and fenced, recoverable export claims."""

from __future__ import annotations

import json
import secrets
import sqlite3
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol

from agent_bom.api.models import JobStatus, ReportJob
from agent_bom.api.storage_schema import ensure_sqlite_schema_version


@dataclass(frozen=True)
class ReportClaim:
    job_id: str
    tenant_id: str
    token: str


class ReportJobStore(Protocol):
    def enqueue(self, job: ReportJob, max_active: int) -> bool: ...
    def get(self, job_id: str, tenant_id: str) -> ReportJob | None: ...
    def claim_next(
        self, lease_seconds: int, max_attempts: int, *, job_id: str | None = None, tenant_id: str | None = None
    ) -> ReportClaim | None: ...
    def renew(self, claim: ReportClaim, lease_seconds: int) -> bool: ...
    def finish(self, job: ReportJob, claim: ReportClaim) -> bool: ...


def _now() -> str:
    return datetime.fromtimestamp(time.time(), timezone.utc).isoformat()


# Deliberately portable scalar columns; payload stays an ordinary JSON document.
# Lease state is authoritative in columns, never in a caller-supplied payload.
REPORT_TABLE_SQL = """
    CREATE TABLE IF NOT EXISTS report_jobs (
        job_id TEXT NOT NULL,
        tenant_id TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at TEXT NOT NULL,
        started_at TEXT,
        completed_at TEXT,
        lease_token TEXT,
        lease_expires_at DOUBLE PRECISION,
        attempts INTEGER NOT NULL DEFAULT 0,
        error TEXT,
        data TEXT NOT NULL, PRIMARY KEY (tenant_id, job_id)
    )
"""
REPORT_INDEX_SQL = (
    "CREATE INDEX IF NOT EXISTS idx_report_tenant_status ON report_jobs(tenant_id, status)",
    "CREATE INDEX IF NOT EXISTS idx_report_claim ON report_jobs(status, lease_expires_at, created_at)",
)


class SQLReportJobStore:
    """Shared SQL contract; concrete stores own transactions and RLS sessions."""

    postgres = False

    @contextmanager
    def _connection(self, tenant_id: str | None, *, write: bool = False) -> Iterator[Any]:
        raise NotImplementedError
        yield  # pragma: no cover

    def _execute(self, conn: Any, sql: str, args: tuple = ()) -> Any:
        # Every SQL string is internal and static; only placeholder syntax varies.
        return conn.execute(sql.replace("?", "%s") if self.postgres else sql, args)

    def _clock(self, conn: Any) -> float:
        if self.postgres:
            return float(conn.execute("SELECT EXTRACT(EPOCH FROM clock_timestamp())").fetchone()[0])
        return time.time()

    def enqueue(self, job: ReportJob, max_active: int) -> bool:
        if job.status != JobStatus.PENDING:
            raise ValueError("Only pending reports may be enqueued")
        with self._connection(job.tenant_id, write=True) as conn:
            if self.postgres:
                self._execute(conn, "SELECT pg_advisory_xact_lock(hashtextextended(?, 0))", ("report-admission:" + job.tenant_id,))
            active = self._execute(
                conn, "SELECT COUNT(*) FROM report_jobs WHERE tenant_id = ? AND status IN ('pending', 'running')", (job.tenant_id,)
            ).fetchone()[0]
            if max_active > 0 and active >= max_active:
                return False
            self._execute(
                conn,
                "INSERT INTO report_jobs(job_id, tenant_id, status, created_at, data) VALUES (?, ?, 'pending', ?, ?)",
                (job.job_id, job.tenant_id, job.created_at, job.model_dump_json()),
            )
        return True

    @staticmethod
    def _job(row: Any) -> ReportJob:
        data = json.loads(row[0])
        data.update(status=row[1], started_at=row[2], completed_at=row[3], error=row[4], job_id=row[5], tenant_id=row[6])
        return ReportJob.model_validate(data)

    def get(self, job_id: str, tenant_id: str) -> ReportJob | None:
        with self._connection(tenant_id) as conn:
            row = self._execute(
                conn,
                "SELECT data, status, started_at, completed_at, error, job_id, tenant_id "
                "FROM report_jobs WHERE job_id = ? AND tenant_id = ?",
                (job_id, tenant_id),
            ).fetchone()
        return self._job(row) if row else None

    def claim_next(
        self, lease_seconds: int, max_attempts: int, *, job_id: str | None = None, tenant_id: str | None = None
    ) -> ReportClaim | None:
        # Global polling uses the dedicated maintenance identity on Postgres.
        # It reads routing columns only; workers load payloads through tenant RLS.
        if (job_id is None) != (tenant_id is None):
            raise ValueError("A targeted claim requires both job and tenant")
        with self._connection(tenant_id, write=True) as conn:
            now = self._clock(conn)
            scope = " AND job_id = ? AND tenant_id = ?" if job_id else ""
            args: tuple = (now,)
            if job_id:
                args += (job_id, tenant_id)
            # Bounded maintenance: retire at most 32 exhausted claims each tick.
            sql = (
                "SELECT job_id, tenant_id, attempts FROM report_jobs WHERE "
                "(status = 'pending' OR (status = 'running' AND lease_expires_at <= ?))" + scope + " ORDER BY created_at, job_id LIMIT 32"
            )
            if self.postgres:
                sql += " FOR UPDATE SKIP LOCKED"
            rows = self._execute(conn, sql, args).fetchall()
            for name, tenant, attempts in rows:
                if attempts >= max(1, max_attempts):
                    self._execute(
                        conn,
                        "UPDATE report_jobs SET status = 'failed', completed_at = ?, error = ?, "
                        "lease_token = NULL, lease_expires_at = NULL "
                        "WHERE job_id = ? AND tenant_id = ?",
                        (_now(), "Export attempt limit reached after worker lease expiry", name, tenant),
                    )
                    continue
                token = secrets.token_hex(16)
                self._execute(
                    conn,
                    "UPDATE report_jobs SET status = 'running', started_at = ?, attempts = attempts + 1, "
                    "lease_token = ?, lease_expires_at = ? WHERE job_id = ? AND tenant_id = ?",
                    (_now(), token, now + max(1, lease_seconds), name, tenant),
                )
                return ReportClaim(name, tenant, token)
        return None

    def renew(self, claim: ReportClaim, lease_seconds: int) -> bool:
        with self._connection(claim.tenant_id, write=True) as conn:
            now = self._clock(conn)
            count = self._execute(
                conn,
                "UPDATE report_jobs SET lease_expires_at = ? WHERE job_id = ? AND tenant_id = ? "
                "AND status = 'running' AND lease_token = ? AND lease_expires_at > ?",
                (now + max(1, lease_seconds), claim.job_id, claim.tenant_id, claim.token, now),
            ).rowcount
        return bool(count == 1)

    def finish(self, job: ReportJob, claim: ReportClaim) -> bool:
        if job.job_id != claim.job_id or job.tenant_id != claim.tenant_id:
            return False
        if job.status not in (JobStatus.DONE, JobStatus.FAILED):
            raise ValueError("Only a terminal report may finish a claim")
        with self._connection(claim.tenant_id, write=True) as conn:
            count = self._execute(
                conn,
                "UPDATE report_jobs SET data = ?, status = ?, completed_at = ?, error = ?, lease_token = NULL, lease_expires_at = NULL "
                "WHERE job_id = ? AND tenant_id = ? AND status = 'running' AND lease_token = ? AND lease_expires_at > ?",
                (job.model_dump_json(), job.status.value, _now(), job.error, claim.job_id, claim.tenant_id, claim.token, self._clock(conn)),
            ).rowcount
        return bool(count == 1)


class SQLiteReportJobStore(SQLReportJobStore):
    """SQLite transactions serialize claims across local processes; WAL readers remain concurrent."""

    def __init__(self, db_path: str) -> None:
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(db_path, timeout=15, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(REPORT_TABLE_SQL)
        for sql in REPORT_INDEX_SQL:
            self._conn.execute(sql)
        ensure_sqlite_schema_version(self._conn, "report_jobs")
        self._conn.commit()

    @contextmanager
    def _connection(self, tenant_id: str | None, *, write: bool = False) -> Iterator[Any]:
        with self._lock:
            try:
                if write:
                    self._conn.execute("BEGIN IMMEDIATE")
                yield self._conn
                self._conn.commit()
            except BaseException:
                self._conn.rollback()
                raise

    def close(self) -> None:
        with self._lock:
            self._conn.close()


class InMemoryReportJobStore(SQLiteReportJobStore):
    """Explicit ephemeral mode with the same claim semantics as durable stores."""

    def __init__(self) -> None:
        super().__init__(":memory:")


_store: ReportJobStore | None = None
_store_lock = threading.Lock()


def get_report_job_store() -> ReportJobStore:
    global _store
    if _store is None:
        with _store_lock:
            if _store is None:
                from agent_bom.api.durable_store import select_backend, sqlite_path

                backend = select_backend()
                if backend == "postgres":
                    from agent_bom.api.postgres_report_jobs import PostgresReportJobStore

                    _store = PostgresReportJobStore()
                elif backend == "memory":
                    _store = InMemoryReportJobStore()
                else:
                    _store = SQLiteReportJobStore(sqlite_path())
    return _store


def set_report_job_store(store: ReportJobStore) -> None:
    global _store
    _store = store


def reset_report_job_store() -> None:
    global _store
    with _store_lock:
        previous, _store = _store, None
        close = getattr(previous, "close", None)
        if callable(close):
            close()
