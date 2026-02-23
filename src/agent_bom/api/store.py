"""Job storage backends for the agent-bom API server.

Provides pluggable job persistence:
- ``InMemoryJobStore`` — default, no persistence across restarts
- ``SQLiteJobStore``  — persistent storage via stdlib sqlite3
"""

from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timezone
from typing import Protocol

from .server import JobStatus, ScanJob

_JOB_TTL_SECONDS = 3600  # 1 hour


class JobStore(Protocol):
    """Protocol for scan job persistence."""

    def put(self, job: ScanJob) -> None: ...
    def get(self, job_id: str) -> ScanJob | None: ...
    def delete(self, job_id: str) -> bool: ...
    def list_all(self) -> list[ScanJob]: ...
    def list_summary(self) -> list[dict]: ...
    def cleanup_expired(self, ttl_seconds: int = _JOB_TTL_SECONDS) -> int: ...


class InMemoryJobStore:
    """Dict-based in-memory store (original behavior)."""

    def __init__(self) -> None:
        self._jobs: dict[str, ScanJob] = {}

    def put(self, job: ScanJob) -> None:
        self._jobs[job.job_id] = job

    def get(self, job_id: str) -> ScanJob | None:
        return self._jobs.get(job_id)

    def delete(self, job_id: str) -> bool:
        if job_id in self._jobs:
            del self._jobs[job_id]
            return True
        return False

    def list_all(self) -> list[ScanJob]:
        return list(self._jobs.values())

    def list_summary(self) -> list[dict]:
        return [
            {
                "job_id": j.job_id,
                "status": j.status,
                "created_at": j.created_at,
                "completed_at": j.completed_at,
            }
            for j in self._jobs.values()
        ]

    def cleanup_expired(self, ttl_seconds: int = _JOB_TTL_SECONDS) -> int:
        now = datetime.now(timezone.utc)
        expired = [
            jid for jid, job in self._jobs.items()
            if job.status in (JobStatus.DONE, JobStatus.FAILED, JobStatus.CANCELLED)
            and job.completed_at
            and (now - datetime.fromisoformat(job.completed_at)).total_seconds() > ttl_seconds
        ]
        for jid in expired:
            del self._jobs[jid]
        return len(expired)


class SQLiteJobStore:
    """SQLite-backed persistent job store.

    Schema:
        jobs(job_id TEXT PK, status TEXT, created_at TEXT,
             completed_at TEXT, data TEXT)

    The ``data`` column stores the full ScanJob as JSON. Status and timestamps
    are duplicated as columns for efficient queries.
    """

    def __init__(self, db_path: str = "agent_bom_jobs.db") -> None:
        self._db_path = db_path
        self._local = threading.local()
        self._init_db()

    @property
    def _conn(self) -> sqlite3.Connection:
        """Thread-local connection."""
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self._db_path, check_same_thread=False)
            self._local.conn.execute("PRAGMA journal_mode=WAL")
        return self._local.conn

    def _init_db(self) -> None:
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS jobs (
                job_id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                completed_at TEXT,
                data TEXT NOT NULL
            )
        """)
        self._conn.commit()

    @staticmethod
    def _serialize(job: ScanJob) -> str:
        return job.model_dump_json()

    @staticmethod
    def _deserialize(data: str) -> ScanJob:
        return ScanJob.model_validate_json(data)

    def put(self, job: ScanJob) -> None:
        self._conn.execute(
            """INSERT OR REPLACE INTO jobs (job_id, status, created_at, completed_at, data)
               VALUES (?, ?, ?, ?, ?)""",
            (job.job_id, job.status.value, job.created_at, job.completed_at, self._serialize(job)),
        )
        self._conn.commit()

    def get(self, job_id: str) -> ScanJob | None:
        row = self._conn.execute(
            "SELECT data FROM jobs WHERE job_id = ?", (job_id,)
        ).fetchone()
        if row is None:
            return None
        return self._deserialize(row[0])

    def delete(self, job_id: str) -> bool:
        cursor = self._conn.execute("DELETE FROM jobs WHERE job_id = ?", (job_id,))
        self._conn.commit()
        return cursor.rowcount > 0

    def list_all(self) -> list[ScanJob]:
        rows = self._conn.execute("SELECT data FROM jobs ORDER BY created_at DESC").fetchall()
        return [self._deserialize(r[0]) for r in rows]

    def list_summary(self) -> list[dict]:
        rows = self._conn.execute(
            "SELECT job_id, status, created_at, completed_at FROM jobs ORDER BY created_at DESC"
        ).fetchall()
        return [
            {"job_id": r[0], "status": r[1], "created_at": r[2], "completed_at": r[3]}
            for r in rows
        ]

    def cleanup_expired(self, ttl_seconds: int = _JOB_TTL_SECONDS) -> int:
        now = datetime.now(timezone.utc).isoformat()
        cursor = self._conn.execute(
            """DELETE FROM jobs
               WHERE status IN ('done', 'failed', 'cancelled')
                 AND completed_at IS NOT NULL
                 AND julianday(?) - julianday(completed_at) > ?""",
            (now, ttl_seconds / 86400.0),
        )
        self._conn.commit()
        return cursor.rowcount
