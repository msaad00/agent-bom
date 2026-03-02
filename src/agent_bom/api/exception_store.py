"""Exception / waiver management for vulnerability findings.

Allows security teams to grant temporary exceptions for specific CVEs,
packages, or servers — with approval workflows and automatic expiration.

Lifecycle:
    PENDING → APPROVED → ACTIVE → EXPIRED
    PENDING → REJECTED
    ACTIVE  → REVOKED
"""

from __future__ import annotations

import logging
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Protocol
from uuid import uuid4

logger = logging.getLogger(__name__)


class ExceptionStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    ACTIVE = "active"
    REJECTED = "rejected"
    EXPIRED = "expired"
    REVOKED = "revoked"


@dataclass
class VulnException:
    """A vulnerability exception / waiver."""

    exception_id: str = ""
    vuln_id: str = ""  # CVE ID or "*" for package-level
    package_name: str = ""  # Package name or "*" for CVE-level
    server_name: str = ""  # MCP server name or "*"
    reason: str = ""
    requested_by: str = ""
    approved_by: str = ""
    status: ExceptionStatus = ExceptionStatus.PENDING
    created_at: str = ""
    expires_at: str = ""  # ISO datetime
    approved_at: str = ""
    revoked_at: str = ""
    tenant_id: str = "default"

    def __post_init__(self) -> None:
        if not self.exception_id:
            self.exception_id = f"exc-{uuid4().hex[:12]}"
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()

    def is_expired(self) -> bool:
        if not self.expires_at:
            return False
        now = datetime.now(timezone.utc).isoformat()
        return now > self.expires_at

    def matches(self, vuln_id: str, package_name: str, server_name: str = "") -> bool:
        """Check if this exception covers a specific finding."""
        if self.status not in (ExceptionStatus.APPROVED, ExceptionStatus.ACTIVE):
            return False
        if self.is_expired():
            return False
        vuln_match = self.vuln_id == "*" or self.vuln_id == vuln_id
        pkg_match = self.package_name == "*" or self.package_name == package_name
        srv_match = self.server_name == "*" or self.server_name == server_name or not self.server_name
        return vuln_match and pkg_match and srv_match

    def to_dict(self) -> dict:
        return {
            "exception_id": self.exception_id,
            "vuln_id": self.vuln_id,
            "package_name": self.package_name,
            "server_name": self.server_name,
            "reason": self.reason,
            "requested_by": self.requested_by,
            "approved_by": self.approved_by,
            "status": self.status.value,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "approved_at": self.approved_at,
            "revoked_at": self.revoked_at,
            "tenant_id": self.tenant_id,
        }


class ExceptionStore(Protocol):
    def put(self, exc: VulnException) -> None: ...
    def get(self, exception_id: str) -> VulnException | None: ...
    def delete(self, exception_id: str) -> bool: ...
    def list_all(self, status: str | None = None, tenant_id: str = "default") -> list[VulnException]: ...
    def find_matching(self, vuln_id: str, package_name: str, server_name: str = "", tenant_id: str = "default") -> VulnException | None: ...


class InMemoryExceptionStore:
    def __init__(self) -> None:
        self._store: dict[str, VulnException] = {}
        self._lock = threading.Lock()

    def put(self, exc: VulnException) -> None:
        with self._lock:
            self._store[exc.exception_id] = exc

    def get(self, exception_id: str) -> VulnException | None:
        return self._store.get(exception_id)

    def delete(self, exception_id: str) -> bool:
        with self._lock:
            return self._store.pop(exception_id, None) is not None

    def list_all(self, status: str | None = None, tenant_id: str = "default") -> list[VulnException]:
        with self._lock:
            results = list(self._store.values())
        if status:
            results = [e for e in results if e.status.value == status]
        results = [e for e in results if e.tenant_id == tenant_id]
        return sorted(results, key=lambda e: e.created_at, reverse=True)

    def find_matching(self, vuln_id: str, package_name: str, server_name: str = "", tenant_id: str = "default") -> VulnException | None:
        with self._lock:
            for exc in self._store.values():
                if exc.tenant_id == tenant_id and exc.matches(vuln_id, package_name, server_name):
                    return exc
        return None


class SQLiteExceptionStore:
    def __init__(self, db_path: str = "agent_bom_jobs.db") -> None:
        self._db_path = db_path
        self._local = threading.local()
        self._init_db()

    @property
    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self._db_path, check_same_thread=False)
            self._local.conn.execute("PRAGMA journal_mode=WAL")
        return self._local.conn

    def _init_db(self) -> None:
        self._conn.execute("""CREATE TABLE IF NOT EXISTS exceptions (
            exception_id TEXT PRIMARY KEY,
            vuln_id TEXT NOT NULL,
            package_name TEXT NOT NULL,
            server_name TEXT NOT NULL DEFAULT '',
            reason TEXT NOT NULL DEFAULT '',
            requested_by TEXT NOT NULL DEFAULT '',
            approved_by TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL DEFAULT '',
            approved_at TEXT NOT NULL DEFAULT '',
            revoked_at TEXT NOT NULL DEFAULT '',
            tenant_id TEXT NOT NULL DEFAULT 'default'
        )""")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_exc_status ON exceptions(status)")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_exc_tenant ON exceptions(tenant_id)")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_exc_vuln ON exceptions(vuln_id)")
        self._conn.commit()

    def put(self, exc: VulnException) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO exceptions (exception_id, vuln_id, package_name, server_name, reason, "
            "requested_by, approved_by, status, created_at, expires_at, approved_at, revoked_at, tenant_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                exc.exception_id,
                exc.vuln_id,
                exc.package_name,
                exc.server_name,
                exc.reason,
                exc.requested_by,
                exc.approved_by,
                exc.status.value,
                exc.created_at,
                exc.expires_at,
                exc.approved_at,
                exc.revoked_at,
                exc.tenant_id,
            ),
        )
        self._conn.commit()

    def get(self, exception_id: str) -> VulnException | None:
        row = self._conn.execute(
            "SELECT exception_id, vuln_id, package_name, server_name, reason, requested_by, "
            "approved_by, status, created_at, expires_at, approved_at, revoked_at, tenant_id "
            "FROM exceptions WHERE exception_id = ?",
            (exception_id,),
        ).fetchone()
        if not row:
            return None
        return VulnException(
            exception_id=row[0],
            vuln_id=row[1],
            package_name=row[2],
            server_name=row[3],
            reason=row[4],
            requested_by=row[5],
            approved_by=row[6],
            status=ExceptionStatus(row[7]),
            created_at=row[8],
            expires_at=row[9],
            approved_at=row[10],
            revoked_at=row[11],
            tenant_id=row[12],
        )

    def delete(self, exception_id: str) -> bool:
        cursor = self._conn.execute("DELETE FROM exceptions WHERE exception_id = ?", (exception_id,))
        self._conn.commit()
        return cursor.rowcount > 0

    def list_all(self, status: str | None = None, tenant_id: str = "default") -> list[VulnException]:
        clauses = ["tenant_id = ?"]
        params: list = [tenant_id]
        if status:
            clauses.append("status = ?")
            params.append(status)
        where = " AND ".join(clauses)
        rows = self._conn.execute(
            f"SELECT exception_id, vuln_id, package_name, server_name, reason, requested_by, "  # nosec B608 — clauses are static strings, values are parameterized
            f"approved_by, status, created_at, expires_at, approved_at, revoked_at, tenant_id "
            f"FROM exceptions WHERE {where} ORDER BY created_at DESC",
            params,
        ).fetchall()
        return [
            VulnException(
                exception_id=r[0],
                vuln_id=r[1],
                package_name=r[2],
                server_name=r[3],
                reason=r[4],
                requested_by=r[5],
                approved_by=r[6],
                status=ExceptionStatus(r[7]),
                created_at=r[8],
                expires_at=r[9],
                approved_at=r[10],
                revoked_at=r[11],
                tenant_id=r[12],
            )
            for r in rows
        ]

    def find_matching(self, vuln_id: str, package_name: str, server_name: str = "", tenant_id: str = "default") -> VulnException | None:
        exceptions = self.list_all(status="active", tenant_id=tenant_id)
        exceptions += self.list_all(status="approved", tenant_id=tenant_id)
        for exc in exceptions:
            if exc.matches(vuln_id, package_name, server_name):
                return exc
        return None
