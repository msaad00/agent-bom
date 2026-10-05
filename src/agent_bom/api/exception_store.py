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
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Protocol
from uuid import uuid4

from agent_bom.api.storage_schema import ensure_sqlite_schema_version
from agent_bom.api.suppression_approval import suppression_active
from agent_bom.core.tenancy import require_explicit_tenant_id
from agent_bom.core.timestamps import parse_identity_timestamp

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
    approval_version: int = 0

    def __post_init__(self) -> None:
        if not self.exception_id:
            self.exception_id = f"exc-{uuid4().hex[:12]}"
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()

    def is_expired(self) -> bool:
        expiry = parse_identity_timestamp(self.expires_at, require_timezone=True)
        return expiry is None or expiry <= datetime.now(timezone.utc)

    def matches(self, vuln_id: str, package_name: str, server_name: str = "") -> bool:
        """Only explicitly approved, bounded exceptions affect a finding."""
        return (
            suppression_active(self)
            and self.vuln_id == vuln_id
            and self.package_name == package_name
            and (self.server_name in {"", "*", server_name})
        )

    def to_dict(self) -> dict[str, Any]:
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
            "approval_version": self.approval_version,
        }


class ExceptionStore(Protocol):
    def put(self, exc: VulnException, *, tenant_id: str) -> None: ...
    def get(self, exception_id: str, *, tenant_id: str) -> VulnException | None: ...
    def delete(self, exception_id: str, *, tenant_id: str) -> bool: ...
    def list_all(self, status: str | None = None, *, tenant_id: str) -> list[VulnException]: ...
    def find_matching(self, vuln_id: str, package_name: str, server_name: str = "", *, tenant_id: str) -> VulnException | None: ...


def exception_write_tenant(exc: VulnException, tenant_id: str) -> str:
    """An exception record cannot choose a different tenant than its caller."""
    tenant = require_explicit_tenant_id(tenant_id)
    if exc.tenant_id != tenant:
        raise ValueError("Exception tenant does not match the authorized tenant")
    return tenant


def exception_record_for_tenant(exc: VulnException, tenant_id: str) -> VulnException:
    """Reject serialized exception data whose tenant disagrees with its row."""
    tenant = require_explicit_tenant_id(tenant_id)
    if exc.tenant_id != tenant:
        raise ValueError("Stored exception tenant does not match its row tenant")
    return exc


class InMemoryExceptionStore:
    def __init__(self) -> None:
        self._store: dict[str, VulnException] = {}
        self._lock = threading.Lock()

    def put(self, exc: VulnException, *, tenant_id: str) -> None:
        tenant = exception_write_tenant(exc, tenant_id)
        with self._lock:
            existing = self._store.get(exc.exception_id)
            if existing is not None and existing.tenant_id != tenant:
                raise ValueError("Exception identity belongs to a different tenant")
            self._store[exc.exception_id] = replace(exc)

    def get(self, exception_id: str, *, tenant_id: str) -> VulnException | None:
        tenant = require_explicit_tenant_id(tenant_id)
        with self._lock:
            exc = self._store.get(exception_id)
            if exc is None or exc.tenant_id != tenant:
                return None
            return replace(exc)

    def delete(self, exception_id: str, *, tenant_id: str) -> bool:
        tenant = require_explicit_tenant_id(tenant_id)
        with self._lock:
            exc = self._store.get(exception_id)
            if exc is None or exc.tenant_id != tenant:
                return False
            self._store.pop(exception_id, None)
            return True

    def list_all(self, status: str | None = None, *, tenant_id: str) -> list[VulnException]:
        tenant = require_explicit_tenant_id(tenant_id)
        with self._lock:
            results = [replace(exc) for exc in self._store.values() if exc.tenant_id == tenant]
        if status:
            results = [e for e in results if e.status.value == status]
        return sorted(results, key=lambda e: e.created_at, reverse=True)

    def find_matching(self, vuln_id: str, package_name: str, server_name: str = "", *, tenant_id: str) -> VulnException | None:
        tenant = require_explicit_tenant_id(tenant_id)
        with self._lock:
            for exc in self._store.values():
                if exc.tenant_id == tenant and exc.matches(vuln_id, package_name, server_name):
                    return replace(exc)
        return None


class SQLiteExceptionStore:
    def __init__(self, db_path: str = "agent_bom_jobs.db") -> None:
        self._db_path = db_path
        self._local = threading.local()
        self._init_db()

    @property
    def _conn(self) -> sqlite3.Connection:
        conn: sqlite3.Connection | None = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self._db_path, check_same_thread=False)
            conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn = conn
        return conn

    def _init_db(self) -> None:
        ensure_sqlite_schema_version(self._conn, "exceptions", version=2)
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
        if "approval_version" not in {row[1] for row in self._conn.execute("PRAGMA table_info(exceptions)")}:
            self._conn.execute("ALTER TABLE exceptions ADD COLUMN approval_version INTEGER NOT NULL DEFAULT 0")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_exc_status ON exceptions(status)")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_exc_tenant ON exceptions(tenant_id)")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_exc_vuln ON exceptions(vuln_id)")
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_exc_tenant_status_match ON exceptions(tenant_id, status, vuln_id, package_name, server_name)"
        )
        self._conn.commit()

    def put(self, exc: VulnException, *, tenant_id: str) -> None:
        tenant = exception_write_tenant(exc, tenant_id)
        cursor = self._conn.execute(
            "INSERT INTO exceptions (exception_id, vuln_id, package_name, server_name, reason, "
            "requested_by, approved_by, status, created_at, expires_at, approved_at, revoked_at, tenant_id, approval_version) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT (exception_id) DO UPDATE SET vuln_id=excluded.vuln_id, package_name=excluded.package_name, "
            "server_name=excluded.server_name, reason=excluded.reason, requested_by=excluded.requested_by, "
            "approved_by=excluded.approved_by, status=excluded.status, created_at=excluded.created_at, "
            "expires_at=excluded.expires_at, approved_at=excluded.approved_at, revoked_at=excluded.revoked_at, "
            "approval_version=excluded.approval_version "
            "WHERE exceptions.tenant_id=excluded.tenant_id",
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
                tenant,
                exc.approval_version,
            ),
        )
        self._conn.commit()
        if cursor.rowcount == 0:
            raise ValueError("Exception identity belongs to a different tenant")

    def get(self, exception_id: str, *, tenant_id: str) -> VulnException | None:
        tenant = require_explicit_tenant_id(tenant_id)
        row = self._conn.execute(
            "SELECT exception_id, vuln_id, package_name, server_name, reason, requested_by, "
            "approved_by, status, created_at, expires_at, approved_at, revoked_at, tenant_id, approval_version "
            "FROM exceptions WHERE exception_id = ? AND tenant_id = ?",
            (exception_id, tenant),
        ).fetchone()
        if not row:
            return None
        return exception_record_for_tenant(
            VulnException(
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
                approval_version=row[13],
            ),
            tenant,
        )

    def delete(self, exception_id: str, *, tenant_id: str) -> bool:
        tenant = require_explicit_tenant_id(tenant_id)
        cursor = self._conn.execute(
            "DELETE FROM exceptions WHERE exception_id = ? AND tenant_id = ?",
            (exception_id, tenant),
        )
        self._conn.commit()
        return cursor.rowcount > 0

    def list_all(self, status: str | None = None, *, tenant_id: str) -> list[VulnException]:
        tenant = require_explicit_tenant_id(tenant_id)
        clauses: list[str] = ["tenant_id = ?"]
        params: list[Any] = [tenant]
        if status:
            clauses.append("status = ?")
            params.append(status)
        where = " AND ".join(clauses)
        rows = self._conn.execute(
            f"SELECT exception_id, vuln_id, package_name, server_name, reason, requested_by, "  # nosec B608 — clauses are static strings, values are parameterized
            f"approved_by, status, created_at, expires_at, approved_at, revoked_at, tenant_id, approval_version "
            f"FROM exceptions WHERE {where} ORDER BY created_at DESC",
            params,
        ).fetchall()
        return [
            exception_record_for_tenant(
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
                    approval_version=r[13],
                ),
                tenant,
            )
            for r in rows
        ]

    def find_matching(self, vuln_id: str, package_name: str, server_name: str = "", *, tenant_id: str) -> VulnException | None:
        tenant = require_explicit_tenant_id(tenant_id)
        exceptions = self.list_all(status="active", tenant_id=tenant)
        exceptions += self.list_all(status="approved", tenant_id=tenant)
        for exc in exceptions:
            if exc.matches(vuln_id, package_name, server_name):
                return exc
        return None
