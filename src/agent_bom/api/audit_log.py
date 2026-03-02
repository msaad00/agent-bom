"""Immutable audit log for compliance and forensics.

Append-only log of all significant actions:
    - Scan executions
    - Policy evaluations
    - Fleet state changes
    - Exception grants/revocations
    - Alert dispatches

Each entry is HMAC-signed to detect tampering. The log supports both
in-memory (dev) and SQLite (production) backends.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import sqlite3
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Protocol
from uuid import uuid4

logger = logging.getLogger(__name__)

_HMAC_KEY = os.environ.get("AGENT_BOM_AUDIT_HMAC_KEY", "agent-bom-default-audit-key").encode()


@dataclass
class AuditEntry:
    """Single audit log entry."""

    entry_id: str = ""
    timestamp: str = ""
    action: str = ""  # scan, policy_eval, fleet_change, exception, alert, config
    actor: str = ""  # API key prefix, role, or "system"
    resource: str = ""  # e.g., "job/abc123", "fleet/agent-1", "exception/exc-1"
    details: dict = field(default_factory=dict)
    hmac_signature: str = ""

    def __post_init__(self) -> None:
        if not self.entry_id:
            self.entry_id = str(uuid4())
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    def compute_hmac(self) -> str:
        """Compute HMAC-SHA256 signature for tamper detection."""
        payload = f"{self.entry_id}|{self.timestamp}|{self.action}|{self.actor}|{self.resource}"
        return hmac.new(_HMAC_KEY, payload.encode(), hashlib.sha256).hexdigest()

    def sign(self) -> None:
        """Sign this entry."""
        self.hmac_signature = self.compute_hmac()

    def verify(self) -> bool:
        """Verify HMAC signature."""
        return hmac.compare_digest(self.hmac_signature, self.compute_hmac())

    def to_dict(self) -> dict:
        return {
            "entry_id": self.entry_id,
            "timestamp": self.timestamp,
            "action": self.action,
            "actor": self.actor,
            "resource": self.resource,
            "details": self.details,
            "hmac_signature": self.hmac_signature,
        }


class AuditLogStore(Protocol):
    """Protocol for audit log persistence."""

    def append(self, entry: AuditEntry) -> None: ...
    def list_entries(
        self,
        action: str | None = None,
        resource: str | None = None,
        since: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AuditEntry]: ...
    def count(self, action: str | None = None) -> int: ...
    def verify_integrity(self, limit: int = 1000) -> tuple[int, int]: ...


class InMemoryAuditLog:
    """In-memory audit log for development."""

    _MAX_ENTRIES = 50_000

    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []
        self._lock = threading.Lock()

    def append(self, entry: AuditEntry) -> None:
        entry.sign()
        with self._lock:
            self._entries.append(entry)
            if len(self._entries) > self._MAX_ENTRIES:
                self._entries = self._entries[self._MAX_ENTRIES // 2 :]

    def list_entries(
        self,
        action: str | None = None,
        resource: str | None = None,
        since: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AuditEntry]:
        with self._lock:
            filtered = self._entries
            if action:
                filtered = [e for e in filtered if e.action == action]
            if resource:
                filtered = [e for e in filtered if e.resource.startswith(resource)]
            if since:
                filtered = [e for e in filtered if e.timestamp >= since]
            # Most recent first
            filtered = list(reversed(filtered))
            return filtered[offset : offset + limit]

    def count(self, action: str | None = None) -> int:
        with self._lock:
            if action:
                return sum(1 for e in self._entries if e.action == action)
            return len(self._entries)

    def verify_integrity(self, limit: int = 1000) -> tuple[int, int]:
        """Verify HMAC signatures. Returns (verified_count, tampered_count)."""
        with self._lock:
            entries = self._entries[-limit:]
        verified = sum(1 for e in entries if e.verify())
        tampered = len(entries) - verified
        return verified, tampered


class SQLiteAuditLog:
    """SQLite-backed append-only audit log."""

    def __init__(self, db_path: str = "agent_bom_audit.db") -> None:
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
        self._conn.execute("""CREATE TABLE IF NOT EXISTS audit_log (
            entry_id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            action TEXT NOT NULL,
            actor TEXT NOT NULL DEFAULT '',
            resource TEXT NOT NULL DEFAULT '',
            details TEXT NOT NULL DEFAULT '{}',
            hmac_signature TEXT NOT NULL
        )""")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action)")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(timestamp)")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_resource ON audit_log(resource)")
        self._conn.commit()

    def append(self, entry: AuditEntry) -> None:
        entry.sign()
        self._conn.execute(
            "INSERT INTO audit_log (entry_id, timestamp, action, actor, resource, details, hmac_signature) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (entry.entry_id, entry.timestamp, entry.action, entry.actor, entry.resource, json.dumps(entry.details), entry.hmac_signature),
        )
        self._conn.commit()

    def list_entries(
        self,
        action: str | None = None,
        resource: str | None = None,
        since: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AuditEntry]:
        clauses = []
        params: list = []
        if action:
            clauses.append("action = ?")
            params.append(action)
        if resource:
            clauses.append("resource LIKE ?")
            params.append(f"{resource}%")
        if since:
            clauses.append("timestamp >= ?")
            params.append(since)

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""  # nosec B608 — clauses are static strings, values are parameterized
        sql = f"SELECT entry_id, timestamp, action, actor, resource, details, hmac_signature FROM audit_log {where} ORDER BY timestamp DESC LIMIT ? OFFSET ?"  # nosec B608
        params.extend([limit, offset])

        rows = self._conn.execute(sql, params).fetchall()
        return [
            AuditEntry(
                entry_id=r[0],
                timestamp=r[1],
                action=r[2],
                actor=r[3],
                resource=r[4],
                details=json.loads(r[5]),
                hmac_signature=r[6],
            )
            for r in rows
        ]

    def count(self, action: str | None = None) -> int:
        if action:
            row = self._conn.execute("SELECT COUNT(*) FROM audit_log WHERE action = ?", (action,)).fetchone()
        else:
            row = self._conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()
        return row[0] if row else 0

    def verify_integrity(self, limit: int = 1000) -> tuple[int, int]:
        entries = self.list_entries(limit=limit)
        verified = sum(1 for e in entries if e.verify())
        tampered = len(entries) - verified
        return verified, tampered


# ── Module-level singleton ──

_audit_log: AuditLogStore | None = None
_audit_lock = threading.Lock()


def get_audit_log() -> AuditLogStore:
    global _audit_log
    if _audit_log is None:
        with _audit_lock:
            if _audit_log is None:
                db = os.environ.get("AGENT_BOM_AUDIT_DB")
                if db:
                    _audit_log = SQLiteAuditLog(db)
                else:
                    _audit_log = InMemoryAuditLog()
    return _audit_log


def set_audit_log(store: AuditLogStore) -> None:
    global _audit_log
    with _audit_lock:
        _audit_log = store


def log_action(action: str, actor: str = "system", resource: str = "", **details: object) -> None:
    """Convenience: append an audit entry."""
    entry = AuditEntry(action=action, actor=actor, resource=resource, details=dict(details))
    get_audit_log().append(entry)
