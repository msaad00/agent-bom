"""Tenant-scoped external issue mapping store."""

from __future__ import annotations

import sqlite3
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol

from agent_bom.api.storage_schema import ensure_sqlite_schema_version


def _utcnow() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass
class IssueMapping:
    mapping_id: str
    tenant_id: str
    target_kind: str
    target_id: str
    provider: str
    external_id: str
    external_url: str
    status: str
    created_at: str
    updated_at: str

    def to_dict(self) -> dict[str, str]:
        return {
            "id": self.mapping_id,
            "tenant_id": self.tenant_id,
            "target_kind": self.target_kind,
            "target_id": self.target_id,
            "provider": self.provider,
            "external_id": self.external_id,
            "external_url": self.external_url,
            "status": self.status,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


class IssueMappingStore(Protocol):
    def get(self, mapping_id: str, *, tenant_id: str) -> IssueMapping | None: ...

    def find(self, *, tenant_id: str, target_kind: str, target_id: str, provider: str) -> IssueMapping | None: ...

    def put(
        self,
        *,
        tenant_id: str,
        target_kind: str,
        target_id: str,
        provider: str,
        external_id: str,
        external_url: str,
        status: str = "open",
    ) -> IssueMapping: ...

    def update_status(self, mapping_id: str, *, tenant_id: str, status: str) -> IssueMapping | None: ...


class InMemoryIssueMappingStore:
    def __init__(self) -> None:
        self._records: dict[str, IssueMapping] = {}
        self._lock = threading.Lock()

    def get(self, mapping_id: str, *, tenant_id: str) -> IssueMapping | None:
        with self._lock:
            record = self._records.get(mapping_id)
            return record if record and record.tenant_id == tenant_id else None

    def find(self, *, tenant_id: str, target_kind: str, target_id: str, provider: str) -> IssueMapping | None:
        with self._lock:
            for record in self._records.values():
                if (
                    record.tenant_id == tenant_id
                    and record.target_kind == target_kind
                    and record.target_id == target_id
                    and record.provider == provider
                ):
                    return record
        return None

    def put(
        self,
        *,
        tenant_id: str,
        target_kind: str,
        target_id: str,
        provider: str,
        external_id: str,
        external_url: str,
        status: str = "open",
    ) -> IssueMapping:
        now = _utcnow()
        with self._lock:
            existing = next(
                (
                    record
                    for record in self._records.values()
                    if record.tenant_id == tenant_id
                    and record.target_kind == target_kind
                    and record.target_id == target_id
                    and record.provider == provider
                ),
                None,
            )
            if existing:
                existing.external_id = external_id
                existing.external_url = external_url
                existing.status = status
                existing.updated_at = now
                return existing
            record = IssueMapping(
                mapping_id=f"issue-map-{uuid.uuid4().hex}",
                tenant_id=tenant_id,
                target_kind=target_kind,
                target_id=target_id,
                provider=provider,
                external_id=external_id,
                external_url=external_url,
                status=status,
                created_at=now,
                updated_at=now,
            )
            self._records[record.mapping_id] = record
            return record

    def update_status(self, mapping_id: str, *, tenant_id: str, status: str) -> IssueMapping | None:
        with self._lock:
            record = self._records.get(mapping_id)
            if not record or record.tenant_id != tenant_id:
                return None
            record.status = status
            record.updated_at = _utcnow()
            return record


class SQLiteIssueMappingStore:
    def __init__(self, db_path: str = "agent_bom_jobs.db") -> None:
        self._db_path = db_path
        self._local = threading.local()
        self._init_db()

    @property
    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self._db_path, check_same_thread=False)
            self._local.conn.execute("PRAGMA journal_mode=WAL")
        conn: sqlite3.Connection = self._local.conn
        return conn

    def _init_db(self) -> None:
        ensure_sqlite_schema_version(self._conn, "issue_mappings")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS issue_mappings (
                mapping_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                target_kind TEXT NOT NULL,
                target_id TEXT NOT NULL,
                provider TEXT NOT NULL,
                external_id TEXT NOT NULL,
                external_url TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(tenant_id, target_kind, target_id, provider)
            )
            """
        )
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_issue_mappings_tenant ON issue_mappings(tenant_id)")
        self._conn.commit()

    def _row_to_mapping(self, row: sqlite3.Row | tuple | None) -> IssueMapping | None:
        if not row:
            return None
        return IssueMapping(*row)

    def get(self, mapping_id: str, *, tenant_id: str) -> IssueMapping | None:
        row = self._conn.execute(
            """SELECT mapping_id, tenant_id, target_kind, target_id, provider,
                      external_id, external_url, status, created_at, updated_at
               FROM issue_mappings WHERE mapping_id = ? AND tenant_id = ?""",
            (mapping_id, tenant_id),
        ).fetchone()
        return self._row_to_mapping(row)

    def find(self, *, tenant_id: str, target_kind: str, target_id: str, provider: str) -> IssueMapping | None:
        row = self._conn.execute(
            """SELECT mapping_id, tenant_id, target_kind, target_id, provider,
                      external_id, external_url, status, created_at, updated_at
               FROM issue_mappings
               WHERE tenant_id = ? AND target_kind = ? AND target_id = ? AND provider = ?""",
            (tenant_id, target_kind, target_id, provider),
        ).fetchone()
        return self._row_to_mapping(row)

    def put(
        self,
        *,
        tenant_id: str,
        target_kind: str,
        target_id: str,
        provider: str,
        external_id: str,
        external_url: str,
        status: str = "open",
    ) -> IssueMapping:
        now = _utcnow()
        existing = self.find(tenant_id=tenant_id, target_kind=target_kind, target_id=target_id, provider=provider)
        mapping_id = existing.mapping_id if existing else f"issue-map-{uuid.uuid4().hex}"
        created_at = existing.created_at if existing else now
        self._conn.execute(
            """INSERT INTO issue_mappings
               (mapping_id, tenant_id, target_kind, target_id, provider,
                external_id, external_url, status, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(tenant_id, target_kind, target_id, provider)
               DO UPDATE SET external_id = excluded.external_id,
                             external_url = excluded.external_url,
                             status = excluded.status,
                             updated_at = excluded.updated_at""",
            (mapping_id, tenant_id, target_kind, target_id, provider, external_id, external_url, status, created_at, now),
        )
        self._conn.commit()
        record = self.find(tenant_id=tenant_id, target_kind=target_kind, target_id=target_id, provider=provider)
        assert record is not None
        return record

    def update_status(self, mapping_id: str, *, tenant_id: str, status: str) -> IssueMapping | None:
        now = _utcnow()
        self._conn.execute(
            "UPDATE issue_mappings SET status = ?, updated_at = ? WHERE mapping_id = ? AND tenant_id = ?",
            (status, now, mapping_id, tenant_id),
        )
        self._conn.commit()
        return self.get(mapping_id, tenant_id=tenant_id)
