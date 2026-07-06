"""Human-in-the-loop approval decisions for blocked runtime tool calls."""

from __future__ import annotations

import hashlib
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Protocol

from agent_bom.api.storage_schema import ensure_sqlite_schema_version


class HitlDecisionStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"


@dataclass
class HitlApprovalRecord:
    item_id: str
    tenant_id: str
    span_id: str
    session_id: str
    agent: str
    tool: str
    status: HitlDecisionStatus = HitlDecisionStatus.PENDING
    detail: str = ""
    linked_finding_ids: list[str] | None = None
    compliance_controls: list[str] | None = None
    decided_by: str = ""
    decided_at: str = ""
    note: str = ""
    created_at: str = ""

    def __post_init__(self) -> None:
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()
        if self.linked_finding_ids is None:
            self.linked_finding_ids = []
        if self.compliance_controls is None:
            self.compliance_controls = []

    def to_dict(self) -> dict[str, Any]:
        return {
            "item_id": self.item_id,
            "tenant_id": self.tenant_id,
            "span_id": self.span_id,
            "session_id": self.session_id,
            "agent": self.agent,
            "tool": self.tool,
            "status": self.status.value,
            "detail": self.detail,
            "linked_finding_ids": list(self.linked_finding_ids or []),
            "compliance_controls": list(self.compliance_controls or []),
            "decided_by": self.decided_by,
            "decided_at": self.decided_at,
            "note": self.note,
            "created_at": self.created_at,
        }


def hitl_item_id(*, tenant_id: str, span_id: str) -> str:
    digest = hashlib.sha256(f"{tenant_id}:{span_id}".encode()).hexdigest()[:16]
    return f"hitl-{digest}"


class HitlApprovalStore(Protocol):
    def upsert(self, record: HitlApprovalRecord) -> None: ...
    def get(self, item_id: str, *, tenant_id: str) -> HitlApprovalRecord | None: ...
    def list_for_tenant(self, tenant_id: str) -> list[HitlApprovalRecord]: ...


class InMemoryHitlApprovalStore:
    def __init__(self) -> None:
        self._store: dict[str, HitlApprovalRecord] = {}
        self._lock = threading.Lock()

    def upsert(self, record: HitlApprovalRecord) -> None:
        with self._lock:
            self._store[record.item_id] = record

    def get(self, item_id: str, *, tenant_id: str) -> HitlApprovalRecord | None:
        record = self._store.get(item_id)
        if record is None or record.tenant_id != tenant_id:
            return None
        return record

    def list_for_tenant(self, tenant_id: str) -> list[HitlApprovalRecord]:
        with self._lock:
            rows = [row for row in self._store.values() if row.tenant_id == tenant_id]
        return sorted(rows, key=lambda row: row.created_at, reverse=True)


class SQLiteHitlApprovalStore:
    def __init__(self, db_path: str) -> None:
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
        ensure_sqlite_schema_version(self._conn, "hitl_approvals")
        self._conn.execute(
            """CREATE TABLE IF NOT EXISTS hitl_approvals (
            item_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            span_id TEXT NOT NULL,
            session_id TEXT NOT NULL DEFAULT '',
            agent TEXT NOT NULL DEFAULT '',
            tool TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'pending',
            detail TEXT NOT NULL DEFAULT '',
            linked_finding_ids TEXT NOT NULL DEFAULT '[]',
            compliance_controls TEXT NOT NULL DEFAULT '[]',
            decided_by TEXT NOT NULL DEFAULT '',
            decided_at TEXT NOT NULL DEFAULT '',
            note TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        )"""
        )
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_hitl_tenant ON hitl_approvals(tenant_id)")
        self._conn.commit()

    def upsert(self, record: HitlApprovalRecord) -> None:
        import json

        self._conn.execute(
            """INSERT OR REPLACE INTO hitl_approvals (
                item_id, tenant_id, span_id, session_id, agent, tool, status, detail,
                linked_finding_ids, compliance_controls, decided_by, decided_at, note, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                record.item_id,
                record.tenant_id,
                record.span_id,
                record.session_id,
                record.agent,
                record.tool,
                record.status.value,
                record.detail,
                json.dumps(record.linked_finding_ids or []),
                json.dumps(record.compliance_controls or []),
                record.decided_by,
                record.decided_at,
                record.note,
                record.created_at,
            ),
        )
        self._conn.commit()

    def get(self, item_id: str, *, tenant_id: str) -> HitlApprovalRecord | None:
        import json

        row = self._conn.execute(
            "SELECT item_id, tenant_id, span_id, session_id, agent, tool, status, detail, "
            "linked_finding_ids, compliance_controls, decided_by, decided_at, note, created_at "
            "FROM hitl_approvals WHERE item_id = ? AND tenant_id = ?",
            (item_id, tenant_id),
        ).fetchone()
        if row is None:
            return None
        return HitlApprovalRecord(
            item_id=row[0],
            tenant_id=row[1],
            span_id=row[2],
            session_id=row[3],
            agent=row[4],
            tool=row[5],
            status=HitlDecisionStatus(row[6]),
            detail=row[7],
            linked_finding_ids=json.loads(row[8] or "[]"),
            compliance_controls=json.loads(row[9] or "[]"),
            decided_by=row[10],
            decided_at=row[11],
            note=row[12],
            created_at=row[13],
        )

    def list_for_tenant(self, tenant_id: str) -> list[HitlApprovalRecord]:
        import json

        rows = self._conn.execute(
            "SELECT item_id, tenant_id, span_id, session_id, agent, tool, status, detail, "
            "linked_finding_ids, compliance_controls, decided_by, decided_at, note, created_at "
            "FROM hitl_approvals WHERE tenant_id = ? ORDER BY created_at DESC",
            (tenant_id,),
        ).fetchall()
        return [
            HitlApprovalRecord(
                item_id=row[0],
                tenant_id=row[1],
                span_id=row[2],
                session_id=row[3],
                agent=row[4],
                tool=row[5],
                status=HitlDecisionStatus(row[6]),
                detail=row[7],
                linked_finding_ids=json.loads(row[8] or "[]"),
                compliance_controls=json.loads(row[9] or "[]"),
                decided_by=row[10],
                decided_at=row[11],
                note=row[12],
                created_at=row[13],
            )
            for row in rows
        ]


_hitl_store: HitlApprovalStore | None = None
_hitl_lock = threading.Lock()


def get_hitl_approval_store() -> HitlApprovalStore:
    global _hitl_store
    if _hitl_store is None:
        with _hitl_lock:
            if _hitl_store is None:
                import os

                db_path = os.environ.get("AGENT_BOM_DB", "").strip()
                if db_path:
                    _hitl_store = SQLiteHitlApprovalStore(db_path)
                else:
                    _hitl_store = InMemoryHitlApprovalStore()
    return _hitl_store


def set_hitl_approval_store(store: HitlApprovalStore | None) -> None:
    global _hitl_store
    with _hitl_lock:
        _hitl_store = store
