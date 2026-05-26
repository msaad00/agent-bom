"""Tenant-scoped evaluation run registry for headless control-plane clients."""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from dataclasses import asdict, dataclass, field
from typing import Any, Protocol

from agent_bom.api.storage_schema import ensure_sqlite_schema_version


@dataclass(frozen=True)
class EvaluationRunRecord:
    tenant_id: str
    evaluation_id: str
    created_at: str
    updated_at: str
    name: str | None = None
    status: str = "completed"
    dataset_id: str | None = None
    dataset_version_id: str | None = None
    trace_id: str | None = None
    model: str | None = None
    prompt_hash: str | None = None
    source: str = "api"
    scores: dict[str, float] = field(default_factory=dict)
    summary: dict[str, Any] = field(default_factory=dict)
    cases: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class EvaluationRunStore(Protocol):
    def put(self, record: EvaluationRunRecord) -> None: ...
    def get(self, tenant_id: str, evaluation_id: str) -> EvaluationRunRecord | None: ...
    def list(self, tenant_id: str, *, dataset_id: str | None = None, limit: int = 100, offset: int = 0) -> list[EvaluationRunRecord]: ...


class InMemoryEvaluationRunStore:
    def __init__(self) -> None:
        self._records: dict[tuple[str, str], EvaluationRunRecord] = {}
        self._lock = threading.Lock()

    def put(self, record: EvaluationRunRecord) -> None:
        with self._lock:
            self._records[(record.tenant_id, record.evaluation_id)] = record

    def get(self, tenant_id: str, evaluation_id: str) -> EvaluationRunRecord | None:
        with self._lock:
            return self._records.get((tenant_id, evaluation_id))

    def list(self, tenant_id: str, *, dataset_id: str | None = None, limit: int = 100, offset: int = 0) -> list[EvaluationRunRecord]:
        with self._lock:
            records = [
                record
                for record in self._records.values()
                if record.tenant_id == tenant_id and (dataset_id is None or record.dataset_id == dataset_id)
            ]
        ordered = sorted(records, key=lambda record: record.created_at, reverse=True)
        return ordered[offset : offset + limit]


class SQLiteEvaluationRunStore:
    def __init__(self, db_path: str = "agent_bom.db") -> None:
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
        ensure_sqlite_schema_version(self._conn, "evaluation_runs")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS evaluation_runs (
                tenant_id TEXT NOT NULL,
                evaluation_id TEXT NOT NULL,
                dataset_id TEXT,
                created_at TEXT NOT NULL,
                data TEXT NOT NULL,
                PRIMARY KEY (tenant_id, evaluation_id)
            )
            """
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_evaluation_runs_tenant_dataset_created "
            "ON evaluation_runs(tenant_id, dataset_id, created_at DESC)"
        )
        self._conn.commit()

    def put(self, record: EvaluationRunRecord) -> None:
        self._conn.execute(
            """
            INSERT OR REPLACE INTO evaluation_runs
                (tenant_id, evaluation_id, dataset_id, created_at, data)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                record.tenant_id,
                record.evaluation_id,
                record.dataset_id,
                record.created_at,
                json.dumps(record.to_dict(), sort_keys=True),
            ),
        )
        self._conn.commit()

    def get(self, tenant_id: str, evaluation_id: str) -> EvaluationRunRecord | None:
        row = self._conn.execute(
            "SELECT data FROM evaluation_runs WHERE tenant_id = ? AND evaluation_id = ?",
            (tenant_id, evaluation_id),
        ).fetchone()
        return _record_from_json(row[0]) if row else None

    def list(self, tenant_id: str, *, dataset_id: str | None = None, limit: int = 100, offset: int = 0) -> list[EvaluationRunRecord]:
        if dataset_id is None:
            rows = self._conn.execute(
                """
                SELECT data FROM evaluation_runs
                WHERE tenant_id = ?
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
                """,
                (tenant_id, limit, offset),
            ).fetchall()
        else:
            rows = self._conn.execute(
                """
                SELECT data FROM evaluation_runs
                WHERE tenant_id = ? AND dataset_id = ?
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
                """,
                (tenant_id, dataset_id, limit, offset),
            ).fetchall()
        return [_record_from_json(row[0]) for row in rows]


def _record_from_json(raw: str) -> EvaluationRunRecord:
    payload = json.loads(raw)
    scores = payload.get("scores")
    return EvaluationRunRecord(
        tenant_id=str(payload["tenant_id"]),
        evaluation_id=str(payload["evaluation_id"]),
        created_at=str(payload["created_at"]),
        updated_at=str(payload.get("updated_at") or payload["created_at"]),
        name=payload.get("name"),
        status=str(payload.get("status") or "completed"),
        dataset_id=payload.get("dataset_id"),
        dataset_version_id=payload.get("dataset_version_id"),
        trace_id=payload.get("trace_id"),
        model=payload.get("model"),
        prompt_hash=payload.get("prompt_hash"),
        source=str(payload.get("source") or "api"),
        scores={str(key): float(value) for key, value in scores.items()} if isinstance(scores, dict) else {},
        summary=payload.get("summary") if isinstance(payload.get("summary"), dict) else {},
        cases=payload.get("cases") if isinstance(payload.get("cases"), list) else [],
        metadata=payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {},
    )


_EVALUATION_RUN_STORE: EvaluationRunStore | None = None


def get_evaluation_run_store() -> EvaluationRunStore:
    global _EVALUATION_RUN_STORE
    if _EVALUATION_RUN_STORE is not None:
        return _EVALUATION_RUN_STORE
    if os.environ.get("AGENT_BOM_DB"):
        _EVALUATION_RUN_STORE = SQLiteEvaluationRunStore(os.environ["AGENT_BOM_DB"])
    else:
        _EVALUATION_RUN_STORE = InMemoryEvaluationRunStore()
    return _EVALUATION_RUN_STORE


def set_evaluation_run_store(store: EvaluationRunStore | None) -> None:
    global _EVALUATION_RUN_STORE
    _EVALUATION_RUN_STORE = store


def reset_evaluation_run_store() -> None:
    set_evaluation_run_store(None)
