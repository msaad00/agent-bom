"""Tenant-scoped runtime session and observation persistence."""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from collections import Counter
from dataclasses import asdict, dataclass, field
from typing import Any, Protocol

from agent_bom.api.storage_schema import ensure_sqlite_schema_version
from agent_bom.security import sanitize_sensitive_payload, sanitize_text

RAW_RUNTIME_FIELDS = {
    "args",
    "arguments",
    "input",
    "inputs",
    "output",
    "outputs",
    "prompt",
    "prompts",
    "raw",
    "raw_input",
    "raw_output",
    "raw_prompt",
    "request_body",
    "response_body",
    "tool_input",
    "tool_output",
    "tool_outputs",
}


@dataclass(frozen=True)
class RuntimeObservationRecord:
    tenant_id: str
    observation_id: str
    session_id: str
    observed_at: str
    source: str = "api"
    surface: str = "runtime"
    event_type: str = "runtime_event"
    severity: str = "unknown"
    verdict: str = "observed"
    tool_name: str = ""
    agent_name: str = ""
    trace_id: str = ""
    span_id: str = ""
    request_id: str = ""
    summary: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    redaction_status: str = "metadata_only"
    raw_payload_stored: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class RuntimeSessionRecord:
    tenant_id: str
    session_id: str
    first_seen: str
    last_seen: str
    source: str = "api"
    agent_name: str = ""
    trace_id: str = ""
    observation_count: int = 0
    event_types: dict[str, int] = field(default_factory=dict)
    verdicts: dict[str, int] = field(default_factory=dict)
    severities: dict[str, int] = field(default_factory=dict)
    tools: list[str] = field(default_factory=list)
    redaction_status: str = "metadata_only"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class RuntimeEventStore(Protocol):
    def put_observation(self, record: RuntimeObservationRecord) -> None: ...

    def list_sessions(self, tenant_id: str, *, limit: int = 100, offset: int = 0) -> list[RuntimeSessionRecord]: ...

    def get_session(self, tenant_id: str, session_id: str) -> RuntimeSessionRecord | None: ...

    def list_observations(
        self,
        tenant_id: str,
        *,
        session_id: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[RuntimeObservationRecord]: ...


def sanitize_runtime_metadata(value: object, *, max_items: int = 50) -> dict[str, Any]:
    """Return metadata safe for durable runtime observability storage.

    Raw prompt, argument, and tool-output fields are intentionally omitted.
    This preserves correlation and security verdicts without turning the
    observability store into a replay database.
    """
    if not isinstance(value, dict):
        return {}
    safe: dict[str, Any] = {}
    for raw_key, raw_value in list(value.items())[:max_items]:
        key = sanitize_text(raw_key, max_len=120)
        if not key or key.lower() in RAW_RUNTIME_FIELDS:
            continue
        safe[key] = sanitize_sensitive_payload(raw_value, key=key, max_str_len=500)
    return safe


def _merge_session(existing: RuntimeSessionRecord | None, observation: RuntimeObservationRecord) -> RuntimeSessionRecord:
    event_types = Counter(existing.event_types if existing else {})
    verdicts = Counter(existing.verdicts if existing else {})
    severities = Counter(existing.severities if existing else {})
    tools = set(existing.tools if existing else [])
    if observation.event_type:
        event_types[observation.event_type] += 1
    if observation.verdict:
        verdicts[observation.verdict] += 1
    if observation.severity:
        severities[observation.severity] += 1
    if observation.tool_name:
        tools.add(observation.tool_name)

    first_seen = min(existing.first_seen, observation.observed_at) if existing else observation.observed_at
    last_seen = max(existing.last_seen, observation.observed_at) if existing else observation.observed_at
    return RuntimeSessionRecord(
        tenant_id=observation.tenant_id,
        session_id=observation.session_id,
        first_seen=first_seen,
        last_seen=last_seen,
        source=existing.source if existing and existing.source else observation.source,
        agent_name=existing.agent_name if existing and existing.agent_name else observation.agent_name,
        trace_id=existing.trace_id if existing and existing.trace_id else observation.trace_id,
        observation_count=(existing.observation_count if existing else 0) + 1,
        event_types=dict(sorted(event_types.items())),
        verdicts=dict(sorted(verdicts.items())),
        severities=dict(sorted(severities.items())),
        tools=sorted(tools)[:100],
    )


class InMemoryRuntimeEventStore:
    def __init__(self) -> None:
        self._observations: dict[tuple[str, str], RuntimeObservationRecord] = {}
        self._sessions: dict[tuple[str, str], RuntimeSessionRecord] = {}
        self._lock = threading.Lock()

    def put_observation(self, record: RuntimeObservationRecord) -> None:
        key = (record.tenant_id, record.observation_id)
        session_key = (record.tenant_id, record.session_id)
        with self._lock:
            if key in self._observations:
                return
            self._observations[key] = record
            self._sessions[session_key] = _merge_session(self._sessions.get(session_key), record)

    def list_sessions(self, tenant_id: str, *, limit: int = 100, offset: int = 0) -> list[RuntimeSessionRecord]:
        with self._lock:
            rows = [row for (row_tenant, _), row in self._sessions.items() if row_tenant == tenant_id]
        return sorted(rows, key=lambda row: row.last_seen, reverse=True)[offset : offset + limit]

    def get_session(self, tenant_id: str, session_id: str) -> RuntimeSessionRecord | None:
        with self._lock:
            return self._sessions.get((tenant_id, session_id))

    def list_observations(
        self,
        tenant_id: str,
        *,
        session_id: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[RuntimeObservationRecord]:
        with self._lock:
            rows = [
                row
                for (row_tenant, _), row in self._observations.items()
                if row_tenant == tenant_id and (session_id is None or row.session_id == session_id)
            ]
        return sorted(rows, key=lambda row: row.observed_at, reverse=True)[offset : offset + limit]


class SQLiteRuntimeEventStore:
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
        ensure_sqlite_schema_version(self._conn, "runtime_events")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS runtime_observations (
                tenant_id TEXT NOT NULL,
                observation_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                data TEXT NOT NULL,
                PRIMARY KEY (tenant_id, observation_id)
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS runtime_sessions (
                tenant_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                data TEXT NOT NULL,
                PRIMARY KEY (tenant_id, session_id)
            )
            """
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_runtime_observations_tenant_session_time "
            "ON runtime_observations(tenant_id, session_id, observed_at DESC)"
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_runtime_sessions_tenant_last_seen ON runtime_sessions(tenant_id, last_seen DESC)"
        )
        self._conn.commit()

    def put_observation(self, record: RuntimeObservationRecord) -> None:
        existing = self._conn.execute(
            "SELECT 1 FROM runtime_observations WHERE tenant_id = ? AND observation_id = ?",
            (record.tenant_id, record.observation_id),
        ).fetchone()
        if existing:
            return
        session = _merge_session(self.get_session(record.tenant_id, record.session_id), record)
        self._conn.execute(
            """
            INSERT INTO runtime_observations
                (tenant_id, observation_id, session_id, observed_at, data)
            VALUES (?, ?, ?, ?, ?)
            """,
            (record.tenant_id, record.observation_id, record.session_id, record.observed_at, json.dumps(record.to_dict(), sort_keys=True)),
        )
        self._conn.execute(
            """
            INSERT OR REPLACE INTO runtime_sessions
                (tenant_id, session_id, last_seen, data)
            VALUES (?, ?, ?, ?)
            """,
            (session.tenant_id, session.session_id, session.last_seen, json.dumps(session.to_dict(), sort_keys=True)),
        )
        self._conn.commit()

    def list_sessions(self, tenant_id: str, *, limit: int = 100, offset: int = 0) -> list[RuntimeSessionRecord]:
        rows = self._conn.execute(
            """
            SELECT data FROM runtime_sessions
            WHERE tenant_id = ?
            ORDER BY last_seen DESC
            LIMIT ? OFFSET ?
            """,
            (tenant_id, limit, offset),
        ).fetchall()
        return [_session_from_json(row[0]) for row in rows]

    def get_session(self, tenant_id: str, session_id: str) -> RuntimeSessionRecord | None:
        row = self._conn.execute(
            "SELECT data FROM runtime_sessions WHERE tenant_id = ? AND session_id = ?",
            (tenant_id, session_id),
        ).fetchone()
        return _session_from_json(row[0]) if row else None

    def list_observations(
        self,
        tenant_id: str,
        *,
        session_id: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[RuntimeObservationRecord]:
        if session_id:
            rows = self._conn.execute(
                """
                SELECT data FROM runtime_observations
                WHERE tenant_id = ? AND session_id = ?
                ORDER BY observed_at DESC
                LIMIT ? OFFSET ?
                """,
                (tenant_id, session_id, limit, offset),
            ).fetchall()
        else:
            rows = self._conn.execute(
                """
                SELECT data FROM runtime_observations
                WHERE tenant_id = ?
                ORDER BY observed_at DESC
                LIMIT ? OFFSET ?
                """,
                (tenant_id, limit, offset),
            ).fetchall()
        return [_observation_from_json(row[0]) for row in rows]


def _observation_from_json(raw: str) -> RuntimeObservationRecord:
    payload = json.loads(raw)
    return RuntimeObservationRecord(
        tenant_id=str(payload["tenant_id"]),
        observation_id=str(payload["observation_id"]),
        session_id=str(payload["session_id"]),
        observed_at=str(payload["observed_at"]),
        source=str(payload.get("source") or "api"),
        surface=str(payload.get("surface") or "runtime"),
        event_type=str(payload.get("event_type") or "runtime_event"),
        severity=str(payload.get("severity") or "unknown"),
        verdict=str(payload.get("verdict") or "observed"),
        tool_name=str(payload.get("tool_name") or ""),
        agent_name=str(payload.get("agent_name") or ""),
        trace_id=str(payload.get("trace_id") or ""),
        span_id=str(payload.get("span_id") or ""),
        request_id=str(payload.get("request_id") or ""),
        summary=payload.get("summary") if isinstance(payload.get("summary"), dict) else {},
        metadata=payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {},
        redaction_status=str(payload.get("redaction_status") or "metadata_only"),
        raw_payload_stored=bool(payload.get("raw_payload_stored", False)),
    )


def _session_from_json(raw: str) -> RuntimeSessionRecord:
    payload = json.loads(raw)
    return RuntimeSessionRecord(
        tenant_id=str(payload["tenant_id"]),
        session_id=str(payload["session_id"]),
        first_seen=str(payload["first_seen"]),
        last_seen=str(payload["last_seen"]),
        source=str(payload.get("source") or "api"),
        agent_name=str(payload.get("agent_name") or ""),
        trace_id=str(payload.get("trace_id") or ""),
        observation_count=int(payload.get("observation_count") or 0),
        event_types={str(key): int(value) for key, value in (payload.get("event_types") or {}).items()},
        verdicts={str(key): int(value) for key, value in (payload.get("verdicts") or {}).items()},
        severities={str(key): int(value) for key, value in (payload.get("severities") or {}).items()},
        tools=[str(item) for item in payload.get("tools", []) if str(item)],
        redaction_status=str(payload.get("redaction_status") or "metadata_only"),
    )


_RUNTIME_EVENT_STORE: RuntimeEventStore | None = None


def get_runtime_event_store() -> RuntimeEventStore:
    global _RUNTIME_EVENT_STORE
    if _RUNTIME_EVENT_STORE is not None:
        return _RUNTIME_EVENT_STORE
    if os.environ.get("AGENT_BOM_DB"):
        _RUNTIME_EVENT_STORE = SQLiteRuntimeEventStore(os.environ["AGENT_BOM_DB"])
    else:
        _RUNTIME_EVENT_STORE = InMemoryRuntimeEventStore()
    return _RUNTIME_EVENT_STORE


def set_runtime_event_store(store: RuntimeEventStore | None) -> None:
    global _RUNTIME_EVENT_STORE
    _RUNTIME_EVENT_STORE = store


def reset_runtime_event_store() -> None:
    set_runtime_event_store(None)
