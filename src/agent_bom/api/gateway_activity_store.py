"""Typed, append-only gateway activity ledger with tenant-safe cursors.

This ledger is intentionally separate from the generic runtime session rollup:
gateway activity needs conflict-aware replay, a server-owned ordering ordinal,
and an explicit retention floor. Caller timestamps remain provenance only and
never determine cursor or pruning order.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import sqlite3
import threading
from collections import deque
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from agent_bom.api.storage_schema import ensure_sqlite_schema_version
from agent_bom.runtime.gateway_events import (
    GATEWAY_ALLOWED_EVENT_TYPES,
    GATEWAY_BLOCKED_EVENT_TYPES,
    GATEWAY_DATA_FILTER_EVENT_TYPES,
)
from agent_bom.storage.base import BackendKind, StorageSchema, TableSchema

GATEWAY_ACTIVITY_SCHEMA_VERSION = 1
GATEWAY_ACTIVITY_STORAGE_VERSION = 2
DEFAULT_MAX_EVENTS_PER_TENANT = 50_000
DEFAULT_MAX_TOMBSTONES_PER_TENANT = 100_000
MAX_ACTIVITY_PAGE_SIZE = 500
MAX_ACTIVITY_BATCH_SIZE = 500
MAX_EVENT_FUTURE_SKEW = timedelta(minutes=5)

_SQLITE_EVENTS_DDL = """
CREATE TABLE IF NOT EXISTS gateway_activity_events (
    tenant_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    ingest_ordinal INTEGER NOT NULL,
    event_timestamp TEXT NOT NULL,
    ingested_at TEXT NOT NULL,
    event_digest TEXT NOT NULL,
    data TEXT NOT NULL,
    PRIMARY KEY (tenant_id, event_id)
)
"""
_POSTGRES_EVENTS_DDL = """
CREATE TABLE IF NOT EXISTS gateway_activity_events (
    tenant_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    ingest_ordinal BIGINT NOT NULL,
    event_timestamp TIMESTAMPTZ NOT NULL,
    ingested_at TIMESTAMPTZ NOT NULL,
    event_digest TEXT NOT NULL,
    data TEXT NOT NULL,
    PRIMARY KEY (tenant_id, event_id)
)
"""
_SQLITE_SEQUENCES_DDL = """
CREATE TABLE IF NOT EXISTS gateway_activity_sequences (
    tenant_id TEXT PRIMARY KEY,
    next_ordinal INTEGER NOT NULL CHECK (next_ordinal >= 1)
)
"""
_POSTGRES_SEQUENCES_DDL = """
CREATE TABLE IF NOT EXISTS gateway_activity_sequences (
    tenant_id TEXT PRIMARY KEY,
    next_ordinal BIGINT NOT NULL CHECK (next_ordinal >= 1)
)
"""
_SQLITE_TOMBSTONES_DDL = """
CREATE TABLE IF NOT EXISTS gateway_activity_tombstones (
    tenant_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    event_digest TEXT NOT NULL,
    pruned_ordinal INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, event_id)
)
"""
_POSTGRES_TOMBSTONES_DDL = """
CREATE TABLE IF NOT EXISTS gateway_activity_tombstones (
    tenant_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    event_digest TEXT NOT NULL,
    pruned_ordinal BIGINT NOT NULL,
    PRIMARY KEY (tenant_id, event_id)
)
"""

GATEWAY_ACTIVITY_STORE_SCHEMA = StorageSchema(
    component="runtime_events",
    tables=(
        TableSchema(
            "gateway_activity_events",
            ("tenant_id", "event_id", "ingest_ordinal", "event_timestamp", "ingested_at", "event_digest", "data"),
            {BackendKind.SQLITE.value: _SQLITE_EVENTS_DDL, BackendKind.POSTGRES.value: _POSTGRES_EVENTS_DDL},
        ),
        TableSchema(
            "gateway_activity_sequences",
            ("tenant_id", "next_ordinal"),
            {BackendKind.SQLITE.value: _SQLITE_SEQUENCES_DDL, BackendKind.POSTGRES.value: _POSTGRES_SEQUENCES_DDL},
        ),
        TableSchema(
            "gateway_activity_tombstones",
            ("tenant_id", "event_id", "event_digest", "pruned_ordinal"),
            {BackendKind.SQLITE.value: _SQLITE_TOMBSTONES_DDL, BackendKind.POSTGRES.value: _POSTGRES_TOMBSTONES_DDL},
        ),
    ),
)


def ensure_sqlite_gateway_activity_schema(conn: sqlite3.Connection) -> None:
    """Create the complete gateway portion of ``runtime_events`` schema v2."""

    conn.execute(_SQLITE_EVENTS_DDL)
    conn.execute(_SQLITE_SEQUENCES_DDL)
    conn.execute(_SQLITE_TOMBSTONES_DDL)
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_gateway_activity_events_tenant_ordinal "
        "ON gateway_activity_events(tenant_id, ingest_ordinal)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_gateway_activity_tombstones_tenant_ordinal "
        "ON gateway_activity_tombstones(tenant_id, pruned_ordinal)"
    )
    # The readiness marker is deliberately last: v2 means every ledger table
    # and uniqueness guard above exists, regardless of which runtime store was
    # constructed first.
    ensure_sqlite_schema_version(conn, "runtime_events", version=GATEWAY_ACTIVITY_STORAGE_VERSION)

_EVENT_TYPES = GATEWAY_ALLOWED_EVENT_TYPES | GATEWAY_BLOCKED_EVENT_TYPES | GATEWAY_DATA_FILTER_EVENT_TYPES
_EXPECTED_DECISIONS = {
    "gateway.tool_call.allowed": "allow",
    "gateway.tool_call.blocked": "deny",
    "gateway.dlp.arguments_redacted": "allow",
    "gateway.dlp.result_redacted": "allow",
    "gateway.dlp.result_blocked": "deny",
    "gateway.visual.redacted": "allow",
}
_ALLOWED_EVENT_FIELDS = frozenset(
    {
        "schema_version",
        "event_id",
        "decision_id",
        "event_type",
        "event_timestamp",
        "tenant_id",
        "agent_id",
        "identity_id",
        "profile_id",
        "profile_revision",
        "blueprint_id",
        "blueprint_revision",
        "policy_ids",
        "upstream",
        "tool",
        "decision",
        "policy_source",
        "reason_code",
        "trace_id",
        "data_action",
        "policy_id",
        "evidence_id",
        "development_mode",
    }
)


class GatewayActivityConflictError(ValueError):
    """An event ID was replayed with different canonical metadata."""


class GatewayActivityCursorError(ValueError):
    """A cursor is malformed, foreign, unsupported, or ahead of the ledger."""


class GatewayActivityCursorExpiredError(GatewayActivityCursorError):
    """A cursor points below the retained tenant activity floor."""

    def __init__(self, retention_floor_ordinal: int) -> None:
        super().__init__("Gateway activity cursor is older than retained history")
        self.retention_floor_ordinal = retention_floor_ordinal


@dataclass(frozen=True)
class GatewayActivityRecord:
    tenant_id: str
    event_id: str
    decision_id: str
    event_type: str
    event_schema_version: str
    event_timestamp: str
    ingested_at: str
    source_id: str
    session_id: str
    agent_id: str
    upstream: str
    tool: str
    decision: str
    policy_source: str
    trace_id: str
    identity_id: str = ""
    profile_id: str = ""
    profile_revision: int = 0
    blueprint_id: str = ""
    blueprint_revision: int = 0
    policy_ids: tuple[str, ...] = ()
    reason_code: str = ""
    data_action: str = ""
    policy_id: str = ""
    evidence_id: str = ""
    development_mode: bool = False
    event_digest: str = ""
    ingest_ordinal: int = 0
    raw_payload_stored: bool = False
    record_schema_version: str = "gateway.activity.record.v1"

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["policy_ids"] = list(self.policy_ids)
        return payload

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), separators=(",", ":"), sort_keys=True)


@dataclass(frozen=True)
class GatewayActivityAppendResult:
    inserted_event_ids: tuple[str, ...] = ()
    duplicate_event_ids: tuple[str, ...] = ()

    @property
    def inserted_count(self) -> int:
        return len(self.inserted_event_ids)

    @property
    def duplicate_count(self) -> int:
        return len(self.duplicate_event_ids)


@dataclass(frozen=True)
class GatewayActivityPage:
    tenant_id: str
    events: list[dict[str, Any]]
    cursor: str | None
    next_cursor: str | None
    has_more: bool
    retention_floor_ordinal: int
    latest_ordinal: int
    max_events_per_tenant: int
    dedupe_window_events: int


def _required_text(value: object, field: str, *, max_len: int = 200) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"gateway activity {field} is required")
    normalized = value.strip()
    if len(normalized) > max_len:
        raise ValueError(f"gateway activity {field} exceeds {max_len} characters")
    return normalized


def _optional_text(value: object, field: str, *, max_len: int = 200) -> str:
    if value in (None, ""):
        return ""
    if not isinstance(value, str):
        raise ValueError(f"gateway activity {field} must be text")
    normalized = value.strip()
    if len(normalized) > max_len:
        raise ValueError(f"gateway activity {field} exceeds {max_len} characters")
    return normalized


def _revision(value: object, field: str) -> int:
    if value in (None, ""):
        return 0
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"gateway activity {field} must be a non-negative integer")
    return value


def _event_timestamp(value: object, *, received_at: datetime) -> str:
    raw = _required_text(value, "event_timestamp", max_len=80)
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("gateway activity event_timestamp is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("gateway activity event_timestamp must include a timezone")
    normalized_received_at = received_at.astimezone(timezone.utc)
    normalized = parsed.astimezone(timezone.utc)
    if normalized > normalized_received_at + MAX_EVENT_FUTURE_SKEW:
        raise ValueError("gateway activity event_timestamp is too far in the future")
    return normalized.isoformat()


def _policy_ids(value: object) -> tuple[str, ...]:
    if value in (None, ()):
        return ()
    if not isinstance(value, list | tuple) or len(value) > 200:
        raise ValueError("gateway activity policy_ids must contain at most 200 items")
    normalized: list[str] = []
    for item in value:
        policy_id = _required_text(item, "policy_ids item")
        if policy_id not in normalized:
            normalized.append(policy_id)
    return tuple(normalized)


def _development_mode(value: object) -> bool:
    if value is None:
        return False
    if not isinstance(value, bool):
        raise ValueError("gateway activity development_mode must be a boolean")
    return value


def _validate_store_config(max_events_per_tenant: int, max_tombstones_per_tenant: int) -> None:
    if isinstance(max_events_per_tenant, bool) or max_events_per_tenant < 1:
        raise ValueError("gateway activity max_events_per_tenant must be at least 1")
    if isinstance(max_tombstones_per_tenant, bool) or max_tombstones_per_tenant < 1:
        raise ValueError("gateway activity max_tombstones_per_tenant must be at least 1")


def _digest_payload(record: GatewayActivityRecord) -> str:
    payload = record.to_dict()
    payload.pop("event_digest", None)
    payload.pop("ingest_ordinal", None)
    payload.pop("ingested_at", None)
    encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def gateway_activity_record_from_event(
    event: dict[str, Any],
    *,
    tenant_id: str,
    source_id: str,
    session_id: str,
    received_at: datetime | None = None,
) -> GatewayActivityRecord:
    """Validate one exact typed event and bind it to server-owned context."""

    unexpected = sorted(set(event) - _ALLOWED_EVENT_FIELDS)
    if unexpected:
        raise ValueError(f"unexpected gateway activity field: {unexpected[0]}")
    if event.get("schema_version") != "gateway.runtime.event.v1":
        raise ValueError("gateway activity schema_version must be gateway.runtime.event.v1")
    event_id = _required_text(event.get("event_id"), "event_id")
    decision_id = _required_text(event.get("decision_id"), "decision_id")
    if decision_id != event_id:
        raise ValueError("gateway activity decision_id must equal event_id")
    event_type = _required_text(event.get("event_type"), "event_type", max_len=120)
    if event_type not in _EVENT_TYPES:
        raise ValueError("gateway activity event_type is not canonical")
    decision = _required_text(event.get("decision"), "decision", max_len=20)
    if decision != _EXPECTED_DECISIONS[event_type]:
        raise ValueError("gateway activity decision is inconsistent with event_type")
    now = received_at or datetime.now(timezone.utc)
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("gateway activity received_at must include a timezone")
    record = GatewayActivityRecord(
        tenant_id=_required_text(tenant_id, "tenant_id"),
        event_id=event_id,
        decision_id=decision_id,
        event_type=event_type,
        event_schema_version="gateway.runtime.event.v1",
        event_timestamp=_event_timestamp(event.get("event_timestamp"), received_at=now),
        ingested_at=now.astimezone(timezone.utc).isoformat(),
        source_id=_required_text(source_id, "source_id"),
        session_id=_required_text(session_id, "session_id"),
        agent_id=_required_text(event.get("agent_id"), "agent_id"),
        identity_id=_optional_text(event.get("identity_id"), "identity_id"),
        profile_id=_optional_text(event.get("profile_id"), "profile_id"),
        profile_revision=_revision(event.get("profile_revision"), "profile_revision"),
        blueprint_id=_optional_text(event.get("blueprint_id"), "blueprint_id"),
        blueprint_revision=_revision(event.get("blueprint_revision"), "blueprint_revision"),
        policy_ids=_policy_ids(event.get("policy_ids")),
        upstream=_required_text(event.get("upstream"), "upstream"),
        tool=_required_text(event.get("tool"), "tool"),
        decision=decision,
        policy_source=_required_text(event.get("policy_source"), "policy_source", max_len=120),
        reason_code=_optional_text(event.get("reason_code"), "reason_code"),
        trace_id=_required_text(event.get("trace_id"), "trace_id"),
        data_action=_optional_text(event.get("data_action"), "data_action", max_len=80),
        policy_id=_optional_text(event.get("policy_id"), "policy_id"),
        evidence_id=_optional_text(event.get("evidence_id"), "evidence_id"),
        development_mode=_development_mode(event.get("development_mode")),
    )
    return replace(record, event_digest=_digest_payload(record))


def _prepare_batch(records: list[GatewayActivityRecord]) -> tuple[str, list[GatewayActivityRecord]]:
    if not records:
        return "", []
    if len(records) > MAX_ACTIVITY_BATCH_SIZE:
        raise ValueError(f"gateway activity batch exceeds {MAX_ACTIVITY_BATCH_SIZE} events")
    tenants = {record.tenant_id for record in records}
    if len(tenants) != 1:
        raise ValueError("gateway activity batch must contain exactly one tenant")
    by_id: dict[str, GatewayActivityRecord] = {}
    for record in records:
        if record.event_digest != _digest_payload(record):
            raise ValueError(f"gateway activity event_digest is invalid: {record.event_id}")
        existing = by_id.get(record.event_id)
        if existing is not None and existing.event_digest != record.event_digest:
            raise GatewayActivityConflictError(f"gateway activity event_id conflict: {record.event_id}")
        by_id.setdefault(record.event_id, record)
    return next(iter(tenants)), list(by_id.values())


def _encode_cursor(tenant_id: str, ordinal: int) -> str:
    payload = json.dumps(
        {"ordinal": ordinal, "tenant_id": tenant_id, "v": GATEWAY_ACTIVITY_SCHEMA_VERSION},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")


def _decode_cursor(cursor: str, tenant_id: str) -> int:
    if not cursor or len(cursor) > 1000:
        raise GatewayActivityCursorError("Invalid gateway activity cursor")
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        payload = json.loads(base64.b64decode(padded, altchars=b"-_", validate=True))
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise GatewayActivityCursorError("Invalid gateway activity cursor") from exc
    if not isinstance(payload, dict) or payload.get("v") != GATEWAY_ACTIVITY_SCHEMA_VERSION:
        raise GatewayActivityCursorError("Invalid gateway activity cursor")
    if payload.get("tenant_id") != tenant_id:
        raise GatewayActivityCursorError("Invalid gateway activity cursor")
    ordinal = payload.get("ordinal")
    if isinstance(ordinal, bool) or not isinstance(ordinal, int) or ordinal < 0:
        raise GatewayActivityCursorError("Invalid gateway activity cursor")
    return ordinal


def _page(
    tenant_id: str,
    records: list[GatewayActivityRecord],
    *,
    cursor: str | None,
    limit: int,
    floor: int,
    latest: int,
    max_events: int,
    max_tombstones: int,
) -> GatewayActivityPage:
    bounded_limit = max(1, min(limit, MAX_ACTIVITY_PAGE_SIZE))
    has_more = len(records) > bounded_limit
    page_records = records[:bounded_limit]
    next_cursor: str | None = (
        _encode_cursor(tenant_id, page_records[-1].ingest_ordinal) if page_records else cursor
    )
    return GatewayActivityPage(
        tenant_id=tenant_id,
        events=[record.to_dict() for record in page_records],
        cursor=cursor,
        next_cursor=next_cursor,
        has_more=has_more,
        retention_floor_ordinal=floor,
        latest_ordinal=latest,
        max_events_per_tenant=max_events,
        dedupe_window_events=max_events + max_tombstones,
    )


class InMemoryGatewayActivityStore:
    def __init__(
        self,
        *,
        max_events_per_tenant: int = DEFAULT_MAX_EVENTS_PER_TENANT,
        max_tombstones_per_tenant: int = DEFAULT_MAX_TOMBSTONES_PER_TENANT,
    ) -> None:
        _validate_store_config(max_events_per_tenant, max_tombstones_per_tenant)
        self.max_events_per_tenant = max_events_per_tenant
        self.max_tombstones_per_tenant = max_tombstones_per_tenant
        self._events: dict[tuple[str, str], GatewayActivityRecord] = {}
        self._tombstones: dict[tuple[str, str], tuple[str, int]] = {}
        self._tombstone_order: dict[str, deque[tuple[int, str]]] = {}
        self._next_ordinal: dict[str, int] = {}
        self._lock = threading.Lock()

    def init_schema(self) -> None:
        """Satisfy the shared store contract; memory has no external schema."""

    @staticmethod
    def encode_cursor(tenant_id: str, ordinal: int) -> str:
        return _encode_cursor(tenant_id, ordinal)

    def append_batch(self, records: list[GatewayActivityRecord]) -> GatewayActivityAppendResult:
        tenant_id, prepared = _prepare_batch(records)
        if not prepared:
            return GatewayActivityAppendResult()
        with self._lock:
            duplicates: list[str] = []
            new_records: list[GatewayActivityRecord] = []
            for record in prepared:
                key = (tenant_id, record.event_id)
                existing = self._events.get(key)
                tombstone = self._tombstones.get(key)
                existing_digest = existing.event_digest if existing is not None else tombstone[0] if tombstone else None
                if existing_digest is not None:
                    if existing_digest != record.event_digest:
                        raise GatewayActivityConflictError(f"gateway activity event_id conflict: {record.event_id}")
                    duplicates.append(record.event_id)
                else:
                    new_records.append(record)
            next_ordinal = self._next_ordinal.get(tenant_id, 1)
            inserted: list[str] = []
            for record in new_records:
                stored = replace(record, ingest_ordinal=next_ordinal)
                self._events[(tenant_id, record.event_id)] = stored
                inserted.append(record.event_id)
                next_ordinal += 1
            self._next_ordinal[tenant_id] = next_ordinal
            tenant_events = sorted(
                (record for (row_tenant, _), record in self._events.items() if row_tenant == tenant_id),
                key=lambda record: record.ingest_ordinal,
            )
            if self.max_events_per_tenant > 0:
                for stale in tenant_events[: max(0, len(tenant_events) - self.max_events_per_tenant)]:
                    self._events.pop((tenant_id, stale.event_id), None)
                    self._tombstones[(tenant_id, stale.event_id)] = (stale.event_digest, stale.ingest_ordinal)
                    self._tombstone_order.setdefault(tenant_id, deque()).append((stale.ingest_ordinal, stale.event_id))
            tombstone_order = self._tombstone_order.setdefault(tenant_id, deque())
            while len(tombstone_order) > self.max_tombstones_per_tenant:
                ordinal, event_id = tombstone_order.popleft()
                current = self._tombstones.get((tenant_id, event_id))
                if current is not None and current[1] == ordinal:
                    self._tombstones.pop((tenant_id, event_id), None)
            return GatewayActivityAppendResult(tuple(inserted), tuple(duplicates))

    def list_activity(self, tenant_id: str, *, cursor: str | None = None, limit: int = 100) -> GatewayActivityPage:
        with self._lock:
            latest = self._next_ordinal.get(tenant_id, 1) - 1
            rows = sorted(
                (record for (row_tenant, _), record in self._events.items() if row_tenant == tenant_id),
                key=lambda record: record.ingest_ordinal,
            )
            floor = rows[0].ingest_ordinal if rows else latest + 1
            after = _decode_cursor(cursor, tenant_id) if cursor else floor - 1
            if after > latest:
                raise GatewayActivityCursorError("Invalid gateway activity cursor")
            if after < floor - 1:
                raise GatewayActivityCursorExpiredError(floor)
            selected = [record for record in rows if record.ingest_ordinal > after]
            return _page(
                tenant_id,
                selected[: max(1, min(limit, MAX_ACTIVITY_PAGE_SIZE)) + 1],
                cursor=cursor,
                limit=limit,
                floor=floor,
                latest=latest,
                max_events=self.max_events_per_tenant,
                max_tombstones=self.max_tombstones_per_tenant,
            )


class SQLiteGatewayActivityStore:
    def __init__(
        self,
        db_path: str,
        *,
        max_events_per_tenant: int = DEFAULT_MAX_EVENTS_PER_TENANT,
        max_tombstones_per_tenant: int = DEFAULT_MAX_TOMBSTONES_PER_TENANT,
    ) -> None:
        _validate_store_config(max_events_per_tenant, max_tombstones_per_tenant)
        self.db_path = str(Path(db_path))
        self.max_events_per_tenant = max_events_per_tenant
        self.max_tombstones_per_tenant = max_tombstones_per_tenant
        self._local = threading.local()
        self._init_schema()

    def init_schema(self) -> None:
        """Idempotently initialize the SQLite ledger schema."""

        self._init_schema()

    @property
    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self._local.conn.execute("PRAGMA journal_mode=WAL")
        return self._local.conn

    @staticmethod
    def encode_cursor(tenant_id: str, ordinal: int) -> str:
        return _encode_cursor(tenant_id, ordinal)

    def _init_schema(self) -> None:
        conn = self._conn
        ensure_sqlite_gateway_activity_schema(conn)
        conn.commit()

    def append_batch(self, records: list[GatewayActivityRecord]) -> GatewayActivityAppendResult:
        tenant_id, prepared = _prepare_batch(records)
        if not prepared:
            return GatewayActivityAppendResult()
        conn = self._conn
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "INSERT INTO gateway_activity_sequences(tenant_id, next_ordinal) VALUES (?, 1) "
                "ON CONFLICT(tenant_id) DO NOTHING",
                (tenant_id,),
            )
            event_ids = [record.event_id for record in prepared]
            placeholders = ",".join("?" for _ in event_ids)
            active = dict(
                conn.execute(
                    f"SELECT event_id, event_digest FROM gateway_activity_events "  # nosec B608
                    f"WHERE tenant_id = ? AND event_id IN ({placeholders})",
                    (tenant_id, *event_ids),
                ).fetchall()
            )
            tombstones = dict(
                conn.execute(
                    f"SELECT event_id, event_digest FROM gateway_activity_tombstones "  # nosec B608
                    f"WHERE tenant_id = ? AND event_id IN ({placeholders})",
                    (tenant_id, *event_ids),
                ).fetchall()
            )
            duplicates: list[str] = []
            new_records: list[GatewayActivityRecord] = []
            for record in prepared:
                digest = active.get(record.event_id) or tombstones.get(record.event_id)
                if digest is not None:
                    if digest != record.event_digest:
                        raise GatewayActivityConflictError(f"gateway activity event_id conflict: {record.event_id}")
                    duplicates.append(record.event_id)
                else:
                    new_records.append(record)
            next_ordinal = int(
                conn.execute(
                    "SELECT next_ordinal FROM gateway_activity_sequences WHERE tenant_id = ?",
                    (tenant_id,),
                ).fetchone()[0]
            )
            stored_records = [replace(record, ingest_ordinal=next_ordinal + index) for index, record in enumerate(new_records)]
            conn.executemany(
                """
                INSERT INTO gateway_activity_events
                    (tenant_id,event_id,ingest_ordinal,event_timestamp,ingested_at,event_digest,data)
                VALUES (?,?,?,?,?,?,?)
                """,
                [
                    (
                        record.tenant_id,
                        record.event_id,
                        record.ingest_ordinal,
                        record.event_timestamp,
                        record.ingested_at,
                        record.event_digest,
                        record.to_json(),
                    )
                    for record in stored_records
                ],
            )
            conn.execute(
                "UPDATE gateway_activity_sequences SET next_ordinal = ? WHERE tenant_id = ?",
                (next_ordinal + len(stored_records), tenant_id),
            )
            if self.max_events_per_tenant > 0:
                count = int(
                    conn.execute(
                        "SELECT COUNT(*) FROM gateway_activity_events WHERE tenant_id = ?",
                        (tenant_id,),
                    ).fetchone()[0]
                )
                excess = max(0, count - self.max_events_per_tenant)
                stale = conn.execute(
                    "SELECT event_id,event_digest,ingest_ordinal FROM gateway_activity_events "
                    "WHERE tenant_id = ? ORDER BY ingest_ordinal ASC LIMIT ?",
                    (tenant_id, excess),
                ).fetchall()
                if stale:
                    conn.executemany(
                        "INSERT INTO gateway_activity_tombstones(tenant_id,event_id,event_digest,pruned_ordinal) VALUES (?,?,?,?) "
                        "ON CONFLICT(tenant_id,event_id) DO UPDATE SET "
                        "event_digest=excluded.event_digest,pruned_ordinal=excluded.pruned_ordinal",
                        [(tenant_id, event_id, digest, ordinal) for event_id, digest, ordinal in stale],
                    )
                    conn.executemany(
                        "DELETE FROM gateway_activity_events WHERE tenant_id = ? AND event_id = ?",
                        [(tenant_id, event_id) for event_id, _digest, _ordinal in stale],
                    )
                    tombstone_count = int(
                        conn.execute(
                            "SELECT COUNT(*) FROM gateway_activity_tombstones WHERE tenant_id = ?",
                            (tenant_id,),
                        ).fetchone()[0]
                    )
                    tombstone_excess = max(0, tombstone_count - self.max_tombstones_per_tenant)
                    expired_ids = conn.execute(
                        "SELECT event_id FROM gateway_activity_tombstones "
                        "WHERE tenant_id = ? ORDER BY pruned_ordinal ASC LIMIT ?",
                        (tenant_id, tombstone_excess),
                    ).fetchall()
                    conn.executemany(
                        "DELETE FROM gateway_activity_tombstones WHERE tenant_id = ? AND event_id = ?",
                        [(tenant_id, event_id) for (event_id,) in expired_ids],
                    )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        return GatewayActivityAppendResult(
            tuple(record.event_id for record in stored_records),
            tuple(duplicates),
        )

    def list_activity(self, tenant_id: str, *, cursor: str | None = None, limit: int = 100) -> GatewayActivityPage:
        conn = self._conn
        bounded_limit = max(1, min(limit, MAX_ACTIVITY_PAGE_SIZE))
        requested_after = _decode_cursor(cursor, tenant_id) if cursor else None
        rows = conn.execute(
            """
            WITH bounds AS (
                SELECT
                    COALESCE((SELECT next_ordinal - 1 FROM gateway_activity_sequences WHERE tenant_id = ?), 0) AS latest,
                    COALESCE(
                        (SELECT MIN(ingest_ordinal) FROM gateway_activity_events WHERE tenant_id = ?),
                        (SELECT next_ordinal FROM gateway_activity_sequences WHERE tenant_id = ?),
                        1
                    ) AS floor
            ), page AS (
                SELECT data, ingest_ordinal
                FROM gateway_activity_events, bounds
                WHERE tenant_id = ?
                  AND ingest_ordinal > COALESCE(?, bounds.floor - 1)
                ORDER BY ingest_ordinal ASC
                LIMIT ?
            )
            SELECT bounds.latest, bounds.floor, page.data
            FROM bounds LEFT JOIN page ON 1 = 1
            ORDER BY page.ingest_ordinal ASC
            """,
            (tenant_id, tenant_id, tenant_id, tenant_id, requested_after, bounded_limit + 1),
        ).fetchall()
        latest = int(rows[0][0])
        floor = int(rows[0][1])
        after = requested_after if requested_after is not None else floor - 1
        if cursor:
            if after > latest:
                raise GatewayActivityCursorError("Invalid gateway activity cursor")
            if after < floor - 1:
                raise GatewayActivityCursorExpiredError(floor)
        records = [_record_from_json(row[2]) for row in rows if row[2] is not None]
        return _page(
            tenant_id,
            records,
            cursor=cursor,
            limit=bounded_limit,
            floor=floor,
            latest=latest,
            max_events=self.max_events_per_tenant,
            max_tombstones=self.max_tombstones_per_tenant,
        )

    def query_plan(self, tenant_id: str, *, after_ordinal: int, limit: int) -> str:
        rows = self._conn.execute(
            "EXPLAIN QUERY PLAN SELECT data FROM gateway_activity_events "
            "WHERE tenant_id = ? AND ingest_ordinal > ? ORDER BY ingest_ordinal ASC LIMIT ?",
            (tenant_id, after_ordinal, limit),
        ).fetchall()
        return " ".join(str(column) for row in rows for column in row)


def _record_from_json(raw: str) -> GatewayActivityRecord:
    payload = json.loads(raw)
    return GatewayActivityRecord(
        tenant_id=str(payload["tenant_id"]),
        event_id=str(payload["event_id"]),
        decision_id=str(payload["decision_id"]),
        event_type=str(payload["event_type"]),
        event_schema_version=str(payload["event_schema_version"]),
        event_timestamp=str(payload["event_timestamp"]),
        ingested_at=str(payload["ingested_at"]),
        source_id=str(payload["source_id"]),
        session_id=str(payload["session_id"]),
        agent_id=str(payload["agent_id"]),
        identity_id=str(payload.get("identity_id") or ""),
        profile_id=str(payload.get("profile_id") or ""),
        profile_revision=int(payload.get("profile_revision") or 0),
        blueprint_id=str(payload.get("blueprint_id") or ""),
        blueprint_revision=int(payload.get("blueprint_revision") or 0),
        policy_ids=tuple(str(value) for value in payload.get("policy_ids") or []),
        upstream=str(payload["upstream"]),
        tool=str(payload["tool"]),
        decision=str(payload["decision"]),
        policy_source=str(payload["policy_source"]),
        reason_code=str(payload.get("reason_code") or ""),
        trace_id=str(payload["trace_id"]),
        data_action=str(payload.get("data_action") or ""),
        policy_id=str(payload.get("policy_id") or ""),
        evidence_id=str(payload.get("evidence_id") or ""),
        development_mode=bool(payload.get("development_mode", False)),
        event_digest=str(payload["event_digest"]),
        ingest_ordinal=int(payload["ingest_ordinal"]),
        raw_payload_stored=False,
        record_schema_version=str(payload.get("record_schema_version") or "gateway.activity.record.v1"),
    )


__all__ = [
    "GatewayActivityAppendResult",
    "GatewayActivityConflictError",
    "GatewayActivityCursorError",
    "GatewayActivityCursorExpiredError",
    "GatewayActivityPage",
    "GatewayActivityRecord",
    "GATEWAY_ACTIVITY_STORE_SCHEMA",
    "DEFAULT_MAX_TOMBSTONES_PER_TENANT",
    "MAX_ACTIVITY_BATCH_SIZE",
    "InMemoryGatewayActivityStore",
    "SQLiteGatewayActivityStore",
    "gateway_activity_record_from_event",
    "ensure_sqlite_gateway_activity_schema",
]
