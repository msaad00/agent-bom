"""Tier-B (replay-only) capture store for the MCP proxy audit relay.

Issue #2261 — two-bucket evidence redaction.

When the operator launches the proxy with ``--capture-replay``, tier-B
fields (raw prompts, tool inputs / outputs, full URLs, command args,
response bodies, workspace content) flow into this store instead of being
discarded.  Every row carries a ``not_after`` TTL — defaulting to 7 days,
configurable via ``AGENT_BOM_REPLAY_TTL_DAYS`` — and the lifecycle hook in
``api/server.py`` purges expired rows on a recurring tick.

Three backends mirror the ``compliance_hub_store`` pattern so the same
selection logic applies:

* :class:`InMemoryProxyReplayStore` — process-local, tests + single-node.
* :class:`SQLiteProxyReplayStore` — single-node persistence.
* :class:`PostgresProxyReplayStore` — multi-replica deployments.

Without ``--capture-replay`` the store stays empty: the proxy never calls
``add()``, and tier-B data is dropped at the redaction layer in
:func:`agent_bom.proxy_audit.write_audit_record`.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any, Protocol

from agent_bom.evidence import replay_not_after, replay_ttl_days


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


class ProxyReplayStore(Protocol):
    """Append-mostly tier-B store with TTL-driven cleanup."""

    def add(
        self,
        tenant_id: str,
        record: dict[str, Any],
        *,
        not_after: datetime | None = None,
    ) -> str: ...

    def list(self, tenant_id: str, *, limit: int = 100) -> list[dict[str, Any]]: ...

    def cleanup_expired(self, *, now: datetime | None = None) -> int: ...

    def count(self, tenant_id: str | None = None) -> int: ...


# ─── In-memory backend ──────────────────────────────────────────────────────


class InMemoryProxyReplayStore:
    """Process-local replay store. Tests + single-process proxy demos."""

    def __init__(self) -> None:
        self._rows: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def add(
        self,
        tenant_id: str,
        record: dict[str, Any],
        *,
        not_after: datetime | None = None,
    ) -> str:
        from uuid import uuid4

        not_after = not_after or replay_not_after()
        row_id = str(uuid4())
        with self._lock:
            self._rows.append(
                {
                    "row_id": row_id,
                    "tenant_id": str(tenant_id or "default"),
                    "captured_at": _iso(_now_utc()),
                    "not_after": _iso(not_after),
                    "record": dict(record),
                }
            )
        return row_id

    def list(self, tenant_id: str, *, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            rows = [row for row in self._rows if row["tenant_id"] == tenant_id]
            return list(rows[-limit:])

    def cleanup_expired(self, *, now: datetime | None = None) -> int:
        now = now or _now_utc()
        cutoff_iso = _iso(now)
        with self._lock:
            before = len(self._rows)
            self._rows = [row for row in self._rows if str(row["not_after"]) >= cutoff_iso]
            return before - len(self._rows)

    def count(self, tenant_id: str | None = None) -> int:
        with self._lock:
            if tenant_id is None:
                return len(self._rows)
            return sum(1 for row in self._rows if row["tenant_id"] == tenant_id)


# ─── SQLite backend ─────────────────────────────────────────────────────────


_SCHEMA_KEY = "proxy_replay_log"


class SQLiteProxyReplayStore:
    """SQLite-backed tier-B capture store for single-node proxies."""

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
        from agent_bom.api.storage_schema import ensure_sqlite_schema_version

        ensure_sqlite_schema_version(self._conn, _SCHEMA_KEY)
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS proxy_replay_log (
                row_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                captured_at TEXT NOT NULL,
                not_after TEXT NOT NULL,
                record TEXT NOT NULL
            )
            """
        )
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_replay_not_after ON proxy_replay_log(not_after)")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_replay_tenant ON proxy_replay_log(tenant_id)")
        self._conn.commit()

    def add(
        self,
        tenant_id: str,
        record: dict[str, Any],
        *,
        not_after: datetime | None = None,
    ) -> str:
        from uuid import uuid4

        not_after = not_after or replay_not_after()
        row_id = str(uuid4())
        self._conn.execute(
            """
            INSERT INTO proxy_replay_log (row_id, tenant_id, captured_at, not_after, record)
            VALUES (?, ?, ?, ?, ?)
            """,
            (row_id, str(tenant_id or "default"), _iso(_now_utc()), _iso(not_after), json.dumps(record)),
        )
        self._conn.commit()
        return row_id

    def list(self, tenant_id: str, *, limit: int = 100) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT row_id, tenant_id, captured_at, not_after, record"
            " FROM proxy_replay_log WHERE tenant_id = ? ORDER BY captured_at DESC LIMIT ?",
            (tenant_id, int(limit)),
        ).fetchall()
        return [
            {
                "row_id": row[0],
                "tenant_id": row[1],
                "captured_at": row[2],
                "not_after": row[3],
                "record": json.loads(row[4]),
            }
            for row in rows
        ]

    def cleanup_expired(self, *, now: datetime | None = None) -> int:
        now = now or _now_utc()
        cur = self._conn.execute("DELETE FROM proxy_replay_log WHERE not_after < ?", (_iso(now),))
        self._conn.commit()
        return int(cur.rowcount or 0)

    def count(self, tenant_id: str | None = None) -> int:
        if tenant_id is None:
            row = self._conn.execute("SELECT COUNT(*) FROM proxy_replay_log").fetchone()
        else:
            row = self._conn.execute("SELECT COUNT(*) FROM proxy_replay_log WHERE tenant_id = ?", (tenant_id,)).fetchone()
        return int(row[0]) if row else 0


# ─── Postgres backend ───────────────────────────────────────────────────────


class PostgresProxyReplayStore:
    """Postgres-backed tier-B capture store for multi-replica deployments."""

    def __init__(self, pool=None) -> None:
        from agent_bom.api.postgres_common import _get_pool

        self._pool = pool or _get_pool()
        self._init_tables()

    def _init_tables(self) -> None:
        from agent_bom.api.postgres_common import _ensure_tenant_rls
        from agent_bom.api.storage_schema import ensure_postgres_schema_version

        with self._pool.connection() as conn:
            ensure_postgres_schema_version(conn, _SCHEMA_KEY)
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS proxy_replay_log (
                    row_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    captured_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                    not_after TIMESTAMPTZ NOT NULL,
                    record JSONB NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_replay_not_after ON proxy_replay_log(not_after)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_replay_tenant ON proxy_replay_log(tenant_id)")
            _ensure_tenant_rls(conn, "proxy_replay_log", "tenant_id")
            conn.commit()

    def add(
        self,
        tenant_id: str,
        record: dict[str, Any],
        *,
        not_after: datetime | None = None,
    ) -> str:
        from uuid import uuid4

        from agent_bom.api.postgres_common import _tenant_connection

        not_after = not_after or replay_not_after()
        row_id = str(uuid4())
        with _tenant_connection(self._pool) as conn:
            conn.execute(
                """
                INSERT INTO proxy_replay_log (row_id, tenant_id, not_after, record)
                VALUES (%s, %s, %s, %s::jsonb)
                """,
                (row_id, str(tenant_id or "default"), not_after, json.dumps(record)),
            )
            conn.commit()
        return row_id

    def list(self, tenant_id: str, *, limit: int = 100) -> list[dict[str, Any]]:
        from agent_bom.api.postgres_common import _tenant_connection

        with _tenant_connection(self._pool) as conn:
            rows = conn.execute(
                "SELECT row_id, tenant_id, captured_at, not_after, record"
                " FROM proxy_replay_log WHERE tenant_id = %s ORDER BY captured_at DESC LIMIT %s",
                (tenant_id, int(limit)),
            ).fetchall()
        out: list[dict[str, Any]] = []
        for row in rows:
            record = row[4] if isinstance(row[4], dict) else json.loads(row[4])
            out.append(
                {
                    "row_id": row[0],
                    "tenant_id": row[1],
                    "captured_at": row[2].isoformat() if hasattr(row[2], "isoformat") else str(row[2]),
                    "not_after": row[3].isoformat() if hasattr(row[3], "isoformat") else str(row[3]),
                    "record": record,
                }
            )
        return out

    def cleanup_expired(self, *, now: datetime | None = None) -> int:
        now = now or _now_utc()
        with self._pool.connection() as conn:
            cur = conn.execute("DELETE FROM proxy_replay_log WHERE not_after < %s", (now,))
            conn.commit()
        return int(getattr(cur, "rowcount", 0) or 0)

    def count(self, tenant_id: str | None = None) -> int:
        with self._pool.connection() as conn:
            if tenant_id is None:
                row = conn.execute("SELECT COUNT(*) FROM proxy_replay_log").fetchone()
            else:
                row = conn.execute("SELECT COUNT(*) FROM proxy_replay_log WHERE tenant_id = %s", (tenant_id,)).fetchone()
        return int(row[0]) if row else 0


# ─── Module-level singleton ──────────────────────────────────────────────────


_REPLAY_STORE: ProxyReplayStore | None = None
_REPLAY_LOCK = threading.Lock()


def get_proxy_replay_store() -> ProxyReplayStore:
    """Return the active replay store, lazily picking the configured backend.

    Resolution order matches the compliance-hub pattern:
      1. ``AGENT_BOM_POSTGRES_URL`` -> Postgres
      2. ``AGENT_BOM_DB`` -> SQLite
      3. neither -> in-memory
    """

    global _REPLAY_STORE
    if _REPLAY_STORE is not None:
        return _REPLAY_STORE
    with _REPLAY_LOCK:
        if _REPLAY_STORE is not None:
            return _REPLAY_STORE
        if os.environ.get("AGENT_BOM_POSTGRES_URL"):
            _REPLAY_STORE = PostgresProxyReplayStore()
        elif os.environ.get("AGENT_BOM_DB"):
            _REPLAY_STORE = SQLiteProxyReplayStore(os.environ["AGENT_BOM_DB"])
        else:
            _REPLAY_STORE = InMemoryProxyReplayStore()
    return _REPLAY_STORE


def set_proxy_replay_store(store: ProxyReplayStore | None) -> None:
    """Override the replay store. Used by tests."""

    global _REPLAY_STORE
    with _REPLAY_LOCK:
        _REPLAY_STORE = store


def reset_proxy_replay_store() -> None:
    """Reset to lazy-init. Used by tests; never call from production code."""

    global _REPLAY_STORE
    with _REPLAY_LOCK:
        _REPLAY_STORE = None


# ─── Capture-replay enablement flag ──────────────────────────────────────────

_CAPTURE_REPLAY_ENABLED = False
_CAPTURE_LOCK = threading.Lock()


def set_capture_replay(enabled: bool) -> None:
    """Enable or disable tier-B capture for this process."""

    global _CAPTURE_REPLAY_ENABLED
    with _CAPTURE_LOCK:
        _CAPTURE_REPLAY_ENABLED = bool(enabled)


def capture_replay_enabled() -> bool:
    """Return True when ``--capture-replay`` is in effect for this process."""

    if _CAPTURE_REPLAY_ENABLED:
        return True
    raw = (os.environ.get("AGENT_BOM_CAPTURE_REPLAY") or "").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def capture_tier_b(tenant_id: str, record: dict[str, Any]) -> str | None:
    """Persist a tier-B record when capture-replay is enabled.

    Returns the new row id, or ``None`` when capture-replay is off (caller
    should treat the tier-B fields as discarded).
    """
    if not capture_replay_enabled():
        return None
    return get_proxy_replay_store().add(tenant_id, record, not_after=replay_not_after())


def replay_status() -> dict[str, Any]:
    """Operator-facing replay-store posture for status surfaces."""

    return {
        "capture_replay_enabled": capture_replay_enabled(),
        "ttl_days": replay_ttl_days(),
        "ttl_env": "AGENT_BOM_REPLAY_TTL_DAYS",
    }
