"""Tenant-scoped store for hub-ingested findings (#1044 PR C + persistence).

Three backends share the same Protocol so callers (`api/routes/compliance.py`)
don't care which is wired:

- ``InMemoryComplianceHubStore`` — process-local; ephemeral; the test default.
- ``SQLiteComplianceHubStore`` — single-node persistence behind
  ``AGENT_BOM_DB``. Survives restarts; not safe for multi-replica.
- ``PostgresComplianceHubStore`` — multi-replica; required behind
  ``AGENT_BOM_POSTGRES_URL`` for clustered self-hosted deployments.

Selection happens in ``stores.get_compliance_hub_store()``. Same env-var
pattern as the SCIM lifecycle store, so an operator who's already
configured Postgres for SCIM gets durable hub findings for free.

Schema is denormalised on the framework slugs: a CSV column
``applicable_frameworks_csv`` lets posture aggregation filter at the SQL
layer instead of decoding every payload. Each finding is also tagged
with ``ingested_at`` so future expiry / TTL work has a key.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from typing import Any, Protocol


class ComplianceHubStore(Protocol):
    """Append-only ledger of hub-ingested findings, scoped per tenant."""

    def add(self, tenant_id: str, findings: list[dict[str, Any]]) -> int:
        """Append findings for a tenant. Returns the new total count."""
        ...

    def list(self, tenant_id: str) -> list[dict[str, Any]]:
        """Return every finding for a tenant in ingest order (oldest first)."""
        ...

    def count(self, tenant_id: str) -> int:
        """Return the count of findings for a tenant."""
        ...

    def clear(self, tenant_id: str) -> int:
        """Remove all findings for a tenant. Returns the number removed."""
        ...


# ─── In-memory backend ──────────────────────────────────────────────────────


class InMemoryComplianceHubStore:
    """Process-local store. Ephemeral; tests + single-node demos only."""

    def __init__(self) -> None:
        self._by_tenant: dict[str, list[dict[str, Any]]] = {}
        self._lock = threading.Lock()

    def add(self, tenant_id: str, findings: list[dict[str, Any]]) -> int:
        with self._lock:
            bucket = self._by_tenant.setdefault(tenant_id, [])
            bucket.extend(findings)
            return len(bucket)

    def list(self, tenant_id: str) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._by_tenant.get(tenant_id, []))

    def count(self, tenant_id: str) -> int:
        with self._lock:
            return len(self._by_tenant.get(tenant_id, []))

    def clear(self, tenant_id: str) -> int:
        with self._lock:
            removed = len(self._by_tenant.get(tenant_id, []))
            self._by_tenant[tenant_id] = []
            return removed


# ─── SQLite backend ─────────────────────────────────────────────────────────

# Default name surfaced in the openapi description; set when AGENT_BOM_DB is wired.
_SCHEMA_KEY = "compliance_hub"


def _frameworks_csv(payload: dict[str, Any]) -> str:
    """Denormalise the framework slug list into a sortable CSV column."""
    slugs = payload.get("applicable_frameworks") or []
    if not isinstance(slugs, list):
        return ""
    return ",".join(str(s) for s in slugs if s)


def _now_utc_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class SQLiteComplianceHubStore:
    """SQLite-backed hub store for single-node persistence.

    NOT safe for multi-replica API deployments: SQLite's WAL is local to
    the file. Use ``PostgresComplianceHubStore`` when more than one API
    pod must share findings.
    """

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
            CREATE TABLE IF NOT EXISTS compliance_hub_findings (
                tenant_id TEXT NOT NULL,
                finding_id TEXT NOT NULL,
                ingested_at TEXT NOT NULL,
                source TEXT NOT NULL,
                applicable_frameworks_csv TEXT NOT NULL DEFAULT '',
                payload TEXT NOT NULL,
                ordinal INTEGER NOT NULL,
                PRIMARY KEY (tenant_id, finding_id, ordinal)
            )
            """
        )
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_hub_findings_tenant_order ON compliance_hub_findings(tenant_id, ordinal)")
        self._conn.commit()

    def _next_ordinal(self, tenant_id: str) -> int:
        row = self._conn.execute(
            "SELECT COALESCE(MAX(ordinal), 0) FROM compliance_hub_findings WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchone()
        return int(row[0]) + 1 if row else 1

    def add(self, tenant_id: str, findings: list[dict[str, Any]]) -> int:
        if not findings:
            return self.count(tenant_id)
        now = _now_utc_iso()
        next_ord = self._next_ordinal(tenant_id)
        rows = []
        for offset, payload in enumerate(findings):
            rows.append(
                (
                    tenant_id,
                    str(payload.get("id") or f"hub-{next_ord + offset}"),
                    now,
                    str(payload.get("source") or ""),
                    _frameworks_csv(payload),
                    json.dumps(payload, sort_keys=True),
                    next_ord + offset,
                )
            )
        self._conn.executemany(
            """
            INSERT OR REPLACE INTO compliance_hub_findings
                (tenant_id, finding_id, ingested_at, source, applicable_frameworks_csv, payload, ordinal)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
        self._conn.commit()
        return self.count(tenant_id)

    def list(self, tenant_id: str) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT payload FROM compliance_hub_findings WHERE tenant_id = ? ORDER BY ordinal ASC",
            (tenant_id,),
        ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def count(self, tenant_id: str) -> int:
        row = self._conn.execute(
            "SELECT COUNT(*) FROM compliance_hub_findings WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchone()
        return int(row[0]) if row else 0

    def clear(self, tenant_id: str) -> int:
        cur = self._conn.execute(
            "DELETE FROM compliance_hub_findings WHERE tenant_id = ?",
            (tenant_id,),
        )
        self._conn.commit()
        return cur.rowcount or 0


# ─── Module-level access (set/reset wired in stores.py) ──────────────────────


_HUB_STORE: ComplianceHubStore | None = None


def get_compliance_hub_store() -> ComplianceHubStore:
    """Return the active hub store, lazily picking the configured backend.

    Resolution order:
      1. ``AGENT_BOM_POSTGRES_URL`` -> Postgres (multi-replica safe)
      2. ``AGENT_BOM_DB`` -> SQLite (single-node persistent)
      3. neither -> in-memory (ephemeral)
    """
    import os

    global _HUB_STORE
    if _HUB_STORE is not None:
        return _HUB_STORE

    if os.environ.get("AGENT_BOM_POSTGRES_URL"):
        from agent_bom.api.postgres_compliance_hub import PostgresComplianceHubStore

        _HUB_STORE = PostgresComplianceHubStore()
    elif os.environ.get("AGENT_BOM_DB"):
        _HUB_STORE = SQLiteComplianceHubStore(os.environ["AGENT_BOM_DB"])
    else:
        _HUB_STORE = InMemoryComplianceHubStore()
    return _HUB_STORE


def set_compliance_hub_store(store: ComplianceHubStore | None) -> None:
    """Override the hub store. Used by tests to inject a clean backend."""
    global _HUB_STORE
    _HUB_STORE = store


def reset_compliance_hub_store() -> None:
    """Reset to lazy-init. Used by tests; never call from production code."""
    global _HUB_STORE
    _HUB_STORE = None
