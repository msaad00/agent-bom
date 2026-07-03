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
from collections.abc import Callable
from typing import Any, Protocol

from agent_bom.evidence import EvidenceTier, redact_for_persistence

# Defined here (module scope) so ``list`` resolves to the builtin: the store
# classes below define a ``list`` method that would otherwise shadow it in
# their ``list_page`` return annotations.
FindingPage = tuple[list[dict[str, Any]], int]

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}

# Sort keys supported by ``list_page``. ``effective_reach`` is the default and
# the only one backed by a dedicated index/column; ``cvss`` and ``severity``
# fall back to JSON-extraction ordering, and ``ordinal`` uses ingest order.
_LIST_PAGE_SORTS = ("effective_reach", "cvss", "severity", "ordinal")


def _severity_rank(payload: dict[str, Any]) -> int:
    return _SEVERITY_RANK.get(str(payload.get("severity", "")).lower(), 0)


def _cvss_value(payload: dict[str, Any]) -> float:
    try:
        return float(payload.get("cvss_score") or 0.0)
    except (TypeError, ValueError):
        return 0.0


def compute_effective_reach_score(payload: dict[str, Any]) -> float:
    """Return the composite effective-reach signal for a finding payload.

    Shared by the API sort path (``routes/scan.py``) and the persistence
    layer so the ``effective_reach_score`` column materialised on ingest
    matches the in-memory ranking exactly. Prefers an explicit
    ``effective_reach_score`` field, then the ``effective_reach.composite``
    breakdown, defaulting to ``0.0`` when neither is present.
    """
    reach = payload.get("effective_reach_score")
    if reach is None:
        breakdown = payload.get("effective_reach") or {}
        if isinstance(breakdown, dict):
            reach = breakdown.get("composite")
    try:
        return float(reach or 0.0)
    except (TypeError, ValueError):
        return 0.0


def _page_signal(row: dict[str, Any], sort: str) -> float:
    """Return the single descending sort signal for ``list_page``."""
    if sort == "cvss":
        return _cvss_value(row)
    if sort == "severity":
        return float(_severity_rank(row))
    return compute_effective_reach_score(row)  # effective_reach default


def _page_sort_key(sort: str) -> Callable[[dict[str, Any]], float]:
    """Return a Python sort key mirroring the SQL ordering of ``list_page``.

    Descending on the requested signal only. Python's stable sort preserves
    ingest order for ties, which matches the SQL ``ORDER BY <signal> DESC,
    ordinal ASC`` tiebreak used by the persistent backends.
    """
    normalized = sort if sort in _LIST_PAGE_SORTS else "effective_reach"
    return lambda row: -_page_signal(row, normalized)


def _redact_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Drop tier-B fields before any compliance-hub finding is stored.

    The hub is a tier-A sink — findings are exported, queried by auditors,
    and held indefinitely. See issue #2261.
    """
    redacted: list[dict[str, Any]] = []
    for payload in findings:
        if not isinstance(payload, dict):
            continue
        clean = redact_for_persistence(payload, EvidenceTier.SAFE_TO_STORE)
        # Preserve identity fields the store keys on, even if the redactor
        # didn't recognise them by exact name (e.g. legacy "id" alias).
        if "id" not in clean and "id" in payload:
            clean["id"] = str(payload["id"])
        if "source" not in clean and "source" in payload:
            clean["source"] = str(payload["source"])
        for key in ("origin", "batch_id", "bulk_ordinal"):
            if key not in clean and key in payload:
                clean[key] = payload[key]
        redacted.append(clean)
    return redacted


class ComplianceHubStore(Protocol):
    """Append-only ledger of hub-ingested findings, scoped per tenant."""

    def add(self, tenant_id: str, findings: list[dict[str, Any]]) -> int:
        """Append findings for a tenant. Returns the new total count."""
        ...

    def list(self, tenant_id: str) -> list[dict[str, Any]]:
        """Return every finding for a tenant in ingest order (oldest first).

        Deprecated for read-path use at scale: loads the full tenant into
        memory. Prefer :meth:`list_page` for API surfaces that paginate.
        Retained for posture aggregation and callers that genuinely need
        the whole tenant.
        """
        ...

    def list_page(
        self,
        tenant_id: str,
        *,
        limit: int,
        offset: int = 0,
        sort: str = "effective_reach",
        severity: str | None = None,
        scan_id: str | None = None,
        origin: str | None = None,
    ) -> FindingPage:
        """Return a single page of findings plus the matching total.

        Pushes ``ORDER BY`` / ``LIMIT`` / ``OFFSET`` and the optional
        ``severity`` / ``scan_id`` / ``origin`` filters into the backend so
        the read path stays sub-linear at million-row scale. ``sort`` is one
        of ``effective_reach`` (default, indexed), ``cvss``, ``severity`` or
        ``ordinal`` (ingest order). Returns ``(rows, total)`` where ``total``
        counts all findings matching the filters, not just the page.
        """
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
        clean = _redact_findings(findings)
        with self._lock:
            bucket = self._by_tenant.setdefault(tenant_id, [])
            bucket.extend(clean)
            return len(bucket)

    def list(self, tenant_id: str) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._by_tenant.get(tenant_id, []))

    def list_page(
        self,
        tenant_id: str,
        *,
        limit: int,
        offset: int = 0,
        sort: str = "effective_reach",
        severity: str | None = None,
        scan_id: str | None = None,
        origin: str | None = None,
    ) -> FindingPage:
        with self._lock:
            rows = list(self._by_tenant.get(tenant_id, []))
        if origin is not None:
            rows = [r for r in rows if r.get("origin") == origin]
        if severity is not None:
            sev = severity.lower()
            rows = [r for r in rows if str(r.get("severity", "")).lower() == sev]
        if scan_id is not None:
            rows = [r for r in rows if str(r.get("scan_id") or "") == scan_id]
        total = len(rows)
        if sort != "ordinal":
            rows.sort(key=_page_sort_key(sort))
        if offset:
            rows = rows[offset:]
        if limit >= 0:
            rows = rows[:limit]
        return rows, total

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


def _sqlite_order_clause(sort: str) -> str:
    """ORDER BY clause for the SQLite backend, ordinal-tiebroken to match
    the in-memory backend's stable sort."""
    if sort == "ordinal":
        return "ORDER BY ordinal ASC"
    if sort == "cvss":
        return "ORDER BY CAST(json_extract(payload, '$.cvss_score') AS REAL) DESC, ordinal ASC"
    if sort == "severity":
        # Map severity band to the same rank used in-memory.
        return (
            "ORDER BY CASE LOWER(COALESCE(json_extract(payload, '$.severity'), '')) "
            "WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 "
            "ELSE 0 END DESC, ordinal ASC"
        )
    # effective_reach (default) — index-backed range scan + limit.
    return "ORDER BY effective_reach_score DESC, ordinal ASC"


def _postgres_order_clause(sort: str) -> str:
    """ORDER BY clause for the Postgres backend, mirroring SQLite semantics."""
    if sort == "ordinal":
        return "ORDER BY ordinal ASC"
    if sort == "cvss":
        return "ORDER BY (payload->>'cvss_score')::float8 DESC NULLS LAST, ordinal ASC"
    if sort == "severity":
        return (
            "ORDER BY CASE LOWER(COALESCE(payload->>'severity', '')) "
            "WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 "
            "ELSE 0 END DESC, ordinal ASC"
        )
    return "ORDER BY effective_reach_score DESC, ordinal ASC"


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
                effective_reach_score REAL NOT NULL DEFAULT 0,
                origin TEXT NOT NULL DEFAULT '',
                PRIMARY KEY (tenant_id, finding_id, ordinal)
            )
            """
        )
        self._migrate_columns()
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_hub_findings_tenant_order ON compliance_hub_findings(tenant_id, ordinal)")
        self._ensure_scale_indexes()
        self._conn.commit()

    def _migrate_columns(self) -> None:
        """Add PR1 read-scale columns to pre-existing tables (idempotent)."""
        cols = {row[1] for row in self._conn.execute("PRAGMA table_info(compliance_hub_findings)").fetchall()}
        if "effective_reach_score" not in cols:
            self._conn.execute("ALTER TABLE compliance_hub_findings ADD COLUMN effective_reach_score REAL NOT NULL DEFAULT 0")
        if "origin" not in cols:
            self._conn.execute("ALTER TABLE compliance_hub_findings ADD COLUMN origin TEXT NOT NULL DEFAULT ''")
            # Backfill origin from the stored payload so pre-migration rows
            # remain filterable without a full rewrite on the read path.
            self._conn.execute(
                "UPDATE compliance_hub_findings SET origin = COALESCE(json_extract(payload, '$.origin'), '') WHERE origin = ''"
            )

    def _ensure_scale_indexes(self) -> None:
        """Install origin-aware read indexes, replacing the pre-origin index.

        ``CREATE INDEX IF NOT EXISTS`` does not update an existing index with
        the same name, so older SQLite DBs would silently keep
        ``(tenant_id, effective_reach_score, ordinal)`` and scan every tenant
        row for ``origin='bulk_ingest'``. Drop/recreate keeps the migration
        deterministic and idempotent.
        """
        self._conn.execute("DROP INDEX IF EXISTS idx_hub_findings_tenant_reach")
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_hub_findings_tenant_origin_reach "
            "ON compliance_hub_findings(tenant_id, origin, effective_reach_score DESC, ordinal)"
        )
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_hub_findings_tenant_origin ON compliance_hub_findings(tenant_id, origin)")

    def _next_ordinal(self, tenant_id: str) -> int:
        row = self._conn.execute(
            "SELECT COALESCE(MAX(ordinal), 0) FROM compliance_hub_findings WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchone()
        return int(row[0]) + 1 if row else 1

    def add(self, tenant_id: str, findings: list[dict[str, Any]]) -> int:
        findings = _redact_findings(findings)
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
                    compute_effective_reach_score(payload),
                    str(payload.get("origin") or ""),
                )
            )
        self._conn.executemany(
            """
            INSERT OR REPLACE INTO compliance_hub_findings
                (tenant_id, finding_id, ingested_at, source, applicable_frameworks_csv, payload, ordinal, effective_reach_score, origin)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
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

    def list_page(
        self,
        tenant_id: str,
        *,
        limit: int,
        offset: int = 0,
        sort: str = "effective_reach",
        severity: str | None = None,
        scan_id: str | None = None,
        origin: str | None = None,
    ) -> FindingPage:
        where = ["tenant_id = ?"]
        params: list[Any] = [tenant_id]
        if origin is not None:
            where.append("origin = ?")
            params.append(origin)
        if severity is not None:
            where.append("LOWER(json_extract(payload, '$.severity')) = ?")
            params.append(severity.lower())
        if scan_id is not None:
            where.append("CAST(json_extract(payload, '$.scan_id') AS TEXT) = ?")
            params.append(scan_id)
        where_sql = " AND ".join(where)

        total_row = self._conn.execute(
            f"SELECT COUNT(*) FROM compliance_hub_findings WHERE {where_sql}",
            params,
        ).fetchone()
        total = int(total_row[0]) if total_row else 0

        order_sql = _sqlite_order_clause(sort)
        page_params = [*params, int(limit), int(offset)]
        rows = self._conn.execute(
            f"SELECT payload FROM compliance_hub_findings WHERE {where_sql} {order_sql} LIMIT ? OFFSET ?",
            page_params,
        ).fetchall()
        return [json.loads(row[0]) for row in rows], total

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
