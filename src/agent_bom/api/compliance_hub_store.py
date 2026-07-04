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
from collections.abc import Callable, Iterable, Sequence
from typing import Any, Protocol

from agent_bom.api.hub_current_payload import (
    batch_ledger_payloads,
    current_state_overlay,
    hydrate_current_payload,
    resolve_ledger_finding_id,
)
from agent_bom.evidence import EvidenceTier, redact_for_persistence
from agent_bom.graph.severity import severity_policy_rank

# Defined here (module scope) so ``list`` resolves to the builtin: the store
# classes below define a ``list`` method that would otherwise shadow it in
# their ``list_page`` return annotations.
FindingPage = tuple[list[dict[str, Any]], int | None]
_HubFindingRows = list[dict[str, Any]]

# Sort keys supported by ``list_page``. ``effective_reach`` (default),
# ``cvss`` and ``severity`` are each backed by a materialised column +
# composite ``(tenant_id, origin, <col> DESC, ordinal)`` index; ``ordinal``
# uses ingest order.
_LIST_PAGE_SORTS = ("effective_reach", "cvss", "severity", "ordinal")


def _severity_rank(payload: dict[str, Any]) -> int:
    return severity_policy_rank(str(payload.get("severity", "")))


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


def _filter_hub_rows(
    rows: list[dict[str, Any]],
    *,
    severity: str | None,
    scan_id: str | None,
    origin: str | None,
) -> list[dict[str, Any]]:
    if origin is not None:
        rows = [r for r in rows if r.get("origin") == origin]
    if severity is not None:
        sev = severity.lower()
        rows = [r for r in rows if str(r.get("severity", "")).lower() == sev]
    if scan_id is not None:
        rows = [r for r in rows if str(r.get("scan_id") or "") == scan_id]
    return rows


def _severity_breakdown_from_rows(rows: Iterable[dict[str, Any]]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}
    for row in rows:
        sev = str(row.get("severity") or "unknown").lower()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _framework_slug_counts_from_rows(rows: Iterable[dict[str, Any]]) -> dict[str, int]:
    from agent_bom.compliance_coverage import normalize_framework_slug

    counts: dict[str, int] = {}
    for row in rows:
        for slug in row.get("applicable_frameworks") or []:
            canonical = normalize_framework_slug(str(slug))
            counts[canonical] = counts.get(canonical, 0) + 1
    return counts


def _redact_findings(findings: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
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
        include_total: bool = True,
    ) -> FindingPage:
        """Return a single page of findings plus the matching total.

        Pushes ``ORDER BY`` / ``LIMIT`` / ``OFFSET`` and the optional
        ``severity`` / ``scan_id`` / ``origin`` filters into the backend so
        the read path stays sub-linear at million-row scale. ``sort`` is one
        of ``effective_reach`` (default, indexed), ``cvss``, ``severity`` or
        ``ordinal`` (ingest order). Returns ``(rows, total)`` where ``total``
        counts all findings matching the filters, not just the page. When
        ``include_total`` is false the backend skips ``COUNT(*)`` and
        returns ``None`` for ``total``.
        """
        ...

    def count(self, tenant_id: str) -> int:
        """Return the count of findings for a tenant."""
        ...

    def severity_breakdown(self, tenant_id: str) -> dict[str, int]:
        """Return per-severity counts for hub findings without loading payloads."""
        ...

    def framework_slug_counts(self, tenant_id: str) -> dict[str, int]:
        """Return per-framework slug counts from denormalised CSV columns."""
        ...

    def clear(self, tenant_id: str) -> int:
        """Remove all findings for a tenant. Returns the number removed."""
        ...

    def upsert_current_batch(
        self,
        tenant_id: str,
        findings: Sequence[dict[str, Any]],
        *,
        observed_at: str,
        batch_id: str,
        source: str = "",
    ) -> None:
        """Merge findings into the current-state lifecycle table (#3465 L1)."""
        ...

    def get_current(self, tenant_id: str, canonical_id: str) -> dict[str, Any] | None:
        """Return one current-state lifecycle row for tests and diagnostics."""
        ...

    def list_current_page(
        self,
        tenant_id: str,
        *,
        limit: int,
        offset: int = 0,
        sort: str = "effective_reach",
        severity: str | None = None,
        scan_id: str | None = None,
        origin: str | None = None,
        include_total: bool = True,
    ) -> FindingPage:
        """Return a page from ``hub_findings_current`` with lifecycle fields merged."""
        ...

    def reconcile_current_absent(
        self,
        tenant_id: str,
        *,
        present_canonical_ids: set[str],
        observed_at: str,
        scope_source: str | None = None,
    ) -> int:
        """Mark open findings absent from a scan batch as resolved at ``observed_at``."""
        ...


def _fetch_ledger_payloads_sqlite(
    conn: sqlite3.Connection,
    tenant_id: str,
    finding_ids: Sequence[str],
) -> dict[str, dict[str, Any]]:
    if not finding_ids:
        return {}
    placeholders = ",".join("?" * len(finding_ids))
    rows = conn.execute(
        f"""
        SELECT finding_id, payload
        FROM compliance_hub_findings
        WHERE tenant_id = ? AND finding_id IN ({placeholders})
        """,  # nosec B608
        (tenant_id, *finding_ids),
    ).fetchall()
    return {str(row[0]): json.loads(row[1]) for row in rows}


def _sqlite_current_row_from_db(row: tuple[Any, ...], *, has_ledger_col: bool) -> dict[str, Any]:
    current_row = {
        "canonical_id": row[0],
        "first_seen": row[1],
        "last_seen": row[2],
        "status": row[3],
        "severity": row[4],
        "severity_rank": row[5],
        "cvss_score": row[6],
        "effective_reach_score": row[7],
        "scan_count": row[8],
        "resolved_at": row[9],
        "reopened_at": row[10],
        "updated_at": row[11],
        "payload": json.loads(row[12]),
    }
    if has_ledger_col:
        current_row["ledger_finding_id"] = row[13]
    return current_row


def _upsert_current_finding_sqlite(
    conn: sqlite3.Connection,
    *,
    tenant_id: str,
    payload: dict[str, Any],
    observed_at: str,
    scan_id: str,
    source: str,
) -> None:
    from agent_bom.api.finding_lifecycle import (
        apply_observation_to_current,
        lifecycle_metrics,
        resolve_canonical_id,
    )

    canonical = resolve_canonical_id(payload, source=source)
    metrics = lifecycle_metrics(payload)
    now = _now_utc_iso()
    ledger_finding_id = resolve_ledger_finding_id(payload, canonical_id=canonical)
    overlay = current_state_overlay(payload) if ledger_finding_id else dict(payload)
    payload_json = json.dumps(overlay, sort_keys=True)
    inserted = conn.execute(
        """
        INSERT OR IGNORE INTO hub_findings_current_observations
            (tenant_id, canonical_id, scan_id, observed_at)
        VALUES (?, ?, ?, ?)
        """,
        (tenant_id, canonical, scan_id, observed_at),
    ).rowcount
    if not inserted:
        return

    has_ledger_col = _hub_findings_current_has_ledger_col(conn)
    payload_select = "payload, ledger_finding_id" if has_ledger_col else "payload"
    existing_row = conn.execute(
        f"""
        SELECT canonical_id, first_seen, last_seen, status, severity, severity_rank,
               cvss_score, effective_reach_score, scan_count, resolved_at, reopened_at,
               updated_at, {payload_select}
        FROM hub_findings_current
        WHERE tenant_id = ? AND canonical_id = ?
        """,  # nosec B608
        (tenant_id, canonical),
    ).fetchone()
    existing: dict[str, Any] | None
    if existing_row is None:
        existing = None
    else:
        existing = _sqlite_current_row_from_db(existing_row, has_ledger_col=has_ledger_col)
        if has_ledger_col:
            ledger_map = _fetch_ledger_payloads_sqlite(
                conn,
                tenant_id,
                [str(existing.get("ledger_finding_id") or "")],
            )
            existing["payload"] = hydrate_current_payload(existing, ledger_payloads=ledger_map)
    merged = apply_observation_to_current(
        existing,
        canonical_id=canonical,
        observed_at=observed_at,
        metrics=metrics,
        payload=payload,
        updated_at=now,
    )
    if has_ledger_col:
        conn.execute(
            """
            INSERT INTO hub_findings_current
                (tenant_id, canonical_id, first_seen, last_seen, status, severity, severity_rank,
                 cvss_score, effective_reach_score, scan_count, resolved_at, reopened_at,
                 updated_at, payload, ledger_finding_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(tenant_id, canonical_id) DO UPDATE SET
                first_seen = MIN(hub_findings_current.first_seen, excluded.first_seen),
                last_seen = MAX(hub_findings_current.last_seen, excluded.last_seen),
                status = excluded.status,
                severity = excluded.severity,
                severity_rank = excluded.severity_rank,
                cvss_score = excluded.cvss_score,
                effective_reach_score = excluded.effective_reach_score,
                scan_count = excluded.scan_count,
                resolved_at = excluded.resolved_at,
                reopened_at = excluded.reopened_at,
                updated_at = excluded.updated_at,
                payload = excluded.payload,
                ledger_finding_id = excluded.ledger_finding_id
            """,
            (
                tenant_id,
                canonical,
                merged["first_seen"],
                merged["last_seen"],
                merged["status"],
                merged["severity"],
                merged["severity_rank"],
                merged["cvss_score"],
                merged["effective_reach_score"],
                merged["scan_count"],
                merged["resolved_at"],
                merged["reopened_at"],
                merged["updated_at"],
                payload_json,
                ledger_finding_id or None,
            ),
        )
    else:
        conn.execute(
            """
            INSERT INTO hub_findings_current
                (tenant_id, canonical_id, first_seen, last_seen, status, severity, severity_rank,
                 cvss_score, effective_reach_score, scan_count, resolved_at, reopened_at,
                 updated_at, payload)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(tenant_id, canonical_id) DO UPDATE SET
                first_seen = MIN(hub_findings_current.first_seen, excluded.first_seen),
                last_seen = MAX(hub_findings_current.last_seen, excluded.last_seen),
                status = excluded.status,
                severity = excluded.severity,
                severity_rank = excluded.severity_rank,
                cvss_score = excluded.cvss_score,
                effective_reach_score = excluded.effective_reach_score,
                scan_count = excluded.scan_count,
                resolved_at = excluded.resolved_at,
                reopened_at = excluded.reopened_at,
                updated_at = excluded.updated_at,
                payload = excluded.payload
            """,
            (
                tenant_id,
                canonical,
                merged["first_seen"],
                merged["last_seen"],
                merged["status"],
                merged["severity"],
                merged["severity_rank"],
                merged["cvss_score"],
                merged["effective_reach_score"],
                merged["scan_count"],
                merged["resolved_at"],
                merged["reopened_at"],
                merged["updated_at"],
                payload_json,
            ),
        )


def _hydrate_sqlite_current_rows(
    conn: sqlite3.Connection,
    tenant_id: str,
    current_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    ledger_map = batch_ledger_payloads(
        lambda ids: _fetch_ledger_payloads_sqlite(conn, tenant_id, ids),
        [str(row.get("ledger_finding_id") or "") for row in current_rows],
    )
    hydrated: list[dict[str, Any]] = []
    for row in current_rows:
        hydrated_row = dict(row)
        hydrated_row["payload"] = hydrate_current_payload(row, ledger_payloads=ledger_map)
        hydrated.append(hydrated_row)
    return hydrated


def _hub_findings_current_has_ledger_col(conn: sqlite3.Connection) -> bool:
    cols = {row[1] for row in conn.execute("PRAGMA table_info(hub_findings_current)").fetchall()}
    return "ledger_finding_id" in cols


def _migrate_current_ledger_ref_sqlite(conn: sqlite3.Connection) -> None:
    cols = {row[1] for row in conn.execute("PRAGMA table_info(hub_findings_current)").fetchall()}
    if "ledger_finding_id" not in cols:
        conn.execute("ALTER TABLE hub_findings_current ADD COLUMN ledger_finding_id TEXT")


def _ensure_current_lifecycle_sqlite(conn: sqlite3.Connection) -> None:
    from agent_bom.api.finding_lifecycle import _CURRENT_LIFECYCLE_SQLITE_DDL

    conn.executescript(_CURRENT_LIFECYCLE_SQLITE_DDL)
    _migrate_lifecycle_observations_l2_sqlite(conn)
    _migrate_current_ledger_ref_sqlite(conn)


def _migrate_lifecycle_observations_l2_sqlite(conn: sqlite3.Connection) -> None:
    """Upgrade L1 observation rows (PK on observed_at) to L2 (PK on scan_id)."""
    rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='hub_findings_current_observations'").fetchall()
    if not rows:
        return
    cols = {row[1] for row in conn.execute("PRAGMA table_info(hub_findings_current_observations)").fetchall()}
    if "scan_id" in cols:
        return
    conn.execute("ALTER TABLE hub_findings_current_observations RENAME TO hub_findings_current_observations_l1")
    conn.execute(
        """
        CREATE TABLE hub_findings_current_observations (
            tenant_id TEXT NOT NULL,
            canonical_id TEXT NOT NULL,
            scan_id TEXT NOT NULL,
            observed_at TEXT NOT NULL,
            PRIMARY KEY (tenant_id, canonical_id, scan_id)
        )
        """
    )
    conn.execute(
        """
        INSERT INTO hub_findings_current_observations (tenant_id, canonical_id, scan_id, observed_at)
        SELECT tenant_id, canonical_id, observed_at, observed_at
        FROM hub_findings_current_observations_l1
        """
    )
    conn.execute("DROP TABLE hub_findings_current_observations_l1")


# ─── In-memory backend ──────────────────────────────────────────────────────


class InMemoryComplianceHubStore:
    """Process-local store. Ephemeral; tests + single-node demos only."""

    def __init__(self) -> None:
        self._by_tenant: dict[str, list[dict[str, Any]]] = {}
        # Maps finding_id -> ingest-order slot so a resend of the same
        # (tenant_id, finding_id) refreshes its row in place instead of
        # appending a duplicate (idempotent ingest, mirrors the SQL backends).
        self._slots: dict[str, dict[str, int]] = {}
        self._current: dict[str, dict[str, dict[str, Any]]] = {}
        self._current_observations: dict[str, set[tuple[str, str]]] = {}
        self._lock = threading.Lock()

    def add(self, tenant_id: str, findings: list[dict[str, Any]]) -> int:
        clean = _redact_findings(findings)
        with self._lock:
            bucket = self._by_tenant.setdefault(tenant_id, [])
            slots = self._slots.setdefault(tenant_id, {})
            for payload in clean:
                finding_id = str(payload.get("id") or "")
                if finding_id and finding_id in slots:
                    # Refresh payload, keep original ingest position.
                    bucket[slots[finding_id]] = payload
                    continue
                if finding_id:
                    slots[finding_id] = len(bucket)
                bucket.append(payload)
            total = len(bucket)
        if clean:
            from agent_bom.api.findings_count_cache import invalidate_tenant

            invalidate_tenant(tenant_id)
        return total

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
        include_total: bool = True,
    ) -> FindingPage:
        with self._lock:
            rows = list(self._by_tenant.get(tenant_id, []))
        rows = _filter_hub_rows(rows, severity=severity, scan_id=scan_id, origin=origin)
        total = len(rows) if include_total else None
        if sort != "ordinal":
            rows.sort(key=_page_sort_key(sort))
        if offset:
            rows = rows[offset:]
        if limit >= 0:
            rows = rows[:limit]
        return rows, total

    def severity_breakdown(self, tenant_id: str) -> dict[str, int]:
        with self._lock:
            rows = list(self._by_tenant.get(tenant_id, []))
        return _severity_breakdown_from_rows(rows)

    def framework_slug_counts(self, tenant_id: str) -> dict[str, int]:
        with self._lock:
            rows = list(self._by_tenant.get(tenant_id, []))
        return _framework_slug_counts_from_rows(rows)

    def count(self, tenant_id: str) -> int:
        with self._lock:
            return len(self._by_tenant.get(tenant_id, []))

    def clear(self, tenant_id: str) -> int:
        with self._lock:
            removed = len(self._by_tenant.get(tenant_id, []))
            self._by_tenant[tenant_id] = []
            self._slots[tenant_id] = {}
            self._current.pop(tenant_id, None)
            self._current_observations.pop(tenant_id, None)
        if removed:
            from agent_bom.api.findings_count_cache import invalidate_tenant

            invalidate_tenant(tenant_id)
        return removed

    def upsert_current_batch(
        self,
        tenant_id: str,
        findings: Sequence[dict[str, Any]],
        *,
        observed_at: str,
        batch_id: str,
        source: str = "",
    ) -> None:
        from agent_bom.api.finding_lifecycle import (
            apply_observation_to_current,
            lifecycle_metrics,
            resolve_canonical_id,
        )

        clean = _redact_findings(findings)
        now = _now_utc_iso()
        with self._lock:
            current = self._current.setdefault(tenant_id, {})
            observations = self._current_observations.setdefault(tenant_id, set())
            for payload in clean:
                canonical = resolve_canonical_id(payload, source=source)
                obs_key = (canonical, batch_id)
                if obs_key in observations:
                    continue
                observations.add(obs_key)
                merged = apply_observation_to_current(
                    current.get(canonical),
                    canonical_id=canonical,
                    observed_at=observed_at,
                    metrics=lifecycle_metrics(payload),
                    payload=payload,
                    updated_at=now,
                )
                finding_id = resolve_ledger_finding_id(payload, canonical_id=canonical)
                if finding_id:
                    merged["ledger_finding_id"] = finding_id
                    merged["payload"] = current_state_overlay(payload)
                current[canonical] = merged

    def _ledger_payload_map(self, tenant_id: str, finding_ids: Sequence[str]) -> dict[str, dict[str, Any]]:
        slots = self._slots.get(tenant_id, {})
        bucket = self._by_tenant.get(tenant_id, [])
        out: dict[str, dict[str, Any]] = {}
        for finding_id in finding_ids:
            idx = slots.get(finding_id)
            if idx is not None and 0 <= idx < len(bucket):
                out[finding_id] = dict(bucket[idx])
        return out

    def _hydrate_current_rows(self, tenant_id: str, rows: _HubFindingRows) -> _HubFindingRows:
        ledger_map = batch_ledger_payloads(
            lambda ids: self._ledger_payload_map(tenant_id, ids),
            [str(row.get("ledger_finding_id") or "") for row in rows],
        )
        hydrated: list[dict[str, Any]] = []
        for row in rows:
            hydrated_row = dict(row)
            hydrated_row["payload"] = hydrate_current_payload(row, ledger_payloads=ledger_map)
            hydrated.append(hydrated_row)
        return hydrated

    def get_current(self, tenant_id: str, canonical_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._current.get(tenant_id, {}).get(canonical_id)
            if not row:
                return None
            hydrated = self._hydrate_current_rows(tenant_id, [dict(row)])
            return hydrated[0]

    def list_current_page(
        self,
        tenant_id: str,
        *,
        limit: int,
        offset: int = 0,
        sort: str = "effective_reach",
        severity: str | None = None,
        scan_id: str | None = None,
        origin: str | None = None,
        include_total: bool = True,
    ) -> FindingPage:
        from agent_bom.api.finding_lifecycle import enriched_finding_payload

        with self._lock:
            rows = list(self._current.get(tenant_id, {}).values())
        rows = _filter_current_rows(rows, severity=severity, scan_id=scan_id, origin=origin)
        total = len(rows) if include_total else None
        rows.sort(key=_current_page_sort_key(sort))
        if offset:
            rows = rows[offset:]
        if limit >= 0:
            rows = rows[:limit]
        rows = self._hydrate_current_rows(tenant_id, [dict(row) for row in rows])
        return [enriched_finding_payload(row) for row in rows], total

    def reconcile_current_absent(
        self,
        tenant_id: str,
        *,
        present_canonical_ids: set[str],
        observed_at: str,
        scope_source: str | None = None,
    ) -> int:
        now = _now_utc_iso()
        updated = 0
        with self._lock:
            current = self._current.setdefault(tenant_id, {})
            for canonical_id, row in list(current.items()):
                if str(row.get("status") or "") not in ("open", "reopened"):
                    continue
                if canonical_id in present_canonical_ids:
                    continue
                payload = row.get("payload") or {}
                if scope_source is not None and str(payload.get("source") or "") != scope_source:
                    continue
                merged = dict(row)
                merged["status"] = "resolved"
                merged["resolved_at"] = observed_at
                merged["updated_at"] = now
                current[canonical_id] = merged
                updated += 1
        return updated


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
    the in-memory backend's stable sort.

    ``cvss``/``severity`` order by the materialised ``cvss_score`` /
    ``severity_rank`` columns (not ``json_extract``) so the composite
    ``(tenant_id, origin, <col> DESC, ordinal)`` indexes back the sort with
    an ordered range scan instead of a temp-B-tree filesort (#3192).
    """
    if sort == "ordinal":
        return "ORDER BY ordinal ASC"
    if sort == "cvss":
        return "ORDER BY cvss_score DESC, ordinal ASC"
    if sort == "severity":
        return "ORDER BY severity_rank DESC, ordinal ASC"
    # effective_reach (default) — index-backed range scan + limit.
    return "ORDER BY effective_reach_score DESC, ordinal ASC"


def _sqlite_current_order_clause(sort: str) -> str:
    """ORDER BY for ``hub_findings_current`` (no ingest ``ordinal`` column)."""
    if sort == "ordinal":
        return "ORDER BY last_seen ASC, canonical_id ASC"
    if sort == "cvss":
        return "ORDER BY cvss_score DESC, last_seen DESC, canonical_id ASC"
    if sort == "severity":
        return "ORDER BY severity_rank DESC, last_seen DESC, canonical_id ASC"
    return "ORDER BY effective_reach_score DESC, last_seen DESC, canonical_id ASC"


def _postgres_current_order_clause(sort: str) -> str:
    """Postgres ORDER BY for ``hub_findings_current``."""
    return _sqlite_current_order_clause(sort)


def _current_page_sort_key(sort: str) -> Callable[[dict[str, Any]], tuple[float | str, str, str]]:
    """Sort key for in-memory current-state pages (descending primary signal)."""
    normalized = sort if sort in _LIST_PAGE_SORTS else "effective_reach"

    def _key(row: dict[str, Any]) -> tuple[float | str, str, str]:
        tie = str(row.get("last_seen") or "")
        canonical = str(row.get("canonical_id") or "")
        if normalized == "ordinal":
            return (tie, canonical, "")
        if normalized == "cvss":
            primary = float(row.get("cvss_score") or 0.0)
        elif normalized == "severity":
            primary = float(row.get("severity_rank") or 0)
        else:
            primary = float(row.get("effective_reach_score") or 0.0)
        return (-primary, tie, canonical)

    return _key


def _filter_current_rows(
    rows: list[dict[str, Any]],
    *,
    severity: str | None,
    scan_id: str | None,
    origin: str | None,
) -> list[dict[str, Any]]:
    if origin is not None:
        rows = [r for r in rows if (r.get("payload") or {}).get("origin") == origin]
    if severity is not None:
        sev = severity.lower()
        rows = [r for r in rows if str(r.get("severity") or (r.get("payload") or {}).get("severity", "")).lower() == sev]
    if scan_id is not None:
        rows = [
            r for r in rows if str((r.get("payload") or {}).get("batch_id") or (r.get("payload") or {}).get("scan_id") or "") == scan_id
        ]
    return rows


def _postgres_order_clause(sort: str) -> str:
    """ORDER BY clause for the Postgres backend, mirroring SQLite semantics.

    ``cvss``/``severity`` order by the materialised ``cvss_score`` /
    ``severity_rank`` columns backed by the composite
    ``(tenant_id, origin, <col> DESC, ordinal)`` indexes (#3192).
    """
    if sort == "ordinal":
        return "ORDER BY ordinal ASC"
    if sort == "cvss":
        return "ORDER BY cvss_score DESC, ordinal ASC"
    if sort == "severity":
        return "ORDER BY severity_rank DESC, ordinal ASC"
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
                severity TEXT NOT NULL DEFAULT '',
                severity_rank INTEGER NOT NULL DEFAULT 0,
                cvss_score REAL NOT NULL DEFAULT 0,
                PRIMARY KEY (tenant_id, finding_id)
            )
            """
        )
        self._migrate_columns()
        self._migrate_primary_key()
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_hub_findings_tenant_order ON compliance_hub_findings(tenant_id, ordinal)")
        self._ensure_scale_indexes()
        _ensure_current_lifecycle_sqlite(self._conn)
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
        # Materialise severity/cvss sort keys so the filtered severity/cvss
        # sorts ride a composite index instead of a json_extract filesort
        # (#3192). Backfill extracts from the stored payload for legacy rows.
        if "severity" not in cols:
            self._conn.execute("ALTER TABLE compliance_hub_findings ADD COLUMN severity TEXT NOT NULL DEFAULT ''")
            self._conn.execute(
                "UPDATE compliance_hub_findings SET severity = COALESCE(json_extract(payload, '$.severity'), '') WHERE severity = ''"
            )
        if "severity_rank" not in cols:
            self._conn.execute("ALTER TABLE compliance_hub_findings ADD COLUMN severity_rank INTEGER NOT NULL DEFAULT 0")
            self._conn.execute(
                "UPDATE compliance_hub_findings SET severity_rank = CASE "
                "LOWER(COALESCE(json_extract(payload, '$.severity'), '')) "
                "WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 "
                "ELSE 0 END WHERE severity_rank = 0"
            )
        if "cvss_score" not in cols:
            self._conn.execute("ALTER TABLE compliance_hub_findings ADD COLUMN cvss_score REAL NOT NULL DEFAULT 0")
            self._conn.execute(
                "UPDATE compliance_hub_findings SET cvss_score = "
                "CAST(COALESCE(json_extract(payload, '$.cvss_score'), 0) AS REAL) WHERE cvss_score = 0"
            )

    def _migrate_primary_key(self) -> None:
        """Collapse the primary key to ``(tenant_id, finding_id)`` (idempotent).

        Pre-idempotency tables keyed on ``(tenant_id, finding_id, ordinal)`` so
        every resend of the same finding minted a new row. SQLite cannot ALTER a
        primary key in place, so we rebuild: dedup existing duplicates keeping
        the lowest ordinal (the original ingest), then swap in the new-schema
        table. A no-op when the table already carries the collapsed key.
        """
        pk_cols = [row[1] for row in self._conn.execute("PRAGMA table_info(compliance_hub_findings)").fetchall() if row[5]]
        if "ordinal" not in pk_cols:
            return  # already migrated to (tenant_id, finding_id)

        self._conn.execute(
            """
            CREATE TABLE compliance_hub_findings_v2 (
                tenant_id TEXT NOT NULL,
                finding_id TEXT NOT NULL,
                ingested_at TEXT NOT NULL,
                source TEXT NOT NULL,
                applicable_frameworks_csv TEXT NOT NULL DEFAULT '',
                payload TEXT NOT NULL,
                ordinal INTEGER NOT NULL,
                effective_reach_score REAL NOT NULL DEFAULT 0,
                origin TEXT NOT NULL DEFAULT '',
                severity TEXT NOT NULL DEFAULT '',
                severity_rank INTEGER NOT NULL DEFAULT 0,
                cvss_score REAL NOT NULL DEFAULT 0,
                PRIMARY KEY (tenant_id, finding_id)
            )
            """
        )
        # Keep the lowest-ordinal row for each (tenant_id, finding_id) so the
        # rebuild is deterministic and preserves the original ingest order.
        self._conn.execute(
            """
            INSERT INTO compliance_hub_findings_v2
                (tenant_id, finding_id, ingested_at, source, applicable_frameworks_csv, payload,
                 ordinal, effective_reach_score, origin, severity, severity_rank, cvss_score)
            SELECT f.tenant_id, f.finding_id, f.ingested_at, f.source, f.applicable_frameworks_csv,
                   f.payload, f.ordinal, f.effective_reach_score, f.origin, f.severity, f.severity_rank, f.cvss_score
            FROM compliance_hub_findings f
            WHERE f.ordinal = (
                SELECT MIN(s.ordinal) FROM compliance_hub_findings s
                WHERE s.tenant_id = f.tenant_id AND s.finding_id = f.finding_id
            )
            """
        )
        self._conn.execute("DROP TABLE compliance_hub_findings")
        self._conn.execute("ALTER TABLE compliance_hub_findings_v2 RENAME TO compliance_hub_findings")

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
        # Back the filtered severity/cvss sorts with ordered composite indexes
        # so ORDER BY rides an index range scan (no temp B-tree filesort) — the
        # numeric severity_rank keeps critical>high>medium>low ordering (#3192).
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_hub_findings_tenant_origin_severity "
            "ON compliance_hub_findings(tenant_id, origin, severity_rank DESC, ordinal)"
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_hub_findings_tenant_origin_cvss "
            "ON compliance_hub_findings(tenant_id, origin, cvss_score DESC, ordinal)"
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_hub_findings_tenant_origin_severity_cvss "
            "ON compliance_hub_findings(tenant_id, origin, severity_rank, cvss_score DESC, ordinal)"
        )

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
                    str(payload.get("severity") or ""),
                    _severity_rank(payload),
                    _cvss_value(payload),
                )
            )
        # Idempotent ingest: a repeat of the same (tenant_id, finding_id)
        # refreshes the stored payload/metadata in place and keeps the original
        # ``ordinal`` (ingest order) instead of appending a duplicate row.
        self._conn.executemany(
            """
            INSERT INTO compliance_hub_findings
                (tenant_id, finding_id, ingested_at, source, applicable_frameworks_csv, payload,
                 ordinal, effective_reach_score, origin, severity, severity_rank, cvss_score)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(tenant_id, finding_id) DO UPDATE SET
                ingested_at = excluded.ingested_at,
                source = excluded.source,
                applicable_frameworks_csv = excluded.applicable_frameworks_csv,
                payload = excluded.payload,
                effective_reach_score = excluded.effective_reach_score,
                origin = excluded.origin,
                severity = excluded.severity,
                severity_rank = excluded.severity_rank,
                cvss_score = excluded.cvss_score
            """,
            rows,
        )
        self._conn.commit()
        if rows:
            from agent_bom.api.findings_count_cache import invalidate_tenant

            invalidate_tenant(tenant_id)
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
        include_total: bool = True,
    ) -> FindingPage:
        where = ["tenant_id = ?"]
        params: list[Any] = [tenant_id]
        if origin is not None:
            where.append("origin = ?")
            params.append(origin)
        if severity is not None:
            where.append("severity_rank = ?")
            params.append(severity_policy_rank(severity))
        if scan_id is not None:
            where.append("CAST(json_extract(payload, '$.scan_id') AS TEXT) = ?")
            params.append(scan_id)
        where_sql = " AND ".join(where)

        total: int | None
        if include_total:
            # ``where_sql`` is assembled only from fixed predicates above; all caller values
            # stay in ``params`` as sqlite bindings.
            total_row = self._conn.execute(
                f"SELECT COUNT(*) FROM compliance_hub_findings WHERE {where_sql}",  # nosec B608
                params,
            ).fetchone()
            total = int(total_row[0]) if total_row else 0
        else:
            total = None

        order_sql = _sqlite_order_clause(sort)
        page_params = [*params, int(limit), int(offset)]
        # ``order_sql`` comes from a closed sort allowlist; all caller values stay bound.
        rows = self._conn.execute(
            f"SELECT payload FROM compliance_hub_findings WHERE {where_sql} {order_sql} LIMIT ? OFFSET ?",  # nosec B608
            page_params,
        ).fetchall()
        return [json.loads(row[0]) for row in rows], total

    def severity_breakdown(self, tenant_id: str) -> dict[str, int]:
        rows = self._conn.execute(
            """
            SELECT LOWER(COALESCE(json_extract(payload, '$.severity'), 'unknown')) AS sev, COUNT(*)
            FROM compliance_hub_findings
            WHERE tenant_id = ?
            GROUP BY sev
            """,
            (tenant_id,),
        ).fetchall()
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}
        for sev, count in rows:
            key = str(sev or "unknown").lower()
            counts[key] = counts.get(key, 0) + int(count)
        return counts

    def framework_slug_counts(self, tenant_id: str) -> dict[str, int]:
        from agent_bom.compliance_coverage import normalize_framework_slug

        rows = self._conn.execute(
            "SELECT applicable_frameworks_csv FROM compliance_hub_findings WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchall()
        counts: dict[str, int] = {}
        for (csv_value,) in rows:
            if not csv_value:
                continue
            for slug in str(csv_value).split(","):
                slug = slug.strip()
                if not slug:
                    continue
                canonical = normalize_framework_slug(slug)
                counts[canonical] = counts.get(canonical, 0) + 1
        return counts

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
        self._conn.execute("DELETE FROM hub_findings_current WHERE tenant_id = ?", (tenant_id,))
        self._conn.execute("DELETE FROM hub_findings_current_observations WHERE tenant_id = ?", (tenant_id,))
        self._conn.commit()
        removed = cur.rowcount or 0
        if removed:
            from agent_bom.api.findings_count_cache import invalidate_tenant

            invalidate_tenant(tenant_id)
        return removed

    def upsert_current_batch(
        self,
        tenant_id: str,
        findings: Sequence[dict[str, Any]],
        *,
        observed_at: str,
        batch_id: str,
        source: str = "",
    ) -> None:
        clean = _redact_findings(findings)
        if not clean:
            return
        for payload in clean:
            _upsert_current_finding_sqlite(
                self._conn,
                tenant_id=tenant_id,
                payload=payload,
                observed_at=observed_at,
                scan_id=batch_id,
                source=source,
            )
        self._conn.commit()

    def get_current(self, tenant_id: str, canonical_id: str) -> dict[str, Any] | None:
        has_ledger_col = _hub_findings_current_has_ledger_col(self._conn)
        payload_select = "payload, ledger_finding_id" if has_ledger_col else "payload"
        row = self._conn.execute(
            f"""
            SELECT canonical_id, first_seen, last_seen, status, severity, severity_rank,
                   cvss_score, effective_reach_score, scan_count, resolved_at, reopened_at,
                   updated_at, {payload_select}
            FROM hub_findings_current
            WHERE tenant_id = ? AND canonical_id = ?
            """,  # nosec B608
            (tenant_id, canonical_id),
        ).fetchone()
        if row is None:
            return None
        current_row = _sqlite_current_row_from_db(row, has_ledger_col=has_ledger_col)
        return _hydrate_sqlite_current_rows(self._conn, tenant_id, [current_row])[0]

    def list_current_page(
        self,
        tenant_id: str,
        *,
        limit: int,
        offset: int = 0,
        sort: str = "effective_reach",
        severity: str | None = None,
        scan_id: str | None = None,
        origin: str | None = None,
        include_total: bool = True,
    ) -> FindingPage:
        from agent_bom.api.finding_lifecycle import enriched_finding_payload

        where = ["tenant_id = ?"]
        params: list[Any] = [tenant_id]
        if origin is not None:
            where.append("json_extract(payload, '$.origin') = ?")
            params.append(origin)
        if severity is not None:
            where.append("severity_rank = ?")
            params.append(severity_policy_rank(severity))
        if scan_id is not None:
            where.append("(CAST(json_extract(payload, '$.batch_id') AS TEXT) = ? OR CAST(json_extract(payload, '$.scan_id') AS TEXT) = ?)")
            params.extend([scan_id, scan_id])
        where_sql = " AND ".join(where)

        total: int | None
        if include_total:
            total_row = self._conn.execute(
                f"SELECT COUNT(*) FROM hub_findings_current WHERE {where_sql}",  # nosec B608
                params,
            ).fetchone()
            total = int(total_row[0]) if total_row else 0
        else:
            total = None

        order_sql = _sqlite_current_order_clause(sort)
        page_params = [*params, int(limit), int(offset)]
        has_ledger_col = _hub_findings_current_has_ledger_col(self._conn)
        payload_select = "payload, ledger_finding_id" if has_ledger_col else "payload"
        rows = self._conn.execute(
            f"""
            SELECT canonical_id, first_seen, last_seen, status, severity, severity_rank,
                   cvss_score, effective_reach_score, scan_count, resolved_at, reopened_at,
                   updated_at, {payload_select}
            FROM hub_findings_current
            WHERE {where_sql} {order_sql} LIMIT ? OFFSET ?
            """,  # nosec B608
            page_params,
        ).fetchall()
        current_rows = [_sqlite_current_row_from_db(row, has_ledger_col=has_ledger_col) for row in rows]
        hydrated_rows = _hydrate_sqlite_current_rows(self._conn, tenant_id, current_rows)
        out: list[dict[str, Any]] = []
        for current_row in hydrated_rows:
            out.append(enriched_finding_payload(current_row))
        return out, total

    def reconcile_current_absent(
        self,
        tenant_id: str,
        *,
        present_canonical_ids: set[str],
        observed_at: str,
        scope_source: str | None = None,
    ) -> int:
        now = _now_utc_iso()
        where = ["tenant_id = ?", "status IN ('open', 'reopened')"]
        params: list[Any] = [observed_at, now, tenant_id]
        if scope_source is not None:
            where.append("json_extract(payload, '$.source') = ?")
            params.append(scope_source)
        if present_canonical_ids:
            placeholders = ",".join("?" * len(present_canonical_ids))
            where.append(f"canonical_id NOT IN ({placeholders})")
            params.extend(sorted(present_canonical_ids))
        cur = self._conn.execute(
            f"""
            UPDATE hub_findings_current
            SET status = 'resolved', resolved_at = ?, updated_at = ?
            WHERE {" AND ".join(where)}
            """,  # nosec B608
            params,
        )
        self._conn.commit()
        return int(cur.rowcount or 0)


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
