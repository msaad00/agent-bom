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

import logging
import sqlite3
import threading
from collections.abc import Callable, Iterable, Mapping, Sequence
from typing import Any, Protocol

from agent_bom.api.finding_cursor import (
    cursor_from_current_row,
    cvss_sort_value,
    decode_finding_cursor,
    row_is_after_cursor,
    sqlite_keyset_clause,
)
from agent_bom.api.hub_current_payload import (
    batch_ledger_payloads,
    current_state_overlay,
    hydrate_current_payload,
    resolve_ledger_finding_id,
)
from agent_bom.api.hub_payload_codec import decode_hub_payload, encode_hub_payload
from agent_bom.api.hub_reference_store import (
    ensure_sqlite_reference_tables,
    hydrate_finding_payloads_memory,
    hydrate_finding_payloads_sqlite,
    normalize_finding_payload_for_store,
    persist_finding_references_sqlite,
)
from agent_bom.evidence import EvidenceTier, redact_for_persistence
from agent_bom.graph.severity import severity_policy_rank

_logger = logging.getLogger(__name__)

# Chunk size for reconcile UPDATE … IN (…) to stay under SQLite/Postgres bind limits.
RECONCILE_ABSENT_CHUNK = 500

# Row-count ceiling for the process-local InMemoryComplianceHubStore. Its paged
# read copies + re-sorts a tenant's entire row list on every request (O(n log n)
# per read, independent of page size) — fine for the demo/single-node backend it
# is scoped to, but it degrades on a large tenant. Above this ceiling we emit a
# one-time-per-tenant warning steering operators to a SQL backend (SQLite /
# Postgres), which sort in the query plan instead of in Python.
IN_MEMORY_SORT_CEILING = 50_000

# Defined here (module scope) so ``list`` resolves to the builtin: the store
# classes below define a ``list`` method that would otherwise shadow it in
# their ``list_page`` return annotations.
FindingPage = tuple[list[dict[str, Any]], int | None]
FindingCursorPage = tuple[list[dict[str, Any]], int | None, str | None]
_HubFindingRows = list[dict[str, Any]]
_CurrentPageSortKey = tuple[float | str, str | tuple[int, ...], str]

# Sort keys supported by ``list_page``. ``effective_reach`` (default),
# ``cvss`` and ``severity`` are each backed by a materialised column +
# composite ``(tenant_id, origin, <col> DESC, ordinal)`` index; ``ordinal``
# uses ingest order.
_LIST_PAGE_SORTS = ("effective_reach", "cvss", "severity", "ordinal")

# Private per-row slot on the in-memory store carrying the effective-reach
# composite materialised at ingest (mirrors the SQL ``effective_reach_score``
# column). The read-path sort trusts this scalar instead of re-deriving
# ``symbol_reachability_from_payload`` for every row on every request (#4049).
# Stripped from every returned payload so it never leaks into API output.
_REACH_SORT_KEY = "__reach_sort__"

# Bounds for the store-internal scope-filtered keyset batch fetch: never
# materialize the whole tenant table to serve a scoped page. A single batch of
# pre-enrichment current rows is hydrated at a time; the loop advances by keyset
# cursor until it has ``page_limit + 1`` matches or the stream is exhausted.
_SCOPE_FILTER_MIN_BATCH = 200
_SCOPE_FILTER_MAX_BATCH = 1000


def scope_filter_batch_size(page_limit: int) -> int:
    """Bounded batch size for the scope-filtered keyset scan (never the table)."""
    return min(_SCOPE_FILTER_MAX_BATCH, max(_SCOPE_FILTER_MIN_BATCH, int(page_limit) + 1))


# Lifecycle-status filter — a single source of truth shared by every read
# surface (list_current_page + current_severity_breakdown, all backends) and the
# route. ``status`` is a real, sargable column on ``hub_findings_current``
# (DEFAULT 'open'); the live posture is open OR reopened. The store-level param
# defaults to ``None`` (no predicate = all history) so existing callers are
# unchanged; the API route defaults the *user-facing* filter to ``open``.
_LIVE_STATUSES = ("open", "reopened")
STATUS_FILTERS = ("open", "resolved", "all")


def normalize_status_filter(status: str | None) -> str | None:
    """Canonicalize a lifecycle-status filter.

    ``None`` -> ``None`` (no predicate; legacy all-history behavior). ``open`` /
    ``resolved`` / ``all`` pass through. An unrecognized value collapses to
    ``None`` (never silently HIDES rows — the route validates + 422s the user).
    """
    if status is None:
        return None
    key = status.strip().lower()
    return key if key in STATUS_FILTERS else None


def status_sql_predicate(status: str | None, placeholder: str = "?") -> tuple[str, list[Any]]:
    """SQL fragment + params for the lifecycle-status filter over ``status``.

    ``open`` (live posture) -> ``status IN (open, reopened)``; ``resolved`` ->
    ``status = resolved``; ``None`` / ``all`` -> no predicate. Rides the
    ``status`` column (and the open partial index for the default sort/COUNT), so
    it stays sargable — no filesort.
    """
    normalized = normalize_status_filter(status)
    if normalized == "open":
        return f"status IN ({placeholder}, {placeholder})", ["open", "reopened"]
    if normalized == "resolved":
        return f"status = {placeholder}", ["resolved"]
    return "", []


def status_matches(row: Mapping[str, Any], status: str | None) -> bool:
    """In-memory mirror of :func:`status_sql_predicate`.

    A row with no explicit lifecycle status is treated as ``open`` — scan
    findings (no reconcile lifecycle) are live by construction, so the default
    and ``all`` include them and ``resolved`` excludes them.
    """
    normalized = normalize_status_filter(status)
    if normalized is None or normalized == "all":
        return True
    payload = row.get("payload") if isinstance(row.get("payload"), Mapping) else {}
    row_status = str(row.get("status") or (payload or {}).get("status") or "open").strip().lower() or "open"
    if normalized == "open":
        return row_status in _LIVE_STATUSES
    return row_status == "resolved"


def collect_scope_filtered_page(
    fetch_batch: Callable[[str | None, int], tuple[list[tuple[dict[str, Any], dict[str, Any]]], str | None]],
    *,
    predicate: Callable[[dict[str, Any]], bool],
    page_limit: int,
    start_cursor: str | None,
    sort: str,
    batch_size: int,
) -> tuple[list[dict[str, Any]], str | None]:
    """Collect one scope-filtered keyset page without materializing the table.

    ``fetch_batch(cursor, limit)`` returns ``(items, batch_next_cursor)`` where
    ``items`` is a list of ``(current_row, enriched_payload)`` pairs in keyset
    order after ``cursor``; ``current_row`` carries the sort fields
    (effective_reach_score / cvss_score / severity_rank / ledger_ordinal +
    last_seen / first_seen / canonical_id) and ``enriched_payload`` is what the
    route sees. ``batch_next_cursor`` is ``None`` when the underlying stream is
    exhausted.

    The loop applies ``predicate`` to each ``enriched_payload``, collecting
    matches until it holds ``page_limit + 1`` (enough to know a further page
    exists) or the stream ends. ``next_cursor`` is derived from the LAST EMITTED
    match's ``current_row`` — never a discarded probe row — so the next page
    resumes strictly after it: 0 duplicates, 0 dropped rows across pages, and the
    filtered order matches the unfiltered keyset order restricted to the matching
    subset. Returns ``(enriched_payloads[:page_limit], next_cursor)``.
    """
    page_limit = max(0, int(page_limit))
    if page_limit == 0:
        return [], None
    matches: list[tuple[dict[str, Any], dict[str, Any]]] = []
    batch_cursor = start_cursor
    while len(matches) <= page_limit:
        items, batch_next = fetch_batch(batch_cursor, batch_size)
        for current_row, enriched in items:
            if predicate(enriched):
                matches.append((current_row, enriched))
                if len(matches) > page_limit:
                    break
        if len(matches) > page_limit or batch_next is None:
            break
        batch_cursor = batch_next
    has_more = len(matches) > page_limit
    emitted = matches[:page_limit]
    payloads = [enriched for (_current, enriched) in emitted]
    next_cursor = None
    if has_more and emitted:
        next_cursor = cursor_from_current_row(emitted[-1][0], sort=sort)
    return payloads, next_cursor


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
    from agent_bom.symbol_reach_triage import apply_composite_delta, symbol_reachability_from_payload

    reach = payload.get("effective_reach_score")
    if reach is None:
        breakdown = payload.get("effective_reach") or {}
        if isinstance(breakdown, dict):
            reach = breakdown.get("composite")
    try:
        base = float(reach or 0.0)
    except (TypeError, ValueError):
        base = 0.0
    sym = symbol_reachability_from_payload(payload)
    breakdown = payload.get("effective_reach") or {}
    if isinstance(breakdown, dict) and breakdown.get("symbol_reach_adjustment") is not None:
        return base
    return apply_composite_delta(base, sym)


def _page_signal(row: dict[str, Any], sort: str) -> float:
    """Return the single descending sort signal for ``list_page``."""
    if sort == "cvss":
        return _cvss_value(row)
    if sort == "severity":
        return float(_severity_rank(row))
    # effective_reach (default): trust the composite materialised at ingest
    # (``_REACH_SORT_KEY``) instead of re-deriving it per row on the read path.
    # Fall back to deriving it for any row that predates materialisation (#4049).
    cached = row.get(_REACH_SORT_KEY)
    if cached is not None:
        try:
            return float(cached)
        except (TypeError, ValueError):
            pass
    return compute_effective_reach_score(row)


def _page_sort_key(sort: str) -> Callable[[dict[str, Any]], float]:
    """Return a Python sort key mirroring the SQL ordering of ``list_page``.

    Descending on the requested signal only. Python's stable sort preserves
    ingest order for ties, which matches the SQL ``ORDER BY <signal> DESC,
    ordinal ASC`` tiebreak used by the persistent backends.
    """
    normalized = sort if sort in _LIST_PAGE_SORTS else "effective_reach"
    return lambda row: -_page_signal(row, normalized)


def _strip_reach_sort(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Drop the private ingest-materialised reach scalar from returned payloads.

    ``hydrate_finding_payloads_memory`` returns fresh dict copies, so popping
    here never mutates the stored bucket — it just keeps ``_REACH_SORT_KEY`` an
    internal sort scalar and out of the API response (#4049).
    """
    for row in rows:
        row.pop(_REACH_SORT_KEY, None)
    return rows


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


def _severity_breakdown_from_current_rows(rows: Iterable[dict[str, Any]]) -> dict[str, int]:
    """Per-severity counts over current-state rows.

    Resolves severity the same way :func:`_filter_current_rows` does (top-level
    column first, then ``payload``) so the buckets match ``list_current_page``'s
    ``severity=`` COUNT exactly.
    """
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}
    for row in rows:
        sev = str(row.get("severity") or (row.get("payload") or {}).get("severity") or "unknown").lower()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _payload_is_kev(payload: Mapping[str, Any] | None) -> bool:
    """Return True when a finding payload carries a CISA-KEV flag.

    The hub normalises ``cisa_kev`` to ``is_kev`` on store, but accept either so
    a freshly-ingested or hydrated payload both resolve — matching what the
    /v1/findings drill shows per row."""
    if not payload:
        return False
    return bool(payload.get("is_kev") or payload.get("cisa_kev"))


def _kev_json_cond_sqlite(col: str) -> str:
    """SQLite predicate: the KEV flag on a JSON column (bool ``true`` or string)."""
    return (
        f"json_extract({col}, '$.is_kev') IN (1, 'true', 'True', '1') "
        f"OR json_extract({col}, '$.cisa_kev') IN (1, 'true', 'True', '1')"
    )


def _current_kev_count_from_rows(rows: Iterable[dict[str, Any]]) -> int:
    """Count current-state rows whose (hydrated) payload is CISA-KEV flagged."""
    return sum(1 for row in rows if _payload_is_kev(row.get("payload")))


def _framework_slug_counts_from_rows(rows: Iterable[dict[str, Any]]) -> dict[str, int]:
    from agent_bom.compliance_coverage import normalize_framework_slug

    counts: dict[str, int] = {}
    for row in rows:
        for slug in row.get("applicable_frameworks") or []:
            canonical = normalize_framework_slug(str(slug))
            counts[canonical] = counts.get(canonical, 0) + 1
    return counts


def _redact_finding(payload: dict[str, Any]) -> dict[str, Any]:
    """Redact one hub finding payload for persistence."""
    redacted = redact_for_persistence(payload, EvidenceTier.SAFE_TO_STORE)
    clean: dict[str, Any] = redacted if isinstance(redacted, dict) else {}
    if "id" not in clean and "id" in payload:
        clean["id"] = str(payload["id"])
    if "source" not in clean and "source" in payload:
        clean["source"] = str(payload["source"])
    for key in ("origin", "batch_id", "bulk_ordinal", "intel_ref", "framework_ref"):
        if key not in clean and key in payload:
            clean[key] = payload[key]
    return clean


def _redact_findings(findings: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Drop tier-B fields before any compliance-hub finding is stored.

    The hub is a tier-A sink — findings are exported, queried by auditors,
    and held indefinitely. See issue #2261.
    """
    redacted: list[dict[str, Any]] = []
    for payload in findings:
        if not isinstance(payload, dict):
            continue
        redacted.append(_redact_finding(payload))
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

    def current_severity_breakdown(
        self,
        tenant_id: str,
        *,
        origin: str | None = None,
        since: str | None = None,
        status: str | None = None,
    ) -> dict[str, int]:
        """Per-severity counts over CURRENT-STATE rows matching the drill-down.

        Mirrors :meth:`list_current_page`'s COUNT filters (tenant + ``origin``
        + ``since`` read-window + lifecycle ``status``) so the exec headline
        reconciles EXACTLY with ``/v1/findings`` — a click-through can never
        disagree with the headline. ``status`` (``open`` = live posture,
        open+reopened / ``resolved`` / ``all``; ``None`` = all history) keeps
        resolved findings out of the exec headline by default. Unlike
        :meth:`severity_breakdown` (which scans the append-only ledger, all-origin
        and unbounded), this reads ``hub_findings_current`` so retired / aged
        findings that linger in the ledger never inflate the exec numbers. An
        indexed ``GROUP BY`` — no payload hydration.
        """
        ...

    def current_kev_count(
        self,
        tenant_id: str,
        *,
        origin: str | None = None,
        since: str | None = None,
    ) -> int:
        """Count CURRENT-STATE findings flagged CISA-KEV, matching the drill.

        Same tenant + ``origin`` + ``since`` read-window predicates as
        :meth:`current_severity_breakdown`, so the exec KEV headline reconciles
        with the KEV rows /v1/findings shows. The KEV flag lives in the finding
        payload (inline, or in the CVE-intel reference for CVE findings), so the
        SQL backends resolve it from the current row, the ledger payload, and the
        intel reference — never scan-lane only.
        """
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
        cursor: str | None = None,
        since: str | None = None,
        scope: Mapping[str, str] | None = None,
        status: str | None = None,
    ) -> FindingCursorPage:
        """Return a page from ``hub_findings_current`` with lifecycle fields merged.

        ``since`` (ISO-8601 cutoff) bounds the page to findings whose
        ``last_seen`` is within the read window; ``None`` returns all history.

        ``status`` filters the sargable lifecycle column (``open`` = live posture
        open+reopened / ``resolved`` / ``all``; ``None`` = no predicate). It rides
        the ``status`` column (+ open partial index) and applies in BOTH the fast
        keyset path and the scoped batched path.

        ``scope`` (keys ``provider`` / ``account_ref`` / ``environment`` /
        ``domain``, already canonicalized/lowercased by the caller) applies the
        overlapping-lens scope predicate INSIDE the store on pre-enrichment
        current rows, batched + keyset-paged so a scoped page never materializes
        the whole tenant. When ``scope`` is set the exact O(table) ``COUNT(*)`` is
        skipped and ``total`` is ``None`` (the route flags it approximate); when
        ``scope`` is falsy behavior is unchanged.
        """
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
    if not rows:
        return {}
    ordered_ids = [str(row[0]) for row in rows]
    payloads = [decode_hub_payload(row[1]) for row in rows]
    hydrated = hydrate_finding_payloads_sqlite(conn, tenant_id, payloads)
    return dict(zip(ordered_ids, hydrated))


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
        "payload": decode_hub_payload(row[12]),
    }
    if has_ledger_col:
        current_row["ledger_finding_id"] = row[13]
        if len(row) > 14:
            current_row["ledger_ordinal"] = int(row[14])
    return current_row


def _upsert_current_finding_sqlite(
    conn: sqlite3.Connection,
    *,
    tenant_id: str,
    payload: dict[str, Any],
    observed_at: str,
    scan_id: str,
    source: str,
    has_ledger_col: bool | None = None,
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
    payload_json = encode_hub_payload(overlay)
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

    if has_ledger_col is None:
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
    origin_val = str(payload.get("origin") or "")
    # Materialise the scan filter key: batch_id first, scan_id fallback — the
    # canonical ``batch_id or scan_id`` the in-memory filter compares against so
    # every backend agrees and the read rides the (tenant_id, scan_id) index.
    scan_id_val = str(payload.get("batch_id") or payload.get("scan_id") or "")
    if has_ledger_col:
        # Materialise the ledger ingest ordinal so ``sort=ordinal`` reads an
        # index range scan instead of a per-row correlated subquery (#3984).
        ledger_ordinal_val = resolve_current_ledger_ordinal_sqlite(conn, tenant_id, ledger_finding_id or "")
        conn.execute(
            """
            INSERT INTO hub_findings_current
                (tenant_id, canonical_id, first_seen, last_seen, status, severity, severity_rank,
                 cvss_score, effective_reach_score, scan_count, resolved_at, reopened_at,
                 updated_at, payload, ledger_finding_id, origin, scan_id, ledger_ordinal)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                ledger_finding_id = excluded.ledger_finding_id,
                origin = excluded.origin,
                scan_id = excluded.scan_id,
                ledger_ordinal = excluded.ledger_ordinal
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
                origin_val,
                scan_id_val,
                ledger_ordinal_val,
            ),
        )
    else:
        conn.execute(
            """
            INSERT INTO hub_findings_current
                (tenant_id, canonical_id, first_seen, last_seen, status, severity, severity_rank,
                 cvss_score, effective_reach_score, scan_count, resolved_at, reopened_at,
                 updated_at, payload, origin, scan_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                origin = excluded.origin,
                scan_id = excluded.scan_id
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
                origin_val,
                scan_id_val,
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


def _migrate_current_ledger_ordinal_sqlite(conn: sqlite3.Connection) -> None:
    """Materialise the ledger ingest ``ordinal`` onto ``hub_findings_current``.

    ``sort=ordinal`` used to resolve ingest order with a per-row correlated
    subquery against the ledger (full scan + filesort at scale, #3984). This
    promotes it to a stored column so the sort rides
    ``idx_hub_findings_current_tenant_ordinal`` as an ordered range scan.

    The guarded ALTER seeds every pre-existing row with the sort sentinel
    (``MAX(bigint)``), then the one-shot backfill resolves the real ordinal for
    rows that carry a ledger pointer — matching the old
    ``COALESCE(subquery, 9223372036854775807)`` value exactly. Idempotent: the
    ALTER+backfill only run while the column is absent, and empty tables update
    zero rows. Requires ``ledger_finding_id`` to already exist.
    """
    cols = {row[1] for row in conn.execute("PRAGMA table_info(hub_findings_current)").fetchall()}
    if "ledger_ordinal" not in cols:
        conn.execute(f"ALTER TABLE hub_findings_current ADD COLUMN ledger_ordinal INTEGER NOT NULL DEFAULT {_LEDGER_ORDINAL_SENTINEL}")
        conn.execute(
            """
            UPDATE hub_findings_current SET ledger_ordinal = COALESCE(
                (
                    SELECT f.ordinal
                    FROM compliance_hub_findings f
                    WHERE f.tenant_id = hub_findings_current.tenant_id
                      AND f.finding_id = hub_findings_current.ledger_finding_id
                    LIMIT 1
                ),
                ?
            )
            WHERE ledger_finding_id IS NOT NULL AND ledger_finding_id != ''
            """,
            (_LEDGER_ORDINAL_SENTINEL,),
        )


def _migrate_current_origin_col_sqlite(conn: sqlite3.Connection) -> None:
    """Promote ``origin`` to a real indexed column on ``hub_findings_current``.

    Filtering ``origin`` via ``json_extract(payload, '$.origin')`` forces a
    full-table scan on the exact ``COUNT(*)`` (#3641). Backfilling a materialised
    column from the stored overlay lets the count ride the
    ``(tenant_id, origin, …)`` index prefix. Idempotent: the guarded ALTER only
    runs once and the backfill only touches empty ``origin`` cells.
    """
    cols = {row[1] for row in conn.execute("PRAGMA table_info(hub_findings_current)").fetchall()}
    if "origin" not in cols:
        conn.execute("ALTER TABLE hub_findings_current ADD COLUMN origin TEXT NOT NULL DEFAULT ''")
        conn.execute("UPDATE hub_findings_current SET origin = COALESCE(json_extract(payload, '$.origin'), '') WHERE origin = ''")


def _migrate_current_scan_id_col_sqlite(conn: sqlite3.Connection) -> None:
    """Promote ``scan_id`` to a real indexed column on ``hub_findings_current``.

    The default ``/v1/findings`` (current-state) reach read filtered ``scan_id``
    via ``json_extract(payload, '$.batch_id'/'$.scan_id')`` per row — a full-table
    scan of the tenant, paid twice (COUNT + page). This mirrors the ledger fix
    (#3641/#3913): backfill a materialised column so the filter rides an index.

    The materialised value matches the canonical in-memory filter
    (``batch_id or scan_id``): ``batch_id`` takes precedence and ``scan_id`` is
    the fallback, so pre-migration rows resolve to the exact same key the old
    per-row json_extract compared against. Idempotent: the guarded ALTER runs
    once and the backfill only touches empty cells.
    """
    cols = {row[1] for row in conn.execute("PRAGMA table_info(hub_findings_current)").fetchall()}
    if "scan_id" not in cols:
        conn.execute("ALTER TABLE hub_findings_current ADD COLUMN scan_id TEXT NOT NULL DEFAULT ''")
        conn.execute(
            "UPDATE hub_findings_current SET scan_id = "
            "COALESCE(NULLIF(json_extract(payload, '$.batch_id'), ''), json_extract(payload, '$.scan_id'), '') "
            "WHERE scan_id = ''"
        )


def _ensure_current_scale_indexes_sqlite(conn: sqlite3.Connection) -> None:
    """Partial indexes backing the current-state scan_id + severity filters.

    Both are ``WHERE <col> != ''`` partial indexes: the common rows (no scan_id,
    or an empty severity) stay OUT of the index so an all-empty
    ``(tenant_id, col)`` index cannot shadow the default reach read as a
    perfect tenant-equality candidate and force a filesort. Real filters always
    query a non-empty value, so the partial index still serves them (mirrors the
    ledger treatment in ``_ensure_scale_indexes``).
    """
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_hub_findings_current_tenant_scan ON hub_findings_current(tenant_id, scan_id) WHERE scan_id != ''"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_hub_findings_current_tenant_severity_ci "
        "ON hub_findings_current(tenant_id, LOWER(severity)) WHERE severity != ''"
    )


def _ensure_current_lifecycle_sqlite(conn: sqlite3.Connection) -> None:
    from agent_bom.api.finding_lifecycle import (
        _CURRENT_LIFECYCLE_SORT_INDEXES_SQLITE,
        _CURRENT_LIFECYCLE_SQLITE_DDL,
    )

    conn.executescript(_CURRENT_LIFECYCLE_SQLITE_DDL)
    # Backfill the origin column before the sort indexes so the composite
    # ``(tenant_id, origin, cvss_score DESC, …)`` index can build on pre-existing
    # tables that predate the column.
    _migrate_current_origin_col_sqlite(conn)
    # Materialise scan_id before its index so the partial index can build on
    # tables that predate the column (the default /v1/findings scan filter).
    _migrate_current_scan_id_col_sqlite(conn)
    # Materialise the ledger pointer + its ingest ordinal before the sort
    # indexes so the ``(tenant_id, ledger_ordinal, …)`` index can build on
    # pre-existing tables that predate those columns (#3984).
    _migrate_current_ledger_ref_sqlite(conn)
    _migrate_current_ledger_ordinal_sqlite(conn)
    conn.executescript(_CURRENT_LIFECYCLE_SORT_INDEXES_SQLITE)
    _ensure_current_scale_indexes_sqlite(conn)
    _migrate_lifecycle_observations_l2_sqlite(conn)
    conn.execute("UPDATE hub_findings_current SET cvss_score = 0 WHERE cvss_score IS NULL")


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
    """Process-local store. Ephemeral; tests + single-node demos only.

    Scale ceiling: reads copy + re-sort a tenant's whole row list per request
    (see ``IN_MEMORY_SORT_CEILING``). This backend is intentionally the demo /
    single-node path; production deployments use the SQLite or Postgres backend,
    which sort in the query plan. A tenant that grows past the ceiling logs a
    one-time warning rather than silently degrading.
    """

    def __init__(self) -> None:
        self._by_tenant: dict[str, list[dict[str, Any]]] = {}
        # Tenants already warned about crossing IN_MEMORY_SORT_CEILING, so the
        # guard logs once per tenant instead of on every paged read.
        self._sort_ceiling_warned: set[str] = set()
        # Maps finding_id -> ingest-order slot so a resend of the same
        # (tenant_id, finding_id) refreshes its row in place instead of
        # appending a duplicate (idempotent ingest, mirrors the SQL backends).
        self._slots: dict[str, dict[str, int]] = {}
        self._current: dict[str, dict[str, dict[str, Any]]] = {}
        self._current_observations: dict[str, set[tuple[str, str]]] = {}
        self._lock = threading.Lock()

    def _invalidate_ingest_caches(self, tenant_id: str) -> None:
        from agent_bom.api import hub_overview_cache
        from agent_bom.api.findings_count_cache import invalidate_tenant

        invalidate_tenant(tenant_id)
        hub_overview_cache.invalidate_tenant(tenant_id)

    def _add_locked(self, tenant_id: str, findings: list[dict[str, Any]]) -> int:
        """Append the batch to the ledger. Caller MUST hold ``self._lock``."""
        bucket = self._by_tenant.setdefault(tenant_id, [])
        slots = self._slots.setdefault(tenant_id, {})
        for payload in findings:
            if not isinstance(payload, dict):
                continue
            slim = normalize_finding_payload_for_store(tenant_id, payload)
            stored = _redact_finding(slim)
            # Materialise the effective-reach composite once at ingest so the
            # read-path sort never re-derives it per row (#4049). Mirrors the
            # SQL backends materialising the ``effective_reach_score`` column.
            stored[_REACH_SORT_KEY] = compute_effective_reach_score(stored)
            finding_id = str(stored.get("id") or "")
            if finding_id and finding_id in slots:
                # Refresh payload, keep original ingest position.
                bucket[slots[finding_id]] = stored
                continue
            if finding_id:
                slots[finding_id] = len(bucket)
            bucket.append(stored)
        return len(bucket)

    def add(self, tenant_id: str, findings: list[dict[str, Any]]) -> int:
        with self._lock:
            total = self._add_locked(tenant_id, findings)
        if findings:
            self._invalidate_ingest_caches(tenant_id)
        return total

    def ingest_batch_atomic(
        self,
        tenant_id: str,
        findings: list[dict[str, Any]],
        *,
        observed_at: str,
        batch_id: str,
        source: str,
        reconcile_absent: bool,
        present_canonical_ids: set[str],
    ) -> tuple[int, int]:
        """Ledger append + current upsert (+ reconcile) as one atomic unit.

        The three writes ran as separate lock acquisitions, so a failure between
        them left the ledger appended while current-state stayed behind. Here all
        three run under a single lock; on failure the pre-batch snapshot is
        restored so nothing is partially applied. Mirrors the SQL backends'
        single-transaction seam. Returns ``(new_total, reconciled)``.
        """
        clean = _redact_findings(findings)
        with self._lock:
            snap_bucket = list(self._by_tenant.get(tenant_id, []))
            snap_slots = dict(self._slots.get(tenant_id, {}))
            snap_current = {k: dict(v) for k, v in self._current.get(tenant_id, {}).items()}
            snap_obs = set(self._current_observations.get(tenant_id, set()))
            try:
                total = self._add_locked(tenant_id, findings)
                self._upsert_current_locked(
                    tenant_id,
                    clean,
                    observed_at=observed_at,
                    batch_id=batch_id,
                    source=source,
                )
                reconciled = 0
                if reconcile_absent:
                    reconciled = self._reconcile_locked(
                        tenant_id,
                        present_canonical_ids=present_canonical_ids,
                        observed_at=observed_at,
                        scope_source=source,
                    )
            except Exception:
                self._by_tenant[tenant_id] = snap_bucket
                self._slots[tenant_id] = snap_slots
                self._current[tenant_id] = snap_current
                self._current_observations[tenant_id] = snap_obs
                raise
        if findings or reconcile_absent:
            self._invalidate_ingest_caches(tenant_id)
        return total, reconciled

    def list(self, tenant_id: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = list(self._by_tenant.get(tenant_id, []))
        return _strip_reach_sort(hydrate_finding_payloads_memory(tenant_id, rows))

    def _guard_sort_ceiling(self, tenant_id: str, row_count: int) -> None:
        """Warn once per tenant when the whole-tenant re-sort ceiling is crossed.

        The in-memory backend re-sorts a tenant's entire row list on every paged
        read. Past ``IN_MEMORY_SORT_CEILING`` that is a real per-request cost;
        surface it (once per tenant) instead of degrading silently — a SQL
        backend sorts in the query plan and should be used at that scale.
        """
        if row_count <= IN_MEMORY_SORT_CEILING or tenant_id in self._sort_ceiling_warned:
            return
        self._sort_ceiling_warned.add(tenant_id)
        _logger.warning(
            "InMemoryComplianceHubStore is sorting %d rows per read (ceiling %d); "
            "this demo/single-node backend re-sorts the whole tenant per request — "
            "use the SQLite or Postgres backend at this scale.",
            row_count,
            IN_MEMORY_SORT_CEILING,
        )

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
        self._guard_sort_ceiling(tenant_id, len(rows))
        rows = _filter_hub_rows(rows, severity=severity, scan_id=scan_id, origin=origin)
        total = len(rows) if include_total else None
        if sort != "ordinal":
            rows.sort(key=_page_sort_key(sort))
        if offset:
            rows = rows[offset:]
        if limit >= 0:
            rows = rows[:limit]
        return _strip_reach_sort(hydrate_finding_payloads_memory(tenant_id, rows)), total

    def severity_breakdown(self, tenant_id: str) -> dict[str, int]:
        with self._lock:
            rows = list(self._by_tenant.get(tenant_id, []))
        return _severity_breakdown_from_rows(rows)

    def current_severity_breakdown(
        self,
        tenant_id: str,
        *,
        origin: str | None = None,
        since: str | None = None,
        status: str | None = None,
    ) -> dict[str, int]:
        with self._lock:
            rows = list(self._current.get(tenant_id, {}).values())
        rows = _filter_current_rows(rows, severity=None, scan_id=None, origin=origin, since=since, status=status)
        return _severity_breakdown_from_current_rows(rows)

    def current_kev_count(
        self,
        tenant_id: str,
        *,
        origin: str | None = None,
        since: str | None = None,
    ) -> int:
        with self._lock:
            rows = [dict(r) for r in self._current.get(tenant_id, {}).values()]
        rows = _filter_current_rows(rows, severity=None, scan_id=None, origin=origin, since=since)
        # Current-state rows keep an overlay-only payload; the KEV flag lives in
        # the ledger payload, so hydrate first (same source the drill reads).
        rows = self._hydrate_current_rows(tenant_id, rows)
        return _current_kev_count_from_rows(rows)

    def framework_slug_counts(self, tenant_id: str) -> dict[str, int]:
        with self._lock:
            rows = list(self._by_tenant.get(tenant_id, []))
        rows = hydrate_finding_payloads_memory(tenant_id, rows)
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
            from agent_bom.api import hub_overview_cache
            from agent_bom.api.findings_count_cache import invalidate_tenant

            invalidate_tenant(tenant_id)
            hub_overview_cache.invalidate_tenant(tenant_id)
        return removed

    def _upsert_current_locked(
        self,
        tenant_id: str,
        clean: Sequence[dict[str, Any]],
        *,
        observed_at: str,
        batch_id: str,
        source: str = "",
    ) -> None:
        """Upsert current-state for a redacted batch. Caller MUST hold the lock."""
        from agent_bom.api.finding_lifecycle import (
            apply_observation_to_current,
            lifecycle_metrics,
            resolve_canonical_id,
        )

        now = _now_utc_iso()
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
                merged["ledger_ordinal"] = self._slots.get(tenant_id, {}).get(finding_id, _LEDGER_ORDINAL_SENTINEL)
            else:
                merged["ledger_ordinal"] = _LEDGER_ORDINAL_SENTINEL
            current[canonical] = merged

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
        with self._lock:
            self._upsert_current_locked(
                tenant_id,
                clean,
                observed_at=observed_at,
                batch_id=batch_id,
                source=source,
            )

    def _ledger_payload_map(self, tenant_id: str, finding_ids: Sequence[str]) -> dict[str, dict[str, Any]]:
        slots = self._slots.get(tenant_id, {})
        bucket = self._by_tenant.get(tenant_id, [])
        out: dict[str, dict[str, Any]] = {}
        for finding_id in finding_ids:
            idx = slots.get(finding_id)
            if idx is not None and 0 <= idx < len(bucket):
                out[finding_id] = hydrate_finding_payloads_memory(tenant_id, [bucket[idx]])[0]
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
        cursor: str | None = None,
        since: str | None = None,
        scope: Mapping[str, str] | None = None,
        status: str | None = None,
    ) -> FindingCursorPage:
        from agent_bom.api.finding_lifecycle import enriched_finding_payload

        normalized_sort = sort if sort in _LIST_PAGE_SORTS else "effective_reach"
        if scope:
            return self._list_current_page_scoped(
                tenant_id,
                limit=limit,
                sort=normalized_sort,
                severity=severity,
                scan_id=scan_id,
                origin=origin,
                cursor=cursor,
                since=since,
                scope=scope,
                status=status,
            )
        with self._lock:
            rows = list(self._current.get(tenant_id, {}).values())
        rows = _filter_current_rows(rows, severity=severity, scan_id=scan_id, origin=origin, since=since, status=status)
        total = len(rows) if include_total else None
        rows.sort(key=_current_page_sort_key(normalized_sort))
        if cursor:
            primary, last_seen, canonical_id = decode_finding_cursor(cursor, expected_sort=normalized_sort)
            rows = [
                row
                for row in rows
                if row_is_after_cursor(
                    row,
                    sort=normalized_sort,
                    primary=primary,
                    last_seen=last_seen,
                    canonical_id=canonical_id,
                )
            ]
        elif offset:
            rows = rows[offset:]
        page_limit = max(0, int(limit))
        fetch_limit = page_limit + 1 if page_limit >= 0 else page_limit
        if page_limit >= 0:
            chunk = rows[:fetch_limit]
            has_more = len(chunk) > page_limit
            rows = chunk[:page_limit]
        else:
            has_more = False
        rows = self._hydrate_current_rows(tenant_id, [dict(row) for row in rows])
        enriched = [enriched_finding_payload(row) for row in rows]
        next_cursor = None
        if has_more and rows:
            next_cursor = cursor_from_current_row(rows[-1], sort=normalized_sort)
        return enriched, total, next_cursor

    def _list_current_page_scoped(
        self,
        tenant_id: str,
        *,
        limit: int,
        sort: str,
        severity: str | None,
        scan_id: str | None,
        origin: str | None,
        cursor: str | None,
        since: str | None,
        scope: Mapping[str, str],
        status: str | None = None,
    ) -> FindingCursorPage:
        from agent_bom.api.finding_lifecycle import enriched_finding_payload
        from agent_bom.finding_scope import row_matches_scope

        # The process-local store is already fully materialized; a single batch
        # (the whole filtered+sorted stream after the cursor) feeds the shared
        # keyset collector, so scope semantics and next_cursor emission match the
        # SQL backends exactly. total is None under a scope filter (approximate).
        def fetch_batch(batch_cursor: str | None, _batch_limit: int) -> tuple[list[tuple[dict[str, Any], dict[str, Any]]], str | None]:
            with self._lock:
                rows = list(self._current.get(tenant_id, {}).values())
            rows = _filter_current_rows(rows, severity=severity, scan_id=scan_id, origin=origin, since=since, status=status)
            rows.sort(key=_current_page_sort_key(sort))
            if batch_cursor:
                primary, last_seen, canonical_id = decode_finding_cursor(batch_cursor, expected_sort=sort)
                rows = [
                    row
                    for row in rows
                    if row_is_after_cursor(row, sort=sort, primary=primary, last_seen=last_seen, canonical_id=canonical_id)
                ]
            hydrated = self._hydrate_current_rows(tenant_id, [dict(row) for row in rows])
            pairs = [(row, enriched_finding_payload(row)) for row in hydrated]
            return pairs, None

        page_limit = max(0, int(limit))
        payloads, next_cursor = collect_scope_filtered_page(
            fetch_batch,
            predicate=lambda payload: row_matches_scope(payload, scope),
            page_limit=page_limit,
            start_cursor=cursor,
            sort=sort,
            batch_size=scope_filter_batch_size(page_limit),
        )
        return payloads, None, next_cursor

    def _reconcile_locked(
        self,
        tenant_id: str,
        *,
        present_canonical_ids: set[str],
        observed_at: str,
        scope_source: str | None = None,
    ) -> int:
        """Resolve absent open findings. Caller MUST hold ``self._lock``."""
        now = _now_utc_iso()
        updated = 0
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

    def reconcile_current_absent(
        self,
        tenant_id: str,
        *,
        present_canonical_ids: set[str],
        observed_at: str,
        scope_source: str | None = None,
    ) -> int:
        with self._lock:
            return self._reconcile_locked(
                tenant_id,
                present_canonical_ids=present_canonical_ids,
                observed_at=observed_at,
                scope_source=scope_source,
            )


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


# Rows in ``hub_findings_current`` with no resolvable ledger ``ordinal`` sort
# last under ``sort=ordinal``. ``9223372036854775807`` is ``MAX(int64)`` /
# ``MAX(bigint)`` — the same sentinel the pre-materialisation ``COALESCE`` used,
# so ordering is byte-for-byte unchanged after the column swap (#3984).
_LEDGER_ORDINAL_SENTINEL = 9223372036854775807


def resolve_current_ledger_ordinal_sqlite(
    conn: sqlite3.Connection,
    tenant_id: str,
    ledger_finding_id: str,
) -> int:
    """Return the ledger ingest ``ordinal`` for a current-state row's pointer.

    A point lookup on the ledger primary key ``(tenant_id, finding_id)`` — the
    ledger row is always written (``add``) before the current batch upsert, so
    the ordinal is present. Missing pointers fall back to the sort sentinel.
    """
    if not ledger_finding_id:
        return _LEDGER_ORDINAL_SENTINEL
    row = conn.execute(
        "SELECT ordinal FROM compliance_hub_findings WHERE tenant_id = ? AND finding_id = ?",
        (tenant_id, ledger_finding_id),
    ).fetchone()
    return int(row[0]) if row else _LEDGER_ORDINAL_SENTINEL


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
    """ORDER BY for ``hub_findings_current``.

    Current-state rows keep a ``ledger_finding_id`` pointer to the durable
    ingest row, and its ingest ``ordinal`` is materialised into the
    ``ledger_ordinal`` column at upsert time (mirroring ``severity_rank`` /
    ``cvss_score`` / ``scan_id``). The legacy hub-list ``ordinal`` contract
    therefore orders by that column directly — an index range scan over
    ``idx_hub_findings_current_tenant_ordinal`` — instead of the per-row
    correlated ledger subquery that forced a full scan + filesort at scale
    (#3984). Rows without a ledger reference carry the ``MAX(bigint)`` sentinel
    (``_LEDGER_ORDINAL_SENTINEL``) so they still sort last, exactly as the old
    ``COALESCE(..., 9223372036854775807)`` fallback did.
    """
    if sort == "ordinal":
        return "ORDER BY ledger_ordinal ASC, first_seen ASC, canonical_id ASC"
    if sort == "cvss":
        # ``cvss_score`` is NOT NULL DEFAULT 0 (backfilled), so bare
        # ``cvss_score DESC`` rides ``idx_hub_findings_current_tenant[_origin]_cvss``
        # as an ordered range scan. A ``COALESCE`` wrapper here defeats the index
        # and forces a full-table temp-B-tree filesort (#3641).
        return "ORDER BY cvss_score DESC, last_seen DESC, canonical_id ASC"
    if sort == "severity":
        return "ORDER BY severity_rank DESC, last_seen DESC, canonical_id ASC"
    return "ORDER BY effective_reach_score DESC, last_seen DESC, canonical_id ASC"


def _postgres_current_order_clause(sort: str) -> str:
    """Postgres ORDER BY for ``hub_findings_current``."""
    return _sqlite_current_order_clause(sort)


def _desc_tie_break(value: str) -> tuple[int, ...]:
    """Lex descending tie-breaker aligned with SQL ``last_seen DESC``."""
    return tuple(-ord(ch) for ch in value)


def _current_page_sort_key(sort: str) -> Callable[[dict[str, Any]], _CurrentPageSortKey]:
    """Sort key for in-memory current-state pages (descending primary signal)."""
    normalized = sort if sort in _LIST_PAGE_SORTS else "effective_reach"

    def _key(row: dict[str, Any]) -> _CurrentPageSortKey:
        tie = str(row.get("last_seen") or "")
        canonical = str(row.get("canonical_id") or "")
        if normalized == "ordinal":
            raw_ordinal = row.get("ledger_ordinal")
            ordinal = _LEDGER_ORDINAL_SENTINEL if raw_ordinal is None else int(raw_ordinal)
            return (ordinal, str(row.get("first_seen") or ""), canonical)
        if normalized == "cvss":
            primary = cvss_sort_value(row.get("cvss_score"))
        elif normalized == "severity":
            primary = float(row.get("severity_rank") or 0)
        else:
            primary = float(row.get("effective_reach_score") or 0.0)
        return (-primary, _desc_tie_break(tie), canonical)

    return _key


def _filter_current_rows(
    rows: list[dict[str, Any]],
    *,
    severity: str | None,
    scan_id: str | None,
    origin: str | None,
    since: str | None = None,
    status: str | None = None,
) -> list[dict[str, Any]]:
    if status is not None:
        rows = [r for r in rows if status_matches(r, status)]
    if origin is not None:
        rows = [r for r in rows if (r.get("payload") or {}).get("origin") == origin]
    if severity is not None:
        sev = severity.lower()
        rows = [r for r in rows if str(r.get("severity") or (r.get("payload") or {}).get("severity", "")).lower() == sev]
    if scan_id is not None:
        rows = [
            r for r in rows if str((r.get("payload") or {}).get("batch_id") or (r.get("payload") or {}).get("scan_id") or "") == scan_id
        ]
    if since:
        rows = [r for r in rows if str(r.get("last_seen") or "") >= since]
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
        self._current_has_ledger_col: bool | None = None
        self._ingest_stats_lock = threading.Lock()
        self._next_ordinal_by_tenant: dict[str, int] = {}
        self._finding_count_by_tenant: dict[str, int] = {}
        self._init_db()

    def _ensure_current_has_ledger_col(self) -> bool:
        if self._current_has_ledger_col is None:
            self._current_has_ledger_col = _hub_findings_current_has_ledger_col(self._conn)
        return self._current_has_ledger_col

    @property
    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self._db_path, check_same_thread=False)
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            # Without a busy timeout, concurrent writers hit "database is locked"
            # immediately and their writes are silently lost. Mirror the primary
            # schema (db/schema.py): wait up to 30s for the write lock and use
            # NORMAL sync, which is durable enough under WAL.
            self._local.conn.execute("PRAGMA busy_timeout=30000")
            self._local.conn.execute("PRAGMA synchronous=NORMAL")
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
                scan_id TEXT NOT NULL DEFAULT '',
                PRIMARY KEY (tenant_id, finding_id)
            )
            """
        )
        self._migrate_columns()
        self._migrate_primary_key()
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_hub_findings_tenant_order ON compliance_hub_findings(tenant_id, ordinal)")
        self._ensure_scale_indexes()
        _ensure_current_lifecycle_sqlite(self._conn)
        ensure_sqlite_reference_tables(self._conn)
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
                # Mirror severity_policy_rank() so backfilled ranks match new
                # writes: info==low==1, none==0, everything unknown==-1 (#3192).
                "UPDATE compliance_hub_findings SET severity_rank = CASE "
                "LOWER(COALESCE(json_extract(payload, '$.severity'), '')) "
                "WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 "
                "WHEN 'info' THEN 1 WHEN 'informational' THEN 1 WHEN 'none' THEN 0 "
                "ELSE -1 END WHERE severity_rank = 0"
            )
        if "cvss_score" not in cols:
            self._conn.execute("ALTER TABLE compliance_hub_findings ADD COLUMN cvss_score REAL NOT NULL DEFAULT 0")
            self._conn.execute(
                "UPDATE compliance_hub_findings SET cvss_score = "
                "CAST(COALESCE(json_extract(payload, '$.cvss_score'), 0) AS REAL) WHERE cvss_score = 0"
            )
        # Materialise scan_id so the scan filter rides an index instead of a
        # per-row json_extract full scan of the tenant's findings. Backfill from
        # the stored payload for legacy rows.
        if "scan_id" not in cols:
            self._conn.execute("ALTER TABLE compliance_hub_findings ADD COLUMN scan_id TEXT NOT NULL DEFAULT ''")
            self._conn.execute(
                "UPDATE compliance_hub_findings SET scan_id = COALESCE(json_extract(payload, '$.scan_id'), '') WHERE scan_id = ''"
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
                scan_id TEXT NOT NULL DEFAULT '',
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
                 ordinal, effective_reach_score, origin, severity, severity_rank, cvss_score, scan_id)
            SELECT f.tenant_id, f.finding_id, f.ingested_at, f.source, f.applicable_frameworks_csv,
                   f.payload, f.ordinal, f.effective_reach_score, f.origin, f.severity, f.severity_rank, f.cvss_score, f.scan_id
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
        # Non-origin covering sort indexes so the *unfiltered* default reads
        # (``WHERE tenant_id=? ORDER BY <col> DESC, ordinal``) ride an ordered
        # index range scan + LIMIT instead of a temp-B-tree filesort — the
        # origin-scoped indexes above cannot serve them because ``origin`` is an
        # unconstrained middle column (#4049). Distinct names + IF NOT EXISTS so
        # steady-state startup is a no-op (no rebuild); the origin-scoped indexes
        # are kept for the filtered reads that still need origin equality.
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_hub_findings_tenant_reach_all "
            "ON compliance_hub_findings(tenant_id, effective_reach_score DESC, ordinal)"
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_hub_findings_tenant_cvss_all ON compliance_hub_findings(tenant_id, cvss_score DESC, ordinal)"
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_hub_findings_tenant_severity_all "
            "ON compliance_hub_findings(tenant_id, severity_rank DESC, ordinal)"
        )
        # Back the scan_id filter with an index (was a per-row json_extract scan).
        # PARTIAL on scan_id != '' so the common no-scan_id rows stay OUT of the
        # index — otherwise an all-empty (tenant_id, scan_id) index looks like a
        # perfect tenant-equality candidate and the planner grabs it for the
        # default reach read, forcing a filesort. Real filters always query a
        # non-empty scan_id, so the partial index still serves them.
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_hub_findings_tenant_scan ON compliance_hub_findings(tenant_id, scan_id) WHERE scan_id != ''"
        )
        # Expression index so the case-insensitive severity equality filter
        # (LOWER(severity) = ?) is sargable. Partial on severity != '' for the
        # same planner-shadowing reason as the scan index above.
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_hub_findings_tenant_severity_ci "
            "ON compliance_hub_findings(tenant_id, LOWER(severity)) WHERE severity != ''"
        )

    def _reset_ingest_stats(self, tenant_id: str) -> None:
        with self._ingest_stats_lock:
            self._next_ordinal_by_tenant.pop(tenant_id, None)
            self._finding_count_by_tenant.pop(tenant_id, None)

    def _bootstrap_ingest_stats(self, tenant_id: str) -> None:
        with self._ingest_stats_lock:
            if tenant_id in self._finding_count_by_tenant:
                return
        count_row = self._conn.execute(
            "SELECT COUNT(*) FROM compliance_hub_findings WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchone()
        max_row = self._conn.execute(
            "SELECT COALESCE(MAX(ordinal), 0) FROM compliance_hub_findings WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchone()
        with self._ingest_stats_lock:
            if tenant_id in self._finding_count_by_tenant:
                return
            self._finding_count_by_tenant[tenant_id] = int(count_row[0]) if count_row else 0
            self._next_ordinal_by_tenant[tenant_id] = int(max_row[0]) + 1 if max_row else 1

    def _existing_finding_ids(self, tenant_id: str, finding_ids: list[str]) -> set[str]:
        if not finding_ids:
            return set()
        existing: set[str] = set()
        chunk_size = 500
        for offset in range(0, len(finding_ids), chunk_size):
            chunk = finding_ids[offset : offset + chunk_size]
            placeholders = ",".join("?" * len(chunk))
            rows = self._conn.execute(
                f"SELECT finding_id FROM compliance_hub_findings WHERE tenant_id = ? AND finding_id IN ({placeholders})",  # nosec B608
                [tenant_id, *chunk],
            ).fetchall()
            existing.update(str(row[0]) for row in rows)
        return existing

    def _next_ordinal(self, tenant_id: str) -> int:
        self._bootstrap_ingest_stats(tenant_id)
        with self._ingest_stats_lock:
            return self._next_ordinal_by_tenant[tenant_id]

    def _invalidate_ingest_caches(self, tenant_id: str) -> None:
        from agent_bom.api import hub_overview_cache
        from agent_bom.api.findings_count_cache import invalidate_tenant

        invalidate_tenant(tenant_id)
        hub_overview_cache.invalidate_tenant(tenant_id)

    def _ledger_insert_no_commit(self, tenant_id: str, findings: list[dict[str, Any]]) -> tuple[int, int, int]:
        """Append the batch to the ledger WITHOUT committing.

        Returns ``(new_rows, next_ord, num_rows)`` so the caller can commit (or
        roll back) as part of a larger transaction and only then advance the
        cached ordinal/total. The commit and the post-commit stat/cache updates
        are the caller's responsibility (see ``add`` / ``ingest_batch_atomic``).
        """
        now = _now_utc_iso()
        next_ord = self._next_ordinal(tenant_id)
        rows: list[tuple[Any, ...]] = []
        finding_ids: list[str] = []
        for offset, original in enumerate(findings):
            if not isinstance(original, dict):
                continue
            frameworks_csv = _frameworks_csv(original)
            slim = persist_finding_references_sqlite(self._conn, tenant_id, original)
            payload = _redact_finding(slim)
            finding_id = str(payload.get("id") or f"hub-{next_ord + offset}")
            finding_ids.append(finding_id)
            rows.append(
                (
                    tenant_id,
                    finding_id,
                    now,
                    str(payload.get("source") or ""),
                    frameworks_csv,
                    encode_hub_payload(payload),
                    next_ord + offset,
                    compute_effective_reach_score(payload),
                    str(payload.get("origin") or ""),
                    str(payload.get("severity") or ""),
                    _severity_rank(payload),
                    _cvss_value(payload),
                    str(payload.get("scan_id") or ""),
                )
            )
        existing_ids = self._existing_finding_ids(tenant_id, finding_ids)
        new_rows = sum(1 for row in rows if str(row[1]) not in existing_ids)
        # Idempotent ingest: a repeat of the same (tenant_id, finding_id)
        # refreshes the stored payload/metadata in place and keeps the original
        # ``ordinal`` (ingest order) instead of appending a duplicate row.
        self._conn.executemany(
            """
            INSERT INTO compliance_hub_findings
                (tenant_id, finding_id, ingested_at, source, applicable_frameworks_csv, payload,
                 ordinal, effective_reach_score, origin, severity, severity_rank, cvss_score, scan_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(tenant_id, finding_id) DO UPDATE SET
                ingested_at = excluded.ingested_at,
                source = excluded.source,
                applicable_frameworks_csv = excluded.applicable_frameworks_csv,
                payload = excluded.payload,
                effective_reach_score = excluded.effective_reach_score,
                origin = excluded.origin,
                severity = excluded.severity,
                severity_rank = excluded.severity_rank,
                cvss_score = excluded.cvss_score,
                scan_id = excluded.scan_id
            """,
            rows,
        )
        return new_rows, next_ord, len(rows)

    def _commit_ledger_stats(self, tenant_id: str, next_ord: int, num_rows: int, new_rows: int) -> int:
        """Advance the cached ordinal/total AFTER the ledger write committed."""
        with self._ingest_stats_lock:
            self._next_ordinal_by_tenant[tenant_id] = next_ord + num_rows
            self._finding_count_by_tenant[tenant_id] += new_rows
            return self._finding_count_by_tenant[tenant_id]

    def add(self, tenant_id: str, findings: list[dict[str, Any]]) -> int:
        if not findings:
            self._bootstrap_ingest_stats(tenant_id)
            with self._ingest_stats_lock:
                if tenant_id in self._finding_count_by_tenant:
                    return self._finding_count_by_tenant[tenant_id]
            return self.count(tenant_id)
        new_rows, next_ord, num_rows = self._ledger_insert_no_commit(tenant_id, findings)
        self._conn.commit()
        if num_rows:
            self._invalidate_ingest_caches(tenant_id)
        return self._commit_ledger_stats(tenant_id, next_ord, num_rows, new_rows)

    def ingest_batch_atomic(
        self,
        tenant_id: str,
        findings: list[dict[str, Any]],
        *,
        observed_at: str,
        batch_id: str,
        source: str,
        reconcile_absent: bool,
        present_canonical_ids: set[str],
    ) -> tuple[int, int]:
        """Ledger append + current upsert (+ reconcile) in ONE transaction.

        ``add`` / ``upsert_current_batch`` / ``reconcile_current_absent`` each
        committed independently, so a crash between the ledger commit and the
        current-state upsert left ``tenant_total`` inflated while the findings
        never appeared in any list. Threading all three writes through a single
        ``with conn`` block (commit on success, rollback on failure) makes a
        mid-batch failure roll BOTH back, mirroring the Postgres seam. The cached
        ordinal/total is advanced only after the commit succeeds. Returns
        ``(new_total, reconciled)``.
        """
        conn = self._conn
        with conn:  # sqlite3 connection: commit on success, rollback on exception
            if findings:
                new_rows, next_ord, num_rows = self._ledger_insert_no_commit(tenant_id, findings)
            else:
                new_rows, next_ord, num_rows = 0, self._next_ordinal(tenant_id), 0
            self._upsert_current_no_commit(
                tenant_id,
                findings,
                observed_at=observed_at,
                batch_id=batch_id,
                source=source,
            )
            reconciled = 0
            if reconcile_absent:
                reconciled = self._reconcile_current_absent_no_commit(
                    tenant_id,
                    present_canonical_ids=present_canonical_ids,
                    observed_at=observed_at,
                    scope_source=source,
                )
        self._invalidate_ingest_caches(tenant_id)
        new_total = self._commit_ledger_stats(tenant_id, next_ord, num_rows, new_rows)
        return new_total, reconciled

    def list(self, tenant_id: str) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT payload FROM compliance_hub_findings WHERE tenant_id = ? ORDER BY ordinal ASC",
            (tenant_id,),
        ).fetchall()
        payloads = [decode_hub_payload(row[0]) for row in rows]
        return hydrate_finding_payloads_sqlite(self._conn, tenant_id, payloads)

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
            # Filter on the materialised severity STRING (exact match, lowercased)
            # so every backend agrees. ``severity_rank`` collapses info==low and
            # is kept for ORDER BY only (#3192). The ``severity != ''`` guard is
            # redundant for any real severity but lets the partial expression
            # index idx_hub_findings_tenant_severity_ci serve the filter.
            where.append("severity != '' AND LOWER(severity) = ?")
            params.append(severity.lower())
        if scan_id is not None:
            # Materialised scan_id column + partial idx_hub_findings_tenant_scan
            # (was a per-row json_extract scan). The ``scan_id != ''`` guard is
            # redundant for any real scan_id but lets the partial index apply.
            where.append("scan_id = ? AND scan_id != ''")
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
        payloads = [decode_hub_payload(row[0]) for row in rows]
        return hydrate_finding_payloads_sqlite(self._conn, tenant_id, payloads), total

    def severity_breakdown(self, tenant_id: str) -> dict[str, int]:
        # GROUP BY the materialised ``severity`` column (populated on ingest and
        # backed by ``idx_hub_findings_tenant_severity_ci``) instead of an
        # unindexed per-row ``json_extract(payload, '$.severity')`` decode (#3963).
        rows = self._conn.execute(
            """
            SELECT LOWER(COALESCE(NULLIF(severity, ''), 'unknown')) AS sev, COUNT(*)
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

    def current_severity_breakdown(
        self,
        tenant_id: str,
        *,
        origin: str | None = None,
        since: str | None = None,
        status: str | None = None,
    ) -> dict[str, int]:
        # GROUP BY the materialised ``severity`` column on the current-state
        # table, applying the SAME tenant/since/origin/status predicates
        # ``list_current_page`` counts on, so the exec headline reconciles
        # exactly with the ``/v1/findings`` drill-down (#3961/#4009). The
        # lifecycle ``status`` filter keeps resolved rows out of the headline.
        where = ["tenant_id = ?"]
        params: list[Any] = [tenant_id]
        if since:
            where.append("last_seen >= ?")
            params.append(since)
        if origin is not None:
            where.append("origin = ?")
            params.append(origin)
        status_sql, status_params = status_sql_predicate(status)
        if status_sql:
            where.append(status_sql)
            params.extend(status_params)
        where_sql = " AND ".join(where)
        rows = self._conn.execute(
            f"""
            SELECT LOWER(COALESCE(NULLIF(severity, ''), 'unknown')) AS sev, COUNT(*)
            FROM hub_findings_current
            WHERE {where_sql}
            GROUP BY sev
            """,  # nosec B608
            params,
        ).fetchall()
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}
        for sev, count in rows:
            key = str(sev or "unknown").lower()
            counts[key] = counts.get(key, 0) + int(count)
        return counts

    def current_kev_count(
        self,
        tenant_id: str,
        *,
        origin: str | None = None,
        since: str | None = None,
    ) -> int:
        # Same tenant/since/origin predicates as ``current_severity_breakdown``.
        # The KEV flag is not a current-state column (the overlay keeps only
        # sort/filter scalars), so resolve it from the current payload, the joined
        # ledger payload, and the CVE-intel reference — the exact places the drill
        # hydrates it from — so the exec KEV count reconciles with the drill.
        where = ["c.tenant_id = ?"]
        params: list[Any] = [tenant_id]
        if since:
            where.append("c.last_seen >= ?")
            params.append(since)
        if origin is not None:
            where.append("c.origin = ?")
            params.append(origin)
        where_sql = " AND ".join(where)
        kev_cond = " OR ".join(
            _kev_json_cond_sqlite(col) for col in ("c.payload", "l.payload", "i.payload")
        )
        row = self._conn.execute(
            f"""
            SELECT COUNT(*)
            FROM hub_findings_current c
            LEFT JOIN compliance_hub_findings l
                ON l.tenant_id = c.tenant_id AND l.finding_id = c.ledger_finding_id
            LEFT JOIN hub_cve_intel i
                ON i.tenant_id = c.tenant_id AND i.cve_id = json_extract(l.payload, '$.intel_ref')
            WHERE {where_sql} AND ({kev_cond})
            """,  # nosec B608
            params,
        ).fetchone()
        return int((row[0] if row else 0) or 0)

    def framework_slug_counts(self, tenant_id: str) -> dict[str, int]:
        from agent_bom.compliance_coverage import normalize_framework_slug

        # Split + aggregate the denormalised CSV IN SQL via a recursive CTE so
        # the query returns O(distinct slugs) rows, never the full tenant ledger
        # pulled into Python (#3963). The handful of raw tokens are then folded
        # to canonical slugs (alias/underscore normalisation) in Python.
        rows = self._conn.execute(
            """
            WITH RECURSIVE split(rest, token) AS (
                SELECT applicable_frameworks_csv || ',', ''
                  FROM compliance_hub_findings
                 WHERE tenant_id = ? AND applicable_frameworks_csv <> ''
                UNION ALL
                SELECT substr(rest, instr(rest, ',') + 1),
                       substr(rest, 1, instr(rest, ',') - 1)
                  FROM split
                 WHERE rest <> ''
            )
            SELECT TRIM(token) AS slug, COUNT(*) AS n
              FROM split
             WHERE TRIM(token) <> ''
             GROUP BY TRIM(token)
            """,
            (tenant_id,),
        ).fetchall()
        counts: dict[str, int] = {}
        for slug, n in rows:
            canonical = normalize_framework_slug(str(slug))
            counts[canonical] = counts.get(canonical, 0) + int(n)
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
        self._reset_ingest_stats(tenant_id)
        if removed:
            from agent_bom.api import hub_overview_cache
            from agent_bom.api.findings_count_cache import invalidate_tenant

            invalidate_tenant(tenant_id)
            hub_overview_cache.invalidate_tenant(tenant_id)
        return removed

    def _upsert_current_no_commit(
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
        has_ledger_col = self._ensure_current_has_ledger_col()
        for payload in clean:
            _upsert_current_finding_sqlite(
                self._conn,
                tenant_id=tenant_id,
                payload=payload,
                observed_at=observed_at,
                scan_id=batch_id,
                source=source,
                has_ledger_col=has_ledger_col,
            )

    def upsert_current_batch(
        self,
        tenant_id: str,
        findings: Sequence[dict[str, Any]],
        *,
        observed_at: str,
        batch_id: str,
        source: str = "",
    ) -> None:
        self._upsert_current_no_commit(
            tenant_id,
            findings,
            observed_at=observed_at,
            batch_id=batch_id,
            source=source,
        )
        self._conn.commit()

    def get_current(self, tenant_id: str, canonical_id: str) -> dict[str, Any] | None:
        has_ledger_col = _hub_findings_current_has_ledger_col(self._conn)
        payload_select = "payload, ledger_finding_id, ledger_ordinal" if has_ledger_col else "payload"
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
        cursor: str | None = None,
        since: str | None = None,
        scope: Mapping[str, str] | None = None,
        status: str | None = None,
    ) -> FindingCursorPage:
        from agent_bom.api.finding_lifecycle import enriched_finding_payload

        normalized_sort = sort if sort in _LIST_PAGE_SORTS else "effective_reach"
        where = ["tenant_id = ?"]
        params: list[Any] = [tenant_id]
        if since:
            # Default read-window: bound to findings last observed within the
            # window so counts stay honestly "last Nd" at scale (#4009).
            where.append("last_seen >= ?")
            params.append(since)
        if origin is not None:
            # Materialised column (backfilled from payload) so the exact COUNT(*)
            # rides the (tenant_id, origin, …) index prefix instead of scanning
            # every row through json_extract (#3641).
            where.append("origin = ?")
            params.append(origin)
        if severity is not None:
            # Match the materialised severity STRING (exact, lowercased) so all
            # backends agree; ``severity_rank`` stays ORDER-BY-only (#3192). The
            # ``severity != ''`` guard is redundant for any real severity but
            # lets the partial expression index idx_hub_findings_current_tenant_
            # severity_ci serve the filter (#3926).
            where.append("severity != '' AND LOWER(severity) = ?")
            params.append(severity.lower())
        if scan_id is not None:
            # Materialised column (backfilled from batch_id|scan_id) so the scan
            # filter and its COUNT(*) ride idx_hub_findings_current_tenant_scan
            # instead of a per-row json_extract full scan. The ``scan_id != ''``
            # guard is redundant for any real scan_id but lets SQLite apply the
            # partial index (it cannot prove a bound param is non-empty) (#3926).
            where.append("scan_id = ? AND scan_id != ''")
            params.append(scan_id)
        # Lifecycle-status filter over the sargable ``status`` column. Added to
        # the base predicate so it applies in BOTH the fast keyset path and the
        # scoped batched path (base_where flows into the scope fetch_batch). The
        # default-open path rides idx_hub_findings_current_tenant_open_reach.
        status_sql, status_params = status_sql_predicate(status)
        if status_sql:
            where.append(status_sql)
            params.extend(status_params)
        if scope:
            # provider/account_ref/environment/domain live in the JSON payload and
            # ``domain`` is a computed overlapping-lens SET — not a single SQL
            # predicate. Run the scope filter INSIDE the store on pre-enrichment
            # current rows, batched + keyset-paged, so a scoped page never
            # materializes the whole tenant. total is None (approximate) here.
            return self._list_current_page_scoped(
                base_where=list(where),
                base_params=list(params),
                tenant_id=tenant_id,
                normalized_sort=normalized_sort,
                limit=limit,
                cursor=cursor,
                scope=scope,
            )
        if cursor:
            keyset_sql, keyset_params = sqlite_keyset_clause(normalized_sort, cursor)
            where.append(keyset_sql.removeprefix(" AND "))
            params.extend(keyset_params)
        where_sql = " AND ".join(where)

        total: int | None
        if include_total and not cursor:
            total_row = self._conn.execute(
                f"SELECT COUNT(*) FROM hub_findings_current WHERE {where_sql}",  # nosec B608
                params,
            ).fetchone()
            total = int(total_row[0]) if total_row else 0
        else:
            total = None

        order_sql = _sqlite_current_order_clause(normalized_sort)
        page_limit = max(0, int(limit))
        fetch_limit = page_limit + 1 if page_limit >= 0 else page_limit
        if cursor:
            page_params = [*params, fetch_limit]
            limit_sql = "LIMIT ?"
        else:
            page_params = [*params, fetch_limit, int(offset)]
            limit_sql = "LIMIT ? OFFSET ?"
        has_ledger_col = _hub_findings_current_has_ledger_col(self._conn)
        payload_select = "payload, ledger_finding_id, ledger_ordinal" if has_ledger_col else "payload"
        rows = self._conn.execute(
            f"""
            SELECT canonical_id, first_seen, last_seen, status, severity, severity_rank,
                   cvss_score, effective_reach_score, scan_count, resolved_at, reopened_at,
                   updated_at, {payload_select}
            FROM hub_findings_current
            WHERE {where_sql} {order_sql} {limit_sql}
            """,  # nosec B608
            page_params,
        ).fetchall()
        current_rows = [_sqlite_current_row_from_db(row, has_ledger_col=has_ledger_col) for row in rows]
        has_more = page_limit >= 0 and len(current_rows) > page_limit
        if has_more:
            current_rows = current_rows[:page_limit]
        hydrated_rows = _hydrate_sqlite_current_rows(self._conn, tenant_id, current_rows)
        out: list[dict[str, Any]] = []
        for current_row in hydrated_rows:
            out.append(enriched_finding_payload(current_row))
        next_cursor = None
        if has_more and hydrated_rows:
            next_cursor = cursor_from_current_row(hydrated_rows[-1], sort=normalized_sort)
        return out, total, next_cursor

    def _list_current_page_scoped(
        self,
        *,
        base_where: Sequence[str],
        base_params: Sequence[Any],
        tenant_id: str,
        normalized_sort: str,
        limit: int,
        cursor: str | None,
        scope: Mapping[str, str],
    ) -> FindingCursorPage:
        from agent_bom.api.finding_lifecycle import enriched_finding_payload
        from agent_bom.finding_scope import row_matches_scope

        order_sql = _sqlite_current_order_clause(normalized_sort)
        has_ledger_col = _hub_findings_current_has_ledger_col(self._conn)
        payload_select = "payload, ledger_finding_id, ledger_ordinal" if has_ledger_col else "payload"

        def fetch_batch(batch_cursor: str | None, batch_limit: int) -> tuple[list[tuple[dict[str, Any], dict[str, Any]]], str | None]:
            where = list(base_where)
            params = list(base_params)
            if batch_cursor:
                keyset_sql, keyset_params = sqlite_keyset_clause(normalized_sort, batch_cursor)
                where.append(keyset_sql.removeprefix(" AND "))
                params.extend(keyset_params)
            where_sql = " AND ".join(where)
            fetch_limit = batch_limit + 1
            rows = self._conn.execute(
                f"""
                SELECT canonical_id, first_seen, last_seen, status, severity, severity_rank,
                       cvss_score, effective_reach_score, scan_count, resolved_at, reopened_at,
                       updated_at, {payload_select}
                FROM hub_findings_current
                WHERE {where_sql} {order_sql} LIMIT ?
                """,  # nosec B608
                [*params, fetch_limit],
            ).fetchall()
            current_rows = [_sqlite_current_row_from_db(row, has_ledger_col=has_ledger_col) for row in rows]
            more = len(current_rows) > batch_limit
            if more:
                current_rows = current_rows[:batch_limit]
            hydrated = _hydrate_sqlite_current_rows(self._conn, tenant_id, current_rows)
            pairs = [(row, enriched_finding_payload(row)) for row in hydrated]
            batch_next = cursor_from_current_row(hydrated[-1], sort=normalized_sort) if more and hydrated else None
            return pairs, batch_next

        page_limit = max(0, int(limit))
        payloads, next_cursor = collect_scope_filtered_page(
            fetch_batch,
            predicate=lambda payload: row_matches_scope(payload, scope),
            page_limit=page_limit,
            start_cursor=cursor,
            sort=normalized_sort,
            batch_size=scope_filter_batch_size(page_limit),
        )
        return payloads, None, next_cursor

    def _reconcile_current_absent_no_commit(
        self,
        tenant_id: str,
        *,
        present_canonical_ids: set[str],
        observed_at: str,
        scope_source: str | None = None,
    ) -> int:
        now = _now_utc_iso()
        where = ["tenant_id = ?", "status IN ('open', 'reopened')"]
        params: list[Any] = [tenant_id]
        if scope_source is not None:
            where.append("json_extract(payload, '$.source') = ?")
            params.append(scope_source)
        where_sql = " AND ".join(where)
        rows = self._conn.execute(
            f"SELECT canonical_id FROM hub_findings_current WHERE {where_sql}",  # nosec B608
            params,
        ).fetchall()
        open_ids = {str(row[0]) for row in rows}
        absent = sorted(open_ids - present_canonical_ids)
        if not absent:
            return 0
        total = 0
        for offset in range(0, len(absent), RECONCILE_ABSENT_CHUNK):
            chunk = absent[offset : offset + RECONCILE_ABSENT_CHUNK]
            placeholders = ",".join("?" * len(chunk))
            cur = self._conn.execute(
                f"""
                UPDATE hub_findings_current
                SET status = 'resolved', resolved_at = ?, updated_at = ?
                WHERE {where_sql} AND canonical_id IN ({placeholders})
                """,  # nosec B608
                [observed_at, now, *params, *chunk],
            )
            total += int(cur.rowcount or 0)
        return total

    def reconcile_current_absent(
        self,
        tenant_id: str,
        *,
        present_canonical_ids: set[str],
        observed_at: str,
        scope_source: str | None = None,
    ) -> int:
        total = self._reconcile_current_absent_no_commit(
            tenant_id,
            present_canonical_ids=present_canonical_ids,
            observed_at=observed_at,
            scope_source=scope_source,
        )
        self._conn.commit()
        return total


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
