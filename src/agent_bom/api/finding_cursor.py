"""Opaque keyset cursors for ``hub_findings_current`` sorted reads."""

from __future__ import annotations

import base64
import json
from typing import Any

from agent_bom.api.storage.sql import Col, Dialect, Keyset
from agent_bom.core.cvss import normalize_cvss_score
from agent_bom.core.severity import severity_policy_rank

_ALLOWED_SORTS = frozenset({"effective_reach", "cvss", "severity", "ordinal"})

# ``cvss_score`` is NOT NULL DEFAULT 0 at the storage layer (legacy NULLs are
# backfilled to 0 on migration), so keyset comparisons stay three-valued-logic
# safe without a COALESCE wrapper (#3511 / audit 2026-07-04 / #3641). The Python
# helper keeps a defensive 0 for in-memory rows that never touched storage.
_CVSS_NULL_SORT_VALUE = 0.0


def cvss_sort_value(raw: Any) -> float:
    return normalize_cvss_score(raw) or _CVSS_NULL_SORT_VALUE


def severity_rank_sort_value(row: dict[str, Any]) -> float:
    """Severity keyset rank for a row, whether store-shaped or API-payload-shaped.

    Enriched API payloads carry ``severity`` but not always the denormalised
    ``severity_rank`` column; defaulting the missing rank to 0 minted cursors
    whose resume keyset matched nothing, silently truncating severity-sorted
    walks. Derive the rank from the severity string with the SAME mapping the
    store materialises at ingest (``severity_policy_rank``).
    """
    raw = row.get("severity_rank")
    if raw is not None:
        try:
            return float(raw)
        except (TypeError, ValueError):
            pass
    return float(severity_policy_rank(str(row.get("severity") or "")))


def encode_finding_cursor(
    *,
    sort: str,
    primary: float,
    last_seen: str,
    canonical_id: str,
) -> str:
    payload = {
        "sort": sort if sort in _ALLOWED_SORTS else "effective_reach",
        "primary": primary,
        "last_seen": last_seen,
        "canonical_id": canonical_id,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_finding_cursor(cursor: str, *, expected_sort: str) -> tuple[float, str, str]:
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        raw = base64.urlsafe_b64decode(padded.encode()).decode()
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            raise ValueError
        sort = str(payload.get("sort") or "")
        if sort != expected_sort:
            raise ValueError("Cursor sort mismatch")
        primary: float | int
        if sort == "ordinal":
            # Ordinal cursors use the actual indexed ORDER BY tuple:
            # (ledger_ordinal ASC, first_seen ASC, canonical_id ASC). Keep the
            # bigint as an int so MAX(bigint) remains exact through JSON decode.
            primary = int(payload.get("primary") or 0)
        else:
            primary = float(payload.get("primary") or 0.0)
        return primary, str(payload.get("last_seen") or ""), str(payload.get("canonical_id") or "")
    except Exception as exc:
        raise ValueError("Invalid findings cursor") from exc


_MERGED_SCAN_CURSOR_MARKER = "merge1"
_GROUP_CURSOR_MARKER = "group1"


def encode_finding_group_cursor(*, sort: str, offset: int) -> str:
    """Encode the next offset in the fully materialized issue-group list."""
    payload = {
        "t": _GROUP_CURSOR_MARKER,
        "sort": sort if sort in _ALLOWED_SORTS else "effective_reach",
        "offset": max(0, int(offset)),
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_finding_group_cursor(cursor: str, *, expected_sort: str) -> int | None:
    """Decode an issue-group cursor, returning ``None`` for another cursor type."""
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        raw = base64.urlsafe_b64decode(padded.encode()).decode()
        payload = json.loads(raw)
    except Exception:
        return None
    if not isinstance(payload, dict) or payload.get("t") != _GROUP_CURSOR_MARKER:
        return None
    if str(payload.get("sort") or "") != expected_sort:
        raise ValueError("Cursor sort mismatch")
    try:
        offset = int(payload.get("offset") or 0)
    except (TypeError, ValueError) as exc:
        raise ValueError("Invalid grouped findings cursor") from exc
    if offset < 0:
        raise ValueError("Invalid grouped findings cursor")
    return offset


def encode_merged_scan_cursor(*, sort: str, scan_index: int, bulk_cursor: str) -> str:
    """Encode a compound cursor over the merged in-memory-scan + hub stream.

    ``/v1/findings`` interleaves two sources: the fully-materialized in-memory
    scan findings (walked by integer index) and the keyset-paged hub findings
    (walked by ``bulk_cursor``). One opaque token carries both frontiers so a
    keyset caller resumes the merge with 0 dups / 0 drops instead of losing the
    scan half after page 1.
    """
    payload = {
        "t": _MERGED_SCAN_CURSOR_MARKER,
        "sort": sort if sort in _ALLOWED_SORTS else "effective_reach",
        "si": int(scan_index),
        "bc": bulk_cursor or "",
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_merged_scan_cursor(cursor: str, *, expected_sort: str) -> tuple[int, str] | None:
    """Decode a compound merged cursor.

    Returns ``(scan_index, bulk_cursor)`` when ``cursor`` is a merged token,
    ``None`` when it is a plain hub keyset cursor (so the caller can fall back).
    Raises ``ValueError`` when it IS a merged token but is corrupt or its sort
    disagrees with ``expected_sort`` (mirrors :func:`decode_finding_cursor`).
    """
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        raw = base64.urlsafe_b64decode(padded.encode()).decode()
        payload = json.loads(raw)
    except Exception:
        return None
    if not isinstance(payload, dict) or payload.get("t") != _MERGED_SCAN_CURSOR_MARKER:
        return None
    sort = str(payload.get("sort") or "")
    if sort != expected_sort:
        raise ValueError("Cursor sort mismatch")
    try:
        scan_index = int(payload.get("si") or 0)
    except (TypeError, ValueError) as exc:
        raise ValueError("Invalid merged findings cursor") from exc
    if scan_index < 0:
        raise ValueError("Invalid merged findings cursor")
    bulk_cursor = str(payload.get("bc") or "")
    return scan_index, bulk_cursor


def cursor_from_current_row(row: dict[str, Any], *, sort: str) -> str:
    normalized = sort if sort in _ALLOWED_SORTS else "effective_reach"
    primary: float | int
    if normalized == "ordinal":
        raw_ordinal = row.get("ledger_ordinal")
        primary = int(raw_ordinal) if raw_ordinal is not None else 0
        tie = str(row.get("first_seen") or "")
    elif normalized == "cvss":
        primary = cvss_sort_value(row.get("cvss_score"))
        tie = str(row.get("last_seen") or "")
    elif normalized == "severity":
        primary = severity_rank_sort_value(row)
        tie = str(row.get("last_seen") or "")
    else:
        primary = float(row.get("effective_reach_score") or 0.0)
        tie = str(row.get("last_seen") or "")
    return encode_finding_cursor(
        sort=normalized,
        primary=primary,
        # The cursor stays opaque to callers. For ordinal, this slot carries
        # first_seen; for descending risk sorts it carries last_seen.
        last_seen=tie,
        canonical_id=str(row.get("canonical_id") or ""),
    )


def finding_keyset(sort: str) -> Keyset:
    """Sort key of a ``hub_findings_current`` page, shared by both engines.

    Risk sorts order by the materialised score descending, then ``last_seen``
    descending, then ``canonical_id`` ascending; ``ordinal`` orders by the
    ledger ordinal, ``first_seen`` and ``canonical_id``, all ascending. Score
    columns are bare NOT NULL columns (``cvss_score`` defaults to 0, #3641) so
    the order and the cursor bound ride the sort indexes. Text tie-breakers
    compare by code point on both engines, which Postgres serves from the
    ``COLLATE "C"`` sort indexes.
    """
    normalized = sort if sort in _ALLOWED_SORTS else "effective_reach"
    if normalized == "ordinal":
        return Keyset([Col("ledger_ordinal", numeric=True), Col("first_seen"), Col("canonical_id")])
    primary = {"cvss": "cvss_score", "severity": "severity_rank"}.get(normalized, "effective_reach_score")
    return Keyset([Col(primary, desc=True, numeric=True), Col("last_seen", desc=True), Col("canonical_id")])


def finding_order_clause(dialect: Dialect, sort: str) -> str:
    """``ORDER BY`` clause for a ``hub_findings_current`` page."""
    return f"ORDER BY {finding_keyset(sort).order_by(dialect)}"


def _keyset_clause(dialect: Dialect, sort: str, cursor: str) -> tuple[str, list[Any]]:
    normalized = sort if sort in _ALLOWED_SORTS else "effective_reach"
    position = decode_finding_cursor(cursor, expected_sort=normalized)
    predicate, params = finding_keyset(normalized).after(dialect, position)
    return f" AND {predicate}", list(params)


def sqlite_keyset_clause(sort: str, cursor: str) -> tuple[str, list[Any]]:
    """Return extra WHERE SQL + params for keyset pagination after ``cursor``."""
    return _keyset_clause("sqlite", sort, cursor)


def postgres_keyset_clause(sort: str, cursor: str) -> tuple[str, list[Any]]:
    """Postgres form of :func:`sqlite_keyset_clause` with ``%s`` placeholders."""
    clause, params = _keyset_clause("postgres", sort, cursor)
    return clause.replace("?", "%s"), params


def row_is_after_cursor(
    row: dict[str, Any],
    *,
    sort: str,
    primary: float,
    last_seen: str,
    canonical_id: str,
) -> bool:
    """Return True when ``row`` sorts strictly after the cursor tuple."""
    normalized = sort if sort in _ALLOWED_SORTS else "effective_reach"
    row_last = str(row.get("last_seen") or "")
    row_canonical = str(row.get("canonical_id") or "")
    if normalized == "ordinal":
        raw_ordinal = row.get("ledger_ordinal")
        row_ordinal = int(raw_ordinal) if raw_ordinal is not None else 0
        row_first = str(row.get("first_seen") or "")
        cursor_ordinal = int(primary)
        if row_ordinal != cursor_ordinal:
            return row_ordinal > cursor_ordinal
        if row_first != last_seen:
            return row_first > last_seen
        return row_canonical > canonical_id
    if normalized == "cvss":
        row_primary = cvss_sort_value(row.get("cvss_score"))
    elif normalized == "severity":
        row_primary = severity_rank_sort_value(row)
    else:
        row_primary = float(row.get("effective_reach_score") or 0.0)
    if row_primary < primary:
        return True
    if row_primary > primary:
        return False
    if row_last < last_seen:
        return True
    if row_last > last_seen:
        return False
    return row_canonical > canonical_id
