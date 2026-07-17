"""Opaque keyset cursors for ``hub_findings_current`` sorted reads."""

from __future__ import annotations

import base64
import json
from typing import Any

_ALLOWED_SORTS = frozenset({"effective_reach", "cvss", "severity", "ordinal"})

# ``cvss_score`` is NOT NULL DEFAULT 0 at the storage layer (legacy NULLs are
# backfilled to 0 on migration), so keyset comparisons stay three-valued-logic
# safe without a COALESCE wrapper (#3511 / audit 2026-07-04 / #3641). The Python
# helper keeps a defensive 0 for in-memory rows that never touched storage.
_CVSS_NULL_SORT_VALUE = 0.0


def cvss_sort_value(raw: Any) -> float:
    if raw is None:
        return _CVSS_NULL_SORT_VALUE
    try:
        return float(raw)
    except (TypeError, ValueError):
        return _CVSS_NULL_SORT_VALUE


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
        primary = float(row.get("severity_rank") or 0.0)
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


def _cvss_keyset_expr() -> str:
    # Bare column (not COALESCE) so the keyset range predicate rides the
    # cvss sort index; safe because cvss_score is NOT NULL DEFAULT 0 (#3641).
    return "cvss_score"


def sqlite_keyset_clause(sort: str, cursor: str) -> tuple[str, list[Any]]:
    """Return extra WHERE SQL + params for keyset pagination after ``cursor``."""
    normalized = sort if sort in _ALLOWED_SORTS else "effective_reach"
    if normalized == "ordinal":
        primary, first_seen, canonical_id = decode_finding_cursor(cursor, expected_sort=normalized)
        return (
            " AND (ledger_ordinal > ? OR (ledger_ordinal = ? AND (first_seen > ? OR (first_seen = ? AND canonical_id > ?))))",
            [primary, primary, first_seen, first_seen, canonical_id],
        )
    primary, last_seen, canonical_id = decode_finding_cursor(cursor, expected_sort=normalized)
    if normalized == "cvss":
        col = _cvss_keyset_expr()
    elif normalized == "severity":
        col = "severity_rank"
    else:
        col = "effective_reach_score"
    return (
        f" AND ({col} < ? OR ({col} = ? AND (last_seen < ? OR (last_seen = ? AND canonical_id > ?))))",
        [primary, primary, last_seen, last_seen, canonical_id],
    )


def postgres_keyset_clause(sort: str, cursor: str) -> tuple[str, list[Any]]:
    clause, params = sqlite_keyset_clause(sort, cursor)
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
        row_primary = float(row.get("severity_rank") or 0.0)
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
