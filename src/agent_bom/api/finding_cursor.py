"""Opaque keyset cursors for ``hub_findings_current`` sorted reads."""

from __future__ import annotations

import base64
import json
from typing import Any

_ALLOWED_SORTS = frozenset({"effective_reach", "cvss", "severity", "ordinal"})


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
        return float(payload.get("primary") or 0.0), str(payload.get("last_seen") or ""), str(payload.get("canonical_id") or "")
    except Exception as exc:
        raise ValueError("Invalid findings cursor") from exc


def cursor_from_current_row(row: dict[str, Any], *, sort: str) -> str:
    normalized = sort if sort in _ALLOWED_SORTS else "effective_reach"
    if normalized == "ordinal":
        primary = 0.0
    elif normalized == "cvss":
        primary = float(row.get("cvss_score") or 0.0)
    elif normalized == "severity":
        primary = float(row.get("severity_rank") or 0.0)
    else:
        primary = float(row.get("effective_reach_score") or 0.0)
    return encode_finding_cursor(
        sort=normalized,
        primary=primary,
        last_seen=str(row.get("last_seen") or ""),
        canonical_id=str(row.get("canonical_id") or ""),
    )


def sqlite_keyset_clause(sort: str, cursor: str) -> tuple[str, list[Any]]:
    """Return extra WHERE SQL + params for keyset pagination after ``cursor``."""
    normalized = sort if sort in _ALLOWED_SORTS else "effective_reach"
    primary, last_seen, canonical_id = decode_finding_cursor(cursor, expected_sort=normalized)
    if normalized == "ordinal":
        return (
            " AND (last_seen > ? OR (last_seen = ? AND canonical_id > ?))",
            [last_seen, last_seen, canonical_id],
        )
    if normalized == "cvss":
        col = "cvss_score"
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
        return (row_last, row_canonical) > (last_seen, canonical_id)
    if normalized == "cvss":
        row_primary = float(row.get("cvss_score") or 0.0)
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
