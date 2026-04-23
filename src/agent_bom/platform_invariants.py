"""Shared platform record invariants.

These helpers keep tenant- and time-bearing records consistent across fleet,
gateway/discovery provenance, and later graph/event consumers.
"""

from __future__ import annotations

from datetime import datetime, timezone


def now_utc_iso() -> str:
    """Return the current UTC timestamp as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


def normalize_tenant_id(value: str | None) -> str:
    """Return a canonical tenant id, falling back to ``default``."""
    tenant_id = (value or "").strip()
    return tenant_id or "default"


def normalize_timestamp(value: str | None) -> str | None:
    """Return a canonical UTC ISO-8601 timestamp.

    Blank values stay ``None``. Naive timestamps are treated as UTC.
    """
    if value is None:
        return None
    text = value.strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    else:
        parsed = parsed.astimezone(timezone.utc)
    normalized = parsed.isoformat()
    if normalized.endswith("+00:00"):
        return f"{normalized[:-6]}Z"
    return normalized
