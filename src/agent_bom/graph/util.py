"""Graph utilities — shared helpers."""

from __future__ import annotations

from datetime import datetime, timezone


def _now_iso() -> str:
    """Current UTC time as ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
