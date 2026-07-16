"""Default read-window helpers for bounded, honestly-scoped list surfaces.

List / graph / snapshot read endpoints default to the last
``config.RETENTION_DAYS`` (≈90d) so counts stay honestly scoped to a recent
window at scale. Callers widen or clear the window with ``?window_days=`` where
``0`` means "all history". This is a *view* default only — it never deletes
data; hard deletion is governed by the retention purge knobs.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from agent_bom import config


def default_window_days() -> int:
    """Return the configured default read-window in days (never negative)."""
    return max(0, int(config.RETENTION_DAYS))


def normalize_window_days(value: int | None) -> int:
    """Resolve a requested window.

    ``None`` → the server default; ``<= 0`` → ``0`` (all history / no bound);
    otherwise the requested positive day count.
    """
    if value is None:
        return default_window_days()
    resolved = int(value)
    return resolved if resolved > 0 else 0


def window_cutoff(window_days: int, *, now: datetime | None = None) -> datetime | None:
    """Return the cutoff datetime for *window_days*, or ``None`` when unbounded."""
    if window_days <= 0:
        return None
    now_dt = now or datetime.now(timezone.utc)
    if now_dt.tzinfo is None:
        now_dt = now_dt.replace(tzinfo=timezone.utc)
    return now_dt - timedelta(days=window_days)


def window_since_iso(window_days: int, *, now: datetime | None = None) -> str | None:
    """Return the ISO-8601 cutoff string for *window_days*, or ``None``."""
    cutoff = window_cutoff(window_days, now=now)
    return cutoff.isoformat() if cutoff is not None else None


def window_metadata(window_days: int, *, now: datetime | None = None) -> dict[str, Any]:
    """Describe the applied read-window so clients can label it honestly."""
    since = window_since_iso(window_days, now=now)
    return {
        "days": window_days,
        "since": since,
        "applied": since is not None,
        "label": "All time" if since is None else f"Last {window_days} days",
    }


__all__ = [
    "default_window_days",
    "normalize_window_days",
    "window_cutoff",
    "window_metadata",
    "window_since_iso",
]
