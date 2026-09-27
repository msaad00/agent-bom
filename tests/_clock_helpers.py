"""Keep fixture timestamps inside time-windowed reads whenever the suite runs.

Findings, overview and posture reads default to a bounded window measured from
the current time. A fixture pinned to a literal date drops out of that window
once the calendar passes it, and the test starts failing with no code change.
``recent`` keeps a literal's age relative to today: it shifts the timestamp
forward by whole days, so order, time of day and UTC-offset style are unchanged.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

_ANCHOR = datetime(2026, 9, 1, tzinfo=timezone.utc)


def recent(iso: str) -> str:
    """Shift *iso* by the whole days elapsed since the fixtures were authored."""
    zulu = iso.endswith("Z")
    parsed = datetime.fromisoformat(iso[:-1] + "+00:00" if zulu else iso)
    shifted = parsed + timedelta(days=(datetime.now(timezone.utc) - _ANCHOR).days)
    text = shifted.isoformat()
    return text.replace("+00:00", "Z") if zulu else text
