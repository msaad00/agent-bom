"""Transport freshness projection for the gateway feed."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

_FEED_STALE_AFTER_SECONDS = 120


def _parse_iso_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def build_gateway_feed_health(
    *,
    transport_enabled: bool,
    heartbeat_at: str | None,
    now: datetime | None = None,
    sample: bool = False,
    stale_after_seconds: int = _FEED_STALE_AFTER_SECONDS,
) -> dict[str, Any]:
    """Describe transport freshness independently from retained event presence."""
    checked_at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    base: dict[str, Any] = {
        "assurance_basis": "transport_receipt",
        "producer_assurance": "unknown",
        "state": "sample" if sample else "unavailable",
        "live": False,
        "heartbeat_at": heartbeat_at,
        "age_seconds": None,
        "stale_after_seconds": stale_after_seconds,
    }
    if sample:
        base["reason"] = "synthetic_sample"
        return base
    heartbeat = _parse_iso_timestamp(heartbeat_at)
    if not transport_enabled or heartbeat is None:
        base["reason"] = "transport_or_heartbeat_unavailable"
        return base

    age_delta = (checked_at - heartbeat).total_seconds()
    if age_delta < 0:
        base["reason"] = "transport_heartbeat_in_future"
        return base
    age_seconds = int(age_delta)
    base["age_seconds"] = age_seconds
    if age_seconds <= stale_after_seconds:
        base.update({"state": "live", "live": True, "reason": "recent_transport_heartbeat"})
    else:
        base.update({"state": "stale", "reason": "transport_heartbeat_stale"})
    return base
