"""Cost and behavior anomaly detection over persisted runtime data.

Spend attribution (``cost_store``) and runtime observations
(``runtime_event_store``) make a runaway agent *visible after the fact*; this
module surfaces it *proactively* with simple, explainable statistics — a
per-agent / per-session z-score over spend and tool-call volume. No ML, no
opaque model: the threshold and the math are operator-readable, matching the
open posture of the rest of the platform.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

# Modified z-score (median + MAD) threshold. Robust to the outlier inflating its
# own baseline — a plain mean/std z-score caps a single outlier below 3 in small
# samples, so it would never flag the very runaway agent we care about.
DEFAULT_Z_THRESHOLD = 3.5
_MIN_SAMPLES = 4
_MAD_SCALE = 0.6745  # 0.75 quantile of the standard normal

# Temporal (seasonal) baseline tuning (#2926). A spike is judged against the
# agent's OWN history bucketed by (day-of-week, hour) so a predictable nightly
# batch job is not flagged, while a slow creep above the agent's normal level
# for that time slot is. EWMA gives recent buckets more weight; the seasonal
# arm compares "this slot now" to "this slot historically".
_TEMPORAL_MIN_BUCKETS = 6  # need some history before judging temporally
_TEMPORAL_EWMA_ALPHA = 0.3  # weight of the newest bucket in the running mean
_TEMPORAL_RATIO_THRESHOLD = 3.0  # latest >= 3x the seasonal baseline -> spike


def _median(values: list[float]) -> float:
    s = sorted(values)
    n = len(s)
    if n == 0:
        return 0.0
    mid = n // 2
    return s[mid] if n % 2 else (s[mid - 1] + s[mid]) / 2


def _modified_z(value: float, med: float, mad: float) -> float:
    if mad <= 0:
        return 0.0
    return _MAD_SCALE * (value - med) / mad


def _baseline(values: list[float]) -> tuple[float, float]:
    """Return (median, MAD). Falls back to mean-absolute-deviation when MAD is 0
    (happens when over half the samples are identical)."""
    med = _median(values)
    mad = _median([abs(v - med) for v in values])
    if mad <= 0:
        n = len(values)
        mad = (sum(abs(v - med) for v in values) / n) if n else 0.0
    return med, mad


def detect_cost_anomalies(spend_by_agent: dict[str, float], *, z_threshold: float = DEFAULT_Z_THRESHOLD) -> list[dict[str, Any]]:
    """Flag agents whose total spend is a statistical outlier among tenant agents."""
    agents = [a for a in spend_by_agent if a]
    if len(agents) < _MIN_SAMPLES:
        return []
    med, mad = _baseline([spend_by_agent[a] for a in agents])
    out: list[dict[str, Any]] = []
    for agent in agents:
        z = _modified_z(spend_by_agent[agent], med, mad)
        if z >= z_threshold:
            out.append(
                {
                    "type": "cost_spike",
                    "severity": "high" if z >= z_threshold * 1.5 else "medium",
                    "agent": agent,
                    "metric": "total_cost_usd",
                    "value": round(spend_by_agent[agent], 6),
                    "baseline_median": round(med, 6),
                    "z_score": round(z, 2),
                    "recommendation": "Review this agent's spend; consider an enforce-mode budget cap.",
                }
            )
    return sorted(out, key=lambda a: a["z_score"], reverse=True)


def detect_behavior_anomalies(calls_by_session: dict[str, int], *, z_threshold: float = DEFAULT_Z_THRESHOLD) -> list[dict[str, Any]]:
    """Flag sessions whose tool-call volume is a statistical outlier."""
    sessions = [s for s in calls_by_session if s]
    if len(sessions) < _MIN_SAMPLES:
        return []
    med, mad = _baseline([float(calls_by_session[s]) for s in sessions])
    out: list[dict[str, Any]] = []
    for session in sessions:
        z = _modified_z(float(calls_by_session[session]), med, mad)
        if z >= z_threshold:
            out.append(
                {
                    "type": "call_rate_spike",
                    "severity": "high" if z >= z_threshold * 1.5 else "medium",
                    "session_id": session,
                    "metric": "tool_calls",
                    "value": calls_by_session[session],
                    "baseline_median": round(med, 2),
                    "z_score": round(z, 2),
                    "recommendation": "Inspect this session for runaway looping or abuse.",
                }
            )
    return sorted(out, key=lambda a: a["z_score"], reverse=True)


def _parse_bucket(observed_at: str) -> tuple[int, int] | None:
    """Return the (day-of-week, hour) seasonal bucket for an ISO timestamp.

    Day-of-week is 0=Monday..6=Sunday; hour is 0..23 in UTC. Unparseable or
    empty timestamps are skipped (return None) so they never corrupt a baseline.
    """
    raw = (observed_at or "").strip()
    if not raw:
        return None
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    return dt.weekday(), dt.hour


def detect_temporal_cost_anomalies(
    cost_series_by_agent: dict[str, list[tuple[str, float]]],
    *,
    ratio_threshold: float = _TEMPORAL_RATIO_THRESHOLD,
) -> list[dict[str, Any]]:
    """Flag agents spiking against their OWN seasonal history (#2926).

    For each agent the per-call costs are bucketed by (day-of-week, hour) using
    the call timestamp, then summed per chronological bucket. Two signals back
    the verdict:

    - **seasonal-naive**: the latest bucket vs the EWMA of *prior occurrences of
      the same (day, hour) slot* — a predictable nightly peak has a high slot
      baseline, so it stays quiet.
    - **EWMA creep**: the latest bucket vs the EWMA of *all prior buckets* —
      catches a slow upward drift that no single z-score flags.

    A spike is reported only when the latest bucket exceeds ``ratio_threshold``x
    a non-trivial baseline. No peer comparison here; this is purely temporal and
    complements the cross-sectional :func:`detect_cost_anomalies`.
    """
    out: list[dict[str, Any]] = []
    for agent, series in cost_series_by_agent.items():
        if not agent:
            continue
        # Order by timestamp, drop unparseable rows, key each row to its slot.
        rows: list[tuple[str, tuple[int, int], float]] = []
        for observed_at, cost in series:
            bucket = _parse_bucket(observed_at)
            if bucket is None:
                continue
            rows.append((observed_at, bucket, float(cost)))
        if len(rows) < _TEMPORAL_MIN_BUCKETS:
            continue
        rows.sort(key=lambda r: r[0])

        # Collapse consecutive calls sharing one (timestamp-truncated) slot into
        # per-occurrence totals so a busy hour reads as one observation.
        occurrences: list[tuple[str, tuple[int, int], float]] = []
        for observed_at, bucket, cost in rows:
            slot_key = observed_at[:13]  # ISO hour granularity: YYYY-MM-DDTHH
            if occurrences and occurrences[-1][0][:13] == slot_key and occurrences[-1][1] == bucket:
                prev = occurrences[-1]
                occurrences[-1] = (prev[0], prev[1], prev[2] + cost)
            else:
                occurrences.append((observed_at, bucket, cost))
        if len(occurrences) < _TEMPORAL_MIN_BUCKETS:
            continue

        latest_ts, latest_bucket, latest_cost = occurrences[-1]
        history = occurrences[:-1]

        # Seasonal-naive baseline: EWMA over prior occurrences of the same slot.
        same_slot = [c for _, b, c in history if b == latest_bucket]
        seasonal_baseline = _ewma(same_slot) if same_slot else None
        # A value in line with its own slot history is "predictable" (e.g. a
        # nightly batch) — it must not be flagged even though it dwarfs the
        # agent's overall average. The seasonal arm has authority over the
        # cross-slot EWMA creep arm.
        in_seasonal_pattern = seasonal_baseline is not None and seasonal_baseline > 0 and latest_cost < ratio_threshold * seasonal_baseline
        # EWMA creep baseline: EWMA over every prior occurrence.
        creep_baseline = _ewma([c for _, _, c in history])

        signals: list[str] = []
        ratios: dict[str, float] = {}
        if seasonal_baseline is not None and seasonal_baseline > 0 and latest_cost >= ratio_threshold * seasonal_baseline:
            signals.append("seasonal")
            ratios["seasonal_ratio"] = round(latest_cost / seasonal_baseline, 2)
        if not in_seasonal_pattern and creep_baseline > 0 and latest_cost >= ratio_threshold * creep_baseline:
            signals.append("ewma_creep")
            ratios["ewma_ratio"] = round(latest_cost / creep_baseline, 2)
        if not signals:
            continue
        out.append(
            {
                "type": "temporal_cost_spike",
                "severity": "high" if len(signals) == 2 else "medium",
                "agent": agent,
                "metric": "bucket_cost_usd",
                "value": round(latest_cost, 6),
                "bucket": {"day_of_week": latest_bucket[0], "hour": latest_bucket[1]},
                "seasonal_baseline": round(seasonal_baseline, 6) if seasonal_baseline is not None else None,
                "ewma_baseline": round(creep_baseline, 6),
                "signals": signals,
                **ratios,
                "recommendation": "Spend is anomalous vs this agent's own time-of-day history; review for a creep or a one-off surge.",
            }
        )
    return sorted(out, key=lambda a: a.get("ewma_ratio", a.get("seasonal_ratio", 0.0)), reverse=True)


def _ewma(values: list[float], *, alpha: float = _TEMPORAL_EWMA_ALPHA) -> float:
    """Exponentially weighted moving average; newest value weighted ``alpha``."""
    if not values:
        return 0.0
    avg = values[0]
    for v in values[1:]:
        avg = alpha * v + (1 - alpha) * avg
    return avg


def scan_anomalies(tenant_id: str, *, z_threshold: float = DEFAULT_Z_THRESHOLD) -> dict[str, Any]:
    """Run cost + behavior anomaly detection for a tenant from persisted stores."""
    from agent_bom.api.cost_store import get_cost_store
    from agent_bom.api.runtime_event_store import get_runtime_event_store

    spend_by_agent: dict[str, float] = defaultdict(float)
    cost_series_by_agent: dict[str, list[tuple[str, float]]] = defaultdict(list)
    for rec in get_cost_store().list_records(tenant_id, limit=10000):
        if rec.agent:
            spend_by_agent[rec.agent] += rec.cost_usd
            cost_series_by_agent[rec.agent].append((rec.observed_at, rec.cost_usd))

    calls_by_session: dict[str, int] = {}
    for session in get_runtime_event_store().list_sessions(tenant_id, limit=1000):
        count = getattr(session, "observation_count", None)
        if count is None:
            count = len(getattr(session, "tools", []) or [])
        calls_by_session[session.session_id] = int(count or 0)

    cost = detect_cost_anomalies(dict(spend_by_agent), z_threshold=z_threshold)
    behavior = detect_behavior_anomalies(calls_by_session, z_threshold=z_threshold)
    temporal = detect_temporal_cost_anomalies(dict(cost_series_by_agent))
    return {
        "schema_version": "observability.anomalies.v1",
        "tenant_id": tenant_id,
        "z_threshold": z_threshold,
        "cost_anomalies": cost,
        "temporal_cost_anomalies": temporal,
        "behavior_anomalies": behavior,
        "anomaly_count": len(cost) + len(behavior) + len(temporal),
    }


# Brief cache so a hot caller (the gateway relay) can ask "is this agent's spend
# anomalous?" without re-aggregating every record on every call. The TTL bounds
# how stale the signal can be; a spike is still caught within one window.
_COST_ANOMALY_CACHE_TTL_SECONDS = 30.0
_cost_anomaly_cache: dict[str, tuple[float, dict[str, dict[str, Any]]]] = {}
_cost_anomaly_cache_lock = threading.Lock()


def clear_cost_anomaly_cache() -> None:
    """Drop the cost-anomaly cache (tests / explicit refresh)."""
    with _cost_anomaly_cache_lock:
        _cost_anomaly_cache.clear()


def cost_anomalous_agents(
    tenant_id: str,
    *,
    z_threshold: float = DEFAULT_Z_THRESHOLD,
    _now: float | None = None,
) -> dict[str, dict[str, Any]]:
    """Agents whose total spend is anomalous vs the tenant fleet, mapped to their
    anomaly record. Cached per tenant for ``_COST_ANOMALY_CACHE_TTL_SECONDS``."""
    now = _now if _now is not None else time.monotonic()
    with _cost_anomaly_cache_lock:
        cached = _cost_anomaly_cache.get(tenant_id)
        if cached is not None and cached[0] > now:
            return cached[1]
    result = scan_anomalies(tenant_id, z_threshold=z_threshold)
    by_agent = {a["agent"]: a for a in result.get("cost_anomalies", []) if a.get("agent")}
    with _cost_anomaly_cache_lock:
        _cost_anomaly_cache[tenant_id] = (now + _COST_ANOMALY_CACHE_TTL_SECONDS, by_agent)
    return by_agent
