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
from typing import Any

# Modified z-score (median + MAD) threshold. Robust to the outlier inflating its
# own baseline — a plain mean/std z-score caps a single outlier below 3 in small
# samples, so it would never flag the very runaway agent we care about.
DEFAULT_Z_THRESHOLD = 3.5
_MIN_SAMPLES = 4
_MAD_SCALE = 0.6745  # 0.75 quantile of the standard normal


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


def scan_anomalies(tenant_id: str, *, z_threshold: float = DEFAULT_Z_THRESHOLD) -> dict[str, Any]:
    """Run cost + behavior anomaly detection for a tenant from persisted stores."""
    from agent_bom.api.cost_store import get_cost_store
    from agent_bom.api.runtime_event_store import get_runtime_event_store

    spend_by_agent: dict[str, float] = defaultdict(float)
    for rec in get_cost_store().list_records(tenant_id, limit=10000):
        if rec.agent:
            spend_by_agent[rec.agent] += rec.cost_usd

    calls_by_session: dict[str, int] = {}
    for session in get_runtime_event_store().list_sessions(tenant_id, limit=1000):
        count = getattr(session, "observation_count", None)
        if count is None:
            count = len(getattr(session, "tools", []) or [])
        calls_by_session[session.session_id] = int(count or 0)

    cost = detect_cost_anomalies(dict(spend_by_agent), z_threshold=z_threshold)
    behavior = detect_behavior_anomalies(calls_by_session, z_threshold=z_threshold)
    return {
        "schema_version": "observability.anomalies.v1",
        "tenant_id": tenant_id,
        "z_threshold": z_threshold,
        "cost_anomalies": cost,
        "behavior_anomalies": behavior,
        "anomaly_count": len(cost) + len(behavior),
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
