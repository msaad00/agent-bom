"""Runtime posture for external vulnerability enrichment sources."""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

_DEFAULT_SOURCE_SLOS_SECONDS = {
    "osv": 6 * 60 * 60,
    "nvd": 24 * 60 * 60,
    "epss": 24 * 60 * 60,
    "cisa_kev": 24 * 60 * 60,
    "ghsa": 24 * 60 * 60,
}


@dataclass
class EnrichmentSourceState:
    source: str
    last_success_at: str | None = None
    last_failure_at: str | None = None
    last_cache_at: str | None = None
    last_error: str = ""
    success_count: int = 0
    failure_count: int = 0
    cache_hit_count: int = 0
    consecutive_failure_count: int = 0
    circuit_opened_at: str | None = None
    circuit_open_until: str | None = None


_lock = threading.RLock()
_states: dict[str, EnrichmentSourceState] = {}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _source_slo_seconds(source: str) -> int:
    env_name = f"AGENT_BOM_ENRICHMENT_{source.upper()}_SLO_SECONDS"
    raw = (os.environ.get(env_name) or "").strip()
    if raw:
        try:
            return max(60, int(raw))
        except ValueError:
            pass
    return _DEFAULT_SOURCE_SLOS_SECONDS.get(source, 24 * 60 * 60)


def _source_failure_threshold(source: str) -> int:
    env_name = f"AGENT_BOM_ENRICHMENT_{source.upper()}_CIRCUIT_FAILURES"
    raw = (os.environ.get(env_name) or "").strip()
    if raw:
        try:
            return max(1, int(raw))
        except ValueError:
            pass
    return 3


def _source_circuit_open_seconds(source: str) -> int:
    env_name = f"AGENT_BOM_ENRICHMENT_{source.upper()}_CIRCUIT_OPEN_SECONDS"
    raw = (os.environ.get(env_name) or "").strip()
    if raw:
        try:
            return max(60, int(raw))
        except ValueError:
            pass
    return 5 * 60


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def record_enrichment_source(source: str, outcome: str, *, error: str = "") -> None:
    """Record the latest result for an enrichment source.

    ``outcome`` is one of ``success``, ``failure``, or ``cache``. Unknown
    outcomes are treated as failures to keep operator posture conservative.
    """

    normalized = source.strip().lower().replace("-", "_")
    if not normalized:
        return
    timestamp = _now_iso()
    with _lock:
        state = _states.setdefault(normalized, EnrichmentSourceState(source=normalized))
        if outcome == "success":
            state.last_success_at = timestamp
            state.last_error = ""
            state.success_count += 1
            state.consecutive_failure_count = 0
            state.circuit_opened_at = None
            state.circuit_open_until = None
        elif outcome == "cache":
            state.last_cache_at = timestamp
            state.cache_hit_count += 1
        else:
            state.last_failure_at = timestamp
            state.last_error = str(error).replace("\r", " ").replace("\n", " ").strip()[:300]
            state.failure_count += 1
            state.consecutive_failure_count += 1
            if state.consecutive_failure_count >= _source_failure_threshold(normalized):
                open_until = datetime.now(timezone.utc).timestamp() + _source_circuit_open_seconds(normalized)
                state.circuit_opened_at = timestamp
                state.circuit_open_until = datetime.fromtimestamp(open_until, tz=timezone.utc).isoformat()


def enrichment_source_available(source: str) -> bool:
    """Return False when a source circuit is open.

    Callers should skip non-critical enrichment requests while this is false.
    Cached data can still be used and should be recorded with outcome ``cache``.
    """

    normalized = source.strip().lower().replace("-", "_")
    if not normalized:
        return True
    now = datetime.now(timezone.utc)
    with _lock:
        state = _states.get(normalized)
        if state is None:
            return True
        open_until = _parse_iso(state.circuit_open_until)
        if open_until is None:
            return True
        if open_until <= now:
            state.circuit_open_until = None
            state.circuit_opened_at = None
            return True
        return False


def reset_enrichment_posture_for_tests() -> None:
    with _lock:
        _states.clear()


def describe_enrichment_posture() -> dict[str, Any]:
    """Return non-secret enrichment source health and freshness posture."""

    now = datetime.now(timezone.utc)
    with _lock:
        sources = {name: EnrichmentSourceState(**vars(state)) for name, state in _states.items()}

    rows: list[dict[str, Any]] = []
    for source in sorted(set(_DEFAULT_SOURCE_SLOS_SECONDS) | set(sources)):
        state = sources.get(source, EnrichmentSourceState(source=source))
        last_good = max(
            [dt for dt in (_parse_iso(state.last_success_at), _parse_iso(state.last_cache_at)) if dt is not None],
            default=None,
        )
        last_failure = _parse_iso(state.last_failure_at)
        age_seconds = int((now - last_good).total_seconds()) if last_good else None
        slo_seconds = _source_slo_seconds(source)
        if _parse_iso(state.circuit_open_until) and not enrichment_source_available(source):
            status = "circuit_open"
            message = "enrichment source circuit is open after consecutive failures"
        elif last_failure and (last_good is None or last_failure >= last_good):
            status = "degraded"
            message = state.last_error or "latest enrichment attempt failed"
        elif age_seconds is None:
            status = "unknown"
            message = "no enrichment source result recorded in this process"
        elif age_seconds > slo_seconds:
            status = "stale"
            message = f"last successful enrichment is older than configured SLO ({slo_seconds}s)"
        else:
            status = "ok"
            message = "latest enrichment source result is within SLO"
        rows.append(
            {
                "source": source,
                "status": status,
                "last_success_at": state.last_success_at,
                "last_failure_at": state.last_failure_at,
                "last_cache_at": state.last_cache_at,
                "age_seconds": age_seconds,
                "slo_seconds": slo_seconds,
                "success_count": state.success_count,
                "failure_count": state.failure_count,
                "cache_hit_count": state.cache_hit_count,
                "consecutive_failure_count": state.consecutive_failure_count,
                "circuit_opened_at": state.circuit_opened_at,
                "circuit_open_until": state.circuit_open_until,
                "circuit_failure_threshold": _source_failure_threshold(source),
                "circuit_open_seconds": _source_circuit_open_seconds(source),
                "message": message,
            }
        )

    worst_order = {"circuit_open": 0, "degraded": 1, "stale": 2, "unknown": 3, "ok": 4}
    worst = min(rows, key=lambda item: worst_order.get(str(item["status"]), 0)) if rows else None
    return {
        "status": worst["status"] if worst else "unknown",
        "sources": rows,
        "operator_message": (
            "Enrichment posture is process-local runtime evidence. Pair it with cache freshness and scan warnings "
            "when interpreting KEV, EPSS, NVD, GHSA, and OSV-derived risk scores."
        ),
    }
