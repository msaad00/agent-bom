"""LLM spend burn-rate forecasting and budget-runway projection.

Tracking (:mod:`agent_bom.api.cost_store`) and enforcement
(:func:`agent_bom.api.cost_store.check_budget_enforcement`) make spend
*visible and stoppable*; this module makes it *predictable*. Persisted cost
records carry ``observed_at`` timestamps, so a forward projection is derivable
without any new dependency: bucket spend by time window, take a robust recent
burn rate, and extrapolate to the configured budget and to the end of the
billing period.

The math is deliberately simple and operator-readable (matching
:mod:`agent_bom.api.anomaly`): no model, no heavy deps. A forecast is an
estimate, never an enforcement input — it never blocks a call and never raises
on sparse/empty/garbage history; it returns nulls with a clear ``status``.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from datetime import datetime, timezone
from typing import Any

from agent_bom.api.cost_store import CostBudget, LLMCostRecord

# Trailing windows for the burn-rate estimate, in hours. The shorter window
# reacts fast to a fresh spike; the longer one smooths out diurnal noise. We
# take the more conservative (higher) of the two daily rates so a budget runway
# never over-promises during an acceleration.
_WINDOW_24H = 24.0
_WINDOW_7D = 24.0 * 7.0

_HOURS_PER_DAY = 24.0
_MIN_RECORDS = 2
# A runway beyond this many days is reported as "ample" rather than a precise
# figure — extrapolating a tiny burn rate years out is noise, not signal.
_MAX_RUNWAY_DAYS = 3650.0


def _parse_ts(value: str) -> datetime | None:
    """Parse an ISO-8601 ``observed_at`` into an aware UTC datetime, or None.

    Tolerates a trailing ``Z`` and naive timestamps (assumed UTC). Never raises
    — an unparseable record is simply skipped from the projection.
    """
    text = (value or "").strip()
    if not text:
        return None
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _window_spend(timed: Sequence[tuple[datetime, float]], now: datetime, hours: float) -> tuple[float, float]:
    """Sum spend within ``hours`` before ``now``.

    Returns ``(spend_in_window, observed_span_hours)`` where the observed span
    is clamped to the actual data so a single record an hour into a 24h window
    yields an hourly — not a daily — rate, never inflating runway by treating a
    partly-empty window as if it were full.
    """
    cutoff = now.timestamp() - hours * 3600.0
    in_window = [(ts, cost) for ts, cost in timed if ts.timestamp() >= cutoff]
    if not in_window:
        return 0.0, 0.0
    spend = sum(cost for _, cost in in_window)
    earliest = min(ts.timestamp() for ts, _ in in_window)
    observed_hours = max((now.timestamp() - earliest) / 3600.0, 0.0)
    return spend, observed_hours


def _daily_rate(spend: float, observed_hours: float) -> float | None:
    """Spend-per-day from a window, or None when the span is too short to divide."""
    if observed_hours <= 0.0 or spend <= 0.0:
        return None
    return spend / observed_hours * _HOURS_PER_DAY


def _period_bounds(now: datetime) -> tuple[datetime, datetime, float]:
    """Calendar-month billing period containing ``now``.

    Returns ``(period_start, period_end, hours_remaining)``. A calendar month is
    the default budget cadence; without a configured reset day it is the most
    defensible window and matches how spend caps are reasoned about.
    """
    start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    if start.month == 12:
        end = start.replace(year=start.year + 1, month=1)
    else:
        end = start.replace(month=start.month + 1)
    hours_remaining = max((end.timestamp() - now.timestamp()) / 3600.0, 0.0)
    return start, end, hours_remaining


def _round(value: float | None, digits: int = 6) -> float | None:
    return round(value, digits) if value is not None else None


def forecast_spend(
    records: Iterable[LLMCostRecord],
    *,
    budget: CostBudget | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Project burn rate, period spend, and budget runway from cost records.

    Parameters mirror the cost-store surface: a record iterable (already tenant-
    and, where applicable, agent-scoped by the caller), the budget those records
    are measured against, and an optional ``now`` for deterministic tests.

    The returned ``status`` is one of:
      - ``"insufficient_history"`` — fewer than two timestamped records; every
        projection field is null.
      - ``"budget_exceeded"`` — current spend is already at or over the cap;
        ``days_remaining`` is ``0.0`` and exhaustion is ``"now"``-dated.
      - ``"no_budget"`` — a burn rate exists but no cap is configured, so there
        is nothing to exhaust (runway is null).
      - ``"stale"`` — records exist but none fall inside the trailing windows,
        so no current rate can be derived.
      - ``"ok"`` — a positive burn rate and a configured cap yield a runway.
    """
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)

    timed: list[tuple[datetime, float]] = []
    total_spend = 0.0
    for rec in records:
        total_spend += rec.cost_usd
        ts = _parse_ts(rec.observed_at)
        if ts is not None:
            timed.append((ts, rec.cost_usd))

    limit = budget.limit_usd if budget is not None else None
    base = {
        "schema_version": "observability.cost_forecast.v1",
        "agent": (budget.agent or None) if budget is not None else None,
        "now": now.isoformat(),
        "current_spend_usd": _round(total_spend),
        "budget_limit_usd": limit,
        "burn_rate_usd_per_day": None,
        "burn_rate_basis": None,
        "projected_period_spend_usd": None,
        "period_start": None,
        "period_end": None,
        "days_remaining": None,
        "projected_exhaustion_at": None,
    }

    if len(timed) < _MIN_RECORDS:
        base["status"] = "insufficient_history"
        return base

    period_start, period_end, hours_remaining = _period_bounds(now)
    base["period_start"] = period_start.isoformat()
    base["period_end"] = period_end.isoformat()

    # Budget already blown: the runway is gone regardless of the current rate.
    # A zero cap is a hard cap — any spend exceeds it (mirrors budget_status).
    already_exceeded = limit is not None and (total_spend >= limit if limit > 0.0 else total_spend > 0.0)
    if already_exceeded:
        base["status"] = "budget_exceeded"
        base["days_remaining"] = 0.0
        base["projected_exhaustion_at"] = now.isoformat()
        # Still surface a rate so the caller can see how fast it overran.
        rate, basis = _best_daily_rate(timed, now)
        base["burn_rate_usd_per_day"] = _round(rate)
        base["burn_rate_basis"] = basis
        if rate is not None:
            base["projected_period_spend_usd"] = _round(total_spend + rate * hours_remaining / _HOURS_PER_DAY)
        return base

    rate, basis = _best_daily_rate(timed, now)
    base["burn_rate_usd_per_day"] = _round(rate)
    base["burn_rate_basis"] = basis

    if rate is None:
        # Records exist but all fall outside the trailing windows.
        base["status"] = "stale"
        return base

    base["projected_period_spend_usd"] = _round(total_spend + rate * hours_remaining / _HOURS_PER_DAY)

    if limit is None:
        base["status"] = "no_budget"
        return base

    remaining_budget = limit - total_spend
    days = remaining_budget / rate if rate > 0.0 else _MAX_RUNWAY_DAYS
    days = max(0.0, min(days, _MAX_RUNWAY_DAYS))
    base["days_remaining"] = round(days, 4)
    exhaustion = now.timestamp() + days * _HOURS_PER_DAY * 3600.0
    base["projected_exhaustion_at"] = datetime.fromtimestamp(exhaustion, tz=timezone.utc).isoformat()
    base["status"] = "ok"
    return base


def _best_daily_rate(timed: Sequence[tuple[datetime, float]], now: datetime) -> tuple[float | None, str | None]:
    """Conservative daily burn rate from the trailing 24h and 7d windows.

    Takes the higher of the two daily rates so an accelerating burn shortens the
    projected runway rather than masking the spike under a calmer 7-day average.
    """
    r24 = _daily_rate(*_window_spend(timed, now, _WINDOW_24H))
    r7d = _daily_rate(*_window_spend(timed, now, _WINDOW_7D))
    candidates = [(r, label) for r, label in ((r24, "trailing_24h"), (r7d, "trailing_7d")) if r is not None]
    if not candidates:
        return None, None
    return max(candidates, key=lambda c: c[0])


def forecast_for_tenant(tenant_id: str, *, agent: str | None = None, limit: int = 10000) -> dict[str, Any]:
    """Build a spend forecast for a tenant (optionally one agent) from the store.

    Resolves an agent-scoped budget first, falling back to the tenant-wide cap —
    the same precedence enforcement uses — so the runway is measured against the
    cap that would actually block the agent.
    """
    from agent_bom.api.cost_store import get_cost_store

    store = get_cost_store()
    records = store.list_records(tenant_id, limit=max(1, min(limit, 100000)))
    if agent:
        records = [r for r in records if r.agent == agent]
    budget = store.get_budget(tenant_id, agent or "")
    if budget is None and agent:
        budget = store.get_budget(tenant_id, "")
    result = forecast_spend(records, budget=budget)
    result["tenant_id"] = tenant_id
    return result
