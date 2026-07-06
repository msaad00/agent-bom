"""Triage adjustments driven by AST symbol-level reachability.

``symbol_reachability`` is stamped on ``BlastRadius`` rows after
``--project`` AST analysis. This module turns the three-state signal into
deterministic score nudges and VEX posture — without fabricating
``function_reachable`` when advisory symbol data is absent.
"""

from __future__ import annotations

from typing import Any, Literal

from agent_bom.reachability_cve import FUNCTION_REACHABLE, PACKAGE_REACHABLE, UNREACHABLE

# Effective-reach composite deltas (0..100 scale). Chosen so a green-band
# finding with AST ``unreachable`` drops below 30 and a borderline amber
# ``function_reachable`` finding can cross into red when combined with
# existing graph signals.
_COMPOSITE_DELTA: dict[str, float] = {
    FUNCTION_REACHABLE: 15.0,
    PACKAGE_REACHABLE: 0.0,
    UNREACHABLE: -30.0,
}

# Fused triage priority deltas (0..100 scale, separate formula).
_TRIAGE_DELTA: dict[str, float] = {
    FUNCTION_REACHABLE: 12.0,
    PACKAGE_REACHABLE: 0.0,
    UNREACHABLE: -12.0,
}


def _normalize_symbol_state(symbol_reachability: str | None) -> str | None:
    if not symbol_reachability:
        return None
    state = str(symbol_reachability).strip().lower()
    if state in _COMPOSITE_DELTA:
        return state
    return None


def composite_delta(symbol_reachability: str | None) -> float:
    """Return the additive delta for an effective-reach composite score."""
    state = _normalize_symbol_state(symbol_reachability)
    if state is None:
        return 0.0
    return _COMPOSITE_DELTA[state]


def triage_delta(symbol_reachability: str | None) -> float:
    """Return the additive delta for :func:`exploitability.fused_triage_priority`."""
    state = _normalize_symbol_state(symbol_reachability)
    if state is None:
        return 0.0
    return _TRIAGE_DELTA[state]


def band_from_composite(composite: float) -> Literal["green", "amber", "red", "pulsing-red"]:
    """Mirror :class:`effective_reach.ReachScore` band thresholds."""
    if composite >= 90.0:
        return "pulsing-red"
    if composite > 70.0:
        return "red"
    if composite > 30.0:
        return "amber"
    return "green"


def apply_composite_delta(score: float, symbol_reachability: str | None) -> float:
    """Clamp an effective-reach composite after symbol-reach adjustment."""
    state = _normalize_symbol_state(symbol_reachability)
    if state is None:
        return score
    adjusted = score + composite_delta(state)
    return round(max(0.0, min(adjusted, 100.0)), 2)


def adjust_effective_reach_breakdown(
    breakdown: dict[str, Any],
    symbol_reachability: str | None,
) -> dict[str, Any]:
    """Return a copy of an effective-reach breakdown with symbol adjustment applied."""
    if not breakdown:
        return breakdown
    state = _normalize_symbol_state(symbol_reachability)
    if state is None:
        return breakdown
    out = dict(breakdown)
    try:
        base = float(out.get("composite") or 0.0)
    except (TypeError, ValueError):
        base = 0.0
    composite = apply_composite_delta(base, state)
    out["composite"] = composite
    out["band"] = band_from_composite(composite)
    out["symbol_reachability"] = state
    delta = composite_delta(state)
    if delta:
        out["symbol_reach_adjustment"] = delta
    return out


def symbol_reachability_from_payload(payload: dict[str, Any]) -> str | None:
    """Read ``symbol_reachability`` from a finding or blast-radius dict."""
    raw = payload.get("symbol_reachability")
    if raw is None:
        evidence = payload.get("evidence")
        if isinstance(evidence, dict):
            raw = evidence.get("symbol_reachability")
    return _normalize_symbol_state(str(raw) if raw is not None else None)


__all__ = [
    "adjust_effective_reach_breakdown",
    "apply_composite_delta",
    "band_from_composite",
    "composite_delta",
    "symbol_reachability_from_payload",
    "triage_delta",
]
