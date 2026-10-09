"""Score deltas for the three-state AST symbol-reachability signal.

Pure policy shared by finding triage and effective-reach scoring; it has no
dependency outside ``agent_bom.core`` so domain models can use it directly.
"""

from __future__ import annotations

# Three-state AST signal. Ordered most-specific (most reachable) first.
FUNCTION_REACHABLE = "function_reachable"
PACKAGE_REACHABLE = "package_reachable"
UNREACHABLE = "unreachable"

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
    """Return the additive delta for :func:`agent_bom.core.exploitability.fused_triage_priority`."""
    state = _normalize_symbol_state(symbol_reachability)
    if state is None:
        return 0.0
    return _TRIAGE_DELTA[state]
