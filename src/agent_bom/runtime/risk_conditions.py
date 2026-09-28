"""Finite evidence is required to satisfy a configured runtime risk constraint."""

from __future__ import annotations

import math
from collections.abc import Mapping


def _finite_number(value: object) -> bool:
    if isinstance(value, bool):
        return False
    return isinstance(value, int) or (isinstance(value, float) and math.isfinite(value))


def evaluate_risk_conditions(conditions: Mapping[str, object], score: float | None) -> tuple[bool, str]:
    for name, minimum in (("min_risk_score", True), ("max_risk_score", False)):
        if name not in conditions:
            continue
        bound = conditions[name]
        if not _finite_number(bound) or not _finite_number(score):
            return False, "risk constraint requires a finite score and bound"
        assert isinstance(bound, (int, float)) and isinstance(score, (int, float))
        if minimum and score < bound:
            return False, f"risk score below required minimum {bound}"
        if not minimum and score > bound:
            return False, f"risk score above permitted maximum {bound}"
    return True, ""
