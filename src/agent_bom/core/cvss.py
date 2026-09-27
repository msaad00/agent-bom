"""Canonical CVSS score validation and vector parsing with lazy optional scoring."""

from __future__ import annotations

import logging
import math
from typing import Any, Optional

from agent_bom.core.severity import Severity

_logger = logging.getLogger(__name__)


def cvss_to_severity(score: Optional[float]) -> Severity:
    score = normalize_cvss_score(score)
    if score is None:
        return Severity.UNKNOWN
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0:
        return Severity.LOW
    return Severity.NONE


_CVSS3_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}


_CVSS3_AC = {"L": 0.77, "H": 0.44}


_CVSS3_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}


_CVSS3_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}


_CVSS3_UI = {"N": 0.85, "R": 0.62}


_CVSS3_CIA = {"N": 0.00, "L": 0.22, "H": 0.56}


def parse_cvss4_vector(vector: str) -> Optional[float]:
    """Score CVSS 4.0 with its macrovector algorithm, not v3-style weights."""
    try:
        from cvss import CVSS4

        return float(CVSS4(vector.strip()).scores()[0])
    except Exception:  # noqa: BLE001
        _logger.debug("CVSS 4.0 vector parse failed")
        return None


def parse_cvss_vector(vector: str) -> Optional[float]:
    """Compute CVSS base score from a vector string (v3.x and v4.0)."""
    try:
        vector = vector.strip()
        if vector.startswith("CVSS:4"):
            return parse_cvss4_vector(vector)
        if not vector.startswith("CVSS:3"):
            return None

        parts = vector.split("/")[1:]
        metrics = dict(p.split(":") for p in parts)

        av = _CVSS3_AV.get(metrics.get("AV", ""), None)
        ac = _CVSS3_AC.get(metrics.get("AC", ""), None)
        scope = metrics.get("S", "U")
        pr_map = _CVSS3_PR_C if scope == "C" else _CVSS3_PR_U
        pr = pr_map.get(metrics.get("PR", ""), None)
        ui = _CVSS3_UI.get(metrics.get("UI", ""), None)
        c = _CVSS3_CIA.get(metrics.get("C", ""), None)
        i = _CVSS3_CIA.get(metrics.get("I", ""), None)
        a = _CVSS3_CIA.get(metrics.get("A", ""), None)

        if any(value is None for value in (av, ac, pr, ui, c, i, a)):
            return None

        av, ac, pr, ui = float(av), float(ac), float(pr), float(ui)  # type: ignore[arg-type]
        c, i, a = float(c), float(i), float(a)  # type: ignore[arg-type]

        isc_base = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a)
        if scope == "C":
            isc = 7.52 * (isc_base - 0.029) - 3.25 * ((isc_base - 0.02) ** 15)
        else:
            isc = 6.42 * isc_base

        if isc <= 0:
            return 0.0

        exploitability = 8.22 * av * ac * pr * ui
        raw = min(1.08 * (isc + exploitability), 10.0) if scope == "C" else min(isc + exploitability, 10.0)
        return math.ceil(raw * 10) / 10.0
    except Exception:  # noqa: BLE001
        _logger.debug("CVSS vector parse failed")
        return None


def normalize_cvss_score(value: Any) -> Optional[float]:
    """Extract a 0-10 CVSS score from common OSV/vendor record shapes."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        score = float(value)
        return score if 0.0 <= score <= 10.0 else None
    if isinstance(value, str):
        try:
            score = float(value)
            return score if 0.0 <= score <= 10.0 else None
        except ValueError:
            computed = parse_cvss_vector(value)
            return computed if computed is not None and 0.0 <= computed <= 10.0 else None
    if isinstance(value, dict):
        for key in ("score", "baseScore", "base_score", "cvss", "vector", "vectorString"):
            nested_score = normalize_cvss_score(value.get(key))
            if nested_score is not None:
                return nested_score
    if isinstance(value, list):
        scores = [normalize_cvss_score(item) for item in value]
        valid_scores = [score for score in scores if score is not None]
        if valid_scores:
            return max(valid_scores)
    return None
