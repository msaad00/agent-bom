"""Configurable executive risk-score engine (issue #3940).

The overview "risk posture" grade was historically a fixed, opaque number. This
module makes it **configurable and honest**: the score is a documented,
weighted penalty model over the *same honest counts* the overview already
reconciles (severity buckets whose sum equals the counted total, KEV,
credential/blast-radius exposure, compliance, and the ``unrated`` bucket added
in the findings-taxonomy work). Because every input is one of those counts, the
grade can never contradict them — a non-zero counted total always carries a
non-zero penalty, so the estate can't read as a clean "A / no vulnerabilities"
while findings are open.

Model shape (all penalty POINTS per unit of the driver's count, not fractions —
this keeps each contribution legible: "3 critical × 12 = 36 points of pressure"):

    critical    12   high        6    medium      2    low        0.5
    unrated      1   kev         8    exposure    5    compliance 6

The per-driver points sum to an unbounded ``pressure = Σ weight[d] × count[d]``
which is then mapped to a 0–100 score through a **diminishing-returns curve**
so the grade discriminates across the full estate size instead of saturating::

    score = 100 × scale / (scale + pressure)      (scale = 70)

This is monotonic (more findings only ever lower the score, never raise it),
scores a genuinely clean estate a perfect 100 (grade A), and — unlike a
``100 − min(100, pressure)`` cap that floors at 0 once ~9 criticals accumulate —
keeps assigning *distinct* failing scores to a 20-critical vs a 2000-critical
estate (both F, but distinguishable). Adopters steepen or soften the curve by
scaling the weights: doubling every weight halves the effective ``scale``. The
letter grade comes from configurable thresholds (default A≥90, B≥80, C≥70, D≥60).

Adopters are not locked onto the defaults. Weights, grade thresholds, and the
display format (``grade`` / ``percent`` / ``points``) can be overridden per
tenant (persisted via :mod:`agent_bom.api.exec_score_config`) or process-wide
via ``AGENT_BOM_EXEC_SCORE_POLICY`` (inline JSON) / ``…_POLICY_FILE`` (path).
Every override path is canonicalized and clamped — bad input never raises, it is
normalized back into range.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

# ── Default weighted inputs ───────────────────────────────────────────────────
# Penalty points removed from a perfect 100 per unit of each honest count. The
# critical/high weights match the existing overview blend (critical×12, high×6)
# so the configurable grade reconciles with the number the overview showed
# before this engine landed.
DEFAULT_EXEC_SCORE_WEIGHTS: dict[str, float] = {
    "critical": 12.0,
    "high": 6.0,
    "medium": 2.0,
    "low": 0.5,
    "unrated": 1.0,
    "kev": 8.0,
    "exposure": 5.0,
    "compliance": 6.0,
}

# Human-facing labels + one-line meaning for each driver (drives the UI
# "what influences this score" breakdown).
DRIVER_LABELS: dict[str, str] = {
    "critical": "Critical findings",
    "high": "High findings",
    "medium": "Medium findings",
    "low": "Low findings",
    "unrated": "Unrated findings",
    "kev": "Known-exploited (KEV)",
    "exposure": "Credential / blast-radius exposure",
    "compliance": "Failing compliance frameworks",
}

# Display order for the breakdown (severity bands first, then amplifiers).
DRIVER_ORDER: tuple[str, ...] = (
    "critical",
    "high",
    "medium",
    "low",
    "unrated",
    "kev",
    "exposure",
    "compliance",
)

# Minimum score (inclusive) for each letter grade; anything below D is F.
DEFAULT_GRADE_THRESHOLDS: dict[str, float] = {
    "A": 90.0,
    "B": 80.0,
    "C": 70.0,
    "D": 60.0,
}

DISPLAY_FORMATS: tuple[str, ...] = ("grade", "percent", "points")
DEFAULT_DISPLAY_FORMAT = "percent"

# A single driver weight is clamped into this range so a hostile / fat-fingered
# override can neither invert the score (negative) nor overflow it.
_MAX_WEIGHT = 100.0
# Diminishing-returns scale for the pressure→score curve
# ``score = 100 × scale / (scale + pressure)``. At ``scale = 70`` the historical
# anchor holds exactly (2 critical + 1 high = 30 pressure → score 70 → grade C),
# a clean estate scores 100, and the score decays toward — but never reaches — 0
# so ever-larger estates keep earning distinct (still-failing) scores.
_PENALTY_SCALE = 70.0


@dataclass(frozen=True)
class ExecScoreConfig:
    """Resolved exec-score policy (defaults + optional adopter overrides)."""

    weights: Mapping[str, float]
    grade_thresholds: Mapping[str, float]
    display_format: str = DEFAULT_DISPLAY_FORMAT
    source: str = "default"

    def to_dict(self) -> dict[str, Any]:
        return {
            "weights": dict(self.weights),
            "grade_thresholds": dict(self.grade_thresholds),
            "display_format": self.display_format,
            "source": self.source,
        }


def _coerce_float(value: object) -> float | None:
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def canonicalize_weights(weights: Mapping[str, Any] | None) -> dict[str, float]:
    """Merge caller weights onto defaults, clamped to ``[0, _MAX_WEIGHT]``.

    Unknown keys are ignored and unparseable / out-of-range values fall back to
    the clamped bound rather than raising, so this never rejects input.
    """
    merged = dict(DEFAULT_EXEC_SCORE_WEIGHTS)
    if weights:
        for key, raw in weights.items():
            if key not in merged:
                continue
            parsed = _coerce_float(raw)
            if parsed is None:
                continue
            merged[key] = round(max(0.0, min(_MAX_WEIGHT, parsed)), 4)
    return merged


def canonicalize_thresholds(thresholds: Mapping[str, Any] | None) -> dict[str, float]:
    """Merge caller thresholds onto defaults and keep A≥B≥C≥D, clamped 0–100."""
    merged = dict(DEFAULT_GRADE_THRESHOLDS)
    if thresholds:
        for key, raw in thresholds.items():
            letter = str(key).upper()
            if letter not in merged:
                continue
            parsed = _coerce_float(raw)
            if parsed is None:
                continue
            merged[letter] = max(0.0, min(100.0, parsed))
    # Enforce monotonic ordering A≥B≥C≥D so grade bands never cross.
    ordered_letters = ("A", "B", "C", "D")
    ceiling = 100.0
    for letter in ordered_letters:
        merged[letter] = min(merged[letter], ceiling)
        ceiling = merged[letter]
    return merged


def canonicalize_display_format(value: object) -> str:
    fmt = str(value or "").strip().lower()
    return fmt if fmt in DISPLAY_FORMATS else DEFAULT_DISPLAY_FORMAT


def canonicalize_config(payload: Mapping[str, Any] | None) -> dict[str, Any]:
    """Canonicalize an arbitrary override payload into a persistable config dict.

    Always returns a full, valid config (never raises). Only fields present in
    ``payload`` override the defaults; the rest fall through to defaults.
    """
    payload = payload or {}
    return {
        "weights": canonicalize_weights(payload.get("weights") if isinstance(payload.get("weights"), Mapping) else None),
        "grade_thresholds": canonicalize_thresholds(
            payload.get("grade_thresholds")
            if isinstance(payload.get("grade_thresholds"), Mapping)
            else (payload.get("thresholds") if isinstance(payload.get("thresholds"), Mapping) else None)
        ),
        "display_format": canonicalize_display_format(payload.get("display_format")),
    }


def _env_payload() -> tuple[dict[str, Any] | None, str]:
    raw = os.environ.get("AGENT_BOM_EXEC_SCORE_POLICY", "").strip()
    file_path = os.environ.get("AGENT_BOM_EXEC_SCORE_POLICY_FILE", "").strip()
    if raw:
        try:
            loaded = json.loads(raw)
            if isinstance(loaded, dict):
                return loaded, "env:AGENT_BOM_EXEC_SCORE_POLICY"
        except json.JSONDecodeError:
            return None, "default"
    elif file_path:
        try:
            loaded = json.loads(Path(file_path).read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                return loaded, f"file:{file_path}"
        except (OSError, json.JSONDecodeError):
            return None, "default"
    return None, "default"


def load_exec_score_config(overrides: Mapping[str, Any] | None = None) -> ExecScoreConfig:
    """Resolve config as defaults < env policy < tenant ``overrides``.

    ``overrides`` is a (possibly partial) persisted tenant config. Any layer may
    supply any subset of ``weights`` / ``grade_thresholds`` / ``display_format``;
    later layers win field-by-field. The result is always canonical.
    """
    weights: dict[str, Any] = {}
    thresholds: dict[str, Any] = {}
    display_format: object = None
    source = "default"

    env_payload, env_source = _env_payload()
    if env_payload:
        source = env_source
        if isinstance(env_payload.get("weights"), Mapping):
            weights.update(env_payload["weights"])
        env_thresholds = env_payload.get("grade_thresholds") or env_payload.get("thresholds")
        if isinstance(env_thresholds, Mapping):
            thresholds.update(env_thresholds)
        if env_payload.get("display_format") is not None:
            display_format = env_payload["display_format"]

    if overrides:
        source = "tenant_override" if source == "default" else f"{source}+tenant_override"
        if isinstance(overrides.get("weights"), Mapping):
            weights.update(overrides["weights"])
        ov_thresholds = overrides.get("grade_thresholds") or overrides.get("thresholds")
        if isinstance(ov_thresholds, Mapping):
            thresholds.update(ov_thresholds)
        if overrides.get("display_format") is not None:
            display_format = overrides["display_format"]

    return ExecScoreConfig(
        weights=canonicalize_weights(weights or None),
        grade_thresholds=canonicalize_thresholds(thresholds or None),
        display_format=canonicalize_display_format(display_format),
        source=source,
    )


def score_to_grade(score: float, thresholds: Mapping[str, float] | None = None) -> str:
    bands = thresholds or DEFAULT_GRADE_THRESHOLDS
    if score >= float(bands.get("A", 90)):
        return "A"
    if score >= float(bands.get("B", 80)):
        return "B"
    if score >= float(bands.get("C", 70)):
        return "C"
    if score >= float(bands.get("D", 60)):
        return "D"
    return "F"


def _format_display(score: float, grade: str, display_format: str) -> str:
    rounded = int(round(score))
    if display_format == "grade":
        return f"Grade {grade}"
    if display_format == "points":
        return f"{rounded} / 100"
    return f"{rounded}%"


def compute_exec_score(
    *,
    severity: Mapping[str, int],
    kev: int = 0,
    exposure: int = 0,
    compliance_failing: int = 0,
    config: ExecScoreConfig | None = None,
    floor_score: float | None = None,
    floor_summary: str | None = None,
) -> dict[str, Any]:
    """Compute the configurable exec risk score from honest estate counts.

    Args:
        severity: histogram with ``critical/high/medium/low/unrated`` counts
            (the same reconciled buckets the overview exposes; sum == total).
        kev: number of known-exploited findings (amplifier).
        exposure: number of findings touching exposed credentials / secrets.
        compliance_failing: number of failing compliance frameworks.
        config: resolved :class:`ExecScoreConfig` (defaults when omitted).
        floor_score: an authoritative scan scorecard score, if any. The final
            score is the *worst* (``min``) of the count-derived score and this
            floor, so an existing failing scorecard can never be laundered
            upward by a benign count and ingested evidence only moves down.
        floor_summary: the scan scorecard's own summary (used only when there
            are zero open findings so the blurb explains what graded the estate).

    Returns a JSON-friendly dict with ``grade``, ``score``, ``points``,
    ``percent``, ``display``/``display_format``, per-driver ``breakdown``,
    ``penalty_total``, ``summary``, and the active ``weights``/``thresholds``.
    """
    cfg = config or load_exec_score_config()
    weights = cfg.weights

    counts: dict[str, int] = {
        "critical": max(0, int(severity.get("critical", 0) or 0)),
        "high": max(0, int(severity.get("high", 0) or 0)),
        "medium": max(0, int(severity.get("medium", 0) or 0)),
        "low": max(0, int(severity.get("low", 0) or 0)),
        "unrated": max(0, int(severity.get("unrated", 0) or 0)),
        "kev": max(0, int(kev or 0)),
        "exposure": max(0, int(exposure or 0)),
        "compliance": max(0, int(compliance_failing or 0)),
    }
    finding_total = counts["critical"] + counts["high"] + counts["medium"] + counts["low"] + counts["unrated"]

    breakdown: list[dict[str, Any]] = []
    pressure = 0.0
    for driver in DRIVER_ORDER:
        weight = float(weights.get(driver, 0.0))
        count = counts[driver]
        contribution = round(weight * count, 2)
        pressure += weight * count
        breakdown.append(
            {
                "driver": driver,
                "label": DRIVER_LABELS[driver],
                "count": count,
                "weight": round(weight, 4),
                "contribution": contribution,
            }
        )

    # Diminishing-returns curve: unbounded pressure maps to a (0, 100] score that
    # never floors at 0, so a 20-critical and a 2000-critical estate stay
    # distinguishable instead of both saturating to F/0. score(0) == 100.
    count_score = max(0.0, round(100.0 * _PENALTY_SCALE / (_PENALTY_SCALE + pressure), 1))
    # Effective points removed to reach the count score (score + penalty == 100).
    penalty = round(100.0 - count_score, 1)

    has_evidence = floor_score is not None or finding_total > 0 or counts["kev"] > 0 or counts["exposure"] > 0 or counts["compliance"] > 0

    if not has_evidence:
        return {
            "grade": "N/A",
            "score": 0.0,
            "points": 0.0,
            "percent": 0,
            "display_format": cfg.display_format,
            "display": None,
            "summary": "Awaiting evidence — connect a surface or run a scan to grade posture.",
            "policy_source": cfg.source,
            "weights": dict(weights),
            "grade_thresholds": dict(cfg.grade_thresholds),
            "breakdown": breakdown,
            "penalty_total": 0.0,
            "floored": False,
            "finding_total": 0,
        }

    if floor_score is not None:
        final_score = min(count_score, round(float(floor_score), 1))
        floored = final_score < count_score
    else:
        final_score = count_score
        floored = False

    grade = score_to_grade(final_score, cfg.grade_thresholds)
    summary = _build_summary(
        grade=grade,
        score=final_score,
        counts=counts,
        finding_total=finding_total,
        floor_summary=floor_summary,
    )

    return {
        "grade": grade,
        "score": final_score,
        "points": final_score,
        "percent": int(round(final_score)),
        "display_format": cfg.display_format,
        "display": _format_display(final_score, grade, cfg.display_format),
        "summary": summary,
        "policy_source": cfg.source,
        "weights": dict(weights),
        "grade_thresholds": dict(cfg.grade_thresholds),
        "breakdown": breakdown,
        "penalty_total": round(penalty, 1),
        "floored": floored,
        "finding_total": finding_total,
    }


def _build_summary(
    *,
    grade: str,
    score: float,
    counts: Mapping[str, int],
    finding_total: int,
    floor_summary: str | None,
) -> str:
    """Honest one-line blurb. Never claims 'no vulnerabilities' when total > 0."""
    score_txt = f"{grade} · {int(round(score))}%"
    if finding_total > 0:
        bits: list[str] = []
        if counts["critical"]:
            bits.append(f"{counts['critical']} critical")
        if counts["high"]:
            bits.append(f"{counts['high']} high")
        if counts["kev"]:
            bits.append(f"{counts['kev']} KEV")
        if counts["exposure"]:
            bits.append(f"{counts['exposure']} touch secrets")
        lead = " · ".join(bits) if bits else f"{finding_total} finding(s)"
        return f"{score_txt} — {lead} across connected surfaces."
    # No open findings but still graded: a scan ran (floor present). Explain what
    # graded it instead of asserting a clean "no vulnerabilities / strong" line.
    if floor_summary:
        cleaned = floor_summary.strip()
        if cleaned:
            return f"{score_txt} — {cleaned}"
    return f"{score_txt} — no open findings across connected surfaces."
