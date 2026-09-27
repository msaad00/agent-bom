"""``/v1/posture`` served from the one exec posture computation.

The overview's configurable exec score (issue-group severity, KEV, credential
exposure, failing frameworks, floored by the scan-time scorecard) is the
tenant's posture grade. ``/v1/posture`` returns that same grade, score and
summary; the scan-time scorecard remains available under ``scan_scorecard``
with its per-dimension breakdown, so no surface reports a second grade.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import HTTPException, Request

from agent_bom.core.severity import SEVERITY_DISPLAY_BUCKETS
from agent_bom.exec_score import compute_exec_score

_logger = logging.getLogger(__name__)
_ISSUE_COUNT_KEYS = ("critical", "high", "medium", "low", "unrated", "total", "approximate", "basis")

_EXEC_FIELDS = (
    "grade",
    "score",
    "summary",
    "display",
    "display_format",
    "percent",
    "policy_source",
    "severity_basis",
    "breakdown",
    "floored",
    "finding_total",
)


def issue_severity_counts(request: Request, jobs: list[Any]) -> dict[str, Any] | None:
    """Open issue-group counts shared with ``/v1/posture/counts``; ``None`` if unavailable."""
    from agent_bom.api.routes.compliance import _cached_issue_severity_counts

    try:
        counts = _cached_issue_severity_counts(request, jobs)
    except HTTPException:
        raise
    except Exception:  # noqa: BLE001
        _logger.warning("issue-group counts unavailable; exec posture falls back to occurrence counts")
        return None
    return counts if isinstance(counts, dict) and counts.get("basis") == "issue_groups" else None


def issue_severity_buckets(issue_counts: dict[str, Any] | None) -> dict[str, int] | None:
    if issue_counts is None:
        return None
    return {key: int(issue_counts.get(key, 0) or 0) for key in SEVERITY_DISPLAY_BUCKETS}


def issue_counts_payload(issue_counts: dict[str, Any] | None) -> dict[str, Any] | None:
    return {key: issue_counts.get(key) for key in _ISSUE_COUNT_KEYS} if issue_counts is not None else None


def tenant_exec_posture(
    tenant_id: str,
    scan_posture: dict[str, Any],
    estate: dict[str, Any],
    occurrence_severity: dict[str, int],
    hub_kev: int = 0,
    hub_failing_frameworks: set[str] | None = None,
    issue_severity: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Compute the configurable exec risk score from the honest estate counts.

    Severity buckets are the open issue-group counts the tiles, nav badges and
    the default findings view show (``issue_severity``), so the grade and its
    summary sentence use the numbers beside them; when those are unavailable
    the reconciled occurrence buckets (findings spine + hub evidence) are used
    and ``severity_basis`` says so. KEV, credential exposure, and the live
    count of failing compliance frameworks are further drivers. An
    authoritative scan scorecard is passed as a *floor*: the final score is the
    worst of the count-derived score and that scorecard, so ingested/benign
    evidence can only move the grade down, never launder a failing posture up.
    Reads the tenant's persisted score-config (defaults < env < tenant override).
    """
    from agent_bom.api.exec_score_config import resolve_exec_score_config

    floor: float | None = None
    if scan_posture.get("grade") not in (None, "N/A"):
        floor = float(scan_posture.get("score") or 0.0)
    scan_frameworks = estate.get("compliance_failing_frameworks")
    if scan_frameworks is None:
        compliance_failing = int(estate.get("compliance_failing", 0) or 0) + len(hub_failing_frameworks or set())
    else:
        compliance_failing = len(set(scan_frameworks) | set(hub_failing_frameworks or set()))
    score = compute_exec_score(
        severity=issue_severity_buckets(issue_severity) or occurrence_severity,
        kev=int(estate.get("kev", 0) or 0) + int(hub_kev or 0),
        exposure=int(estate.get("credential_exposed", 0) or 0),
        # Failing frameworks accumulated in the estate rollup (#3962): a
        # framework with a critical/high finding fails; no second evaluation.
        compliance_failing=compliance_failing,
        config=resolve_exec_score_config(tenant_id),
        floor_score=floor,
        floor_summary=str(scan_posture.get("summary") or "") or None,
    )
    score["severity_basis"] = "issue_groups" if issue_severity is not None else "finding_occurrences"
    return score


def canonical_posture_payload(request: Request, scorecard: dict[str, Any]) -> dict[str, Any]:
    from agent_bom.api.routes.overview import _build_overview

    exec_posture = _build_overview(request).get("posture") or {}
    payload: dict[str, Any] = dict(scorecard)
    payload["scan_scorecard"] = {key: scorecard.get(key) for key in ("grade", "score", "summary") if key in scorecard}
    for key in _EXEC_FIELDS:
        if key in exec_posture:
            payload[key] = exec_posture[key]
    payload["basis"] = "exec_posture"
    payload.setdefault("no_data", False)
    return payload


__all__ = [
    "canonical_posture_payload",
    "issue_counts_payload",
    "issue_severity_buckets",
    "issue_severity_counts",
    "tenant_exec_posture",
]
