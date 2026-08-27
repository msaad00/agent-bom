"""Canonical scan-result to posture-trend persistence boundary."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

from agent_bom.baseline import TrendPoint
from agent_bom.security import sanitize_error, sanitize_text

_logger = logging.getLogger(__name__)
_SEVERITIES = ("critical", "high", "medium", "low")


def _vulnerability_severities(result: Mapping[str, Any]) -> list[str]:
    severities: list[str] = []
    packages = result.get("packages")
    if isinstance(packages, list):
        for package in packages:
            if not isinstance(package, Mapping):
                continue
            vulnerabilities = package.get("vulnerabilities")
            if not isinstance(vulnerabilities, list):
                continue
            for vulnerability in vulnerabilities:
                if isinstance(vulnerability, Mapping):
                    severities.append(str(vulnerability.get("severity") or "unknown").strip().lower())
    if severities:
        return severities
    blast_radius = result.get("blast_radius") or result.get("blast_radii")
    if isinstance(blast_radius, list):
        for finding in blast_radius:
            if isinstance(finding, Mapping):
                severities.append(str(finding.get("severity") or "unknown").strip().lower())
    return severities


def trend_point_from_scan_result(
    result: Mapping[str, Any],
    *,
    tenant_id: str,
    scan_id: str | None = None,
    completed_at: str | None = None,
) -> TrendPoint | None:
    """Build one honest, retry-safe trend point from canonical scan JSON."""
    scorecard = result.get("posture_scorecard")
    if not isinstance(scorecard, Mapping) or bool(scorecard.get("no_data")):
        return None
    grade = str(scorecard.get("grade") or "").strip().upper()
    if not grade or grade == "N/A":
        return None
    try:
        score = float(scorecard["score"])
    except (KeyError, TypeError, ValueError):
        return None
    resolved_scan_id = str(scan_id or result.get("scan_id") or "").strip()
    if not resolved_scan_id:
        return None
    timestamp = str(completed_at or result.get("generated_at") or "").strip()
    if not timestamp:
        return None
    severities = _vulnerability_severities(result)
    counts = {severity: severities.count(severity) for severity in _SEVERITIES}
    return TrendPoint(
        timestamp=timestamp,
        total_vulns=len(severities),
        critical=counts["critical"],
        high=counts["high"],
        medium=counts["medium"],
        low=counts["low"],
        posture_score=score,
        posture_grade=grade,
        tenant_id=str(tenant_id or "default"),
        scan_id=resolved_scan_id,
    )


def record_scan_trend_best_effort(
    result: Mapping[str, Any],
    *,
    tenant_id: str,
    scan_id: str | None = None,
    completed_at: str | None = None,
) -> bool:
    """Persist one trend point; return whether a gradable point was recorded."""
    point = trend_point_from_scan_result(
        result,
        tenant_id=tenant_id,
        scan_id=scan_id,
        completed_at=completed_at,
    )
    if point is None:
        return False
    try:
        from agent_bom.api.stores import _get_trend_store

        _get_trend_store().record(point)
    except Exception as exc:  # noqa: BLE001 - trend history must not fail a completed scan
        _logger.warning("Posture trend persistence skipped: %s", sanitize_text(sanitize_error(exc, generic=True)))
        return False
    return True
