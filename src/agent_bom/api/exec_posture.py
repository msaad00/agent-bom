"""``/v1/posture`` served from the one exec posture computation.

The overview's configurable exec score (issue-group severity, KEV, credential
exposure, failing frameworks, floored by the scan-time scorecard) is the
tenant's posture grade. ``/v1/posture`` returns that same grade, score and
summary; the scan-time scorecard remains available under ``scan_scorecard``
with its per-dimension breakdown, so no surface reports a second grade.
"""

from __future__ import annotations

import logging
from typing import Any, cast

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


def compound_issue_count(tenant_jobs: list[Any]) -> int:
    """Count high-priority compound issues from blast-radius correlation.

    A compound issue is a KEV vuln that is also reachable or exposes a
    credential, or a high-CVSS + high-EPSS vuln — the reachability/exposure
    correlation that lives in ``blast_radius`` (not a raw severity count).
    Deduped by vulnerability id across scans.
    """
    from agent_bom.api.findings_current import current_scan_jobs

    seen_ids: set[str] = set()
    compound = 0
    for job in current_scan_jobs(
        tenant_jobs,
        since=None,
        scan_id=None,
        require_authoritative_evidence=True,
    ):
        result = cast(dict[str, Any], job.result)
        for b in result.get("blast_radius", []):
            vid = b.get("vulnerability_id", "")
            if vid in seen_ids:
                continue
            seen_ids.add(vid)
            is_kev = bool(b.get("cisa_kev") or b.get("is_kev"))
            if is_kev and (b.get("reachable_tools") or b.get("exposed_credentials")):
                compound += 1
            elif (b.get("epss_score") or 0) >= 0.3 and (b.get("cvss_score") or 0) >= 7:
                compound += 1
    return compound


def posture_evidence_blocks(request: Request, tenant_jobs: list[Any]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Exec severity, compound issues and issue groups for the current evidence fingerprint."""
    from agent_bom.api.posture_counts_cache import cached_posture_block
    from agent_bom.api.routes import overview
    from agent_bom.api.routes.compliance import _cached_issue_severity_counts

    reconciled = cached_posture_block(request, tenant_jobs, "exec_severity", lambda: overview.exec_severity_counts(request, tenant_jobs))
    compound = cached_posture_block(request, tenant_jobs, "compound_issues", lambda: {"count": compound_issue_count(tenant_jobs)})
    return reconciled, compound, _cached_issue_severity_counts(request, tenant_jobs)


def precompute_posture_evidence(tenant_id: str) -> None:
    """Fill the evidence blocks for the tenant's current fingerprint after a write.

    Uses the read path's own functions and cache keys, so a later read with the
    same fingerprint gets exactly the value it would have computed.
    """
    from agent_bom.api.stores import _get_store

    request = Request({"type": "http", "method": "GET", "path": "/v1/posture/counts", "headers": [], "query_string": b"", "state": {}})
    request.state.tenant_id = tenant_id
    posture_evidence_blocks(request, _get_store().list_all(tenant_id=tenant_id))


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
    "compound_issue_count",
    "issue_counts_payload",
    "issue_severity_buckets",
    "issue_severity_counts",
    "posture_evidence_blocks",
    "precompute_posture_evidence",
    "tenant_exec_posture",
]
