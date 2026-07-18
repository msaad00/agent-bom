"""Canonical current-state fold for scan-produced findings.

The findings list and executive count surfaces share this module so their
default time-window, parent-job exclusion, and cross-job replacement semantics
cannot drift independently.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from datetime import datetime, timezone
from typing import Any, Protocol

from agent_bom.api.models import JobStatus


class _ScanJobLike(Protocol):
    """Structural contract for the scan-job rows this fold reads.

    Kept as a Protocol (rather than importing ``ScanJob``) so the fold stays
    decoupled from the concrete store row and accepts any object exposing the
    same surface. ``ScanJob`` satisfies it structurally.
    """

    job_id: str
    status: JobStatus
    result: dict[str, Any] | None
    created_at: str
    completed_at: str | None
    child_job_ids: list[str]


def job_in_window(job: _ScanJobLike, since: str | None) -> bool:
    """Return whether a job's completion timestamp is inside ``since``."""
    if since is None:
        return True
    stamp = getattr(job, "completed_at", None) or getattr(job, "created_at", None)
    try:
        observed = datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
        cutoff = datetime.fromisoformat(since.replace("Z", "+00:00"))
        if observed.tzinfo is None:
            observed = observed.replace(tzinfo=timezone.utc)
        if cutoff.tzinfo is None:
            cutoff = cutoff.replace(tzinfo=timezone.utc)
        return observed >= cutoff
    except (TypeError, ValueError):
        return False


def finding_identity(finding: dict[str, Any]) -> str:
    """Stable identity used to collapse a finding across scan jobs."""
    raw_id = finding.get("id")
    if raw_id:
        return str(raw_id)
    vuln_id = finding.get("vulnerability_id") or finding.get("cve_id") or finding.get("title") or ""
    raw_asset = finding.get("asset")
    asset = raw_asset if isinstance(raw_asset, dict) else {}
    package = finding.get("package") or finding.get("package_name") or asset.get("name", "")
    return f"{vuln_id}:{package}"


def current_scan_findings(
    jobs: Iterable[_ScanJobLike],
    *,
    since: str | None,
    scan_id: str | None,
    iter_findings: Callable[[Any], list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    """Return the latest current row per identity across eligible scan jobs.

    Parent aggregation jobs are excluded from the unscoped view because their
    child jobs already own the evidence. A direct ``scan_id`` query retains the
    selected job's rows verbatim.
    """
    deduped: dict[str, dict[str, Any]] = {}
    eligible = (
        job for job in jobs if getattr(job, "status", None) == JobStatus.DONE and getattr(job, "result", None) and job_in_window(job, since)
    )
    for job in sorted(
        eligible,
        key=lambda item: (
            getattr(item, "completed_at", None) or "",
            getattr(item, "created_at", None) or "",
            getattr(item, "job_id", ""),
        ),
    ):
        job_id = str(getattr(job, "job_id", ""))
        if scan_id and job_id != scan_id:
            continue
        if getattr(job, "child_job_ids", None) and job_id != scan_id:
            continue
        for row in iter_findings(job):
            deduped[finding_identity(row)] = row
    return list(deduped.values())


__all__ = ["current_scan_findings", "finding_identity", "job_in_window"]
