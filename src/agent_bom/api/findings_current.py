"""Canonical current-state fold for scan-produced findings.

The findings list and executive count surfaces share this module so their
default time-window, parent-job exclusion, and cross-job replacement semantics
cannot drift independently.
"""

from __future__ import annotations

import json
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


_SCAN_TARGET_FIELDS = (
    "inventory",
    "images",
    "k8s",
    "k8s_namespace",
    "tf_dirs",
    "gha_path",
    "repo_url",
    "agent_projects",
    "jupyter_dirs",
    "sbom",
    "external_scan",
    "vex",
    "connectors",
    "filesystem_paths",
    "dynamic_discovery",
    "dynamic_max_depth",
    "discover_host",
    "scope_agents",
    "scope_servers",
    "exclude_agents",
    "exclude_servers",
    "dry_run",
    "no_scan",
)


def _normalized_evidence_timestamp(*values: Any) -> str:
    """Return the first valid timestamp in a UTC-sortable representation."""
    for value in values:
        raw = str(value or "").strip()
        if not raw:
            continue
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            continue
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat()
    return ""


def scan_evidence_authority_key(job: _ScanJobLike) -> tuple[str, str, str]:
    """Deterministic newest-wins key for one completed scan snapshot.

    The stores do not yet persist one shared commit sequence. If evidence and
    completion timestamps are exactly equal, ``job_id`` is therefore a stable
    backend-independent tie-break, not a claim about commit chronology.
    """
    raw_result = getattr(job, "result", None)
    result: dict[str, Any] = raw_result if isinstance(raw_result, dict) else {}
    raw_scan_run = result.get("scan_run")
    scan_run: dict[str, Any] = raw_scan_run if isinstance(raw_scan_run, dict) else {}
    completed_at = _normalized_evidence_timestamp(
        getattr(job, "completed_at", None),
        getattr(job, "created_at", None),
    )
    evidence_at = _normalized_evidence_timestamp(
        result.get("generated_at"),
        result.get("scan_timestamp"),
        scan_run.get("generated_at"),
        completed_at,
    )
    return evidence_at, completed_at, str(getattr(job, "job_id", ""))


def scan_scope_key(job: _ScanJobLike) -> str:
    """Canonical target scope whose newer successful scan replaces the older.

    Result ordering cannot express replacement semantics: an empty successful
    scan has no finding identity to overwrite.  The request's target-bearing
    fields are therefore the durable scope.  Execution/enrichment/output flags
    are intentionally excluded because they do not identify a different asset
    estate.  Legacy/default jobs fall back to their reported scan-source set.
    """
    request = getattr(job, "request", None)
    if request is not None and hasattr(request, "model_dump"):
        raw_request = request.model_dump(mode="json")
    elif isinstance(request, dict):
        raw_request = request
    else:
        raw_request = {}

    target: dict[str, Any] = {}
    for field in _SCAN_TARGET_FIELDS:
        if field == "dynamic_max_depth" and not raw_request.get("dynamic_discovery"):
            continue
        value = raw_request.get(field)
        if value in (None, "", False, [], {}):
            continue
        if isinstance(value, list):
            value = sorted(str(item) for item in value)
        target[field] = value
    explicit_target = getattr(job, "target", None)
    if isinstance(explicit_target, dict) and explicit_target:
        target["job_target"] = explicit_target
    source_id = str(getattr(job, "source_id", None) or "").strip()
    if source_id:
        target["source_id"] = source_id
    if target:
        return "request:" + json.dumps(target, sort_keys=True, separators=(",", ":"), default=str)

    raw_result = getattr(job, "result", None)
    result: dict[str, Any] = raw_result if isinstance(raw_result, dict) else {}
    explicit = str(result.get("scan_scope") or result.get("source_scope") or "").strip()
    if explicit:
        return f"explicit:{explicit}"
    sources = sorted({str(item).strip() for item in result.get("scan_sources", []) or [] if str(item).strip()})
    return "sources:" + json.dumps(sources or ["local-agents"], separators=(",", ":"))


def _job_matches_scan_id(job: _ScanJobLike, scan_id: str) -> bool:
    if str(getattr(job, "job_id", "")) == scan_id:
        return True
    raw_result = getattr(job, "result", None)
    result: dict[str, Any] = raw_result if isinstance(raw_result, dict) else {}
    raw_scan_run = result.get("scan_run")
    scan_run: dict[str, Any] = raw_scan_run if isinstance(raw_scan_run, dict) else {}
    return scan_id in {str(result.get("scan_id") or ""), str(scan_run.get("scan_id") or "")}


def current_scan_jobs(
    jobs: Iterable[_ScanJobLike],
    *,
    since: str | None,
    scan_id: str | None,
) -> list[_ScanJobLike]:
    """Select the newest successful leaf snapshot for every target scope.

    A newer empty result remains selected and thereby retires the older scope's
    absent findings.  Stable evidence-time/job-id authority makes the result
    independent of InMemory, SQLite, or Postgres return order.
    """
    eligible = [
        job
        for job in jobs
        if getattr(job, "status", None) == JobStatus.DONE and isinstance(getattr(job, "result", None), dict) and job_in_window(job, since)
    ]
    if scan_id:
        selected = [job for job in eligible if _job_matches_scan_id(job, scan_id)]
        return sorted(selected, key=scan_evidence_authority_key)

    current: dict[str, _ScanJobLike] = {}
    for job in eligible:
        if getattr(job, "child_job_ids", None):
            continue
        scope = scan_scope_key(job)
        existing = current.get(scope)
        if existing is None or scan_evidence_authority_key(job) > scan_evidence_authority_key(existing):
            current[scope] = job
    return sorted(current.values(), key=lambda job: (scan_evidence_authority_key(job), scan_scope_key(job)))


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
    deduped: dict[str, tuple[tuple[str, str, str], dict[str, Any]]] = {}
    for job in current_scan_jobs(jobs, since=since, scan_id=scan_id):
        authority = scan_evidence_authority_key(job)
        for row in iter_findings(job):
            identity = finding_identity(row)
            existing = deduped.get(identity)
            if existing is None or authority > existing[0]:
                deduped[identity] = (authority, row)
    return [deduped[key][1] for key in sorted(deduped)]


def latest_current_scan_job(jobs: Iterable[_ScanJobLike]) -> _ScanJobLike | None:
    """Return the newest authoritative successful scan across current scopes."""
    current = current_scan_jobs(jobs, since=None, scan_id=None)
    return max(current, key=scan_evidence_authority_key, default=None)


__all__ = [
    "current_scan_findings",
    "current_scan_jobs",
    "finding_identity",
    "job_in_window",
    "latest_current_scan_job",
    "scan_evidence_authority_key",
    "scan_scope_key",
]
