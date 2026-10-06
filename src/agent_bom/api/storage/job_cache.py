"""Bounded hot-cache payloads; durable jobs retain the complete scan result."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from agent_bom.api.models import JobStatus

if TYPE_CHECKING:
    from agent_bom.api.models import ScanJob
_COMPACTED_RESULT_MARKER = "_agent_bom_hot_cache_compacted"


def _compact_terminal_job(job: ScanJob) -> ScanJob:
    """Return a hot-cache copy that keeps status/progress but drops full results."""
    if job.status not in (JobStatus.DONE, JobStatus.FAILED, JobStatus.CANCELLED):
        return job

    compact_result: dict[str, Any] = {_COMPACTED_RESULT_MARKER: True}
    if isinstance(job.result, dict):
        for key in ("summary", "scan_timestamp", "generated_at", "scan_run", "pushed", "auto_correlation"):
            if key in job.result:
                compact_result[key] = job.result[key]
        if "scan_timestamp" not in compact_result and "generated_at" in compact_result:
            compact_result["scan_timestamp"] = compact_result["generated_at"]
        scorecard = job.result.get("posture_scorecard")
        if isinstance(scorecard, dict):
            compact_result["posture_scorecard"] = {key: scorecard[key] for key in ("grade", "score", "summary") if key in scorecard}
        scan_sources = job.result.get("scan_sources")
        if isinstance(scan_sources, list):
            compact_result["scan_sources"] = scan_sources
        warnings = job.result.get("warnings")
        if isinstance(warnings, list):
            compact_result["warnings"] = [str(item) for item in warnings[:3]]
    return job.model_copy(update={"result": compact_result})


def _compact_terminal_job_in_place(job: ScanJob) -> None:
    """Drop heavy terminal results from an already-persisted in-process job."""
    compact = _compact_terminal_job(job)
    if compact is not job:
        job.result = compact.result


def _jobs_is_compacted(job: ScanJob) -> bool:
    """Return True when a hot-cache job has only compact terminal metadata."""
    return isinstance(job.result, dict) and bool(job.result.get(_COMPACTED_RESULT_MARKER))
