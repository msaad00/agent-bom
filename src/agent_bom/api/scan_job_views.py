"""Response payload builders for scan job list, detail and inventory routes."""

from __future__ import annotations

import sys
from collections.abc import Mapping
from typing import Any, cast

from agent_bom.api.models import JobStatus, ScanJob


def _inventory_packages_from_agents(agents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Retain package occurrences; display names are not asset identities."""
    packages: list[dict[str, Any]] = []
    seen: set[tuple[str, ...]] = set()
    for agent_index, agent in enumerate(agents):
        agent_name = str(agent.get("name") or "")
        agent_id = str(agent.get("canonical_id") or agent.get("stable_id") or agent.get("agent_id") or "")
        environment = str(agent.get("environment") or "")
        for server_index, server in enumerate(agent.get("mcp_servers", []) or []):
            if not isinstance(server, dict):
                continue
            server_name = str(server.get("name") or "")
            server_id = str(server.get("canonical_id") or server.get("stable_id") or server.get("server_id") or "")
            # Missing identity stays scoped to this observed row; never merge
            # otherwise distinct runtime occurrences by their display labels.
            agent_key = agent_id or f"unidentified-agent-row:{agent_index}"
            server_key = server_id or f"unidentified-server-row:{agent_index}:{server_index}"
            for package in server.get("packages", []) or []:
                if not isinstance(package, dict):
                    continue
                row = {
                    "name": str(package.get("name") or ""),
                    "version": str(package.get("version") or ""),
                    "ecosystem": str(package.get("ecosystem") or ""),
                    "agent": agent_name,
                    "server": server_name,
                    "agent_id": agent_id,
                    "server_id": server_id,
                    "environment": environment,
                }
                key = (str(row["name"]), str(row["version"]), str(row["ecosystem"]), agent_key, server_key, environment)
                if key in seen:
                    continue
                seen.add(key)
                packages.append(row)
    return packages


def _job_summary_payload(job: ScanJob) -> dict[str, Any]:
    """Build a lightweight summary payload for list surfaces."""
    from agent_bom.security import sanitize_sensitive_payload, sanitize_text

    result = job.result if isinstance(job.result, dict) else {}
    summary = result.get("summary") if isinstance(result.get("summary"), dict) else None
    aggregation = result.get("aggregation") if isinstance(result.get("aggregation"), dict) else None
    scan_run = result.get("scan_run") if isinstance(result.get("scan_run"), dict) else None
    warnings_value = result.get("warnings")
    warnings: list[Any] = warnings_value if isinstance(warnings_value, list) else []
    raw_warning_count = (scan_run or {}).get("warning_count")
    warning_count = max(0, min(100, raw_warning_count)) if isinstance(raw_warning_count, int) else len(warnings)
    generated_at = result.get("generated_at") or (scan_run or {}).get("generated_at")
    scan_timestamp = result.get("scan_timestamp") or generated_at
    auto_correlation = sanitize_sensitive_payload(result.get("auto_correlation"))
    request_payload = sanitize_sensitive_payload(job.request.model_dump(exclude_defaults=True, exclude_none=True))
    return {
        "job_id": job.job_id,
        # Locator only: graph persistence may still be unavailable or incomplete.
        "graph_scan_id": str(result.get("scan_id") or job.job_id) if job.status == JobStatus.DONE else None,
        "tenant_id": job.tenant_id,
        "batch_id": job.batch_id,
        "correlation_cohort_id": job.correlation_cohort_id,
        "correlation_cohort_manifest_hash": job.correlation_cohort_manifest_hash,
        "correlation_max_age_hours": job.correlation_max_age_hours,
        "parent_job_id": job.parent_job_id,
        "child_job_ids": list(job.child_job_ids),
        "target": job.target,
        "target_index": job.target_index,
        "target_count": job.target_count,
        "source_id": job.source_id,
        "schedule_id": job.schedule_id,
        "status": job.status,
        "created_at": job.created_at,
        "completed_at": job.completed_at,
        "request": request_payload if isinstance(request_payload, dict) else {},
        "summary": sanitize_sensitive_payload(summary),
        "aggregation": sanitize_sensitive_payload(aggregation),
        **({"auto_correlation": auto_correlation} if isinstance(auto_correlation, dict) else {}),
        "scan_timestamp": scan_timestamp,
        "generated_at": generated_at,
        "scan_run": sanitize_sensitive_payload(scan_run),
        "scan_outcome": (scan_run or {}).get("outcome"),
        "warning_count": warning_count,
        "warnings_preview": sanitize_sensitive_payload(warnings[:3]),
        "pushed": bool(result.get("pushed")),
        "error": sanitize_text(job.error, max_len=1_000) if job.error else None,
    }


def _redact_scan_result_for_response(result: dict[str, Any] | None) -> dict[str, Any] | None:
    """Redact the complete scan envelope and drop replay-only finding fields."""
    if not isinstance(result, dict):
        return result
    from agent_bom.cloud.cis_remediation import fail_closed_cis_result
    from agent_bom.security import sanitize_sensitive_payload

    findings = result.get("findings")
    envelope = {key: value for key, value in result.items() if key != "findings"}
    # This is the explicit full-result endpoint.  Redact sensitive content but
    # do not silently truncate legitimate evidence; callers that only need a
    # bounded polling envelope use ``/{job_id}/status`` instead.
    sanitized = sanitize_sensitive_payload(envelope, max_str_len=sys.maxsize)
    if not isinstance(sanitized, dict):
        return {"document_type": "AI-BOM", "redaction_error": "scan result sanitizer returned a non-object payload"}
    redacted = cast(dict[str, Any], fail_closed_cis_result(sanitized))
    if not isinstance(findings, list):
        return redacted
    from agent_bom.finding_scope import safe_finding_response_payload

    redacted["findings"] = [safe_finding_response_payload(item) for item in findings if isinstance(item, Mapping)]
    return redacted


def _job_response_payload(job: ScanJob) -> ScanJob:
    redacted_result = _redact_scan_result_for_response(job.result)
    if redacted_result is job.result:
        return job
    return job.model_copy(update={"result": redacted_result})
