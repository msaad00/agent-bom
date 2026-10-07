"""Server-side trust boundary for pushed scan reports."""

from __future__ import annotations

from copy import deepcopy
from typing import cast

from agent_bom.api.audit_log import log_action
from agent_bom.api.finding_collection import collect_scan_findings
from agent_bom.api.models import PushPayload, ScanJob, ScanRequest
from agent_bom.api.push_models import normalize_push_coverage
from agent_bom.mcp_blocklist import sanitize_security_intelligence_entry
from agent_bom.output.json_fmt import _build_finding_summary
from agent_bom.security import (
    sanitize_command_args,
    sanitize_env_vars,
    sanitize_security_warnings,
    sanitize_sensitive_payload,
    sanitize_text,
    sanitize_url,
)


def normalize_pushed_report(body: PushPayload, *, fallback_scan_id: str) -> dict:
    """Coerce pushed payloads onto the canonical scan report contract.

    The main scan pipeline emits `blast_radius` and agent `type`, while some
    push clients still send `blast_radii` and `agent_type`. Normalizing here
    keeps graph persistence, UI pages, and downstream exporters aligned.
    """
    report = cast(dict, sanitize_sensitive_payload(body.model_dump()))
    blast_radius = deepcopy(report.get("blast_radius") or report.get("blast_radii") or [])
    report["blast_radius"] = blast_radius
    if "blast_radii" not in report:
        report["blast_radii"] = deepcopy(blast_radius)
    report["scan_id"] = str(report.get("scan_id") or fallback_scan_id)

    normalized_agents: list[dict] = []
    for raw_agent in report.get("agents", []):
        agent = dict(raw_agent)
        agent_type = str(agent.get("type") or agent.get("agent_type") or "").strip()
        if agent_type:
            agent["type"] = agent_type
            agent["agent_type"] = agent_type
        sanitized_servers: list[dict] = []
        for raw_server in agent.get("mcp_servers", []) or agent.get("servers", []) or []:
            if not isinstance(raw_server, dict):
                continue
            server = dict(raw_server)
            server["command"] = sanitize_text(server.get("command", ""), max_len=200)
            server["args"] = sanitize_command_args(list(server.get("args", []) or []))
            server["url"] = sanitize_url(str(server.get("url") or "")) if server.get("url") else None
            server["env"] = sanitize_env_vars(dict(server.get("env", {}) or {}))
            server["security_warnings"] = sanitize_security_warnings(list(server.get("security_warnings", []) or []))
            server["security_intelligence"] = [
                sanitize_security_intelligence_entry(item)
                for item in (server.get("security_intelligence", []) or [])
                if isinstance(item, dict)
            ]
            sanitized_servers.append(server)
        agent["mcp_servers"] = sanitized_servers
        if "servers" in agent:
            agent["servers"] = sanitized_servers
        normalized_agents.append(agent)
    report["agents"] = normalized_agents
    if (body.target_scope or "summary" in body.model_fields_set) and not body.model_fields_set.intersection(
        {"agents", "blast_radius", "blast_radii", "findings", "endpoint_inventory"}
    ):
        report.setdefault("warnings", []).append(
            "Pushed report contains no supported evidence rows; summary-only data cannot establish coverage."
        )
    report = normalize_push_coverage(report, source_id=body.source_id, target_scope=body.target_scope)
    derive_push_summary(report)
    # A producer grade is not a server-computed posture assessment.
    report.pop("posture_scorecard", None)
    return report


def derive_push_summary(report: dict) -> None:
    """Count retained evidence using the same deduplication as the findings API.

    Current runtime enrichment and approved suppressions are read-time state;
    they must not rewrite the stored observation or establish clean evidence.
    """
    job = ScanJob(job_id=report["scan_id"], created_at="", request=ScanRequest(), result=report)
    findings = collect_scan_findings(job)
    finding_summary = _build_finding_summary(findings)
    agents = report.get("agents") or []
    servers = [server for agent in agents for server in agent.get("mcp_servers", []) or []]
    packages = [package for server in servers for package in server.get("packages", []) or [] if isinstance(package, dict)]
    package_keys = {(str(p.get("name") or ""), str(p.get("version") or ""), str(p.get("ecosystem") or "")) for p in packages}
    vuln_ids = {str(f.get("vulnerability_id") or f.get("cve_id")) for f in findings if f.get("vulnerability_id") or f.get("cve_id")}
    report["summary"] = {
        "total_agents": len(agents),
        "total_mcp_servers": len(servers),
        "total_packages": len(packages),
        "unique_packages": len(package_keys),
        "total_vulnerabilities": len(vuln_ids),
        "total_findings": len(findings),
        "critical_findings": finding_summary["by_severity"]["critical"],
        "critical_unified_findings": finding_summary["by_severity"]["critical"],
        "high_unified_findings": finding_summary["by_severity"]["high"],
        "coverage_warnings": report.get("coverage_warnings", []),
    }
    report["finding_summary"] = finding_summary


def audit_push_admission(job: ScanJob, report: dict, *, actor: str, request_hash: str) -> None:
    """Fail closed before writes; admission is explicitly not a commit receipt.

    Audit and evidence stores do not share a transaction. Retain this attempt
    even when a subsequent write fails; use its job id to inspect the result.
    Idempotent replays bypass admission and cannot manufacture another event.
    """
    log_action(
        "results.push.accepted",
        actor=actor,
        resource=job.job_id,
        tenant_id=job.tenant_id,
        job_id=job.job_id,
        source_id=job.source_id or "",
        scan_id=str(report.get("scan_id") or job.job_id),
        evidence_id=str(report.get("target_scope") or "unscoped"),
        payload_sha256=request_hash,
        outcome="accepted",
    )
