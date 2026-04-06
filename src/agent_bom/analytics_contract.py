"""Shared analytics payload builders for ClickHouse persistence.

These helpers keep CLI and API scan paths aligned so both emit the same
finding, scan-metadata, and posture snapshot contract when analytics are
enabled.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Any

from agent_bom.api.fleet_store import FleetLifecycleState
from agent_bom.fleet.trust_scoring import compute_trust_score
from agent_bom.models import AIBOMReport
from agent_bom.output import to_json


@dataclass
class ScanAnalyticsPayload:
    """Normalized analytics rows derived from an AI-BOM report."""

    scan_id: str
    agent_findings: dict[str, list[dict[str, Any]]]
    scan_metadata: dict[str, Any]
    posture_snapshots: dict[str, dict[str, Any]]
    fleet_snapshots: list[dict[str, Any]]
    compliance_controls: list[dict[str, Any]]


def build_scan_analytics_payload(
    report: AIBOMReport,
    *,
    report_json: dict[str, Any] | None = None,
    scan_id: str | None = None,
    source: str = "cli",
) -> ScanAnalyticsPayload:
    """Build shared ClickHouse analytics rows from a report.

    The API and CLI use the same contract so dashboards and operators do not
    get subtly different records depending on how a scan was launched.
    """
    data = report_json or to_json(report)
    final_scan_id = scan_id or data.get("scan_id") or report.scan_id
    if not final_scan_id:
        raise ValueError("scan_id required for analytics payload")

    agent_findings = _build_agent_findings(data.get("blast_radius", []), report.agents)
    posture_snapshots = _build_posture_snapshots(report, data.get("blast_radius", []))
    summary = data.get("summary", {})
    posture = data.get("posture_scorecard", {})

    scan_metadata = {
        "scan_id": final_scan_id,
        "agent_count": int(summary.get("total_agents", report.total_agents)),
        "package_count": int(summary.get("total_packages", report.total_packages)),
        "vuln_count": int(summary.get("total_vulnerabilities", report.total_vulnerabilities)),
        "critical_count": int(summary.get("critical_findings", len(report.critical_vulns))),
        "high_count": sum(1 for item in data.get("blast_radius", []) if item.get("severity") == "high"),
        "posture_grade": posture.get("grade", ""),
        "scan_duration_ms": int(data.get("scan_duration_ms", 0) or 0),
        "source": source,
        "aisvs_score": float((report.aisvs_benchmark_data or {}).get("overall_score", 0.0) or 0.0),
        "has_runtime_correlation": bool(report.runtime_correlation),
    }
    return ScanAnalyticsPayload(
        scan_id=final_scan_id,
        agent_findings=agent_findings,
        scan_metadata=scan_metadata,
        posture_snapshots=posture_snapshots,
        fleet_snapshots=_build_fleet_snapshots(report),
        compliance_controls=_build_compliance_controls(report, data),
    )


def _build_agent_findings(blast_radius: list[dict[str, Any]], agents: list[Any]) -> dict[str, list[dict[str, Any]]]:
    findings_by_agent: dict[str, list[dict[str, Any]]] = {agent.name: [] for agent in agents}
    for item in blast_radius:
        finding = {
            "package_name": item.get("package_name", ""),
            "package_version": item.get("package_version", ""),
            "package": item.get("package", ""),
            "ecosystem": item.get("ecosystem", ""),
            "cve_id": item.get("vulnerability_id", ""),
            "cvss_score": float(item.get("cvss_score") or 0.0),
            "epss_score": float(item.get("epss_score") or 0.0),
            "severity": item.get("severity", "unknown"),
            "source": item.get("primary_advisory_source") or "osv",
            "environment": item.get("environment", ""),
            "cmmc_tags": list(item.get("cmmc_tags", [])),
        }
        for agent_name in item.get("affected_agents", []):
            findings_by_agent.setdefault(agent_name, []).append(dict(finding))
    return findings_by_agent


def _build_posture_snapshots(report: AIBOMReport, blast_radius: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    findings_by_agent: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in blast_radius:
        for agent_name in item.get("affected_agents", []):
            findings_by_agent[agent_name].append(item)

    snapshots: dict[str, dict[str, Any]] = {}
    for agent in report.agents:
        findings = findings_by_agent.get(agent.name, [])
        severity_counts = Counter(str(item.get("severity", "")).lower() for item in findings)
        total_findings = len(findings)
        total_packages = sum(len(server.packages) for server in agent.mcp_servers)
        max_risk_score = max((float(item.get("risk_score") or 0.0) for item in findings), default=0.0)
        compliance_hits = sum(
            1
            for item in findings
            if any(
                item.get(key)
                for key in (
                    "owasp_tags",
                    "atlas_tags",
                    "nist_ai_rmf_tags",
                    "owasp_mcp_tags",
                    "owasp_agentic_tags",
                    "eu_ai_act_tags",
                    "nist_csf_tags",
                    "iso_27001_tags",
                    "soc2_tags",
                    "cis_tags",
                    "cmmc_tags",
                )
            )
            or bool(item.get("compliance_tags"))
        )
        compliance_score = (compliance_hits / total_findings * 100.0) if total_findings else 100.0
        posture_score = max(
            0.0,
            100.0
            - severity_counts.get("critical", 0) * 25.0
            - severity_counts.get("high", 0) * 10.0
            - severity_counts.get("medium", 0) * 4.0
            - severity_counts.get("low", 0) * 1.0,
        )
        snapshots[agent.name] = {
            "total_packages": total_packages,
            "critical": severity_counts.get("critical", 0),
            "high": severity_counts.get("high", 0),
            "medium": severity_counts.get("medium", 0),
            "grade": _score_to_grade(posture_score),
            "risk_score": round(max_risk_score, 2),
            "compliance_score": round(compliance_score, 2),
        }
    return snapshots


def _score_to_grade(score: float) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def _build_fleet_snapshots(report: AIBOMReport) -> list[dict[str, Any]]:
    snapshots: list[dict[str, Any]] = []
    measured_at = report.generated_at.isoformat()
    for agent in report.agents:
        score, _factors = compute_trust_score(agent)
        snapshots.append(
            {
                "agent_name": agent.name,
                "agent_type": agent.agent_type.value if hasattr(agent.agent_type, "value") else str(agent.agent_type),
                "lifecycle_state": FleetLifecycleState.DISCOVERED.value,
                "trust_score": float(score),
                "server_count": len(agent.mcp_servers),
                "package_count": sum(len(server.packages) for server in agent.mcp_servers),
                "credential_count": sum(len(server.credential_names) for server in agent.mcp_servers),
                "vuln_count": sum(server.total_vulnerabilities for server in agent.mcp_servers),
                "tenant_id": "default",
                "last_seen": measured_at,
            }
        )
    return snapshots


def _build_compliance_controls(report: AIBOMReport, data: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    measured_at = report.generated_at.isoformat()
    summary = data.get("threat_framework_summary", {})
    framework_map = {
        "owasp_llm_top10": "owasp-llm-top10",
        "mitre_atlas": "mitre-atlas",
        "nist_ai_rmf": "nist-ai-rmf",
        "owasp_mcp_top10": "owasp-mcp-top10",
        "owasp_agentic_top10": "owasp-agentic-top10",
        "eu_ai_act": "eu-ai-act",
        "nist_csf": "nist-csf",
        "iso_27001": "iso-27001",
        "soc2_tsc": "soc2-tsc",
        "cis_controls": "cis-controls",
    }
    for key, framework_name in framework_map.items():
        for item in summary.get(key, []):
            control_id = item.get("code") or item.get("technique_id") or item.get("subcategory_id") or item.get("section") or ""
            finding_count = int(item.get("findings", 0) or 0)
            rows.append(
                {
                    "framework": framework_name,
                    "control_id": str(control_id),
                    "control_name": item.get("name", ""),
                    "status": "fail" if item.get("triggered") else "pass",
                    "finding_count": finding_count,
                    "score": float(0 if finding_count else 100),
                    "measured_at": measured_at,
                    "scan_id": report.scan_id,
                }
            )

    aisvs = report.aisvs_benchmark_data or {}
    for check in aisvs.get("checks", []) or []:
        status = str(check.get("status", "")).lower() or "unknown"
        rows.append(
            {
                "framework": "owasp-aisvs",
                "control_id": str(check.get("check_id", "")),
                "control_name": check.get("title", ""),
                "status": status,
                "finding_count": 0 if status == "pass" else 1,
                "score": float(check.get("score", aisvs.get("overall_score", 0.0)) or 0.0),
                "measured_at": measured_at,
                "scan_id": report.scan_id,
            }
        )
    return rows
