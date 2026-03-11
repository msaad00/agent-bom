"""Compliance evidence bundle export (CMMC, FedRAMP, NIST AI RMF)."""

from __future__ import annotations

import json
import zipfile

from agent_bom.models import AIBOMReport
from agent_bom.output.cyclonedx_fmt import to_cyclonedx


def export_compliance_bundle(
    report: AIBOMReport,
    framework: str,
    output_path: str,
) -> str:
    """Export CMMC/FedRAMP/NIST-AI-RMF compliance evidence bundle as ZIP.

    Returns the path to the written ZIP file.
    """
    cmmc_control_map = {
        "CM-8": "Configuration Management — Component Inventory",
        "SI-2": "System & Information Integrity — Flaw Remediation",
        "SR-3": "Supply Chain Risk Management — Supply Chain Controls",
        "RA-3": "Risk Assessment — Risk Assessment",
        "AU-2": "Audit & Accountability — Event Logging",
    }

    # Build SBOM (CycloneDX)
    sbom_data = to_cyclonedx(report)

    # Build vulnerability report
    vuln_entries = []
    for br in report.blast_radii:
        vuln_entries.append(
            {
                "id": br.vulnerability.id,
                "severity": br.vulnerability.severity.value,
                "package": br.package.name,
                "version": br.package.version,
                "fixed_version": br.vulnerability.fixed_version,
                "risk_score": br.risk_score,
                "affected_agents": [a.name for a in br.affected_agents],
                "affected_servers": [s.name for s in br.affected_servers],
            }
        )

    # Build policy results
    policy_results = {
        "framework": framework,
        "scan_date": report.generated_at.isoformat(),
        "tool_version": report.tool_version,
        "total_agents": report.total_agents,
        "total_servers": report.total_servers,
        "total_packages": report.total_packages,
        "total_vulnerabilities": report.total_vulnerabilities,
        "critical_count": len(report.critical_vulns),
    }

    # Build control mapping
    control_mapping = {}
    for ctrl_id, ctrl_desc in cmmc_control_map.items():
        findings = []
        if ctrl_id == "CM-8":
            findings = [{"type": "inventory", "count": report.total_packages}]
        elif ctrl_id == "SI-2":
            findings = [{"type": "vulnerabilities", "count": report.total_vulnerabilities}]
        elif ctrl_id == "SR-3":
            findings = [{"type": "supply_chain", "servers": report.total_servers}]
        elif ctrl_id == "RA-3":
            findings = [{"type": "risk_assessment", "blast_radii": len(report.blast_radii)}]
        elif ctrl_id == "AU-2":
            findings = [{"type": "audit_trail", "scan_date": report.generated_at.isoformat()}]
        control_mapping[ctrl_id] = {
            "description": ctrl_desc,
            "status": "pass" if not findings or report.total_vulnerabilities == 0 else "review",
            "findings": findings,
        }

    # Executive summary text
    summary_lines = [
        f"Compliance Evidence Bundle — {framework.upper()}",
        f"Generated: {report.generated_at.isoformat()}",
        f"Tool: agent-bom v{report.tool_version}",
        "",
        f"Agents scanned: {report.total_agents}",
        f"MCP servers: {report.total_servers}",
        f"Packages inventoried: {report.total_packages}",
        f"Vulnerabilities found: {report.total_vulnerabilities}",
        f"Critical findings: {len(report.critical_vulns)}",
        "",
        "Controls mapped: " + ", ".join(cmmc_control_map.keys()),
    ]

    zip_path = output_path if output_path.endswith(".zip") else output_path + ".zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("sbom.cdx.json", json.dumps(sbom_data, indent=2, default=str))
        zf.writestr("vulnerability_report.json", json.dumps(vuln_entries, indent=2, default=str))
        zf.writestr("policy_results.json", json.dumps(policy_results, indent=2, default=str))
        zf.writestr("compliance_mapping.json", json.dumps(control_mapping, indent=2, default=str))
        zf.writestr("summary.txt", "\n".join(summary_lines))

    return zip_path
