"""Compatibility views over the unified Finding stream for output formatters."""

from __future__ import annotations

from typing import Any

from agent_bom.finding import Finding, FindingType, blast_radius_to_finding
from agent_bom.models import AIBOMReport, BlastRadius, Severity


def cve_findings(report: AIBOMReport, blast_radii: list[BlastRadius] | None = None) -> list[Finding]:
    """Return CVE findings, accepting non-empty legacy BlastRadius overrides."""
    if blast_radii:
        return [blast_radius_to_finding(br) for br in blast_radii]

    return [finding for finding in report.to_findings() if finding.finding_type == FindingType.CVE]


def nested_vulnerabilities(report: AIBOMReport) -> list[Any]:
    """Return package vulnerabilities from the legacy inventory tree."""
    vulns: list[Any] = []
    for agent in report.agents:
        for server in agent.mcp_servers:
            for package in server.packages:
                vulns.extend(package.vulnerabilities)
    return vulns


def evidence(finding: Finding, key: str, default: Any = "") -> Any:
    value = finding.evidence.get(key, default)
    return default if value is None else value


def package_name(finding: Finding) -> str:
    value = evidence(finding, "package_name", "")
    if value:
        return str(value)
    identifier = finding.asset.identifier or ""
    if "/" in identifier:
        tail = identifier.rsplit("/", 1)[-1]
        return tail.rsplit("@", 1)[0]
    return finding.asset.name


def package_version(finding: Finding) -> str:
    value = evidence(finding, "package_version", "")
    if value:
        return str(value)
    identifier = finding.asset.identifier or ""
    if "@" in identifier:
        return identifier.rsplit("@", 1)[-1]
    return ""


def package_ecosystem(finding: Finding) -> str:
    value = evidence(finding, "ecosystem", "")
    if value:
        return str(value)
    identifier = finding.asset.identifier or ""
    if identifier.startswith("pkg:") and "/" in identifier:
        return identifier.removeprefix("pkg:").split("/", 1)[0]
    return ""


def severity_value(finding: Finding) -> str:
    return str(finding.effective_severity() or finding.severity or "unknown").lower()


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {severity.value: 0 for severity in Severity if severity != Severity.NONE}
    for finding in findings:
        severity = severity_value(finding)
        if severity in counts:
            counts[severity] += 1
    return counts


def has_high_or_critical(finding: Finding) -> bool:
    return severity_value(finding) in {"critical", "high"}


def is_medium(finding: Finding) -> bool:
    return severity_value(finding) == "medium"
