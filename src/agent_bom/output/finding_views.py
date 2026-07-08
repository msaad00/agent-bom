"""Compatibility views over the unified Finding stream for output formatters."""

from __future__ import annotations

from typing import Any

from agent_bom.finding import Finding, FindingType, blast_radius_to_finding
from agent_bom.models import AIBOMReport, BlastRadius, Severity

_MACHINE_EXPORT_TYPES = (FindingType.CVE, FindingType.MALICIOUS_PACKAGE)


def cve_findings(report: AIBOMReport, blast_radii: list[BlastRadius] | None = None) -> list[Finding]:
    """Return CVE findings, accepting non-empty legacy BlastRadius overrides."""
    source_blast_radii = blast_radii if blast_radii is not None else report.blast_radii
    if source_blast_radii:
        return [blast_radius_to_finding(br) for br in source_blast_radii]

    return [finding for finding in report.to_findings() if finding.finding_type in _MACHINE_EXPORT_TYPES]


def machine_export_findings(report: AIBOMReport, blast_radii: list[BlastRadius] | None = None) -> list[Finding]:
    """Rows for flat machine exports (CSV/Parquet): CVE findings plus synthesized
    malicious-package findings.

    ``cve_findings`` only includes synthesized malicious (vuln-less typosquat /
    dep-confusion) findings when there are no BlastRadius rows to override with;
    once any CVE BlastRadius exists it returns the BlastRadius list alone, so a
    malicious-only package would silently vanish from CSV/Parquet even though
    JSON/SARIF (which read ``report.to_findings()``) still surface it. Append the
    malicious findings that the BlastRadius list doesn't already carry, deduped by
    finding id, so every export sees the same rows.
    """
    findings = cve_findings(report, blast_radii)
    seen = {getattr(finding, "id", None) for finding in findings}
    findings.extend(
        finding
        for finding in report.to_findings()
        if finding.finding_type == FindingType.MALICIOUS_PACKAGE and getattr(finding, "id", None) not in seen
    )
    return findings


def active_cve_findings(report: AIBOMReport, blast_radii: list[BlastRadius] | None = None) -> list[Finding]:
    """Return CVE findings that remain active after VEX suppression."""
    from agent_bom.vex import active_blast_radii

    source = blast_radii if blast_radii is not None else report.blast_radii
    if source:
        return cve_findings(report, active_blast_radii(source))
    return [finding for finding in cve_findings(report) if not finding.suppressed]


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


def finding_severity(finding: Finding) -> Severity:
    """Map a unified finding to the legacy Severity enum for console badges."""
    raw = severity_value(finding)
    if raw == "none":
        return Severity.NONE
    try:
        return Severity(raw)
    except ValueError:
        return Severity.UNKNOWN


def is_package_direct(finding: Finding) -> bool:
    return bool(evidence(finding, "package_is_direct", False))


def is_package_malicious(finding: Finding) -> bool:
    return bool(evidence(finding, "package_is_malicious", False))


def is_actionable_finding(finding: Finding) -> bool:
    """Return whether a CVE finding should surface in default actionable views."""
    if finding.is_actionable is not None:
        return bool(finding.is_actionable)
    if finding.suppressed:
        return False
    if finding.is_kev:
        return True
    if severity_value(finding) in {"critical", "high"}:
        return True
    if finding.exposed_credentials or finding.exposed_tools:
        return True
    if is_package_direct(finding) or is_package_malicious(finding):
        return True
    return False


def exploit_likelihood_value(finding: Finding) -> str:
    """Graded exploit-likelihood signal derived from unified finding enrichment."""
    from agent_bom.config import EPSS_ACTIVE_EXPLOITATION_THRESHOLD

    if finding.is_kev:
        return "actively_exploited"
    epss = finding.epss_score
    percentile = evidence(finding, "epss_percentile", None)
    if epss is not None and epss >= EPSS_ACTIVE_EXPLOITATION_THRESHOLD:
        return "likely_exploited"
    if percentile is not None and percentile >= 95:
        return "likely_exploited"
    if percentile is not None and percentile >= 80:
        return "public_exploit"
    return "theoretical"


def finding_references(finding: Finding) -> list[str]:
    refs = evidence(finding, "references", [])
    if isinstance(refs, list):
        return [str(ref) for ref in refs if ref]
    return []


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


def ranked_cve_findings(
    report: AIBOMReport,
    blast_radii: list[BlastRadius] | None = None,
    *,
    limit: int = 10,
) -> list[Finding]:
    """Return top CVE findings by unified risk score for exposure-path views."""
    findings = cve_findings(report, blast_radii)
    return sorted(findings, key=lambda finding: float(finding.risk_score or 0.0), reverse=True)[:limit]


def topology_package_key(finding: Finding) -> tuple[str, str]:
    """Return ``(name, ecosystem)`` for graph/mermaid package nodes."""
    return package_name(finding), package_ecosystem(finding)


def compliance_row_dict(finding: Finding) -> dict[str, Any]:
    """Framework table row payload from a unified CVE finding."""
    return {
        "severity": severity_value(finding),
        "owasp_tags": list(finding.owasp_tags),
        "atlas_tags": list(finding.atlas_tags),
        "attack_tags": list(finding.attack_tags),
        "nist_ai_rmf_tags": list(finding.nist_ai_rmf_tags),
        "owasp_agentic_tags": list(finding.owasp_agentic_tags),
        "eu_ai_act_tags": list(finding.eu_ai_act_tags),
    }


def topology_vuln_dict(finding: Finding) -> dict[str, Any]:
    """Project a unified CVE finding into the graph builder vuln payload shape."""
    summary = finding.description or finding.title or ""
    return {
        "id": finding.cve_id or finding.title,
        "severity": severity_value(finding),
        "summary": summary[:100] if summary else "",
        "risk_score": finding.risk_score,
        "cvss_score": finding.cvss_score or 0,
        "fix_version": finding.fixed_version or "",
        "owasp_tags": list(finding.owasp_tags),
        "atlas_tags": list(finding.atlas_tags),
        "attack_tags": list(finding.attack_tags),
        "nist_ai_rmf_tags": list(finding.nist_ai_rmf_tags),
        "owasp_mcp_tags": list(finding.owasp_mcp_tags),
        "owasp_agentic_tags": list(finding.owasp_agentic_tags),
        "eu_ai_act_tags": list(finding.eu_ai_act_tags),
    }
