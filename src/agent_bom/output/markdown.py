"""Markdown output for PR comments, wiki pages, and GitHub issue bodies.

Produces a self-contained Markdown report with summary table and detailed findings.
"""

from __future__ import annotations

from agent_bom.finding import Finding, FindingType
from agent_bom.models import AIBOMReport, BlastRadius, Severity


def to_markdown(report: AIBOMReport, blast_radii: list[BlastRadius] | None = None) -> str:
    """Convert an AIBOMReport to Markdown string."""
    brs = blast_radii or report.blast_radii
    policy_findings = _non_cve_findings(report)
    lines: list[str] = []

    # Header
    lines.append("# agent-bom Scan Report")
    lines.append("")
    lines.append(f"**Generated**: {report.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}  ")
    lines.append(f"**Version**: agent-bom v{report.tool_version}")
    lines.append("")

    # Summary
    sev_counts = _severity_counts(brs)
    lines.append("## Summary")
    lines.append("")
    lines.append("| Metric | Count |")
    lines.append("|--------|-------|")
    lines.append(f"| Agents discovered | {report.total_agents} |")
    lines.append(f"| MCP servers | {report.total_servers} |")
    lines.append(f"| Packages scanned | {report.total_packages} |")
    lines.append(f"| Vulnerabilities | {len(brs)} |")
    lines.append(f"| Policy/security findings | {len(policy_findings)} |")
    lines.append(f"| Critical | {sev_counts.get('critical', 0)} |")
    lines.append(f"| High | {sev_counts.get('high', 0)} |")
    lines.append(f"| Medium | {sev_counts.get('medium', 0)} |")
    lines.append(f"| Low | {sev_counts.get('low', 0)} |")
    lines.append("")

    if not brs and not policy_findings:
        lines.append("No vulnerabilities found.")
        return "\n".join(lines) + "\n"

    if policy_findings:
        lines.append("## Policy & Security Findings")
        lines.append("")
        lines.append("| Severity | Type | Asset | Finding | Source |")
        lines.append("|----------|------|-------|---------|--------|")
        for finding in sorted(policy_findings, key=lambda f: _finding_sev_order(f.severity)):
            asset = _md_cell(finding.asset.name or finding.asset.identifier or "-")
            location = f"<br>`{finding.asset.location}`" if finding.asset.location else ""
            title = _md_cell(finding.title or finding.description or finding.finding_type.value)
            source = finding.source.value
            lines.append(
                f"| {_severity_text(finding.severity)} | `{finding.finding_type.value}` | {asset}{location} | {title} | `{source}` |"
            )
        lines.append("")

        high_policy_findings = [f for f in policy_findings if f.severity.lower() in {"critical", "high"}]
        if high_policy_findings:
            lines.append("## High-Risk Policy Findings")
            lines.append("")
            for finding in high_policy_findings:
                title = finding.title or finding.finding_type.value
                lines.append(f"### {title}")
                lines.append("")
                lines.append(f"- **Severity**: {finding.severity.upper()}")
                lines.append(f"- **Type**: {finding.finding_type.value}")
                lines.append(f"- **Asset**: {finding.asset.name}")
                if finding.asset.location:
                    lines.append(f"- **Location**: `{finding.asset.location}`")
                if finding.description:
                    lines.append(f"- **Description**: {finding.description}")
                if finding.remediation_guidance:
                    lines.append(f"- **Remediation**: {finding.remediation_guidance}")
                if finding.evidence:
                    evidence = ", ".join(f"{key}={value}" for key, value in finding.evidence.items() if value is not None)
                    if evidence:
                        lines.append(f"- **Evidence**: {evidence}")
                lines.append("")

    # Findings table
    if brs:
        lines.append("## Findings")
        lines.append("")
        lines.append("| Severity | CVE | Package | Version | Fix | CVSS | Agents |")
        lines.append("|----------|-----|---------|---------|-----|------|--------|")

        for br in sorted(brs, key=lambda b: _sev_order(b.vulnerability.severity)):
            v = br.vulnerability
            sev_badge = _severity_badge(v.severity)
            cvss = f"{v.cvss_score}" if v.cvss_score is not None else "-"
            fix = v.fixed_version or "-"
            agents = str(len(br.affected_agents))
            lines.append(f"| {sev_badge} | {v.id} | {br.package.name} | {br.package.version or '-'} | {fix} | {cvss} | {agents} |")

        lines.append("")

    # Critical/High details
    critical_high = [br for br in brs if br.vulnerability.severity in (Severity.CRITICAL, Severity.HIGH)]
    if critical_high:
        lines.append("## Critical & High Findings")
        lines.append("")
        for br in critical_high:
            v = br.vulnerability
            lines.append(f"### {v.id} — {br.package.name}@{br.package.version or '?'}")
            lines.append("")
            if v.summary:
                lines.append(f"> {v.summary}")
                lines.append("")
            lines.append(f"- **Severity**: {v.severity.value.upper()}")
            if v.cvss_score is not None:
                lines.append(f"- **CVSS**: {v.cvss_score}")
            if v.epss_score is not None:
                lines.append(f"- **EPSS**: {v.epss_score:.4f}")
            if v.is_kev:
                lines.append("- **KEV**: Yes (CISA Known Exploited)")
            if v.fixed_version:
                lines.append(f"- **Fix**: Upgrade to {v.fixed_version}")
            if v.cwe_ids:
                lines.append(f"- **CWE**: {', '.join(v.cwe_ids)}")
            if br.affected_agents:
                lines.append(f"- **Affected agents**: {', '.join(a.name for a in br.affected_agents)}")
            if br.exposed_credentials:
                lines.append(f"- **Exposed credentials**: {len(br.exposed_credentials)}")
            lines.append("")

    # Footer
    lines.append("---")
    lines.append(f"*Scanned by [agent-bom](https://github.com/msaad00/agent-bom) v{report.tool_version}*")

    return "\n".join(lines) + "\n"


def export_markdown(report: AIBOMReport, output_path: str, blast_radii: list[BlastRadius] | None = None) -> None:
    """Write Markdown report to file."""
    from pathlib import Path

    Path(output_path).write_text(to_markdown(report, blast_radii), encoding="utf-8")


def _severity_counts(brs: list[BlastRadius]) -> dict[str, int]:
    """Count findings by severity."""
    counts: dict[str, int] = {}
    for br in brs:
        key = br.vulnerability.severity.value
        counts[key] = counts.get(key, 0) + 1
    return counts


def _non_cve_findings(report: AIBOMReport) -> list[Finding]:
    """Return unified findings that do not already appear in the CVE table."""
    return [finding for finding in report.to_findings() if finding.finding_type != FindingType.CVE]


_SEV_ORDER = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.UNKNOWN: 4, Severity.NONE: 5}
_FINDING_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4, "none": 5}


def _sev_order(sev: Severity) -> int:
    return _SEV_ORDER.get(sev, 99)


def _finding_sev_order(sev: str) -> int:
    return _FINDING_SEV_ORDER.get(sev.lower(), 99)


def _severity_badge(sev: Severity) -> str:
    """Return a text badge for severity."""
    return f"**{sev.value.upper()}**"


def _severity_text(sev: str) -> str:
    """Return a text badge for string severities from unified findings."""
    return f"**{sev.upper()}**"


def _md_cell(value: object) -> str:
    """Escape Markdown table separators without hiding human-readable context."""
    return str(value).replace("|", "\\|")
