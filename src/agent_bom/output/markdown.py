"""Markdown output for PR comments, wiki pages, and GitHub issue bodies.

Produces a self-contained Markdown report with summary table and detailed findings.
"""

from __future__ import annotations

from agent_bom.compliance_utils import framework_qualified_finding_tags
from agent_bom.finding import Finding, FindingType
from agent_bom.graph.severity import severity_policy_rank
from agent_bom.models import AIBOMReport, BlastRadius, Severity
from agent_bom.output.exposure_path import exposure_path_brief_for_finding
from agent_bom.output.finding_views import (
    cve_findings,
    evidence,
    has_high_or_critical,
    package_name,
    package_version,
    ranked_cve_findings,
    severity_value,
)


def to_markdown(report: AIBOMReport, blast_radii: list[BlastRadius] | None = None) -> str:
    """Convert an AIBOMReport to Markdown string."""
    brs = blast_radii or report.blast_radii
    cve_rows = cve_findings(report, blast_radii)
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

    trust_lines = _trust_assessment_section(report)
    if trust_lines:
        lines.extend(trust_lines)

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
                    evidence_text = ", ".join(f"{key}={value}" for key, value in finding.evidence.items() if value is not None)
                    if evidence_text:
                        lines.append(f"- **Evidence**: {evidence_text}")
                lines.append("")

    # Findings table
    if cve_rows:
        lines.append("## Findings")
        lines.append("")
        lines.append("| Severity | CVE | Package | Version | Fix | CVSS | EPSS | KEV | CWE | Tags | Source | Agents |")
        lines.append("|----------|-----|---------|---------|-----|------|------|-----|-----|------|--------|--------|")

        for finding in sorted(cve_rows, key=lambda f: _finding_sev_order(severity_value(f))):
            vuln_id = finding.cve_id or finding.id
            sev_badge = _severity_text(severity_value(finding))
            cvss = f"{finding.cvss_score}" if finding.cvss_score is not None else "-"
            epss = f"{finding.epss_score:.4f}" if finding.epss_score is not None else "-"
            kev = "Yes" if finding.is_kev else "-"
            cwe = _md_cell(", ".join(finding.cwe_ids) if finding.cwe_ids else "-")
            tags = _md_cell(", ".join(framework_qualified_finding_tags(finding)) or "-")
            source = _md_cell(evidence(finding, "severity_source", "-") or "-")
            fix = finding.fixed_version or "-"
            agents = str(len(finding.affected_agents))
            lines.append(
                f"| {sev_badge} | {vuln_id} | {package_name(finding)} | {package_version(finding) or '-'} | {fix} | {cvss} | "
                f"{epss} | {kev} | {cwe} | {tags} | {source} | {agents} |"
            )

        lines.append("")

        lines.extend(_exposure_path_section(report, blast_radii))

    # Critical/High details
    critical_high = [finding for finding in cve_rows if has_high_or_critical(finding)]
    if critical_high:
        lines.append("## Critical & High Findings")
        lines.append("")
        for finding in critical_high:
            vuln_id = finding.cve_id or finding.id
            lines.append(f"### {vuln_id} — {package_name(finding)}@{package_version(finding) or '?'}")
            lines.append("")
            if finding.description:
                lines.append(f"> {finding.description}")
                lines.append("")
            lines.append(f"- **Severity**: {severity_value(finding).upper()}")
            severity_source = evidence(finding, "severity_source", "")
            if severity_source:
                lines.append(f"- **Severity source**: {severity_source}")
            if finding.cvss_score is not None:
                lines.append(f"- **CVSS**: {finding.cvss_score}")
            if finding.epss_score is not None:
                lines.append(f"- **EPSS**: {finding.epss_score:.4f}")
            epss_percentile = evidence(finding, "epss_percentile", None)
            if epss_percentile is not None:
                lines.append(f"- **EPSS percentile**: {float(epss_percentile):.4f}")
            if finding.is_kev:
                lines.append("- **KEV**: Yes (CISA Known Exploited)")
            kev_date_added = evidence(finding, "kev_date_added", "")
            if kev_date_added:
                lines.append(f"- **KEV date added**: {kev_date_added}")
            kev_due_date = evidence(finding, "kev_due_date", "")
            if kev_due_date:
                lines.append(f"- **KEV due date**: {kev_due_date}")
            if finding.fixed_version:
                lines.append(f"- **Fix**: Upgrade to {finding.fixed_version}")
            if finding.cwe_ids:
                lines.append(f"- **CWE**: {', '.join(finding.cwe_ids)}")
            compliance_tags = ", ".join(framework_qualified_finding_tags(finding))
            if compliance_tags:
                lines.append(f"- **Compliance tags**: {compliance_tags}")
            if finding.affected_agents:
                lines.append(f"- **Affected agents**: {', '.join(finding.affected_agents)}")
            if finding.exposed_credentials:
                lines.append(f"- **Exposed credentials**: {len(finding.exposed_credentials)}")
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


def _trust_assessment_section(report: AIBOMReport) -> list[str]:
    """Render dual-axis skill trust metadata in Markdown."""
    data = getattr(report, "trust_assessment_data", None)
    if not isinstance(data, dict) or not data:
        return []

    lines = [
        "## Skill Trust Assessment",
        "",
        "| Field | Value |",
        "|-------|-------|",
        f"| Verdict | `{_md_cell(data.get('verdict', 'benign'))}` |",
        f"| Content verdict | `{_md_cell(data.get('content_verdict', 'benign'))}` |",
        f"| Provenance verdict | `{_md_cell(data.get('provenance_verdict', 'unverified'))}` |",
        f"| Recommendation | `{_md_cell(data.get('overall_recommendation') or data.get('review_verdict', 'review'))}` |",
    ]
    if data.get("skill_name"):
        lines.append(f"| Skill | {_md_cell(data['skill_name'])} |")
    if data.get("source_file"):
        lines.append(f"| Source | `{_md_cell(data['source_file'])}` |")
    lines.append("")
    return lines


def _finding_sev_order(sev: str) -> int:
    return -severity_policy_rank(sev)


def _severity_text(sev: str) -> str:
    """Return a text badge for string severities from unified findings."""
    return f"**{sev.upper()}**"


def _md_cell(value: object) -> str:
    """Escape Markdown table separators without hiding human-readable context."""
    return str(value).replace("|", "\\|")


def _exposure_path_section(report: AIBOMReport, blast_radii: list[BlastRadius] | None) -> list[str]:
    """Render the top CVE findings as investigation-first exposure paths."""
    findings = ranked_cve_findings(report, blast_radii)
    if not findings:
        return []

    lines = [
        "## Exposure Paths",
        "",
        "| Rank | Risk | Severity | Path | Proof | Fix |",
        "|------|------|----------|------|-------|-----|",
    ]
    for rank, finding in enumerate(findings, 1):
        brief = exposure_path_brief_for_finding(finding, rank=rank)
        lines.append(
            f"| #{brief['rank']} | {brief['risk']} | {brief['severity']} | {_md_cell(brief['path'])} | "
            f"{_md_cell(brief['proof'])} | {_md_cell(brief['fix'])} |"
        )
    lines.append("")
    return lines
