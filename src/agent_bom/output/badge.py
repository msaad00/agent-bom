"""Shields.io badge output formats."""

from __future__ import annotations

import json
from pathlib import Path

from agent_bom.models import AIBOMReport, Severity
from agent_bom.output.finding_views import cve_findings, nested_vulnerabilities, severity_value


def to_badge(report: AIBOMReport) -> dict:
    """Generate a shields.io endpoint badge JSON from scan results.

    The output follows the shields.io endpoint schema:
    https://shields.io/badges/endpoint-badge

    Use with: https://img.shields.io/endpoint?url=<badge-json-url>
    """
    findings = cve_findings(report)
    if findings:
        severities = [severity_value(finding) for finding in findings]
    else:
        severities = [vuln.severity.value for vuln in nested_vulnerabilities(report)]

    critical = len([severity for severity in severities if severity == Severity.CRITICAL.value])
    high = len([severity for severity in severities if severity == Severity.HIGH.value])
    total = len(severities)

    if critical > 0:
        color = "critical"
        message = f"{critical} critical, {high} high"
    elif high > 0:
        color = "orange"
        message = f"{high} high, {total} total"
    elif total > 0:
        color = "yellow"
        message = f"{total} findings"
    else:
        color = "brightgreen"
        message = "clean"

    return {
        "schemaVersion": 1,
        "label": "agent-bom",
        "message": message,
        "color": color,
        "namedLogo": "shield",
    }


def export_badge(report: AIBOMReport, output_path: str) -> None:
    """Export shields.io endpoint badge JSON to file."""
    data = to_badge(report)
    Path(output_path).write_text(json.dumps(data, indent=2))


def to_rsp_badge(report: AIBOMReport) -> dict:
    """Generate Anthropic RSP v3.0 alignment badge (shields.io JSON endpoint format).

    Checks whether any Claude agents are present and whether they have
    critical/high vulnerabilities in their supply chain.
    """
    from agent_bom.models import AgentType

    claude_types = {AgentType.CLAUDE_DESKTOP, AgentType.CLAUDE_CODE}
    claude_agents = [a for a in report.agents if a.agent_type in claude_types]

    if not claude_agents:
        return {
            "schemaVersion": 1,
            "label": "Anthropic RSP",
            "message": "RSP n/a",
            "color": "lightgrey",
        }

    findings = cve_findings(report)
    has_vulns = any(severity_value(finding) in {Severity.CRITICAL.value, Severity.HIGH.value} for finding in findings)

    if has_vulns:
        return {
            "schemaVersion": 1,
            "label": "Anthropic RSP",
            "message": "RSP review needed",
            "color": "orange",
        }

    return {
        "schemaVersion": 1,
        "label": "Anthropic RSP",
        "message": "RSP v3.0 aligned",
        "color": "brightgreen",
    }
