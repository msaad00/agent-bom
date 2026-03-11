"""Shields.io badge output formats."""

from __future__ import annotations

import json
from pathlib import Path

from agent_bom.models import AIBOMReport, Severity


def to_badge(report: AIBOMReport) -> dict:
    """Generate a shields.io endpoint badge JSON from scan results.

    The output follows the shields.io endpoint schema:
    https://shields.io/badges/endpoint-badge

    Use with: https://img.shields.io/endpoint?url=<badge-json-url>
    """
    all_vulns = []
    for agent in report.agents:
        for server in agent.mcp_servers:
            for pkg in server.packages:
                all_vulns.extend(pkg.vulnerabilities)
    critical = len([v for v in all_vulns if v.severity == Severity.CRITICAL])
    high = len([v for v in all_vulns if v.severity == Severity.HIGH])
    total = len(all_vulns)

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

    has_vulns = any(br.vulnerability.severity in (Severity.CRITICAL, Severity.HIGH) for br in report.blast_radii)

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
