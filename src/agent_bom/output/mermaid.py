"""Mermaid diagram generator for blast radius visualization.

Generates Mermaid flowchart syntax from blast radius data, suitable for
embedding in markdown documents, GitHub issues/PRs, or rendering with
any Mermaid-compatible tool.

Usage:
    agent-bom scan --format mermaid
    agent-bom scan --format mermaid --output blast-radius.mmd
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agent_bom.models import AIBOMReport, BlastRadius


def _sanitize_id(text: str) -> str:
    """Sanitize a string for use as a Mermaid node ID."""
    return re.sub(r"[^a-zA-Z0-9_]", "_", text)


def _sanitize_label(text: str) -> str:
    """Sanitize a string for use as a Mermaid node label."""
    return text.replace('"', "'").replace("\n", " ")[:80]


def to_mermaid(report: AIBOMReport, blast_radii: list[BlastRadius]) -> str:
    """Generate a Mermaid flowchart from blast radius data.

    The graph shows the attack chain:
        CVE → package → server → agent → credentials/tools

    Args:
        report: The AI-BOM report (used for metadata).
        blast_radii: List of BlastRadius objects to visualize.

    Returns:
        Mermaid flowchart as a string.
    """
    lines: list[str] = ["graph LR"]

    if not blast_radii:
        lines.append('    empty["No vulnerabilities found"]')
        return "\n".join(lines)

    # Deduplicate edges
    edges: set[str] = set()
    # Track severity for CVE node styling
    cve_severities: dict[str, str] = {}

    for br in blast_radii:
        cve_id = br.vulnerability.id
        cve_node = _sanitize_id(cve_id)
        sev = br.vulnerability.severity.value.lower()
        cve_severities[cve_node] = sev

        pkg_label = f"{br.package.name}@{br.package.version}"
        pkg_node = _sanitize_id(f"pkg_{br.package.name}_{br.package.version}")

        # CVE → package
        edge = f'    {cve_node}["{_sanitize_label(cve_id)}"] -->|affects| {pkg_node}["{_sanitize_label(pkg_label)}"]'
        edges.add(edge)

        # package → servers
        for server in br.affected_servers:
            srv_node = _sanitize_id(f"srv_{server.name}")
            edge = f'    {pkg_node} -->|in| {srv_node}["{_sanitize_label(server.name)}"]'
            edges.add(edge)

            # server → agents
            for agent in br.affected_agents:
                agt_node = _sanitize_id(f"agt_{agent.name}")
                edge = f'    {srv_node} -->|used by| {agt_node}["{_sanitize_label(agent.name)}"]'
                edges.add(edge)

        # server → credentials
        for cred in br.exposed_credentials:
            cred_node = _sanitize_id(f"cred_{cred}")
            # Link from each affected server
            for server in br.affected_servers:
                srv_node = _sanitize_id(f"srv_{server.name}")
                edge = f'    {srv_node} -->|exposes| {cred_node}["{_sanitize_label(cred)}"]'
                edges.add(edge)

        # server → tools
        for tool in br.exposed_tools:
            tool_node = _sanitize_id(f"tool_{tool.name}")
            for server in br.affected_servers:
                srv_node = _sanitize_id(f"srv_{server.name}")
                edge = f'    {srv_node} -->|exposes| {tool_node}["{_sanitize_label(tool.name)}"]'
                edges.add(edge)

    # Add edges
    for edge in sorted(edges):
        lines.append(edge)

    # Add severity styling
    style_map = {
        "critical": "fill:#d32f2f,color:#fff,stroke:#b71c1c",
        "high": "fill:#f57c00,color:#fff,stroke:#e65100",
        "medium": "fill:#fbc02d,color:#000,stroke:#f9a825",
        "low": "fill:#81c784,color:#000,stroke:#66bb6a",
    }
    for node, sev in cve_severities.items():
        if sev in style_map:
            lines.append(f"    style {node} {style_map[sev]}")

    return "\n".join(lines) + "\n"
