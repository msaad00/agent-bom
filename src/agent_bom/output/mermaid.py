"""Mermaid diagram generator for supply chain and blast radius visualization.

Generates Mermaid flowchart syntax suitable for embedding in markdown
documents, GitHub issues/PRs, or rendering with any Mermaid-compatible tool.

Two modes:
  - **supply-chain** (default): Full hierarchy Provider → Agent → Server → Package
  - **attack-flow**: CVE-centric blast radius chains CVE → Package → Server → Agent

Usage:
    agent-bom scan --format mermaid                          # supply-chain (default)
    agent-bom scan --format mermaid --mermaid-mode attack-flow
    agent-bom scan --format mermaid --output diagram.mmd
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


def to_mermaid_supply_chain(report: AIBOMReport) -> str:
    """Generate a Mermaid flowchart showing the full AI supply chain hierarchy.

    Layout: Provider --> Agent --> MCP Server --> Package
    Vulnerable packages and credential-bearing servers are highlighted.

    Args:
        report: The AI-BOM report.

    Returns:
        Mermaid flowchart as a string.
    """
    lines: list[str] = ["graph LR"]

    if not report.agents:
        lines.append('    empty["No agents discovered"]')
        return "\n".join(lines)

    edges: set[str] = set()
    server_styles: dict[str, str] = {}
    pkg_styles: dict[str, str] = {}
    provider_seen: set[str] = set()

    for agent in report.agents:
        source = agent.source or "local"
        prov_node = _sanitize_id(f"prov_{source}")
        agt_node = _sanitize_id(f"agt_{agent.name}")

        # Provider node (only once)
        if source not in provider_seen:
            provider_seen.add(source)
            prov_label = _provider_label(source)
            edges.add(f'    {prov_node}["{_sanitize_label(prov_label)}"]')

        # Provider → Agent
        edges.add(
            f'    {prov_node} --> {agt_node}["{_sanitize_label(agent.name)}"]'
        )

        for srv in agent.mcp_servers:
            srv_node = _sanitize_id(f"srv_{agent.name}_{srv.name}")
            cred_badge = ""
            if srv.has_credentials:
                cred_badge = f" 🔑{len(srv.credential_names)}"
                server_styles[srv_node] = "cred"

            pkg_badge = f" ({len(srv.packages)})"
            srv_label = f"{srv.name}{cred_badge}{pkg_badge}"

            # Agent → Server
            edges.add(
                f'    {agt_node} --> {srv_node}["{_sanitize_label(srv_label)}"]'
            )

            # Server → Packages (show top 5 per server to avoid explosion)
            for pkg in srv.packages[:5]:
                pkg_node = _sanitize_id(f"pkg_{pkg.name}_{pkg.version}")
                pkg_label = f"{pkg.name}@{pkg.version}"

                if pkg.vulnerabilities:
                    sev = max(
                        (v.severity.value.lower() for v in pkg.vulnerabilities),
                        key=lambda s: {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(s, 0),
                        default="low",
                    )
                    vuln_count = len(pkg.vulnerabilities)
                    pkg_label += f" ⚠{vuln_count}"
                    pkg_styles[pkg_node] = sev
                    if srv_node not in server_styles:
                        server_styles[srv_node] = "vuln"

                edges.add(
                    f'    {srv_node} --> {pkg_node}["{_sanitize_label(pkg_label)}"]'
                )

            if len(srv.packages) > 5:
                more_node = _sanitize_id(f"more_{agent.name}_{srv.name}")
                edges.add(
                    f'    {srv_node} -.-> {more_node}["{len(srv.packages) - 5} more..."]'
                )

    for edge in sorted(edges):
        lines.append(edge)

    # Styling
    sev_style = {
        "critical": "fill:#d32f2f,color:#fff,stroke:#b71c1c",
        "high": "fill:#f57c00,color:#fff,stroke:#e65100",
        "medium": "fill:#fbc02d,color:#000,stroke:#f9a825",
        "low": "fill:#81c784,color:#000,stroke:#66bb6a",
    }
    for node, sev in pkg_styles.items():
        if sev in sev_style:
            lines.append(f"    style {node} {sev_style[sev]}")

    for node, stype in server_styles.items():
        if stype == "cred":
            lines.append(f"    style {node} fill:#fff3e0,stroke:#e65100,stroke-width:2px")
        elif stype == "vuln":
            lines.append(f"    style {node} fill:#fbe9e7,stroke:#b71c1c,stroke-width:2px")

    return "\n".join(lines) + "\n"


def _provider_label(source: str) -> str:
    """Human-readable label for provider source."""
    labels = {
        "local": "Local",
        "aws-bedrock": "AWS Bedrock",
        "aws-ecs": "AWS ECS",
        "azure-container-apps": "Azure Container Apps",
        "gcp-vertex-ai": "GCP Vertex AI",
        "databricks": "Databricks",
        "snowflake": "Snowflake",
        "snowflake-cortex": "Snowflake Cortex",
        "mcp-registry": "MCP Registry",
        "huggingface": "Hugging Face",
        "openai": "OpenAI",
    }
    return labels.get(source, source.replace("-", " ").title())
