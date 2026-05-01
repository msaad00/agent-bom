"""Mermaid diagram generator for supply chain and blast radius visualization.

Generates Mermaid flowchart syntax suitable for embedding in markdown
documents, GitHub issues/PRs, or rendering with any Mermaid-compatible tool.

Three modes:
  - **supply-chain** (default): Full hierarchy Provider → Agent → Server → Package
  - **attack-flow**: CVE-centric blast radius chains CVE → Package → Server → Agent
  - **lifecycle**: Vulnerability lifecycle gantt timeline per package

Usage:
    agent-bom scan --format mermaid                               # supply-chain (default)
    agent-bom scan --format mermaid --mermaid-mode attack-flow
    agent-bom scan --format mermaid --mermaid-mode lifecycle
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


class _MermaidIds:
    """Map descriptive raw entity keys to short deterministic Mermaid IDs."""

    def __init__(self) -> None:
        self._ids: dict[str, str] = {}

    def get(self, raw: str) -> str:
        if raw not in self._ids:
            self._ids[raw] = f"n{len(self._ids) + 1}"
        return self._ids[raw]


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
    ids = _MermaidIds()

    for br in blast_radii:
        cve_id = br.vulnerability.id
        cve_node = ids.get(f"cve:{cve_id}")
        sev = br.vulnerability.severity.value.lower()
        cve_severities[cve_node] = sev

        pkg_label = f"{br.package.name}@{br.package.version}"
        pkg_node = ids.get(f"pkg:{br.package.ecosystem}:{br.package.name}@{br.package.version}")

        # CVE → package
        edge = f'    {cve_node}["{_sanitize_label(cve_id)}"] -->|affects| {pkg_node}["{_sanitize_label(pkg_label)}"]'
        edges.add(edge)

        # package → servers
        for server in br.affected_servers:
            srv_node = ids.get(f"srv:{server.name}")
            edge = f'    {pkg_node} -->|in| {srv_node}["{_sanitize_label(server.name)}"]'
            edges.add(edge)

            # server → agents
            for agent in br.affected_agents:
                agt_node = ids.get(f"agt:{agent.name}")
                edge = f'    {srv_node} -->|used by| {agt_node}["{_sanitize_label(agent.name)}"]'
                edges.add(edge)

        # server → credentials
        for cred in br.exposed_credentials:
            cred_node = ids.get(f"cred:{cred}")
            # Link from each affected server
            for server in br.affected_servers:
                srv_node = ids.get(f"srv:{server.name}")
                edge = f'    {srv_node} -->|exposes| {cred_node}["{_sanitize_label(cred)}"]'
                edges.add(edge)

        # server → tools
        for tool in br.exposed_tools:
            tool_node = ids.get(f"tool:{tool.name}")
            for server in br.affected_servers:
                srv_node = ids.get(f"srv:{server.name}")
                edge = f'    {srv_node} -->|exposes| {tool_node}["{_sanitize_label(tool.name)}"]'
                edges.add(edge)

        # credential → tools reachable through the same affected server scope.
        # This mirrors the conservative graph-builder mapping used by JSON,
        # Cytoscape, GraphML, and Cypher exports.
        for cred in br.exposed_credentials:
            cred_node = ids.get(f"cred:{cred}")
            for tool in br.exposed_tools:
                tool_node = ids.get(f"tool:{tool.name}")
                edge = f"    {cred_node} -.->|reaches_tool| {tool_node}"
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
    ids = _MermaidIds()

    for agent in report.agents:
        source = agent.source or "local"
        prov_node = ids.get(f"prov:{source}")
        agt_node = ids.get(f"agt:{agent.name}")

        # Provider node (only once)
        if source not in provider_seen:
            provider_seen.add(source)
            prov_label = _provider_label(source)
            edges.add(f'    {prov_node}["{_sanitize_label(prov_label)}"]')

        # Provider → Agent
        edges.add(f'    {prov_node} --> {agt_node}["{_sanitize_label(agent.name)}"]')

        for srv in agent.mcp_servers:
            srv_node = ids.get(f"srv:{agent.name}:{srv.name}")
            cred_badge = ""
            if srv.has_credentials:
                cred_badge = f" 🔑{len(srv.credential_names)}"
                server_styles[srv_node] = "cred"

            pkg_badge = f" ({len(srv.packages)})"
            srv_label = f"{srv.name}{cred_badge}{pkg_badge}"

            # Agent → Server
            edges.add(f'    {agt_node} --> {srv_node}["{_sanitize_label(srv_label)}"]')

            # Server → Packages (show top 5 per server to avoid explosion)
            for pkg in srv.packages[:5]:
                pkg_node = ids.get(f"pkg:{pkg.ecosystem}:{pkg.name}@{pkg.version}")
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

                edges.add(f'    {srv_node} --> {pkg_node}["{_sanitize_label(pkg_label)}"]')

            if len(srv.packages) > 5:
                more_node = ids.get(f"more:{agent.name}:{srv.name}")
                edges.add(f'    {srv_node} -.-> {more_node}["{len(srv.packages) - 5} more..."]')

            tool_nodes: list[tuple[str, str]] = []
            for tool in srv.tools:
                tool_node = ids.get(f"tool:{agent.name}:{srv.name}:{tool.name}")
                tool_nodes.append((tool.name, tool_node))
                edges.add(f'    {srv_node} -->|provides_tool| {tool_node}["{_sanitize_label(tool.name)}"]')

            for cred in srv.credential_names:
                cred_node = ids.get(f"cred:{agent.name}:{srv.name}:{cred}")
                edges.add(f'    {srv_node} -->|exposes_cred| {cred_node}["{_sanitize_label(cred)}"]')
                for _tool_name, tool_node in tool_nodes:
                    edges.add(f"    {cred_node} -.->|reaches_tool| {tool_node}")

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


def to_mermaid_lifecycle(report: AIBOMReport, blast_radii: list[BlastRadius]) -> str:
    """Generate a Mermaid gantt chart showing vulnerability lifecycle timeline.

    Shows per-package milestones: scan date → vuln discovered → fix available.

    Args:
        report: The AI-BOM report (used for scan date).
        blast_radii: List of BlastRadius objects to visualize.

    Returns:
        Mermaid gantt chart as a string.
    """
    lines: list[str] = [
        "gantt",
        "    title Vulnerability Lifecycle Timeline",
        "    dateFormat YYYY-MM-DD",
        "    axisFormat %Y-%m",
    ]

    if not blast_radii:
        lines.append("    section No vulnerabilities")
        lines.append("    Clean scan :done, s0, 2025-01-01, 1d")
        return "\n".join(lines) + "\n"

    # Use report date as scan date
    scan_date = getattr(report, "generated_at", None) or "2025-01-01"
    if hasattr(scan_date, "strftime"):
        scan_date = scan_date.strftime("%Y-%m-%d")
    else:
        scan_date = str(scan_date)[:10]

    # Group blast radii by package
    pkg_vulns: dict[str, list[BlastRadius]] = {}
    for br in blast_radii:
        pkg_label = f"{br.package.name}@{br.package.version}"
        pkg_vulns.setdefault(pkg_label, []).append(br)

    task_id = 0
    for pkg_label, brs in sorted(pkg_vulns.items()):
        safe_label = _sanitize_label(pkg_label)
        lines.append(f"    section {safe_label}")

        # Scanned milestone
        lines.append(f"    Scanned :done, t{task_id}, {scan_date}, 1d")
        prev_id = f"t{task_id}"
        task_id += 1

        for br in brs:
            vuln = br.vulnerability
            vuln_id = vuln.id

            # Determine discovery date
            discover_date = getattr(vuln, "published_at", None) or getattr(vuln, "nvd_published", None)
            if discover_date:
                discover_str = str(discover_date)[:10]
                lines.append(f"    {vuln_id} :crit, t{task_id}, {discover_str}, 1d")
            else:
                lines.append(f"    {vuln_id} :crit, t{task_id}, after {prev_id}, 1d")
            prev_id = f"t{task_id}"
            task_id += 1

            # Fixed version milestone
            if vuln.fixed_version:
                lines.append(f"    Fix → {vuln.fixed_version} :active, t{task_id}, after {prev_id}, 1d")
                prev_id = f"t{task_id}"
                task_id += 1

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
