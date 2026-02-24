"""SVG supply chain diagram generator.

Produces a self-contained SVG file showing the full AI supply chain hierarchy:
    Source/Provider --> Agent --> MCP Server --> Package (with CVE indicators)

Pure Python implementation — no external rendering dependencies required.
Output is viewable in any browser, image viewer, or embedded in HTML/markdown.

Usage:
    agent-bom scan --format svg -o supply-chain.svg
"""

from __future__ import annotations

import html
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agent_bom.models import AIBOMReport, BlastRadius

# ── Layout constants ──────────────────────────────────────────────────────────

_COL_PROVIDER = 50
_COL_AGENT = 320
_COL_SERVER = 590
_COL_PACKAGE = 860
_COL_CVE = 1130

_NODE_W = 200
_NODE_H = 44
_NODE_RX = 8
_ROW_GAP = 14
_HEADER_H = 80

# ── Color palette ─────────────────────────────────────────────────────────────

_COLORS = {
    "provider": ("#1e3a5f", "#e8f0fe", "#90b4d6"),
    "agent": ("#1b5e20", "#e8f5e9", "#81c784"),
    "server_clean": ("#37474f", "#eceff1", "#90a4ae"),
    "server_vuln": ("#b71c1c", "#fbe9e7", "#ef9a9a"),
    "server_cred": ("#e65100", "#fff3e0", "#ffcc80"),
    "pkg_clean": ("#455a64", "#eceff1", "#b0bec5"),
    "pkg_vuln": ("#c62828", "#ffebee", "#ef9a9a"),
    "cve_critical": ("#d32f2f", "#ffcdd2", "#ef5350"),
    "cve_high": ("#e65100", "#ffe0b2", "#ff9800"),
    "cve_medium": ("#f9a825", "#fff9c4", "#ffee58"),
    "cve_low": ("#2e7d32", "#c8e6c9", "#66bb6a"),
}

_FONT = "system-ui, -apple-system, 'Segoe UI', sans-serif"


def to_svg(
    report: AIBOMReport,
    blast_radii: list[BlastRadius],
) -> str:
    """Generate a self-contained SVG supply chain diagram.

    Shows hierarchical layout: Provider -> Agent -> MCP Server -> Package -> CVE
    Color-coded by severity and status.

    Args:
        report: The AI-BOM report.
        blast_radii: List of BlastRadius objects for CVE indicators.

    Returns:
        Complete SVG document as a string.
    """
    vuln_pkg_keys: set[tuple[str, str]] = {
        (br.package.name, br.package.ecosystem) for br in blast_radii
    }
    pkg_cve_map: dict[tuple[str, str], list[dict]] = {}
    for br in blast_radii:
        key = (br.package.name, br.package.ecosystem)
        if key not in pkg_cve_map:
            pkg_cve_map[key] = []
        pkg_cve_map[key].append({
            "id": br.vulnerability.id,
            "severity": br.vulnerability.severity.value.lower(),
        })

    # ── Collect layout items per column ───────────────────────────────────
    providers: list[dict] = []
    agents: list[dict] = []
    servers: list[dict] = []
    packages: list[dict] = []
    cves: list[dict] = []

    provider_set: set[str] = set()
    cve_set: set[str] = set()

    # Maps for edge routing
    provider_to_agents: list[tuple[str, str]] = []
    agent_to_servers: list[tuple[str, str]] = []
    server_to_packages: list[tuple[str, str]] = []
    package_to_cves: list[tuple[str, str]] = []

    for agent in report.agents:
        source = agent.source or "local"
        if source not in provider_set:
            provider_set.add(source)
            providers.append({"id": f"p:{source}", "label": _provider_label(source)})

        aid = f"a:{agent.name}"
        agents.append({
            "id": aid,
            "label": agent.name,
            "type": agent.agent_type.value,
            "servers": len(agent.mcp_servers),
        })
        provider_to_agents.append((f"p:{source}", aid))

        for srv in agent.mcp_servers:
            sid = f"s:{agent.name}:{srv.name}"
            has_vuln = any(
                (p.name, p.ecosystem) in vuln_pkg_keys for p in srv.packages
            )
            has_cred = srv.has_credentials
            stype = "server_vuln" if has_vuln else ("server_cred" if has_cred else "server_clean")

            cred_label = ""
            if has_cred:
                cred_label = f" [{len(srv.credential_names)} cred]"

            servers.append({
                "id": sid,
                "label": srv.name + cred_label,
                "type": stype,
                "pkg_count": len(srv.packages),
                "tool_count": len(srv.tools) if srv.tools else 0,
            })
            agent_to_servers.append((aid, sid))

            for pkg in srv.packages:
                pkg_key = (pkg.name, pkg.ecosystem)
                pid = f"pkg:{pkg.name}:{pkg.ecosystem}"
                is_vuln = pkg_key in vuln_pkg_keys

                packages.append({
                    "id": pid,
                    "label": f"{pkg.name}@{pkg.version}",
                    "type": "pkg_vuln" if is_vuln else "pkg_clean",
                    "ecosystem": pkg.ecosystem,
                })
                server_to_packages.append((sid, pid))

                if is_vuln and pkg_key in pkg_cve_map:
                    for cve_info in pkg_cve_map[pkg_key]:
                        cve_id = f"cve:{cve_info['id']}"
                        if cve_info["id"] not in cve_set:
                            cve_set.add(cve_info["id"])
                            cves.append({
                                "id": cve_id,
                                "label": cve_info["id"],
                                "type": f"cve_{cve_info['severity']}",
                                "severity": cve_info["severity"],
                            })
                        package_to_cves.append((pid, cve_id))

    # Deduplicate packages/servers (same ID can appear under multiple parents)
    packages = _dedup_by_id(packages)
    servers = _dedup_by_id(servers)

    # ── Assign Y positions ────────────────────────────────────────────────
    columns = [providers, agents, servers, packages, cves]
    max_rows = max(len(col) for col in columns) if columns else 1
    total_h = _HEADER_H + max_rows * (_NODE_H + _ROW_GAP) + 40

    col_positions = [_COL_PROVIDER, _COL_AGENT, _COL_SERVER, _COL_PACKAGE, _COL_CVE]
    node_y_map: dict[str, float] = {}

    for col_items, _x in zip(columns, col_positions):
        col_h = len(col_items) * (_NODE_H + _ROW_GAP)
        start_y = _HEADER_H + (total_h - _HEADER_H - col_h) / 2
        for i, item in enumerate(col_items):
            node_y_map[item["id"]] = start_y + i * (_NODE_H + _ROW_GAP)

    total_w = _COL_CVE + _NODE_W + 60 if cves else _COL_PACKAGE + _NODE_W + 60

    # ── Build SVG ─────────────────────────────────────────────────────────
    parts: list[str] = []
    parts.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {total_w} {total_h}" '
        f'width="{total_w}" height="{total_h}" '
        f'style="font-family: {_FONT}; font-size: 12px; background: #fafafa;">'
    )

    # Defs: arrowhead
    parts.append("""<defs>
  <marker id="arrow" viewBox="0 0 10 6" refX="10" refY="3"
    markerWidth="8" markerHeight="6" orient="auto-start-reverse">
    <path d="M 0 0 L 10 3 L 0 6 z" fill="#999"/>
  </marker>
</defs>""")

    # Title bar
    agent_count = len(agents)
    server_count = len(servers)
    pkg_count = len(packages)
    vuln_count = len(cves)
    parts.append(
        f'<text x="{total_w / 2}" y="30" text-anchor="middle" '
        f'font-size="18" font-weight="bold" fill="#1a1a1a">'
        f'AI Supply Chain — agent-bom</text>'
    )
    parts.append(
        f'<text x="{total_w / 2}" y="52" text-anchor="middle" '
        f'font-size="13" fill="#666">'
        f'{agent_count} agents | {server_count} servers | '
        f'{pkg_count} packages | {vuln_count} CVEs</text>'
    )

    # Column headers
    headers = [
        (_COL_PROVIDER, "Sources"), (_COL_AGENT, "Agents"),
        (_COL_SERVER, "MCP Servers"), (_COL_PACKAGE, "Packages"),
    ]
    if cves:
        headers.append((_COL_CVE, "CVEs"))
    for x, label in headers:
        parts.append(
            f'<text x="{x + _NODE_W / 2}" y="{_HEADER_H - 12}" '
            f'text-anchor="middle" font-size="13" font-weight="600" fill="#444">'
            f'{label}</text>'
        )

    # Edges (draw first so nodes appear on top)
    all_edges = (
        provider_to_agents + agent_to_servers +
        server_to_packages + package_to_cves
    )
    col_x_map = {}
    for item in providers:
        col_x_map[item["id"]] = _COL_PROVIDER
    for item in agents:
        col_x_map[item["id"]] = _COL_AGENT
    for item in servers:
        col_x_map[item["id"]] = _COL_SERVER
    for item in packages:
        col_x_map[item["id"]] = _COL_PACKAGE
    for item in cves:
        col_x_map[item["id"]] = _COL_CVE

    seen_edges: set[tuple[str, str]] = set()
    for src, tgt in all_edges:
        if (src, tgt) in seen_edges:
            continue
        seen_edges.add((src, tgt))
        if src not in node_y_map or tgt not in node_y_map:
            continue
        sx = col_x_map.get(src, 0) + _NODE_W
        sy = node_y_map[src] + _NODE_H / 2
        tx = col_x_map.get(tgt, 0)
        ty = node_y_map[tgt] + _NODE_H / 2
        mid = (sx + tx) / 2
        parts.append(
            f'<path d="M {sx} {sy} C {mid} {sy}, {mid} {ty}, {tx} {ty}" '
            f'fill="none" stroke="#ccc" stroke-width="1.5" marker-end="url(#arrow)"/>'
        )

    # Nodes
    def _draw_nodes(items: list[dict], col_x: int, color_key: str) -> None:
        for item in items:
            y = node_y_map.get(item["id"], 0)
            ctype = item.get("type", color_key)
            colors = _COLORS.get(ctype, _COLORS.get(color_key, ("#333", "#f5f5f5", "#999")))
            text_color, bg_color, border_color = colors
            label = html.escape(item["label"][:28])

            parts.append(
                f'<rect x="{col_x}" y="{y}" width="{_NODE_W}" height="{_NODE_H}" '
                f'rx="{_NODE_RX}" fill="{bg_color}" stroke="{border_color}" stroke-width="1.5"/>'
            )
            parts.append(
                f'<text x="{col_x + _NODE_W / 2}" y="{y + _NODE_H / 2 + 4}" '
                f'text-anchor="middle" font-size="11" font-weight="500" fill="{text_color}">'
                f'{label}</text>'
            )

    _draw_nodes(providers, _COL_PROVIDER, "provider")
    _draw_nodes(agents, _COL_AGENT, "agent")
    _draw_nodes(servers, _COL_SERVER, "server_clean")
    _draw_nodes(packages, _COL_PACKAGE, "pkg_clean")
    _draw_nodes(cves, _COL_CVE, "cve_medium")

    # Empty state
    if not report.agents:
        parts.append(
            f'<text x="{total_w / 2}" y="{total_h / 2}" text-anchor="middle" '
            f'font-size="16" fill="#999">No agents discovered</text>'
        )

    parts.append("</svg>")
    return "\n".join(parts)


def export_svg(
    report: AIBOMReport,
    blast_radii: list[BlastRadius],
    output_path: str,
) -> None:
    """Generate and write SVG supply chain diagram to a file."""
    from pathlib import Path

    svg = to_svg(report, blast_radii)
    Path(output_path).write_text(svg, encoding="utf-8")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _dedup_by_id(items: list[dict]) -> list[dict]:
    """Deduplicate items by their 'id' key, keeping first occurrence."""
    seen: set[str] = set()
    result: list[dict] = []
    for item in items:
        if item["id"] not in seen:
            seen.add(item["id"])
            result.append(item)
    return result


def _provider_label(source: str) -> str:
    """Human-readable label for a provider source."""
    labels = {
        "local": "Local",
        "aws-bedrock": "AWS Bedrock",
        "aws-ecs": "AWS ECS",
        "aws-sagemaker": "AWS SageMaker",
        "azure-container-apps": "Azure Container Apps",
        "azure-ai-foundry": "Azure AI Foundry",
        "gcp-vertex-ai": "GCP Vertex AI",
        "gcp-cloud-run": "GCP Cloud Run",
        "databricks": "Databricks",
        "snowflake-cortex": "Snowflake Cortex",
        "snowflake-streamlit": "Snowflake Streamlit",
        "snowflake": "Snowflake",
        "mcp-registry": "MCP Registry",
        "smithery": "Smithery",
        "huggingface": "Hugging Face",
        "openai": "OpenAI",
        "mlflow": "MLflow",
        "wandb": "W&B",
    }
    return labels.get(source, source.replace("-", " ").title())
