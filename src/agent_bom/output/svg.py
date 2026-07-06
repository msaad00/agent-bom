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

from agent_bom.asset_provenance import package_version_provenance
from agent_bom.output.finding_views import cve_findings, severity_value, topology_package_key

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
_ROWS_PER_PAGE = 50
_PAGE_HEADER_H = 34
_PAGE_GAP = 28
_DEFAULT_MAX_ROWS_PER_COLUMN = _ROWS_PER_PAGE

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
    "omitted": ("#92400e", "#fffbeb", "#f59e0b"),
}

_FONT = "system-ui, -apple-system, 'Segoe UI', sans-serif"


def to_svg(
    report: AIBOMReport,
    blast_radii: list[BlastRadius],
    *,
    max_rows_per_column: int | None = _DEFAULT_MAX_ROWS_PER_COLUMN,
) -> str:
    """Generate a self-contained SVG supply chain diagram.

    Shows hierarchical layout: Provider -> Agent -> MCP Server -> Package -> CVE
    Color-coded by severity and status.

    Args:
        report: The AI-BOM report.
        blast_radii: List of BlastRadius objects for CVE indicators.
        max_rows_per_column: Maximum rendered rows per SVG column. ``None``
            renders the full graph. The default keeps static SVG exports
            readable in browsers and reports by adding an explicit omission
            marker for oversized columns.

    Returns:
        Complete SVG document as a string.
    """
    if max_rows_per_column is not None and max_rows_per_column < 2:
        raise ValueError("max_rows_per_column must be at least 2 or None")

    findings = cve_findings(report, blast_radii)
    vuln_pkg_keys: set[tuple[str, str]] = {topology_package_key(finding) for finding in findings}
    pkg_cve_map: dict[tuple[str, str], list[dict]] = {}
    for finding in findings:
        key = topology_package_key(finding)
        if key not in pkg_cve_map:
            pkg_cve_map[key] = []
        pkg_cve_map[key].append(
            {
                "id": finding.cve_id or finding.title,
                "severity": severity_value(finding),
            }
        )

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
        agents.append(
            {
                "id": aid,
                "label": agent.name,
                "type": agent.agent_type.value,
                "servers": len(agent.mcp_servers),
            }
        )
        provider_to_agents.append((f"p:{source}", aid))

        for srv in agent.mcp_servers:
            sid = f"s:{agent.name}:{srv.name}"
            has_vuln = any((p.name, p.ecosystem) in vuln_pkg_keys for p in srv.packages)
            has_cred = srv.has_credentials
            stype = "server_vuln" if has_vuln else ("server_cred" if has_cred else "server_clean")

            cred_label = ""
            if has_cred:
                cred_label = f" [{len(srv.credential_names)} cred]"

            servers.append(
                {
                    "id": sid,
                    "label": srv.name + cred_label,
                    "type": stype,
                    "pkg_count": len(srv.packages),
                    "tool_count": len(srv.tools) if srv.tools else 0,
                }
            )
            agent_to_servers.append((aid, sid))

            for pkg in srv.packages:
                pkg_key = (pkg.name, pkg.ecosystem)
                pid = f"pkg:{pkg.name}:{pkg.ecosystem}"
                is_vuln = pkg_key in vuln_pkg_keys

                packages.append(
                    {
                        "id": pid,
                        "label": f"{pkg.name}@{pkg.version}",
                        "type": "pkg_vuln" if is_vuln else "pkg_clean",
                        "ecosystem": pkg.ecosystem,
                        "version_provenance": package_version_provenance(pkg),
                    }
                )
                server_to_packages.append((sid, pid))

                if is_vuln and pkg_key in pkg_cve_map:
                    for cve_info in pkg_cve_map[pkg_key]:
                        cve_id = f"cve:{cve_info['id']}"
                        if cve_info["id"] not in cve_set:
                            cve_set.add(cve_info["id"])
                            cves.append(
                                {
                                    "id": cve_id,
                                    "label": cve_info["id"],
                                    "type": f"cve_{cve_info['severity']}",
                                    "severity": cve_info["severity"],
                                }
                            )
                        package_to_cves.append((pid, cve_id))

    # Deduplicate packages/servers (same ID can appear under multiple parents)
    packages = _dedup_by_id(packages)
    servers = _dedup_by_id(servers)
    graph_counts = {
        "agents": len(agents),
        "servers": len(servers),
        "packages": len(packages),
        "cves": len(cves),
    }

    omitted_counts: dict[str, int] = {}
    providers, omitted_counts["sources"] = _bound_column(providers, "sources", max_rows_per_column)
    agents, omitted_counts["agents"] = _bound_column(agents, "agents", max_rows_per_column)
    servers, omitted_counts["servers"] = _bound_column(servers, "servers", max_rows_per_column)
    packages, omitted_counts["packages"] = _bound_column(packages, "packages", max_rows_per_column)
    cves, omitted_counts["CVEs"] = _bound_column(cves, "CVEs", max_rows_per_column)
    omitted_nodes = sum(omitted_counts.values())

    # ── Assign Y positions ────────────────────────────────────────────────
    columns = [providers, agents, servers, packages, cves]
    max_rows = max(len(col) for col in columns) if columns else 1
    page_count = max(1, (max_rows + _ROWS_PER_PAGE - 1) // _ROWS_PER_PAGE)
    page_h = _PAGE_HEADER_H + min(max_rows, _ROWS_PER_PAGE) * (_NODE_H + _ROW_GAP) + _PAGE_GAP
    total_h = _HEADER_H + page_count * page_h + 40

    col_positions = [_COL_PROVIDER, _COL_AGENT, _COL_SERVER, _COL_PACKAGE, _COL_CVE]
    node_y_map: dict[str, float] = {}
    node_page_map: dict[str, int] = {}

    for col_items, _x in zip(columns, col_positions):
        for i, item in enumerate(col_items):
            page_idx = i // _ROWS_PER_PAGE
            row_idx = i % _ROWS_PER_PAGE
            page_top = _HEADER_H + page_idx * page_h
            node_y_map[item["id"]] = page_top + _PAGE_HEADER_H + row_idx * (_NODE_H + _ROW_GAP)
            node_page_map[item["id"]] = page_idx

    total_w = _COL_CVE + _NODE_W + 60 if cves else _COL_PACKAGE + _NODE_W + 60

    visible_node_ids = {item["id"] for column in columns for item in column}
    all_edges = provider_to_agents + agent_to_servers + server_to_packages + package_to_cves
    unique_edges = set(all_edges)
    rendered_edges = {edge for edge in unique_edges if edge[0] in visible_node_ids and edge[1] in visible_node_ids}
    omitted_edges = len(unique_edges) - len(rendered_edges)

    # ── Build SVG ─────────────────────────────────────────────────────────
    parts: list[str] = []
    parts.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {total_w} {total_h}" '
        f'width="{total_w}" height="{total_h}" '
        f'preserveAspectRatio="xMinYMin meet" '
        f'style="font-family: {_FONT}; font-size: 12px; background: #fafafa;">'
    )
    if omitted_nodes or omitted_edges:
        omitted_label = ", ".join(f"{count} {kind}" for kind, count in omitted_counts.items() if count)
        parts.append(
            "<metadata>"
            f"Bounded SVG export: omitted {html.escape(omitted_label or '0 nodes')} "
            f"and {omitted_edges} edges. Export JSON, DOT, GraphML, or Cypher for the full graph."
            "</metadata>"
        )

    # Defs: arrowhead
    parts.append("""<defs>
  <marker id="arrow" viewBox="0 0 10 6" refX="10" refY="3"
    markerWidth="8" markerHeight="6" orient="auto-start-reverse">
    <path d="M 0 0 L 10 3 L 0 6 z" fill="#999"/>
  </marker>
</defs>""")

    # Title bar
    parts.append(
        f'<text x="{total_w / 2}" y="30" text-anchor="middle" '
        f'font-size="18" font-weight="bold" fill="#1a1a1a">'
        f"AI Supply Chain — agent-bom</text>"
    )
    parts.append(
        f'<text x="{total_w / 2}" y="52" text-anchor="middle" '
        f'font-size="13" fill="#666">'
        f"{graph_counts['agents']} agents | {graph_counts['servers']} servers | "
        f"{graph_counts['packages']} packages | {graph_counts['cves']} CVEs</text>"
    )
    if omitted_nodes or omitted_edges:
        parts.append(
            f'<text x="{total_w / 2}" y="70" text-anchor="middle" '
            f'font-size="11" fill="#92400e">'
            f"Bounded view: {omitted_nodes} nodes and {omitted_edges} edges omitted; export JSON/DOT/GraphML/Cypher for full graph</text>"
        )

    # Column headers
    headers = [
        (_COL_PROVIDER, "Sources"),
        (_COL_AGENT, "Agents"),
        (_COL_SERVER, "MCP Servers"),
        (_COL_PACKAGE, "Packages"),
    ]
    if cves:
        headers.append((_COL_CVE, "CVEs"))
    for x, label in headers:
        parts.append(
            f'<text x="{x + _NODE_W / 2}" y="{_HEADER_H - 12}" '
            f'text-anchor="middle" font-size="13" font-weight="600" fill="#444">'
            f"{label}</text>"
        )

    if page_count > 1:
        for page_idx in range(page_count):
            page_top = _HEADER_H + page_idx * page_h
            parts.append(
                f'<g id="page-{page_idx + 1}">'
                f'<rect x="20" y="{page_top + 2}" width="{total_w - 40}" height="{page_h - _PAGE_GAP / 2}" '
                f'fill="none" stroke="#d7dde3" stroke-width="1" stroke-dasharray="6 6"/>'
                f'<text x="34" y="{page_top + 23}" font-size="12" font-weight="600" fill="#59636e">'
                f"Page {page_idx + 1} of {page_count}</text></g>"
            )

    # Edges (draw first so nodes appear on top)
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
    skipped_cross_page_edges = 0
    for src, tgt in all_edges:
        if (src, tgt) in seen_edges:
            continue
        seen_edges.add((src, tgt))
        if src not in node_y_map or tgt not in node_y_map:
            continue
        if node_page_map.get(src, 0) != node_page_map.get(tgt, 0):
            skipped_cross_page_edges += 1
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

    if skipped_cross_page_edges:
        parts.append(
            f'<text x="{total_w / 2}" y="{total_h - 18}" text-anchor="middle" font-size="12" fill="#6b7280">'
            f"{skipped_cross_page_edges} cross-page relationships summarized to keep dense SVG pages readable</text>"
        )

    # Nodes
    def _draw_nodes(items: list[dict], col_x: int, color_key: str) -> None:
        for item in items:
            y = node_y_map.get(item["id"], 0)
            ctype = item.get("type", color_key)
            colors = _COLORS.get(ctype, _COLORS.get(color_key, ("#333", "#f5f5f5", "#999")))
            text_color, bg_color, border_color = colors
            label = html.escape(item["label"][:28])
            version_attrs = ""
            version_provenance = item.get("version_provenance")
            if isinstance(version_provenance, dict):
                source = html.escape(str(version_provenance.get("version_source", "unknown")), quote=True)
                confidence = html.escape(str(version_provenance.get("confidence", "unknown")), quote=True)
                version_attrs = f' data-version-source="{source}" data-version-confidence="{confidence}"'

            parts.append(
                f'<rect x="{col_x}" y="{y}" width="{_NODE_W}" height="{_NODE_H}" '
                f'rx="{_NODE_RX}" fill="{bg_color}" stroke="{border_color}" stroke-width="1.5"{version_attrs}/>'
            )
            parts.append(
                f'<text x="{col_x + _NODE_W / 2}" y="{y + _NODE_H / 2 + 4}" '
                f'text-anchor="middle" font-size="11" font-weight="500" fill="{text_color}">'
                f"{label}</text>"
            )

    _draw_nodes(providers, _COL_PROVIDER, "provider")
    _draw_nodes(agents, _COL_AGENT, "agent")
    _draw_nodes(servers, _COL_SERVER, "server_clean")
    _draw_nodes(packages, _COL_PACKAGE, "pkg_clean")
    _draw_nodes(cves, _COL_CVE, "cve_medium")

    # Empty state
    if not report.agents:
        parts.append(
            f'<text x="{total_w / 2}" y="{total_h / 2}" text-anchor="middle" font-size="16" fill="#999">No agents discovered</text>'
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


def _bound_column(items: list[dict], label: str, max_rows: int | None) -> tuple[list[dict], int]:
    """Bound a rendered SVG column and append a visible omission marker."""
    if max_rows is None or len(items) <= max_rows:
        return items, 0

    visible = items[: max_rows - 1]
    omitted = len(items) - len(visible)
    return [
        *visible,
        {
            "id": f"omitted:{label}",
            "label": f"{omitted} more {label} omitted",
            "type": "omitted",
        },
    ], omitted


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
