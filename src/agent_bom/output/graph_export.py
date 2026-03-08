"""Export transitive dependency graphs in standalone formats (DOT, Mermaid, JSON).

Loads a saved ``agent-bom scan --format json`` report and rebuilds the
agent → server → package → CVE graph for export as:

- **JSON** — machine-readable nodes/edges list
- **DOT** — Graphviz (render with ``dot -Tsvg deps.dot -o deps.svg``)
- **Mermaid** — embed in markdown, GitHub issues, Notion, etc.

Usage::

    agent-bom scan --format json --output report.json
    agent-bom graph --from-scan report.json --format dot --output deps.dot
    dot -Tsvg deps.dot -o deps.svg

    agent-bom graph --from-scan report.json --format mermaid

Closes #292.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Union

# ── Internal graph representation ──────────────────────────────────────────────


class _Node:
    __slots__ = ("id", "label", "kind", "severity")

    def __init__(self, node_id: str, label: str, kind: str, severity: str = "") -> None:
        self.id = node_id
        self.label = label
        self.kind = kind
        self.severity = severity


class _Edge:
    __slots__ = ("source", "target", "kind")

    def __init__(self, source: str, target: str, kind: str) -> None:
        self.source = source
        self.target = target
        self.kind = kind


class DepGraph:
    """Lightweight in-process graph built from a scan JSON report."""

    def __init__(self) -> None:
        self._nodes: dict[str, _Node] = {}
        self._edges: list[_Edge] = []
        self._edge_set: set[tuple[str, str]] = set()

    def add_node(self, node_id: str, label: str, kind: str, severity: str = "") -> None:
        if node_id not in self._nodes:
            self._nodes[node_id] = _Node(node_id, label, kind, severity)

    def add_edge(self, source: str, target: str, kind: str) -> None:
        key = (source, target)
        if key not in self._edge_set:
            self._edge_set.add(key)
            self._edges.append(_Edge(source, target, kind))

    @property
    def nodes(self) -> list[_Node]:
        return list(self._nodes.values())

    @property
    def edges(self) -> list[_Edge]:
        return list(self._edges)

    def node_count(self) -> int:
        return len(self._nodes)

    def edge_count(self) -> int:
        return len(self._edges)


# ── Load from scan JSON ─────────────────────────────────────────────────────────


def load_graph_from_scan(scan_path: Union[str, Path]) -> DepGraph:
    """Build a :class:`DepGraph` from a saved JSON scan report.

    Args:
        scan_path: Path to a JSON file produced by ``agent-bom scan --format json``.

    Returns:
        Populated :class:`DepGraph` with agent, server, package, and CVE nodes.

    Raises:
        ValueError: If the file is not a valid agent-bom JSON report.
        FileNotFoundError: If the path does not exist.
    """
    path = Path(scan_path)
    data = json.loads(path.read_text())

    if data.get("document_type") != "AI-BOM":
        raise ValueError(f"{scan_path} does not appear to be an agent-bom JSON report (missing 'document_type: AI-BOM')")

    graph = DepGraph()

    for agent in data.get("agents", []):
        agent_name = agent.get("name", "unknown-agent")
        source = agent.get("source") or "local"
        source_id = f"provider:{source}"
        graph.add_node(source_id, source, "provider")

        agent_id = f"agent:{agent_name}"
        graph.add_node(agent_id, agent_name, "agent")
        graph.add_edge(source_id, agent_id, "hosts")

        for server in agent.get("mcp_servers", []):
            srv_name = server.get("name", "unknown-server")
            has_creds = server.get("has_credentials", False)
            srv_kind = "server_cred" if has_creds else "server"

            srv_id = f"server:{agent_name}/{srv_name}"
            graph.add_node(srv_id, srv_name, srv_kind)
            graph.add_edge(agent_id, srv_id, "uses")

            for pkg in server.get("packages", []):
                pkg_name = pkg.get("name", "?")
                pkg_ver = pkg.get("version", "")
                pkg_eco = pkg.get("ecosystem", "")
                is_direct = pkg.get("is_direct", True)
                dep_depth = pkg.get("dependency_depth", 0)
                vulns = pkg.get("vulnerabilities", [])

                pkg_kind = "pkg_vuln" if vulns else ("pkg_transitive" if not is_direct else "pkg")
                pkg_id = f"pkg:{pkg_eco}/{pkg_name}@{pkg_ver}"
                pkg_label = f"{pkg_name}@{pkg_ver}" if pkg_ver else pkg_name
                if dep_depth and dep_depth > 0:
                    pkg_label += f" (depth {dep_depth})"
                graph.add_node(pkg_id, pkg_label, pkg_kind)
                graph.add_edge(srv_id, pkg_id, "depends_on")

                for vuln in vulns:
                    vuln_id_str = vuln.get("id", "UNKNOWN")
                    severity = vuln.get("severity", "unknown").lower()
                    cve_id = f"cve:{vuln_id_str}"
                    graph.add_node(cve_id, vuln_id_str, "cve", severity)
                    graph.add_edge(pkg_id, cve_id, "affects")

    return graph


# ── Export formats ──────────────────────────────────────────────────────────────

_DOT_COLORS: dict[str, str] = {
    "provider": "#4a9eff",
    "agent": "#2ea043",
    "server": "#6e7681",
    "server_cred": "#d29922",
    "pkg": "#8b949e",
    "pkg_vuln": "#f85149",
    "pkg_transitive": "#8b949e",
    "cve": "#da3633",
}

_DOT_SHAPES: dict[str, str] = {
    "provider": "cylinder",
    "agent": "box",
    "server": "ellipse",
    "server_cred": "ellipse",
    "pkg": "rectangle",
    "pkg_vuln": "rectangle",
    "pkg_transitive": "rectangle",
    "cve": "diamond",
}


def _dot_id(raw: str) -> str:
    """Sanitize a node ID for DOT format."""
    return '"' + raw.replace('"', '\\"') + '"'


def to_dot(graph: DepGraph, title: str = "agent-bom dependency graph") -> str:
    """Render a :class:`DepGraph` as Graphviz DOT source.

    Pipe the output through ``dot -Tsvg`` or ``dot -Tpng`` to produce images.

    Args:
        graph: Populated dependency graph.
        title: Graph title shown in the DOT header comment.

    Returns:
        DOT-format string.
    """
    lines = [
        f"// {title}",
        "digraph dependency_graph {",
        '    graph [rankdir=LR fontname="Helvetica" bgcolor="#0d1117"]',
        '    node [style=filled fontname="Helvetica" fontcolor="#e6edf3" fontsize=10]',
        '    edge [color="#30363d" fontsize=8 fontcolor="#8b949e"]',
        "",
    ]

    # Cluster by kind for layout
    kind_groups: dict[str, list[_Node]] = {}
    for node in graph.nodes:
        kind_groups.setdefault(node.kind, []).append(node)

    for kind, nodes in kind_groups.items():
        color = _DOT_COLORS.get(kind, "#8b949e")
        shape = _DOT_SHAPES.get(kind, "ellipse")
        lines.append(f"    // {kind} nodes")
        for node in nodes:
            label = node.label.replace('"', '\\"')
            lines.append(f'    {_dot_id(node.id)} [label={_dot_id(label)} fillcolor="{color}" shape={shape}]')
        lines.append("")

    lines.append("    // edges")
    for edge in graph.edges:
        lines.append(f'    {_dot_id(edge.source)} -> {_dot_id(edge.target)} [label="{edge.kind}"]')

    lines.append("}")
    return "\n".join(lines)


def to_mermaid(graph: DepGraph) -> str:
    """Render a :class:`DepGraph` as a Mermaid LR flowchart.

    Paste the output into a markdown fenced block (`` ```mermaid ``) to render
    in GitHub, Notion, MkDocs, or any Mermaid-compatible renderer.

    Args:
        graph: Populated dependency graph.

    Returns:
        Mermaid flowchart string.
    """

    def _safe_id(raw: str) -> str:
        return re.sub(r"[^a-zA-Z0-9_]", "_", raw)

    def _style_class(kind: str) -> str:
        return {
            "provider": "provider",
            "agent": "agent",
            "server": "server",
            "server_cred": "servercred",
            "pkg": "pkg",
            "pkg_vuln": "pkgvuln",
            "pkg_transitive": "pkgtrans",
            "cve": "cve",
        }.get(kind, "pkg")

    lines = [
        "flowchart LR",
        "    classDef provider fill:#4a9eff,color:#fff,stroke:#2563eb",
        "    classDef agent fill:#2ea043,color:#fff,stroke:#16a34a",
        "    classDef server fill:#6e7681,color:#fff,stroke:#374151",
        "    classDef servercred fill:#d29922,color:#fff,stroke:#b45309",
        "    classDef pkg fill:#8b949e,color:#fff,stroke:#374151",
        "    classDef pkgvuln fill:#f85149,color:#fff,stroke:#dc2626",
        "    classDef pkgtrans fill:#8b949e,color:#ddd,stroke:#6b7280,stroke-dasharray:4 2",
        "    classDef cve fill:#da3633,color:#fff,stroke:#991b1b",
        "",
    ]

    for node in graph.nodes:
        nid = _safe_id(node.id)
        label = node.label.replace('"', "'")
        cls = _style_class(node.kind)
        if node.kind == "cve":
            lines.append(f'    {nid}{{"{label}"}}:::{cls}')
        elif node.kind in ("provider", "agent"):
            lines.append(f'    {nid}["{label}"]:::{cls}')
        else:
            lines.append(f'    {nid}("{label}"):::{cls}')

    lines.append("")
    for edge in graph.edges:
        src = _safe_id(edge.source)
        tgt = _safe_id(edge.target)
        lines.append(f"    {src} -->|{edge.kind}| {tgt}")

    return "\n".join(lines)


def to_json(graph: DepGraph) -> dict:
    """Return a JSON-serialisable representation of the graph.

    Args:
        graph: Populated dependency graph.

    Returns:
        Dict with ``nodes``, ``edges``, and ``stats`` keys.
    """
    return {
        "nodes": [{"id": n.id, "label": n.label, "kind": n.kind, "severity": n.severity} for n in graph.nodes],
        "edges": [{"source": e.source, "target": e.target, "kind": e.kind} for e in graph.edges],
        "stats": {
            "node_count": graph.node_count(),
            "edge_count": graph.edge_count(),
        },
    }
