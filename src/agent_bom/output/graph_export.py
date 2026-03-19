"""Export transitive dependency graphs in standalone formats.

Loads a saved ``agent-bom scan --format json`` report and rebuilds the
agent → server → package → CVE graph for export as:

- **JSON** — machine-readable nodes/edges list
- **DOT** — Graphviz (render with ``dot -Tsvg deps.dot -o deps.svg``)
- **Mermaid** — embed in markdown, GitHub issues, Notion, etc.
- **GraphML** — yEd / Gephi / NetworkX compatible, with AIBOM-typed attributes
- **Neo4j Cypher** — importable into Neo4j with AIBOM node labels and relationships

Usage::

    agent-bom scan --format json --output report.json
    agent-bom graph --from-scan report.json --format dot --output deps.dot
    agent-bom graph --from-scan report.json --format graphml --output deps.graphml
    agent-bom graph --from-scan report.json --format cypher --output import.cypher

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


# ── Graph-native AIBOM exports ───────────────────────────────────────────────

# AIBOM node type → Neo4j label mapping
_NEO4J_LABELS: dict[str, str] = {
    "provider": "Provider",
    "agent": "AIAgent",
    "server": "MCPServer",
    "server_cred": "MCPServer",
    "pkg": "Package",
    "pkg_vuln": "Package",
    "pkg_transitive": "Package",
    "cve": "Vulnerability",
}

# AIBOM edge kind → Neo4j relationship type
_NEO4J_REL_TYPES: dict[str, str] = {
    "hosts": "HOSTS",
    "uses": "USES_SERVER",
    "depends_on": "DEPENDS_ON",
    "affects": "AFFECTS",
}

# GraphML data key definitions for AIBOM attributes
_GRAPHML_KEYS = [
    ("kind", "node", "string", "Node type in AIBOM graph"),
    ("label", "node", "string", "Display label"),
    ("severity", "node", "string", "CVE severity (critical/high/medium/low)"),
    ("has_credentials", "node", "boolean", "MCP server exposes credentials"),
    ("is_vulnerable", "node", "boolean", "Package has known vulnerabilities"),
    ("is_transitive", "node", "boolean", "Transitive (indirect) dependency"),
    ("relationship", "edge", "string", "AIBOM relationship type"),
]


def _xml_escape(text: str) -> str:
    """Escape special XML characters."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&apos;")


def to_graphml(graph: DepGraph) -> str:
    """Render a :class:`DepGraph` as GraphML with AIBOM-typed attributes.

    Produces a standards-compliant GraphML 1.1 document importable into
    yEd, Gephi, NetworkX, and Cytoscape. Nodes carry AIBOM semantic
    attributes (kind, severity, has_credentials, is_vulnerable, is_transitive)
    as GraphML ``<data>`` elements.

    Args:
        graph: Populated dependency graph.

    Returns:
        GraphML XML string.
    """
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<graphml xmlns="http://graphml.graphstruct.org/graphml"',
        '         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"',
        '         xsi:schemaLocation="http://graphml.graphstruct.org/graphml http://graphml.graphstruct.org/xmlns/1.1/graphml.xsd">',
        "  <!-- AIBOM graph exported by agent-bom -->",
    ]

    # Declare data keys
    for key_id, for_type, attr_type, desc in _GRAPHML_KEYS:
        lines.append(f'  <key id="{key_id}" for="{for_type}" attr.name="{key_id}" attr.type="{attr_type}">')
        lines.append(f"    <desc>{_xml_escape(desc)}</desc>")
        lines.append("  </key>")

    lines.append('  <graph id="aibom" edgedefault="directed">')

    # Nodes
    for node in graph.nodes:
        nid = _xml_escape(node.id)
        lines.append(f'    <node id="{nid}">')
        lines.append(f'      <data key="kind">{_xml_escape(node.kind)}</data>')
        lines.append(f'      <data key="label">{_xml_escape(node.label)}</data>')
        if node.severity:
            lines.append(f'      <data key="severity">{_xml_escape(node.severity)}</data>')
        lines.append(f'      <data key="has_credentials">{"true" if node.kind == "server_cred" else "false"}</data>')
        lines.append(f'      <data key="is_vulnerable">{"true" if node.kind == "pkg_vuln" else "false"}</data>')
        lines.append(f'      <data key="is_transitive">{"true" if node.kind == "pkg_transitive" else "false"}</data>')
        lines.append("    </node>")

    # Edges
    for i, edge in enumerate(graph.edges):
        src = _xml_escape(edge.source)
        tgt = _xml_escape(edge.target)
        lines.append(f'    <edge id="e{i}" source="{src}" target="{tgt}">')
        lines.append(f'      <data key="relationship">{_xml_escape(edge.kind)}</data>')
        lines.append("    </edge>")

    lines.append("  </graph>")
    lines.append("</graphml>")
    return "\n".join(lines)


def to_cypher(graph: DepGraph) -> str:
    """Render a :class:`DepGraph` as Neo4j Cypher import statements.

    Produces a Cypher script with AIBOM-specific node labels
    (``AIAgent``, ``MCPServer``, ``Package``, ``Vulnerability``, ``Provider``)
    and relationship types (``HOSTS``, ``USES_SERVER``, ``DEPENDS_ON``, ``AFFECTS``).

    Import into Neo4j::

        cat import.cypher | cypher-shell -u neo4j -p password
        # or paste into Neo4j Browser

    Args:
        graph: Populated dependency graph.

    Returns:
        Cypher script string.
    """
    lines = [
        "// AIBOM graph import — generated by agent-bom",
        "// Node labels: Provider, AIAgent, MCPServer, Package, Vulnerability",
        "// Relationships: HOSTS, USES_SERVER, DEPENDS_ON, AFFECTS",
        "",
        "// ── Create constraints for idempotent import ──",
        "CREATE CONSTRAINT IF NOT EXISTS FOR (n:AIAgent) REQUIRE n.id IS UNIQUE;",
        "CREATE CONSTRAINT IF NOT EXISTS FOR (n:MCPServer) REQUIRE n.id IS UNIQUE;",
        "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Package) REQUIRE n.id IS UNIQUE;",
        "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Vulnerability) REQUIRE n.id IS UNIQUE;",
        "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Provider) REQUIRE n.id IS UNIQUE;",
        "",
        "// ── Create nodes ──",
    ]

    def _cypher_str(s: str) -> str:
        return s.replace("\\", "\\\\").replace("'", "\\'")

    for node in graph.nodes:
        label = _NEO4J_LABELS.get(node.kind, "Unknown")
        nid = _cypher_str(node.id)
        nlabel = _cypher_str(node.label)

        props = [f"id: '{nid}'", f"name: '{nlabel}'", f"kind: '{_cypher_str(node.kind)}'"]
        if node.severity:
            props.append(f"severity: '{_cypher_str(node.severity)}'")
        if node.kind == "server_cred":
            props.append("has_credentials: true")
        if node.kind == "pkg_vuln":
            props.append("is_vulnerable: true")
        if node.kind == "pkg_transitive":
            props.append("is_transitive: true")

        props_str = ", ".join(props)
        lines.append(f"MERGE (:{label} {{{props_str}}});")

    lines.append("")
    lines.append("// ── Create relationships ──")

    for edge in graph.edges:
        src_label = _NEO4J_LABELS.get(next((n.kind for n in graph.nodes if n.id == edge.source), ""), "Unknown")
        tgt_label = _NEO4J_LABELS.get(next((n.kind for n in graph.nodes if n.id == edge.target), ""), "Unknown")
        rel_type = _NEO4J_REL_TYPES.get(edge.kind, edge.kind.upper())
        src_id = _cypher_str(edge.source)
        tgt_id = _cypher_str(edge.target)

        lines.append(f"MATCH (a:{src_label} {{id: '{src_id}'}}), (b:{tgt_label} {{id: '{tgt_id}'}}) MERGE (a)-[:{rel_type}]->(b);")

    lines.append("")
    lines.append(f"// Total: {graph.node_count()} nodes, {graph.edge_count()} relationships")
    return "\n".join(lines)
