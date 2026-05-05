"""Helpers for the graph-accuracy guards (#2259).

These helpers project a built ``ContextGraph`` *back* to a flat inventory shape
so the round-trip property test can assert that the original inventory is a
subset of the projected one (no nodes silently dropped during graph build).

The projector is intentionally conservative: it reads only structural
information that the builder *must* preserve to be useful (agent names, server
names, tool names, credential env-var names, vulnerability IDs).  It does not
reconstruct deep package graphs because the builder collapses package counts
into metadata.

Edge counters are exposed for guard B (edge-count regression).
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from agent_bom.constants import is_credential_key
from agent_bom.context_graph import (
    ContextGraph,
    EdgeKind,
    NodeKind,
    build_context_graph,
)

FIXTURE_DIR = Path(__file__).parent / "fixtures"
SELF_SCAN_FIXTURE = FIXTURE_DIR / "agent_bom_self_scan_inventory.json"
EDGE_COUNTS_FIXTURE = FIXTURE_DIR / "graph_edge_counts.json"
GRAPH_SNAPSHOT_DIR = FIXTURE_DIR / "graph-snapshots"
GRAPH_SNAPSHOT_FIXTURE = GRAPH_SNAPSHOT_DIR / "security-graph.json"


def load_self_scan_fixture() -> dict[str, Any]:
    """Load the trimmed agent-bom self-scan fixture used by guards A/B/C."""
    with SELF_SCAN_FIXTURE.open() as f:
        return json.load(f)


def synthetic_inventory() -> dict[str, Any]:
    """Tiny deterministic inventory: 3 agents, 5 packages, 2 CVEs, 2 credentials.

    Designed to exercise every ``EdgeKind`` produced by the builder:

    - USES, PROVIDES, EXPOSES, VULNERABLE_TO
    - SHARES_SERVER (agents A & B both use ``filesystem``)
    - SHARES_CREDENTIAL (agents A & B both expose ``GITHUB_TOKEN``)
    - ATTACHED_TO (agent A has a cloud_principal in metadata)
    """
    return {
        "agents": [
            {
                "name": "agent-a",
                "type": "claude-desktop",
                "status": "configured",
                "metadata": {
                    "cloud_principal": {
                        "principal_id": "arn:aws:iam::111:role/agent-a",
                        "principal_type": "iam_role",
                        "provider": "aws",
                        "service": "iam",
                    }
                },
                "mcp_servers": [
                    {
                        "name": "filesystem",
                        "command": "npx",
                        "transport": "stdio",
                        "env": {"GITHUB_TOKEN": "***", "DEBUG": "1"},
                        "tools": [
                            {"name": "read_file", "description": "Read a file"},
                            {"name": "write_file", "description": "Write a file"},
                        ],
                        "packages": [
                            {"name": "langchain", "version": "0.1.0"},
                            {"name": "openai", "version": "1.30.0"},
                        ],
                    }
                ],
            },
            {
                "name": "agent-b",
                "type": "cursor",
                "status": "configured",
                "metadata": {},
                "mcp_servers": [
                    {
                        "name": "filesystem",
                        "command": "npx",
                        "transport": "stdio",
                        "env": {"GITHUB_TOKEN": "***"},
                        "tools": [
                            {"name": "read_file", "description": "Read a file"},
                        ],
                        "packages": [
                            {"name": "langchain", "version": "0.1.0"},
                        ],
                    }
                ],
            },
            {
                "name": "agent-c",
                "type": "vscode",
                "status": "configured",
                "metadata": {},
                "mcp_servers": [
                    {
                        "name": "github",
                        "command": "docker",
                        "transport": "stdio",
                        "env": {"GH_TOKEN": "***"},
                        "tools": [
                            {"name": "create_issue", "description": "Create an issue"},
                        ],
                        "packages": [
                            {"name": "requests", "version": "2.31.0"},
                            {"name": "pydantic", "version": "2.5.0"},
                        ],
                    }
                ],
            },
        ],
        "blast_radius": [
            {
                "vulnerability_id": "CVE-2025-0001",
                "severity": "critical",
                "cvss_score": 9.8,
                "epss_score": 0.5,
                "is_kev": False,
                "risk_score": 9.0,
                "package": "langchain@0.1.0",
                "affected_agents": ["agent-a", "agent-b"],
                "affected_servers": ["filesystem"],
                "exposed_credentials": ["GITHUB_TOKEN"],
                "exposed_tools": ["read_file", "write_file"],
            },
            {
                "vulnerability_id": "CVE-2025-0002",
                "severity": "high",
                "cvss_score": 7.5,
                "epss_score": 0.1,
                "is_kev": False,
                "risk_score": 6.5,
                "package": "requests@2.31.0",
                "affected_agents": ["agent-c"],
                "affected_servers": ["github"],
                "exposed_credentials": ["GH_TOKEN"],
                "exposed_tools": ["create_issue"],
            },
        ],
    }


def build_graph_from_inventory(inv: dict[str, Any]) -> ContextGraph:
    """Build a context graph from an inventory dict (round-trip entry point)."""
    return build_context_graph(inv.get("agents", []), inv.get("blast_radius", []))


# ── Inventory projection ────────────────────────────────────────────────


def expected_inventory_sets(inv: dict[str, Any]) -> dict[str, set[str]]:
    """Flatten an inventory dict to canonical ID-sets for subset comparison."""
    agents: set[str] = set()
    servers: set[str] = set()  # ``server:<agent>:<name>``
    tools: set[str] = set()  # ``tool:server:<agent>:<server>:<name>``
    credentials: set[str] = set()  # ``cred:<env_key>``
    iam_roles: set[str] = set()  # ``iam_role:<principal_id>``
    vulnerabilities: set[str] = set()  # ``vuln:<id>``

    for agent in inv.get("agents", []) or []:
        a_name = agent.get("name", "")
        if not a_name:
            continue
        agents.add(f"agent:{a_name}")

        principal = (agent.get("metadata") or {}).get("cloud_principal") or {}
        if isinstance(principal, dict):
            pid = principal.get("principal_id") or principal.get("principal_name")
            if pid:
                iam_roles.add(f"iam_role:{pid}")

        for srv in agent.get("mcp_servers", []) or []:
            s_name = srv.get("name", "")
            if not s_name:
                continue
            srv_id = f"server:{a_name}:{s_name}"
            servers.add(srv_id)
            for env_key in srv.get("env") or {}:
                if is_credential_key(env_key):
                    credentials.add(f"cred:{env_key}")
            for tool in srv.get("tools", []) or []:
                t_name = tool.get("name", "")
                if t_name:
                    tools.add(f"tool:{srv_id}:{t_name}")

    for br in inv.get("blast_radius", []) or []:
        vid = br.get("vulnerability_id")
        if vid:
            vulnerabilities.add(f"vuln:{vid}")

    return {
        "agents": agents,
        "servers": servers,
        "tools": tools,
        "credentials": credentials,
        "iam_roles": iam_roles,
        "vulnerabilities": vulnerabilities,
    }


def project_graph_to_inventory_sets(graph: ContextGraph) -> dict[str, set[str]]:
    """Project a built graph back to inventory ID-sets, by node kind."""
    out: dict[str, set[str]] = {
        "agents": set(),
        "servers": set(),
        "tools": set(),
        "credentials": set(),
        "iam_roles": set(),
        "vulnerabilities": set(),
    }
    kind_to_bucket = {
        NodeKind.AGENT: "agents",
        NodeKind.SERVER: "servers",
        NodeKind.TOOL: "tools",
        NodeKind.CREDENTIAL: "credentials",
        NodeKind.IAM_ROLE: "iam_roles",
        NodeKind.VULNERABILITY: "vulnerabilities",
    }
    for node in graph.nodes.values():
        bucket = kind_to_bucket.get(node.kind)
        if bucket is not None:
            out[bucket].add(node.id)
    return out


# ── Edge counting (guard B) ─────────────────────────────────────────────


def edge_counts_by_kind(graph: ContextGraph) -> dict[str, int]:
    """Return ``{edge_kind: count}`` over a built graph (alphabetised)."""
    counter: Counter[str] = Counter()
    for edge in graph.edges:
        kind = edge.kind.value if isinstance(edge.kind, EdgeKind) else str(edge.kind)
        counter[kind] += 1
    return dict(sorted(counter.items()))


def node_counts_by_kind(graph: ContextGraph) -> dict[str, int]:
    """Return ``{node_kind: count}`` over a built graph (alphabetised)."""
    counter: Counter[str] = Counter()
    for node in graph.nodes.values():
        kind = node.kind.value if isinstance(node.kind, NodeKind) else str(node.kind)
        counter[kind] += 1
    return dict(sorted(counter.items()))


# ── Visual snapshot helpers (guard C) ───────────────────────────────────


def graph_visual_snapshot(graph: ContextGraph) -> dict[str, Any]:
    """Deterministic, layout-free snapshot of the rendered security graph.

    We snapshot the *graph payload* (the same node + edge set that the
    Cytoscape renderer in ``output/graph.py`` consumes), not a literal SVG.
    Cytoscape's force-directed layout is non-deterministic, so a pixel-level
    SVG diff would either be flaky or require pinning random seeds in
    third-party JS — out of scope for a Python-only CI guard.

    Snapshotting the payload still catches every regression a visual diff
    would catch *for the graph data itself*: dropped nodes, dropped edges,
    renamed kinds, swapped labels.  Pure layout regressions (algorithm
    changes, viewport changes) are explicitly out of scope here and tracked
    as a Playwright follow-up in guard C option 2.
    """
    nodes = sorted(
        (
            {
                "id": n.id,
                "kind": n.kind.value if isinstance(n.kind, NodeKind) else str(n.kind),
                "label": n.label,
            }
            for n in graph.nodes.values()
        ),
        key=lambda n: n["id"],
    )
    edges = sorted(
        (
            {
                "source": e.source,
                "target": e.target,
                "kind": e.kind.value if isinstance(e.kind, EdgeKind) else str(e.kind),
            }
            for e in graph.edges
        ),
        key=lambda e: (e["source"], e["target"], e["kind"]),
    )
    return {
        "schema": "agent-bom.graph-snapshot/v1",
        "node_count": len(nodes),
        "edge_count": len(edges),
        "node_kind_counts": _node_kind_counts(nodes),
        "edge_kind_counts": _edge_kind_counts(edges),
        "nodes": nodes,
        "edges": edges,
    }


def _node_kind_counts(nodes: Iterable[dict[str, Any]]) -> dict[str, int]:
    counter: Counter[str] = Counter()
    for n in nodes:
        counter[n["kind"]] += 1
    return dict(sorted(counter.items()))


def _edge_kind_counts(edges: Iterable[dict[str, Any]]) -> dict[str, int]:
    counter: Counter[str] = Counter()
    for e in edges:
        counter[e["kind"]] += 1
    return dict(sorted(counter.items()))
