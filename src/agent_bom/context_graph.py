"""Agent context graph — lateral movement analysis across MCP agent fleets.

Builds a graph from scan results that models reachability between agents,
servers, credentials, tools, and vulnerabilities.  Answers the question:
"If Agent A is compromised, what else becomes reachable?"

Works with raw JSON dicts (same as output/attack_flow.py) so both CLI and
API can call it without model reconstruction.  Zero new dependencies —
stdlib ``collections.deque`` for BFS.

Types and severity constants are sourced from :mod:`graph_schema` — the
single source of truth for the entire graph subsystem.
"""

from __future__ import annotations

import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from agent_bom.constants import is_credential_key as _is_credential_key
from agent_bom.graph import (
    EDGE_KIND_TO_RELATIONSHIP as _EDGE_KIND_TO_RELATIONSHIP,
)
from agent_bom.graph import (
    NODE_KIND_TO_ENTITY as _NODE_KIND_TO_ENTITY,
)
from agent_bom.graph import (
    SEVERITY_RISK_SCORE as _SEVERITY_SCORES,
)
from agent_bom.graph import (
    AttackPath,
    EntityType,
    InteractionRisk,
    NodeDimensions,
    UnifiedEdge,
    UnifiedGraph,
    UnifiedNode,
)

_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")
_UNTRUSTED_PREFIX = "[UNTRUSTED MCP METADATA] "


def _untrusted_metadata_text(value: object, *, max_length: int = 1000) -> str:
    text = _CONTROL_CHARS_RE.sub(" ", str(value)).replace("\u2028", " ").replace("\u2029", " ")
    return f"{_UNTRUSTED_PREFIX}{text[:max_length]}"


# ── Enums (backward-compat — existing consumers import these) ────────────
# These map 1:1 to graph_schema.EntityType / RelationshipType but keep the
# original string values so serialised JSON is stable.


class NodeKind(str, Enum):
    AGENT = "agent"
    SERVER = "server"
    CREDENTIAL = "credential"
    TOOL = "tool"
    VULNERABILITY = "vulnerability"


class EdgeKind(str, Enum):
    USES = "uses"  # agent → server
    EXPOSES = "exposes"  # server → credential
    PROVIDES = "provides"  # server → tool
    VULNERABLE_TO = "vulnerable_to"  # server → vulnerability
    SHARES_SERVER = "shares_server"  # agent ↔ agent
    SHARES_CREDENTIAL = "shares_credential"  # agent ↔ agent


# ── Data structures (backward-compat) ────────────────────────────────────


@dataclass
class GraphNode:
    id: str
    kind: NodeKind
    label: str
    metadata: dict = field(default_factory=dict)


@dataclass
class GraphEdge:
    source: str
    target: str
    kind: EdgeKind
    weight: float = 1.0
    metadata: dict = field(default_factory=dict)


@dataclass
class ContextGraph:
    nodes: dict[str, GraphNode] = field(default_factory=dict)
    edges: list[GraphEdge] = field(default_factory=list)
    adjacency: dict[str, list[GraphEdge]] = field(default_factory=lambda: defaultdict(list))
    _edge_keys: set[tuple[str, str, str]] = field(default_factory=set)

    def add_node(self, node: GraphNode) -> None:
        self.nodes[node.id] = node

    def add_edge(self, edge: GraphEdge) -> None:
        """Add an edge with O(1) deduplication by (source, target, kind)."""
        key = (edge.source, edge.target, edge.kind.value if isinstance(edge.kind, EdgeKind) else str(edge.kind))
        if key in self._edge_keys:
            return
        self._edge_keys.add(key)
        self.edges.append(edge)
        self.adjacency[edge.source].append(edge)
        # Bidirectional adjacency for BFS traversal
        reverse = GraphEdge(
            source=edge.target,
            target=edge.source,
            kind=edge.kind,
            weight=edge.weight,
            metadata=edge.metadata,
        )
        self.adjacency[edge.target].append(reverse)


@dataclass
class LateralPath:
    source: str
    target: str
    hops: list[str]
    edges: list[EdgeKind]
    composite_risk: float
    summary: str
    credential_exposure: list[str]
    tool_exposure: list[str]
    vuln_ids: list[str]


# ── Tool capability classification (lazy import to avoid circular) ────────


def _classify_tool(name: str, description: str = "", declared_capabilities: object = None) -> list[str]:
    """Classify tool capabilities, returning capability value strings."""
    try:
        from agent_bom.models import MCPTool
        from agent_bom.risk_analyzer import classify_mcp_tool

        declared = [str(value) for value in declared_capabilities] if isinstance(declared_capabilities, list) else []
        tool = MCPTool(name=name, description=description, declared_capabilities=declared)
        return [c.value for c in classify_mcp_tool(tool)]
    except ImportError:
        return []


# ── Graph builder ─────────────────────────────────────────────────────────


def build_context_graph(
    agents_data: list[dict],
    blast_data: list[dict],
) -> ContextGraph:
    """Build a context graph from raw JSON scan data.

    Args:
        agents_data: The ``agents`` list from ``to_json()`` output.
        blast_data: The ``blast_radius`` list from ``to_json()`` output.

    Returns:
        A populated ``ContextGraph`` with nodes, edges, and adjacency map.
    """
    graph = ContextGraph()

    # Track which agents use which server names / credential names
    server_to_agents: dict[str, list[str]] = defaultdict(list)
    cred_to_agents: dict[str, list[str]] = defaultdict(list)

    # ── Build agent → server → credential / tool nodes & edges ────────
    for agent_dict in agents_data:
        agent_name = agent_dict.get("name", "unknown")
        agent_id = f"agent:{agent_name}"
        graph.add_node(
            GraphNode(
                id=agent_id,
                kind=NodeKind.AGENT,
                label=agent_name,
                metadata={
                    "agent_type": agent_dict.get("type", ""),
                    "status": agent_dict.get("status", ""),
                    "server_count": len(agent_dict.get("mcp_servers", [])),
                },
            )
        )

        for srv_dict in agent_dict.get("mcp_servers", []):
            srv_name = srv_dict.get("name", "unknown")
            srv_id = f"server:{agent_name}:{srv_name}"
            graph.add_node(
                GraphNode(
                    id=srv_id,
                    kind=NodeKind.SERVER,
                    label=srv_name,
                    metadata={
                        "command": srv_dict.get("command", ""),
                        "transport": srv_dict.get("transport", ""),
                        "package_count": len(srv_dict.get("packages", [])),
                        "agent": agent_name,
                    },
                )
            )
            graph.add_edge(GraphEdge(source=agent_id, target=srv_id, kind=EdgeKind.USES))

            # Track shared server detection
            server_to_agents[srv_name].append(agent_name)

            # Credentials from env keys
            env_dict = srv_dict.get("env", {})
            for env_key in env_dict:
                if _is_credential_key(env_key):
                    cred_id = f"cred:{env_key}"
                    if cred_id not in graph.nodes:
                        graph.add_node(
                            GraphNode(
                                id=cred_id,
                                kind=NodeKind.CREDENTIAL,
                                label=env_key,
                                metadata={"servers": []},
                            )
                        )
                    # Track which servers expose this credential
                    if srv_id not in graph.nodes[cred_id].metadata["servers"]:
                        graph.nodes[cred_id].metadata["servers"].append(srv_id)
                    graph.add_edge(
                        GraphEdge(
                            source=srv_id,
                            target=cred_id,
                            kind=EdgeKind.EXPOSES,
                            weight=2.0,
                        )
                    )
                    cred_to_agents[env_key].append(agent_name)

            # Tools
            for tool_dict in srv_dict.get("tools", []):
                tool_name = tool_dict.get("name", "unknown")
                tool_desc = tool_dict.get("description", "")
                tool_id = f"tool:{srv_id}:{tool_name}"
                capabilities = _classify_tool(tool_name, tool_desc, tool_dict.get("capabilities"))
                graph.add_node(
                    GraphNode(
                        id=tool_id,
                        kind=NodeKind.TOOL,
                        label=tool_name,
                        metadata={
                            "description": _untrusted_metadata_text(tool_desc),
                            "description_trust": "untrusted_external_mcp_metadata",
                            "capabilities": capabilities,
                            "server": srv_id,
                            "agent": agent_name,
                        },
                    )
                )
                weight = 3.0 if "execute" in capabilities else 1.0
                graph.add_edge(
                    GraphEdge(
                        source=srv_id,
                        target=tool_id,
                        kind=EdgeKind.PROVIDES,
                        weight=weight,
                    )
                )

    # ── Vulnerability nodes from blast radius ─────────────────────────
    seen_vulns: set[str] = set()
    for br_dict in blast_data:
        vuln_id = br_dict.get("vulnerability_id", "")
        if not vuln_id:
            continue
        severity = br_dict.get("severity", "").lower()

        if vuln_id not in seen_vulns:
            seen_vulns.add(vuln_id)
            graph.add_node(
                GraphNode(
                    id=f"vuln:{vuln_id}",
                    kind=NodeKind.VULNERABILITY,
                    label=vuln_id,
                    metadata={
                        "severity": severity,
                        "cvss_score": br_dict.get("cvss_score"),
                        "epss_score": br_dict.get("epss_score"),
                        "is_kev": br_dict.get("is_kev", False),
                        "risk_score": br_dict.get("risk_score", 0),
                        "package": br_dict.get("package", ""),
                    },
                )
            )

        # Link affected servers → vulnerability
        for agent_name in br_dict.get("affected_agents", []):
            for srv_name in br_dict.get("affected_servers", []):
                srv_id = f"server:{agent_name}:{srv_name}"
                if srv_id in graph.nodes:
                    graph.add_edge(
                        GraphEdge(
                            source=srv_id,
                            target=f"vuln:{vuln_id}",
                            kind=EdgeKind.VULNERABLE_TO,
                            weight=_SEVERITY_SCORES.get(severity, 1.0),
                            metadata={"package": br_dict.get("package", "")},
                        )
                    )

    # ── Shared server edges (agent ↔ agent) ───────────────────────────
    for _srv_name, agent_names in server_to_agents.items():
        unique = sorted(set(agent_names))
        if len(unique) >= 2:
            for i, a1 in enumerate(unique):
                for a2 in unique[i + 1 :]:
                    graph.add_edge(
                        GraphEdge(
                            source=f"agent:{a1}",
                            target=f"agent:{a2}",
                            kind=EdgeKind.SHARES_SERVER,
                            weight=3.0,
                            metadata={"server": _srv_name},
                        )
                    )

    # ── Shared credential edges (agent ↔ agent) ──────────────────────
    # Deduplication is now handled by ContextGraph.add_edge() in O(1).
    for _cred_name, agent_names in cred_to_agents.items():
        unique = sorted(set(agent_names))
        if len(unique) >= 2:
            for i, a1 in enumerate(unique):
                for a2 in unique[i + 1 :]:
                    graph.add_edge(
                        GraphEdge(
                            source=f"agent:{a1}",
                            target=f"agent:{a2}",
                            kind=EdgeKind.SHARES_CREDENTIAL,
                            weight=4.0,
                            metadata={"credential": _cred_name},
                        )
                    )

    return graph


# ── Lateral path finder (BFS) ─────────────────────────────────────────────

_MAX_PATHS = 100
_MAX_QUEUE_SIZE = 10_000  # Prevent OOM on large graphs (100+ agents)


def find_lateral_paths(
    graph: ContextGraph,
    source_node_id: str,
    max_depth: int = 4,
) -> list[LateralPath]:
    """BFS from a node to find all lateral movement paths.

    A lateral path is one that reaches a *different* agent node, or reaches
    a credential/tool belonging to a different agent.

    Args:
        graph: The context graph.
        source_node_id: Starting node (typically ``"agent:<name>"``).
        max_depth: Maximum hop depth for BFS (1-6).

    Returns:
        Up to 100 ``LateralPath`` objects, sorted by composite_risk desc.
    """
    if source_node_id not in graph.nodes:
        return []

    source_node = graph.nodes[source_node_id]
    source_agent = source_node.label if source_node.kind == NodeKind.AGENT else source_node.metadata.get("agent", "")

    paths: list[LateralPath] = []
    # BFS: queue items are (current_node_id, path_of_node_ids, path_of_edge_kinds, visited_set)
    queue: deque[tuple[str, list[str], list[EdgeKind], frozenset[str]]] = deque()
    queue.append((source_node_id, [source_node_id], [], frozenset([source_node_id])))

    visited_paths: set[tuple[str, ...]] = set()

    while queue and len(paths) < _MAX_PATHS:
        current_id, path_nodes, path_edges, visited = queue.popleft()

        if len(path_nodes) > max_depth + 1:
            continue

        # Check if we reached a lateral target
        if len(path_nodes) > 1:
            current_node = graph.nodes.get(current_id)
            if current_node:
                is_lateral = False
                if current_node.kind == NodeKind.AGENT and current_node.label != source_agent:
                    is_lateral = True
                elif current_node.kind in (NodeKind.CREDENTIAL, NodeKind.TOOL):
                    node_agent = current_node.metadata.get("agent", "")
                    if node_agent and node_agent != source_agent:
                        is_lateral = True

                if is_lateral:
                    path_key = tuple(path_nodes)
                    if path_key not in visited_paths:
                        visited_paths.add(path_key)
                        lp = _build_lateral_path(
                            graph,
                            source_node_id,
                            current_id,
                            path_nodes,
                            path_edges,
                            source_agent,
                        )
                        paths.append(lp)
                        continue  # Don't expand further from this target

        # Expand neighbors (bounded queue prevents OOM on dense graphs)
        if len(queue) >= _MAX_QUEUE_SIZE:
            continue
        for edge in graph.adjacency.get(current_id, []):
            neighbor = edge.target
            if neighbor not in visited:  # O(1) cycle check via frozenset
                queue.append(
                    (
                        neighbor,
                        path_nodes + [neighbor],
                        path_edges + [edge.kind],
                        visited | {neighbor},
                    )
                )

    paths.sort(key=lambda p: p.composite_risk, reverse=True)
    return paths[:_MAX_PATHS]


def _build_lateral_path(
    graph: ContextGraph,
    source_id: str,
    target_id: str,
    hops: list[str],
    edges: list[EdgeKind],
    source_agent: str,
) -> LateralPath:
    """Construct a LateralPath with risk scoring and summary."""
    cred_exposure: list[str] = []
    tool_exposure: list[str] = []
    vuln_ids: list[str] = []
    max_sev_score = 0.0
    execute_tool_count = 0

    for nid in hops:
        node = graph.nodes.get(nid)
        if not node:
            continue
        if node.kind == NodeKind.CREDENTIAL:
            if node.label not in cred_exposure:
                cred_exposure.append(node.label)
        elif node.kind == NodeKind.TOOL:
            if node.label not in tool_exposure:
                tool_exposure.append(node.label)
                caps = node.metadata.get("capabilities", [])
                if "execute" in caps:
                    execute_tool_count += 1
        elif node.kind == NodeKind.VULNERABILITY:
            if node.label not in vuln_ids:
                vuln_ids.append(node.label)
                sev = node.metadata.get("severity", "")
                max_sev_score = max(max_sev_score, _SEVERITY_SCORES.get(sev, 0))
        elif node.kind == NodeKind.SERVER:
            # Aggregate credentials, tools, and vulns exposed by servers along path
            for adj_edge in graph.adjacency.get(nid, []):
                neighbor = graph.nodes.get(adj_edge.target)
                if not neighbor:
                    continue
                if adj_edge.kind == EdgeKind.EXPOSES and neighbor.kind == NodeKind.CREDENTIAL:
                    if neighbor.label not in cred_exposure:
                        cred_exposure.append(neighbor.label)
                elif adj_edge.kind == EdgeKind.PROVIDES and neighbor.kind == NodeKind.TOOL:
                    if neighbor.label not in tool_exposure:
                        tool_exposure.append(neighbor.label)
                        caps = neighbor.metadata.get("capabilities", [])
                        if "execute" in caps:
                            execute_tool_count += 1
                elif adj_edge.kind == EdgeKind.VULNERABLE_TO and neighbor.kind == NodeKind.VULNERABILITY:
                    if neighbor.label not in vuln_ids:
                        vuln_ids.append(neighbor.label)
                        sev = neighbor.metadata.get("severity", "")
                        max_sev_score = max(max_sev_score, _SEVERITY_SCORES.get(sev, 0))

    # Also aggregate from sharing edges (SHARES_SERVER / SHARES_CREDENTIAL).
    # These create direct agent→agent paths that bypass server nodes.
    for i, ek in enumerate(edges):
        if ek == EdgeKind.SHARES_SERVER and i < len(hops) - 1:
            src, dst = hops[i], hops[i + 1]
            srv_name = ""
            for adj_edge in graph.adjacency.get(src, []):
                if adj_edge.target == dst and adj_edge.kind == EdgeKind.SHARES_SERVER:
                    srv_name = adj_edge.metadata.get("server", "")
                    break
            if srv_name:
                for nid, node in graph.nodes.items():
                    if node.kind == NodeKind.SERVER and node.label == srv_name:
                        for adj_edge in graph.adjacency.get(nid, []):
                            nbr = graph.nodes.get(adj_edge.target)
                            if not nbr:
                                continue
                            if adj_edge.kind == EdgeKind.EXPOSES and nbr.kind == NodeKind.CREDENTIAL:
                                if nbr.label not in cred_exposure:
                                    cred_exposure.append(nbr.label)
                            elif adj_edge.kind == EdgeKind.PROVIDES and nbr.kind == NodeKind.TOOL:
                                if nbr.label not in tool_exposure:
                                    tool_exposure.append(nbr.label)
                                    caps = nbr.metadata.get("capabilities", [])
                                    if "execute" in caps:
                                        execute_tool_count += 1
                            elif adj_edge.kind == EdgeKind.VULNERABLE_TO and nbr.kind == NodeKind.VULNERABILITY:
                                if nbr.label not in vuln_ids:
                                    vuln_ids.append(nbr.label)
                                    sev = nbr.metadata.get("severity", "")
                                    max_sev_score = max(max_sev_score, _SEVERITY_SCORES.get(sev, 0))
        elif ek == EdgeKind.SHARES_CREDENTIAL and i < len(hops) - 1:
            src, dst = hops[i], hops[i + 1]
            for adj_edge in graph.adjacency.get(src, []):
                if adj_edge.target == dst and adj_edge.kind == EdgeKind.SHARES_CREDENTIAL:
                    cred_name = adj_edge.metadata.get("credential", "")
                    if cred_name and cred_name not in cred_exposure:
                        cred_exposure.append(cred_name)
                    break

    composite = min(
        max_sev_score + len(cred_exposure) * 0.3 + execute_tool_count * 0.2,
        10.0,
    )

    # Build human-readable summary from node labels
    labels = []
    for nid in hops:
        node = graph.nodes.get(nid)
        if node:
            labels.append(node.label)
    summary = " → ".join(labels)

    return LateralPath(
        source=source_id,
        target=target_id,
        hops=hops,
        edges=edges,
        composite_risk=round(composite, 1),
        summary=summary,
        credential_exposure=cred_exposure,
        tool_exposure=tool_exposure,
        vuln_ids=vuln_ids,
    )


# ── Interaction risk detector ─────────────────────────────────────────────


def compute_interaction_risks(graph: ContextGraph) -> list[InteractionRisk]:
    """Identify risky cross-agent interaction patterns in the graph."""
    risks: list[InteractionRisk] = []

    # Collect cross-agent patterns from edges
    shared_servers: dict[str, list[str]] = defaultdict(list)
    shared_creds: dict[str, list[str]] = defaultdict(list)

    for edge in graph.edges:
        if edge.kind == EdgeKind.SHARES_SERVER:
            srv_name = edge.metadata.get("server", "")
            a1 = edge.source.removeprefix("agent:")
            a2 = edge.target.removeprefix("agent:")
            shared_servers[srv_name].extend([a1, a2])
        elif edge.kind == EdgeKind.SHARES_CREDENTIAL:
            cred_name = edge.metadata.get("credential", "")
            a1 = edge.source.removeprefix("agent:")
            a2 = edge.target.removeprefix("agent:")
            shared_creds[cred_name].extend([a1, a2])

    # ── Pattern: shared credential ────────────────────────────────────
    for cred_name, agent_names in shared_creds.items():
        unique = sorted(set(agent_names))
        if len(unique) >= 2:
            risks.append(
                InteractionRisk(
                    pattern="shared_credential",
                    agents=unique,
                    risk_score=7.0 + min(len(unique) * 0.5, 2.0),
                    description=(
                        f"Credential '{cred_name}' is shared across {len(unique)} agents "
                        f"({', '.join(unique)}). Compromising one agent grants access to "
                        f"the credential used by others."
                    ),
                    owasp_agentic_tag="ASI07",
                )
            )

    # ── Pattern: shared server ────────────────────────────────────────
    for srv_name, agent_names in shared_servers.items():
        unique = sorted(set(agent_names))
        if len(unique) >= 2:
            risks.append(
                InteractionRisk(
                    pattern="shared_server",
                    agents=unique,
                    risk_score=5.0 + min(len(unique) * 0.5, 2.0),
                    description=(
                        f"MCP server '{srv_name}' is shared across {len(unique)} agents "
                        f"({', '.join(unique)}). A vulnerability in this server affects all."
                    ),
                )
            )

    # ── Pattern: EXECUTE tool overlap ─────────────────────────────────
    execute_agents: dict[str, set[str]] = defaultdict(set)
    for node in graph.nodes.values():
        if node.kind == NodeKind.TOOL:
            caps = node.metadata.get("capabilities", [])
            if "execute" in caps:
                agent_name = node.metadata.get("agent", "")
                if agent_name:
                    execute_agents[node.label].add(agent_name)

    for tool_name, agents in execute_agents.items():
        if len(agents) >= 2:
            unique = sorted(agents)
            risks.append(
                InteractionRisk(
                    pattern="tool_overlap_execute",
                    agents=unique,
                    risk_score=6.0 + min(len(unique) * 0.5, 2.0),
                    description=(
                        f"EXECUTE-capable tool '{tool_name}' is accessible to {len(unique)} "
                        f"agents ({', '.join(unique)}). Code execution from any of them "
                        f"can pivot laterally."
                    ),
                    owasp_agentic_tag="ASI07",
                )
            )

    # ── Pattern: multi-hop vulnerability in shared server ─────────────
    for edge in graph.edges:
        if edge.kind == EdgeKind.VULNERABLE_TO:
            srv_id = edge.source
            vuln_id = edge.target
            srv_node = graph.nodes.get(srv_id)
            vuln_node = graph.nodes.get(vuln_id)
            if not srv_node or not vuln_node:
                continue
            sev = vuln_node.metadata.get("severity", "")
            if sev not in ("critical", "high"):
                continue
            srv_name = srv_node.label
            if srv_name in shared_servers:
                unique = sorted(set(shared_servers[srv_name]))
                risks.append(
                    InteractionRisk(
                        pattern="multi_hop_vuln",
                        agents=unique,
                        risk_score=8.0 + (1.0 if sev == "critical" else 0.0),
                        description=(
                            f"{sev.upper()} vulnerability {vuln_node.label} in shared server "
                            f"'{srv_name}' affects agents: {', '.join(unique)}. "
                            f"Exploit chains across agents are possible."
                        ),
                        owasp_agentic_tag="ASI07",
                    )
                )

    # Deduplicate multi_hop_vuln by (vuln_id, frozenset(agents))
    seen: set[tuple[str, frozenset[str]]] = set()
    deduped: list[InteractionRisk] = []
    for risk in risks:
        if risk.pattern == "multi_hop_vuln":
            key = (risk.description.split(" ")[2], frozenset(risk.agents))
            if key in seen:
                continue
            seen.add(key)
        deduped.append(risk)

    deduped.sort(key=lambda r: r.risk_score, reverse=True)
    return deduped


# ── Serialization ─────────────────────────────────────────────────────────


def to_serializable(
    graph: ContextGraph,
    lateral_paths: Optional[list[LateralPath]] = None,
    interaction_risks: Optional[list[InteractionRisk]] = None,
) -> dict:
    """Convert a context graph to a JSON-serializable dict."""
    paths = lateral_paths or []
    risks = interaction_risks or []

    agent_count = sum(1 for n in graph.nodes.values() if n.kind == NodeKind.AGENT)
    shared_srv = sum(1 for e in graph.edges if e.kind == EdgeKind.SHARES_SERVER)
    shared_cred = sum(1 for e in graph.edges if e.kind == EdgeKind.SHARES_CREDENTIAL)

    return {
        "nodes": [
            {
                "id": n.id,
                "kind": n.kind.value,
                "label": n.label,
                "metadata": n.metadata,
            }
            for n in graph.nodes.values()
        ],
        "edges": [
            {
                "source": e.source,
                "target": e.target,
                "kind": e.kind.value,
                "weight": e.weight,
                "metadata": e.metadata,
            }
            for e in graph.edges
        ],
        "lateral_paths": [
            {
                "source": p.source,
                "target": p.target,
                "hops": p.hops,
                "edges": [ek.value if isinstance(ek, EdgeKind) else ek for ek in p.edges],
                "composite_risk": p.composite_risk,
                "summary": p.summary,
                "credential_exposure": p.credential_exposure,
                "tool_exposure": p.tool_exposure,
                "vuln_ids": p.vuln_ids,
            }
            for p in paths
        ],
        "interaction_risks": [
            {
                "pattern": r.pattern,
                "agents": r.agents,
                "risk_score": r.risk_score,
                "description": r.description,
                "owasp_agentic_tag": r.owasp_agentic_tag,
            }
            for r in risks
        ],
        "stats": {
            "total_nodes": len(graph.nodes),
            "total_edges": len(graph.edges),
            "agent_count": agent_count,
            "shared_server_count": shared_srv,
            "shared_credential_count": shared_cred,
            "lateral_path_count": len(paths),
            "max_lateral_depth": max((len(p.hops) - 1 for p in paths), default=0),
            "highest_path_risk": max((p.composite_risk for p in paths), default=0.0),
            "interaction_risk_count": len(risks),
        },
    }


# ═══════════════════════════════════════════════════════════════════════════
# Unified Graph bridge — converts ContextGraph ↔ UnifiedGraph
# ═══════════════════════════════════════════════════════════════════════════


def to_unified_graph(
    graph: ContextGraph,
    lateral_paths: Optional[list[LateralPath]] = None,
    interaction_risks: Optional[list[InteractionRisk]] = None,
    *,
    scan_id: str = "",
    tenant_id: str = "",
) -> UnifiedGraph:
    """Convert a ContextGraph to a UnifiedGraph (the canonical representation).

    This is the bridge between the legacy context graph builder and the
    unified schema.  All downstream consumers (SIEM push, persistence,
    graph export, UI) should work from the UnifiedGraph.
    """
    ug = UnifiedGraph(scan_id=scan_id, tenant_id=tenant_id)

    for node in graph.nodes.values():
        entity_type = _NODE_KIND_TO_ENTITY.get(node.kind.value, EntityType.SERVER)
        severity = node.metadata.get("severity", "")
        ug.add_node(
            UnifiedNode(
                id=node.id,
                entity_type=entity_type,
                label=node.label,
                severity=severity if isinstance(severity, str) else "",
                risk_score=float(node.metadata.get("risk_score", 0)),
                attributes=node.metadata,
                dimensions=NodeDimensions(
                    agent_type=node.metadata.get("agent_type", ""),
                    surface="mcp-server" if entity_type == EntityType.SERVER else "",
                ),
                data_sources=["mcp-scan"],
            )
        )

    for edge in graph.edges:
        rel = _EDGE_KIND_TO_RELATIONSHIP.get(edge.kind.value)
        if not rel:
            continue
        ug.add_edge(
            UnifiedEdge(
                source=edge.source,
                target=edge.target,
                relationship=rel,
                direction="bidirectional"
                if edge.kind
                in (
                    EdgeKind.SHARES_SERVER,
                    EdgeKind.SHARES_CREDENTIAL,
                )
                else "directed",
                weight=edge.weight,
                evidence=edge.metadata,
            )
        )

    # Convert lateral paths → AttackPath
    for lp in lateral_paths or []:
        ug.attack_paths.append(
            AttackPath(
                source=lp.source,
                target=lp.target,
                hops=lp.hops,
                edges=[ek.value if isinstance(ek, EdgeKind) else str(ek) for ek in lp.edges],
                composite_risk=lp.composite_risk,
                summary=lp.summary,
                credential_exposure=lp.credential_exposure,
                tool_exposure=lp.tool_exposure,
                vuln_ids=lp.vuln_ids,
            )
        )

    # InteractionRisk is already imported from graph_schema — same type
    ug.interaction_risks = list(interaction_risks or [])

    return ug
